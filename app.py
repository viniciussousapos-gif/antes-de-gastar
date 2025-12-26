import os
import re
import time
import hmac
import uuid
import sqlite3
import hashlib
from datetime import datetime, date, timedelta
import streamlit as st


# =========================
# CONFIG
# =========================
APP_NAME = "Antes de Gastar"
APP_SUBTITLE = "Antes de gastar, entenda o porquê. 1 pergunta por dia → padrões simples → mais consciência."

# Banco: em Cloud, prefira um path relativo. Vamos criar pasta "data" no repo.
DB_DIR = os.getenv("DB_DIR", "data")
DB_PATH = os.getenv("DB_PATH", os.path.join(DB_DIR, "por_que_gastei.db"))

# Admin: defina no Streamlit Cloud em Settings -> Secrets:
# ADMIN_PASSWORD = "uma_senha_forte"
ADMIN_PASSWORD = None
try:
    ADMIN_PASSWORD = st.secrets.get("ADMIN_PASSWORD", None)
except Exception:
    ADMIN_PASSWORD = os.getenv("ADMIN_PASSWORD")


# =========================
# HELPERS
# =========================
def now_iso():
    # ISO com timezone "local" simplificado
    return datetime.now().isoformat(timespec="seconds")

def today_str():
    return date.today().isoformat()

def normalize_email(email: str) -> str:
    return (email or "").strip().lower()

def normalize_apelido(apelido: str) -> str:
    # apelido simples (sem espaços extremos)
    return (apelido or "").strip()

def is_valid_email(email: str) -> bool:
    email = normalize_email(email)
    # regex simples (suficiente para MVP)
    return bool(re.match(r"^[^@\s]+@[^@\s]+\.[^@\s]+$", email))

def ensure_db_dir():
    os.makedirs(DB_DIR, exist_ok=True)

def get_conn():
    ensure_db_dir()
    conn = sqlite3.connect(DB_PATH, check_same_thread=False)
    conn.execute("PRAGMA journal_mode=WAL;")
    conn.execute("PRAGMA synchronous=NORMAL;")
    return conn


# =========================
# PASSWORD HASHING (PBKDF2)
# =========================
def hash_password(password: str, salt: bytes | None = None) -> str:
    if salt is None:
        salt = os.urandom(16)
    pw = password.encode("utf-8")
    dk = hashlib.pbkdf2_hmac("sha256", pw, salt, 200_000)
    return f"pbkdf2_sha256$200000${salt.hex()}${dk.hex()}"

def verify_password(password: str, stored: str) -> bool:
    try:
        algo, iters, salt_hex, hash_hex = stored.split("$")
        if algo != "pbkdf2_sha256":
            return False
        salt = bytes.fromhex(salt_hex)
        test = hash_password(password, salt)
        # comparação constante
        return hmac.compare_digest(test, stored)
    except Exception:
        return False


# =========================
# DB INIT + MIGRATIONS
# =========================
def table_columns(cur, table_name: str) -> set[str]:
    cur.execute(f"PRAGMA table_info({table_name})")
    return {row[1] for row in cur.fetchall()}

def init_db():
    """
    Cria tabelas e MIGRA o schema antigo (Cloud) para evitar:
    sqlite3.OperationalError: no such column: user_key
    """
    conn = get_conn()
    cur = conn.cursor()

    # 1) users
    cur.execute("""
        CREATE TABLE IF NOT EXISTS users (
            user_key TEXT PRIMARY KEY,
            email TEXT UNIQUE NOT NULL,
            apelido TEXT UNIQUE,
            password_hash TEXT NOT NULL,
            created_at TEXT NOT NULL
        )
    """)

    # 2) password resets (para "esqueci a senha" sem email ainda)
    cur.execute("""
        CREATE TABLE IF NOT EXISTS password_resets (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            email TEXT NOT NULL,
            token TEXT NOT NULL,
            expires_at TEXT NOT NULL,
            used_at TEXT
        )
    """)
    cur.execute("""
        CREATE INDEX IF NOT EXISTS idx_password_resets_email
        ON password_resets(email)
    """)
    cur.execute("""
        CREATE INDEX IF NOT EXISTS idx_password_resets_token
        ON password_resets(token)
    """)

    # 3) respostas
    # Criamos com user_key. Se já existir antigo, faremos ALTER TABLE abaixo.
    cur.execute("""
        CREATE TABLE IF NOT EXISTS respostas (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_key TEXT,
            dt_ref TEXT,
            gasto_nao_planejado INTEGER,
            motivo TEXT,
            momento TEXT,
            created_at TEXT
        )
    """)

    # -------------------------
    # MIGRAÇÃO: respostas.user_key
    # -------------------------
    cols = table_columns(cur, "respostas")
    if "user_key" not in cols:
        cur.execute("ALTER TABLE respostas ADD COLUMN user_key TEXT")

        # tenta reaproveitar colunas antigas se existirem
        if "user_id" in cols:
            cur.execute("UPDATE respostas SET user_key = user_id WHERE user_key IS NULL")
        elif "user" in cols:
            cur.execute("UPDATE respostas SET user_key = user WHERE user_key IS NULL")

    # Índice único por usuário + dia (para upsert lógico)
    cur.execute("""
        CREATE UNIQUE INDEX IF NOT EXISTS idx_respostas_user_dia
        ON respostas(user_key, dt_ref)
    """)

    conn.commit()
    conn.close()


# =========================
# USERS CRUD
# =========================
def create_user(email: str, apelido: str, password: str) -> tuple[bool, str]:
    email = normalize_email(email)
    apelido = normalize_apelido(apelido)

    if not is_valid_email(email):
        return False, "Email inválido."
    if len(password or "") < 6:
        return False, "Senha muito curta. Use pelo menos 6 caracteres."
    if apelido and len(apelido) < 2:
        return False, "Apelido muito curto."

    user_key = uuid.uuid4().hex
    pw_hash = hash_password(password)

    conn = get_conn()
    cur = conn.cursor()

    # checa duplicados
    cur.execute("SELECT 1 FROM users WHERE email = ?", (email,))
    if cur.fetchone():
        conn.close()
        return False, "Este email já existe. Faça login."

    if apelido:
        cur.execute("SELECT 1 FROM users WHERE apelido = ?", (apelido,))
        if cur.fetchone():
            conn.close()
            return False, "Este apelido já existe. Escolha outro."

    cur.execute("""
        INSERT INTO users(user_key, email, apelido, password_hash, created_at)
        VALUES(?,?,?,?,?)
    """, (user_key, email, apelido if apelido else None, pw_hash, now_iso()))
    conn.commit()
    conn.close()
    return True, "Conta criada com sucesso! Faça login."

def auth_user(email: str, password: str) -> tuple[bool, dict | None, str]:
    email = normalize_email(email)
    conn = get_conn()
    cur = conn.cursor()

    cur.execute("""
        SELECT user_key, email, apelido, password_hash
        FROM users
        WHERE email = ?
    """, (email,))
    row = cur.fetchone()
    conn.close()

    if not row:
        return False, None, "Email não encontrado. Crie uma conta."
    user_key, email_db, apelido_db, pw_hash = row

    if not verify_password(password, pw_hash):
        return False, None, "Senha incorreta."

    return True, {
        "user_key": user_key,
        "email": email_db,
        "apelido": apelido_db
    }, "OK"

def request_password_reset(email: str) -> tuple[bool, str]:
    email = normalize_email(email)
    if not is_valid_email(email):
        return False, "Email inválido."

    conn = get_conn()
    cur = conn.cursor()
    cur.execute("SELECT 1 FROM users WHERE email = ?", (email,))
    if not cur.fetchone():
        conn.close()
        return False, "Não existe conta com esse email."

    token = uuid.uuid4().hex
    expires = (datetime.now() + timedelta(hours=1)).isoformat(timespec="seconds")

    cur.execute("""
        INSERT INTO password_resets(email, token, expires_at, used_at)
        VALUES(?,?,?,NULL)
    """, (email, token, expires))
    conn.commit()
    conn.close()

    # Como ainda não enviamos email:
    # devolvemos o link/código pra você copiar e mandar para a pessoa.
    return True, token

def reset_password_with_token(token: str, new_password: str) -> tuple[bool, str]:
    token = (token or "").strip()
    if len(new_password or "") < 6:
        return False, "Senha muito curta. Use pelo menos 6 caracteres."

    conn = get_conn()
    cur = conn.cursor()

    cur.execute("""
        SELECT email, expires_at, used_at
        FROM password_resets
        WHERE token = ?
        ORDER BY id DESC
        LIMIT 1
    """, (token,))
    row = cur.fetchone()
    if not row:
        conn.close()
        return False, "Token inválido."
    email, expires_at, used_at = row

    if used_at:
        conn.close()
        return False, "Este token já foi usado."

    try:
        exp_dt = datetime.fromisoformat(expires_at)
        if datetime.now() > exp_dt:
            conn.close()
            return False, "Token expirado. Gere outro."
    except Exception:
        conn.close()
        return False, "Token inválido (formato)."

    pw_hash = hash_password(new_password)

    cur.execute("UPDATE users SET password_hash = ? WHERE email = ?", (pw_hash, email))
    cur.execute("UPDATE password_resets SET used_at = ? WHERE token = ?", (now_iso(), token))
    conn.commit()
    conn.close()
    return True, "Senha atualizada com sucesso! Faça login."


# =========================
# RESPOSTAS CRUD
# =========================
def upsert_resposta(user_key: str, dt_ref: str, gasto: int, motivo: str | None, momento: str | None):
    conn = get_conn()
    cur = conn.cursor()
    # se existe (user_key, dt_ref) atualiza; senão insere.
    cur.execute("""
        INSERT INTO respostas(user_key, dt_ref, gasto_nao_planejado, motivo, momento, created_at)
        VALUES(?,?,?,?,?,?)
        ON CONFLICT(user_key, dt_ref)
        DO UPDATE SET
            gasto_nao_planejado = excluded.gasto_nao_planejado,
            motivo = excluded.motivo,
            momento = excluded.momento,
            created_at = excluded.created_at
    """, (user_key, dt_ref, int(gasto), motivo, momento, now_iso()))
    conn.commit()
    conn.close()

def get_resposta_do_dia(user_key: str, dt_ref: str):
    conn = get_conn()
    cur = conn.cursor()
    cur.execute("""
        SELECT dt_ref, gasto_nao_planejado, COALESCE(motivo,''), COALESCE(momento,''), created_at
        FROM respostas
        WHERE user_key = ? AND dt_ref = ?
    """, (user_key, dt_ref))
    row = cur.fetchone()
    conn.close()
    return row

def get_historico(user_key: str, limit: int = 60):
    conn = get_conn()
    cur = conn.cursor()
    cur.execute("""
        SELECT dt_ref, gasto_nao_planejado, COALESCE(motivo,''), COALESCE(momento,''), created_at
        FROM respostas
        WHERE user_key = ?
        ORDER BY dt_ref DESC
        LIMIT ?
    """, (user_key, int(limit)))
    rows = cur.fetchall()
    conn.close()
    return rows

def insight_ultimos_7_dias(user_key: str):
    rows = get_historico(user_key, limit=120)
    if not rows:
        return None

    # filtra últimos 7 dias
    hoje = date.today()
    recents = []
    for dt_ref, gasto, motivo, momento, created_at in rows:
        try:
            d = date.fromisoformat(dt_ref)
        except Exception:
            continue
        if (hoje - d).days <= 6:
            recents.append((d, gasto, motivo, momento))

    if not recents:
        return None

    total_dias = len({d for d, *_ in recents})
    dias_com_gasto = len({d for d, gasto, *_ in recents if int(gasto) == 1})

    motivos = {}
    momentos = {}
    for d, gasto, motivo, momento in recents:
        if int(gasto) == 1:
            if motivo:
                motivos[motivo] = motivos.get(motivo, 0) + 1
            if momento:
                momentos[momento] = momentos.get(momento, 0) + 1

    top_motivo = max(motivos, key=motivos.get) if motivos else None
    top_momento = max(momentos, key=momentos.get) if momentos else None

    return {
        "total_dias": total_dias,
        "dias_com_gasto": dias_com_gasto,
        "pct": round((dias_com_gasto / max(total_dias, 1)) * 100),
        "top_motivo": top_motivo,
        "top_momento": top_momento,
    }


# =========================
# UI
# =========================
st.set_page_config(page_title=APP_NAME, page_icon="🧠", layout="wide")

# garante migração sempre no começo (CRÍTICO para Cloud)
init_db()


def sidebar_account():
    st.sidebar.markdown("## Conta")

    # sessão
    if "auth" not in st.session_state:
        st.session_state.auth = None  # dict com user_key/email/apelido

    if st.session_state.auth:
        u = st.session_state.auth
        label = u.get("apelido") or u.get("email")
        st.sidebar.success(f"Logado como: {label}")
        if st.sidebar.button("Sair"):
            st.session_state.auth = None
            st.rerun()
        return

    tab_login, tab_signup, tab_forgot = st.sidebar.tabs(["Entrar", "Criar conta", "Esqueci a senha"])

    with tab_login:
        email = st.text_input("Email", key="login_email")
        password = st.text_input("Senha", type="password", key="login_password")
        if st.button("Entrar", key="btn_login"):
            ok, user, msg = auth_user(email, password)
            if ok:
                st.session_state.auth = user
                st.rerun()
            else:
                st.error(msg)

    with tab_signup:
        email = st.text_input("Email", key="signup_email")
        apelido = st.text_input("Apelido (opcional)", key="signup_apelido")
        password = st.text_input("Senha", type="password", key="signup_password")
        password2 = st.text_input("Confirmar senha", type="password", key="signup_password2")
        if st.button("Criar conta", key="btn_signup"):
            if password != password2:
                st.error("As senhas não conferem.")
            else:
                ok, msg = create_user(email, apelido, password)
                if ok:
                    st.success(msg)
                else:
                    st.error(msg)

    with tab_forgot:
        st.caption("Sem email automático por enquanto. Vamos gerar um token para você copiar e enviar.")
        email = st.text_input("Seu email", key="forgot_email")
        if st.button("Gerar token de reset", key="btn_forgot"):
            ok, out = request_password_reset(email)
            if ok:
                token = out
                st.success("Token gerado! Copie o link abaixo (vale por 1 hora):")
                # link baseado no próprio app
                base = st.get_option("server.baseUrlPath") or ""
                # Streamlit não dá URL absoluta fácil; deixamos token para colar no campo abaixo
                st.code(token)
                st.info("Agora vá na aba 'Reset' (no topo do app) e cole o token.")
            else:
                st.error(out)

    st.sidebar.markdown("---")
    st.sidebar.caption("Dica: use sempre o email para evitar colisão de nomes.")


def main_header():
    c1, c2, c3 = st.columns([1, 6, 1])
    with c2:
        st.markdown(f"# 🧠 {APP_NAME}")
        st.caption(APP_SUBTITLE)
        st.markdown("---")


def page_reset_password():
    st.markdown("## Reset de senha")
    st.caption("Cole o token gerado na aba 'Esqueci a senha' e defina uma nova senha.")
    token = st.text_input("Token")
    new_password = st.text_input("Nova senha", type="password")
    new_password2 = st.text_input("Confirmar nova senha", type="password")
    if st.button("Atualizar senha"):
        if new_password != new_password2:
            st.error("As senhas não conferem.")
            return
        ok, msg = reset_password_with_token(token, new_password)
        if ok:
            st.success(msg)
        else:
            st.error(msg)


def page_app():
    if not st.session_state.auth:
        st.info("Faça login ou crie uma conta na barra lateral para começar.")
        return

    user_key = st.session_state.auth["user_key"]
    dt_ref = today_str()

    st.markdown("## Pergunta de hoje")
    st.markdown("**Hoje você gastou com algo que não planejava?**")

    row = get_resposta_do_dia(user_key, dt_ref)

    if row:
        _, gasto, motivo, momento, created_at = row
        st.success(f"Resposta registrada hoje em **{dt_ref}**. Última atualização: **{created_at}**. Você pode editar e salvar novamente se quiser.")
    else:
        gasto, motivo, momento = 0, "", ""

    escolha = st.radio("Escolha uma opção:", ["Não", "Sim"], index=1 if int(gasto) == 1 else 0, horizontal=False)
    gasto_val = 1 if escolha == "Sim" else 0

    motivos_opcoes = [
        "Pressão social",
        "Recompensa (\"eu mereço\")",
        "Ansiedade/estresse",
        "Tédio",
        "Promoção/impulso",
        "Fome/vontade",
        "Outro"
    ]
    motivo_sel = st.selectbox("O que mais influenciou esse gasto?", [""] + motivos_opcoes, index=([""] + motivos_opcoes).index(motivo) if motivo in motivos_opcoes else 0)
    momento_sel = st.radio("Em que momento do dia isso aconteceu?", ["", "Manhã", "Tarde", "Noite"], index=(["", "Manhã", "Tarde", "Noite"].index(momento) if momento in ["Manhã","Tarde","Noite"] else 0), horizontal=True)

    st.caption("Sugestão: antes do próximo gasto, faça uma pausa curta e pergunte: “isso resolve o que eu estou sentindo agora?”")

    if st.button("Salvar resposta"):
        # se marcou "Não", limpamos motivo/momento
        m = motivo_sel if gasto_val == 1 else ""
        mo = momento_sel if gasto_val == 1 else ""
        upsert_resposta(user_key, dt_ref, gasto_val, m, mo)
        st.rerun()

    st.markdown("---")
    st.markdown("## Insight (últimos 7 dias)")
    ins = insight_ultimos_7_dias(user_key)
    if not ins:
        st.write("Ainda não há dados suficientes para gerar insights. Responda diariamente para começar.")
    else:
        txt = f"Nos últimos 7 dias, **{ins['pct']}%** dos seus dias tiveram gasto não planejado."
        if ins["top_motivo"]:
            txt += f" O motivo mais comum foi **{ins['top_motivo']}**."
        if ins["top_momento"]:
            txt += f" Esses episódios tendem a acontecer mais em **{ins['top_momento']}**."
        st.write(txt)

    st.markdown("---")
    st.markdown("## Histórico")
    hist = get_historico(user_key, limit=30)
    if not hist:
        st.write("Sem histórico ainda. Responda a pergunta de hoje 🙂")
    else:
        for dt_ref, gasto, motivo, momento, created_at in hist:
            status = "✅ Sim" if int(gasto) == 1 else "⬜ Não"
            detalhe = ""
            if int(gasto) == 1:
                parts = []
                if motivo:
                    parts.append(motivo)
                if momento:
                    parts.append(momento)
                detalhe = f" — {' / '.join(parts)}" if parts else ""
            st.write(f"**{dt_ref}** — {status}{detalhe}")


def page_admin():
    # Admin só abre com query param ?admin=1
    params = st.query_params
    if str(params.get("admin", "0")) != "1":
        return

    st.markdown("## Admin (restrito)")
    if not ADMIN_PASSWORD:
        st.warning("ADMIN_PASSWORD não configurado nos secrets/env. Configure para liberar admin.")
        return

    pwd = st.text_input("Senha de admin", type="password")
    if not pwd:
        st.info("Digite a senha para acessar.")
        return

    if pwd != ADMIN_PASSWORD:
        st.error("Senha incorreta.")
        return

    st.success("Admin liberado ✅")

    conn = get_conn()
    cur = conn.cursor()

    cur.execute("SELECT COUNT(*) FROM users")
    total_users = cur.fetchone()[0]
    cur.execute("SELECT COUNT(*) FROM respostas")
    total_resp = cur.fetchone()[0]
    st.write(f"**Usuários:** {total_users} | **Respostas:** {total_resp}")

    st.markdown("### Últimas 50 respostas (geral)")
    cur.execute("""
        SELECT r.dt_ref, u.email, COALESCE(u.apelido,''), r.gasto_nao_planejado, COALESCE(r.motivo,''), COALESCE(r.momento,''), r.created_at
        FROM respostas r
        LEFT JOIN users u ON u.user_key = r.user_key
        ORDER BY r.created_at DESC
        LIMIT 50
    """)
    rows = cur.fetchall()
    conn.close()

    if not rows:
        st.write("Sem dados.")
    else:
        for dt_ref, email, apelido, gasto, motivo, momento, created_at in rows:
            who = apelido if apelido else email
            status = "Sim" if int(gasto) == 1 else "Não"
            extra = []
            if motivo:
                extra.append(motivo)
            if momento:
                extra.append(momento)
            extra_txt = f" ({' / '.join(extra)})" if extra else ""
            st.write(f"- **{dt_ref}** — **{who}** — **{status}**{extra_txt} — _{created_at}_")


# =========================
# RENDER
# =========================
sidebar_account()

main_header()

# mini “navegação”
tabs = st.tabs(["App", "Reset"])
with tabs[0]:
    page_app()
with tabs[1]:
    page_reset_password()

# Admin invisível (só com ?admin=1)
page_admin()
