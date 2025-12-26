import sqlite3
import os
import hmac
import hashlib
import secrets
from datetime import datetime, date, timedelta
from zoneinfo import ZoneInfo

import streamlit as st

# =========================
# Config da página
# =========================
st.set_page_config(
    page_title="Antes de Gastar",
    page_icon="🧠",
    layout="centered",
)

TZ = ZoneInfo("America/Sao_Paulo")
DB_PATH = "por_que_gastei_v2.db"

# Admin invisível via query param
params = st.query_params
IS_ADMIN_ROUTE = params.get("admin") == "1"

# Troque depois
ADMIN_PASSWORD = "admin123"

# Pepper opcional (melhora segurança). Ideal colocar em Secrets/Env do Streamlit Cloud.
PEPPER = os.environ.get("APP_PEPPER", "change-me-pepper")


# =========================
# DB
# =========================
def get_conn():
    return sqlite3.connect(DB_PATH, check_same_thread=False)


def init_db():
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()

    # -------------------------
    # USERS
    # -------------------------
    cur.execute("""
        CREATE TABLE IF NOT EXISTS users (
            user_key TEXT PRIMARY KEY,
            email TEXT UNIQUE NOT NULL,
            apelido TEXT UNIQUE,
            password_hash TEXT NOT NULL,
            created_at TEXT NOT NULL
        )
    """)

    # -------------------------
    # RESPOSTAS
    # -------------------------
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
    # MIGRAÇÃO: respostas.user_key (para bancos antigos)
    # -------------------------
    cur.execute("PRAGMA table_info(respostas)")
    colunas = {c[1] for c in cur.fetchall()}

    if "user_key" not in colunas:
        cur.execute("ALTER TABLE respostas ADD COLUMN user_key TEXT")

        # tenta copiar de colunas antigas (se existirem)
        if "user_id" in colunas:
            cur.execute("UPDATE respostas SET user_key = user_id WHERE user_key IS NULL")

    # Índice único por usuário + dia
    cur.execute("""
        CREATE UNIQUE INDEX IF NOT EXISTS idx_respostas_user_dia
        ON respostas(user_key, dt_ref)
    """)

    conn.commit()
    conn.close()



init_db()


# =========================
# Auth helpers
# =========================
def normalize(s: str) -> str:
    return (s or "").strip()


def normalize_email(s: str) -> str:
    return normalize(s).lower()


def normalize_username(s: str) -> str:
    return normalize(s).lower()


def is_valid_email(email: str) -> bool:
    if not email:
        return False
    if "@" not in email:
        return False
    if "." not in email.split("@")[-1]:
        return False
    return True


def pbkdf2_hash(password: str, salt_hex: str) -> str:
    salt = bytes.fromhex(salt_hex)
    dk = hashlib.pbkdf2_hmac(
        "sha256",
        (password + PEPPER).encode("utf-8"),
        salt,
        200_000,
        dklen=32,
    )
    return dk.hex()


def create_user(username: str, password: str, email: str | None):
    username = normalize_username(username)
    email = normalize_email(email) if email else None

    if not username:
        return False, "Digite um apelido."
    if len(username) < 3:
        return False, "Seu apelido deve ter pelo menos 3 caracteres."
    if not password or len(password) < 6:
        return False, "Sua senha deve ter pelo menos 6 caracteres."
    if email and not is_valid_email(email):
        return False, "Digite um e-mail válido (ou deixe em branco)."

    conn = get_conn()
    cur = conn.cursor()

    # apelido já existe?
    cur.execute("SELECT 1 FROM users WHERE username = ?", (username,))
    if cur.fetchone():
        conn.close()
        return False, "Esse apelido já existe. Tente outro."

    # email já existe?
    if email:
        cur.execute("SELECT 1 FROM users WHERE email = ?", (email,))
        if cur.fetchone():
            conn.close()
            return False, "Esse e-mail já está cadastrado. Tente fazer login."

    salt_hex = secrets.token_hex(16)
    pw_hash = pbkdf2_hash(password, salt_hex)
    now = datetime.now(TZ).isoformat(timespec="seconds")

    cur.execute(
        """
        INSERT INTO users (username, email, salt, password_hash, created_at)
        VALUES (?, ?, ?, ?, ?)
        """,
        (username, email, salt_hex, pw_hash, now),
    )
    conn.commit()
    conn.close()
    return True, "Conta criada com sucesso! Agora faça login."


def verify_login(login: str, password: str):
    login = normalize(login).lower()
    if not login or not password:
        return False, "Preencha login e senha.", None

    conn = get_conn()
    cur = conn.cursor()

    cur.execute(
        """
        SELECT username, salt, password_hash
        FROM users
        WHERE username = ? OR email = ?
        """,
        (login, login),
    )
    row = cur.fetchone()
    conn.close()

    if not row:
        return False, "Usuário/e-mail não encontrado.", None

    username, salt_hex, stored_hash = row
    calc = pbkdf2_hash(password, salt_hex)

    if not hmac.compare_digest(calc, stored_hash):
        return False, "Senha incorreta.", None

    return True, "Login realizado.", username


def reset_password(username_or_email: str, new_password: str):
    """
    Reset manual via admin:
    - procura por username OU email
    - atualiza salt + hash
    """
    login = normalize(username_or_email).lower()
    if not login:
        return False, "Digite o apelido ou e-mail do usuário."

    if not new_password or len(new_password) < 6:
        return False, "A nova senha deve ter pelo menos 6 caracteres."

    conn = get_conn()
    cur = conn.cursor()

    cur.execute(
        """
        SELECT username
        FROM users
        WHERE username = ? OR email = ?
        """,
        (login, login),
    )
    row = cur.fetchone()

    if not row:
        conn.close()
        return False, "Usuário não encontrado."

    username = row[0]

    salt_hex = secrets.token_hex(16)
    pw_hash = pbkdf2_hash(new_password, salt_hex)

    cur.execute(
        """
        UPDATE users
        SET salt = ?, password_hash = ?
        WHERE username = ?
        """,
        (salt_hex, pw_hash, username),
    )
    conn.commit()
    conn.close()

    return True, f"Senha resetada com sucesso para '{username}'."


# =========================
# Data helpers
# =========================
def upsert_resposta(user_key: str, dt_ref: str, gasto: int, motivo: str | None, momento: str | None):
    now = datetime.now(TZ).isoformat(timespec="seconds")
    conn = get_conn()
    cur = conn.cursor()

    cur.execute(
        """
        INSERT INTO respostas (user_key, dt_ref, gasto_nao_planejado, motivo, momento, created_at, updated_at)
        VALUES (?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(user_key, dt_ref) DO UPDATE SET
            gasto_nao_planejado = excluded.gasto_nao_planejado,
            motivo = excluded.motivo,
            momento = excluded.momento,
            updated_at = excluded.updated_at
        """,
        (user_key, dt_ref, gasto, motivo, momento, now, now),
    )

    conn.commit()
    conn.close()


def get_resposta_do_dia(user_key: str, dt_ref: str):
    conn = get_conn()
    cur = conn.cursor()
    cur.execute(
        """
        SELECT dt_ref, gasto_nao_planejado, COALESCE(motivo,''), COALESCE(momento,''),
               created_at, updated_at
        FROM respostas
        WHERE user_key = ? AND dt_ref = ?
        """,
        (user_key, dt_ref),
    )
    row = cur.fetchone()
    conn.close()
    return row


def get_historico(user_key: str, limit: int = 60):
    conn = get_conn()
    cur = conn.cursor()
    cur.execute(
        """
        SELECT dt_ref, gasto_nao_planejado, COALESCE(motivo,''), COALESCE(momento,''), created_at
        FROM respostas
        WHERE user_key = ?
        ORDER BY dt_ref DESC
        LIMIT ?
        """,
        (user_key, limit),
    )
    rows = cur.fetchall()
    conn.close()
    return rows


def get_ultimos_dias(user_key: str, dias: int = 7):
    fim = date.today()
    inicio = fim - timedelta(days=dias - 1)

    conn = get_conn()
    cur = conn.cursor()
    cur.execute(
        """
        SELECT dt_ref, gasto_nao_planejado, COALESCE(motivo,''), COALESCE(momento,'')
        FROM respostas
        WHERE user_key = ?
          AND date(dt_ref) BETWEEN date(?) AND date(?)
        ORDER BY dt_ref ASC
        """,
        (user_key, inicio.isoformat(), fim.isoformat()),
    )
    rows = cur.fetchall()
    conn.close()
    return rows


def insight_7_dias(rows_7d):
    if not rows_7d:
        return None

    total = len(rows_7d)
    dias_com_gasto = sum(1 for r in rows_7d if int(r[1]) == 1)
    pct = round((dias_com_gasto / total) * 100) if total else 0

    motivos = {}
    momentos = {}
    for _, gasto, motivo, momento in rows_7d:
        if int(gasto) == 1:
            if motivo:
                motivos[motivo] = motivos.get(motivo, 0) + 1
            if momento:
                momentos[momento] = momentos.get(momento, 0) + 1

    motivo_top = max(motivos, key=motivos.get) if motivos else None
    momento_top = max(momentos, key=momentos.get) if momentos else None

    partes = [f"Nos últimos 7 dias, gastos não planejados ocorreram em **{pct}%** dos dias respondidos."]
    if motivo_top:
        partes.append(f"Motivo mais comum: **{motivo_top}**.")
    if momento_top:
        partes.append(f"Momento mais comum: **{momento_top.lower()}**.")
    partes.append("Perceber o padrão é o primeiro passo para mudar.")

    return " ".join(partes)


def sugestao_por_motivo(motivo_top: str | None):
    if not motivo_top:
        return "Antes do próximo gasto, faça uma pausa curta e pergunte: “isso resolve o que eu estou sentindo agora?”"
    m = motivo_top.lower()
    if "pressão" in m:
        return "Respire 10s e pergunte: “eu compraria isso se ninguém estivesse olhando?”"
    if "recompensa" in m or "mereço" in m:
        return "Pergunte: “qual recompensa menor (e suficiente) eu posso escolher agora?”"
    if "ansiedade" in m or "estresse" in m:
        return "Faça uma pausa de 60s (água + respiração) e reavalie."
    if "tédio" in m:
        return "Faça uma alternativa de 2 min (andar/alongar/música) e reavalie."
    return "Antes do próximo gasto, faça uma pausa curta e pergunte: “isso resolve o que eu estou sentindo agora?”"


# =========================
# UI
# =========================
st.markdown("## 🧠 Antes de Gastar")
st.caption("Antes de gastar, entenda o porquê. 1 pergunta por dia → padrões simples → mais consciência.")


# =========================
# ADMIN invisível + reset senha
# =========================
if IS_ADMIN_ROUTE:
    st.markdown("---")
    st.subheader("🔒 Área administrativa")

    senha = st.text_input("Senha admin", type="password")
    if senha:
        if senha == ADMIN_PASSWORD:
            st.success("Acesso liberado.")

            # Painel simples
            conn = get_conn()
            cur = conn.cursor()

            cur.execute("SELECT COUNT(1) FROM users")
            tot_users = int(cur.fetchone()[0])

            cur.execute("SELECT COUNT(1) FROM respostas")
            tot_resp = int(cur.fetchone()[0])

            st.write(f"**Usuários:** {tot_users}  |  **Respostas:** {tot_resp}")

            st.markdown("### 🔁 Reset de senha (manual)")
            target = st.text_input("Apelido ou e-mail do usuário", key="adm_target")
            new_pw = st.text_input("Nova senha (mín. 6)", type="password", key="adm_newpw")

            if st.button("Resetar senha", key="adm_reset_btn"):
                ok, msg = reset_password(target, new_pw)
                if ok:
                    st.success(msg)
                else:
                    st.error(msg)

            st.markdown("### Últimas respostas (100)")
            cur.execute(
                """
                SELECT user_key, dt_ref, gasto_nao_planejado,
                       COALESCE(motivo,''), COALESCE(momento,''),
                       created_at, updated_at
                FROM respostas
                ORDER BY updated_at DESC
                LIMIT 100
                """
            )
            rows = cur.fetchall()
            conn.close()

            st.dataframe(rows, use_container_width=True)
            st.caption("Dica: evite compartilhar prints (privacidade).")

        else:
            st.error("Senha incorreta.")

    st.stop()


# =========================
# Auth na sidebar
# =========================
if "auth_user" not in st.session_state:
    st.session_state.auth_user = None

st.sidebar.header("Conta")

if st.session_state.auth_user:
    st.sidebar.success(f"Logado como: {st.session_state.auth_user}")
    if st.sidebar.button("Sair"):
        st.session_state.auth_user = None
        st.rerun()
else:
    tab_login, tab_signup = st.sidebar.tabs(["Entrar", "Criar conta"])

    with tab_login:
        login = st.text_input("E-mail ou apelido", key="login_login")
        senha = st.text_input("Senha", type="password", key="login_senha")
        if st.button("Entrar", key="btn_entrar"):
            ok, msg, username = verify_login(login, senha)
            if ok:
                st.session_state.auth_user = username
                st.sidebar.success(msg)
                st.rerun()
            else:
                st.sidebar.error(msg)

        st.caption("Esqueceu a senha? Fale com o criador do app para reset manual.")

    with tab_signup:
        username = st.text_input("Apelido (único)", key="signup_username")
        email = st.text_input("E-mail (opcional)", key="signup_email")
        senha = st.text_input("Senha (mín. 6)", type="password", key="signup_pw")
        if st.button("Criar conta", key="btn_criar"):
            ok, msg = create_user(username, senha, email if email.strip() else None)
            if ok:
                st.sidebar.success(msg)
            else:
                st.sidebar.error(msg)

# Bloqueia app se não logou
if not st.session_state.auth_user:
    st.info("Faça login (ou crie uma conta) na barra lateral para começar.")
    st.stop()

user_key = st.session_state.auth_user

# =========================
# App principal
# =========================
hoje = datetime.now(TZ).date()
dt_ref = hoje.isoformat()

st.markdown("---")
st.subheader("Pergunta de hoje")
st.write("**Hoje você gastou com algo que não planejava?**")

row = get_resposta_do_dia(user_key, dt_ref)

default_gasto = 0
default_motivo = ""
default_momento = ""

if row:
    _, gasto_salvo, motivo_salvo, momento_salvo, created_at, updated_at = row
    default_gasto = int(gasto_salvo)
    default_motivo = motivo_salvo or ""
    default_momento = momento_salvo or ""
    st.info(
        f"Resposta registrada hoje em **{created_at}**."
        + (f" Última atualização: **{updated_at}**." if updated_at and updated_at != created_at else "")
        + " Você pode editar e salvar novamente se quiser."
    )

gasto_txt = st.radio(
    "Escolha uma opção:",
    options=["Não", "Sim"],
    index=1 if default_gasto == 1 else 0,
)

gasto = 1 if gasto_txt == "Sim" else 0

motivos_opcoes = [
    "",
    "Pressão social",
    "Recompensa (\"eu mereço\")",
    "Ansiedade / estresse",
    "Tédio",
    "Impulso / promoção",
    "Fome / cansaço",
    "Outro",
]

motivo = ""
momento = ""

if gasto == 1:
    motivo = st.selectbox(
        "O que mais influenciou esse gasto?",
        options=motivos_opcoes,
        index=motivos_opcoes.index(default_motivo) if default_motivo in motivos_opcoes else 0,
    )
    momento = st.radio(
        "Em que momento do dia isso aconteceu?",
        options=["Manhã", "Tarde", "Noite"],
        index=["Manhã", "Tarde", "Noite"].index(default_momento) if default_momento in ["Manhã", "Tarde", "Noite"] else 0,
        horizontal=True,
    )

st.caption("Sugestão: " + (sugestao_por_motivo(motivo if motivo else None) if gasto == 1 else "Ótimo. Manter consistência também é um padrão."))

if st.button("Salvar resposta", type="primary"):
    if gasto == 1 and not motivo:
        st.warning("Selecione um motivo para salvar.")
    else:
        upsert_resposta(user_key=user_key, dt_ref=dt_ref, gasto=gasto, motivo=motivo or None, momento=momento or None)
        st.success("Resposta salva!")
        st.rerun()

st.markdown("---")
st.subheader("Insight (últimos 7 dias)")
rows_7d = get_ultimos_dias(user_key, dias=7)
ins = insight_7_dias(rows_7d)
if not ins:
    st.write("Ainda não há dados suficientes para gerar insights. Responda diariamente para começar.")
else:
    st.write(ins)

st.markdown("---")
st.subheader("Histórico")
hist = get_historico(user_key, limit=60)
if not hist:
    st.write("Sem histórico ainda. Responda a pergunta de hoje 🙂")
else:
    for dt_ref_i, gasto_i, motivo_i, momento_i, _created_at in hist[:20]:
        status = "✅ Sim" if int(gasto_i) == 1 else "⬜ Não"
        extras = []
        if motivo_i:
            extras.append(motivo_i)
        if momento_i:
            extras.append(momento_i.lower())
        extra_txt = f" • " + " • ".join(extras) if extras else ""
        st.write(f"**{dt_ref_i}** — {status}{extra_txt}")

    if len(hist) > 20:
        with st.expander("Ver mais"):
            for dt_ref_i, gasto_i, motivo_i, momento_i, _created_at in hist[20:]:
                status = "✅ Sim" if int(gasto_i) == 1 else "⬜ Não"
                extras = []
                if motivo_i:
                    extras.append(motivo_i)
                if momento_i:
                    extras.append(momento_i.lower())
                extra_txt = f" • " + " • ".join(extras) if extras else ""
                st.write(f"**{dt_ref_i}** — {status}{extra_txt}")
