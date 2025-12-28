import os
import re
import hmac
import uuid
import sqlite3
import hashlib
import csv
import io
from datetime import datetime, date, timedelta

import streamlit as st


# =========================
# CONFIG
# =========================
APP_NAME = "Antes de Gastar"
APP_SUBTITLE = "Antes de gastar, entenda o porquê. 1 pergunta por dia → padrões simples → mais consciência."

DB_DIR = os.getenv("DB_DIR", "data")
DB_PATH = os.getenv("DB_PATH", os.path.join(DB_DIR, "por_que_gastei.db"))

# Secrets/env
def _get_secret(name: str, default=None):
    try:
        return st.secrets.get(name, default)
    except Exception:
        return os.getenv(name, default)

ADMIN_PASSWORD = _get_secret("ADMIN_PASSWORD", None)

# Stripe Payment Link (ex: https://buy.stripe.com/xxxx)
STRIPE_PAYMENT_LINK = _get_secret("STRIPE_PAYMENT_LINK", "")

# Preço exibido (somente UI)
PREMIUM_PRICE_TEXT = _get_secret("PREMIUM_PRICE_TEXT", "R$ 9,90/mês")


# =========================
# HELPERS
# =========================
def now_iso():
    return datetime.now().isoformat(timespec="seconds")


def today_str():
    return date.today().isoformat()


def normalize_email(email: str) -> str:
    return (email or "").strip().lower()


def normalize_apelido(apelido: str) -> str:
    return (apelido or "").strip()


def is_valid_email(email: str) -> bool:
    email = normalize_email(email)
    return bool(re.match(r"^[^@\s]+@[^@\s]+\.[^@\s]+$", email))


def ensure_db_dir():
    os.makedirs(DB_DIR, exist_ok=True)


def get_conn():
    ensure_db_dir()
    conn = sqlite3.connect(DB_PATH, check_same_thread=False)
    conn.execute("PRAGMA journal_mode=WAL;")
    conn.execute("PRAGMA synchronous=NORMAL;")
    return conn


def get_user_label(user: dict | None) -> str:
    if not user:
        return ""
    return user.get("apelido") or user.get("email") or "Usuário"


def is_pro() -> bool:
    u = st.session_state.get("auth")
    return bool(u and u.get("plan") == "pro")


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
    Cria tabelas e migra schema antigo para evitar erros na Cloud:
    - respostas.user_key
    - users.plan (free/pro)
    """
    conn = get_conn()
    cur = conn.cursor()

    # users
    cur.execute("""
        CREATE TABLE IF NOT EXISTS users (
            user_key TEXT PRIMARY KEY,
            email TEXT UNIQUE NOT NULL,
            apelido TEXT UNIQUE,
            password_hash TEXT NOT NULL,
            created_at TEXT NOT NULL
        )
    """)

    # MIGRAÇÃO: users.plan
    user_cols = table_columns(cur, "users")
    if "plan" not in user_cols:
        cur.execute("ALTER TABLE users ADD COLUMN plan TEXT DEFAULT 'free'")

    # password resets
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

    # respostas
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

    # MIGRAÇÃO: respostas.user_key
    cols = table_columns(cur, "respostas")
    if "user_key" not in cols:
        cur.execute("ALTER TABLE respostas ADD COLUMN user_key TEXT")
        if "user_id" in cols:
            cur.execute("UPDATE respostas SET user_key = user_id WHERE user_key IS NULL")
        elif "user" in cols:
            cur.execute("UPDATE respostas SET user_key = user WHERE user_key IS NULL")

    # índice único por usuário + dia
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
        INSERT INTO users(user_key, email, apelido, password_hash, created_at, plan)
        VALUES(?,?,?,?,?,?)
    """, (user_key, email, apelido if apelido else None, pw_hash, now_iso(), "free"))
    conn.commit()
    conn.close()
    return True, "Conta criada com sucesso! Faça login."


def auth_user(email: str, password: str) -> tuple[bool, dict | None, str]:
    email = normalize_email(email)

    conn = get_conn()
    cur = conn.cursor()
    cur.execute("""
        SELECT user_key, email, apelido, password_hash, COALESCE(plan,'free')
        FROM users
        WHERE email = ?
    """, (email,))
    row = cur.fetchone()
    conn.close()

    if not row:
        return False, None, "Email não encontrado. Crie uma conta."

    user_key, email_db, apelido_db, pw_hash, plan = row
    if not verify_password(password, pw_hash):
        return False, None, "Senha incorreta."

    return True, {
        "user_key": user_key,
        "email": email_db,
        "apelido": apelido_db,
        "plan": plan
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

    exp_dt = datetime.fromisoformat(expires_at)
    if datetime.now() > exp_dt:
        conn.close()
        return False, "Token expirado. Gere outro."

    pw_hash = hash_password(new_password)
    cur.execute("UPDATE users SET password_hash = ? WHERE email = ?", (pw_hash, email))
    cur.execute("UPDATE password_resets SET used_at = ? WHERE token = ?", (now_iso(), token))
    conn.commit()
    conn.close()
    return True, "Senha atualizada com sucesso! Faça login."


def set_user_plan_by_email(email: str, plan: str) -> tuple[bool, str]:
    """
    Admin: promove/rebaixa usuário por email.
    plan: 'free' ou 'pro'
    """
    email = normalize_email(email)
    if not is_valid_email(email):
        return False, "Email inválido."
    if plan not in ("free", "pro"):
        return False, "Plano inválido."

    conn = get_conn()
    cur = conn.cursor()
    cur.execute("SELECT 1 FROM users WHERE email = ?", (email,))
    if not cur.fetchone():
        conn.close()
        return False, "Usuário não encontrado."

    cur.execute("UPDATE users SET plan = ? WHERE email = ?", (plan, email))
    conn.commit()
    conn.close()
    return True, f"Plano atualizado para: {plan}"


# =========================
# RESPOSTAS CRUD
# =========================
def upsert_resposta(user_key: str, dt_ref: str, gasto: int, motivo: str | None, momento: str | None):
    conn = get_conn()
    cur = conn.cursor()
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


def get_historico_all(user_key: str):
    conn = get_conn()
    cur = conn.cursor()
    cur.execute("""
        SELECT dt_ref, gasto_nao_planejado, COALESCE(motivo,''), COALESCE(momento,''), created_at
        FROM respostas
        WHERE user_key = ?
        ORDER BY dt_ref DESC
    """, (user_key,))
    rows = cur.fetchall()
    conn.close()
    return rows


# =========================
# INSIGHTS
# =========================
def insight_ultimos_7_dias(user_key: str):
    rows = get_historico(user_key, limit=200)
    if not rows:
        return None

    hoje = date.today()
    recents = []
    for dt_ref, gasto, motivo, momento, _ in rows:
        try:
            d = date.fromisoformat(dt_ref)
        except Exception:
            continue
        if (hoje - d).days <= 6:
            recents.append((d, int(gasto), motivo, momento))

    if not recents:
        return None

    total_dias = len({d for d, *_ in recents})
    dias_com_gasto = len({d for d, gasto, *_ in recents if gasto == 1})

    motivos = {}
    momentos = {}
    for d, gasto, motivo, momento in recents:
        if gasto == 1:
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


def insight_periodo(user_key: str, dias: int):
    rows = get_historico(user_key, limit=500)
    if not rows:
        return None

    hoje = date.today()
    recents = []
    for dt_ref, gasto, motivo, momento, _ in rows:
        try:
            d = date.fromisoformat(dt_ref)
        except Exception:
            continue
        if (hoje - d).days <= (dias - 1):
            recents.append((d, int(gasto), motivo, momento))

    if not recents:
        return None

    total_dias = len({d for d, *_ in recents})
    dias_com_gasto = len({d for d, gasto, *_ in recents if gasto == 1})

    motivos = {}
    momentos = {}
    combos = {}

    for d, gasto, motivo, momento in recents:
        if gasto == 1:
            if motivo:
                motivos[motivo] = motivos.get(motivo, 0) + 1
            if momento:
                momentos[momento] = momentos.get(momento, 0) + 1
            if motivo and momento:
                key = f"{motivo} + {momento}"
                combos[key] = combos.get(key, 0) + 1

    top_combo = None
    if combos:
        best = max(combos, key=combos.get)
        if combos[best] >= 3:
            top_combo = best

    return {
        "dias": dias,
        "total_dias": total_dias,
        "dias_com_gasto": dias_com_gasto,
        "pct": round((dias_com_gasto / max(total_dias, 1)) * 100),
        "top_motivos": sorted(motivos.items(), key=lambda x: x[1], reverse=True)[:3],
        "top_momentos": sorted(momentos.items(), key=lambda x: x[1], reverse=True)[:3],
        "top_combo": top_combo,
    }


def calcular_streak(user_key: str) -> int:
    rows = get_historico(user_key, limit=200)
    if not rows:
        return 0

    datas = set()
    for dt_ref, *_ in rows:
        try:
            datas.add(date.fromisoformat(dt_ref))
        except Exception:
            pass

    streak = 0
    dia = date.today()
    while dia in datas:
        streak += 1
        dia = dia - timedelta(days=1)
    return streak


# =========================
# CSV EXPORT (Premium)
# =========================
def gerar_csv_historico(user_key: str) -> bytes:
    rows = get_historico_all(user_key)

    out = io.StringIO()
    w = csv.writer(out, delimiter=";")
    w.writerow(["dt_ref", "gasto_nao_planejado", "motivo", "momento", "created_at"])

    for dt_ref, gasto, motivo, momento, created_at in rows:
        w.writerow([dt_ref, int(gasto), motivo, momento, created_at])

    return out.getvalue().encode("utf-8")


# =========================
# UI
# =========================
st.set_page_config(page_title=APP_NAME, page_icon="🧠", layout="wide")

# CRÍTICO: migra sempre no começo (Cloud)
init_db()


def sidebar_account():
    st.sidebar.markdown("## Conta")

    if "auth" not in st.session_state:
        st.session_state.auth = None

    if st.session_state.auth:
        u = st.session_state.auth
        label = get_user_label(u)
        badge = "💎 Premium" if u.get("plan") == "pro" else "🆓 Free"
        st.sidebar.success(f"Logado como: {label}\n\nPlano: {badge}")

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
                st.success("Token gerado! Copie o token abaixo (vale por 1 hora):")
                st.code(out)
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
        _, gasto, motivo_db, momento_db, created_at = row
        st.success(
            f"Resposta registrada hoje em **{dt_ref}**. Última atualização: **{created_at}**. "
            f"Você pode editar e salvar novamente se quiser."
        )
    else:
        gasto, motivo_db, momento_db = 0, "", ""

    escolha = st.radio(
        "Escolha uma opção:",
        ["Não", "Sim"],
        index=1 if int(gasto) == 1 else 0,
        horizontal=False,
    )
    gasto_val = 1 if escolha == "Sim" else 0

    motivos_opcoes = [
        "Pressão social",
        "Recompensa (\"eu mereço\")",
        "Ansiedade/estresse",
        "Tédio",
        "Promoção/impulso",
        "Fome/vontade",
        "Outro",
    ]

    motivo_sel = ""
    momento_sel = ""

    if gasto_val == 1:
        # motivo
        motivo_options = [""] + motivos_opcoes
        default_idx = motivo_options.index(motivo_db) if motivo_db in motivo_options else 0

        motivo_sel = st.selectbox(
            "O que mais influenciou esse gasto?",
            motivo_options,
            index=default_idx,
        )

        # momento (sem opção vazia)
        momentos = ["Manhã", "Tarde", "Noite"]
        idx = momentos.index(momento_db) if momento_db in momentos else None

        momento_sel = st.radio(
            "Em que momento do dia isso aconteceu?",
            options=momentos,
            index=idx,
            horizontal=True,
        )

    st.caption("Sugestão: antes do próximo gasto, faça uma pausa curta e pergunte: “isso resolve o que eu estou sentindo agora?”")

    if st.button("Salvar resposta"):
        if gasto_val == 1 and not momento_sel:
            st.warning("Selecione o momento do dia (Manhã/Tarde/Noite).")
            st.stop()

        m = motivo_sel if gasto_val == 1 else ""
        mo = momento_sel if gasto_val == 1 else ""
        upsert_resposta(user_key, dt_ref, gasto_val, m, mo)
        st.rerun()

    # INSIGHTS
    st.markdown("---")
    st.markdown("## Insight")

    st.subheader("📅 Últimos 7 dias (Free)")
    ins7 = insight_ultimos_7_dias(user_key)
    if not ins7:
        st.write("Ainda não há dados suficientes para gerar insights.")
    else:
        txt = f"Nos últimos 7 dias, **{ins7['pct']}%** dos seus dias tiveram gasto não planejado."
        if ins7["top_motivo"]:
            txt += f" Motivo mais comum: **{ins7['top_motivo']}**."
        if ins7["top_momento"]:
            txt += f" Período mais comum: **{ins7['top_momento']}**."
        st.write(txt)

    st.markdown("---")
    st.subheader("💎 Premium")

    if not is_pro():
        st.info(
            "🔒 O Premium desbloqueia **insights de 30 e 90 dias**, **padrões fortes** (motivo + momento), "
            "**streak de hábito**, **histórico ilimitado** e **exportação CSV**."
        )
        st.caption("Vá na aba **Premium** para assinar.")
    else:
        ins30 = insight_periodo(user_key, 30)
        if ins30:
            st.markdown("### 📊 Últimos 30 dias")
            st.write(f"- **{ins30['pct']}%** dos dias tiveram gasto não planejado.")
            if ins30["top_motivos"]:
                st.write("**Motivos mais frequentes:**")
                for m, c in ins30["top_motivos"]:
                    st.write(f"- {m}: {c}x")
            if ins30["top_momentos"]:
                st.write("**Momentos mais frequentes:**")
                for m, c in ins30["top_momentos"]:
                    st.write(f"- {m}: {c}x")
            if ins30["top_combo"]:
                st.success(f"⚠️ **Padrão forte detectado:** {ins30['top_combo']}")

        ins90 = insight_periodo(user_key, 90)
        if ins90:
            st.markdown("### 📈 Últimos 90 dias")
            st.write(f"- **{ins90['pct']}%** dos dias tiveram gasto não planejado.")

        streak = calcular_streak(user_key)
        st.markdown("### 🔥 Seu streak")
        st.write(f"Você respondeu **{streak} dias seguidos**. Continue assim 👏")

    # HISTÓRICO
    st.markdown("---")
    st.markdown("## Histórico")

    # Free vê 30, Pro vê tudo
    hist_limit = 30 if not is_pro() else 3650
    hist = get_historico(user_key, limit=hist_limit)

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

        if not is_pro():
            st.warning("🔒 Histórico ilimitado disponível no Premium.")


def page_premium():
    st.markdown("## 💎 Premium")
    st.caption("Assinatura mensal para quem quer clareza e consistência, não só um registro.")

    if not st.session_state.auth:
        st.info("Faça login para ver seu plano e assinar o Premium.")
        return

    u = st.session_state.auth
    label = get_user_label(u)

    c1, c2 = st.columns([2, 3])
    with c1:
        st.markdown(f"### 👤 {label}")
        st.write(f"**Plano atual:** {'💎 Premium' if is_pro() else '🆓 Free'}")
        st.write(f"**Preço:** {PREMIUM_PRICE_TEXT}")

    with c2:
        st.markdown("### O que você destrava")
        st.write("- Insights de **30 e 90 dias**")
        st.write("- **Padrões fortes** (motivo + momento)")
        st.write("- **Streak** (dias seguidos respondendo)")
        st.write("- Histórico **ilimitado**")
        st.write("- Exportar **CSV**")

    st.markdown("---")

    if is_pro():
        st.success("Você já é Premium ✅")
        st.markdown("### 📥 Exportar seus dados (CSV)")
        csv_bytes = gerar_csv_historico(u["user_key"])
        st.download_button(
            label="Baixar histórico (CSV)",
            data=csv_bytes,
            file_name="antes_de_gastar_historico.csv",
            mime="text/csv",
        )
        st.caption("Dica: o CSV usa ';' como separador (melhor para Excel PT-BR).")
        return

    st.markdown("### Assinar Premium")
    if STRIPE_PAYMENT_LINK:
        st.link_button("Assinar com Stripe", STRIPE_PAYMENT_LINK)
        st.info(
            "Após o pagamento, seu plano pode levar alguns minutos para ser liberado. "
            "Se ainda estiver Free, envie seu email para o responsável liberar o Premium."
        )
    else:
        st.warning(
            "Payment Link do Stripe ainda não configurado.\n\n"
            "No Streamlit Cloud → Settings → Secrets, adicione:\n"
            "STRIPE_PAYMENT_LINK = \"https://buy.stripe.com/...\""
        )

    st.markdown("---")
    st.markdown("### 📌 Preview do Premium (sem desbloquear)")
    st.write("No Premium, você verá tendências de 30/90 dias, top motivos, top horários e padrões fortes.")


def page_admin():
    """
    Admin oculto:
    - Só aparece com ?admin=1
    - E exige ADMIN_PASSWORD
    """
    params = st.query_params
    if str(params.get("admin", "0")) != "1":
        return
    if not ADMIN_PASSWORD:
        return

    st.markdown("## Admin (restrito)")
    pwd = st.text_input("Senha de admin", type="password", key="admin_pwd")
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

    st.markdown("---")
    st.markdown("### Gerenciar plano (manual)")
    st.caption("Use isso para liberar Premium após pagamento no Stripe (fase inicial, sem webhook).")

    email = st.text_input("Email do usuário", key="admin_email_plan")
    plan = st.selectbox("Plano", ["free", "pro"], index=1, key="admin_plan_sel")
    if st.button("Atualizar plano", key="admin_plan_btn"):
        ok, msg = set_user_plan_by_email(email, plan)
        if ok:
            st.success(msg)
        else:
            st.error(msg)

    st.markdown("---")
    st.markdown("### Últimos 50 usuários")
    cur.execute("""
        SELECT email, COALESCE(apelido,''), COALESCE(plan,'free'), created_at
        FROM users
        ORDER BY created_at DESC
        LIMIT 50
    """)
    users = cur.fetchall()
    if users:
        for email, apelido, plan, created_at in users:
            who = apelido if apelido else email
            badge = "💎 pro" if plan == "pro" else "🆓 free"
            st.write(f"- **{who}** — {badge} — _{created_at}_")
    else:
        st.write("Sem usuários.")

    st.markdown("---")
    st.markdown("### Últimas 50 respostas (geral)")
    cur.execute("""
        SELECT r.dt_ref, u.email, COALESCE(u.apelido,''), COALESCE(u.plan,'free'),
               r.gasto_nao_planejado, COALESCE(r.motivo,''), COALESCE(r.momento,''), r.created_at
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
        for dt_ref, email, apelido, plan, gasto, motivo, momento, created_at in rows:
            who = apelido if apelido else email
            badge = "💎" if plan == "pro" else "🆓"
            status = "Sim" if int(gasto) == 1 else "Não"
            extra = []
            if motivo:
                extra.append(motivo)
            if momento:
                extra.append(momento)
            extra_txt = f" ({' / '.join(extra)})" if extra else ""
            st.write(f"- **{dt_ref}** — {badge} **{who}** — **{status}**{extra_txt} — _{created_at}_")


# =========================
# RENDER
# =========================
sidebar_account()
main_header()

tabs = st.tabs(["App", "Premium", "Reset"])
with tabs[0]:
    page_app()
with tabs[1]:
    page_premium()
with tabs[2]:
    page_reset_password()

# Admin invisível (só com ?admin=1)
page_admin()
