# app.py
import sqlite3
from datetime import datetime, date, timedelta
from zoneinfo import ZoneInfo

import streamlit as st

# =========================
# Configuração da página (aba do navegador)
# =========================
st.set_page_config(
    page_title="Antes de Gastar",
    page_icon="🧠",
    layout="centered",
)

# =========================
# Ajustes gerais
# =========================
TZ = ZoneInfo("America/Sao_Paulo")
DB_PATH = "por_que_gastei.db"

# Troque para uma senha sua (e evite compartilhar)
ADMIN_PASSWORD = "admin123"


# =========================
# Banco de dados (SQLite)
# =========================
def get_conn():
    return sqlite3.connect(DB_PATH, check_same_thread=False)


def init_db():
    conn = get_conn()
    cur = conn.cursor()
    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS respostas (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id TEXT NOT NULL,
            dt_ref TEXT NOT NULL,                -- YYYY-MM-DD
            gasto_nao_planejado INTEGER NOT NULL, -- 0/1
            motivo TEXT,
            momento TEXT,
            created_at TEXT NOT NULL,            -- ISO datetime com timezone
            updated_at TEXT NOT NULL             -- ISO datetime com timezone
        );
        """
    )
    cur.execute(
        """
        CREATE UNIQUE INDEX IF NOT EXISTS ux_respostas_user_dia
        ON respostas(user_id, dt_ref);
        """
    )
    conn.commit()
    conn.close()


def upsert_resposta(user_id: str, dt_ref: str, gasto: int, motivo: str | None, momento: str | None):
    now = datetime.now(TZ).isoformat(timespec="seconds")
    conn = get_conn()
    cur = conn.cursor()

    # UPSERT pelo índice único (user_id, dt_ref)
    cur.execute(
        """
        INSERT INTO respostas (user_id, dt_ref, gasto_nao_planejado, motivo, momento, created_at, updated_at)
        VALUES (?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(user_id, dt_ref) DO UPDATE SET
            gasto_nao_planejado = excluded.gasto_nao_planejado,
            motivo = excluded.motivo,
            momento = excluded.momento,
            updated_at = excluded.updated_at
        """,
        (user_id, dt_ref, gasto, motivo, momento, now, now),
    )
    conn.commit()
    conn.close()


def get_resposta_do_dia(user_id: str, dt_ref: str):
    conn = get_conn()
    cur = conn.cursor()
    cur.execute(
        """
        SELECT dt_ref, gasto_nao_planejado, COALESCE(motivo,''), COALESCE(momento,''), created_at, updated_at
        FROM respostas
        WHERE user_id = ? AND dt_ref = ?
        """,
        (user_id, dt_ref),
    )
    row = cur.fetchone()
    conn.close()
    return row


def get_historico(user_id: str, limit: int = 60):
    conn = get_conn()
    cur = conn.cursor()
    cur.execute(
        """
        SELECT dt_ref, gasto_nao_planejado, COALESCE(motivo,''), COALESCE(momento,''), created_at
        FROM respostas
        WHERE user_id = ?
        ORDER BY dt_ref DESC
        LIMIT ?
        """,
        (user_id, limit),
    )
    rows = cur.fetchall()
    conn.close()
    return rows


def get_ultimos_dias(user_id: str, dias: int = 7):
    # pega registros nos últimos "dias" (calendário)
    fim = date.today()
    inicio = fim - timedelta(days=dias - 1)
    conn = get_conn()
    cur = conn.cursor()
    cur.execute(
        """
        SELECT dt_ref, gasto_nao_planejado, COALESCE(motivo,''), COALESCE(momento,'')
        FROM respostas
        WHERE user_id = ?
          AND date(dt_ref) BETWEEN date(?) AND date(?)
        ORDER BY dt_ref ASC
        """,
        (user_id, inicio.isoformat(), fim.isoformat()),
    )
    rows = cur.fetchall()
    conn.close()
    return rows


# =========================
# Insights
# =========================
def insight_7_dias(rows_7d):
    """
    rows_7d: list[(dt_ref, gasto, motivo, momento)]
    Retorna texto de insight e principais frequências.
    """
    if not rows_7d:
        return None

    total = len(rows_7d)
    dias_com_gasto = sum(1 for r in rows_7d if int(r[1]) == 1)

    # Frequências (somente quando gasto=1)
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

    pct = round((dias_com_gasto / total) * 100) if total else 0

    partes = []
    partes.append(
        f"Nos últimos 7 dias, seus registros indicam um padrão de gastos não planejados em **{pct}%** dos dias respondidos."
    )

    if motivo_top:
        partes.append(f"O motivo mais comum foi **{motivo_top}**.")
    if momento_top:
        partes.append(f"Esses episódios tendem a acontecer mais no período da **{momento_top.lower()}**.")

    partes.append("Perceber o padrão é o primeiro passo para mudar.")

    return " ".join(partes), motivo_top, momento_top


def sugestao_por_motivo(motivo_top: str | None):
    if not motivo_top:
        return "Antes do próximo gasto, faça uma pausa curta e pergunte: “isso resolve o que eu estou sentindo agora?”"

    m = motivo_top.lower()
    if "pressão" in m:
        return "Antes do próximo gasto, respire 10s e pergunte: “eu compraria isso se ninguém estivesse olhando?”"
    if "recompensa" in m or "eu mereço" in m:
        return "Antes do próximo gasto, pergunte: “qual recompensa menor (e suficiente) eu posso escolher agora?”"
    if "ansiedade" in m or "estresse" in m:
        return "Antes do próximo gasto, tente uma pausa de 60s (água + respiração) e veja se a vontade diminui."
    if "tédio" in m:
        return "Antes do próximo gasto, escolha uma ação alternativa de 2 minutos (andar, alongar, música) e reavalie."
    return "Antes do próximo gasto, faça uma pausa curta e pergunte: “isso resolve o que eu estou sentindo agora?”"


def insight_avancado(user_id: str):
    """
    Libera quando houver >= 3 registros totais.
    Detecta combinação mais comum (motivo + momento) quando gasto=1.
    """
    conn = get_conn()
    cur = conn.cursor()

    cur.execute("SELECT COUNT(1) FROM respostas WHERE user_id = ?", (user_id,))
    total = int(cur.fetchone()[0])

    if total < 3:
        conn.close()
        return None, total

    cur.execute(
        """
        SELECT COALESCE(motivo,''), COALESCE(momento,''), COUNT(1) as qtd
        FROM respostas
        WHERE user_id = ?
          AND gasto_nao_planejado = 1
          AND COALESCE(motivo,'') <> ''
          AND COALESCE(momento,'') <> ''
        GROUP BY COALESCE(motivo,''), COALESCE(momento,'')
        ORDER BY qtd DESC
        LIMIT 1
        """,
        (user_id,),
    )
    row = cur.fetchone()
    conn.close()

    if not row:
        return "Você já tem registros suficientes. Continue preenchendo para detectarmos combinações (motivo + momento).", total

    motivo, momento, qtd = row
    txt = (
        f"Combinação mais recorrente (quando há gasto não planejado): "
        f"**{motivo}** + **{momento.lower()}** (ocorreu **{qtd}x**). "
        f"Tente preparar uma alternativa rápida para esse momento específico."
    )
    return txt, total


# =========================
# App UI
# =========================
init_db()

st.markdown("## 🧠 Antes de Gastar")
st.caption("Antes de gastar, entenda o porquê. 1 pergunta por dia → padrões simples → mais consciência.")

# Sidebar perfil
st.sidebar.header("Perfil")
user_id = st.sidebar.text_input("Seu identificador (ex: email ou apelido)", value="").strip()
st.sidebar.caption("Dica: use sempre o mesmo identificador para manter seu histórico.")

if not user_id:
    st.info("Digite seu identificador na barra lateral para começar.")
    st.stop()

# Data de referência do dia (no fuso BR)
hoje = datetime.now(TZ).date()
dt_ref = hoje.isoformat()

st.markdown("---")
st.subheader("Pergunta de hoje")
st.write("**Hoje você gastou com algo que não planejava?**")

# Carrega resposta do dia, se existir
row = get_resposta_do_dia(user_id, dt_ref)

# Defaults do formulário
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

# Form
col1, col2 = st.columns([1, 2])

with col1:
    gasto_txt = st.radio(
        "Escolha uma opção:",
        options=["Não", "Sim"],
        index=1 if default_gasto == 1 else 0,
        key="gasto_radio",
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

momento_opcoes = ["", "Manhã", "Tarde", "Noite"]

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
else:
    # se não gastou, limpa motivo/momento no banco
    motivo = ""
    momento = ""

sug = sugestao_por_motivo(default_motivo if default_motivo else None) if gasto == 1 else "Ótimo. Manter consistência também é um padrão."
st.caption(f"Sugestão: {sug}")

if st.button("Salvar resposta", type="primary"):
    # validação simples
    if gasto == 1 and not motivo:
        st.warning("Selecione um motivo para salvar.")
    else:
        upsert_resposta(user_id=user_id, dt_ref=dt_ref, gasto=gasto, motivo=motivo or None, momento=momento or None)
        st.success("Resposta salva!")
        st.rerun()

# Insights
st.markdown("---")
st.subheader("Insight (últimos 7 dias)")

rows_7d = get_ultimos_dias(user_id, dias=7)
ins = insight_7_dias(rows_7d)

if not ins:
    st.write("Ainda não há dados suficientes para gerar insights. Responda a pergunta diária para começar.")
else:
    texto, motivo_top, momento_top = ins
    st.write(texto)

# Insight avançado (bloqueado)
st.subheader("🔒 Insight avançado")
txt_adv, total_regs = insight_avancado(user_id)

if txt_adv is None:
    st.info("Complete **3 registros** para começarmos a detectar combinações (ex: motivo + momento).")
else:
    st.write(txt_adv)
    st.caption(f"Total de registros: {total_regs}")

# Histórico
st.markdown("---")
st.subheader("Histórico")
hist = get_historico(user_id, limit=60)

if not hist:
    st.write("Sem histórico ainda. Responda a pergunta de hoje 🙂")
else:
    # exibe compacto
    for dt_ref_i, gasto_i, motivo_i, momento_i, created_at_i in hist[:20]:
        status = "✅ Sim" if int(gasto_i) == 1 else "⬜ Não"
        extra = []
        if motivo_i:
            extra.append(motivo_i)
        if momento_i:
            extra.append(momento_i.lower())
        extra_txt = f" • " + " • ".join(extra) if extra else ""
        st.write(f"**{dt_ref_i}** — {status}{extra_txt}")

    if len(hist) > 20:
        with st.expander("Ver mais"):
            for dt_ref_i, gasto_i, motivo_i, momento_i, created_at_i in hist[20:]:
                status = "✅ Sim" if int(gasto_i) == 1 else "⬜ Não"
                extra = []
                if motivo_i:
                    extra.append(motivo_i)
                if momento_i:
                    extra.append(momento_i.lower())
                extra_txt = f" • " + " • ".join(extra) if extra else ""
                st.write(f"**{dt_ref_i}** — {status}{extra_txt}")

# =========================
# Admin invisível (via query param)
# =========================
params = st.query_params
is_admin_route = params.get("admin") == "1"

if is_admin_route:
    st.markdown("---")
    st.subheader("🔒 Área administrativa")

    senha = st.text_input("Senha admin", type="password")

    if senha:
        if senha == ADMIN_PASSWORD:
            st.success("Acesso liberado.")

            conn = get_conn()
            cur = conn.cursor()

            cur.execute("SELECT COUNT(1) FROM respostas")
            total_all = int(cur.fetchone()[0])

            cur.execute(
                """
                SELECT user_id, dt_ref, gasto_nao_planejado, 
                       COALESCE(motivo,''), COALESCE(momento,''), 
                       created_at, updated_at
                FROM respostas
                ORDER BY updated_at DESC
                LIMIT 50
                """
            )
            rows = cur.fetchall()
            conn.close()

            st.write(f"**Total de respostas (todos os usuários): {total_all}**")

            st.dataframe(
                rows,
                use_container_width=True,
                column_config={
                    0: "user_id",
                    1: "dt_ref",
                    2: "gasto",
                    3: "motivo",
                    4: "momento",
                    5: "created_at",
                    6: "updated_at",
                },
            )
        else:
            st.error("Senha incorreta.")
