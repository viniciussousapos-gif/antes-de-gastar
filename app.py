# app.py
import sqlite3
from datetime import datetime, timedelta
from zoneinfo import ZoneInfo

import streamlit as st

DB_PATH = "por_que_gastei.db"

MOTIVOS = [
    "Impulso",
    "Ansiedade / estresse",
    'Recompensa ("eu mereço")',
    "Pressão social",
    "Conveniência",
    "Outro",
]

MOMENTOS = ["Manhã", "Tarde", "Noite"]

# Fuso fixo (evita “dia errado” quando rodar em servidor)
TZ = ZoneInfo("America/Sao_Paulo")


def hoje_sp() -> str:
    return datetime.now(TZ).date().isoformat()  # YYYY-MM-DD


def agora_sp() -> str:
    return datetime.now(TZ).isoformat(timespec="seconds")


# -----------------------------
# Banco (SQLite)
# -----------------------------
def get_conn():
    return sqlite3.connect(DB_PATH, check_same_thread=False)


def table_exists(conn: sqlite3.Connection, table: str) -> bool:
    cur = conn.cursor()
    cur.execute(
        "SELECT name FROM sqlite_master WHERE type='table' AND name=?",
        (table,),
    )
    return cur.fetchone() is not None


def ensure_column(conn: sqlite3.Connection, table: str, column: str, coltype: str):
    """Garante que a coluna existe (migração simples para)."""
    if not table_exists(conn, table):
        return
    cur = conn.cursor()
    cur.execute(f"PRAGMA table_info({table})")
    cols = [r[1] for r in cur.fetchall()]  # name is index 1
    if column not in cols:
        cur.execute(f"ALTER TABLE {table} ADD COLUMN {column} {coltype}")
        conn.commit()


def init_db():
    conn = get_conn()
    cur = conn.cursor()

    # Tabela “nova” já com updated_at
    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS respostas (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id TEXT NOT NULL,
            dt_ref TEXT NOT NULL,                  -- YYYY-MM-DD
            gasto_nao_planejado INTEGER NOT NULL,  -- 0/1
            motivo TEXT,
            momento TEXT,
            created_at TEXT NOT NULL,              -- ISO
            updated_at TEXT NOT NULL,              -- ISO
            UNIQUE(user_id, dt_ref)
        )
        """
    )
    conn.commit()

    # Migrações defensivas (caso você tenha rodado versões anteriores)
    ensure_column(conn, "respostas", "motivo", "TEXT")
    ensure_column(conn, "respostas", "momento", "TEXT")
    ensure_column(conn, "respostas", "created_at", "TEXT")
    ensure_column(conn, "respostas", "updated_at", "TEXT")

    # Preenche updated_at para bases antigas
    cur.execute(
        """
        UPDATE respostas
           SET updated_at = COALESCE(updated_at, created_at, ?)
         WHERE updated_at IS NULL OR updated_at = ''
        """,
        (agora_sp(),),
    )
    # Preenche created_at se por algum motivo estiver vazio
    cur.execute(
        """
        UPDATE respostas
           SET created_at = COALESCE(created_at, updated_at, ?)
         WHERE created_at IS NULL OR created_at = ''
        """,
        (agora_sp(),),
    )
    conn.commit()
    conn.close()


def upsert_resposta(
    user_id: str,
    dt_ref: str,
    gasto_nao_planejado: int,
    motivo: str | None,
    momento: str | None,
):
    """
    - created_at: só na primeira gravação
    - updated_at: sempre que salva (inclusive edição)
    """
    conn = get_conn()
    cur = conn.cursor()

    now = agora_sp()
    cur.execute(
        """
        INSERT INTO respostas (user_id, dt_ref, gasto_nao_planejado, motivo, momento, created_at, updated_at)
        VALUES (?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(user_id, dt_ref) DO UPDATE SET
            gasto_nao_planejado=excluded.gasto_nao_planejado,
            motivo=excluded.motivo,
            momento=excluded.momento,
            updated_at=excluded.updated_at
        """,
        (user_id, dt_ref, gasto_nao_planejado, motivo, momento, now, now),
    )
    conn.commit()
    conn.close()


def get_resposta_do_dia(user_id: str, dt_ref: str):
    """
    Retorna: (0/1, motivo, momento, created_at, updated_at) ou None
    """
    conn = get_conn()
    cur = conn.cursor()
    cur.execute(
        """
        SELECT gasto_nao_planejado,
               COALESCE(motivo,''),
               COALESCE(momento,''),
               COALESCE(created_at,''),
               COALESCE(updated_at,'')
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
        SELECT dt_ref,
               gasto_nao_planejado,
               COALESCE(motivo,'')  AS motivo,
               COALESCE(momento,'') AS momento,
               COALESCE(created_at,'') AS created_at,
               COALESCE(updated_at,'') AS updated_at
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


def get_ultimos_7_dias(user_id: str):
    hoje = datetime.now(TZ).date()
    dt_ini = (hoje - timedelta(days=6)).isoformat()
    dt_fim = hoje.isoformat()

    conn = get_conn()
    cur = conn.cursor()
    cur.execute(
        """
        SELECT dt_ref, gasto_nao_planejado, motivo, momento
        FROM respostas
        WHERE user_id = ?
          AND dt_ref BETWEEN ? AND ?
        ORDER BY dt_ref ASC
        """,
        (user_id, dt_ini, dt_fim),
    )
    rows = cur.fetchall()
    conn.close()
    return rows


# -----------------------------
# Insights
# -----------------------------
def analisar_7d(rows_7d):
    total = len(rows_7d)
    nao_planejados = [r for r in rows_7d if int(r[1]) == 1]

    cont_motivo = {}
    cont_momento = {}
    for _, _, motivo, momento in nao_planejados:
        m = (motivo or "Não informado").strip() or "Não informado"
        cont_motivo[m] = cont_motivo.get(m, 0) + 1

        t = (momento or "Não informado").strip() or "Não informado"
        cont_momento[t] = cont_momento.get(t, 0) + 1

    top_motivo = max(cont_motivo.items(), key=lambda x: x[1])[0] if cont_motivo else "Não informado"
    top_momento = max(cont_momento.items(), key=lambda x: x[1])[0] if cont_momento else "Não informado"

    return {
        "total": total,
        "nao_planejados": len(nao_planejados),
        "top_motivo": top_motivo,
        "top_momento": top_momento,
    }


def gerar_insight_7d(rows_7d):
    # Texto sem “100% dos dias”
    if not rows_7d:
        return "Ainda não há dados suficientes para gerar insights. Responda a pergunta diária para começar."

    stats = analisar_7d(rows_7d)

    if stats["nao_planejados"] == 0:
        return "Ótimo sinal! Nos últimos dias, você não registrou gastos não planejados."

    msg = (
        "Nos últimos 7 dias, seus registros indicam um padrão recorrente de gastos não planejados, "
        f"principalmente relacionados à **{stats['top_motivo'].lower()}**."
    )
    if stats["top_momento"] != "Não informado":
        msg += f" Esses episódios tendem a acontecer mais no período da **{stats['top_momento'].lower()}**."
    msg += " Identificar o momento certo abre espaço para escolhas diferentes."
    return msg


# -------- Premium REAL: Padrão de risco recorrente --------
def detectar_padrao_recorrente(rows_7d):
    """
    Retorna (motivo, momento, qtd) se houver padrão recorrente (>=2),
    senão retorna None.
    Considera apenas gasto_nao_planejado=1.
    """
    cont = {}
    for _, gasto_np, motivo, momento in rows_7d:
        if int(gasto_np) != 1:
            continue
        if not motivo or not momento:
            continue
        chave = (motivo.strip(), momento.strip())
        cont[chave] = cont.get(chave, 0) + 1

    if not cont:
        return None

    (motivo, momento), qtd = max(cont.items(), key=lambda x: x[1])
    if qtd >= 2:
        return motivo, momento, qtd
    return None


def gerar_insight_premium(rows_7d):
    """
    Retorna dict:
      {"status": "locked"|"unlocked", "texto": "..."}
    """
    if not rows_7d or len(rows_7d) < 3:
        return {
            "status": "locked",
            "texto": "Complete 3 registros para começarmos a detectar combinações (ex: motivo + momento).",
        }

    padrao = detectar_padrao_recorrente(rows_7d)
    if not padrao:
        return {
            "status": "locked",
            "texto": "Ainda não há padrões recorrentes suficientes para gerar um insight avançado.",
        }

    motivo, momento, qtd = padrao

    texto = (
        "**Padrão de risco recorrente identificado**\n\n"
        f"Nos últimos 7 dias, a combinação **{motivo.lower()} + {momento.lower()}** apareceu **{qtd}x**.\n\n"
        f"Isso sugere que seus gastos não planejados tendem a se repetir quando envolvem **{motivo.lower()}** "
        f"no período da **{momento.lower()}**.\n\n"
        "Criar uma pausa consciente nesse horário pode ajudar a reduzir decisões automáticas."
    )

    return {"status": "unlocked", "texto": texto}


# -----------------------------
# UI helpers
# -----------------------------
def idx_or_default(options: list[str], value: str, default: int = 0) -> int:
    try:
        return options.index(value)
    except ValueError:
        return default


# -----------------------------
# UI (Streamlit)
# -----------------------------
def main():
    st.set_page_config(page_title="Antes de Gastar", page_icon="💸", layout="centered")
    init_db()

    st.title("💸 Antes de Gastar")
    st.caption("Antes de gastar, entenda o porquê. 1 pergunta por dia → padrões simples → mais consciência.")

    with st.sidebar:
        st.header("Perfil")
        user_id = st.text_input("Seu identificador (ex: email ou apelido)", value="vinicius")
        st.divider()
        st.write("Dica: use sempre o mesmo identificador para manter seu histórico.")

    user_id = (user_id or "").strip()
    if not user_id:
        st.warning("Informe um identificador no menu lateral para continuar.")
        st.stop()

    hoje = hoje_sp()
    ja = get_resposta_do_dia(user_id, hoje)

    # defaults para edição
    default_resposta = "Não"
    motivo_salvo = ""
    momento_salvo = ""
    created_at_salvo = ""
    updated_at_salvo = ""

    if ja:
        gasto_np, motivo_salvo, momento_salvo, created_at_salvo, updated_at_salvo = ja
        default_resposta = "Sim" if int(gasto_np) == 1 else "Não"

    st.subheader("Pergunta de hoje")
    st.write("**Hoje você gastou com algo que não planejava?**")

    if ja:
        msg = f"Resposta registrada hoje em {created_at_salvo}."
        if updated_at_salvo and updated_at_salvo != created_at_salvo:
            msg += f" Última atualização: {updated_at_salvo}."
        msg += " Você pode editar e salvar novamente se quiser."
        st.info(msg)

    resposta = st.radio("Escolha uma opção:", ["Não", "Sim"], index=0 if default_resposta == "Não" else 1)

    motivo = None
    momento = None

    if resposta == "Sim":
        motivo = st.selectbox(
            "O que mais influenciou esse gasto?",
            MOTIVOS,
            index=idx_or_default(MOTIVOS, motivo_salvo, default=0),
        )

        momento = st.radio(
            "Em que momento do dia isso aconteceu?",
            MOMENTOS,
            index=idx_or_default(MOMENTOS, momento_salvo, default=0),
            horizontal=True,
        )

        st.caption(
            "Sugestão: antes do próximo gasto, faça uma pausa curta e pergunte "
            "“isso resolve o que eu estou sentindo agora?”"
        )

    if st.button("Salvar resposta", type="primary"):
        upsert_resposta(
            user_id=user_id,
            dt_ref=hoje,
            gasto_nao_planejado=1 if resposta == "Sim" else 0,
            motivo=motivo,
            momento=momento,
        )
        st.success("Salvo! ✅")
        st.rerun()

    st.divider()

    # --------- Insights ---------
    st.subheader("Insight (últimos 7 dias)")
    rows_7d = get_ultimos_7_dias(user_id)
    st.write(gerar_insight_7d(rows_7d))

    st.markdown("### 🔒 Insight avançado")
    premium = gerar_insight_premium(rows_7d)

    if premium["status"] == "locked":
        st.info(premium["texto"])
    else:
        st.success(premium["texto"])

    st.divider()

    # --------- Histórico ---------
    st.subheader("Histórico")
    hist = get_historico(user_id, limit=60)
    if not hist:
        st.write("Sem histórico ainda. Responda a pergunta de hoje 🙂")
    else:
        for dt_ref, gasto_np, motivo_h, momento_h, created_at, updated_at in hist:
            badge = "✅ Sim" if int(gasto_np) == 1 else "❌ Não"
            linha = f"**{dt_ref}** — {badge}"

            if int(gasto_np) == 1:
                if motivo_h:
                    linha += f" · _{motivo_h}_"
                if momento_h:
                    linha += f" ({momento_h.lower()})"

            st.write(linha)

            if updated_at and updated_at != created_at:
                st.caption(f"Criado em: {created_at} · Atualizado em: {updated_at}")
            else:
                st.caption(f"Registrado em: {created_at}")


if __name__ == "__main__":
    main()
