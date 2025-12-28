# Antes de Gastar 🧠

Um mini-app (Streamlit) para registrar **1 pergunta por dia** sobre gastos não planejados e gerar **insights simples**.

## ✅ O que o app faz
- Cadastro e login por **email + senha**
- Registro diário:
  - “Hoje você gastou com algo que não planejava?” (Sim/Não)
  - Se **Sim**, salva: **motivo** e **momento do dia**
- Mostra:
  - **Insight dos últimos 7 dias**
  - **Histórico** (últimos 30 dias)
- Área **Admin** (oculta):
  - Só acessa com `?admin=1` + senha de admin via Secrets

---

## 📦 Requisitos
- Python 3.10+ (recomendado)
- Streamlit

Instalação:
```bash
pip install streamlit
