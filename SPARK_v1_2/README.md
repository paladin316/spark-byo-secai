# SecAI — Phase 6.4 (ADS Alignment + Governance + Diff + Lifecycle)

This demo package implements the **v1.0 locked workflow** with a local-LLM swap-in via **Ollama** (no cloud calls).

## What’s included
- Streamlit MVP UI: **Dashboard → Intel Briefs → Hunt Packages → Runs → Findings → ADS → Artifacts/Export → Settings**
- Local-first storage (JSON + Markdown) under `./data/`
- Guardrail: **Hunt Package generation is blocked until an Intel Brief is marked Approved**
- LLM abstraction (`byo_secai/llm.py`)
  - `OllamaLLM`: calls your local Ollama server
  - `StubLLM`: deterministic fallback when Ollama is not reachable

## Quick start
1) Install dependencies
```bash
python -m venv .venv
source .venv/bin/activate  # Windows: .venv\\Scripts\\activate
pip install -r requirements.txt
```

2) Ensure Ollama is running (optional but recommended)
- Default host: `http://localhost:11434`
- Pull a model, for example:
```bash
ollama pull llama3.1
```

3) Run the app
```bash
streamlit run app.py
```

## Ollama settings
Open **Settings** and set:
- Ollama Host (default: `http://localhost:11434`)
- Model (default: `llama3.1`)
- Temperature

If Ollama is down/unreachable, the app continues in **stub mode**.

## Data
Artifacts are stored in:
- `./data/artifacts/...` (JSON)
- `./data/exports/...` (Markdown exports)

To reset demo state, delete the `data/` directory.

## Fix 7 notes (template + performance)
- Intel Brief generation is **template-locked** to the v1.0 section order (reduces drift).
- Optional URL fetch/extract is **cached** to keep view switching fast.
- Common model preambles (e.g., "Thinking...") are stripped from saved artifacts.
- Default max source extract is **6000** chars for snappy UX (adjustable in Settings).


## Phase 5.4.8 (V1 hardening)
- Cached index/listing via st.cache_data
- Global _index.json maintained on save
- Lazy-load per view (via indexed listing)
- Intel/Hunt preview uses deterministic rendered report from Draft
- LLM output moved to Assistant Suggestions sidecar (.assistant.json)
- Export uses same deterministic renderer output
