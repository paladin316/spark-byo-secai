# HP ZBook Phase 0 Build Design

## Target Host

TBD

## Recommended Stack

```text
TBD
Python: 3.11+
Package manager: uv or pip
API layer: OpenAI / Anthropic / Gemini SDKs
Local model support: Ollama
Database: SQLite for Phase 0
Vector store: ChromaDB or LanceDB
Document output: Markdown first
Optional UI: Streamlit
```

## Resource Strategy

Use external APIs for deep reasoning, long-form analysis, multi-agent synthesis, and report drafting.

Use local compute for prompt routing, JSON schema validation, parsing, evidence storage, query template rendering, and Markdown generation.

## Optional Local Models

```text
llama3.1:8b
mistral:7b
qwen2.5-coder:7b
phi3
```

## Avoid in Phase 0

```text
70B models
Heavy local RAG over massive corpora
Large multi-model concurrent execution
GPU-dependent pipelines
```
