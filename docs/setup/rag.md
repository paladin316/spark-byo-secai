# RAG (Retrieval-Augmented Generation) Setup

This document explains how **Retrieval-Augmented Generation (RAG)** is configured and used in **SPARK (Powered by BYO-SECAI)**.

RAG is designed to **augment analyst thinking**, not replace validation, approvals, or detection logic.

---

## What RAG Means in SPARK

In SPARK, RAG provides **local recall** of previously ingested material to support:

- Analyst exploration
- Context building
- Narrative synthesis
- Technical recall during investigations

RAG is intentionally scoped to the **Notebook Workspace**.

---

## What RAG Is Used For

✔ Supporting analyst reasoning during exploration  
✔ Recalling relevant documents, reports, and notes  
✔ Providing context when drafting or refining content  
✔ Helping analysts connect related material across sources  

---

## What RAG Is *Not* Used For

✘ Automatic generation of production artifacts  
✘ Bypassing Platform Workspace approvals  
✘ Silent enrichment of Intel Briefs, Hunt Packages, Findings, or ADS  
✘ Autonomous decision-making  

All Platform Workspace artifacts remain governed by **contracts, validation, and explicit analyst approval**.

---

## Current RAG Configuration

You currently have RAG enabled with the following settings:

```yaml
rag_enabled: true
rag_top_k: 6
rag_chunk_chars: 1200
rag_overlap_chars: 200
data_dir: data
```

---

## Configuration Options Explained

- `rag_enabled`  
  Enables or disables RAG entirely.

- `rag_top_k`  
  Number of retrieved chunks injected into context during recall.

- `rag_chunk_chars`  
  Size (in characters) used when splitting documents during ingestion.

- `rag_overlap_chars`  
  Overlap between chunks to preserve continuity across boundaries.

- `data_dir`  
  Local directory where SPARK stores RAG data and supporting state.

---

## Practical Tuning Guidance

- **Answers feel thin or incomplete**  
  → Increase `rag_top_k` (e.g., 8–12)

- **Retrieved context feels off-topic or noisy**  
  → Reduce `rag_chunk_chars` (e.g., 800–1000)  
  → Optionally reduce `rag_top_k`

- **Highly technical documents (tables, IOC lists, configs)**  
  → Slightly smaller chunks often retrieve more precisely

There is no universally “correct” setting—tuning should reflect document structure and analyst workflow.

---

## Local Storage & Source Control Hygiene

All RAG data is stored locally under the configured directory:

```yaml
data_dir: data
```

This directory may contain:

- Embedded document chunks
- Metadata
- Cached context

**Recommendation:** treat this directory as **local analyst working state**. It is intentionally not designed to be shared, versioned, or promoted.

If you are using Git, add the directory to your **repo root** `.gitignore` (not under `docs/`), for example:

```gitignore
# SPARK local analyst state (RAG, cache, embeddings)
data/
```

---

## RAG & the SPARK Trust Model

RAG operates under the same principles as the rest of SPARK:

- Local-first by default
- Explicit configuration
- Transparent behavior
- Analyst-driven outcomes

RAG **supports thinking** — it does not make decisions.

For broader configuration context, see:

- `docs/setup/configuration.md`
- `docs/setup/settings-reference.md`
