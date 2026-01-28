
<p align="center">
  <img src="assets/branding/spark_logo_primary.svg" width="380" alt="SPARK (Powered by BYO-SECAI)">
</p>

---

# SPARK — Security Playbook for Analytics, Research, and Knowledge

*(Powered by BYO-SECAI)*

**SPARK (Security Playbook for Analytics, Research, and Knowledge)** is an analyst-driven, open-source platform that applies AI as an **augmentation layer** to transform threat intelligence into executable threat hunts, findings, and detection strategies — end to end.

SPARK is built for threat hunters, detection engineers, and incident responders who want to move faster **without sacrificing transparency, control, or judgment**.

---

## Why SPARK Exists

Threat intelligence is abundant — but operational outcomes are not.

Security teams routinely collect reports, advisories, and indicators, yet the translation from **intelligence → hunt → finding → detection** is often manual, inconsistent, and lost over time. Context fades, assumptions disappear, and detections become disconnected from the intelligence that justified them.

SPARK exists to close this gap by preserving **analyst reasoning, traceability, and intent** while using AI to reduce mechanical effort — **not replace judgment**.

**AI in SPARK is RAG-based and content-agnostic:** no bundled corpus, no internet inference—only analyst-provided knowledge.

---

## Threat Hunting Philosophy

SPARK is built on a practitioner-driven threat hunting philosophy that emphasizes behavioral analysis, hypothesis-driven hunts, and durable detection outcomes.

Rather than focusing on alerts or IOCs alone, SPARK is designed to support hunting “in the gaps” — where advanced threats operate.

See [`docs/01_concepts/threat-hunting-philosophy.md`](docs/01_concepts/threat-hunting-philosophy.md) for details.

For a deeper explanation of how SPARK defines and operationalizes intelligence, see
[`Operational Threat Intelligence`](docs/01_concepts/operational-threat-intelligence.md).

---

## What SPARK Is (and Is Not)

### SPARK is:

* **Analyst-driven and review-first**: Human judgment is the final word.
* **AI-augmented, not AI-authoritative**: AI assists; it does not decide.
* **Traceable**: Every detection is linked back to the original intelligence.
* **Local-first**: Designed for auditability and privacy.

### SPARK is not:

* An autonomous SOC or alerting engine.
* A black-box AI decision system.
* An IOC-only detection platform.
* A replacement for analyst expertise.

SPARK uses opinionated terminology to preserve analytical intent and traceability.
See [`Terminology`](docs/01_concepts/terminology.md) for definitions used throughout the project.

## Documentation
- 📘 [Concepts & Philosophy](docs/01_concepts/)
- 🧠 [Architecture & Design](docs/architecture/)
- 🧩 [Templates](docs/templates/)
- 🚀 [Demo & Examples](docs/demo/)
- 🔧 [Setup & Configuration](docs/setup/)
- 🔐 [Security](SECURITY.md)
- 🗺️ [Roadmap](ROADMAP.md)

---
## How SPARK Works

SPARK operationalizes threat intelligence through a structured, analyst-driven lifecycle
that transforms raw research into validated detections.

<p align="center">
  <img src="/docs/images/spark-process-lifecycle.png" alt="SPARK process lifecycle">
</p>
Each phase is designed to preserve context, enforce validation, and maintain auditability.

---

## Retrieval-Augmented Generation (RAG) Model

SPARK uses a **Retrieval-Augmented Generation (RAG)** approach to ensure AI assistance is grounded in analyst-provided context.

### What This Means

AI suggestions in SPARK are generated exclusively from **locally available, analyst-approved artifacts**, such as Intel Briefs, Hunt Packages, Findings, Detection Strategy documents, and other user-ingested materials.

SPARK **does not ship with a pre-loaded knowledge base** and does **not rely on general internet knowledge** to infer detections or generate content. The quality and relevance of AI output is directly tied to the content you choose to provide.

### Why This Matters

- **Reduces hallucinations** – AI stays within the bounds of known, reviewable material
    
- **Preserves intent** – Outputs remain explainable, auditable, and analyst-owned
    
- **Repeatable** – Enables consistent hunt and detection development across workflows
    
- **Environment-specific** – Intelligence reflects _your_ tooling, threats, and priorities
    

### Content Responsibility (Bring Your Own Knowledge)

SPARK is intentionally content-agnostic. Users are expected to ingest their own material, which may include internal documentation, public threat reports, detection rule repositories, or open-source threat hunting resources. This design avoids licensing issues, prevents stale or generic intelligence, and keeps SPARK aligned to real operational needs.

> **Note:** SPARK may recommend open-source intelligence or detection repositories as optional starter material, but all ingestion is user-initiated and user-controlled.

For guidance on sourcing and organizing RAG content, see  
[`docs/getting-started/rag-starter-content.md`](docs/getting-started/rag-starter-content.md)

---

## Analyst Workspace

SPARK provides a persistent **Analyst Workspace** that acts as the connective tissue between intelligence, hunts, findings, and detections. Think of the **Notebook Workspace** as a threat intelligence that tracks analytical decisions and assumptions over time.

SPARK includes a **chat-first Notebook Workspace** for exploratory analysis and reasoning, and a **platform Workspace model** that governs artifact lifecycle, traceability, and promotion from intelligence to detection.

### Workspace Flow (High Level)

Notebook Workspace (analysis & reasoning)
        ↓
Platform Workspace (validated artifacts & lifecycle)

See `docs/architecture/workspace-chat-notebook.md` and `docs/architecture/workspace-platform.md` for details.

For architectural details, see `docs/architecture/`.


---

## SPARK in Action (Quick Walkthrough)

The following examples show how SPARK supports analysts from intelligence through detection — without black-box automation.

### Structured Threat Intelligence

![SPARK Intel Demo](docs/assets/demo-intel.gif)

SPARK transforms raw operational intelligence into a structured, analyst-validated
threat report.

Indicators, narrative context, and MITRE ATT&CK techniques are preserved together,
ensuring intelligence remains explainable, auditable, and directly usable for downstream
hunting and detection engineering — not trapped in PDFs or disconnected notes.

---

### Structured Threat Hunting

![SPARK Hunt Demo](docs/assets/demo-hunt.gif)

SPARK translates threat intelligence into a structured threat hunt package, capturing
hypotheses, scope, data sources, and queries in a single, repeatable artifact.

Hunts are executed deliberately, with analyst judgment preserved at every step —
enabling clear documentation of decisions, results, and findings without collapsing
context or over-automating conclusions.

---

### Detection Strategy Authoring

![SPARK ADS Demo](docs/assets/demo-ads.gif)

SPARK closes the loop by transforming validated findings into actionable detection
strategies.

Detection logic, observed TTPs, response guidance, and known blind spots are documented
together, ensuring detections are explainable, portable, and ready for downstream
deployment in SIEM or EDR platforms.

---

## Security & Network Controls

### Local-First by Design

* No cloud LLM required by default.
* Compatible with **local LLMs** (e.g., Ollama).
* No hidden telemetry or automatic data exfiltration.

### Prompt Injection Awareness

SPARK includes lightweight defenses to identify instruction-like patterns in security advisories that may influence AI workflows. These risk-rated signals (Low/Medium/High) are designed to **inform analysts**, not block workflows.

### Proxy Support

SPARK supports optional, user-configured outbound proxy settings for restricted enterprise environments.

---

## Quick Start

1. **Install dependencies**:
```bash
python -m venv .venv
source .venv/bin/activate  # Windows: .venv\Scripts\activate
pip install -r requirements.txt

```


2. **(Optional but recommended) Ensure Ollama is running**:
```bash
ollama pull llama3.1

```


3. **Run the application**:
```bash
streamlit run app.py

```



---

## Data and Storage

All artifacts are stored locally by default:

* `./data/artifacts/...` — structured JSON artifacts.
* `./data/exports/...` — human-readable Markdown exports.

No data is transmitted externally unless explicitly configured by the user. To reset the demo state, delete the `data/` directory.

---

**License: Apache-2.0**
