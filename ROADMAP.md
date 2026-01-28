# SPARK Roadmap

This roadmap outlines the intended direction of **SPARK (Security Playbook for Analytics, Research, and Knowledge)**.

It is **not a commitment** to specific features or timelines.  
SPARK is developed deliberately, with an emphasis on correctness, transparency, and analyst trust over speed or breadth.

---

## Guiding Principles

SPARK development is guided by the following principles:

- **Analyst-first**: Analysts remain responsible for judgment, approval, and decisions.
- **Traceability over automation**: Every artifact should retain its origin, context, and reasoning.
- **AI as augmentation**: AI reduces mechanical effort; it does not make security decisions.
- **Local-first by default**: Users control their data, execution, and models.
- **Explicit scope control**: SPARK will not attempt to be everything.

These principles take precedence over feature requests or external pressure.

---

## Current State (v1 / MVP)

SPARK currently provides a complete **analyst-driven workflow** from intelligence to detection strategy:

**Intel Brief → Hunt Package → Run → Findings → ADS → Export**

Key capabilities include:

- Streamlit-based local UI
- Intel Brief creation, review, and approval
- Guardrails enforcing approval before hunt generation
- Hunt Packages with clear objectives and scope
- Runs with timeframe and query execution context
- Findings derived from run results
- ADS (Analyst Detection Strategy) artifacts linked to findings
- Local-first artifact storage (JSON + Markdown)
- Optional local AI augmentation via Ollama
- Deterministic fallback behavior when AI is unavailable
- **Chat-first Notebook Workspace** for exploratory analysis and reasoning

This version prioritizes **correctness, auditability, and workflow integrity** over feature completeness.

---

## Near-Term Focus (v1.x)

The near-term focus is on **hardening, clarity, and usability**, not expansion.

Planned areas of work include:

- Documentation expansion (`/docs`)
  - Operational Threat Intelligence concepts
  - Terminology and definitions
  - Threat hunting maturity and expectations
  - Workspace models (platform vs chat-first notebook)
- Improved validation and consistency checks across artifacts
- Refinement of AI guardrails and heuristic handling
- UX improvements based on real analyst workflows
- Additional example/demo artifacts for education and evaluation
- Improved export quality and structure

The goal of v1.x is to make SPARK **boringly reliable**.

---

## Mid-Term Direction (v2)

Once the foundation is stable, SPARK may expand in the following directions:

- Modular contract and validation architecture
- Additional query language support (e.g., KQL, SPL, SQL, OSQuery)
- More advanced correlation and reasoning support
- Improved artifact lineage and dependency tracking
- Enhanced detection strategy modeling
- Better support for team workflows (still analyst-driven)

These efforts will only proceed once the core workflow is proven stable and understandable.

---

### RAG-Based Recall for Threat Hunting (Exploratory)

SPARK may introduce **Retrieval-Augmented Generation (RAG)-based recall** to assist analysts during exploratory analysis.

RAG recall is intended to assist analysts, not replace documentation or formal artifact creation.

RAG recall is explicitly scoped to the **Notebook Workspace** and may support:

- Recall of prior hunts, findings, and detections
- Tag- and metadata-based context retrieval
- Query and hypothesis development
- Exploration of historical analyst reasoning

RAG recall is **advisory only**.

Retrieved context:
- Does not create artifacts automatically
- Does not modify platform artifacts
- Does not bypass validation or approval gates

All promotion into Hunts, Findings, or ADS remains governed by the **Platform Workspace model**.

---

### Agentic Query Operations (Bounded and Non-Authoritative)

SPARK may experiment with **limited, agent-like assistance** for query exploration and refinement.

Any agentic behavior will be:

- Confined to the **Notebook Workspace**
- Explicitly enabled by the analyst
- Transparent and observable
- Bounded in scope and duration

Agentic operations will **never**:

- Execute queries automatically
- Create or promote artifacts autonomously
- Bypass platform validation or approval steps
- Act as a continuously operating agent

All authoritative actions remain analyst-driven and governed by the Platform Workspace.

---

### Optional MCP-Based Integrations

SPARK may introduce **optional Model Context Protocol (MCP) servers** to expose structured context from external security tools in a controlled, analyst-driven manner.

Potential examples include:
- An MCP server for **Atomic Red Team**, providing structured access to technique metadata, test definitions, and simulation context
- An MCP server for **Splunk**, enabling read-only query generation, validation, and result interpretation support

MCP integrations are intended to **augment analyst workflows**, not automate decisions or actions.

If implemented, MCP integrations will:
- Be explicitly opt-in
- Expose context, metadata, and structure — not trigger execution
- Preserve analyst review and approval at every stage
- Integrate with existing SPARK guardrails and artifact validation workflows
- Be configurable or fully disable

SPARK will not require MCP servers to function, and no external system will be treated as authoritative without explicit analyst approval.

MCP integrations will never bypass SPARK’s approval gates or artifact validation workflows.

See `docs/architecture/mcp-integration.md` for MCP design intent and constraints.

---

## Long-Term Vision

Longer-term, SPARK aims to serve as a **knowledge system for defensive operations**, not just a tooling interface.

Possible directions include:

- Treating threat intelligence, hunts, and detections as first-class knowledge objects
- Enabling reuse and evolution of analyst reasoning over time
- Supporting advanced threat hunting playbooks and methodologies
- Acting as a bridge between intelligence, hunting, detection engineering, and incident response

Any long-term evolution will remain aligned with SPARK’s founding principles.

---

## Explicitly Out of Scope

To avoid ambiguity, the following are **out of scope** for SPARK:

- Fully autonomous detection or response
- “AI SOC” or self-driving security operations
- Black-box scoring or decision engines
- Alerting-only platforms
- Replacement of SIEM, EDR, or SOAR products
- Centralized data collection or mandatory cloud services

SPARK is a **workbench**, not a replacement for existing security platforms.

---

## Feedback and Direction

Feedback is welcome and encouraged, particularly around:
- Analyst workflows
- Documentation clarity
- Conceptual correctness

Feature requests may be discussed, but inclusion will be evaluated against SPARK’s principles and long-term vision.

---

Last updated: 2026
