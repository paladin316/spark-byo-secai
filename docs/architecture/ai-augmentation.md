# AI Augmentation in SPARK

This document defines how artificial intelligence is used within SPARK — and, equally important, how it is **not** used.

SPARK is designed around the principle that **analysts remain responsible for judgment, approval, and decisions**. AI exists to assist analysts by reducing mechanical effort and improving consistency — not to replace expertise or automate outcomes.

This document serves as a **design contract** for contributors and a transparency reference for users.

---

## Design Philosophy

AI in SPARK is intentionally constrained.

Rather than acting as an autonomous agent or decision-maker, AI is treated as an **augmentation layer** that supports analyst-driven workflows.

This philosophy prioritizes:

- Transparency over speed  
- Traceability over automation  
- Reviewability over autonomy  

SPARK explicitly avoids “black box” AI behavior. Every AI-assisted action must be understandable, attributable, and optional.

---

## What AI Is Used For

Within SPARK, AI may be used to:

- Transform narrative intelligence into structured artifacts  
- Assist with drafting hunt hypotheses and objectives  
- Normalize and enrich analyst-authored content  
- Reduce repetitive manual formatting and translation work  
- Help preserve analyst intent across artifacts  
  (Intel Briefs → Hunt Packages → Findings → Detection Strategies)

All AI-generated outputs are:

- Reviewable  
- Editable  
- Non-authoritative  
- Attributable to a specific workflow step  

AI suggestions **never bypass validation or approval gates**.

---

## What AI Is Not Used For

To preserve analyst trust and control, AI in SPARK is **not** used to:

- Make security decisions  
- Declare findings or severity autonomously  
- Trigger detections, alerts, or responses  
- Execute commands or tests  
- Modify the host system  
- Override analyst approvals  
- Act as a self-directed or continuously operating agent  

SPARK does **not** implement autonomous SOC behavior, “AI analyst” personas, or closed-loop enforcement.

---

## Analyst-in-the-Loop by Design

Every AI-assisted workflow in SPARK is explicitly designed to keep analysts in the loop.

This includes:

- Explicit approval steps before artifact promotion  
- Clear separation between *suggestion* and *acceptance*  
- Preservation of original analyst-authored content  
- Visible boundaries between human input and AI output  

AI assistance can be disabled entirely without breaking core workflows.

SPARK remains usable — and correct — even when AI is unavailable.

---

## Retrieval-Augmented Generation (RAG)

SPARK uses a **Retrieval-Augmented Generation (RAG)** approach to ground AI output in analyst-provided context.

Key characteristics:

- Retrieval scope is limited to **local artifacts**  
- Context is derived from analyst-approved material  
- AI output is informed by retrieved content, not global internet knowledge  

This ensures that AI suggestions:

- Reflect the analyst’s actual intelligence corpus  
- Remain explainable and auditable  
- Avoid generic or hallucinated detections  

RAG in SPARK is designed to **support reasoning**, not invent it.

---

## Determinism and Fallback Behavior

SPARK supports deterministic operation when AI services are unavailable or disabled.

This ensures:

- Predictable behavior  
- Reproducible outputs  
- Usability in restricted, offline, or air-gapped environments  

When AI is unavailable:
- Core workflows continue to function
- Artifacts can still be created, edited, and promoted
- No implicit behavior changes occur

AI enhances workflows — it is never required for correctness.

---

## Relationship to External Context (e.g., MCP)

AI augmentation in SPARK may consume **external context** (such as schemas, technique metadata, or reference material) via controlled integration mechanisms (e.g., MCP).

External context:

- Is treated as **informative**, not authoritative  
- Does not trigger actions  
- Does not bypass validation or approval steps  
- Does not modify local artifacts without analyst intent  

See `docs/architecture/mcp-integration.md` for details on how external context is exposed safely.

---

## Security and Risk Considerations

AI-assisted workflows may process untrusted content, including:

- Threat advisories  
- Incident reports  
- Proof-of-concept descriptions  
- Analyst notes and pasted text  

SPARK mitigates risk by:

- Treating all input as untrusted  
- Using heuristic scanning for instruction-like patterns  
- Preserving analyst review before acceptance  
- Avoiding automatic execution or side effects  

SPARK favors **analyst awareness over automated enforcement**.

Users remain responsible for validating outputs before operational use.

---

## Future Capabilities and Explicit Boundaries

SPARK’s architecture allows for future experimentation with more advanced AI capabilities, including agent-like assistance.

However, any such capabilities must:

- Be explicitly enabled  
- Operate within bounded scopes  
- Require analyst approval  
- Remain transparent and observable  

Autonomous behavior is **not a default goal** of SPARK.

---

## Summary

SPARK uses AI to **support analysts, not replace them**.

By constraining AI to augmentation roles and preserving human judgment, SPARK improves speed and consistency without sacrificing:

- Trust  
- Accountability  
- Traceability  
- Transparency  

This approach ensures SPARK remains a **trusted analytical workbench**, not an opaque decision engine.


The RAG content flow diagram illustrates how analyst-provided artifacts are retrieved and used to bound AI suggestions.

┌──────────────────────────┐
│   Analyst-Provided       │
│   Content                │
│                          │
│  • Intel Briefs          │
│  • Hunt Packages         │
│  • Findings              │
│  • Detection Strategies  │
│  • Reports / Playbooks   │
└─────────────┬────────────┘
              │
              ▼
┌──────────────────────────┐
│   RAG Retrieval Layer    │
│                          │
│  • Local                 │
│  • Analyst-approved      │
│  • Content-bounded       │
└─────────────┬────────────┘
              │
              ▼
┌──────────────────────────┐
│   AI Suggestions         │
│                          │
│  • Drafting              │
│  • Refinement            │
│  • Consistency           │
│  • Contextual Guidance   │
│                          │
│  (No external corpus)    │
└──────────────────────────┘


## Related Documentation

- RAG content sourcing and starter profiles:  
  `docs/getting-started/rag-starter-content.md`

