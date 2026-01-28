# SPARK Analytical Templates

SPARK (Powered by BYO-SECAI) uses a small, intentional set of **structured analytical templates** to move from raw intelligence to validated detections without losing context, rigor, or analyst judgment.

These templates are not paperwork. They are **guardrails** — designed to preserve analytical intent as work progresses from research to hunting to response to detection engineering.

> **AI may assist drafting or enrichment, but promotion between artifacts is always analyst-driven.**

## Templates
- [Threat Intelligence Brief](threat-intel-briefing.md)
- [Threat Hunt Package](threat-hunt-package.md)
- [Threat Hunt Report](threat-hunt-report.md)
- [Threat Hunt IR Report](threat-hunt-ir-report.md)
- [Alert Detection Strategy (ADS)](ads.md)

---

## Why Templates Exist in SPARK

Security failures rarely stem from lack of data. They stem from:

- Poor understanding of the threat
- Unstructured hunting
- Undocumented negative results
- Premature alerting
- Detections built on theory instead of observation

SPARK templates exist to solve these problems by enforcing:

- Clear analytical intent
- Explicit assumptions
- Auditable outcomes
- Evidence-backed detections

Each artifact answers a **different analytical question** and serves a **specific role** in the lifecycle.

---

## The SPARK Analytical Lifecycle

**Mental model:**

> **Understand → Test → Observe → Respond → Detect**

**Concrete flow:**

Threat Intelligence Briefing  
↓  
Threat Hunt Package  
↓  
Threat Hunt Report  
↓  
Threat Hunt IR Report (if findings exist)  
↓  
Alert & Detection Strategy (ADS)


Not every workflow produces every artifact.  
Each artifact exists **only when it adds analytical value**.

---

## Core Templates Overview

### 1. Threat Intelligence Briefing

**Purpose:**  
Provide contextual understanding of a threat, campaign, technique, or trend.

**Answers:**  
What is happening? Why it matters. How it typically operates.

**Key traits:**
- Narrative and explanatory
- Context-driven, not IOC-driven
- Focused on understanding, not execution

**Lifecycle role:**  
Starting point. Feeds Threat Hunt Packages.

📄 See: `threat-intel-briefing.md`

---

### 2. Threat Hunt Package

**Purpose:**  
Translate intelligence into a **testable hypothesis and hunt plan**.

**Answers:**  
If this threat is present, what would we expect to see?

**Key traits:**
- Hypothesis-driven
- Query-centric
- Designed for repeatable execution

**Lifecycle role:**  
Built from Threat Intel. Executed as hunts. Produces results.

📄 See: `threat-hunt-package.md`

---

### 3. Threat Hunt Report

**Purpose:**  
Summarize the **outcome of a hunt**, including negative results.

**Answers:**  
What did we test? What did we observe? What did we conclude?

**Key traits:**
- Outcome-focused
- Preserves institutional knowledge
- Lower severity than incident reports

**Lifecycle role:**  
Produced after hunt execution. May stand alone or feed IR.

📄 See: `threat-hunt-report.md`

---

### 4. Threat Hunt IR Report

**Purpose:**  
Document **actionable findings** that warrant incident-style analysis.

**Answers:**  
What suspicious or malicious behavior was observed, and with what confidence?

**Key traits:**
- Evidence-driven
- Triage and response oriented
- Defensible and reviewable

**Lifecycle role:**  
Created only when findings exist. Feeds detection strategy.

📄 See: `threat-hunt-ir-report.md`

---

### 5. Alert & Detection Strategy (ADS)

**Purpose:**  
Convert validated findings into **durable detection logic**.

**Answers:**  
How do we reliably detect this behavior going forward?

**Key traits:**
- Forward-looking
- Detection-engineering focused
- Explicit about blind spots and assumptions

**Lifecycle role:**  
Final analytical artifact. Informs SIEM / EDR implementation.

📄 See: `ads.md`

---

## Design Principles

These templates are intentionally:

- **Analyst-first** — structure supports judgment, not replaces it
- **AI-augmented** — assistance without authority
- **Audit-friendly** — assumptions and decisions are explicit
- **Outcome-oriented** — negative results are still valuable

SPARK does not force promotion between stages.  
Progression happens only when the **evidence justifies it**.

---

## How to Use These Templates

- Use templates **as-is** for consistency
- Extend sections when needed — do not remove intent
- Treat each artifact as a decision point, not a checkbox
- Avoid skipping stages to “save time”

Speed comes from clarity, not shortcuts.

---

## Related Concepts

- Threat Hunting Philosophy → `docs/01_concepts/threat-hunting-philosophy.md`
- Operational Threat Intelligence → `docs/01_concepts/operational-threat-intelligence.md`
- Terminology → `docs/01_concepts/terminology.md`

---

SPARK templates exist to help analysts **think clearly, hunt intentionally, and detect responsibly**.
