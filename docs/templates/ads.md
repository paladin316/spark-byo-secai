# Alert & Detection Strategy (ADS) Template

An **Alert & Detection Strategy (ADS)** defines how to **reliably detect a validated adversary behavior over time**.

This artifact exists to ensure detections are **grounded in observed reality**, not theory, and to prevent premature or brittle alerting.

An ADS is not an alert.  
It is the **design blueprint** for one.

---

## When to Use This Template

Create an ADS when:

- Threat Hunt IR findings have been reviewed and validated
- There is confidence the behavior represents real risk
- You want durable detection, not one-off alerts
- Required telemetry is available or can be obtained

Do **not** create an ADS directly from threat intelligence.  
Detections are built from **evidence**, not expectation.

---

## Required Sections

The sections below define the **minimum design standard** for a detection strategy.

---

### 1. Detection Goal

**Purpose:**  
State what behavior the detection is intended to identify.

Include:
- Description of the behavior
- Why detecting it matters
- What success looks like

Goals should be precise and outcome-oriented.

---

### 2. Categorization

**Purpose:**  
Anchor the detection to known adversary behavior frameworks.

Include:
- MITRE ATT&CK tactic(s)
- Technique ID(s) and name(s)

Categorization supports reporting, alignment, and future correlation.

---

### 3. Strategy Abstract

**Purpose:**  
Describe the **high-level detection approach** in plain language.

Include:
- Core signal(s) being leveraged
- How false positives are reduced
- How confidence is built over time

This section should be understandable without query syntax.

---

### 4. Required Telemetry

**Purpose:**  
Define the data needed to support the strategy.

Include:
- Data sources (e.g., EDR, SIEM, cloud logs)
- Event types or categories
- Required fields or attributes

Explicit telemetry requirements prevent silent detection failure.

---

### 5. Detection Logic

**Purpose:**  
Describe *how detection would be implemented*.

Include:
- Conceptual logic (pseudocode or narrative)
- Query examples (optional, non-final)
- Correlation or sequencing logic (if applicable)

Detection logic should prioritize clarity over optimization.

---

### 6. Blind Spots & Assumptions

**Purpose:**  
Make limitations explicit.

Include:
- Conditions where detection may fail
- Required assumptions
- Environmental or tooling constraints

This section is critical for trust and long-term maintenance.

---

## Optional Sections

Use these sections when they add value.

---

### Alerting & Triage Guidance

Provide guidance on:
- Suggested severity
- Initial triage steps
- Validation checks for analysts

---

### False Positive Considerations

Document:
- Known benign behaviors that may trigger signals
- Recommended allow-listing strategies
- Environmental tuning notes

---

### Testing & Validation

Describe:
- How the detection can be tested
- Simulation or replay options
- Validation frequency

---

## Output & Implementation

An ADS informs:

- SIEM detection rules
- EDR detections
- Analytics pipelines
- Managed detection workflows

Implementation details may vary by platform, but the **strategy remains consistent**.

---

## Design Principles

- Evidence-driven
- Durable over time
- Explicit about limitations
- Analyst-validated before alerting

A strong ADS answers:
**“How do we detect this reliably without waking people up unnecessarily?”**

---

## Related Templates

- Threat Hunt IR Report → `threat-hunt-ir-report.md`
- Threat Hunt Package → `threat-hunt-package.md`

---

SPARK Alert & Detection Strategies ensure detections are **intentional, explainable, and maintainable**.
