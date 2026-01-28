# Threat Hunt Package Template

A **Threat Hunt Package** translates threat intelligence into a **testable hypothesis and repeatable hunt plan**. It defines *what to look for*, *why it matters*, and *how success or failure should be interpreted*.

This artifact exists to prevent unstructured querying and ensure hunts are **intentional, explainable, and auditable**.

---

## When to Use This Template

Create a Threat Hunt Package when:

- New threat intelligence warrants validation in your environment
- You want to test a specific attacker technique or behavior
- You are operationalizing a Threat Intelligence Briefing
- You want repeatable, documented hunt logic

Do **not** use this template to document outcomes or findings.  
That belongs in a Threat Hunt Report or IR Report.

---

## Required Sections

The sections below define the **minimum analytical intent** for a valid hunt.

### 1. Hunt Overview

**Purpose:**  
Briefly explain *why this hunt exists*.

Include:
- Threat, campaign, or technique being investigated
- Reason this activity matters to your environment
- Link to source intelligence (if applicable)

---

### 2. Hunt Hypothesis

**Purpose:**  
State a **falsifiable hypothesis**.

Good hypotheses are specific and observable.

**Example:**
> If this threat is present in our environment, we expect to observe process execution and network activity consistent with \<technique\> on Windows endpoints within the last 30 days.

Avoid vague statements such as:
- “Search for suspicious activity”
- “Look for indicators of compromise”

---

### 3. Scope & Assumptions

**Purpose:**  
Define the boundaries and expectations of the hunt.

Include:
- In-scope platforms (e.g., Windows endpoints, Azure VMs)
- Timeframe
- Assumptions about visibility or tooling
- Explicit exclusions

This section prevents overconfidence in negative results.

---

### 4. Mapped Techniques

**Purpose:**  
Anchor the hunt to known adversary behavior.

Include:
- MITRE ATT&CK tactic(s)
- Technique ID(s) and name(s)

Mapping techniques helps align findings with detection strategy later.

---

### 5. Hunt Logic & Queries

**Purpose:**  
Describe *how the hypothesis will be tested*.

Include:
- One or more hunt queries
- Brief explanation of what each query is intended to surface
- Expected signal (high / medium / exploratory)

Queries should be readable and explainable, not optimized for alerting.

---

### 6. Expected Outcomes

**Purpose:**  
Define what **success and failure look like** before execution.

Include:
- What would support the hypothesis
- What would refute it
- What ambiguous results might mean

This forces interpretation discipline and reduces bias during analysis.

---

## Optional Sections

These sections are recommended when applicable but not required.

### Data Sources & Telemetry

List required or preferred telemetry sources, such as:
- EDR process events
- Network connection logs
- Authentication events
- Cloud control plane logs

---

### Risks & Limitations

Document known blind spots, including:
- Logging gaps
- Tooling limitations
- Environmental constraints

---

### Analyst Notes

Free-form space for:
- Contextual considerations
- Known false positives
- Environment-specific quirks

---

## Output & Next Steps

Execution of a Threat Hunt Package produces:

- A **Threat Hunt Report** (always)
- A **Threat Hunt IR Report** (only if findings exist)

A Threat Hunt Package **never directly creates detections**.  
Detection logic is derived only after evidence is reviewed and validated.

---

## Design Principles

- Hypothesis-driven, not indicator-driven
- Structured but flexible
- Optimized for reasoning, not alerting
- Repeatable by other analysts

A well-written hunt package should allow another analyst to execute it **without additional explanation**.

---

## Related Templates

- Threat Intelligence Briefing → `threat-intel-briefing.md`
- Threat Hunt Report → `threat-hunt-report.md`
- Threat Hunt IR Report → `threat-hunt-ir-report.md`
- Alert & Detection Strategy → `ads.md`

---

SPARK Threat Hunt Packages exist to ensure hunting is **intentional, defensible, and outcome-driven**.
