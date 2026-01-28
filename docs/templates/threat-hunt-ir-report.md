# Threat Hunt IR Report Template

A **Threat Hunt IR Report** documents **actionable findings** identified during a threat hunt that warrant **incident-style analysis, triage, or response**.

This artifact exists to bridge **threat hunting and incident response**, ensuring that findings are **defensible, reviewable, and evidence-driven** before escalation or detection engineering occurs.

---

## When to Use This Template

Create a Threat Hunt IR Report when:

- A threat hunt produces suspicious or malicious findings
- Analyst review indicates potential impact or risk
- Findings require deeper investigation or response
- Evidence may inform future detection logic

Do **not** create this report for every hunt.  
This artifact exists **only when findings justify it**.

---

## Required Sections

The sections below define the **minimum standard** for an actionable IR report.

### 1. BLUF (Bottom Line Up Front)

**Purpose:**  
Provide a concise, decision-oriented summary.

Include:
- Whether malicious or suspicious activity was identified
- Overall severity and confidence
- Immediate recommended action (if any)

This section should be readable by leadership or IR stakeholders.

---

### 2. Description of Activity

**Purpose:**  
Explain what behavior triggered this report.

Include:
- Summary of observed activity
- Relationship to the original hunt hypothesis
- Why this activity matters

Avoid speculation. Focus on observed behavior.

---

### 3. Timeframe

**Purpose:**  
Clearly define when the activity occurred.

Include:
- Earliest and latest observed timestamps
- Whether activity is ongoing or historical

---

### 4. Scope & Impact Assessment

**Purpose:**  
Define the breadth and potential impact of the activity.

Include:
- Affected systems, users, or accounts
- Lateral movement or spread (if observed)
- Potential business or security impact

Unknowns should be explicitly stated.

---

### 5. Evidence & Analysis

**Purpose:**  
Present defensible evidence supporting the assessment.

Include:
- Key events, logs, or telemetry
- Relevant command lines, process relationships, or network activity
- Correlated observations across data sources

Evidence should be factual and reproducible.

---

### 6. Findings

**Purpose:**  
Document each finding with clarity and structure.

Each finding should include:
- Finding ID
- Description
- Severity
- Confidence level
- Associated MITRE techniques

Multiple findings may exist in a single report.

---

### 7. Analyst Assessment

**Purpose:**  
Provide expert interpretation of the findings.

Include:
- Likelihood of malicious intent
- Alternative explanations
- Recommended next steps

This is where analyst judgment belongs.

---

## Optional Sections

Include these sections when applicable.

### Timeline

Chronological reconstruction of activity when sequence matters.

---

### Containment & Response Actions

Document any actions taken, such as:
- Host isolation
- Credential resets
- Blocking indicators

Include timestamps and ownership when possible.

---

### Limitations & Blind Spots

Note factors impacting confidence, such as:
- Partial visibility
- Logging gaps
- Environmental constraints

---

## Output & Next Steps

A completed Threat Hunt IR Report may result in:

- Incident response escalation
- Stakeholder communication
- Creation of an Alert & Detection Strategy (ADS)
- Closure with documented justification

Detection engineering should occur **only after** findings are reviewed and validated.

---

## Design Principles

- Evidence before escalation
- Confidence over certainty
- Clear separation of facts and judgment
- Analyst-driven decision making

A well-written Threat Hunt IR Report should allow a third party to understand:
**what happened, why it matters, and what to do next**.

---

## Related Templates

- Threat Hunt Package → `threat-hunt-package.md`
- Threat Hunt Report → `threat-hunt-report.md`
- Alert & Detection Strategy → `ads.md`

---

SPARK Threat Hunt IR Reports ensure that **detections are built on observed reality, not assumption**.
