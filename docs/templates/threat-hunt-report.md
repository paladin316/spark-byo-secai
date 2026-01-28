# Threat Hunt Report Template

A **Threat Hunt Report** documents the **outcome of a threat hunt**, regardless of whether malicious activity was identified.

This artifact exists to preserve analytical conclusions, including **negative results**, and to prevent teams from re-hunting the same question without context.

---

## When to Use This Template

Create a Threat Hunt Report when:

- A Threat Hunt Package has been executed
- You need to document what was tested and observed
- The hunt produced no actionable findings
- Findings exist but do not yet warrant incident-style analysis

Do **not** use this template for confirmed incidents or escalations.  
That belongs in a Threat Hunt IR Report.

---

## Required Sections

The sections below define the **minimum documentation standard** for a completed hunt.

### 1. Hunt Summary

**Purpose:**  
Provide a concise summary of what was tested and the overall outcome.

Include:
- Hunt objective
- High-level execution result
- Whether findings were identified

This section should be readable by a non-hunter.

---

### 2. Hunt Scope & Execution

**Purpose:**  
Record *what was actually run*, not what was planned.

Include:
- Timeframe analyzed
- Systems or environments covered
- Queries or logic executed (referenced, not rewritten)
- Any deviations from the original hunt package

This preserves accuracy and auditability.

---

### 3. Observations

**Purpose:**  
Describe what was observed during execution.

Include:
- Notable patterns or behaviors
- Volume and distribution of results
- Known-good or expected activity
- Any anomalies that did not meet escalation criteria

Avoid assigning severity in this section.

---

### 4. Assessment & Conclusion

**Purpose:**  
Interpret the observations and state a clear conclusion.

Include:
- Whether the hypothesis was supported or refuted
- Confidence level in the conclusion
- Context explaining ambiguity or uncertainty

Negative conclusions are valid outcomes.

---

## Optional Sections

These sections may be included when relevant.

### Findings Summary

If findings exist but do not yet warrant IR escalation:
- Briefly summarize them
- Explain why escalation was not triggered

---

### Limitations & Blind Spots

Document factors that may impact confidence, such as:
- Telemetry gaps
- Partial visibility
- Tooling constraints

---

### Analyst Notes

Free-form space for:
- Environment-specific context
- Lessons learned
- Recommendations for future hunts

---

## Output & Escalation Guidance

Based on the outcome:

- **No findings:**  
  The Threat Hunt Report stands as the final artifact.

- **Suspicious findings:**  
  Consider creating a Threat Hunt IR Report.

- **Confirmed malicious behavior:**  
  Escalate through incident response processes and generate a Threat Hunt IR Report.

Threat Hunt Reports do **not** directly produce detections.

---

## Design Principles

- Outcome-focused, not query-focused
- Preserves negative knowledge
- Clear conclusions over exhaustive detail
- Suitable for future reference and audits

A well-written Threat Hunt Report should answer:  
**“What did we learn, and can we trust the conclusion?”**

---

## Related Templates

- Threat Hunt Package → `threat-hunt-package.md`
- Threat Hunt IR Report → `threat-hunt-ir-report.md`
- Alert & Detection Strategy → `ads.md`

---

SPARK Threat Hunt Reports ensure that **every hunt leaves behind durable knowledge**.
