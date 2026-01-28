# Threat Intelligence Briefing Template

A **Threat Intelligence Briefing** provides **contextual understanding** of a threat, campaign, technique, or trend. It establishes *what is happening*, *why it matters*, and *how it typically operates*, before any hunting or detection activity begins.

This artifact exists to ensure analysts hunt with **understanding**, not assumption.

---

## When to Use This Template

Create a Threat Intelligence Briefing when:

- New threat reporting warrants internal analysis
- A campaign, actor, or technique needs contextualization
- External intelligence must be translated for operational teams
- Analysts need a shared understanding before hunting begins

Do **not** use this template to document findings or detections.  
This artifact explains *context*, not *presence*.

---

## Required Sections

The sections below define the **minimum standard** for a usable intelligence briefing.

---

### 1. Executive Summary

**Purpose:**  
Provide a concise, high-level overview suitable for both technical and non-technical audiences.

Include:
- What the threat is
- Why it matters now
- Who is likely impacted

This section should be readable in under one minute.

---

### 2. Background & Context

**Purpose:**  
Explain the broader context behind the activity.

Include:
- Threat history or evolution
- Known actors or campaigns (if applicable)
- Why this activity is notable or emerging

Avoid excessive historical detail unless it informs current relevance.

---

### 3. Threat Overview

**Purpose:**  
Describe how the threat typically operates.

Include:
- Common attack vectors
- High-level kill chain or workflow
- Targeted platforms or environments

Focus on *patterns of behavior*, not single indicators.

---

### 4. Observed Techniques

**Purpose:**  
Anchor the briefing in recognized adversary behaviors.

Include:
- MITRE ATT&CK tactic(s)
- Technique ID(s) and name(s)
- Brief explanation of how each technique is used

This section supports downstream hunting and detection mapping.

---

### 5. Impact & Risk Considerations

**Purpose:**  
Explain why this threat is relevant to your organization.

Include:
- Potential business or operational impact
- Likely targets or data at risk
- Environmental factors that may increase or reduce risk

Risk should be contextual, not alarmist.

---

## Optional Sections

Include these sections when they add value.

---

### Indicators & Artifacts

List indicators **only when they add context**, such as:
- Example file names
- Infrastructure patterns
- Behavioral artifacts

Indicators should **support understanding**, not drive the briefing.

---

### Detection & Hunting Considerations

Provide high-level guidance on:
- What behaviors may be observable
- Where to focus hunting efforts
- What telemetry is likely relevant

Avoid embedding full hunt logic here.

---

### Assumptions & Limitations

Document:
- Gaps in available intelligence
- Uncertainty in reporting
- Known areas of ambiguity

This builds trust and analytical discipline.

---

## Recommended Next Steps

Based on this briefing, consider:

- Creating a Threat Hunt Package
- Monitoring relevant telemetry
- Sharing context with stakeholders

Next steps should be proportional to risk.

---

## Design Principles

- Context over indicators
- Clarity over volume
- Analytical neutrality
- Supports, but does not replace, hunting

A strong Threat Intelligence Briefing should answer:  
**“What do we need to understand before we start looking?”**

---

## Related Templates

- Threat Hunt Package → `threat-hunt-package.md`
- Threat Hunt Report → `threat-hunt-report.md`
- Alert & Detection Strategy → `ads.md`

---

SPARK Threat Intelligence Briefings ensure that **hunting begins with understanding, not guesswork**.
