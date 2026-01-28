# Terminology

This document defines key terms as they are used within **SPARK (Security Playbook for Analytics, Research, and Knowledge)**. These definitions are intentionally opinionated to ensure consistency, traceability, and shared understanding across intelligence, hunting, and detection workflows.

---

## Operational Threat Intelligence

**Operational Threat Intelligence** refers to intelligence that directly informs analyst action. It preserves adversary behavior, context, and analytical reasoning in a form that can be validated through hunting and converted into detection and response capability.

In SPARK, operational threat intelligence is the foundation for threat hunts and detection strategies, not a standalone reporting artifact.

---

## Intel Brief (Threat Intelligence / IR Report)

An **Intel Brief** is a structured intelligence artifact that captures:

- Threat context and narrative
    
- Observed or assessed TTPs
    
- Indicators (as supporting evidence)
    
- Analyst assessment, assumptions, and confidence
    

Intel Briefs are designed to be **actionable starting points**, not final conclusions. They provide the context necessary to justify threat hunts and downstream defensive actions.

---

## Threat Hunt Package

A **Threat Hunt Package** is a structured, hypothesis-driven artifact derived from intelligence. It defines:

- What behavior is being hunted
    
- Why the hunt is justified
    
- Scope and assumptions
    
- Required telemetry and data sources
    
- Queries or investigative logic
    
- Execution notes and outcomes
    

Threat Hunt Packages preserve analytical intent and ensure hunts are repeatable, reviewable, and defensible.

---

## Run

A **Run** represents a single execution of a Threat Hunt Package over a defined scope and timeframe.

Runs capture:

- Execution metadata
    
- Analyst run notes
    
- Review status
    
- Linkage to findings
    

A Run documents _what was actually done_, as opposed to what was planned.

---

## Finding

A **Finding** documents the result of a threat hunt execution.

Findings may represent:

- Confirmed malicious activity
    
- Benign or expected behavior
    
- Inconclusive results requiring further analysis
    

Each Finding includes:

- Description and assessment
    
- Severity and confidence
    
- Supporting evidence
    
- Observed techniques
    
- Analyst notes
    

Findings are the **decision point** between investigation and operational action.

---

## Detection Strategy (ADS)

An **ADS (Analytic / Detection Strategy)** is a structured document that defines how a validated behavior should be detected going forward.

An ADS includes:

- Detection goal and intent
    
- Relevant tactics and techniques
    
- Strategy and logic overview
    
- Required telemetry
    
- Assumptions and blind spots
    
- False positive considerations
    
- Response guidance
    
- Example detection logic
    

ADS artifacts represent **author intent**, not deployment configuration. Operational tuning occurs downstream in SIEM, EDR, or detection platforms.

---

## Detection

A **Detection** is an implemented analytic deployed in a security platform (e.g., SIEM, EDR).

Detections are derived from ADS artifacts but may be:

- Tuned for environment-specific risk
    
- Adjusted for alerting thresholds
    
- Integrated into SOC workflows
    

In SPARK, detections are outcomes — not the source of truth.

---

## Notebook Workspace

The **Notebook Workspace** is a chat-first, exploratory environment used for analysis, reasoning, and hypothesis development.

It supports:

- Free-form analyst thinking
    
- Drafting logic and notes
    
- Optional AI augmentation
    

Content in the Notebook Workspace is **not authoritative** until promoted into structured artifacts.

---

## Platform Workspace

The **Platform Workspace** governs the lifecycle of structured artifacts, including:

- Intel Briefs
    
- Threat Hunt Packages
    
- Runs
    
- Findings
    
- Detection Strategies
    

This workspace enforces traceability, promotion rules, and artifact relationships.

---

## Analyst

An **Analyst** is the human decision-maker responsible for evaluating intelligence, executing hunts, validating findings, and approving detections.

SPARK is explicitly designed to **augment analyst workflows**, not replace analyst judgment.

---

## Author Intent

**Author Intent** refers to the analytical reasoning and prioritization applied at the time an artifact is created.

In SPARK, fields such as severity, confidence, and ADS priority reflect author intent and are preserved for traceability, even if operational tuning occurs later.

---

## Severity vs Confidence

- **Severity** reflects the potential impact or risk posed by the observed behavior.
    
- **Confidence** reflects the analyst’s certainty in the assessment.
    

These are intentionally decoupled to avoid false precision.

---

## Indicator (IOC)

An **Indicator** is a discrete data point (e.g., hash, domain, IP) that may support an assessment.

In SPARK, indicators are treated as **supporting evidence**, not authoritative proof of compromise.

---

## Final Note

These definitions are foundational to SPARK’s design. Consistent use of terminology ensures that intelligence, analysis, and detection remain traceable, explainable, and operationally meaningful over time.

---

