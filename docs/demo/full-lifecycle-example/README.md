# Full Lifecycle Example: Ransomware Threat Hunting

This folder demonstrates a **complete SPARK analytical lifecycle**, showing how raw threat intelligence is transformed into a validated detection strategy using structured, analyst-driven artifacts.

The example is based on real-world ransomware tradecraft and uses **representative demo artifacts** to illustrate workflow, intent, and decision points.

---

## What This Example Shows

This example walks through all five SPARK artifacts:

1. **Threat Intelligence Briefing**  
   Establishes context and understanding of the threat.

2. **Threat Hunt Package**  
   Translates intelligence into a testable hunt hypothesis.

3. **Threat Hunt Report**  
   Documents what was tested and what was observed.

4. **Threat Hunt IR Report**  
   Analyzes actionable findings that warrant escalation.

5. **Alert & Detection Strategy (ADS)**  
   Defines how to reliably detect the behavior going forward.

Each artifact builds on the previous one. None are skipped.

---

## How to Read This Folder

Start at `01_threat-intel-briefing.md` and read the files in numerical order.

This mirrors how SPARK is intended to be used in practice:

> **Understand → Test → Observe → Respond → Detect**

---

## Important Notes

- Artifacts are **illustrative**, not exhaustive
- Example data is sanitized and generalized
- The goal is to demonstrate **process and discipline**, not tooling

SPARK emphasizes *how analysts think*, not just what tools they use.

---

## Why This Matters

Many security teams jump directly from intelligence to alerts.

This example shows why SPARK does not.

Detections are strongest when they are built on:
- Context
- Evidence
- Analyst judgment
- Explicit assumptions

This folder exists to make that progression tangible.
