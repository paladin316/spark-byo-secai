# Full Lifecycle Example — Ransomware Threat Hunting

This directory contains a **canonical, end-to-end example** of how SPARK (Powered by BYO-SECAI) is intended to be used in practice.

It demonstrates the *complete analytical lifecycle* — from raw threat intelligence through validated detection strategy — using structured, analyst-driven artifacts.

This is not a tutorial and not a template reference.  
It is a **worked example** that shows how disciplined threat intelligence becomes durable detection.

---

## What This Example Shows

This example walks through all five SPARK artifacts:

1. **Threat Intelligence Briefing**  
   Establishes context, scope, and understanding of the threat.  
   *File:* `01_threat-intel-brief.md`

2. **Threat Hunt Package**  
   Translates intelligence into a testable hunt hypothesis.  
   *File:* `02_threat-hunt-package.md`

3. **Threat Hunt Report**  
   Documents what was tested and what was observed.  
   *File:* `03_threat-hunt-report.md`

4. **Threat Hunt IR Report**  
   Analyzes actionable findings that warrant escalation or response.  
   *File:* `04_threat-hunt-ir-report.md`

5. **Alert & Detection Strategy (ADS)**  
   Defines how to reliably detect the behavior going forward.  
   *File:* `05_ads.md`

Each artifact builds on the previous one. None are skipped.

---

## Why This Example Exists

Most security documentation focuses on tools, queries, or alerts in isolation.

SPARK is different.

This example exists to show:
- How context is preserved across analytical artifacts
- Where analyst judgment is required
- Why detections should be the *result* of analysis, not the starting point

If you only read one folder in this repository, this should be it.

---

## How to Read This Example

Read the files in numerical order, starting with:

`01_threat-intel-brief.md`

Each artifact depends on the assumptions and outcomes of the previous one.  
Skipping steps will break context — intentionally.

This mirrors how SPARK is intended to be used in practice:

> **Understand → Test → Observe → Respond → Detect**

---

## Important Notes

- Artifacts are **illustrative**, not exhaustive
- Example data is sanitized and generalized
- The goal is to demonstrate **process and discipline**, not tooling

SPARK emphasizes *how analysts think*, not just what tools they use.

---

## What This Is Not

- This is not a vendor-specific implementation
- This is not a copy-paste detection pack
- This is not exhaustive threat coverage

It is a **process reference** — meant to be adapted, not reused blindly.
