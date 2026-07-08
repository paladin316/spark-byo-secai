# Threat Weaponization Prediction Program (TWPP)

The **Threat Weaponization Prediction Program (TWPP)** is a SPARK research track focused on predicting which newly disclosed vulnerabilities are most likely to become attacker tradecraft.

Traditional vulnerability management asks:

> What vulnerabilities exist?

TWPP asks:

> Which vulnerabilities are most likely to be weaponized, how quickly, against which environments, and what should defenders do before exploitation becomes widespread?

## Purpose

TWPP is designed to demonstrate how SPARK can move from reactive vulnerability review into predictive cyber defense by combining:

- Vulnerability intelligence
- Threat intelligence correlation
- Weaponization forecasting
- Threat hunt generation
- Exposure analysis
- Customer risk scoring
- Detection gap analysis
- Outcome metrics

## Program Pillars

```text
TWPP
├── Vulnerability Intelligence
├── Weaponization Forecasting Engine
├── Threat Hunt Generator
├── Exposure Analysis
├── Customer Risk Scoring
├── Detection Gap Analysis
└── Outcome Metrics
```

## Repository Contents

| File / Folder | Purpose |
|---|---|
| `methodology.md` | Defines the TWPP operating model and analyst workflow. |
| `scoring-model.md` | Describes the conceptual scoring framework for WFS, TTE, exposure, and risk. |
| `workflow.md` | Walks through the end-to-end SPARK/TWPP lifecycle. |
| `examples/` | Worked examples and public research walkthroughs. |
| `templates/` | Reusable templates for future TWPP packages. |

## Current Examples

- `GhostLock-CVE-2026-43499.md` — Linux local privilege escalation and container escape forecast walkthrough.
- `CVE-2026-41089.md` — Placeholder for Microsoft Netlogon-style disclosure-to-exploitation forecasting case study.
- `Chrome-CVE-2026-11645.md` — Placeholder for browser zero-day / KEV-driven forecasting case study.

## Guiding Principle

SPARK does not replace analyst judgment. It assists analysts by correlating evidence, structuring reasoning, generating hunt hypotheses, identifying detection gaps, and measuring forecast outcomes.

> AI assists. Analysts decide.
