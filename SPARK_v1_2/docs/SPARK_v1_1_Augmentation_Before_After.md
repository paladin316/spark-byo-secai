# SPARK.1 — Evidence-Driven Augmentation (Before / After)

This document shows what changed in SPARK.1 for **Runs**, **Findings**, and **ADS**.

The goal is simple:
- Keep outputs **auditable and deterministic**
- Make artifacts read like an analyst wrote them
- Make promotion decisions **explicit** (confidence ladder + criteria)

> These examples are based on the demo chain: Intel → Hunt → Run → Finding → ADS.

---

## ADS — Before

Typical v1 output looked like:

- Goal: “Detect recurrence of behavior described in finding ...”
- Logic: “Start with high-signal process telemetry... tune later.”
- Deployment: “Pilot as a hunt query first.”

This was safe, but too generic. It didn’t explain **why** the ADS exists, how to gauge confidence, or when to promote.

## ADS — After (v1.1)

v1.1 adds **first-class, evidence-driven augmentation**:

- **Why this ADS exists** (derived from the linked Finding)
- **Signal Confidence Ladder** (Low → Medium → High)
- **Confidence Notes** (drivers + reducers)
- **Promotion Criteria** (promote/suppress conditions)
- **Alerting Guidance** (page-by-default: false)

It also builds a higher-signal draft query when artifacts (like filenames) can be extracted from the Finding.

---

## Finding — Before

Typical v1 finding output included:
- Description
- Evidence list
- MITRE techniques
- Analyst notes

That worked, but it didn’t guide triage beyond “review required.”

## Finding — After (v1.1)

v1.1 adds:

- **Why this finding exists**
- **Signal summary**
- **Triage questions** (explicit pivots)
- **Recommended next steps**
- **Confidence notes** (drivers/reducers)
- **Disposition guidance** (how to treat the finding operationally)

These fields are deterministic and can be edited by the analyst.

---

## Run Report — Before

Run reports were already deterministic and template-aligned, but some placeholders stayed “(TBD)” even when intel context existed.

## Run Report — After (v1.1)

v1.1 improves run reports by:

- Filling **Disposition** based on findings presence
- Filling **Impact to Org** from intel (when available)
- Keeping all content explainable and editable

---

## Code touchpoints (where these changes live)

- `byo_secai/models.py`
  - Added augmentation fields to `Finding`, `ADS`, and `Run`

- `byo_secai/workflow.py`
  - Evidence-driven ADS assembly in `generate_ads()`
  - Deterministic augmentation fields in `generate_findings_from_run()`
  - Enhanced markdown renderers: `render_finding_markdown()` and `render_ads_markdown()`
  - Run report placeholder fixes in `render_run_ir_report_markdown()`

- `byo_secai/contracts/`
  - New contracts:
    - `ads_v1_1.yaml`
    - `finding_v1_1.yaml`
    - `run_v1_1.yaml`

- `byo_secai/contract_framework.py`
  - Added validation helpers: `validate_ads()`, `validate_finding()`, `validate_run()`

---

## Why this matters for launch

The repo can now show real demo artifacts that:

- Read like IR / Detection Engineering deliverables
- Explain *why* a detection exists
- Make promotion criteria explicit
- Preserve the SPARK philosophy: **Operational Threat Intelligence → Hunt → Detection pipeline**
