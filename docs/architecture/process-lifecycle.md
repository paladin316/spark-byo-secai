# SPARK Process Lifecycle

The SPARK process lifecycle defines how raw threat intelligence is transformed into
validated detections through a structured, analyst-driven workflow.

<p align="center">
  <img src="../images/spark-process-lifecycle.png" alt="SPARK process lifecycle">
</p>

## How to Read This Lifecycle

SPARK is designed as a governed lifecycle, not a linear pipeline.
Each phase preserves context from the previous step while enforcing validation,
traceability, and analyst intent.

Human review is explicitly enforced before intelligence is operationalized.

## Phase 0: External Intel / Threat Research
Raw threat intelligence is collected from external sources such as reports, blogs,
CVEs, and operational advisories. This material exists outside SPARK until structured.

## Phase 1: Intel Brief Draft
Raw intelligence is normalized into structured, analyst-readable context, enabling
consistent interpretation and downstream reuse.

## Phase 2: Human Approval Gate
Analyst review acts as a governance checkpoint, ensuring accuracy, intent, and auditability
before intelligence is operationalized.

## Phase 3: Hunt Package Build
Approved intelligence is scoped and transformed into executable hunt logic with clearly
defined assumptions and constraints.

## Phase 4: Hunt Execution & Collection
Hunts are executed in a controlled manner across supported platforms, capturing
telemetry and raw results for analysis.

## Phase 5: Findings
Collected evidence is analyzed and synthesized into structured findings with
severity, confidence, and contextual linkage.

## Phase 6: ADS Generation
Validated findings are translated into repeatable detection strategies, defining
required telemetry and detection logic.

## Phase 7: Reporting & Export
Results are communicated through role-specific outputs with full traceability back
to source intelligence and analyst decisions.
