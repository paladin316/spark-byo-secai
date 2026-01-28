from __future__ import annotations

from enum import Enum
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field


class ApprovalStatus(str, Enum):
    DRAFT = "Draft"
    APPROVED = "Approved"


class ArtifactType(str, Enum):
    INTEL_BRIEF = "intel_brief"
    INTEL_IOCS = "intel_iocs"
    HUNT_PACKAGE = "hunt_package"
    RUN = "run"
    FINDING = "finding"
    ADS = "ads"


class RunStatus(str, Enum):
    READY = "Ready"
    RUNNING = "Running"
    COMPLETE = "Complete"
    FAILED = "Failed"


class Severity(str, Enum):
    LOW = "Low"
    MEDIUM = "Medium"
    HIGH = "High"
    CRITICAL = "Critical"


class ADSLifecycleStatus(str, Enum):
    """Operational lifecycle for an ADS beyond simple content approval."""

    DRAFT = "Draft"
    APPROVED = "Approved"
    PROMOTED = "Promoted"
    DEPLOYED = "Deployed"
    TUNED = "Tuned"
    RETIRED = "Retired"


class ArtifactMeta(BaseModel):
    id: str
    type: ArtifactType
    title: str
    created_at: str
    updated_at: str
    tags: List[str] = Field(default_factory=list)
    links: Dict[str, str] = Field(default_factory=dict)
    # Basic performance timing captured by the UI (seconds).
    # Example: {"intel_generate": 2.31, "hunt_generate": 5.84}
    timings_s: Dict[str, float] = Field(default_factory=dict)

    # Optional audit trail for edits/approvals.
    # Each entry is a small dict like:
    # {"ts": "2026-01-10T04:00:00Z", "actor": "paladin316", "action": "save", "note": "..."}
    history: List[Dict[str, str]] = Field(default_factory=list)


class IntelBrief(BaseModel):
    meta: ArtifactMeta
    approval: ApprovalStatus = ApprovalStatus.DRAFT
    topic: str = ""
    sources: List[str] = Field(default_factory=list)

    # Extracted Indicators of Compromise (IOCs) by type (derived from source text / uploads)
    iocs: Dict[str, List[str]] = Field(default_factory=dict)

    # Threat_Intel_Brief_Report_Template.md aligned sections
    title: str = ""
    date: str = ""
    author: str = ""
    reference_id: str = ""

    bluf: str = ""
    background: str = ""
    threat_description: str = ""
    current_assessment: str = ""
    evidence_and_indicators: str = ""
    impact_assessment: str = ""
    confidence_and_credibility: str = ""
    gaps_and_collection: str = ""
    alternative_analysis: str = ""
    outlook: str = ""
    recommended_actions: str = ""
    summary_paragraphs: str = ""
    appendix: str = ""

    # Structured behaviors extracted from intel (source-agnostic)
    behaviors: List[Behavior] = Field(default_factory=list)

    # Optional: keep MITRE techniques as a structured list for downstream hunts
    observed_mitre_techniques: List[str] = Field(default_factory=list)

    # Optional: ATT&CK tactics observed / discussed (best-effort)
    observed_tactics: List[str] = Field(default_factory=list)



class IntelIOCs(BaseModel):
    """Sidecar artifact for extracted IOCs.

    Stored separately from IntelBrief so query builders can consume a stable,
    minimal schema without re-parsing the original intel content.
    """

    meta: ArtifactMeta
    intel_id: str
    iocs: Dict[str, List[str]] = Field(default_factory=dict)


class HuntQuery(BaseModel):
    title: str
    description: str = ""
    query_language: str = "CrowdStrike LogScale (CQL)"
    query: str
    technique: str = ""  # optional MITRE technique id (T#### or T####.###)

class Behavior(BaseModel):
    """Concrete, telemetry-expressible adversary behavior extracted from intel.

    v1 fields are intentionally simple and source-agnostic.
    """
    behavior_id: str = ""
    name: str = ""
    behavior_type: str = ""  # normalized category (e.g., PROCESS_EXECUTION, OUTBOUND_C2, EXFILTRATION)
    tactic: str = ""         # MITRE tactic (optional)
    technique: str = ""      # MITRE technique id (optional)
    confidence: str = "medium"  # low|medium|high
    sources: List[str] = Field(default_factory=list)

    # Anchors used to generate hunts. These should map cleanly to telemetry fields.
    anchors: Dict[str, Any] = Field(default_factory=dict)

    # Sequence hints (optional)
    order: int = 0
    within_seconds: Optional[int] = None


class HuntPackage(BaseModel):
    meta: ArtifactMeta
    linked_intel_id: str
    approval: ApprovalStatus = ApprovalStatus.DRAFT
    # Filled, human-readable markdown for the Hunt Package (template-rendered).
    rendered_markdown: str = ""
    objective: str = ""
    hypotheses: List[str] = Field(default_factory=list)
    data_sources: List[str] = Field(default_factory=list)
    queries: List[HuntQuery] = Field(default_factory=list)
    behaviors: List[Behavior] = Field(default_factory=list)
    scope_notes: str = ""
    execution_notes: str = ""
    ioc_stats: Dict[str, int] = Field(default_factory=dict)


class RunStep(BaseModel):
    name: str
    status: str
    detail: str = ""
    started_at: Optional[str] = None
    ended_at: Optional[str] = None


class Run(BaseModel):
    meta: ArtifactMeta
    linked_hunt_id: str
    linked_intel_id: str = ""
    status: RunStatus = RunStatus.READY
    steps: List[RunStep] = Field(default_factory=list)
    findings_created: List[str] = Field(default_factory=list)

    # Human-captured execution context (manual Run phase in v1)
    time_window_start: str = ""  # ISO8601 or free text
    time_window_end: str = ""    # ISO8601 or free text
    operator: str = ""
    run_notes: str = ""

    # Optional: draft IR-style run report (searchable) stored with the Run
    report_markdown: str = ""
    report_approval: ApprovalStatus = ApprovalStatus.DRAFT

    # --- Augmentation (v1.1) ---
    # Deterministic, evidence-driven annotations used to render higher-quality reports.
    # This is metadata (not a replacement for analyst notes).
    augmentation: Dict[str, Any] = Field(default_factory=dict)


class Finding(BaseModel):
    meta: ArtifactMeta
    linked_run_id: str
    linked_hunt_id: str = ""
    linked_intel_id: str = ""
    title: str
    description: str = ""
    severity: Severity = Severity.MEDIUM
    confidence: str = "Medium"
    evidence: List[str] = Field(default_factory=list)
    mitre_techniques: List[str] = Field(default_factory=list)
    analyst_notes: str = ""

    # --- Augmentation (v1.1) ---
    why_this_finding_exists: str = ""
    signal_summary: str = ""
    triage_questions: List[str] = Field(default_factory=list)
    recommended_next_steps: List[str] = Field(default_factory=list)
    confidence_drivers: List[str] = Field(default_factory=list)
    confidence_reducers: List[str] = Field(default_factory=list)
    disposition_guidance: str = ""

    approval: ApprovalStatus = ApprovalStatus.DRAFT


class ADS(BaseModel):
    meta: ArtifactMeta
    linked_finding_id: str
    linked_run_id: str = ""
    linked_hunt_id: str = ""
    linked_intel_id: str = ""
    linked_run_id: str = ""
    linked_hunt_id: str = ""
    linked_intel_id: str = ""

    # Core detection content
    detection_goal: str = ""
    logic: str = ""
    cql: str = ""

    # --- Augmentation (v1.1) ---
    why_this_ads_exists: str = ""
    signal_confidence_ladder: List[Dict[str, str]] = Field(default_factory=list)
    confidence_metadata: Dict[str, Any] = Field(default_factory=dict)
    promotion_criteria: Dict[str, Any] = Field(default_factory=dict)
    alerting_guidance: Dict[str, Any] = Field(default_factory=dict)

    # Known tuning / operational notes
    tuning: str = ""
    validation: str = ""
    deployment_notes: str = ""

    # Visibility (structured list retained for deterministic pipelines)
    telemetry: List[str] = Field(default_factory=list)

    # --- ADS_Template.txt aligned first-class fields (editable) ---
    technical_context: str = ""
    visibility_requirements: str = ""
    blind_spots: str = ""

    # --- Categorization (ATT&CK) ---
    mitre_tactics: List[str] = Field(default_factory=list)
    mitre_techniques: List[str] = Field(default_factory=list)

    # --- Operational lifecycle tracking (separate from approval) ---
    lifecycle_status: ADSLifecycleStatus = ADSLifecycleStatus.DRAFT
    detection_id: str = ""  # external reference (SIEM rule id, etc.)
    promoted_at: str = ""
    deployed_at: str = ""
    tuned_at: str = ""
    retired_at: str = ""

    # Content governance approval
    approval: ApprovalStatus = ApprovalStatus.DRAFT


Artifact = IntelBrief | HuntPackage | Run | Finding | ADS
