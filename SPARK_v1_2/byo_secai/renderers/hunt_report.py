from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, List, Optional


# ------------------------------
# HuntReportRenderer v1 Schema
# ------------------------------

@dataclass
class HuntReportV1:
    """Schema for the rendered Threat Hunt Package report (deliverable)."""

    title: str
    tagline: str

    threat_overview: str
    objective: str
    scope_in: str
    scope_out: str

    indicators_and_queries: str

    findings_summary: str
    technical_findings: str

    recommended_interpretation: str
    reporting_summary: str
    optional_add_ons: str
    hunt_metadata: str


def _bullets(items: List[str]) -> str:
    items = [x.strip() for x in (items or []) if str(x).strip()]
    if not items:
        return "- (none)"
    return "\n".join([f"- {x}" for x in items])

def _behaviors_md(behaviors: List[Any]) -> str:
    bs = behaviors or []
    if not bs:
        return "- (none)"
    out: List[str] = []
    for b in bs[:20]:
        name = getattr(b, "name", "") or getattr(b, "behavior_type", "") or "Behavior"
        btype = getattr(b, "behavior_type", "") or ""
        anchors = getattr(b, "anchors", {}) or {}
        anchor_keys = [k for k, v in anchors.items() if v and k not in ("sequence_hint",)]
        out.append(f"- **{name}** ({btype}) — anchors: {', '.join(anchor_keys) if anchor_keys else '(none)'}")
    return "\n".join(out) if out else "- (none)"


def _render_queries(hunt: Any) -> str:
    qs = getattr(hunt, "queries", None) or []
    if not qs:
        return "No hunt queries are currently defined."

    blocks: List[str] = []
    for q in qs:
        title = (q.get("title") if isinstance(q, dict) else getattr(q, "title", "")).strip() or "Untitled Query"
        desc = (q.get("description") if isinstance(q, dict) else getattr(q, "description", "")).strip()
        ql = (q.get("query_language") if isinstance(q, dict) else getattr(q, "query_language", "")).strip() or ""
        body = (q.get("query") if isinstance(q, dict) else getattr(q, "query", "")).strip()

        blocks.append(f"### {title}\n")
        if desc:
            blocks.append(f"{desc}\n")
        if ql:
            blocks.append(f"**Query Language:** {ql}\n")
        if body:
            blocks.append("```\n" + body + "\n```\n")

    return "\n".join(blocks).strip()


def build_hunt_report_v1(hunt: Any, intel: Any | None = None) -> HuntReportV1:
    # Title/tagline
    topic = (getattr(intel, "topic", None) or getattr(intel, "title", None) or "").strip() if intel else ""
    title = topic or (getattr(getattr(hunt, "meta", None), "title", None) or "Threat Hunt Package").strip()
    tagline = (getattr(getattr(hunt, "meta", None), "tagline", None) or "").strip() or "(HUNT_TAGLINE_OR_FOCUS)"

    # Threat Overview (map: intel.threat_description/bluf/impact)
    bluf = (getattr(intel, "bluf", "") or "").strip() if intel else ""
    threat_desc = (getattr(intel, "threat_description", "") or "").strip() if intel else ""
    impact = (getattr(intel, "impact_assessment", "") or "").strip() if intel else ""

    overview_parts: List[str] = []
    if threat_desc:
        overview_parts.append(threat_desc)
    elif bluf:
        overview_parts.append(bluf)

    if impact:
        overview_parts.append("**Why it matters:**\n" + impact)

    # Add quick IOC totals (context only)
    iocs = getattr(intel, "iocs", None) if intel else None
    if isinstance(iocs, dict):
        totals = {k: len(v or []) for k, v in iocs.items()}
        # Hash sub-counts
        hashes = iocs.get("hash", []) or []
        md5 = sum(1 for h in hashes if isinstance(h, str) and len(h.strip()) == 32)
        sha1 = sum(1 for h in hashes if isinstance(h, str) and len(h.strip()) == 40)
        sha256 = sum(1 for h in hashes if isinstance(h, str) and len(h.strip()) == 64)
        totals_line = (
            f"**IOC Totals:** ip_port={totals.get('ip_port',0)}, ip={totals.get('ip',0)}, domain={totals.get('domain',0)}, "
            f"url={totals.get('url',0)}, file={totals.get('file',0)}, hash={totals.get('hash',0)}\n"
            f"- Hashes (queryable): SHA256={sha256}\n"
            f"- Hashes (context only): SHA1={sha1}, MD5={md5}"
        )
        # IOC query coverage counters (from HuntPackage generation)
        stats = getattr(hunt, "ioc_stats", None) or {}
        if stats:
            overview_parts.append(
                f"**IOC Query Coverage:** included={stats.get('included',0)} / context-only={stats.get('context_only',0)} / invalid={stats.get('invalid',0)}"
            )

        overview_parts.append(totals_line)

    threat_overview = "\n\n".join([p for p in overview_parts if p]).strip() or "Threat overview not yet captured."

    # Objective (map: hunt.objective + hypotheses)
    obj = (getattr(hunt, "objective", "") or "").strip()
    hyps = getattr(hunt, "hypotheses", None) or []
    objective = obj or "Objective not yet captured."
    if hyps:
        objective += "\n\n**Hypotheses:**\n" + _bullets([str(x) for x in hyps])

    # Scope (map: hunt.data_sources + scope_notes)
    ds = getattr(hunt, "data_sources", None) or []
    scope_notes = (getattr(hunt, "scope_notes", "") or "").strip()

    scope_in = "**Data Sources / Telemetry**\n" + _bullets([str(x) for x in ds])
    if scope_notes:
        scope_in += "\n\n" + scope_notes

    scope_out = "- (not specified)"

    # Indicators & Queries (map: hunt.queries)
    indicators_and_queries = _render_queries(hunt)

    # Findings sections are generally empty until a Run executes
    findings_summary = "No findings have been recorded for this hunt package yet. Execute a Run to generate Findings."
    technical_findings = "(execution pending)"

    # Recommendations / reporting summary (deterministic, non-TBD)
    recommended_interpretation = "Use Section 4 queries to validate the hypotheses. Escalate any true positives into Findings and promote to ADS once tuned."

    reporting_summary = "\n".join([
        f"Threat: {title}",
        "Status: Draft",
        "Next Step: Execute hunt queries and record Findings",
    ])

    optional_add_ons = "- IOC sweep queries are included in Section 4 when supported by telemetry.\n- MD5/SHA1 are retained for context but are not used for query sweeps."

    # Metadata
    meta_lines: List[str] = []
    meta = getattr(hunt, "meta", None)
    if meta:
        for field in ["artifact_id", "created_at", "updated_at"]:
            v = getattr(meta, field, None)
            if v:
                meta_lines.append(f"- {field}: {v}")
    linked = getattr(hunt, "linked_intel_id", None)
    if linked:
        meta_lines.append(f"- linked_intel_id: {linked}")
    hunt_metadata = "\n".join(meta_lines).strip() or "- (no metadata)"

    return HuntReportV1(
        title=title,
        tagline=tagline,
        threat_overview=threat_overview,
        objective=objective,
        scope_in=scope_in,
        scope_out=scope_out,
        indicators_and_queries=indicators_and_queries,
        findings_summary=findings_summary,
        technical_findings=technical_findings,
        recommended_interpretation=recommended_interpretation,
        reporting_summary=reporting_summary,
        optional_add_ons=optional_add_ons,
        hunt_metadata=hunt_metadata,
    )


def render_hunt_report_markdown_v1(hunt: Any, intel: Any | None = None) -> str:
    """Render a HuntReportV1 as markdown. This is the *deliverable* output."""
    r = build_hunt_report_v1(hunt, intel=intel)

    md = f"""# Threat Hunt Package – {r.title}

{r.tagline}

---

## 1. Threat Overview

{r.threat_overview}

---

## 2. Objective

{r.objective}

---

## 3. Hunt Scope

### 3.1 In-Scope

{r.scope_in}

### 3.2 Out-of-Scope

{r.scope_out}

---

## 4. High-Fidelity Indicators & Hunt Queries

{r.indicators_and_queries}

---

## 5. Findings

### 5.1 Summary

{r.findings_summary}

### 5.2 Technical Findings

{r.technical_findings}

---

## 6. Recommended Analyst Interpretation

{r.recommended_interpretation}

---

## 7. Reporting Summary (Copy/Paste Ready)

{r.reporting_summary}

---

## 8. Optional Add-Ons (If Applicable)

{r.optional_add_ons}

---

## 9. Hunt Metadata

{r.hunt_metadata}
"""
    try:
        from ..config import load_config_yaml
        cfg = load_config_yaml() or {}
        footer = (cfg.get("report_footer") or "").strip() or "Generated by SPARK (powered by BYO-SecAI)"
    except Exception:
        footer = "Generated by SPARK (powered by BYO-SecAI)"
    return md.strip() + "\n\n---\n" + footer + "\n"