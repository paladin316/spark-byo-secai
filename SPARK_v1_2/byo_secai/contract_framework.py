from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import re
import yaml

from .logging_utils import get_logger


@dataclass
class ContractViolation:
    field: str
    code: str
    message: str


def _bundle_contract_dir() -> Path:
    return Path(__file__).resolve().parent / "contracts"


def _bundle_prompt_dir() -> Path:
    return Path(__file__).resolve().parent / "prompt_packs"


def _resolve_override_dir(override: str) -> Optional[Path]:
    if not override:
        return None
    try:
        p = Path(override).expanduser().resolve()
        return p if p.exists() else None
    except Exception:
        return None


def load_contract(profile: str, contract_dir_override: str = "") -> Tuple[Dict[str, Any], Path]:
    """Load a contract YAML by profile name.

    Search order:
      1) <override>/contracts/<profile>.yaml
      2) bundled: byo_secai/contracts/<profile>.yaml
    """
    logger = get_logger()
    override = _resolve_override_dir(contract_dir_override)
    if override:
        cand = override / "contracts" / f"{profile}.yaml"
        if cand.exists():
            data = yaml.safe_load(cand.read_text(encoding="utf-8", errors="ignore")) or {}
            logger.info("[CONTRACT] Loaded profile=%s (override=%s)", profile, cand)
            return (data if isinstance(data, dict) else {}), cand

    bundled = _bundle_contract_dir() / f"{profile}.yaml"
    data = yaml.safe_load(bundled.read_text(encoding="utf-8", errors="ignore")) or {}
    logger.info("[CONTRACT] Loaded profile=%s (bundled=%s)", profile, bundled)
    return (data if isinstance(data, dict) else {}), bundled


def load_prompt_pack(pack: str, artifact_key: str, prompt_dir_override: str = "") -> Tuple[str, str, Optional[Path]]:
    """Load system and user prompt for an artifact.

    Search order:
      1) <override>/prompt_packs/<pack>/<artifact_key>.system.txt
         <override>/prompt_packs/<pack>/<artifact_key>.user.txt
      2) bundled: byo_secai/prompt_packs/<pack>/...
    """
    override = _resolve_override_dir(prompt_dir_override)
    sys_name = f"{artifact_key}.system.txt"
    user_name = f"{artifact_key}.user.txt"

    if override:
        base = override / "prompt_packs" / pack
        sys_p = base / sys_name
        user_p = base / user_name
        if sys_p.exists() and user_p.exists():
            return (
                sys_p.read_text(encoding="utf-8", errors="ignore"),
                user_p.read_text(encoding="utf-8", errors="ignore"),
                base,
            )

    base = _bundle_prompt_dir() / pack
    sys_p = base / sys_name
    user_p = base / user_name
    return (
        sys_p.read_text(encoding="utf-8", errors="ignore") if sys_p.exists() else "",
        user_p.read_text(encoding="utf-8", errors="ignore") if user_p.exists() else "",
        base,
    )


def _looks_like_placeholder(text: str, placeholders: List[str]) -> bool:
    t = (text or "").strip().lower()
    if not t:
        return True
    for p in placeholders:
        if t == p:
            return True
    return False


def _word_count(text: str) -> int:
    return len(re.findall(r"\b\w+\b", (text or "")))


def _count_defanged_indicators(text: str) -> int:
    """Heuristic IOC count for Evidence & Indicators sections.

    We count common defanged patterns:
      - domains/IPs using [.] or hxxp
      - SHA256 hashes (64 hex)
      - CVE IDs
    """
    # Note: We intentionally recognize both defanged and non-defanged forms.
    # We count unique observable artifacts to reduce false negatives.
    t = text or ""
    found: set[str] = set()

    # URLs (defanged)
    for m in re.findall(r"\b(?:hxxp|hxxps)://[^\s)\]]+", t, flags=re.I):
        found.add(m.lower())

    # Domains (defanged or normal). Keep conservative to avoid counting plain sentences.
    domain_re = r"\b[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\[\.\]|\.)[a-z0-9-]{1,63}(?:\[\.\]|\.)[a-z]{2,24}\b"
    for m in re.findall(domain_re, t, flags=re.I):
        found.add(m.lower())

    # IPv4 (defanged or normal) with optional port.
    ip_re = r"\b\d{1,3}(?:\[\.\]|\.)\d{1,3}(?:\[\.\]|\.)\d{1,3}(?:\[\.\]|\.)\d{1,3}(?::\d{1,5})?\b"
    for m in re.findall(ip_re, t, flags=re.I):
        found.add(m)

    # SHA256
    for m in re.findall(r"\b[A-Fa-f0-9]{64}\b", t):
        found.add(m.lower())

    # CVE
    for m in re.findall(r"\bCVE-\d{4}-\d{4,7}\b", t, flags=re.I):
        found.add(m.upper())

    # Keep legacy defanged marker as a weak signal (doesn't count as an IOC by itself).
    # (We do not add "[.]" alone to the set.)
    return len(found)


def summarize_intel_brief(obj: Any, contract: Dict[str, Any]) -> Dict[str, Any]:
    """Return lightweight stats for logging and debugging."""
    rules = (contract or {}).get("rules") or {}
    required_text = rules.get("required_text_fields") or []
    min_lists = rules.get("min_list_lengths") or {}
    min_words = rules.get("min_word_counts") or {}
    evidence_rule = rules.get("evidence_indicator_min") or {}
    semantic_anchors = rules.get("semantic_anchors") or {}

    out: Dict[str, Any] = {}
    if isinstance(required_text, list):
        out["words"] = {f: _word_count(str(getattr(obj, f, "") or "")) for f in required_text}
    if isinstance(min_lists, dict):
        out["lists"] = {}
        for f in min_lists.keys():
            v = getattr(obj, f, [])
            out["lists"][str(f)] = len(v) if isinstance(v, list) else 0
    if isinstance(min_words, dict):
        out["min_word_counts"] = {str(k): int(v) for k, v in min_words.items() if str(v).isdigit()}
    if isinstance(evidence_rule, dict):
        out["evidence_indicator_min"] = int(evidence_rule.get("min", 0) or 0)
        try:
            ev_field = str(evidence_rule.get("field", "evidence_and_indicators") or "evidence_and_indicators")
        except Exception:
            ev_field = "evidence_and_indicators"
        out["evidence_indicator_count"] = _count_defanged_indicators(str(getattr(obj, ev_field, "") or ""))

    # Optional semantic anchor checks (used to avoid padding via word-count gates)
    if isinstance(semantic_anchors, dict):
        out["semantic_anchor_counts"] = {}
        for field, rule in semantic_anchors.items():
            if not isinstance(rule, dict):
                continue
            try:
                min_i = int(rule.get("min", 0) or 0)
            except Exception:
                min_i = 0
            anchors = rule.get("anchors") or []
            if not isinstance(anchors, list):
                anchors = []
            patterns = rule.get("patterns") or []
            if not isinstance(patterns, list):
                patterns = []

            try:
                txt = str(getattr(obj, str(field), "") or "")
            except Exception:
                txt = ""

            hits = 0
            seen = set()
            matched: List[str] = []

            for a in anchors:
                s = str(a).strip()
                if not s:
                    continue
                k = s.lower()
                if k in seen:
                    continue
                if k in txt.lower():
                    hits += 1
                    seen.add(k)
                    matched.append(s)

            for p in patterns:
                s = str(p).strip()
                if not s:
                    continue
                k = f"re:{s}"
                if k in seen:
                    continue
                try:
                    if re.search(s, txt, flags=re.I):
                        hits += 1
                        seen.add(k)
                        matched.append(k)
                except Exception:
                    continue

            # Keep the summary compact; the full violations list is already logged elsewhere.
            out["semantic_anchor_counts"][str(field)] = {
                "min": min_i,
                "hits": hits,
                "matched": matched[:8],
                "anchors": len(anchors),
                "patterns": len(patterns),
            }
    return out


def validate_intel_brief(obj: Any, contract: Dict[str, Any]) -> List[ContractViolation]:
    """Validate an IntelBrief object against contract rules.

    This validator is intentionally lightweight and focuses on analytic completeness.
    """
    violations: List[ContractViolation] = []
    rules = (contract or {}).get("rules") or {}
    if not isinstance(rules, dict):
        rules = {}

    placeholders = rules.get("placeholder_values") or []
    if not isinstance(placeholders, list):
        placeholders = []
    placeholders = [str(p).strip().lower() for p in placeholders if str(p).strip()]

    required_text = rules.get("required_text_fields") or []
    if not isinstance(required_text, list):
        required_text = []

    for field in required_text:
        try:
            val = getattr(obj, field, "")
        except Exception:
            val = ""
        if _looks_like_placeholder(str(val), placeholders):
            violations.append(
                ContractViolation(
                    field=str(field),
                    code="missing_or_placeholder",
                    message=f"Field '{field}' is empty or uses a placeholder.",
                )
            )

    min_lists = rules.get("min_list_lengths") or {}
    if isinstance(min_lists, dict):
        for field, min_len in min_lists.items():
            try:
                min_len_i = int(min_len)
            except Exception:
                continue
            try:
                val = getattr(obj, field, [])
            except Exception:
                val = []
            n = len(val) if isinstance(val, list) else 0
            if n < min_len_i:
                violations.append(
                    ContractViolation(
                        field=str(field),
                        code="min_list_length",
                        message=f"Field '{field}' must contain at least {min_len_i} item(s).",
                    )
                )

    # Minimum word counts for narrative completeness
    min_words = rules.get("min_word_counts") or {}
    if isinstance(min_words, dict):
        for field, min_wc in min_words.items():
            try:
                min_wc_i = int(min_wc)
            except Exception:
                continue
            try:
                val = getattr(obj, str(field), "")
            except Exception:
                val = ""
            wc = _word_count(str(val))
            if wc < min_wc_i:
                violations.append(
                    ContractViolation(
                        field=str(field),
                        code="min_word_count",
                        message=f"Field '{field}' must contain at least {min_wc_i} words (found {wc}).",
                    )
                )

    # Evidence & Indicators should include a minimum number of observable indicators (heuristic).
    evidence_rule = rules.get("evidence_indicator_min") or {}
    if isinstance(evidence_rule, dict):
        try:
            min_i = int(evidence_rule.get("min", 0) or 0)
        except Exception:
            min_i = 0
        try:
            ev_field = str(evidence_rule.get("field", "evidence_and_indicators") or "evidence_and_indicators")
        except Exception:
            ev_field = "evidence_and_indicators"
        if min_i > 0:
            try:
                ev_val = str(getattr(obj, ev_field, "") or "")
            except Exception:
                ev_val = ""
            cnt = _count_defanged_indicators(ev_val)
            if cnt < min_i:
                violations.append(
                    ContractViolation(
                        field=ev_field,
                        code="evidence_indicator_min",
                        message=f"Evidence section must include at least {min_i} defanged/observable indicator(s) (found {cnt}).",
                    )
                )

    # Optional semantic anchor checks for fields where word counts are a poor proxy for quality.
    semantic_anchors = rules.get("semantic_anchors") or {}
    if isinstance(semantic_anchors, dict):
        for field, rule in semantic_anchors.items():
            if not isinstance(rule, dict):
                continue
            try:
                min_i = int(rule.get("min", 0) or 0)
            except Exception:
                min_i = 0
            if min_i <= 0:
                continue
            anchors = rule.get("anchors") or []
            if not isinstance(anchors, list):
                anchors = []
            patterns = rule.get("patterns") or []
            if not isinstance(patterns, list):
                patterns = []
            try:
                txt = str(getattr(obj, str(field), "") or "")
            except Exception:
                txt = ""

            hits = 0
            seen = set()
            for a in anchors:
                s = str(a).strip()
                if not s:
                    continue
                if s.lower() in seen:
                    continue
                if s.lower() in txt.lower():
                    hits += 1
                    seen.add(s.lower())
            for p in patterns:
                s = str(p).strip()
                if not s:
                    continue
                key = f"re:{s}"
                if key in seen:
                    continue
                try:
                    if re.search(s, txt, flags=re.I):
                        hits += 1
                        seen.add(key)
                except Exception:
                    continue

            if hits < min_i:
                violations.append(
                    ContractViolation(
                        field=str(field),
                        code="semantic_anchor_min",
                        message=f"Field '{field}' must include at least {min_i} required analytic anchors/patterns (found {hits}).",
                    )
                )

    return violations


def format_violations(violations: List[ContractViolation]) -> str:
    lines: List[str] = []
    for v in violations:
        lines.append(f"- {v.field}: {v.message}")
    return "\n".join(lines)


def should_regen(enforcement_mode: str, regen_attempts: int) -> bool:
    if (enforcement_mode or "").strip().lower() != "strict":
        return False
    try:
        return int(regen_attempts) > 0
    except Exception:
        return False


def build_intel_brief_regen_guidance(violations: List[ContractViolation], contract: Dict[str, Any]) -> str:
    """Return targeted, non-fluffy guidance to help the model converge on contract compliance."""
    rules = (contract or {}).get("rules") or {}
    placeholders = rules.get("placeholder_values") or []
    if not isinstance(placeholders, list):
        placeholders = []
    placeholders = [str(p).strip() for p in placeholders if str(p).strip()]

    min_lists = rules.get("min_list_lengths") or {}
    min_words = rules.get("min_word_counts") or {}
    evidence_rule = rules.get("evidence_indicator_min") or {}
    semantic = rules.get("semantic_anchors") or {}

    lines: List[str] = []
    if placeholders:
        lines.append(f"- Do not output placeholders like: {', '.join(placeholders[:8])}.")

    # Common, high-impact convergence hints
    if isinstance(min_lists, dict) and "observed_mitre_techniques" in min_lists:
        try:
            n = int(min_lists.get("observed_mitre_techniques") or 0)
        except Exception:
            n = 0
        if n > 0:
            lines.append(
                f"- Observed MITRE Techniques: include at least {n} technique IDs (e.g., T####). Map them to behaviors/tools mentioned in the sources."
            )

    if isinstance(evidence_rule, dict):
        try:
            n = int(evidence_rule.get("min", 0) or 0)
        except Exception:
            n = 0
        if n > 0:
            lines.append(
                f"- Evidence & Indicators: include at least {n} observable/defanged indicators (IPs/domains with [.] or hxxp, CVEs, SHA256, filenames, registry paths)."
            )

    # Semantic anchors for Background/Evidence (avoid padding)
    if isinstance(semantic, dict):
        for field, rule in semantic.items():
            if not isinstance(rule, dict):
                continue
            try:
                min_i = int(rule.get("min", 0) or 0)
            except Exception:
                min_i = 0
            if min_i <= 0:
                continue
            anchors = rule.get("anchors") or []
            patterns = rule.get("patterns") or []
            if field == "background" and isinstance(anchors, list) and anchors:
                lines.append(
                    "- Background: anchor the narrative to the case. Include at least two concrete elements such as initial access, tooling, lateral movement, exfiltration, or ransomware outcomes."
                )
            if field == "evidence_and_indicators" and (patterns or anchors):
                lines.append(
                    "- Evidence & Indicators: structure into Network / Host / Identity / Cloud as applicable and include concrete artifacts (defanged IOCs, toolmarks, filenames, command-lines)."
                )

    # Word count guidance for remaining sections (still useful)
    if isinstance(min_words, dict):
        for f, wc in min_words.items():
            if str(f) in ("background", "evidence_and_indicators"):
                continue
            try:
                wci = int(wc)
            except Exception:
                continue
            if wci > 0:
                lines.append(f"- {f}: expand to at least {wci} words using estimative language and explicit reasoning (no filler).")

    # Directly reflect violations so the model doesn't miss them
    if violations:
        lines.append("- Fix these specific validation failures:")
        for v in violations[:12]:
            lines.append(f"  - {v.field}: {v.message}")

    return "\n".join(lines).strip()


_MITRE_TID_RE = re.compile(r"^T\d{4}(?:\.\d{3})?$")


def _extract_mitre_ids_from_hunt(obj: Any) -> List[str]:
    out: List[str] = []
    # HuntPackage has queries (HuntQuery) and behaviors (Behavior)
    try:
        for q in (getattr(obj, "queries", []) or []):
            tid = str(getattr(q, "technique", "") or "").strip()
            if tid and _MITRE_TID_RE.match(tid):
                out.append(tid)
    except Exception:
        pass
    try:
        for b in (getattr(obj, "behaviors", []) or []):
            tid = str(getattr(b, "technique", "") or "").strip()
            if tid and _MITRE_TID_RE.match(tid):
                out.append(tid)
    except Exception:
        pass
    # unique preserve order
    seen=set()
    uniq=[]
    for t in out:
        if t in seen:
            continue
        seen.add(t)
        uniq.append(t)
    return uniq


def summarize_hunt_package(obj: Any, contract: Dict[str, Any]) -> Dict[str, Any]:
    rules = (contract or {}).get("rules") or {}
    required_text = rules.get("required_text_fields") or []
    min_lists = rules.get("min_list_lengths") or {}
    semantic_anchors = rules.get("semantic_anchors") or {}
    mitre_min = rules.get("mitre_min") or {}

    out: Dict[str, Any] = {}
    if isinstance(required_text, list):
        out["words"] = {f: _word_count(str(getattr(obj, f, "") or "")) for f in required_text}
    if isinstance(min_lists, dict):
        out["lists"] = {}
        for f in min_lists.keys():
            v = getattr(obj, f, [])
            out["lists"][str(f)] = len(v) if isinstance(v, list) else 0
    if isinstance(semantic_anchors, dict):
        out["semantic_anchor_counts"] = {}
        for field, rule in semantic_anchors.items():
            if not isinstance(rule, dict):
                continue
            try:
                min_i = int(rule.get("min", 0) or 0)
            except Exception:
                min_i = 0
            anchors = rule.get("anchors") or []
            if not isinstance(anchors, list):
                anchors = []
            patterns = rule.get("patterns") or []
            if not isinstance(patterns, list):
                patterns = []

            try:
                val = getattr(obj, str(field), "")
            except Exception:
                val = ""
            if isinstance(val, list):
                txt = "\n".join(str(x) for x in val)
            else:
                txt = str(val or "")

            hits = 0
            seen = set()
            matched: List[str] = []
            for a in anchors:
                s = str(a).strip()
                if not s:
                    continue
                k = s.lower()
                if k in seen:
                    continue
                if k in txt.lower():
                    hits += 1
                    seen.add(k)
                    matched.append(s)
            for pat in patterns:
                s = str(pat).strip()
                if not s:
                    continue
                k = f"re:{s}"
                if k in seen:
                    continue
                try:
                    if re.search(s, txt, flags=re.I):
                        hits += 1
                        seen.add(k)
                        matched.append(k)
                except Exception:
                    continue
            out["semantic_anchor_counts"][str(field)] = {
                "min": min_i,
                "hits": hits,
                "matched": matched[:8],
                "anchors": len(anchors),
                "patterns": len(patterns),
            }

    try:
        min_tid = int((mitre_min or {}).get("min", 0) or 0)
    except Exception:
        min_tid = 0
    tids = _extract_mitre_ids_from_hunt(obj)
    out["mitre"] = {"min": min_tid, "found": len(tids), "techniques": tids[:10]}
    return out


def validate_hunt_package(obj: Any, contract: Dict[str, Any]) -> List[ContractViolation]:
    """Validate a HuntPackage object against contract rules."""
    violations: List[ContractViolation] = []
    rules = (contract or {}).get("rules") or {}
    if not isinstance(rules, dict):
        rules = {}

    placeholders = rules.get("placeholder_values") or []
    if not isinstance(placeholders, list):
        placeholders = []
    placeholders = [str(p).strip().lower() for p in placeholders if str(p).strip()]

    required_text = rules.get("required_text_fields") or []
    if not isinstance(required_text, list):
        required_text = []

    for field in required_text:
        try:
            val = getattr(obj, field, "")
        except Exception:
            val = ""
        # allow lists to be joined
        if isinstance(val, list):
            val = "\n".join(str(x) for x in val)
        if _looks_like_placeholder(str(val), placeholders):
            violations.append(
                ContractViolation(
                    field=str(field),
                    code="missing_or_placeholder",
                    message=f"Field '{field}' is empty or uses a placeholder.",
                )
            )

    min_lists = rules.get("min_list_lengths") or {}
    if isinstance(min_lists, dict):
        for field, min_len in min_lists.items():
            try:
                min_len_i = int(min_len)
            except Exception:
                continue
            try:
                val = getattr(obj, field, [])
            except Exception:
                val = []
            n = len(val) if isinstance(val, list) else 0
            if n < min_len_i:
                violations.append(
                    ContractViolation(
                        field=str(field),
                        code="min_list_length",
                        message=f"Field '{field}' must contain at least {min_len_i} item(s).",
                    )
                )

    # MITRE technique requirement (scan behaviors + queries)
    mitre_min = rules.get("mitre_min") or {}
    if isinstance(mitre_min, dict):
        try:
            min_i = int(mitre_min.get("min", 0) or 0)
        except Exception:
            min_i = 0
        if min_i > 0:
            tids = _extract_mitre_ids_from_hunt(obj)
            if len(tids) < min_i:
                violations.append(
                    ContractViolation(
                        field="mitre",
                        code="mitre_min",
                        message=f"Hunt Package must include at least {min_i} valid MITRE technique ID(s) (found {len(tids)}).",
                    )
                )

    # Optional semantic anchor checks
    semantic_anchors = rules.get("semantic_anchors") or {}
    if isinstance(semantic_anchors, dict):
        for field, rule in semantic_anchors.items():
            if not isinstance(rule, dict):
                continue
            try:
                min_i = int(rule.get("min", 0) or 0)
            except Exception:
                min_i = 0
            if min_i <= 0:
                continue
            anchors = rule.get("anchors") or []
            if not isinstance(anchors, list):
                anchors = []
            patterns = rule.get("patterns") or []
            if not isinstance(patterns, list):
                patterns = []

            try:
                val = getattr(obj, str(field), "")
            except Exception:
                val = ""
            if isinstance(val, list):
                txt = "\n".join(str(x) for x in val)
            else:
                txt = str(val or "")

            hits = 0
            seen = set()
            for a in anchors:
                s = str(a).strip()
                if not s:
                    continue
                k = s.lower()
                if k in seen:
                    continue
                if k in txt.lower():
                    hits += 1
                    seen.add(k)
            for ptn in patterns:
                s = str(ptn).strip()
                if not s:
                    continue
                k = f"re:{s}"
                if k in seen:
                    continue
                try:
                    if re.search(s, txt, flags=re.I):
                        hits += 1
                        seen.add(k)
                except Exception:
                    continue
            if hits < min_i:
                violations.append(
                    ContractViolation(
                        field=str(field),
                        code="semantic_anchor_min",
                        message=f"Field '{field}' must satisfy at least {min_i} semantic anchor(s)/pattern(s) (found {hits}).",
                    )
                )

    return violations


def build_hunt_package_regen_guidance(violations: List[ContractViolation], contract: Dict[str, Any]) -> str:
    """Build a short, actionable regen checklist for hunt packages."""
    items: List[str] = []
    fields = {v.field for v in (violations or [])}
    if "objective" in fields:
        items.append("- Rewrite Objective so it explicitly states the behavior being hunted AND the test/outcome (what would confirm/deny the hypothesis).")
    if "hypotheses" in fields:
        items.append("- Add at least 1 concrete hypothesis written as: 'If <behavior> then we expect to observe <telemetry condition> resulting in <outcome>'.")
    if "data_sources" in fields:
        items.append("- List at least 1 specific data source/telemetry set (e.g., ProcessRollup2, NetworkConnectIP4, auth logs, DNS telemetry).")
    if "scope_notes" in fields:
        items.append("- Update Scope & Assumptions to include environment/platform boundaries (endpoint/cloud/network; Windows/Azure/SaaS).")
    if "execution_notes" in fields:
        items.append("- Update Execution Notes with runnable steps (run queries, review hits, pivot/enrich, document findings, decide next actions).")
    if "mitre" in fields:
        items.append("- Add at least 1 valid MITRE technique ID (T#### or T####.###) mapped to the hunt behaviors.")
    if not items:
        items.append("- Address all listed validation issues with specific, testable hunt content. Do not change queries unless explicitly required.")
    return "\n".join(items)



# ---------------------------------------------------------------------------
# v1.1: Contracts for Runs / Findings / ADS
# ---------------------------------------------------------------------------

def _validate_text_and_anchor_rules(obj: Any, rules: Dict[str, Any], placeholders: List[str]) -> List[ContractViolation]:
    violations: List[ContractViolation] = []
    required_text = rules.get("required_text_fields") or []
    min_words = rules.get("min_word_counts") or {}
    semantic_anchors = rules.get("semantic_anchors") or {}
    min_lists = rules.get("min_list_lengths") or {}

    # Required text (non-empty, not placeholder)
    for f in (required_text if isinstance(required_text, list) else []):
        try:
            val = str(getattr(obj, str(f), "") or "")
        except Exception:
            val = ""
        if _looks_like_placeholder(val, placeholders):
            violations.append(ContractViolation(field=str(f), code="REQUIRED", message="Field is missing or placeholder"))

    # Min words
    if isinstance(min_words, dict):
        for f, n in min_words.items():
            try:
                n_i = int(n)
            except Exception:
                continue
            try:
                val = str(getattr(obj, str(f), "") or "")
            except Exception:
                val = ""
            if _word_count(val) < n_i:
                violations.append(ContractViolation(field=str(f), code="MIN_WORDS", message=f"Minimum word count is {n_i}"))

    # List lengths
    if isinstance(min_lists, dict):
        for f, n in min_lists.items():
            try:
                n_i = int(n)
            except Exception:
                n_i = 0
            v = getattr(obj, str(f), []) if hasattr(obj, str(f)) else []
            ln = len(v) if isinstance(v, list) else 0
            if ln < n_i:
                violations.append(ContractViolation(field=str(f), code="MIN_LIST", message=f"Minimum list length is {n_i}"))

    # Semantic anchors (best-effort)
    if isinstance(semantic_anchors, dict):
        for field, rule in semantic_anchors.items():
            if not isinstance(rule, dict):
                continue
            try:
                min_i = int(rule.get("min", 0) or 0)
            except Exception:
                min_i = 0
            anchors = rule.get("anchors") or []
            patterns = rule.get("patterns") or []
            if not isinstance(anchors, list):
                anchors = []
            if not isinstance(patterns, list):
                patterns = []

            try:
                txt = str(getattr(obj, str(field), "") or "")
            except Exception:
                txt = ""
            hits = 0
            for a in anchors:
                s = str(a).strip()
                if s and s.lower() in txt.lower():
                    hits += 1
            for p in patterns:
                s = str(p).strip()
                if not s:
                    continue
                try:
                    if re.search(s, txt, flags=re.I):
                        hits += 1
                except Exception:
                    pass

            if hits < min_i:
                violations.append(ContractViolation(field=str(field), code="SEMANTIC_ANCHORS", message=f"Expected >= {min_i} anchor/pattern hits; got {hits}"))

    return violations


def validate_ads(obj: Any, contract: Dict[str, Any]) -> List[ContractViolation]:
    rules = (contract or {}).get("rules") or {}
    placeholders = rules.get("placeholders") or ["tbd", "(tbd)", "n/a", "(none)"]
    return _validate_text_and_anchor_rules(obj, rules, placeholders)


def validate_finding(obj: Any, contract: Dict[str, Any]) -> List[ContractViolation]:
    rules = (contract or {}).get("rules") or {}
    placeholders = rules.get("placeholders") or ["tbd", "(tbd)", "n/a", "(none)"]
    return _validate_text_and_anchor_rules(obj, rules, placeholders)


def validate_run(obj: Any, contract: Dict[str, Any]) -> List[ContractViolation]:
    rules = (contract or {}).get("rules") or {}
    placeholders = rules.get("placeholders") or ["tbd", "(tbd)", "n/a", "(none)"]
    v = _validate_text_and_anchor_rules(obj, rules, placeholders)

    # Optional: augmentation keys
    req_keys = rules.get("required_augmentation_keys") or []
    if isinstance(req_keys, list) and req_keys:
        aug = getattr(obj, "augmentation", {}) if obj is not None else {}
        if not isinstance(aug, dict):
            aug = {}
        for k in req_keys:
            if str(k) not in aug:
                v.append(ContractViolation(field=f"augmentation.{k}", code="REQUIRED", message="Missing augmentation key"))

    return v
