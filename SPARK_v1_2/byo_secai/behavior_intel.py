from __future__ import annotations

import re
from typing import Any, Dict, List, Tuple

from .models import Behavior

# --- v1 vocab ---
VERB_PATTERNS: List[Tuple[str, str]] = [
    ("PROCESS_EXECUTION", r"\b(executed|launched|ran|run|spawned|started)\b"),
    ("DOWNLOAD", r"\b(downloaded|fetched|retrieved|dropped)\b"),
    ("OUTBOUND_C2", r"\b(beaconed|connected|communicated|called\s+back|c2|command\s+and\s+control)\b"),
    ("PERSISTENCE", r"\b(persist(ed|ence)|installed|registered|autorun|scheduled\s+task|run\s+key|service)\b"),
    ("CREDENTIAL_ACCESS", r"\b(credential|creds|password|hash|dump(ed)?|lsass|ntds\.dit|sam)\b"),
    ("LATERAL_MOVEMENT", r"\b(lateral|psexec|wmic|wmi|remote\s+service|rdp)\b"),
    ("EXFILTRATION", r"\b(exfiltrat(ed|ion)|upload(ed)?|transfer(red)?|rclone|mega\.io|ftp)\b"),
    ("RANSOMWARE", r"\b(ransomware|encrypt(ed|ion)|lockbit)\b"),
]

TOOL_BEHAVIORS: Dict[str, Dict[str, Any]] = {
    "cobalt strike": {"behavior_type": "OUTBOUND_C2", "tactic": "Command and Control"},
    "systembc": {"behavior_type": "OUTBOUND_C2", "tactic": "Command and Control"},
    "ghostsocks": {"behavior_type": "OUTBOUND_C2", "tactic": "Command and Control"},
    "rclone": {"behavior_type": "EXFILTRATION", "tactic": "Exfiltration"},
    "psexec": {"behavior_type": "LATERAL_MOVEMENT", "tactic": "Lateral Movement"},
    "wmic": {"behavior_type": "LATERAL_MOVEMENT", "tactic": "Lateral Movement"},
    "wmi": {"behavior_type": "LATERAL_MOVEMENT", "tactic": "Lateral Movement"},
    "ntdsutil": {"behavior_type": "CREDENTIAL_ACCESS", "tactic": "Credential Access"},
    "ntds.dit": {"behavior_type": "CREDENTIAL_ACCESS", "tactic": "Credential Access"},
    "lsass": {"behavior_type": "CREDENTIAL_ACCESS", "tactic": "Credential Access"},
}

SEQUENCE_HINTS = [
    r"\bafter\b",
    r"\bthen\b",
    r"\bfollowed\s+by\b",
    r"\bsubsequently\b",
    r"\blater\b",
    r"\bprior\s+to\b",
]


def _sentences(text: str) -> List[str]:
    # cheap sentence splitter good enough for v1
    parts = re.split(r"(?<=[\.!\?])\s+", text.strip())
    return [p.strip() for p in parts if p.strip()]


def _pick_anchors(sentence: str, iocs: Dict[str, List[str]]) -> Dict[str, Any]:
    anchors: Dict[str, Any] = {}
    s_lower = sentence.lower()

    # File anchors (simple)
    files = [f for f in (iocs.get("file") or []) if isinstance(f, str) and f.lower() in s_lower]
    if files:
        anchors["file_names"] = sorted(set(files))[:10]

    # Domain/URL anchors
    domains = [d for d in (iocs.get("domain") or []) if isinstance(d, str) and d.lower().strip(".") in s_lower]
    if domains:
        anchors["domains"] = sorted(set([d.lower().strip(".") for d in domains]))[:10]

    urls = [u for u in (iocs.get("url") or []) if isinstance(u, str) and u.lower().rstrip(".,);]") in s_lower]
    if urls:
        anchors["urls"] = sorted(set([u.rstrip(".,);]") for u in urls]))[:10]

    # IP:Port anchors
    ip_ports = []
    for v in (iocs.get("ip_port") or []):
        if isinstance(v, str):
            vp = v.strip()
            if vp and vp in sentence:
                ip_ports.append(vp)
    if ip_ports:
        anchors["ip_ports"] = sorted(set(ip_ports))[:25]

    # Tools by keyword
    tools = []
    for tool in TOOL_BEHAVIORS.keys():
        if tool in s_lower:
            tools.append(tool)
    if tools:
        anchors["tools"] = sorted(set(tools))

    # Sequence hint
    if any(re.search(h, s_lower) for h in SEQUENCE_HINTS):
        anchors["sequence_hint"] = True

    return anchors


def normalize_iocs(iocs: Dict[str, List[str]]) -> Dict[str, List[str]]:
    """Normalize/dedupe IOC strings for behavior extraction (separate from query building)."""
    out: Dict[str, List[str]] = {}

    # domains
    doms = []
    for d in (iocs.get("domain") or []):
        if not isinstance(d, str):
            continue
        dd = d.strip().strip(".").lower()
        if dd:
            doms.append(dd)
    out["domain"] = sorted(set(doms))

    # urls
    urls = []
    for u in (iocs.get("url") or []):
        if not isinstance(u, str):
            continue
        uu = u.strip().rstrip(".,);]")
        if uu:
            urls.append(uu)
    out["url"] = sorted(set(urls))

    # ip_port / ip / file
    out["ip_port"] = sorted(set([x.strip() for x in (iocs.get("ip_port") or []) if isinstance(x, str) and x.strip()]))
    out["ip"] = sorted(set([x.strip() for x in (iocs.get("ip") or []) if isinstance(x, str) and x.strip()]))
    out["file"] = sorted(set([x.strip() for x in (iocs.get("file") or []) if isinstance(x, str) and x.strip()]))

    # hash: keep all for context, but normalize hex
    hashes = []
    for h in (iocs.get("hash") or []):
        if not isinstance(h, str):
            continue
        hh = h.strip()
        if re.fullmatch(r"[A-Fa-f0-9]{32}|[A-Fa-f0-9]{40}|[A-Fa-f0-9]{64}", hh or ""):
            hashes.append(hh.lower())
    out["hash"] = sorted(set(hashes))

    return out


def extract_behaviors_from_intel(intel_title: str, intel_text: str, iocs: Dict[str, List[str]], sources: List[str] | None = None) -> List[Behavior]:
    """Pattern-based behavior extraction (v1).

    Inputs are source-agnostic: any intel narrative text + IOC bundle.
    """
    sources = sources or []
    iocs_n = normalize_iocs(iocs)

    behaviors: List[Behavior] = []
    sentences = _sentences(intel_text)

    order = 0
    for sent in sentences:
        s_lower = sent.lower()

        # Tool-driven behaviors (high confidence)
        for tool, meta in TOOL_BEHAVIORS.items():
            if tool in s_lower:
                order += 1
                anchors = _pick_anchors(sent, iocs_n)
                anchors.setdefault("tools", [])
                if tool not in anchors["tools"]:
                    anchors["tools"].append(tool)
                b = Behavior(
                    behavior_id=f"BHV-{order:04d}",
                    name=f"{meta.get('behavior_type','BEHAVIOR')} via {tool}",
                    behavior_type=meta.get("behavior_type", ""),
                    tactic=meta.get("tactic", ""),
                    technique="",
                    confidence="high",
                    sources=sources,
                    anchors=anchors,
                    order=order,
                    within_seconds=300 if anchors.get("sequence_hint") else None,
                )
                behaviors.append(b)

        # Verb-driven behaviors
        for btype, vpat in VERB_PATTERNS:
            if re.search(vpat, s_lower):
                order += 1
                anchors = _pick_anchors(sent, iocs_n)
                # skip if no anchors at all (too vague)
                if not anchors:
                    continue
                b = Behavior(
                    behavior_id=f"BHV-{order:04d}",
                    name=f"{btype}: {intel_title}".strip(),
                    behavior_type=btype,
                    tactic="",
                    technique="",
                    confidence="medium",
                    sources=sources,
                    anchors=anchors,
                    order=order,
                    within_seconds=300 if anchors.get("sequence_hint") else None,
                )
                behaviors.append(b)

    # Dedup by (behavior_type + key anchors)
    seen = set()
    deduped: List[Behavior] = []
    for b in behaviors:
        key = (b.behavior_type, tuple(sorted((b.anchors.get("tools") or []))), tuple(sorted((b.anchors.get("file_names") or []))), tuple(sorted((b.anchors.get("domains") or []))))
        if key in seen:
            continue
        seen.add(key)
        deduped.append(b)

    # Stable ordering
    deduped.sort(key=lambda x: x.order or 0)
    return deduped
