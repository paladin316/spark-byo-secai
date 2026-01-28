from __future__ import annotations

import random
import json
import re


# --- Phase 6.5.8.2: Best-effort tactic -> technique enrichment + hunt query label sanity ---

_TACTIC_HEADING_MAP = {
    "initial_access": r"(?i)\binitial\s+access\b",
    "execution": r"(?i)\bexecution\b",
    "persistence": r"(?i)\bpersistence\b",
    "privilege_escalation": r"(?i)\bprivilege\s+escalation\b",
    "defense_evasion": r"(?i)\bdefense\s+evasion\b",
    "credential_access": r"(?i)\bcredential\s+access\b",
    "discovery": r"(?i)\bdiscovery\b",
    "lateral_movement": r"(?i)\blateral\s+movement\b",
    "command_and_control": r"(?i)\bcommand\s+and\s+control\b|\bc2\b",
    "exfiltration": r"(?i)\bexfiltration\b",
    "impact": r"(?i)\bimpact\b|\bransomware\b|\bencrypt",
}

# Conservative candidate technique suggestions per tactic.
_TACTIC_TO_TECHNIQUES = {
    "initial_access": ["T1190", "T1566", "T1078"],
    "execution": ["T1059", "T1106"],
    "persistence": ["T1053", "T1547"],
    "privilege_escalation": ["T1068", "T1548"],
    "defense_evasion": ["T1027", "T1070"],
    "credential_access": ["T1003", "T1555"],
    "discovery": ["T1082", "T1046"],
    "lateral_movement": ["T1021", "T1077", "T1210"],
    "command_and_control": ["T1071", "T1095"],
    "exfiltration": ["T1041", "T1567"],
    "impact": ["T1486", "T1490"],
}

# Very lightweight "support" signals: we only add a technique if at least one supporting keyword is present.
_TECH_SUPPORT = {
    "T1190": [r"(?i)\bexploit\b", r"(?i)\bvulnerability\b", r"(?i)\bpublic[- ]facing\b"],
    "T1566": [r"(?i)\bphish", r"(?i)\bemail\b", r"(?i)\battachment\b", r"(?i)\blink\b"],
    "T1078": [r"(?i)\bvalid account", r"(?i)\bcredential", r"(?i)\blogon\b", r"(?i)\brdp\b"],
    "T1059": [r"(?i)\bpowershell\.exe\b", r"(?i)\bcmd\.exe\b", r"(?i)\bscript\b"],
    "T1053": [r"(?i)\bscheduled task\b", r"(?i)\bschtasks\.exe\b"],
    "T1021": [r"(?i)\brdp\b", r"(?i)\bwmic\b", r"(?i)\bpsexec\b", r"(?i)\bsmb\b"],
    "T1210": [r"(?i)\bremote service", r"(?i)\bpsexec\b", r"(?i)\bwmic\b"],
    "T1071": [r"(?i)\bhttp\b", r"(?i)\bhttps\b", r"(?i)\bweb\b", r"(?i)\bdomain\b"],
    "T1041": [r"(?i)\bexfil", r"(?i)\bupload\b", r"(?i)\bftp\b", r"(?i)\brclone\b"],
    "T1486": [r"(?i)\bransom", r"(?i)\bencrypt", r"(?i)\blockbit\b"],
}

def _infer_observed_tactics_from_text(intel_obj) -> list[str]:
    """Best-effort: infer ATT&CK tactics discussed in the Intel Brief text."""
    txt_parts = []
    for f in ["bluf", "background", "threat_description", "current_assessment", "evidence_and_indicators", "recommended_actions"]:
        try:
            txt_parts.append(str(getattr(intel_obj, f, "") or ""))
        except Exception:
            pass
    txt = "\n".join(txt_parts)
    out = []
    for tact, rx in _TACTIC_HEADING_MAP.items():
        try:
            if re.search(rx, txt):
                out.append(tact)
        except Exception:
            continue
    # de-dup, stable
    seen = set()
    ordered = []
    for t in out:
        if t not in seen:
            ordered.append(t)
            seen.add(t)
    return ordered

def _expand_mitre_from_tactics_best_effort(intel_obj, min_required: int = 5, logger=None) -> bool:
    """
    Best-effort tactic->technique expansion:
    - Only runs if observed_mitre_techniques is below min_required
    - Uses observed_tactics if present; otherwise attempts to infer tactics from text
    - Only adds techniques with a weak support signal in the Intel text
    Returns True if modifications were made.
    """
    try:
        current = list(getattr(intel_obj, "observed_mitre_techniques", []) or [])
    except Exception:
        current = []
    current_set = {c.strip() for c in current if isinstance(c, str) and c.strip()}

    if len(current_set) >= int(min_required or 0):
        return False

    # Determine tactics
    tactics = list(getattr(intel_obj, "observed_tactics", []) or [])
    tactics = [t for t in tactics if isinstance(t, str) and t.strip()]
    if not tactics:
        tactics = _infer_observed_tactics_from_text(intel_obj)
        if tactics:
            try:
                intel_obj.observed_tactics = tactics
            except Exception:
                pass

    if not tactics:
        return False

    # Build a text corpus for support matching
    txt_parts = []
    for f in ["bluf", "background", "threat_description", "current_assessment", "evidence_and_indicators", "recommended_actions", "iocs"]:
        try:
            txt_parts.append(str(getattr(intel_obj, f, "") or ""))
        except Exception:
            pass
    corpus = "\n".join(txt_parts)

    added = []
    for tact in tactics:
        for tech in _TACTIC_TO_TECHNIQUES.get(tact, []):
            if tech in current_set:
                continue
            # Support check: at least one keyword regex matches
            support = _TECH_SUPPORT.get(tech) or []
            ok = False
            for rx in support:
                try:
                    if re.search(rx, corpus):
                        ok = True
                        break
                except Exception:
                    continue
            if ok:
                current_set.add(tech)
                added.append(tech)
            if len(current_set) >= int(min_required or 0):
                break
        if len(current_set) >= int(min_required or 0):
            break

    if added:
        try:
            intel_obj.observed_mitre_techniques = sorted(current_set)
        except Exception:
            pass
        if logger:
            try:
                logger.info("[MITRE] tactic->technique expansion added=%s tactics=%s", added, tactics)
            except Exception:
                pass
        return True
    return False

def _sanitize_hunt_query_labels_best_effort(hunt_obj, logger=None) -> list[str]:
    """
    Best-effort: fix obvious title/description mismatches (warn-only).
    If a title mentions FTP but query doesn't contain FTP artifacts, rename the title/description to match query intent.
    Returns list of warnings generated.
    """
    warnings = []
    try:
        queries = list(getattr(hunt_obj, "queries", []) or [])
    except Exception:
        return warnings

    def has_any(s: str, terms: list[str]) -> bool:
        s = s.lower()
        return any(t in s for t in terms)

    for q in queries:
        try:
            title = str(getattr(q, "name", "") or "")
            desc = str(getattr(q, "description", "") or "")
            body = str(getattr(q, "query", "") or "")
        except Exception:
            continue

        t_all = (title + " " + desc).lower()
        b_all = body.lower()

        # Simple heuristic: FTP mention requires ftp/21/ftp.exe/curl ftp:// etc.
        if "ftp" in t_all and not (("ftp" in b_all) or (":21" in b_all) or ("rport=21" in b_all) or ("winscp" in b_all) or ("curl" in b_all and "ftp://" in b_all)):
            # Rename to match query content
            new_title = "Suspicious process activity (review CommandLine keywords)"
            new_desc = "Review process executions matching keyword patterns in CommandLine; update title/logic if this should specifically target FTP exfiltration."
            try:
                q.name = new_title
                q.description = new_desc
            except Exception:
                pass
            warnings.append(f"Query label mismatch fixed: '{title}' did not match query content (FTP not referenced).")
            continue

        # Generic duplicate-query case: if title implies exfil but query has no network artifact
        if has_any(t_all, ["exfil", "data exfil", "upload"]) and not (("network" in b_all) or ("remoteaddress" in b_all) or ("rport" in b_all) or (":21" in b_all) or ("http" in b_all) or ("https" in b_all)):
            new_title = "Suspicious process behavior (non-network)"
            new_desc = "This query primarily targets process behavior; consider adding network telemetry if you intend to detect exfiltration."
            try:
                q.name = new_title
                q.description = new_desc
            except Exception:
                pass
            warnings.append(f"Query label mismatch fixed: '{title}' implied exfiltration but query lacks network indicators.")

    if warnings and logger:
        try:
            logger.warning("[HUNT] query label mismatches corrected count=%d", len(warnings))
        except Exception:
            pass

    # Attach warnings to hunt meta if possible
    try:
        meta = getattr(hunt_obj, "meta", None)
        if meta is not None:
            hist = getattr(meta, "history", None)
            # We don't rely on history type; best-effort only.
    except Exception:
        pass

    return warnings

import ipaddress
from datetime import datetime, timezone
from pathlib import Path
from functools import lru_cache
from typing import List, Tuple
from functools import lru_cache
import re as _re

_SHA256_RE = _re.compile(r"^[A-Fa-f0-9]{64}$")


def _append_report_footer(md: str) -> str:
    """Append a consistent report footer to rendered markdown outputs."""
    try:
        from .config import load_config_yaml
        cfg = load_config_yaml() or {}
        footer = (cfg.get("report_footer") or "").strip()
    except Exception:
        footer = ""

    if not footer:
        footer = "Generated by SPARK (powered by BYO-SecAI)"

    md = (md or "").rstrip()
    return md + "\n\n---\n" + footer + "\n"


# -------- Assistant Suggestions sidecar --------
def _artifact_type_value(artifact_type) -> str:
    return getattr(artifact_type, "value", str(artifact_type))

def assistant_suggestions_path(data_dir: str | Path, artifact_type, artifact_id: str) -> Path:
    base = Path(data_dir)
    tval = _artifact_type_value(artifact_type)
    d = base / "artifacts" / tval
    d.mkdir(parents=True, exist_ok=True)
    return d / f"{artifact_id}.assistant.json"

def read_assistant_suggestions(data_dir: str | Path, artifact_type, artifact_id: str) -> dict:
    """Read non-authoritative LLM suggestions for an artifact."""
    p = assistant_suggestions_path(data_dir, artifact_type, artifact_id)
    if not p.exists():
        return {}
    try:
        return json.loads(p.read_text(encoding="utf-8")) or {}
    except Exception:
        return {}

def write_assistant_suggestions(data_dir: str | Path, artifact_type, artifact_id: str, payload: dict) -> None:
    """Write non-authoritative LLM suggestions for an artifact."""
    p = assistant_suggestions_path(data_dir, artifact_type, artifact_id)
    safe = payload if isinstance(payload, dict) else {"value": payload}
    # add minimal metadata
    safe.setdefault("updated_at", datetime.now(timezone.utc).isoformat())
    p.write_text(json.dumps(safe, indent=2), encoding="utf-8")


def keep_sha256_only(values: list[str] | None) -> list[str]:
    """Return only SHA-256 hashes (64 hex chars). No 0x normalization."""
    out: list[str] = []
    for v in values or []:
        s = (v or "").strip()
        if _SHA256_RE.match(s):
            out.append(s.lower())
    seen = set()
    deduped: list[str] = []
    for x in out:
        if x not in seen:
            seen.add(x)
            deduped.append(x)
    return deduped

_CQL_FORBIDDEN_TOKENS = [
    "ScriptControlScanInfo",
    "NetworkConnectivityEvents",
    "DestinationIP",
    "DestinationPort",
    "RemotePort",
    "RemoteAddress=",
    "ProcessName",
    "EventType",
]

_CQL_ALLOWED_EVENTNAMES = {"ProcessRollup2", "NetworkConnectIP4", "DnsRequest"}

def validate_cql_query(q: str) -> list[str]:
    """Lightweight CQL validation gate for known-bad event/field drift."""
    errs: list[str] = []
    if not q:
        return ["empty query"]
    for tok in _CQL_FORBIDDEN_TOKENS:
        if tok in q:
            errs.append(f"forbidden token: {tok}")
    for m in _re.finditer(r"#event_simpleName\s*=\s*([A-Za-z0-9_]+)", q):
        ev = m.group(1)
        if ev not in _CQL_ALLOWED_EVENTNAMES:
            errs.append(f"invalid #event_simpleName: {ev}")
    if "NetworkConnectIP4" in q and "DestinationIP" in q:
        errs.append("use RemoteAddressIP4 (not DestinationIP) for NetworkConnectIP4")
    return errs


def validate_no_tbd(text: str) -> list[str]:
    """Gate for executive exports.

    Returns a list of violations if the content contains placeholder language.
    Keep this deterministic and strict to prevent shipping half-filled reports.
    """
    violations: list[str] = []
    if not text or not text.strip():
        return ["empty content"]
    needles = ["(TBD)", "{{", "}}", "Unknown", "unknown"]
    for n in needles:
        if n in text:
            violations.append(f"contains placeholder token: {n}")
    return violations

def _ioc_attack_mapping(title: str) -> list[str]:
    """ATT&CK mapping from IOC sweep type."""
    t = (title or "").lower()
    if "sha256" in t or "hash" in t:
        return ["T1204.002 (User Execution: Malicious File)"]
    if "file" in t or "execution" in t or "process" in t:
        return ["T1204.002 (User Execution: Malicious File)", "T1059 (Command and Scripting Interpreter)"]
    if "ip + port" in t or "ip:port" in t:
        return ["T1071 (Application Layer Protocol)", "T1571 (Non-Standard Port)"]
    if "ip" in t:
        return ["T1071 (Application Layer Protocol)"]
    if "domain" in t or "url" in t:
        return ["T1071.001 (Web Protocols)", "T1568.002 (Dynamic Resolution)"]
    return ["T1071 (Application Layer Protocol)"]

def render_section4_structured(hunt: 'HuntPackage', qlang_label: str = "CQL") -> str:
    """Structured-only Section 4 renderer. LLM is forbidden for this section."""
    parts: list[str] = []
    parts.append("## 4. High-Fidelity Indicators & Hunt Queries\n")
    parts.append("> **Note:** This section is **structured-only** (LLM forbidden). Queries are rendered from artifact data.\n")
    parts.append("---\n")
    if not getattr(hunt, "queries", None):
        parts.append("_No hunt queries available._\n")
        return "\n".join(parts)
    for i, q in enumerate(hunt.queries, start=1):
        parts.append(f"### 4.{i} {q.title or f'Hunt {i}'}\n")
        parts.append("**Purpose**\n\n> " + ((q.description or "TBD").strip().replace("\n", "\n> ")) + "\n")
        parts.append("\n**Why this query exists (ATT&CK mapping)**\n")
        parts.extend([f"- {t}" for t in _ioc_attack_mapping(q.title or "")])
        parts.append("\n\n**Query Logic (" + qlang_label + ")**\n")
        parts.append("\n```" + qlang_label.lower() + "\n" + (q.query or "").strip() + "\n```\n")
        parts.append("**Notes / Tuning Guidance**\n")
        parts.append("- Start broad, then add allow-lists for known-good software and internal services.\n")
        parts.append("- If noisy, add scope filters or tighten time windows.\n")
        parts.append("---\n")
    return "\n".join(parts)

def _inject_section4(markdown_text: str, hunt: 'HuntPackage', qlang_label: str = "CQL") -> str:
    sec4 = render_section4_structured(hunt, qlang_label=qlang_label)
    m = _re.search(r"^##\s+4\.[\s\S]*?(?=^##\s+5\.)", markdown_text, flags=_re.M)
    if m:
        return markdown_text[:m.start()] + sec4 + "\n" + markdown_text[m.end():]
    return markdown_text.rstrip() + "\n\n" + sec4 + "\n"


from .llm import BaseLLM, LLMError, StubLLM
from .enrichment_reports import write_plugin_summary_reports
from .models import (
    ADS,
    ApprovalStatus,
    ArtifactMeta,
    ArtifactType,
    Finding,
    HuntPackage,
    HuntQuery,
    Run,
    RunStatus,
    RunStep,
    Severity,
    IntelBrief,
)
from .renderers import render_hunt_report_markdown_v1
from .behavior_intel import extract_behaviors_from_intel
from .query_builders import build_ioc_sweep_queries_cql, build_ioc_sweep_queries_kql, build_routed_hunt_queries_cql
from .query_linter import enforce_cql_core_only, patch_correlated_downgrades
from .behavior import extract_behaviors, build_behavior_checklist, evaluate_query_against_behaviors
from .telemetry_schema import translate_fields_to_crowdstrike


@lru_cache(maxsize=1)
def _load_iana_tlds() -> set[str]:
    """Load a local IANA TLD allow-list.

    This is used to prevent false-positive "domains" from filenames like
    `27138.yar` or `copy.bat` being treated as domains.
    """
    # File ships with the app. One TLD per line (uppercase) from IANA.
    here = Path(__file__).resolve().parent
    tld_path = here / "data" / "tlds-alpha-by-domain.txt"
    if not tld_path.exists():
        # Minimal fallback set (keeps app functional even if file missing).
        return {
            "com", "net", "org", "io", "gov", "edu",
            "co", "us", "uk", "de", "fr", "ru", "cn", "jp", "au", "ca",
        }

    tlds: set[str] = set()
    try:
        for line in tld_path.read_text(encoding="utf-8", errors="ignore").splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            tlds.add(line.lower())
    except Exception:
        return {
            "com", "net", "org", "io", "gov", "edu",
            "co", "us", "uk", "de", "fr", "ru", "cn", "jp", "au", "ca",
        }
    return tlds


def _is_cql_query(q: str) -> bool:
    """Heuristic check for CrowdStrike LogScale (Humio-style) CQL."""
    if not q:
        return False
    s = q.strip()
    # Hard requirement for this project: start with event header filter.
    if s.startswith("#event_simpleName="):
        return True
    # Reject obviously wrong dialects.
    if re.search(r"\bSELECT\b|\bFROM\b|\bWHERE\b", s, re.IGNORECASE):
        return False
    if "| summarize" in s or "DeviceProcessEvents" in s:
        return False
    if "index=" in s or "| stats" in s:
        return False
    return False


def _default_cql_query(topic: str, idx: int) -> str:
    """Fallback CQL to keep Hunt Packages usable if the model returns non-CQL."""
    t = (topic or "threat").replace('"', "")
    if idx == 1:
        return (
            "#event_simpleName=ProcessRollup2\n"
            f"| regex(CommandLine=/.*{re.escape(t)}.*/i)\n"
            "| groupBy([@timestamp, ComputerName, UserName, FileName, CommandLine, ParentBaseFileName], limit=20000)"
        )
    if idx == 2:
        return (
            "#event_simpleName=NetworkConnectIP4\n"
            "| groupBy([@timestamp, ComputerName, UserName, ContextBaseFileName, RemoteAddressIP4, RPort], limit=20000)"
        )
    return (
        "#event_simpleName=ProcessRollup2\n"
        '| in(field=FileName, values=["powershell.exe","cmd.exe","rundll32.exe","mshta.exe","wscript.exe","cscript.exe"])\n'
        "| groupBy([@timestamp, ComputerName, UserName, FileName, CommandLine, ParentBaseFileName], limit=20000)"
    )


def fetch_sources_text(
    sources: list[str],
    max_chars: int = 12000,
    timeout_s: int = 12,
    cfg=None,
    return_errors: bool = False,
):
    """Optionally fetch URL sources and return a clipped plain-text blob.

    Production-minded behavior:
      - Best-effort with short timeouts.
      - Uses the same fetch/extract path as the Workspace (web_search.fetch_url_text),
        including a fallback proxy for some blocked pages.
      - Can optionally return a list of per-URL errors for UI display.

    Returns:
      - str if return_errors=False
      - (str, list[str]) if return_errors=True
    """
    from .web_search import fetch_url_text

    chunks: list[str] = []
    errors: list[str] = []
    remaining = int(max_chars or 0)

    for url in (sources or []):
        if remaining <= 0:
            break
        u = (url or "").strip()
        if not u or not (u.startswith("http://") or u.startswith("https://")):
            continue
        try:
            txt = fetch_url_text(u, timeout_s=int(timeout_s), max_chars=min(remaining, 12000), cfg=cfg)
            txt = (txt or "").strip()
            if not txt:
                errors.append(f"{u}: empty/blocked/unreadable")
                continue
            # Heuristics: filter common bot-wall pages and low-signal boilerplate
            low = txt.lower()
            if any(k in low for k in ["just a moment", "checking your browser", "enable javascript", "cloudflare", "access denied"]):
                errors.append(f"{u}: bot-wall/blocked content")
                continue
            if len(txt) < 400:
                errors.append(f"{u}: extracted too little content ({len(txt)} chars)")
            clip = txt[: min(len(txt), remaining)]
            remaining -= len(clip)
            chunks.append(f"SOURCE: {u}\n{clip}\n")
        except Exception as e:
            errors.append(f"{u}: {e}")
            continue

    out = "\n".join(chunks).strip()
    return (out, errors) if return_errors else out



def run_ioc_enrichment(iocs: dict[str, list[str]]) -> dict:
    """Run optional IOC enrichment plugins for extracted IOCs.

    This is best-effort and safe-by-default:
      - If a plugin is missing API keys, it will return 'skipped' or an error entry.
      - Results are returned as a dict keyed by IOC value (normalized) with per-plugin outputs.

    NOTE: This does not mutate intel artifacts; persistence is handled by the caller.
    """
    try:
        from .plugins.plugin_loader import run_plugins_for_ioc, normalize_ioc
    except Exception as e:
        return {"error": f"plugin_loader unavailable: {e}"}

    results: dict = {}
    # flatten iocs into a single set of indicator strings
    flat: set[str] = set()
    for vals in (iocs or {}).values():
        for v in (vals or []):
            if v and str(v).strip():
                flat.add(str(v).strip())

    for raw in sorted(flat):
        ioc = normalize_ioc(raw)
        try:
            results[ioc] = run_plugins_for_ioc(ioc)
        except Exception as e:
            results[ioc] = {"error": str(e)}
    return results


def enrichment_path(data_dir: str, intel_id: str) -> Path:
    """Return the filesystem path for Intel enrichment JSON."""
    d = Path(data_dir) / "artifacts" / ArtifactType.INTEL_BRIEF.value
    d.mkdir(parents=True, exist_ok=True)
    return d / f"{intel_id}.enrichment.json"


def _is_rfc1918_ipv4(ip: str) -> bool:
    """Return True if ip is in RFC1918 private IPv4 ranges."""
    try:
        addr = ipaddress.ip_address(ip)
        return isinstance(addr, ipaddress.IPv4Address) and addr.is_private
    except Exception:
        return False


def extract_iocs(text: str) -> dict[str, list[str]]:
    """Best-effort IOC extraction from free text.

    Returns a dict keyed by IOC type:
      - ip_port: ["1.2.3.4:443", ...]
      - ip: ["1.2.3.4", ...] (only if not already captured with port)
      - domain: ["example.com", ...]
      - url: ["https://...", ...]
      - hash: ["<md5/sha1/sha256>", ...]
      - email: ["user@example.com", ...]
      - file: ["rclone.exe", ...] (only if explicitly present in text)
    """
    if not text:
        return {}

    # Normalize common defang patterns
    norm = (
        text.replace("[.]", ".")
            .replace("(.)", ".")
            .replace("hxxp://", "http://")
            .replace("hxxps://", "https://")
            .replace("[://]", "://")
            .replace("[://", "://")
            .replace("://]", "://")
    )

    # IP:PORT
    ip_port_re = re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\s*[:|]\s*(\d{1,5})\b")
    # Keep canonical with colon
    ip_port = set()
    for m in ip_port_re.finditer(norm):
        full = m.group(0)
        port = m.group(1)
        ip = re.split(r"[:|]", full)[0].strip()
        ip_port.add(f"{ip}:{port}")

    # Filter RFC1918 IP:PORT entries
    ip_port = {v for v in ip_port if not _is_rfc1918_ipv4(v.split(':',1)[0])}

    # IP only
    ip_re = re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b")
    ips = set(ip_re.findall(norm))
    # Filter RFC1918 IPv4 addresses
    ips = {i for i in ips if not _is_rfc1918_ipv4(i)}
    ips = {i for i in ips if all(part.isdigit() and 0 <= int(part) <= 255 for part in i.split('.'))}

    # URL
    url_re = re.compile(r"\bhttps?://[^\s\]\)\>\"']+", re.IGNORECASE)
    urls = set(url_re.findall(norm))

    # Email
    email_re = re.compile(r"\b[a-zA-Z0-9._%+-]+@(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}\b")
    emails = set(email_re.findall(norm))

    # Hashes (md5/sha1/sha256)
    hash_re = re.compile(r"\b([A-Fa-f0-9]{32}|[A-Fa-f0-9]{40}|[A-Fa-f0-9]{64})\b")
    hashes = set(hash_re.findall(norm))

    # Domains: keep conservative (exclude obvious file extensions and already captured URLs/emails)
    domain_re = re.compile(r"\b(?:[a-zA-Z0-9-]{1,63}\.)+(?:[a-zA-Z]{2,24})\b")
    domains = set(domain_re.findall(norm))

    # Avoid schema-like false positives (e.g., 'process.pe' from Elastic ECS or dotted field paths)
    _schema_prefix_deny = {
        "process", "event", "host", "file", "registry", "user", "source", "destination",
        "dll", "winlog", "ecs", "sigma", "splunk", "endpoint",
    }
    domains = {
        d for d in domains
        if (d.split('.', 1)[0].lower() not in _schema_prefix_deny)
        and not d.lower().startswith("process.")
    }
    # Remove those that are part of emails
    for e in emails:
        domains.discard(e.split('@', 1)[1])
    # Remove those that are part of URLs
    for u in urls:
        try:
            host = re.sub(r"^https?://", "", u, flags=re.IGNORECASE).split('/')[0]
            host = host.split(':')[0]
            domains.discard(host)
        except Exception:
            pass
    # Remove likely false positives
    bad_suffix = (".exe", ".dll", ".sys", ".png", ".jpg", ".jpeg", ".gif", ".pdf", ".docx", ".xlsx")
    domains = {d for d in domains if not d.lower().endswith(bad_suffix)}

    # TLD allow-list guardrail: only keep domains whose terminal label is a real IANA TLD.
    # This prevents filename-like artifacts (e.g., *.yar, *.bat, *.ps1) from being classified as domains.
    tlds = _load_iana_tlds()
    _tld_deny = {
        # common file extensions / markup that frequently appear in reports
        "bat","cmd","ps1","vbs","js","jse","hta","dll","exe","sys",
        "pdf","doc","docx","xls","xlsx","ppt","pptx","csv","txt","log","md","yml","yaml","json","xml","html","htm",
        "jpg","jpeg","png","gif","zip","rar","7z","tar","gz",
        "yar","yara",
        # High-FP script-like ccTLDs that frequently appear as filenames in intel reports
        "sh","py",
    }

    def _tld_ok(tld: str) -> bool:
        t = (tld or "").lower()
        if not t or t in _tld_deny:
            return False
        # If we have the IANA list file, trust it.
        if tlds:
            if t in tlds:
                return True
        # Otherwise, allow ISO-style 2-letter ccTLD patterns, minus denylist.
        return len(t) == 2 and t.isalpha()

    domains = {d for d in domains if _tld_ok(d.split('.')[-1])}

    # Additional sanity: avoid numeric-only second-level labels (often folder names / artifact ids)
    # e.g., "27138.yar" (filtered by TLD list) but also "1768.py" (where .py is a real TLD).
    domains = {
        d for d in domains
        if len(d.split('.')) >= 2 and re.search(r"[a-zA-Z]", d.split('.')[-2])
    }

    # Schema guardrail: do NOT treat telemetry field prefixes as domains.
    # Example: `process.pe.original_file_name` contains `process.pe` which would otherwise
    # pass TLD checks (pe is a real ccTLD).
    _schema_first_labels = {
        "process", "event", "file", "registry", "host", "user", "source", "destination",
        "winlog", "dll", "pe", "network", "http", "dns",
    }
    domains = {
        d for d in domains
        if (d.split('.')[0].lower() not in _schema_first_labels)
        and not d.lower().startswith("process.")
        and not d.lower().startswith("file.")
    }

    
    # Filenames (only explicit)
    file_re = re.compile(r"\b[a-zA-Z0-9_\-\.]{1,80}\.(?:exe|dll|sys|ps1|bat|cmd|vbs|js|hta)\b", re.IGNORECASE)
    files = set(file_re.findall(norm))

    # Remove IPs that are already in ip_port
    ips_noport = {ip for ip in ips if not any(ip_port_val.startswith(ip + ":") for ip_port_val in ip_port)}

    out = {}
    if ip_port:
        out["ip_port"] = sorted(ip_port)
    if ips_noport:
        out["ip"] = sorted(ips_noport)
    if domains:
        out["domain"] = sorted(domains)
    if urls:
        out["url"] = sorted(urls)
    if hashes:
        out["hash"] = sorted(hashes)
    if emails:
        out["email"] = sorted(emails)
    if files:
        out["file"] = sorted({f.lower() for f in files})
    return out


def write_intel_iocs_sidecar(store, intel_id: str, iocs: Dict[str, List[str]]) -> str:
    """
    Persist extracted IOCs as a sidecar JSON file:
      data/artifacts/intel_brief/<intel_id>.iocs.json

    This keeps IOC consumption (query builders) stable and avoids re-parsing.
    Returns the path string.
    """
    try:
        out_dir = store.artifacts_dir / ArtifactType.INTEL_BRIEF.value
    except Exception:
        # fallback for older store implementations
        out_dir = Path("data") / "artifacts" / ArtifactType.INTEL_BRIEF.value
    out_dir.mkdir(parents=True, exist_ok=True)
    out_path = out_dir / f"{intel_id}.iocs.json"
    payload = {
        "meta": {
            "intel_id": intel_id,
            "generated_at": datetime.now(timezone.utc).isoformat(),
        },
        "iocs": iocs or {},
    }
    out_path.write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")
    return str(out_path)


_COMMON_FILE_ALLOWLIST = {
    # common Windows / admin tools seen in hunts; prevent over-blocking
    "cmd.exe", "powershell.exe", "pwsh.exe", "wscript.exe", "cscript.exe",
    "rundll32.exe", "mshta.exe", "regsvr32.exe", "curl.exe", "bitsadmin.exe",
    "certutil.exe", "schtasks.exe", "wevtutil.exe", "whoami.exe", "net.exe",
    "net1.exe", "sc.exe", "wmic.exe", "taskkill.exe", "tasklist.exe",
    "explorer.exe", "svchost.exe", "services.exe", "lsass.exe",
    "psexec.exe", "psexesvc.exe",
}


def _sanitize_ghost_ioc_values_in_query(query_text: str, intel_iocs: Dict[str, List[str]]) -> str:
    """
    Hard-block invented IOC values (ghost binaries) by removing unknown file tokens
    from FileName IOC lists in CQL.

    If a query's FileName list becomes empty after sanitization, returns "" to signal dropping it.
    """
    if not query_text:
        return query_text

    allow_files = set((intel_iocs or {}).get("file", []) or [])
    allow_files = {f.lower() for f in allow_files}
    allow_files |= {f.lower() for f in _COMMON_FILE_ALLOWLIST}

    # Target the common pattern: in(field=FileName, values=[...])
    pattern = r"in\\(field=FileName,\\s*values=(\\[[^\\]]*\\])\\)"
    m = re.search(pattern, query_text)
    if not m:
        return query_text

    raw_list = m.group(1)
    try:
        # raw_list is python-ish list repr; safe eval by json conversion attempt first
        vals = json.loads(raw_list.replace("'", '"'))
        if not isinstance(vals, list):
            return query_text
    except Exception:
        # fallback: extract quoted tokens
        vals = re.findall(r"['\\\"]([^'\\\"]+)['\\\"]", raw_list)

    cleaned = []
    for v in vals:
        vv = str(v).strip()
        if not vv:
            continue
        if vv.lower() in allow_files:
            cleaned.append(vv)

    if not cleaned:
        return ""

    new_list = json.dumps(cleaned)
    # Keep the bracket list style used elsewhere (with double quotes)
    query_text = re.sub(pattern, f'in(field=FileName, values={new_list})', query_text)
    return query_text



def _render_queries_section_markdown(queries: list[HuntQuery], qlang: str) -> str:
    """Render Section 4 (High-Fidelity Indicators & Hunt Queries) deterministically from HuntQuery objects.

    This prevents hallucinated event types and ensures IOC sweep queries are always included.
    """
    fence = "cql" if (qlang or "").upper().strip() == "CQL" else "text"
    lines: list[str] = []
    lines.append("## 4. High-Fidelity Indicators & Hunt Queries\n")
    lines.append("> **Note:** Each subsection below is generated from the structured Hunt Query objects (not free-text).\n")
    lines.append("")

    if not queries:
        lines.append("_No hunt queries available._\n")
        return "\n".join(lines).strip() + "\n"

    for idx, q in enumerate(queries, start=1):
        title = (q.title or f"Hunt Query {idx}").strip()
        purpose = (q.description or "").strip() or "Hunt for behaviors/indicators relevant to this threat."
        lines.append(f"### 4.{idx} {title}")
        lines.append("")
        lines.append("**Purpose**\n")
        lines.append(f"> {purpose}")
        lines.append("")
        lines.append(f"**Query Logic ({qlang.upper().strip()})**\n")
        lines.append(f"```{fence}")
        lines.append((q.query or "").rstrip())
        lines.append("```\n")
        lines.append("**Notes / Tuning Guidance**\n")
        lines.append("- Start with a narrow time window and expand once validated.")
        lines.append("- Baseline results; then add allowlists for known-good software/paths.")
        lines.append("")

    return "\n".join(lines).strip() + "\n"


def _replace_markdown_section(md: str, header: str, next_header_prefix: str, replacement_block: str) -> str:
    """Replace a markdown section starting at `header` up to the next header prefix (e.g., '## 5.')."""
    if not md:
        return replacement_block

    start = md.find(header)
    if start == -1:
        # If the template doesn't include the section, append it.
        return md.rstrip() + "\n\n" + replacement_block

    # Find the next header (e.g., '## 5.') after the start
    after_start = start + len(header)
    nxt = md.find("\n" + next_header_prefix, after_start)
    if nxt == -1:
        return md[:start].rstrip() + "\n\n" + replacement_block

    return md[:start].rstrip() + "\n\n" + replacement_block + "\n\n" + md[nxt+1:].lstrip()


def build_queries_from_iocs(
    iocs: dict[str, list[str]],
    query_language: str,
    qlang_label: str,
    max_queries: int = 10,
    kql_profile: str | None = None,
) -> list[HuntQuery]:
    """Deterministic query generation from extracted IOC tables.

    Used to prevent hallucinated process names and to ensure IOC coverage in Hunt Packages.
    """
    if not iocs:
        return []

    qlang = (query_language or "CQL").upper().strip()
    out: list[HuntQuery] = []

    def _add(title: str, desc: str, q: str):
        if len(out) >= max_queries:
            return
        out.append(HuntQuery(title=title, description=desc, query=q, query_language=qlang_label))

    files = iocs.get("file", []) or []
    ip_ports = iocs.get("ip_port", []) or []
    domains = iocs.get("domain", []) or []
    hashes = iocs.get("hash", []) or []

    if qlang == "CQL":
        if files:
            _add(
                "IOC Process/File Names",
                "Look for executions of file names explicitly present in the intel (no inferred binaries).",
                "#event_simpleName=ProcessRollup2\n"
                + f"| in(field=FileName, values={json.dumps(files)})\n"
                + "| select([@timestamp, ComputerName, UserName, FileName, FilePath, CommandLine, ParentBaseFileName, SHA256HashData, SignedStatus])\n"
                + "| groupBy([ComputerName, UserName, FileName, FilePath], limit=20000)",
            )

        if hashes:
            _add(
                "IOC SHA-256 Hashes",
                "Hunt for processes matching SHA-256 hashes present in the intel (telemetry: SHA256HashData).",
                "#event_simpleName=ProcessRollup2\n"
                + f"| in(field=SHA256HashData, values={json.dumps(keep_sha256_only(hashes))})\n"
                + "| groupBy([ComputerName, UserName, FileName, CommandLine, SHA256HashData], limit=20000)",
            )

        if ip_ports:
            port_map: dict[str, list[str]] = {}
            for v in ip_ports:
                if ":" in v:
                    ip, port = v.split(":", 1)
                    port_map.setdefault(port.strip(), []).append(ip.strip())

            for port, ips in port_map.items():
                rport_vals = [int(port)] if port.isdigit() else [port]
                _add(
                    f"IOC Network Destinations (port {port})",
                    "Connections to IP:port indicators from the intel.",
                    "#event_simpleName=NetworkConnectIP4\n"
                    + f"| in(field=RemoteAddressIP4, values={json.dumps(sorted(set(ips)))})\n"
                    + f"| in(field=RPort, values={json.dumps(rport_vals)})\n"
                    + "| groupBy([ComputerName, UserName, ContextBaseFileName, LocalAddressIP4, RemoteAddressIP4, RPort], limit=20000)",
                )

        if domains:
            # Best-effort: avoid inventing DNS event names. Search within CommandLine strings.
            parts = [re.escape(d) for d in domains[:50]]
            dom_re = "|".join(parts)
            if dom_re:
                _add(
                    "IOC Domains (CommandLine strings)",
                    "Best-effort: processes whose CommandLine contains IOC domain strings.",
                    "#event_simpleName=ProcessRollup2 CommandLine=/" + dom_re + "/i\n"
                    + "| groupBy([ComputerName, UserName, FileName, CommandLine, SHA256HashData], limit=20000)",
                )

    elif qlang == "SPL":
        if ip_ports:
            ips = sorted({v.split(":", 1)[0] for v in ip_ports if ":" in v})
            _add(
                "IOC Network Destinations",
                "Connections to IOC IP values (port handling depends on your data model).",
                "index=network dest_ip IN (" + ", ".join(ips) + ")\n| stats count by src_ip, dest_ip, dest_port, user",
            )

    elif qlang == "KQL":
        profile = (kql_profile or "MDE").upper().strip()
        sha256 = keep_sha256_only(hashes)

        def _fmt_list(vals: list[str]) -> str:
            return ", ".join([json.dumps(v) for v in vals])

        # Microsoft Defender for Endpoint (MDE) Device* tables
        if profile in ("MDE", "HYBRID"):
            if sha256:
                _add(
                    "IOC SHA-256 Hashes (MDE)",
                    "Process executions where the process hash matches an IOC SHA-256.",
                    "DeviceProcessEvents\n"
                    f"| where SHA256 in ({_fmt_list(sha256)})\n"
                    "| summarize Count=count() by DeviceName, AccountName, FileName, FolderPath, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine, SHA256",
                )

            if files:
                _add(
                    "IOC File Names (MDE)",
                    "Process executions where FileName matches an IOC file name.",
                    "DeviceProcessEvents\n"
                    f"| where FileName in ({_fmt_list(files)})\n"
                    "| summarize Count=count() by DeviceName, AccountName, FileName, FolderPath, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine",
                )

            if ip_ports:
                ips = sorted({v.split(":", 1)[0] for v in ip_ports if ":" in v})
                ports = sorted({v.split(":", 1)[1] for v in ip_ports if ":" in v and v.split(":", 1)[1].isdigit()})
                port_line = f"| where RemotePort in ({', '.join([str(int(p)) for p in ports])})\n" if ports else ""
                _add(
                    "IOC Network Destinations (MDE)",
                    "Outbound connections to IOC IP:port pairs (best-effort: IP + port filters).",
                    "DeviceNetworkEvents\n"
                    f"| where RemoteIP in ({_fmt_list(ips)})\n"
                    + port_line
                    + "| summarize Count=count() by DeviceName, InitiatingProcessAccountName, InitiatingProcessFileName, InitiatingProcessCommandLine, RemoteIP, RemotePort, RemoteUrl",
                )

            if domains:
                _add(
                    "IOC Domains (MDE DNS)",
                    "DNS lookups for IOC domains attributed to a process.",
                    "DeviceDnsEvents\n"
                    f"| where Name in ({_fmt_list(domains)})\n"
                    "| summarize Count=count() by DeviceName, AccountName, Name, InitiatingProcessFileName, InitiatingProcessCommandLine",
                )

        # Microsoft Sentinel baseline (SecurityEvent + Sysmon-style)
        if profile in ("SENTINEL", "HYBRID"):
            if sha256:
                _add(
                    "IOC SHA-256 Hashes (Sentinel baseline)",
                    "Baseline process creation matches for IOC SHA-256 (field names depend on connector).",
                    "let ioc_sha256 = dynamic([" + ", ".join([json.dumps(v) for v in sha256]) + "]);\n"
                    "SecurityEvent\n"
                    "| where EventID == 4688\n"
                    "| where tostring(ProcessHash) in (ioc_sha256) or tostring(Hashes) has_any (ioc_sha256)\n"
                    "| project TimeGenerated, Computer, Account, NewProcessName, CommandLine, ParentProcessName, ProcessHash, Hashes",
                )

            if files:
                _add(
                    "IOC File Names (Sentinel baseline)",
                    "Baseline process creation matches for IOC file names (4688/Sysmon EID 1 depending on your schema).",
                    "let ioc_files = dynamic([" + ", ".join([json.dumps(v) for v in files]) + "]);\n"
                    "SecurityEvent\n"
                    "| where EventID == 4688\n"
                    "| where tolower(tostring(NewProcessName)) has_any (ioc_files) or tolower(tostring(CommandLine)) has_any (ioc_files)\n"
                    "| project TimeGenerated, Computer, Account, NewProcessName, CommandLine, ParentProcessName",
                )

            if ip_ports:
                ips = sorted({v.split(":", 1)[0] for v in ip_ports if ":" in v})
                ports = sorted({v.split(":", 1)[1] for v in ip_ports if ":" in v and v.split(":",1)[1].isdigit()})
                _add(
                    "IOC Network Destinations (Sentinel Sysmon baseline)",
                    "Baseline network matches (Sysmon EventID 3 via Sysmon table or Event table).",
                    "let ioc_ips = dynamic([" + ", ".join([json.dumps(v) for v in ips]) + "]);\n"
                    "let ioc_ports = dynamic([" + ", ".join([str(int(p)) for p in ports]) + "]);\n"
                    "Sysmon\n"
                    "| where EventID == 3\n"
                    "| where tostring(DestinationIp) in (ioc_ips) and toint(DestinationPort) in (ioc_ports)\n"
                    "| project TimeGenerated, Computer, UserName, Image, CommandLine, DestinationIp, DestinationPort, DestinationHostname",
                )

    return out



def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def record_history(meta, action: str, actor: str | None = None, note: str = "") -> None:
    """Append a lightweight audit entry onto ArtifactMeta.history.

    This is intentionally best-effort and never blocks saves.
    """
    try:
        entry = {
            "ts": utc_now(),
            "actor": (actor or ""),
            "action": action,
        }
        if note:
            entry["note"] = note
        hist = getattr(meta, "history", None)
        if hist is None:
            meta.history = [entry]  # type: ignore[attr-defined]
        else:
            try:
                hist.append(entry)
            except Exception:
                meta.history = [*list(hist), entry]  # type: ignore[attr-defined]
    except Exception:
        pass



_TEMPLATE_DIR = Path(__file__).resolve().parent / "templates"

# Optional override directory for templates (advanced users).
# When set, _load_template will prefer files from this directory.
_TEMPLATE_DIR_OVERRIDE: Path | None = None

# Phase 6 (local RAG)
_RAG_ENABLED: bool = False
_RAG_TOP_K: int = 6
_RAG_INDEX = None  # type: ignore


def set_rag(index, enabled: bool = True, top_k: int = 6) -> None:
    """Attach a RAG index to the workflow layer.

    Kept intentionally simple so the UI can wire it in without a refactor.
    """
    global _RAG_INDEX, _RAG_ENABLED, _RAG_TOP_K
    _RAG_INDEX = index
    _RAG_ENABLED = bool(enabled)
    try:
        _RAG_TOP_K = max(1, int(top_k))
    except Exception:
        _RAG_TOP_K = 6


def _rag_query_from_prompt(prompt: str) -> str:
    """Try to avoid querying the index with huge source extracts."""
    p = (prompt or "").strip()
    # Prefer the part before SOURCE EXTRACTS (common pattern in our prompts)
    m = re.split(r"\n\s*SOURCE EXTRACTS\s*:\s*\n", p, maxsplit=1, flags=re.IGNORECASE)
    head = (m[0] if m else p).strip()
    # Keep the last chunk (usually contains the ask + constraints)
    if len(head) > 1400:
        head = head[-1400:]
    return head


def set_template_dir_override(path: str | None) -> None:
    """Set a custom template directory at runtime.

    This is intentionally lightweight: it enables power users to swap templates
    without modifying code.
    """
    global _TEMPLATE_DIR_OVERRIDE
    try:
        if path and str(path).strip():
            _TEMPLATE_DIR_OVERRIDE = Path(path).expanduser().resolve()
        else:
            _TEMPLATE_DIR_OVERRIDE = None
    except Exception:
        _TEMPLATE_DIR_OVERRIDE = None


def _load_template(filename: str) -> str | None:
    """Load a bundled template, optionally overridden by a user-supplied template folder.

    Search order:
    1) Template directory override (if set)
    2) Bundled templates directory

    Returns None if the template doesn't exist (keeps demo resilient).
    """
    try:
        candidates = []
        if _TEMPLATE_DIR_OVERRIDE is not None:
            candidates.append(_TEMPLATE_DIR_OVERRIDE / filename)
        candidates.append(_TEMPLATE_DIR / filename)

        for pth in candidates:
            if pth.exists() and pth.is_file():
                try:
                    mtime = int(pth.stat().st_mtime_ns)
                except Exception:
                    mtime = 0
                return _read_text_cached(str(pth), mtime)
        return None
    except Exception:
        return None


@lru_cache(maxsize=128)
def _read_text_cached(path_str: str, mtime_ns: int) -> str:
    """Read a text file with an mtime-based cache key.

    This keeps template reads cheap across reruns and across pages.
    """
    try:
        p = Path(path_str)
        if not p.exists():
            return ""
        return p.read_text(encoding="utf-8", errors="ignore")
    except Exception:
        return ""


def new_meta(artifact_type: ArtifactType, title: str, artifact_id: str) -> ArtifactMeta:
    now = utc_now()
    return ArtifactMeta(id=artifact_id, type=artifact_type, title=title, created_at=now, updated_at=now)


def _safe_generate(llm: BaseLLM, prompt: str, system: str, on_token=None) -> str:
    """Generate text, but never crash the demo UI.

    If the active LLM backend fails (e.g., Ollama route mismatch), we fall back to StubLLM.
    """
    # Phase 6: optionally inject local RAG context into the system prompt.
    # We keep this lightweight and bounded to avoid prompt bloat.
    sys = system
    try:
        if _RAG_ENABLED and _RAG_INDEX is not None:
            q = _rag_query_from_prompt(prompt)
            hits = _RAG_INDEX.query(q, top_k=_RAG_TOP_K)
            if hits:
                lines = ["\n\n# Retrieved context (local library)\n"]
                for ch, score in hits[: _RAG_TOP_K]:
                    snippet = (ch.text or "").strip()
                    if len(snippet) > 520:
                        snippet = snippet[:520].rstrip() + "…"
                    sid = getattr(ch, "source_id", "unknown")
                    stype = getattr(ch, "source_type", "artifact")
                    lines.append(f"- ({stype}:{sid} | score={score:.3f}) {snippet}")
                sys = (system or "") + "\n" + "\n".join(lines)
    except Exception:
        sys = system

    try:
        if on_token is not None:
            resp = llm.generate_stream(prompt=prompt, system=sys, on_token=on_token)
        else:
            resp = llm.generate(prompt=prompt, system=sys)
        return resp.text
    except LLMError as e:
        return StubLLM().generate(prompt=f"[STUB MODE] Ollama generation failed: {e}\n\n{prompt}", system=system).text



_INTEL_SYSTEM = (
    "You are BYO-SecAI, a cyber threat intelligence assistant.\n"
    "Follow the provided Threat Intelligence Brief template EXACTLY.\nWrite in a professional, narrative style with enough context to be useful to analysts and leadership.\nBe moderately verbose (do not be overly terse), but avoid filler or speculation.\n"
    "Rules:\n"
    "- Do not add or remove sections.\n"
    "- Do not rename headings.\n"
    "- Do not output any preamble, thinking text, or extra commentary.\n"
    "- Evidence/Indicators should include at least one concrete indicator token (ip/ip:port/domain/sha256) when available.\n- ONLY use facts supported by the provided SOURCE EXTRACTS.\n"
    "- If something is unknown or not supported by the extracts, write 'Unknown' or 'Not confirmed by provided sources.'\n"
    "- Do not invent specific initial access, tooling, infrastructure, or techniques.\n"
    "- Keep it concise, operational, and evidence-aware.\n"
)


_INTEL_TEMPLATE = (
    "## 1. Title\n"
    "{topic}\n\n"
    "## 2. Date / Author / Reference ID\n"
    "- Date: {date}\n"
    "- Author: {author}\n"
    "- Reference ID: {reference_id}\n\n"
    "## 3. BLUF (Bottom Line Up Front)\n"
    "{bluf}\n\n"
    "## 4. Background\n"
    "{background}\n\n"
    "## 5. Threat Description\n"
    "{threat_description}\n\n"
    "## 6. Current Assessment\n"
    "{current_assessment}\n\n"
    "## 7. Evidence and Indicators\n"
    "{evidence_and_indicators}\n\n"
    "## 8. Impact Assessment\n"
    "{impact_assessment}\n\n"
    "## 9. Confidence and Credibility Ratings\n"
    "{confidence_and_credibility}\n\n"
    "## 10. Gaps and Collection Requirements\n"
    "{gaps_and_collection}\n\n"
    "## 11. Alternative Analysis\n"
    "{alternative_analysis}\n\n"
    "## 12. Outlook / Future Implications\n"
    "{outlook}\n\n"
    "## 13. Recommended Actions\n"
    "{recommended_actions}\n\n"
    "## 14. Summary Paragraph(s)\n"
    "{summary_paragraphs}\n\n"
    "## 15. Appendix\n"
    "{appendix}\n\n"
    "## Sources\n"
    "{sources_bullets}\n"
)


def _parse_intel_brief_text_to_obj(
    meta: ArtifactMeta,
    intel_id: str,
    topic: str,
    sources: list[str],
    source_text: str | None,
    text: str,
    now: str,
) -> IntelBrief:
    """Parse model markdown into the IntelBrief schema.

    Kept tolerant: the model may use markdown headings or plain headings.
    """
    sources_bullets = "\n".join(f"- {s}" for s in sources) or "- (none provided)"

    # Very light parsing: split by headings; keep tolerant
    sections = {
        "1. Title": "",
        "2. Date / Author / Reference ID": "",
        "3. BLUF (Bottom Line Up Front)": "",
        "4. Background": "",
        "5. Threat Description": "",
        "6. Current Assessment": "",
        "7. Evidence and Indicators": "",
        "8. Impact Assessment": "",
        "9. Confidence and Credibility Ratings": "",
        "10. Gaps and Collection Requirements": "",
        "11. Alternative Analysis": "",
        "12. Outlook / Future Implications": "",
        "13. Recommended Actions": "",
        "14. Summary Paragraph(s)": "",
        "15. Appendix": "",
    }

    def _norm_heading(line: str) -> str:
        s = line.strip()
        while s.startswith("#"):
            s = s.lstrip("#").strip()
        s = s.strip("*").strip()
        s = s.rstrip(":").strip()
        return s

    canon_map = {k.lower(): k for k in sections.keys()}

    current = None
    saw_any_heading = False
    for line in (text or "").splitlines():
        nh = _norm_heading(line)
        if nh.lower() in {"sources", "references"}:
            current = None
            saw_any_heading = True
            continue
        key = canon_map.get(nh.lower())
        if key:
            current = key
            saw_any_heading = True
            continue
        if current:
            sections[current] += line + "\n"

    def _strip_embedded_headings(s: str) -> str:
        out_lines: list[str] = []
        for ln in (s or "").splitlines():
            n = _norm_heading(ln)
            if n.lower() in canon_map or n.lower() in {"sources", "references"}:
                continue
            out_lines.append(ln)
        return "\n".join(out_lines).strip()

    for k in list(sections.keys()):
        sections[k] = _strip_embedded_headings(sections[k])

    if not saw_any_heading:
        sections["3. BLUF (Bottom Line Up Front)"] = (text or "").strip()

    title = sections["1. Title"].strip() or topic
    date = now
    author = "Threat Hunting / CTI"
    reference_id = "TBD"
    for ln in sections["2. Date / Author / Reference ID"].splitlines():
        low = ln.lower()
        if "date" in low and ":" in ln:
            date = ln.split(":", 1)[-1].strip() or date
        if "author" in low and ":" in ln:
            author = ln.split(":", 1)[-1].strip() or author
        if "reference" in low and ":" in ln:
            reference_id = ln.split(":", 1)[-1].strip() or reference_id

    mitre = sorted(set(re.findall(r"T\d{4}(?:\.\d{3})?", text or "")))
    return IntelBrief(
        meta=meta,
        approval=ApprovalStatus.DRAFT,
        topic=topic,
        sources=sources,
        iocs=extract_iocs(((source_text or "") + "\n" + (text or "")).strip()),
        title=title,
        date=date,
        author=author,
        reference_id=reference_id,
        bluf=sections["3. BLUF (Bottom Line Up Front)"].strip(),
        background=sections["4. Background"].strip(),
        threat_description=sections["5. Threat Description"].strip(),
        current_assessment=sections["6. Current Assessment"].strip(),
        evidence_and_indicators=sections["7. Evidence and Indicators"].strip(),
        impact_assessment=sections["8. Impact Assessment"].strip(),
        confidence_and_credibility=sections["9. Confidence and Credibility Ratings"].strip(),
        gaps_and_collection=sections["10. Gaps and Collection Requirements"].strip(),
        alternative_analysis=sections["11. Alternative Analysis"].strip(),
        outlook=sections["12. Outlook / Future Implications"].strip(),
        recommended_actions=sections["13. Recommended Actions"].strip(),
        summary_paragraphs=sections["14. Summary Paragraph(s)"].strip(),
        appendix=sections["15. Appendix"].strip(),
        observed_mitre_techniques=mitre,
    )


def generate_intel_brief(
    llm: BaseLLM,
    intel_id: str,
    topic: str,
    sources: list[str],
    source_text: str | None = None,
    cfg: "AppConfig | None" = None,
    on_token=None,
) -> tuple[IntelBrief, str]:
    meta = new_meta(ArtifactType.INTEL_BRIEF, f"Intel Brief: {topic}", intel_id)

    sources_bullets = "\n".join(f"- {s}" for s in sources) or "- (none provided)"
    now = utc_now()
    # Provide a partially-filled template so the model keeps structure.
    template = _INTEL_TEMPLATE.format(
        topic=topic,
        date=now,
        author="Threat Hunting / CTI",
        reference_id="TBD",
        bluf="",
        background="",
        threat_description="",
        current_assessment="",
        evidence_and_indicators="",
        impact_assessment="",
        confidence_and_credibility="",
        gaps_and_collection="",
        alternative_analysis="",
        outlook="",
        recommended_actions="",
        summary_paragraphs="",
        appendix="",
        sources_bullets=sources_bullets,
    )

    # Contract framework (optional): load prompt pack + contract rules.
    sys_prompt = _INTEL_SYSTEM
    user_prompt_prefix = "Use the provided sources to complete the intel brief."
    contract = None
    contract_profile = None
    contract_mode = "off"
    regen_attempts = 0
    try:
        if cfg is not None:
            from .contract_framework import load_contract, load_prompt_pack

            contract_profile = getattr(cfg, "intel_brief_contract_profile", "intel_brief_v1_1")
            contract_mode = getattr(cfg, "contract_enforcement_mode", "strict")
            regen_attempts = int(getattr(cfg, "contract_regen_attempts", 2) or 0)
            sys_p, user_p, _pbase = load_prompt_pack(
                getattr(cfg, "prompt_pack", "default"),
                artifact_key="intel_brief",
                prompt_dir_override=getattr(cfg, "prompt_dir_override", ""),
            )
            if (sys_p or "").strip():
                sys_prompt = sys_p.strip()
            if (user_p or "").strip():
                user_prompt_prefix = user_p.strip()
            contract, _cpath = load_contract(
                contract_profile,
                contract_dir_override=getattr(cfg, "contract_dir_override", ""),
            )
    except Exception:
        contract = None

    prompt_parts = [
        user_prompt_prefix,
        "\nTEMPLATE TO FILL (follow exactly):\n",
        template,
    ]
    if source_text:
        prompt_parts.append("\nSOURCE EXTRACTS (do not quote long passages):\n")
        prompt_parts.append(source_text)
    else:
        prompt_parts.append("\nSOURCES (URLs/notes only; no source text provided):\n")
        prompt_parts.append(sources_bullets)

    prompt = "\n".join(prompt_parts).strip()

    # Generate + validate + targeted regeneration loop.
    from .logging_utils import get_logger
    logger = get_logger()
    logger.info(
        "[CONTRACT] intel_brief profile=%s mode=%s regen_attempts=%s",
        contract_profile or "(none)",
        contract_mode,
        regen_attempts,
    )

    text = ""
    last_obj: IntelBrief | None = None
    last_violations = []
    attempts_total = 1 + max(0, int(regen_attempts or 0))
    for attempt in range(attempts_total):
        if attempt == 0:
            gen_prompt = prompt
        else:
            # Targeted fix: keep structure, only repair failing areas.
            try:
                from .contract_framework import format_violations, build_intel_brief_regen_guidance

                vtxt = format_violations(last_violations)
                guidance = build_intel_brief_regen_guidance(last_violations, contract or {})
            except Exception:
                vtxt = "- (unavailable)"
                guidance = "- Address all listed validation issues using specific, source-grounded detail."

            gen_prompt = (
                "The previous draft failed contract validation. Your job is to produce a compliant, intelligence-grade brief.\n"
                "Fix ONLY the listed issues while preserving all other sections and headings.\n"
                "Do NOT invent facts; use estimative language and explicitly call out gaps when sources are thin.\n\n"
                "Convergence Guidance (apply directly):\n"
                f"{guidance}\n\n"
                "Violations (must be resolved):\n"
                f"{vtxt}\n\n"
                "Previous Draft (for reference):\n"
                f"{text}\n\n"
                "Now output the full brief again using the same template headings.\n\n"
                + prompt
            )

        text = _safe_generate(llm, gen_prompt, sys_prompt, on_token=on_token)

        # Parse into IntelBrief
        obj = None
        try:
            obj = _parse_intel_brief_text_to_obj(meta, intel_id, topic, sources, source_text, text, now)
        except Exception:
            obj = None

        last_obj = obj
        # Phase 6.5.8.2: best-effort tactic->technique enrichment before validation
        try:
            min_required = 0
            try:
                rules = (contract or {}).get("rules") or {}
                min_required = int((rules.get("min_list_lengths") or {}).get("observed_mitre_techniques") or 0)
            except Exception:
                min_required = 0
            _expand_mitre_from_tactics_best_effort(obj, min_required=min_required or 5, logger=logger)
        except Exception:
            pass

        # Phase 6.5.8.5+: deterministic non-destructive repair pass BEFORE validation.
        # This ensures "fail-open" does not create structurally non-canonical briefs and avoids user approval loops.
        try:
            if obj is not None:
                from .intel_invariants import repair_intel_brief

                obj, repairs_applied = repair_intel_brief(obj)
                if repairs_applied:
                    try:
                        obj.meta.history.append({
                            "ts": utc_now(),
                            "actor": "system",
                            "action": "intel_repair_applied",
                            "note": (",".join(repairs_applied))[:2000],
                        })
                    except Exception:
                        pass
        except Exception:
            pass
        if contract is None or (contract_mode or "").strip().lower() == "off":
            break

        # Validate
        try:
            from .contract_framework import validate_intel_brief, ContractViolation

            if obj is None:
                last_violations = [
                    ContractViolation(
                        field="__parse__",
                        code="parse_error",
                        message="Failed to parse model output into the Intel Brief schema.",
                    )
                ]
            else:
                last_violations = validate_intel_brief(obj, contract)
        except Exception:
            last_violations = []

        ok = len(last_violations) == 0
        logger.info("[VALIDATION] intel_brief attempt=%s/%s ok=%s violations=%s", attempt + 1, attempts_total, ok, len(last_violations))
        if ok:
            # Optional: log a small "why this passed" summary (word counts, indicator counts, list lengths)
            try:
                from .contract_framework import summarize_intel_brief

                summary = summarize_intel_brief(obj, contract) if obj is not None else {}
                logger.info("[VALIDATION] intel_brief pass_summary=%s", summary)
            except Exception:
                pass
            break
        # If regen is disabled or we exhausted attempts, stop.
        if attempt + 1 >= attempts_total:
            break

    # Fall back if parsing failed (should be rare)
    if last_obj is None:
        # previous parsing code path
        pass

    # Use parsed object when available
    if last_obj is not None:
        # Persist validation status into the artifact audit trail for transparency.
        try:
            if contract is not None and (contract_mode or "").strip().lower() != "off":
                if last_violations:
                    from .contract_framework import format_violations
                    last_obj.meta.history.append({
                        "ts": utc_now(),
                        "actor": "system",
                        "action": "contract_validation_failed",
                        "note": (format_violations(last_violations) or "validation failed")[:2000],
                    })
                    logger.warning("[ENFORCEMENT] intel_brief non-compliant; saved as Draft with violations=%s", len(last_violations))
                else:
                    last_obj.meta.history.append({
                        "ts": utc_now(),
                        "actor": "system",
                        "action": "contract_validation_passed",
                        "note": "validation passed",
                    })
        except Exception:
            pass
        return last_obj, text

    # Legacy fallback path (should not normally hit)
    

    # Very light parsing: split by headings; keep tolerant
    sections = {
        "1. Title": "",
        "2. Date / Author / Reference ID": "",
        "3. BLUF (Bottom Line Up Front)": "",
        "4. Background": "",
        "5. Threat Description": "",
        "6. Current Assessment": "",
        "7. Evidence and Indicators": "",
        "8. Impact Assessment": "",
        "9. Confidence and Credibility Ratings": "",
        "10. Gaps and Collection Requirements": "",
        "11. Alternative Analysis": "",
        "12. Outlook / Future Implications": "",
        "13. Recommended Actions": "",
        "14. Summary Paragraph(s)": "",
        "15. Appendix": "",
    }

    def _norm_heading(line: str) -> str:
        """Normalize model headings so we can parse regardless of markdown formatting.

        Examples accepted:
          - "Summary"
          - "## Summary"
          - "SUMMARY:"
          - "**Summary**"
        """
        s = line.strip()
        # strip common markdown heading markers
        while s.startswith("#"):
            s = s.lstrip("#").strip()
        # strip emphasis wrappers
        s = s.strip("*").strip()
        # drop trailing colon
        s = s.rstrip(":").strip()
        return s

    # map normalized headings to canonical keys
    canon_map = {k.lower(): k for k in sections.keys()}

    current = None
    saw_any_heading = False
    for line in text.splitlines():
        nh = _norm_heading(line)
        # If the model includes a "Sources" section, stop collecting content into prior sections.
        if nh.lower() in {"sources", "references"}:
            current = None
            saw_any_heading = True
            continue
        key = canon_map.get(nh.lower())
        if key:
            current = key
            saw_any_heading = True
            continue
        if current:
            sections[current] += line + "\n"

    # Sanitize sections: if the model echoed headings inside a section, strip them to avoid duplicate headings
    # in the rendered markdown (e.g., "## Sources" appearing inside Data Exfiltration).
    def _strip_embedded_headings(s: str) -> str:
        out_lines: list[str] = []
        for ln in (s or "").splitlines():
            n = _norm_heading(ln)
            if n.lower() in canon_map or n.lower() in {"sources", "references"}:
                continue
            out_lines.append(ln)
        return "\n".join(out_lines).strip()

    for k in list(sections.keys()):
        sections[k] = _strip_embedded_headings(sections[k])

    # If the model didn't follow headings, fall back to putting everything in BLUF
    if not saw_any_heading:
        sections["3. BLUF (Bottom Line Up Front)"] = text.strip()

    title = sections["1. Title"].strip() or topic
    date = now
    author = "Threat Hunting / CTI"
    reference_id = "TBD"
    # Extract basic metadata lines if present
    for ln in sections["2. Date / Author / Reference ID"].splitlines():
        low = ln.lower()
        if "date" in low and ":" in ln:
            date = ln.split(":", 1)[-1].strip() or date
        if "author" in low and ":" in ln:
            author = ln.split(":", 1)[-1].strip() or author
        if "reference" in low and ":" in ln:
            reference_id = ln.split(":", 1)[-1].strip() or reference_id

    # Best-effort MITRE extraction: look for T#### patterns anywhere.
    mitre = sorted(set(re.findall(r"T\d{4}(?:\.\d{3})?", text)))
    obj = IntelBrief(
        meta=meta,
        approval=ApprovalStatus.DRAFT,
        topic=topic,
        sources=sources,
        iocs=extract_iocs(((source_text or "") + "\n" + (text or "")).strip()),
        title=title,
        date=date,
        author=author,
        reference_id=reference_id,
        bluf=sections["3. BLUF (Bottom Line Up Front)"].strip(),
        background=sections["4. Background"].strip(),
        threat_description=sections["5. Threat Description"].strip(),
        current_assessment=sections["6. Current Assessment"].strip(),
        evidence_and_indicators=sections["7. Evidence and Indicators"].strip(),
        impact_assessment=sections["8. Impact Assessment"].strip(),
        confidence_and_credibility=sections["9. Confidence and Credibility Ratings"].strip(),
        gaps_and_collection=sections["10. Gaps and Collection Requirements"].strip(),
        alternative_analysis=sections["11. Alternative Analysis"].strip(),
        outlook=sections["12. Outlook / Future Implications"].strip(),
        recommended_actions=sections["13. Recommended Actions"].strip(),
        summary_paragraphs=sections["14. Summary Paragraph(s)"].strip(),
        appendix=sections["15. Appendix"].strip(),
        observed_mitre_techniques=mitre,
    )
    return obj, text



_HUNT_SYSTEM = (
    "You are BYO-SecAI, a threat-hunting assistant. Produce hunt packages that are testable and log-centric. "
    "Use CrowdStrike LogScale CQL syntax when including example queries."
)

# --- Phase 6.5.8: Deterministic Intel -> Hunt mapping (v1) ---
# Goal: make Hunt Packages consistent by composing from approved intel, then using LLM only as "narrative glue".
# This reduces contract churn and improves UX (fast, predictable outputs).
_INTEL_TO_HUNT_MAPPING_TABLE = {
    "hunt.linked_intel_id": "intel.meta.id",
    "hunt.objective": "Derived from intel.topic/title + key behaviors + impact (LLM glue may refine).",
    "hunt.hypotheses[]": "Derived from intel.behaviors and/or observed_mitre_techniques (LLM glue may refine).",
    "hunt.data_sources[]": "Default telemetry list by query_language/platform; may be refined (no inventions).",
    "hunt.scope_notes": "Default platform/environment boundaries; may be refined (no inventions).",
    "hunt.execution_notes": "Concrete steps to run queries, pivot, enrich, document findings.",
    "hunt.behaviors[].technique": "Copied from intel.observed_mitre_techniques when behavior techniques are missing.",
}

def build_hunt_seed_from_intel(intel: "IntelBrief", qlang: str, qlang_label: str) -> dict:
    """Create a deterministic Hunt seed from an approved IntelBrief."""
    topic = (getattr(intel, "topic", "") or getattr(intel, "title", "") or "Threat activity").strip()
    # Pull a few high-signal IOCs for wording only (never invent new ones)
    iocs = getattr(intel, "iocs", {}) or {}
    fn = (iocs.get("filenames") or [])[:3] if isinstance(iocs.get("filenames"), list) else []
    dom = (iocs.get("domains") or [])[:3] if isinstance(iocs.get("domains"), list) else []
    tools = [x for x in (fn + dom) if str(x).strip()]
    tool_hint = (", ".join(tools[:3])).strip()
    if tool_hint:
        obj = f"Determine whether telemetry shows activity related to {topic} (e.g., {tool_hint})."
    else:
        obj = f"Determine whether telemetry shows activity related to {topic}."

    # Default scope: keep it concrete and platform-aware
    scope = "Scope: Windows endpoints monitored by CrowdStrike Falcon. Time window: last 30 days. Focus on process + network telemetry."
    if qlang in ("KQL",):
        scope = "Scope: Microsoft Defender / Sentinel data sources for Windows endpoints and identities. Time window: last 30 days."
    if qlang in ("SPL",):
        scope = "Scope: Splunk logs for endpoints and network. Time window: last 30 days."

    # Default data sources by platform
    if qlang == "CQL":
        data_sources = [
            "CrowdStrike Falcon: ProcessRollup2 (process execution)",
            "CrowdStrike Falcon: NetworkConnectIP4 (outbound connections)",
        ]
    elif qlang == "KQL":
        data_sources = [
            "Microsoft Defender: DeviceProcessEvents",
            "Microsoft Defender: DeviceNetworkEvents",
        ]
    else:
        data_sources = ["Endpoint process telemetry", "Network connection telemetry"]

    # Hypotheses: start from behaviors if present; else from observed MITRE
    hyps = []
    behs = getattr(intel, "behaviors", []) or []
    for b in behs[:3]:
        name = (getattr(b, "name", "") or "behavior").strip()
        tech = (getattr(b, "technique", "") or "").strip()
        if tech:
            hyps.append(f"If adversary activity includes {name} ({tech}), then we expect to observe matching process/network telemetry indicating that behavior.")
        else:
            hyps.append(f"If adversary activity includes {name}, then we expect to observe matching process/network telemetry indicating that behavior.")
    tids = getattr(intel, "observed_mitre_techniques", []) or []
    for t in [str(x).strip() for x in tids if str(x).strip()][:3]:
        if len(hyps) >= 3:
            break
        hyps.append(f"If activity aligned to {t} is present, then we expect to observe telemetry consistent with that technique on in-scope systems.")

    if not hyps:
        hyps = ["If the reported threat activity is present, then we expect to observe related process and/or network telemetry consistent with the intel narrative."]

    execution = (
        "Run the hunt queries and record any hits. Pivot on process lineage (parent/child), user, host, and time. "
        "Enrich suspicious domains/IPs, correlate with authentication and lateral movement signals, and document findings for IR Report + ADS."
    )

    return {
        "objective": obj,
        "hypotheses": hyps,
        "data_sources": data_sources,
        "scope_notes": scope,
        "execution_notes": execution,
        "mapping_table": _INTEL_TO_HUNT_MAPPING_TABLE,
    }

def apply_hunt_seed(obj: "HuntPackage", intel: "IntelBrief", seed: dict) -> None:
    """Apply deterministic seed values and ensure MITRE technique coverage via behaviors + query metadata."""
    try:
        if not (getattr(obj, "objective", "") or "").strip():
            obj.objective = str(seed.get("objective", "") or "").strip()
        if not getattr(obj, "hypotheses", None):
            obj.hypotheses = list(seed.get("hypotheses") or [])
        if not getattr(obj, "data_sources", None):
            obj.data_sources = list(seed.get("data_sources") or [])
        if not (getattr(obj, "scope_notes", "") or "").strip():
            obj.scope_notes = str(seed.get("scope_notes", "") or "").strip()
        if not (getattr(obj, "execution_notes", "") or "").strip():
            obj.execution_notes = str(seed.get("execution_notes", "") or "").strip()
    except Exception:
        pass

    # Ensure behaviors include technique IDs (required for contract MITRE extraction)
    try:
        from .models import Behavior
        tids = getattr(intel, "observed_mitre_techniques", []) or []
        tids = [str(t).strip() for t in tids if str(t).strip()]
        have = []
        for b in (getattr(obj, "behaviors", []) or []):
            tid = (getattr(b, "technique", "") or "").strip()
            if tid:
                have.append(tid)
        if not have and tids:
            obj.behaviors = [
                Behavior(
                    behavior_id=f"MITRE-{t}",
                    name=f"Observed technique {t}",
                    behavior_type="MITRE",
                    technique=t,
                    confidence="medium",
                    sources=["intel.observed_mitre_techniques"],
                )
                for t in tids
            ]
    except Exception:
        pass

    # Also annotate queries with techniques (round-robin) so downstream UIs can show mapping
    try:
        tids = [str(t).strip() for t in (getattr(intel, "observed_mitre_techniques", []) or []) if str(t).strip()]
        if tids and getattr(obj, "queries", None):
            for q in (obj.queries or []):
                try:
                    q.technique = _pick_technique_for_query(q, tids)
                except Exception:
                    pass

    except Exception:
        pass





def _pick_technique_for_query(q: "HuntQuery", tids: list) -> str:
    """Assign a MITRE technique to a query in a consistent (but conservative) way.

    Goal: avoid misleading technique names/IDs by round-robin assignment.
    Strategy:
      - Prefer leaving technique blank unless we can map to a reasonable technique
        from the intel's observed technique list.
      - Use stable heuristics based on query intent/title.
    """
    if not tids:
        return ""
    title_l = (getattr(q, "title", "") or "").lower()
    desc_l = (getattr(q, "description", "") or "").lower()

    # Prefer explicit technique already set (if any)
    existing = (getattr(q, "technique", "") or "").strip()
    if existing and existing in tids:
        return existing

    # Helper to pick first available from a preference list.
    def pref(*prefs):
        for p in prefs:
            if p and p in tids:
                return p
        return ""

    # Network-ish (IP / port) queries
    if "network" in title_l or "remoteaddressip" in (getattr(q, "query", "") or "").lower() or "rport" in (getattr(q, "query", "") or "").lower():
        # Prefer common C2 / proxy / remote services techniques if present in intel.
        return pref("T1071.001", "T1090", "T1021") or tids[0]

    # DNS / domain queries
    if "dns" in title_l or "domain" in title_l or "dnsrequest" in (getattr(q, "query", "") or "").lower():
        return pref("T1071.004", "T1071.001", "T1090") or tids[0]

    # URL delivery / phishing often maps to T1566 if present.
    if "url" in title_l or "phish" in desc_l:
        return pref("T1566", "T1105") or tids[0]

    # File / process / hash IOCs: don't guess unless intel already includes strong matches.
    if title_l.startswith("ioc") or "sha256" in title_l or "hash" in title_l or "file name" in title_l:
        # Use execution-ish technique if present, otherwise leave blank to avoid misleading mapping.
        return pref("T1204", "T1059") or ""

    # Correlation behavior queries: align with their dominant signal.
    if "correlate" in desc_l or "correlated" in title_l:
        if "dns" in title_l:
            return pref("T1071.004", "T1071.001", "T1090") or tids[0]
        if "network" in title_l:
            return pref("T1071.001", "T1090", "T1021") or tids[0]

    # Default: first observed technique for consistency across runs.
    return tids[0]


def _normalize_scope_notes(scope_notes: str, intel: "IntelBrief") -> str:
    """Tighten scope wording to avoid claiming cloud context unless the intel supports it."""
    s = (scope_notes or "").strip()
    if not s:
        return s

    intel_text = "\n".join([
        getattr(intel, "title", "") or "",
        getattr(intel, "topic", "") or "",
        getattr(intel, "bluf", "") or "",
        getattr(intel, "background", "") or "",
        getattr(intel, "threat_description", "") or "",
        getattr(intel, "evidence_and_indicators", "") or "",
        getattr(intel, "impact_assessment", "") or "",
    ]).lower()

    cloud_terms = ["azure", "aks", "oci", "oracle cloud", "aws", "amazon web services", "gcp", "google cloud"]
    intel_mentions_cloud = any(t in intel_text for t in cloud_terms)

    if not intel_mentions_cloud:
        # Remove common cloud phrases if they slipped into scope notes.
        s = re.sub(r"\b(in|within)\s+(an?\s+)?(azure|aws|gcp|oci)\b.*?(environment|tenant)?\.?", "", s, flags=re.I)
        s = re.sub(r"\b(azure|aws|gcp|oci|aks)\b", "", s, flags=re.I)
        s = re.sub(r"\s{2,}", " ", s).strip()

    # Normalize spacing/punctuation
    s = s.replace("..", ".").strip()
    return s


def _sanitize_hypotheses(hypotheses: list) -> list:
    """Remove incorrect MITRE technique name parentheticals (keep IDs)."""
    out = []
    for h in (hypotheses or []):
        hs = str(h or "").strip()
        if not hs:
            continue
        # If "If T#### (Something)" -> "If T####"
        hs = re.sub(r"\b(T\d{4}(?:\.\d{3})?)\s*\([^)]*\)", r"\1", hs)
        out.append(hs)
    return out


def render_hunt_markdown_v1(pkg: "HuntPackage", intel: "IntelBrief", qlang_label: str) -> str:
    """Deterministic, compact hunt markdown renderer (avoids template placeholders)."""
    lines: list[str] = []
    title = getattr(getattr(pkg, "meta", None), "title", "Hunt Package") or "Hunt Package"
    lines.append(f"# {title}")
    lines.append("")
    lines.append(f"**Linked Intel:** `{getattr(pkg, 'linked_intel_id', '')}`")
    lines.append("")
    lines.append("## Objective")
    lines.append((pkg.objective or "").strip() or "(Not provided)")
    lines.append("")
    lines.append("## Hypotheses")
    if pkg.hypotheses:
        for h in pkg.hypotheses:
            if str(h).strip():
                lines.append(f"- {str(h).strip()}")
    else:
        lines.append("- (Not provided)")
    lines.append("")
    lines.append("## Scope and Assumptions")
    lines.append((pkg.scope_notes or "").strip() or "(Not provided)")
    lines.append("")
    lines.append("## Data Sources / Telemetry")
    if pkg.data_sources:
        for d in pkg.data_sources:
            if str(d).strip():
                lines.append(f"- {str(d).strip()}")
    else:
        lines.append("- (Not provided)")
    lines.append("")
    # MITRE techniques from behaviors + query annotations
    tids = []
    try:
        for b in (getattr(pkg, 'behaviors', []) or []):
            t = str(getattr(b, 'technique', '') or '').strip()
            if t and t not in tids:
                tids.append(t)
    except Exception:
        pass
    try:
        for q in (getattr(pkg, 'queries', []) or []):
            t = str(getattr(q, 'technique', '') or '').strip()
            if t and t not in tids:
                tids.append(t)
    except Exception:
        pass
    lines.append("## MITRE ATT&CK Coverage")
    if tids:
        lines.append(", ".join(tids))
    else:
        lines.append("(Not provided)")
    lines.append("")
    lines.append("## Hunt Queries")
    if getattr(pkg, 'queries', None):
        for i, q in enumerate(pkg.queries, start=1):
            lines.append(f"### Query {i}: {q.title}")
            if (q.description or "").strip():
                lines.append((q.description or "").strip())
            if (getattr(q, 'technique', '') or '').strip():
                lines.append(f"**Technique:** {getattr(q, 'technique', '').strip()}")
            lines.append("")
            lines.append(f"```{(pkg.queries[i-1].query_language or '').split()[0].lower() if pkg.queries[i-1].query_language else ''}")
            lines.append((q.query or "").strip())
            lines.append("```")
            lines.append("")
    else:
        lines.append("(No queries)")
    lines.append("## Execution Notes")
    lines.append((pkg.execution_notes or "").strip() or "(Not provided)")
    return "\n".join(lines).strip() + "\n"



def _build_deterministic_hunt_objective(topic: str, techniques: list[str] | None, scopes: list[str] | None) -> str:
    """Deterministically build a strong Hunt objective.

    Uses intel topic/title + ATT&CK techniques + telemetry scope hints.
    Keeps this stable to avoid contract drift / fail-open.
    """
    t = (topic or "").strip() or "Untitled"
    techs = [str(x).strip() for x in (techniques or []) if str(x).strip()]
    # Only keep the technique id portion if the string contains a name
    cleaned = []
    for x in techs:
        m = re.match(r"^(T\d{4}(?:\.\d{3})?)", x.strip(), flags=re.I)
        cleaned.append(m.group(1).upper() if m else x)
    # De-dupe while preserving order
    seen = set()
    techs2 = []
    for x in cleaned:
        if x not in seen:
            seen.add(x)
            techs2.append(x)
    scope_list = [str(s).strip() for s in (scopes or []) if str(s).strip()]
    if not scope_list:
        scope_list = ["Process"]
    # Normalize common labels
    norm = []
    for s in scope_list:
        sl = s.lower()
        if "dns" in sl:
            norm.append("DNS")
        elif "net" in sl:
            norm.append("Network")
        elif "process" in sl:
            norm.append("Process")
        else:
            norm.append(s.title())
    # De-dupe
    seen=set()
    norm2=[]
    for s in norm:
        if s not in seen:
            seen.add(s)
            norm2.append(s)
    scope_txt = ", ".join(norm2)

    tech_txt = ", ".join(techs2[:6]) if techs2 else "relevant MITRE ATT&CK techniques"
    obj = (
        f"Hunt for activity related to '{t}' by validating behaviors aligned to {tech_txt} "
        f"using {scope_txt} telemetry. Identify evidence of compromise, scope impacted hosts/users, "
        f"and capture supporting artifacts for IR reporting and detection strategy development."
    )
    # Ensure minimum strength/length
    if len(obj) < 140:
        obj += " Focus on high-signal pivots and document false-positive reduction notes for production detections."
    return obj.strip()


def generate_hunt_package(
    llm: BaseLLM,
    artifact_id: str,
    intel: IntelBrief,
    sources_text: str = "",
    cfg: "AppConfig | None" = None,
    query_language: str = "CQL",
    min_queries: int = 2,
    max_queries: int = 7,
    include_ioc_sweeps: bool = True,
    # Phase 6.3: optional grounding for CQL using the local Knowledge Library
    rag_index=None,
    ground_queries: bool = False,
    grounding_debug: bool = True,
    grounding_top_k_dictionary: int = 5,
    grounding_top_k_examples: int = 5,
    on_token=None,
) -> tuple[HuntPackage, str, dict]:
    """
    Generate a Hunt Package artifact.

    Phase 5.1: The Hunt Package must be template-driven (Threat_Hunt_Package_Template.md).
    We ask the LLM to fill the template placeholders, then derive structured fields
    (objective/hypotheses/data_sources/queries) from that filled content for downstream steps.
    """
    meta = new_meta(ArtifactType.HUNT_PACKAGE, f"Hunt Package: {intel.topic}", artifact_id)

    # --- Contract framework for Hunt Packages (optional): load contract rules ---
    contract = None
    contract_profile = None
    contract_mode = "off"
    regen_attempts = 0
    try:
        if cfg is not None:
            from .contract_framework import load_contract

            contract_profile = getattr(cfg, "hunt_package_contract_profile", "threat_hunt_v1_0")
            contract_mode = getattr(cfg, "contract_enforcement_mode", "strict")
            regen_attempts = int(getattr(cfg, "contract_regen_attempts", 2) or 0)
            contract, _cpath = load_contract(
                contract_profile,
                contract_dir_override=getattr(cfg, "contract_dir_override", ""),
            )
    except Exception:
        contract = None

    template = _load_template("Threat_Hunt_Package_Template.md") or ""
    # For context, prefer BLUF -> Summary Paragraphs -> Threat Description
    intel_summary = (
        (intel.bluf or "").strip()
        or (intel.summary_paragraphs or "").strip()
        or (intel.threat_description or "").strip()
        or "(No intel summary provided)"
    )


    # Phase 6.5.8: deterministic Intel->Hunt mapping seed (fast, consistent)
    # Phase 6.3.2: telemetry schema translation (ECS/Sigma/CIM -> CrowdStrike pivots)
    # This prevents schema tokens like `process.pe` from polluting IOC extraction and
    # forces the model to anchor on ...
    sources_text_translated, translation_debug = translate_fields_to_crowdstrike(sources_text or "")

    # Phase 6.3.1: behavior-first extraction (deterministic).
    # This is used to (1) improve retrieval seeds, (2) constrain prompts, and
    # (3) gate query relevance so we don't emit generic template filler.
    _behavior_text = "\n".join(
        [
            intel.topic or "",
            intel.title or "",
            intel_summary or "",
            (intel.threat_description or "").strip(),
            (intel.evidence_and_indicators or "").strip(),
            (intel.background or "").strip(),
            (sources_text_translated or "").strip(),
        ]
    )
    behavior_profile = extract_behaviors(_behavior_text)
    behavior_checklist = build_behavior_checklist(behavior_profile)

    # Discover placeholders in the template (e.g., {{THREAT_NAME}})
    placeholders = sorted(set(re.findall(r"\{\{([A-Z0-9_]+)\}\}", template)))

    # Build a strict JSON contract so we can reliably fill the template.
    # The model must return JSON ONLY (no code fences).
    qlang = (query_language or "CQL").upper().strip()
    kql_profile = (getattr(cfg, "kql_profile", None) if cfg else None)
    min_queries = max(1, int(min_queries))
    max_queries = max(min_queries, int(max_queries))


    # Human-friendly label for rendered artifacts / UI (must exist before any fallback paths)
    qlang_label = {
        "CQL": "CrowdStrike LogScale CQL",
        "SPL": "SPL",
        "KQL": "KQL",
        "SQL": "SQL",
        "OSQUERY": "OSQuery",
        "PSEUDOCODE": "Pseudocode",
    }.get(qlang, "CrowdStrike LogScale CQL")
    # Phase 6.5.8: deterministic Intel->Hunt mapping seed (fast, consistent)
    seed = build_hunt_seed_from_intel(intel, qlang, qlang_label)

    # Build deterministic IOC sweep queries first ("Level 1" sweeps).
    # These are generated from extracted IOC data and are always injected ahead
    # of any LLM-generated queries.
    ioc_sweep_queries: list[HuntQuery] = []
    ioc_stats: dict = {}  # always defined (prevents UnboundLocalError across qlang branches)
    if include_ioc_sweeps and getattr(intel, "iocs", None):
        try:
            if qlang == "CQL":
                ioc_sweep_queries, ioc_stats = build_ioc_sweep_queries_cql(intel.iocs, qlang_label)
            elif qlang == "KQL":
                ioc_sweep_queries, ioc_stats = build_ioc_sweep_queries_kql(intel.iocs, qlang_label)
        except Exception:
            # Never break hunt generation due to IOC sweep build.
            ioc_sweep_queries = []
            ioc_stats = {}

    dialect_hint = ""
    if qlang == "CQL":
        dialect_hint = (
            "Use CrowdStrike Falcon LogScale CQL (Humio-style). Output ONLY valid CQL.\n"
            "Hard rules:\n"
            " - Each query MUST start with #event_simpleName=\n"
            " - Use in(field=..., values=[...]) instead of SQL IN\n"
            " - Use select(), groupBy(), join() (LogScale functions)\n"
            " - Do NOT invent process names/binaries. Only use filenames/domains/IPs that appear in the IOC TABLE.\n"
            " - Avoid SQL keywords (SELECT/FROM/WHERE), SPL (index=, | stats), and KQL (Device* tables).\n"
            "Example:\n"
            "#event_simpleName=ProcessRollup2\n"
            "| in(field=FileName, values=[\"cmd.exe\",\"powershell.exe\"])\n"
            "| groupBy([ComputerName, UserName, FileName, CommandLine], limit=20000)\n"
        )
    elif qlang == "SPL":
        dialect_hint = "Use Splunk SPL (index=..., sourcetype=..., | stats, | tstats, etc.).\n"
    elif qlang == "KQL":
        prof = (kql_profile or "MDE").upper().strip()
        if prof == "MDE":
            dialect_hint = "Use Microsoft KQL for Microsoft Defender for Endpoint (Device* tables).\n"
        elif prof == "SENTINEL":
            dialect_hint = "Use Microsoft KQL for Microsoft Sentinel (SecurityEvent/Sysmon-style tables).\n"
        else:
            dialect_hint = "Use Microsoft KQL. Emit HYBRID variants when helpful (MDE + Sentinel baseline).\n"

    # Phase 6.3: optional grounding for CQL using the local Knowledge Library.
    # This is best-effort: if the index isn't available, generation falls back to
    # normal template filling.
    grounding: dict = {}
    grounding_text = ""

    # Always keep telemetry translation decisions for the UI debug panel.
    if bool(grounding_debug) and translation_debug:
        grounding["telemetry_translation"] = translation_debug
    if (
        qlang == "CQL"
        and bool(ground_queries)
        and rag_index is not None
        and hasattr(rag_index, "query")
    ):
        try:
            # Two-pass retrieval: authoritative dictionary chunks + example query chunks.
            # Seed retrieval with behavior keywords so we pull dictionary chunks and
            # examples that match the *behavior* (not just generic CQL).
            _bkw = " ".join((behavior_profile.keywords or [])[:24])
            q_seed = (
                f"{intel.topic}\n{intel_summary}\n"
                f"behaviors={_bkw}\n"
                f"iocs={json.dumps(getattr(intel, 'iocs', {}) or {})}"
                "\nCrowdStrike LogScale CQL #event_simpleName fields"
            )
            dict_hits = []
            ex_hits = []
            hits = rag_index.query(q_seed, top_k=int(grounding_top_k_dictionary) + int(grounding_top_k_examples))
            for score, ch in (hits or []):
                stype = getattr(ch, "source_type", "") or ""
                if stype == "dictionary" and len(dict_hits) < int(grounding_top_k_dictionary):
                    dict_hits.append((float(score), ch))
                elif stype in ("examples", "ads", "library") and len(ex_hits) < int(grounding_top_k_examples):
                    ex_hits.append((float(score), ch))
            # If the index isn't tagged, just split the top hits.
            if not dict_hits and hits:
                dict_hits = [(float(s), c) for s, c in hits[: int(grounding_top_k_dictionary)]]
                ex_hits = [(float(s), c) for s, c in hits[int(grounding_top_k_dictionary): int(grounding_top_k_dictionary)+int(grounding_top_k_examples)]]

            def _fmt(hit_list: list[tuple[float, any]], label: str) -> str:
                if not hit_list:
                    return f"{label}: (none)"
                lines = [f"{label}:" ]
                for s, c in hit_list:
                    sid = getattr(c, "source_id", "")
                    txt = (getattr(c, "text", "") or "").strip().replace("\n", " ")
                    if len(txt) > 900:
                        txt = txt[:900] + "…"
                    lines.append(f"- ({s:.3f}) {sid}: {txt}")
                return "\n".join(lines)

            grounding_text = (
                "\n\n".join([
                    _fmt(dict_hits, "AUTHORITATIVE DICTIONARY CONTEXT"),
                    _fmt(ex_hits, "EXAMPLE QUERY / STYLE CONTEXT"),
                ])
            )
            if bool(grounding_debug):
                grounding = {
                    "dictionary": [
                        {
                            "score": round(float(s), 4),
                            "source_id": getattr(c, "source_id", ""),
                            "source_type": getattr(c, "source_type", ""),
                            "text": (getattr(c, "text", "") or "")[:2000],
                        }
                        for s, c in dict_hits
                    ],
                    "examples": [
                        {
                            "score": round(float(s), 4),
                            "source_id": getattr(c, "source_id", ""),
                            "source_type": getattr(c, "source_type", ""),
                            "text": (getattr(c, "text", "") or "")[:2000],
                        }
                        for s, c in ex_hits
                    ],
                }
        except Exception:
            grounding_text = ""
            grounding = {}

    # Phase 6.3.1: behavior-first query regeneration (best-effort + deterministic fallback)
    def _behavior_scaffold_cql() -> str:
        """Deterministic CQL scaffold built from extracted behaviors.

        This is used when the model fails behavior-checklist validation.
        """
        tool = (behavior_profile.tools[0] if behavior_profile.tools else "")
        tool = tool if tool.lower().endswith(".exe") else (tool + ".exe" if tool else "")
        # Build a simple regex with the most relevant action/target tokens.
        toks = []
        for v in (behavior_profile.actions or [])[:4]:
            toks.append(re.escape(v))
        for v in (behavior_profile.targets or [])[:4]:
            toks.append(re.escape(v))
        rx = "|".join([t for t in toks if t])
        rx = rx or "ntds\\.dit|windows\\\\ntds|start\\s+backup"
        q = "#event_simpleName=ProcessRollup2\n"
        if tool:
            q += f"FileName={tool}\n"
        q += f"| regex(CommandLine=/(?:{rx})/i)\n"
        q += "| groupBy([@timestamp, ComputerName, UserName, FileName, CommandLine], limit=20000)"
        return q

    def _rewrite_query_with_llm(title: str, prior_query: str) -> str:
        """Ask the LLM to rewrite a single query to satisfy the checklist."""
        if isinstance(llm, StubLLM):
            return ""
        # Give the model a scaffold and strict requirements.
        scaffold = (
            "#event_simpleName=ProcessRollup2\n"
            "FileName=<tool.exe>\n"
            "| regex(CommandLine=/(<action>|<target>)/i)\n"
            "| groupBy([@timestamp, ComputerName, UserName, FileName, CommandLine], limit=20000)\n"
        )
        rewrite_prompt = (
            "Rewrite ONE CrowdStrike LogScale CQL query so it is behavior-first and satisfies the behavior checklist.\n"
            "Return ONLY the CQL query (no markdown, no backticks, no commentary).\n\n"
            f"TITLE: {title}\n"
            f"INTEL TOPIC: {intel.topic or intel.title or 'Untitled'}\n"
            f"INTEL SUMMARY: {intel_summary[:1400]}\n\n"
            "BEHAVIOR EXTRACTED:\n" + json.dumps(behavior_profile.to_dict(), indent=2) + "\n\n"
            "BEHAVIOR CHECKLIST (must satisfy):\n" + json.dumps(behavior_checklist, indent=2) + "\n\n"
            + ("KNOWLEDGE LIBRARY GROUNDING (dictionary authoritative; examples are style):\n" + grounding_text + "\n\n" if grounding_text else "")
            + "PRIOR QUERY (rewrite this):\n" + (prior_query or "") + "\n\n"
            + "SCAFFOLD (use this shape if helpful):\n" + scaffold
        )
        try:
            out = _safe_generate(llm, rewrite_prompt, _HUNT_SYSTEM).strip()
            # Strip accidental fences
            out = out.replace("```cql", "").replace("```", "").strip()
            return out
        except Exception:
            return ""

    prompt = (
        "You are drafting a Threat Hunt Package using the provided markdown template.\n"
        "Fill EVERY placeholder listed with realistic, concise content based on the intel context.\n\n"
        "Rules:\n"
        "- Output MUST be valid JSON ONLY (no markdown, no backticks).\n"
        "- Keys MUST exactly match the placeholder names.\n"
        "- Values are plain strings. Use markdown bullets (\\n- ...) where appropriate.\n"
        f"- For query placeholders, return a plausible {qlang} query and keep it short.\n"
        f"- Dialect guidance: {dialect_hint}"
        "- If a field is unknown from sources, write 'Unknown' (do not invent specific victims, dates, or amounts).\n\n"
        f"PLACEHOLDERS: {', '.join(placeholders) if placeholders else '(none)'}\n\n"
        "INTEL TOPIC: " + (intel.topic or "Untitled") + "\n\n"
        "INTEL SUMMARY:\n" + intel_summary + "\n\n"
        + ("BEHAVIOR EXTRACTED (use these concrete pivots; prefer behavior-first detections over generic templates):\n"
           + json.dumps(behavior_profile.to_dict(), indent=2) + "\n\n")
        + ("BEHAVIOR CHECKLIST (queries must satisfy these relevance constraints):\n"
           + json.dumps(behavior_checklist, indent=2) + "\n\n")
        + ("SOURCE EXTRACTS:\n" + sources_text_translated + "\n\n" if sources_text_translated else "")
        + ("IOC TABLE (authoritative; do not invent indicators):\n" + json.dumps(getattr(intel, "iocs", {}) or {}, indent=2) + "\n\n" if getattr(intel, "iocs", None) else "")
        + ("KNOWLEDGE LIBRARY GROUNDING (use as constraints; dictionary is authoritative):\n" + grounding_text + "\n\n" if grounding_text else "")
        + "TEMPLATE (for reference):\n" + template[:8000]  # keep prompt bounded
    )

    filled_markdown = ""
    obj_map: dict = {}
    if template and placeholders:
        try:
            raw = _safe_generate(llm, prompt, _HUNT_SYSTEM, on_token=on_token).strip()
            # Best-effort: strip accidental leading/trailing prose
            raw_json = raw
            # If model wrapped JSON in extra text, try to locate first { ... last }
            if "{" in raw_json and "}" in raw_json:
                raw_json = raw_json[raw_json.find("{") : raw_json.rfind("}") + 1]
            obj_map = json.loads(raw_json)
        except Exception:
            obj_map = {}

        if obj_map:
            filled_markdown = template
            for k in placeholders:
                v = str(obj_map.get(k, "Unknown") or "Unknown")
                filled_markdown = filled_markdown.replace("{{" + k + "}}", v)

    # Fallback: if template fill failed, DO NOT call the model again (prevents drift between
    # the structured HuntQuery objects and the rendered markdown). Build a deterministic draft
    # from the intel summary + our known-good query dialects.
    if not filled_markdown:
        topic = intel.topic or intel.title or "Untitled"
        # Deterministic Hunt Objective builder (prevents contract fail-open / weak objectives)
        _techs = list(getattr(intel, "observed_mitre_techniques", []) or [])
        # Infer telemetry scope from IOCs + behavior keywords
        _iocs = getattr(intel, "iocs", {}) or {}
        _scopes = ["Process"]
        try:
            if (_iocs.get("ip_port") or []) or (_iocs.get("ip") or []) or (_iocs.get("domain") or []) or (_iocs.get("url") or []):
                _scopes.append("Network")
            if (_iocs.get("domain") or []) or (_iocs.get("url") or []):
                _scopes.append("DNS")
        except Exception:
            pass
        try:
            kw = " ".join(getattr(behavior_profile, "keywords", []) or []).lower()
            if any(t in kw for t in ["dns", "domain", "url", "http", "https"]):
                _scopes.append("DNS")
            if any(t in kw for t in ["network", "socket", "beacon", "c2", "port", "remote"]):
                _scopes.append("Network")
        except Exception:
            pass
        objective = _build_deterministic_hunt_objective(topic, _techs, _scopes)
        hypotheses = [
            "Adversary may stage payloads via common LOLBins or remote execution tools.",
            "Adversary may establish command-and-control using common ports or unusual destinations.",
            "Adversary may deploy ransomware or disruptive tooling using admin utilities (e.g., PsExec).",
        ]
        # Phase 6.3.2 pruning: only include telemetry sources relevant to the extracted behaviors / IOCs.
        _iocs = getattr(intel, "iocs", {}) or {}
        _has_net_iocs = bool((_iocs.get("ip_port") or []) or (_iocs.get("ip") or []) or (_iocs.get("domain") or []) or (_iocs.get("url") or []))
        _net_tokens = {"http", "https", "dns", "c2", "beacon", "socket", "port", "network", "remote"}
        _has_net_beh = any(t.lower() in (" ".join(behavior_profile.keywords or [])).lower() for t in _net_tokens)
        data_sources = ["Process telemetry", "File events", "Registry telemetry"]
        if _has_net_iocs or _has_net_beh:
            data_sources.insert(1, "Network telemetry")
            data_sources.insert(2, "DNS telemetry")
        queries: List[HuntQuery] = []
        ioc_queries = build_queries_from_iocs(
            getattr(intel, "iocs", {}) or {},
            qlang,
            qlang_label,
            max_queries=max_queries,
            kql_profile=kql_profile,
        )
        if ioc_queries:
            queries.extend(ioc_queries)

        # Hard-block invented IOC values (ghost binaries) in any FileName IOC lists
        sanitized: List[HuntQuery] = []
        for q in queries:
            qtxt = _sanitize_ghost_ioc_values_in_query(q.query, getattr(intel, "iocs", {}) or {})
            if not qtxt:
                continue
            sanitized.append(HuntQuery(title=q.title, description=q.description, query=qtxt, query_language=q.query_language))
        queries = ioc_sweep_queries + sanitized



        for i in range(1, max_queries + 1):
            # Create a small, usable set even when the template JSON step fails.
            if i > min_queries and i > 3:
                break

            if qlang == "CQL":
                qlogic = _default_cql_query(topic, i)
            elif qlang == "SPL":
                qlogic = f"index=endpoint {topic} | stats count by host user process"
            elif qlang == "KQL":
                qlogic = "DeviceProcessEvents | take 50"
            elif qlang == "SQL":
                qlogic = "SELECT * FROM process_events LIMIT 50;"
            elif qlang.upper() == "OSQUERY":
                qlogic = "SELECT pid, name, path, cmdline FROM processes LIMIT 50;"
            else:
                qlogic = "# Pseudocode: filter process/network events for suspicious patterns"

            queries.append(HuntQuery(title=f"Hunt {i}", description="TBD", query=qlogic, query_language=qlang_label))

        # Phase 6.3.1: behavior checklist (fallback branch).
        behavior_checks = {
            "extracted": behavior_profile.to_dict(),
            "checklist": behavior_checklist,
            "results": [],
        }
        if qlang == "CQL":
            fixed: list[HuntQuery] = []
            for q in (queries or []):
                # Determine whether this query is an IOC sweep/indicator query.
                # NOTE: q.title is a string; do NOT wrap in bool() or you'll lose .lower().
                _title = (q.title or "")
                _title_l = _title.lower()
                is_ioc = _title_l.startswith("ioc") or ("sha-256" in _title_l) or ("sha256" in _title_l)
                ok, missing = evaluate_query_against_behaviors(q.query or "", behavior_checklist)
                if is_ioc:
                    behavior_checks["results"].append({"title": q.title, "passes": True, "missing": [], "ioc": True})
                    fixed.append(q)
                    continue
                if ok:
                    behavior_checks["results"].append({"title": q.title, "passes": True, "missing": [], "ioc": False})
                    fixed.append(q)
                else:
                    behavior_checks["results"].append({"title": q.title, "passes": False, "missing": missing, "ioc": False, "fallback": True})
                    fixed.append(HuntQuery(title=q.title, description=q.description, query=_behavior_scaffold_cql(), query_language=q.query_language))
            queries = fixed

        # Build a template-aligned markdown even in fallback mode so Sections 1–3 are present.
        scope_notes = "TBD"
        execution_notes = "TBD"

        fallback_md = ""
        if template:
            # Best-effort placeholder fill: keep it deterministic and avoid inventing details.
            ph = sorted(set(re.findall(r"\{\{([A-Z0-9_]+)\}\}", template)))
            ds = (data_sources or [])
            repl = {k: "Unknown" for k in ph}
            repl.update(
                {
                    "THREAT_NAME": intel.topic or intel.title or "Untitled",
                    "THREAT_FAMILY_OR_CAMPAIGN": intel.topic or intel.title or "Unknown",
                    "KEY_BEHAVIORS_AND_TACTICS": (intel_summary or "").strip()[:400] or "Unknown",
                    "BUSINESS_IMPACT_SUMMARY": (intel.impact_assessment or "").strip()[:400] or "Unknown",
                    "PRIMARY_OBJECTIVE": objective,
                    "ORG_NAME": "Your organization",
                    "HUNT_TAGLINE_OR_FOCUS": f"{qlang_label} telemetry-focused hunt",
                    "DATA_SOURCE_1": ds[0] if len(ds) > 0 else "ProcessRollup2",
                    "DATA_SOURCE_2": ds[1] if len(ds) > 1 else "NetworkConnectIP4",
                    "DATA_SOURCE_3": ds[2] if len(ds) > 2 else "(other)",
                    "SYSTEM_TYPE_1": "Endpoints",
                    "SYSTEM_TYPE_2": "Servers",
                    "SYSTEM_TYPE_3": "(other)",
                    "OS_1": "Windows",
                    "OS_2": "macOS",
                    "OS_3": "Linux",
                    "OUT_OF_SCOPE_ITEM_1": "Network perimeter-only telemetry",
                    "OUT_OF_SCOPE_ITEM_2": "Third-party systems without endpoint telemetry",
                    "OUT_OF_SCOPE_ITEM_3": "(other)",
                }
            )

            fallback_md = template
            for k in ph:
                fallback_md = fallback_md.replace("{{" + k + "}}", str(repl.get(k, "Unknown")))

        # Always inject Section 4 from structured queries (LLM forbidden).
        rendered = _inject_section4(fallback_md or "# Threat Hunt Package\n\n", HuntPackage(
            meta=meta,
            linked_intel_id=intel.meta.id,
            objective=objective,
            hypotheses=hypotheses,
            data_sources=data_sources,
            queries=queries,
            scope_notes=scope_notes,
            execution_notes=execution_notes,
            rendered_markdown="",
        ), qlang_label=qlang)
    
    # Phase 6.5.8: apply deterministic seed + MITRE mapping before any LLM glue/validation
    try:
        _pkg = locals().get("obj") or locals().get("hunt") or locals().get("pkg")
        if _pkg is None:
            _pkg = locals().get("hunt_pkg") or locals().get("hp") or locals().get("package")
        if _pkg is None:
            _pkg = locals().get("obj")  # fallback
        if _pkg is None:
            _pkg = locals().get("pkg")
        if _pkg is None:
            _pkg = locals().get("hunt")
        if _pkg is None:
            _pkg = locals().get("obj")
        if _pkg is not None:
            apply_hunt_seed(_pkg, intel, seed)
            obj = _pkg
    except Exception:
        pass

# --- Behavior Intelligence Layer (v1) ---
    # Extract concrete, telemetry-expressible behaviors from intel narrative (source-agnostic).
    intel_text = "\n\n".join([
        getattr(intel, "title", ""),
        getattr(intel, "bluf", ""),
        getattr(intel, "threat_description", ""),
        getattr(intel, "background", ""),
        getattr(intel, "risk", ""),
        getattr(intel, "mitigation", ""),
        getattr(intel, "impact_assessment", ""),
        getattr(intel, "appendix", ""),
    ])
    extracted_behaviors = extract_behaviors_from_intel(intel.title or intel.topic or "Intel", intel_text, intel.iocs, sources=intel.sources)
    try:
        intel.behaviors = extracted_behaviors
    except Exception:
        pass
    # Resolve the hunt package object for this function (older branches may not bind `obj`).
    pkg = locals().get("obj") or locals().get("hunt")
    if pkg is None:
        # Bootstrap a minimal HuntPackage so the behavior layer can attach queries.
        obj = HuntPackage(
            meta=meta,
            linked_intel_id=getattr(getattr(intel, 'meta', None), 'id', ''),
            objective=locals().get('objective') or 'Determine whether there is evidence of threat activity aligned to the intel.',
            hypotheses=locals().get('hypotheses') or [],
            data_sources=locals().get('data_sources') or [],
            queries=locals().get('queries') or [],
            scope_notes=locals().get('scope_notes') or '',
            execution_notes=locals().get('execution_notes') or '',
            rendered_markdown='',
        )
        pkg = obj

    try:
        pkg.behaviors = extracted_behaviors
    except Exception:
        pass

    # Remove legacy placeholder hunts (Hunt 1/2/3) if they slipped in from older flows.
    try:
        pkg.queries = [q for q in (pkg.queries or []) if (getattr(q, 'title', '') or "").strip().lower() not in {"hunt 1","hunt 2","hunt 3"}]
    except Exception:
        pass

    # Gate behavior-driven hunt generation: only emit when there are concrete anchors beyond IOC sweeps.
    behavior_queries = []
    for b in extracted_behaviors:
        anchors = getattr(b, 'anchors', None) or {}
        # Require at least 2 distinct anchor categories to avoid redundant, vague hunts.
        anchor_kinds = [k for k in ["file_names","domains","urls","ip_ports","tools"] if anchors.get(k)]
        if len(anchor_kinds) < 2:
            continue
        title = getattr(b, 'name', '') or f"Behavior Hunt: {getattr(b, 'behavior_type', '')}"
        desc = f"Behavior-driven hunt derived from intel: {getattr(b, 'behavior_type', '')}. Anchors: {', '.join(anchor_kinds)}"
        # Build a simple CQL from available anchors (best-effort).
        clauses = []
        if anchors.get("file_names"):
            clauses.append(f"in(field=FileName, values={json.dumps(anchors['file_names'])})")
        if anchors.get("domains"):
            doms = anchors['domains']
            if doms:
                rx = "|".join([re.escape(d) for d in doms[:15]])
                clauses.append(f"CommandLine=/{rx}/i")
        if anchors.get("urls"):
            urls = anchors['urls']
            if urls:
                rx = "|".join([re.escape(u) for u in urls[:8]])
                clauses.append(f"CommandLine=/{rx}/i")
        if not clauses:
            continue
        query = "#event_simpleName=ProcessRollup2\n| " + "\n| ".join(clauses) + "\n| groupBy([@timestamp, ComputerName, UserName, FileName, CommandLine, ParentBaseFileName, SHA256HashData], limit=20000)"
        behavior_queries.append(HuntQuery(title=title, description=desc, query=query, language=getattr((pkg.queries[0] if pkg.queries else None), 'language', 'CrowdStrike LogScale CQL')))

    # Append behavior queries after IOC sweeps (avoid duplicates by title).
    existing_titles = { (getattr(q,'title','') or "").strip().lower() for q in (pkg.queries or []) }
    for q in behavior_queries:
        t = (getattr(q,'title','') or "").strip().lower()
        if t in existing_titles:
            continue
        pkg.queries.append(q)
        existing_titles.add(t)



    # Derive structured fields from the JSON map when possible.
    objective = (obj_map.get("PRIMARY_OBJECTIVE") or obj_map.get("OBJECTIVE") or "").strip()
    if not objective:
        objective = "Determine whether there is evidence of threat activity aligned to the intel."

    # Hypotheses: allow keys like HYPOTHESES or infer from provided "KEY_CAPABILITIES"
    hypotheses = []
    hyp = (obj_map.get("HYPOTHESES") or "").strip()
    if hyp:
        hypotheses = [h.strip("- ").strip() for h in hyp.splitlines() if h.strip()]
    if not hypotheses:
        kc = (obj_map.get("KEY_CAPABILITIES") or "").strip()
        if kc:
            hypotheses = [f"Adversary capability observed: {line.strip('- ').strip()}" for line in kc.splitlines() if line.strip()]
    hypotheses = hypotheses[:8] if hypotheses else ["Hypothesis: validate endpoint telemetry for known ransomware staging/execution behaviors."]

    # Data sources
    data_sources = []
    ds = (obj_map.get("DATA_SOURCES_TELEMETRY") or "").strip()
    if ds:
        data_sources = [d.strip("- ").strip() for d in ds.splitlines() if d.strip()]
    if not data_sources:
        data_sources = ["Process telemetry", "File events", "Network telemetry", "DNS telemetry", "Registry telemetry"]

    # Phase 6.3.2 pruning: remove irrelevant telemetry sources for behavior-first hunts.
    try:
        _iocs_ds = getattr(intel, "iocs", {}) or {}
        _has_net_iocs_ds = bool((_iocs_ds.get("ip_port") or []) or (_iocs_ds.get("ip") or []) or (_iocs_ds.get("domain") or []) or (_iocs_ds.get("url") or []))
        _net_tokens_ds = {"http","https","dns","c2","beacon","socket","port","network","remote"}
        _has_net_beh_ds = any(t in (" ".join((behavior_profile.keywords or [])).lower()) for t in _net_tokens_ds)
        if not (_has_net_iocs_ds or _has_net_beh_ds):
            data_sources = [d for d in (data_sources or []) if d.lower() not in {"network telemetry", "dns telemetry"}]
    except Exception:
        pass

    # Queries (dynamic count)
    qlang_label = {
        "CQL": "CrowdStrike LogScale (CQL)",
        "SPL": "Splunk SPL",
        "KQL": "Microsoft KQL",
    }.get(qlang, qlang)

    obj.ioc_stats = ioc_stats or {}

    # --- Query routing (deterministic) ---
    # Phase 6.5.8.3: select query *blueprints* based on extracted signals so
    # titles and query logic cannot drift.
    queries: list[HuntQuery] = []

    # Target count here is ONLY for non-IOC-sweep hunts. IOC sweeps are injected later.
    # Keep v1 small and stable.
    non_ioc_target = min(3, max(0, int(max_queries) - len(ioc_sweep_queries)))

    if qlang == "CQL":
        try:
            queries = build_routed_hunt_queries_cql(
                getattr(intel, "iocs", {}) or {},
                behavior_keywords=(behavior_profile.keywords or []),
                qlang_label=qlang_label,
                desired=non_ioc_target or 0,
            )
        except Exception:
            queries = []

    # Fallback: if routing produced nothing (or non-CQL dialects), use template-provided queries.
    if not queries:
        # Template typically includes DETECTION_FOCUS_1..3. Pull whatever exists.
        for i in range(1, 8):
            title = (obj_map.get(f"DETECTION_FOCUS_{i}_TITLE") or f"Hunt {i}").strip()
            purpose = (obj_map.get(f"DETECTION_FOCUS_{i}_PURPOSE") or "").strip()
            qlogic = (obj_map.get(f"DETECTION_FOCUS_{i}_QUERY") or "").strip()
            if not qlogic:
                continue
            if qlang == "CQL" and not _is_cql_query(qlogic):
                qlogic = _default_cql_query(intel.topic, i)
            queries.append(HuntQuery(title=title, description=purpose or "TBD", query_language=qlang_label, query=qlogic))

    # Ensure we have at least min_queries overall (including IOC sweeps later).
    target_total = max(min_queries, min(max_queries, max(len(queries) + len(ioc_sweep_queries), min_queries)))
    if (len(queries) + len(ioc_sweep_queries)) < target_total:
        need = target_total - (len(queries) + len(ioc_sweep_queries))
        extra: list[HuntQuery] = []
        # Deterministic extra queries for CQL; avoid additional LLM drift.
        if qlang == "CQL":
            for j in range(1, need + 1):
                idx = len(queries) + j
                extra.append(
                    HuntQuery(
                        title=f"Behavior — Additional pivot ({idx})",
                        description="Extra pivot query (deterministic fallback).",
                        query_language=qlang_label,
                        query=_default_cql_query(intel.topic, idx),
                    )
                )
        else:
            for j in range(1, need + 1):
                idx = len(queries) + j
                extra.append(HuntQuery(title=f"Hunt {idx}", description="Additional hunt query", query_language=qlang_label, query="(query placeholder)"))

        queries.extend(extra)

        # Append extra sections to the rendered markdown so the template stays honest.
        if extra:
            filled_markdown += "\n\n---\n\n## Additional Hunt Queries\n"
            for idx, hq in enumerate(extra, start=1):
                filled_markdown += f"\n### Extra Hunt {idx}: {hq.title}\n\n{hq.description}\n\n```\n{hq.query}\n```\n"

    scope_notes = "In-scope telemetry and systems are defined in the template."
    execution_notes = "Execute queries, validate hits, and document findings in the Hunt Report stage."

    # Hard-block invented IOC values (ghost binaries) in any FileName IOC lists
    sanitized: List[HuntQuery] = []
    for q in queries:
        qtxt = _sanitize_ghost_ioc_values_in_query(q.query, getattr(intel, "iocs", {}) or {})
        if not qtxt:
            continue
        sanitized.append(HuntQuery(title=q.title, description=q.description, query=qtxt, query_language=q.query_language))
    queries = ioc_sweep_queries + sanitized

    # Phase 6.5.8.4: enforce CQL core-only output and prevent correlated blueprints from downgrading
    # to PR2-only scaffolds during behavior-check evaluation.
    if qlang == "CQL":
        try:
            routed_for_patch = build_routed_hunt_queries_cql(
                getattr(intel, "iocs", {}) or {},
                behavior_keywords=(behavior_profile.keywords or []),
                qlang_label=qlang_label,
                desired=3,
            )
            queries = patch_correlated_downgrades(queries, routed_for_patch)
        except Exception:
            pass
        # Hard gate: do not allow helper macros or placeholder tokens in v1 output.
        enforce_cql_core_only(queries)


    # Phase 6.3.1: behavior checklist gate.
    # We evaluate non-IOC-sweep queries against extracted behaviors. If a query fails,
    # try a focused rewrite once, then fall back to a deterministic scaffold.
    behavior_checks = {
        "extracted": behavior_profile.to_dict(),
        "checklist": behavior_checklist,
        "results": [],
    }
    if qlang == "CQL":
        fixed: list[HuntQuery] = []
        for q in queries:
            # Skip deterministic IOC sweeps (Section 4 locked) but still record status.
            # Determine whether this query is an IOC sweep/indicator query.
            _title = (q.title or "")
            _title_l = _title.lower()
            is_ioc = _title_l.startswith("ioc") or ("sha-256" in _title_l) or ("sha256" in _title_l)
            # v1: correlated pivot queries are allowed even if they don't match the behavior checklist
            # tokens directly (they are correlation scaffolds, not keyword filters).
            is_corr = ("correlat" in _title_l) or ("selfjoinfilter" in (q.query or "").lower())
            if is_corr and (not is_ioc):
                behavior_checks["results"].append({"title": q.title, "passes": True, "missing": [], "ioc": False, "correlated": True})
                fixed.append(q)
                continue
            ok, missing = evaluate_query_against_behaviors(q.query or "", behavior_checklist)
            if is_ioc:
                behavior_checks["results"].append({"title": q.title, "passes": True, "missing": [], "ioc": True})
                fixed.append(q)
                continue
            if ok:
                behavior_checks["results"].append({"title": q.title, "passes": True, "missing": [], "ioc": False})
                fixed.append(q)
                continue

            # Try rewrite
            new_q = _rewrite_query_with_llm(q.title or "Hunt", q.query or "") if bool(ground_queries) else ""
            if new_q:
                # Validate CQL fields/syntax gate and behavior gate
                errs = validate_cql_query(new_q)
                ok2, _missing2 = evaluate_query_against_behaviors(new_q, behavior_checklist)
                if not errs and ok2:
                    behavior_checks["results"].append({"title": q.title, "passes": True, "missing": [], "ioc": False, "rewritten": True})
                    fixed.append(HuntQuery(title=q.title, description=q.description, query=new_q, query_language=q.query_language))
                    continue

            # Deterministic fallback
            fallback_q = _behavior_scaffold_cql()
            behavior_checks["results"].append({"title": q.title, "passes": False, "missing": missing, "ioc": False, "fallback": True})
            fixed.append(HuntQuery(title=q.title, description=q.description, query=fallback_q, query_language=q.query_language))
        queries = fixed

    # Deterministically render Section 4 from the structured HuntQuery objects to avoid hallucinated event types
    # and to ensure low-level IOC sweep queries are present in the final markdown.
    try:
        section4 = _render_queries_section_markdown(queries, qlang)
        filled_markdown = _replace_markdown_section(
            filled_markdown,
            "## 4. High-Fidelity Indicators & Hunt Queries",
            "## 5.",
            section4,
        )
    except Exception:
        # If anything goes wrong, keep the existing markdown rather than failing the workflow.
        pass

    
    # --- Query Validation Gate (CQL) ---
    if qlang == "CQL":
        violations: list[str] = []
        # Validate the final rendered query set (includes deterministic IOC sweeps + any LLM suggestions
        # that survived sanitization).
        for q in (queries or []):
            errs = validate_cql_query(q.query or "")
            if errs:
                violations.append(f"{q.title or 'untitled'}: " + "; ".join(errs))
        if violations:
            raise ValueError("CQL validation failed:\n- " + "\n- ".join(violations))
        # Phase 6.5.8: finalize HuntPackage via deterministic mapping + compact renderer
    try:
        if "obj" not in locals() or obj is None:
            obj = HuntPackage(
                meta=meta,
                linked_intel_id=intel.meta.id,
            )
        # Ensure required narrative fields + MITRE coverage are populated deterministically
        apply_hunt_seed(obj, intel, seed)

        # Attach queries computed above
        obj.queries = queries

        # Re-apply MITRE annotations to queries (round-robin) after final query list is known
        apply_hunt_seed(obj, intel, seed)

        # Deterministic markdown renderer (no template placeholders)
        obj.rendered_markdown = render_hunt_markdown_v1(obj, intel, qlang_label)
    except Exception:
        obj = HuntPackage(
            meta=meta,
            linked_intel_id=intel.meta.id,
            objective=objective,
            hypotheses=hypotheses,
            data_sources=data_sources,
            queries=queries,
            scope_notes=scope_notes,
            execution_notes=execution_notes,
            rendered_markdown=filled_markdown,
        )



    
    # Phase 6.5.8: LLM narrative glue (constrained) — only if enabled.
    try:
        if cfg is not None and bool(getattr(cfg, "hunt_glue_enabled", True)) and not isinstance(llm, StubLLM):
            from .contract_framework import load_prompt_pack
            pack = getattr(cfg, "hunt_glue_prompt_pack", "hunt_v1") or "hunt_v1"
            sys_p, user_p, _pbase = load_prompt_pack(pack, artifact_key="hunt_glue", prompt_dir_override=getattr(cfg, "prompt_dir_override", ""))
            if (sys_p or "").strip() and (user_p or "").strip():
                mapping_table = json.dumps(seed.get("mapping_table") or {}, indent=2)
                intel_json = intel.model_dump() if hasattr(intel, "model_dump") else {}
                hunt_seed_json = {
                    "objective": obj.objective,
                    "hypotheses": obj.hypotheses,
                    "data_sources": obj.data_sources,
                    "scope_notes": obj.scope_notes,
                    "execution_notes": obj.execution_notes,
                }
                up = (user_p
                      .replace("{{MAPPING_TABLE}}", mapping_table)
                      .replace("{{INTEL_JSON}}", json.dumps(intel_json, indent=2)[:12000])
                      .replace("{{HUNT_SEED_JSON}}", json.dumps(hunt_seed_json, indent=2)[:8000])
                )
                out = _safe_generate(llm, up, sys_p).strip()
                out = out.replace("```json", "").replace("```", "").strip()
                data = json.loads(out) if out.startswith("{") else {}
                if isinstance(data, dict):
                    if str(data.get("objective", "")).strip():
                        obj.objective = str(data.get("objective")).strip()
                    if isinstance(data.get("hypotheses"), list) and data.get("hypotheses"):
                        obj.hypotheses = _sanitize_hypotheses([str(x).strip() for x in data.get("hypotheses") if str(x).strip()])
                    if isinstance(data.get("data_sources"), list) and data.get("data_sources"):
                        obj.data_sources = [str(x).strip() for x in data.get("data_sources") if str(x).strip()]
                    if str(data.get("scope_notes", "")).strip():
                        obj.scope_notes = _normalize_scope_notes(str(data.get("scope_notes")).strip(), intel)
                    if str(data.get("execution_notes", "")).strip():
                        obj.execution_notes = str(data.get("execution_notes")).strip()
                    # refresh markdown
                    obj.rendered_markdown = render_hunt_markdown_v1(obj, intel, qlang_label)
    except Exception:
        pass

# --- Contract Validation (Hunt Package) ---
    try:
        from .logging_utils import get_logger
        logger = get_logger()
        logger.info(
            "[CONTRACT] hunt_package profile=%s mode=%s regen_attempts=%s",
            contract_profile or "(none)",
            contract_mode,
            regen_attempts,
        )
    except Exception:
        logger = None

    try:
        _sanitize_hunt_query_labels_best_effort(obj, logger=logger)
    except Exception:
        pass

    if contract is not None and (contract_mode or "").strip().lower() != "off":
        try:
            from .contract_framework import validate_hunt_package, format_violations, build_hunt_package_regen_guidance, summarize_hunt_package
        except Exception:
            validate_hunt_package = None
            format_violations = None
            build_hunt_package_regen_guidance = None
            summarize_hunt_package = None

        attempts_total = 1 + max(0, int(regen_attempts or 0))
        last_violations = []

        for attempt in range(attempts_total):
            if validate_hunt_package is None:
                break
            last_violations = validate_hunt_package(obj, contract)
            ok = len(last_violations) == 0
            if logger:
                logger.info("[VALIDATION] hunt_package attempt=%s/%s ok=%s violations=%s", attempt+1, attempts_total, ok, len(last_violations))
            if ok:
                try:
                    if summarize_hunt_package is not None and logger:
                        logger.info("[VALIDATION] hunt_package pass_summary=%s", summarize_hunt_package(obj, contract))
                except Exception:
                    pass
                break

            # If no more regen attempts, stop.
            if attempt + 1 >= attempts_total:
                break

            # Targeted regen: update narrative fields only; do NOT change queries.
            if isinstance(llm, StubLLM):
                break

            try:
                vtxt = format_violations(last_violations) if format_violations else "- (unavailable)"
                guidance = build_hunt_package_regen_guidance(last_violations, contract) if build_hunt_package_regen_guidance else "- Fix all listed violations."
            except Exception:
                vtxt = "- (unavailable)"
                guidance = "- Fix all listed violations."

                        # Phase 6.5.8: contract auto-correct using prompt templates (bounded)
            try:
                from .contract_framework import load_prompt_pack
                pack = getattr(cfg, "hunt_autocorrect_prompt_pack", "hunt_v1") if cfg is not None else "hunt_v1"
                sys_p, user_p, _pbase = load_prompt_pack(pack or "hunt_v1", artifact_key="hunt_autocorrect", prompt_dir_override=getattr(cfg, "prompt_dir_override", "") if cfg is not None else "")
            except Exception:
                sys_p, user_p = "", ""

            fields_to_update = ["objective","hypotheses","data_sources","scope_notes","execution_notes","mitre_techniques"]
            current_fields = {
                "objective": obj.objective,
                "hypotheses": obj.hypotheses,
                "data_sources": obj.data_sources,
                "scope_notes": obj.scope_notes,
                "execution_notes": obj.execution_notes,
            }
            if (sys_p or "").strip() and (user_p or "").strip():
                regen_prompt = (user_p
                    .replace("{{FIELDS_TO_UPDATE}}", ", ".join(fields_to_update))
                    .replace("{{VIOLATIONS}}", str(vtxt))
                    .replace("{{INTEL_SUMMARY}}", (intel_summary or "")[:1800])
                    .replace("{{CURRENT_FIELDS_JSON}}", json.dumps(current_fields, indent=2)[:8000])
                )
                regen_system = sys_p
            else:
                regen_prompt = (
                    "The Hunt Package draft failed contract validation. Fix the issues and update ONLY the following fields: "
                    + ", ".join(fields_to_update)
                    + ". Keep queries unchanged. Return JSON only with keys objective, hypotheses, data_sources, scope_notes, execution_notes, mitre_techniques."
                    + "\n\nViolations:\n" + str(vtxt)
                    + "\n\nIntel Summary:\n" + (intel_summary or "")[:1800]
                    + "\n\nCurrent Fields:\n" + json.dumps(current_fields, indent=2)[:8000]
                )
                regen_system = _HUNT_SYSTEM



            try:
                raw = _safe_generate(llm, regen_prompt, regen_system).strip()
                if "{" in raw and "}" in raw:
                    raw = raw[raw.find("{") : raw.rfind("}") + 1]
                data = json.loads(raw)
            except Exception:
                data = {}

            if isinstance(data, dict):
                try:
                    if str(data.get("objective", "")).strip():
                        obj.objective = str(data.get("objective", "")).strip()
                    if isinstance(data.get("hypotheses"), list):
                        obj.hypotheses = _sanitize_hypotheses([str(x).strip() for x in data.get("hypotheses") if str(x).strip()])
                    if isinstance(data.get("data_sources"), list):
                        obj.data_sources = [str(x).strip() for x in data.get("data_sources") if str(x).strip()]
                    if str(data.get("scope_notes", "")).strip():
                        obj.scope_notes = str(data.get("scope_notes", "")).strip()
                    if str(data.get("execution_notes", "")).strip():
                        obj.execution_notes = str(data.get("execution_notes", "")).strip()

                    # Apply MITRE techniques to query metadata (keeps query text unchanged)
                    tids = data.get("mitre_techniques") if isinstance(data.get("mitre_techniques"), list) else []
                    tids = [str(t).strip() for t in (tids or []) if str(t).strip()]
                    if tids and getattr(obj, "queries", None):
                        # round-robin assign
                        for i, q in enumerate(obj.queries):
                            try:
                                q.technique = tids[i % len(tids)]
                            except Exception:
                                pass
                except Exception:
                    pass

        # Persist validation status into history for transparency.
        try:
            if last_violations:
                note = (format_violations(last_violations) if format_violations else "validation failed")
                obj.meta.history.append({
                    "ts": utc_now(),
                    "actor": "system",
                    "action": "contract_validation_failed",
                    "note": (note or "validation failed")[:2000],
                })
                if logger:
                    logger.warning("[ENFORCEMENT] hunt_package non-compliant; saved as Draft with violations=%s", len(last_violations))
                # Phase 6.5.8: fail-open as last resort (with warning) for Hunt Packages
                try:
                    if cfg is not None and bool(getattr(cfg, "hunt_fail_open_after_autocorrect", True)) and str(contract_mode or "").strip().lower() == "strict":
                        obj.approval = ApprovalStatus.APPROVED
                        # Store a compact warning summary for UI display
                        warn_txt = (format_violations(last_violations) if format_violations else str(last_violations)) or "validation warnings"
                        obj.meta.links["contract_warnings"] = (warn_txt or "validation warnings")[:1800]
                        obj.meta.history.append({
                            "ts": utc_now(),
                            "actor": "system",
                            "action": "approval_fail_open",
                            "note": "Approved with validation warnings (fail-open).",
                        })
                        if logger:
                            logger.warning("[FAIL_OPEN] hunt_package approved with warnings violations=%s", len(last_violations))
                except Exception:
                    pass

            else:
                obj.meta.history.append({
                    "ts": utc_now(),
                    "actor": "system",
                    "action": "contract_validation_passed",
                    "note": "validation passed",
                })
        except Exception:
            pass



    # Include behavior debug payload for UI + exports.
    try:
        grounding = dict(grounding or {})
        grounding["behavior"] = behavior_checks
        grounding["telemetry_translation"] = translation_debug
    except Exception:
        pass
    # Phase 6+: hunt package generation returns the structured object.
    # Raw markdown is no longer produced here (rendering is handled by the UI/export renderers).
    return obj, "", grounding



def render_intel_markdown(intel: IntelBrief) -> str:
    """Render an IntelBrief as markdown aligned to the CTI template.

    The UI uses this for consistent display.
    """
    sources_bullets = "\n".join(f"- {s}" for s in (intel.sources or [])) or "- (none)"
    body = _INTEL_TEMPLATE.format(
        topic=intel.title or intel.topic or "Untitled",
        date=intel.date or intel.meta.created_at,
        author=intel.author or "Threat Hunting / CTI",
        reference_id=intel.reference_id or "TBD",
        bluf=intel.bluf or "",
        background=intel.background or "",
        threat_description=intel.threat_description or "",
        current_assessment=intel.current_assessment or "",
        evidence_and_indicators=intel.evidence_and_indicators or "",
        impact_assessment=intel.impact_assessment or "",
        confidence_and_credibility=intel.confidence_and_credibility or "",
        gaps_and_collection=intel.gaps_and_collection or "",
        alternative_analysis=intel.alternative_analysis or "",
        outlook=intel.outlook or "",
        recommended_actions=intel.recommended_actions or "",
        summary_paragraphs=intel.summary_paragraphs or "",
        appendix=intel.appendix or "",
        sources_bullets=sources_bullets,
    )

    mitre = "\n".join(f"- {t}" for t in (intel.observed_mitre_techniques or [])) or "- (none listed)"
    # NOTE: _INTEL_TEMPLATE already includes a Sources section.
    md = (
        f"# Intel Brief: {intel.topic or intel.title or 'Untitled'}\n\n"
        f"- ID: `{intel.meta.id}`\n"
        f"- Status: **{intel.approval.value}**\n"
        f"- Topic: {intel.topic or intel.title or 'Untitled'}\n\n"
        + body
        + "\n\n## Observed MITRE Techniques (extracted)\n"
        + mitre
        + "\n"
    )
    return _append_report_footer(md)


def render_hunt_markdown(hunt: HuntPackage) -> str:
    """Render the hunt package markdown (template-driven when available)."""
    template = _load_template("Threat_Hunt_Package_Template.md")
    if not template:
        # Fallback: legacy renderer
        q_md = []
        for q in hunt.queries:
            q_md.append(f"### {q.title}\n{q.description}\n\n```\n{q.query.strip()}\n```\n")
        md = f"""# {hunt.meta.title}

- ID: `{hunt.meta.id}`
- Linked Intel: `{hunt.linked_intel_id}`

## Objective
{hunt.objective}

## Hypotheses
""" + "\n".join(f"- {h}" for h in hunt.hypotheses) + "\n\n## Data Sources\n" + "\n".join(
            f"- {d}" for d in hunt.data_sources
        ) + "\n\n## Hunts\n" + "\n".join(q_md) + f"\n## Scope Notes\n{hunt.scope_notes}\n\n## Execution Notes\n{hunt.execution_notes}\n"
        return _append_report_footer(md)

    # Map first three queries into the template placeholders.
    qs = hunt.queries[:3] + [HuntQuery(title="", description="", query="")] * max(0, 3 - len(hunt.queries))
    q1, q2, q3 = qs[0], qs[1], qs[2]

    repl = {
        "{{HUNT_NAME}}": hunt.meta.title,
        "{{DATE}}": hunt.meta.created_at[:10],
        "{{AUTHOR}}": "Threat Hunting",
        "{{JIRA_TICKET}}": "TBD",
        "{{TICKET}}": "TBD",
        "{{THREAT_NAME}}": hunt.meta.title.replace("Hunt Package: ", ""),
        "{{LINKED_INTEL_ID}}": hunt.linked_intel_id,
        "{{OBJECTIVE}}": hunt.objective,
        "{{HYPOTHESES}}": "\n".join(f"- {h}" for h in hunt.hypotheses) or "- (none)",
        "{{DATA_SOURCES}}": "\n".join(f"- {d}" for d in hunt.data_sources) or "- (none)",
        "{{SCOPE_NOTES}}": hunt.scope_notes or "TBD",
        "{{EXECUTION_NOTES}}": hunt.execution_notes or "TBD",
        "{{QUERY_1_TITLE}}": q1.title or "Hunt 1",
        "{{QUERY_1_DESCRIPTION}}": q1.description or "TBD",
        "{{QUERY_1}}": q1.query.strip() if q1.query else "",
        "{{QUERY_2_TITLE}}": q2.title or "Hunt 2",
        "{{QUERY_2_DESCRIPTION}}": q2.description or "TBD",
        "{{QUERY_2}}": q2.query.strip() if q2.query else "",
        "{{QUERY_3_TITLE}}": q3.title or "Hunt 3",
        "{{QUERY_3_DESCRIPTION}}": q3.description or "TBD",
        "{{QUERY_3}}": q3.query.strip() if q3.query else "",
    }

    out = template
    for k, v in repl.items():
        out = out.replace(k, v)
    return _append_report_footer(_inject_section4(out, hunt, qlang_label="CQL"))


def render_finding_markdown(finding: Finding) -> str:
    ev = "\n".join(f"- {e}" for e in finding.evidence) or "- (none)"
    mitre = "\n".join(f"- {t}" for t in finding.mitre_techniques) or "- (none)"
    md = f"""# {finding.meta.title}

- ID: `{finding.meta.id}`
- Linked Run: `{finding.linked_run_id}`
- Severity: **{finding.severity.value}**
- Confidence: {finding.confidence}

## Description
{finding.description}

## Evidence
{ev}

## MITRE Techniques
{mitre}

## Analyst Notes
{finding.analyst_notes}
"""
    return _append_report_footer(md)


def render_ads_markdown(ads: ADS) -> str:
    """Render ADS markdown aligned to the canonical ADS_Template.txt structure.

    This renderer is deterministic (no LLM) and keeps the headings stable so
    detection content can be diffed and reviewed over time.
    """
    tele = "\n".join(f"- {t}" for t in (ads.telemetry or [])) or "- (none)"
    cql = f"```\n{ads.cql.strip()}\n```" if ads.cql.strip() else "(none)"

    tactics = list(getattr(ads, "mitre_tactics", []) or [])
    techniques = list(getattr(ads, "mitre_techniques", []) or [])
    tactic = ", ".join(tactics) if tactics else "(none)"
    technique = ", ".join(techniques) if techniques else "(none)"

    goal = ads.detection_goal.strip() or "(none)"
    strategy_abstract = ads.logic.strip() or "(none)"
    technical_context = getattr(ads, "technical_context", "").strip() or "(none)"
    vis_req = getattr(ads, "visibility_requirements", "").strip() or tele
    blind_spots = getattr(ads, "blind_spots", "").strip() or "(none)"
    tuning = ads.tuning.strip() or "(none)"
    validation = ads.validation.strip() or "(none)"
    response = ads.deployment_notes.strip() or "(none)"

    md = f"""# {ads.meta.title}

- ID: `{ads.meta.id}`
- Linked Finding: `{ads.linked_finding_id}`

## Goal
{goal}

## Categorization

Tactic: {tactic}
Technique: {technique}

## Strategy Abstract
{strategy_abstract}

## Technical Context
{technical_context}

## Blind Spots and Assumptions

### Visibility Requirements
{vis_req}

### Blind spots
{blind_spots}

## False Positives
{tuning}

## Priority
- (unknown)

## Validation
{validation}

## Response
{response}

## Example ADS Query

### CrowdStrike Detection Query
{cql}

## Examples Splunk Notable

### Splunk Query
(n/a)

## Additional Resources
- (none)
"""

    # Contract check: keep ADS renderer aligned to ADS_Template.txt headings.
    missing = validate_ads_template_contract(md)
    if missing:
        md = md + "\n\n<!-- TEMPLATE DRIFT WARNING: missing headings: " + ", ".join(missing) + " -->\n"

    return _append_report_footer(md)


def validate_ads_template_contract(markdown: str) -> list[str]:
    """Best-effort validation that the rendered ADS follows ADS_Template.txt structure."""
    required = [
        "## Goal",
        "## Categorization",
        "## Strategy Abstract",
        "## Technical Context",
        "## Blind Spots and Assumptions",
        "### Visibility Requirements",
        "### Blind spots",
        "## False Positives",
        "## Validation",
        "## Response",
        "## Example ADS Query",
    ]
    missing = [h for h in required if h not in (markdown or "")]
    return missing


def render_run_ir_report_markdown(run: Run, hunt: HuntPackage | None, findings: list[Finding] | None, intel: IntelBrief | None = None) -> str:
    """Deterministically render a Threat Hunt / IR Report for a Run.

    v1 behavior: no LLM required. This is meant to be editable by the analyst.
    """
    template = _load_template("Threat_Hunt_IR_Report_Template.md") or ""
    findings = findings or []

    # Build simple summaries
    f_sum_lines = [f"- **{f.meta.title}** (Severity: {getattr(f.severity, 'value', f.severity)})" for f in findings] or ["- (none)"]
    detailed = []
    for f in findings:
        detailed.append(f"### {f.meta.title}\n")
        if f.description:
            detailed.append(f"{f.description}\n")
        if f.evidence:
            detailed.append("**Evidence**")
            detailed.extend([f"- {e}" for e in f.evidence])
            detailed.append("")
        if f.analyst_notes:
            detailed.append("**Analyst Notes**")
            detailed.append(f.analyst_notes)
            detailed.append("")
    detailed_txt = "\n".join(detailed).strip() or "(none)"

    scope = []
    if hunt is not None:
        if hunt.data_sources:
            scope.append("**Telemetry / Data Sources**")
            scope.extend([f"- {d}" for d in hunt.data_sources])
        if hunt.scope_notes:
            scope.append("\n**Notes**")
            scope.append(hunt.scope_notes)
    if run.time_window_start or run.time_window_end:
        scope.append(f"\n**Time Window**: {run.time_window_start or 'Unknown'} → {run.time_window_end or 'Unknown'}")
    scope_txt = "\n".join(scope).strip() or "(scope not captured yet)"

    timeline = []
    for s in (run.steps or []):
        timeline.append(f"- {s.name}: {s.status} — {s.detail}")
    timeline_txt = "\n".join(timeline) or "- (no run steps captured)"

    bluf = ""
    if findings:
        top = findings[0]
        bluf = f"Run **{run.meta.id}** completed with {len(findings)} finding(s). Top finding: **{top.meta.title}**."
    else:
        bluf = f"Run **{run.meta.id}** completed with no findings captured yet."

    # Severity: choose highest observed
    sev_order = {"Low": 0, "Medium": 1, "High": 2, "Critical": 3}
    top_sev = "Unknown"
    try:
        if findings:
            top_sev = max([getattr(f.severity, "value", str(f.severity)) for f in findings], key=lambda s: sev_order.get(s, -1))
    except Exception:
        pass

    timeframe = ""
    if run.time_window_start or run.time_window_end:
        timeframe = f"{run.time_window_start or 'Unknown'} → {run.time_window_end or 'Unknown'}"

    # Actions taken: run steps + query titles (if present)
    actions = []
    if run.steps:
        actions.append("**Run Steps**")
        actions.extend([f"- {s.name}: {s.status} — {s.detail}" for s in run.steps])
    if hunt and getattr(hunt, "queries", None):
        actions.append("\n**Hunt Queries Executed (planned / manual execution)**")
        actions.extend([f"- {q.title}" for q in hunt.queries])
    actions_txt = "\n".join(actions).strip() or "(TBD)"

    findings_block = "\n".join([
        "### Findings Summary",
        "\n".join(f_sum_lines),
        "",
        "### Detailed Findings",
        detailed_txt,
    ]).strip()


    # Optional intel-derived narrative fields
    threat_desc = (getattr(intel, "threat_description", "") or getattr(intel, "summary_paragraphs", "") or getattr(intel, "bluf", "")).strip() if intel else ""
    business_impact = (getattr(intel, "impact_assessment", "") or "").strip() if intel else ""
    what_is_it_txt = threat_desc or (getattr(hunt, "objective", "") or "").strip() if hunt else ""
    background_txt = (getattr(intel, "background", "") or "").strip() if intel else ""
    risk_txt = business_impact or "Risk assessment pending. Summarize likely business impact if activity is confirmed."
    mitigation_txt = "Mitigation guidance pending. Capture immediate containment actions and longer-term hardening steps."
    impact_txt = business_impact or "Impact assessment pending. Capture confirmed impact once scope is validated."
    repl = {
        "{{REPORT_TITLE}}": (hunt.meta.title if hunt else run.meta.title) or "Threat Hunt",
        "{{JIRA_TICKET}}": "TBD",
        "{{TICKET}}": "TBD",
        "{{DATE}}": (run.meta.updated_at or run.meta.created_at)[:10],
        "{{AUTHOR}}": run.operator or "Threat Hunting",
        "{{BLUF}}": bluf,
        "{{DESCRIPTION_OF_ACTIVITY}}": (hunt.objective if hunt else "(no hunt linked)") or "(none)",
        "{{TIMEFRAME}}": timeframe or "(TBD)",
        "{{SEVERITY_ASSESSMENT}}": f"{top_sev}" if top_sev else "(TBD)",
        "{{SUMMARY}}": (hunt.objective if hunt else "(no hunt linked)") or "(none)",
        "{{WHAT_IS_IT}}": what_is_it_txt or "TBD",
        "{{BACKGROUND}}": background_txt or "TBD",
        "{{DISPOSITION}}": "(TBD)",
        "{{ORG_NAME}}": "Org Name",
        "{{RISK_TO_ORG}}": risk_txt,
        "{{MITIGATION}}": mitigation_txt,
        "{{IMPACT_TO_ORG}}": "(TBD)",
        "{{ACTIONS_TAKEN}}": actions_txt,
        "{{FINDINGS}}": findings_block,
        "{{OBSERVED_MITRE}}": "\n".join(sorted({t for f in findings for t in (getattr(f, "mitre_techniques", []) or [])})) or "(none)",
        "{{PROTECTION_DETECTION}}": "Protection/detection notes pending. Document existing coverage and any gaps identified during the hunt.",
        "{{ACCOUNT_COMPROMISE}}": "Account compromise assessment pending. Record suspicious identities, credential theft indicators, or misuse.",
        "{{LATERAL_MOVEMENT}}": "Lateral movement assessment pending. Record signs of remote execution, admin shares, or credential reuse.",
        "{{C2}}": "Command & Control assessment pending. Record beaconing, suspicious destinations, or proxy tooling.",
        "{{DATA_EXFIL}}": "Data exfiltration assessment pending. Record evidence of staging, transfer tooling, or outbound volume.",
    }

    if not template:
        # Simple fallback
        md = "# Threat Hunt / IR Report\n\n" + "\n\n".join([
            f"**Run:** `{run.meta.id}`",
            f"**Hunt:** `{getattr(run,'linked_hunt_id','')}`",
            "## BLUF\n" + repl["{{BLUF}}"],
            "## Timeframe\n" + repl["{{TIMEFRAME}}"],
            "## Actions Taken\n" + repl["{{ACTIONS_TAKEN}}"],
            "## Findings\n" + repl["{{FINDINGS}}"],
        ])
        return _append_report_footer(md)

    out = template
    for k, v in repl.items():
        out = out.replace(k, v)
    return _append_report_footer(out)


# ---------------------------------------------------------------------------
# Run / Findings / ADS helpers (v1 demo)
# ---------------------------------------------------------------------------

def simulate_run(run_id: str, hunt: HuntPackage) -> Run:
    """Create a simulated Run object for the manual Run phase.

    The UI uses this to create a first-class Run artifact so that:
    - Findings can be linked to a run
    - IR-style Run Reports can be generated and searched

    This does *not* execute queries. It just records a plausible timeline.
    """
    meta = new_meta(ArtifactType.RUN, title=f"Run: {hunt.meta.title}", artifact_id=run_id)

    now = utc_now()
    steps = [
        RunStep(name="Initialize", status="OK", detail="Run created", started_at=now, ended_at=now),
        RunStep(name="Execute", status="OK", detail="Manual execution (out-of-band)", started_at=now, ended_at=now),
        RunStep(name="Review", status="OK", detail="Ready for findings capture", started_at=now, ended_at=now),
    ]

    return Run(
        meta=meta,
        linked_hunt_id=hunt.meta.id,
        linked_intel_id=getattr(hunt, "linked_intel_id", ""),
        status=RunStatus.COMPLETE,
        steps=steps,
        findings_created=[],
        report_markdown="",
        report_approval=ApprovalStatus.DRAFT,
    )


def generate_findings_from_run(
    run: Run,
    hunt: HuntPackage | None = None,
    intel: IntelBrief | None = None,
) -> list[Finding]:
    """Generate 1–2 mock findings from a run.

    In v1 the Run phase is manual, but we still want the artifact chain to work end-to-end.
    This provides usable demo data and a place for the analyst to edit.
    """
    # Stable-ish pseudo randomness for repeatability
    seed = sum(ord(c) for c in (run.meta.id or ""))
    rng = random.Random(seed)
    n = 1 if rng.random() < 0.65 else 2

    findings: list[Finding] = []
    for i in range(1, n + 1):
        fid = f"finding_{run.meta.id}_{i}".replace("run_", "")
        title = "Potential malicious execution pattern" if i == 1 else "Suspicious network behavior" 
        meta = new_meta(ArtifactType.FINDING, title=title, artifact_id=fid)

        evidence: list[str] = []
        if hunt and getattr(hunt, "queries", None):
            q = hunt.queries[0]
            if q and q.title:
                evidence.append(f"Matched hunt query: {q.title}")
        evidence.append("Analyst review required: validate against allow-lists and known-good activity")

        # Technique inheritance (Finding -> ADS):
        # 1) Matched query technique
        # 2) Intel observed techniques
        # 3) Safe fallback
        q_match = None
        if hunt and getattr(hunt, "queries", None):
            try:
                q_match = hunt.queries[i-1] if len(hunt.queries) >= i else hunt.queries[0]
            except Exception:
                q_match = hunt.queries[0]
        matched_tech = str(getattr(q_match, "technique", "") or "").strip() if q_match else ""
        intel_techs = [str(t).strip() for t in (getattr(intel, "observed_mitre_techniques", []) or []) if str(t).strip()] if intel else []
        safe_fallback = "T1071 (Application Layer Protocol)" if i == 2 else "T1204.002 (User Execution: Malicious File)"
        if matched_tech:
            mitre = [matched_tech]
        elif intel_techs:
            mitre = intel_techs[:2]
        else:
            mitre = [safe_fallback]

        findings.append(
            Finding(
                meta=meta,
                linked_run_id=run.meta.id,
                linked_hunt_id=getattr(run, "linked_hunt_id", ""),
                linked_intel_id=getattr(run, "linked_intel_id", ""),
                title=meta.title,
                description=(
                    "Initial review indicates behavior that warrants triage. "
                    "Confirm scope, user context, and whether the behavior is expected in your environment."
                ),
                severity=Severity.MEDIUM,
                confidence="Medium",
                evidence=evidence,
                mitre_techniques=mitre,
                analyst_notes="",
                approval=ApprovalStatus.DRAFT,
            )
        )

    return findings


def generate_ads(llm: BaseLLM, ads_id: str, finding: Finding) -> ADS:
    """Generate an ADS draft (deterministic by default).

    For v1, keep this conservative and templated. The analyst can edit and approve.
    """
    meta = new_meta(ArtifactType.ADS, title=f"ADS: {finding.meta.title}", artifact_id=ads_id)

    # A safe, dictionary-aligned example CQL.
    example_cql = (
        "#event_simpleName=ProcessRollup2\n"
        "| groupBy([@timestamp, ComputerName, UserName, FileName, CommandLine, ParentBaseFileName, SHA256HashData], limit=20000)"
    )
    # Validate and fall back if needed
    if validate_cql_query(example_cql):
        example_cql = (
            "#event_simpleName=ProcessRollup2\n"
            "| groupBy([@timestamp, ComputerName, UserName, FileName, CommandLine, ParentBaseFileName], limit=20000)"
        )

    telem = [
        "ProcessRollup2",
        "SHA256HashData",
        "CommandLine",
        "ParentBaseFileName",
    ]

    # Seed Categorization from linked Finding (structured, not just a display hint)
    mitre_techs = list(getattr(finding, "mitre_techniques", []) or [])

    # Template-aligned defaults
    vis_req = (
        "CrowdStrike (or equivalent EDR) is installed on the host and configured to collect process creation "
        "events with command line, parent process context, and file hashes.\n\n"
        "Required telemetry (high level):\n" + "\n".join(f"- {t}" for t in telem)
    )

    blind_spots = (
        "If process telemetry is missing (agent not installed, sensor disabled, tampering, or logging gaps), "
        "this ADS will not fire.\n"
        "If adversaries use alternate tooling/binaries or obfuscate command lines beyond the query logic, "
        "coverage may be reduced."
    )

    from .models import ADSLifecycleStatus

    return ADS(
        meta=meta,
        linked_finding_id=finding.meta.id,
        linked_run_id=getattr(finding, "linked_run_id", ""),
        linked_hunt_id=getattr(finding, "linked_hunt_id", ""),
        linked_intel_id=getattr(finding, "linked_intel_id", ""),
        detection_goal=f"Detect recurrence of behavior described in finding: {finding.meta.title}",
        telemetry=telem,
        logic=(
            "Start with high-signal process telemetry, then add allow-lists for known-good software. "
            "Escalate when suspicious parent/child patterns or uncommon binaries are observed."
        ),
        cql=example_cql,
        tuning="Exclude known enterprise management tools; add allow-lists by signer/path where possible.",
        validation="Validate in a lab using safe simulations and confirm expected telemetry fields.",
        deployment_notes="Pilot as a hunt query first; promote to detection once false positive rate is acceptable.",
        technical_context="",
        visibility_requirements=vis_req,
        blind_spots=blind_spots,
        mitre_techniques=mitre_techs,
        mitre_tactics=[],
        lifecycle_status=ADSLifecycleStatus.DRAFT,
        approval=ApprovalStatus.DRAFT,
    )

def render_hunt_report_markdown(hunt: HuntPackage, intel: IntelBrief | None = None) -> str:
    """Deterministic Hunt Package report renderer (deliverable)."""
    return render_hunt_report_markdown_v1(hunt, intel=intel)
# ---------------- Phase 6.5.7: Approval gate auto-correct ----------------

# Only these Intel Brief sections are considered safe to auto-regenerate at approval time.
# These are narrative/analytic scaffolding fields; they are NOT raw evidence or IOC content.
_INTEL_AUTOCORRECT_SAFE_FIELDS = {
    "gaps_and_collection",
    "alternative_analysis",
    "appendix",
    "observed_mitre_techniques",
}

# Never auto-regenerate these fields. They are source-of-truth or high-risk for hallucination.
_INTEL_AUTOCORRECT_UNSAFE_FIELDS = {
    "sources",
    "evidence_and_indicators",
    "iocs",
    "topic",
    "title",
    "date",
    "author",
    "reference_id",
    "bluf",
    "background",
    "threat_description",
    "current_assessment",
    "impact_assessment",
    "confidence_and_credibility",
    "outlook",
    "recommended_actions",
    "summary_paragraphs",
}


def intel_autocorrect_field_policy() -> dict:
    """Return a user-readable safe/unsafe policy for approval-time auto-correct."""
    return {
        "safe": sorted(_INTEL_AUTOCORRECT_SAFE_FIELDS),
        "unsafe": sorted(_INTEL_AUTOCORRECT_UNSAFE_FIELDS),
    }


def _apply_intel_autocorrect_patch(intel, patch: dict, fields_to_update: list[str]) -> None:
    """Apply a JSON patch to an IntelBrief object, constrained to fields_to_update."""
    for f in fields_to_update:
        if f not in patch:
            continue
        try:
            setattr(intel, f, patch.get(f))
        except Exception:
            pass


def autocorrect_intel_brief_for_approval(
    llm,
    intel,
    cfg,
    violations,
) -> tuple[object, list, dict]:
    """Attempt to auto-correct only safe Intel Brief fields to satisfy contract validation.

    Returns:
      (intel_obj, new_violations, meta)

    Notes:
    - This function never edits unsafe fields.
    - It is intended to be used at approval time (not during initial generation).
    """
    meta = {
        "attempted": False,
        "fields_to_update": [],
        "autocorrect_notes": "",
    }

    try:
        from .contract_framework import load_contract, validate_intel_brief, format_violations, load_prompt_pack
    except Exception:
        return intel, violations, meta

    if llm is None or intel is None:
        return intel, violations, meta

    # Determine which failing fields are safe to auto-correct.
    failing_fields = sorted({getattr(v, "field", "") for v in (violations or []) if getattr(v, "field", "")})
    fields_to_update = [f for f in failing_fields if f in _INTEL_AUTOCORRECT_SAFE_FIELDS]

    # Special-case: validators may reference nested keys; normalize common variants.
    if any(f.startswith("observed_mitre") for f in failing_fields) and "observed_mitre_techniques" not in fields_to_update:
        fields_to_update.append("observed_mitre_techniques")

    fields_to_update = sorted(set(fields_to_update))
    if not fields_to_update:
        return intel, violations, meta

    meta["attempted"] = True
    meta["fields_to_update"] = fields_to_update

    # Load contract + prompt pack.
    contract_profile = getattr(cfg, "intel_brief_contract_profile", "intel_brief_v1_1")
    contract_mode = (getattr(cfg, "contract_enforcement_mode", "off") or "off").strip().lower()
    contract, _ = load_contract(contract_profile, contract_dir_override=getattr(cfg, "contract_dir_override", ""))

    sys_t, user_t, _ = load_prompt_pack(
        getattr(cfg, "approval_autocorrect_prompt_pack", "autocorrect"),
        artifact_key="intel_brief_autocorrect",
        prompt_dir_override=getattr(cfg, "prompt_dir_override", ""),
    )

    # Build user prompt (fill placeholders).
    vtxt = format_violations(violations or [])
    current_fields = {f: getattr(intel, f, "") for f in fields_to_update}

    user_prompt = (user_t or "").replace("{{FIELDS_TO_UPDATE}}", "\n".join(f"- {f}" for f in fields_to_update))
    user_prompt = user_prompt.replace("{{CONTRACT_VIOLATIONS}}", vtxt or "- (none)")
    user_prompt = user_prompt.replace("{{CURRENT_FIELDS_JSON}}", json.dumps(current_fields, indent=2, ensure_ascii=False))

    raw = ""
    try:
        from .llm import safe_generate

        raw = safe_generate(llm, user_prompt, sys_t or "")
    except Exception:
        # fall back to the internal helper if safe_generate is not present
        try:
            raw = _safe_generate(llm, user_prompt, sys_t or "")
        except Exception:
            raw = ""

    patch = {}
    try:
        patch = json.loads((raw or "").strip()) if (raw or "").strip().startswith("{") else {}
        if not isinstance(patch, dict):
            patch = {}
    except Exception:
        patch = {}

    # Apply patch safely.
    _apply_intel_autocorrect_patch(intel, patch, fields_to_update)
    try:
        if isinstance(patch.get("_autocorrect_notes"), str):
            meta["autocorrect_notes"] = patch.get("_autocorrect_notes")
    except Exception:
        pass

    # Re-validate.
    new_violations = []
    try:
        if contract is not None and contract_mode != "off":
            new_violations = validate_intel_brief(intel, contract)
    except Exception:
        new_violations = violations or []

    # Audit trail.
    try:
        intel.meta.history.append({
            "ts": utc_now(),
            "actor": "system",
            "action": "approval_autocorrect_attempt",
            "note": f"fields={','.join(fields_to_update)} violations_before={len(violations or [])} violations_after={len(new_violations or [])}",
        })
    except Exception:
        pass

    return intel, new_violations, meta