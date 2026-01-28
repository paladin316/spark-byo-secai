"""
Query builders for IOC sweeps.

Brick-by-brick: start with CrowdStrike LogScale CQL.
"""
from __future__ import annotations

import re
from typing import Dict, List, Sequence

from ..models import HuntQuery

def _is_hex_len(s: str, n: int) -> bool:
    s = (s or "").strip()
    return bool(re.fullmatch(rf"[A-Fa-f0-9]{{{n}}}", s))

def _clean(v: str) -> str:
    return (v or "").strip()

def _dedupe(values: List) -> List:
    seen = set()
    out = []
    for x in values or []:
        if x in seen:
            continue
        seen.add(x)
        out.append(x)
    return out



def _chunk(values: Sequence[str], size: int) -> List[List[str]]:
    out: List[List[str]] = []
    cur: List[str] = []
    for v in values:
        if not v:
            continue
        cur.append(v)
        if len(cur) >= size:
            out.append(cur)
            cur = []
    if cur:
        out.append(cur)
    return out



def normalize_iocs(iocs: Dict[str, List[str]]) -> tuple[Dict[str, List[str]], Dict[str, int]]:
    """Normalize + dedupe IOC lists and compute counters.

    Counters:
      - included: queryable IOCs included in sweeps (ip_port/ip/domain/url/file/sha256)
      - context_only: iocs retained for context but not queried (md5/sha1)
      - invalid: malformed entries ignored
    """
    iocs = iocs or {}
    norm: Dict[str, List[str]] = {k: [] for k in ["ip_port", "ip", "domain", "url", "file", "hash"]}

    invalid = 0
    included = 0
    context_only = 0

    # --- hash normalization ---
    hashes_raw = [_clean(h) for h in (iocs.get("hash", []) or []) if _clean(h)]
    sha256: List[str] = []
    md5 = 0
    sha1 = 0
    other_hash = 0
    for h in hashes_raw:
        s = h.strip().lower()
        if _is_hex_len(s, 64):
            sha256.append(s)
        elif _is_hex_len(s, 32):
            md5 += 1
        elif _is_hex_len(s, 40):
            sha1 += 1
        else:
            other_hash += 1
            invalid += 1
    sha256 = _dedupe(sha256)
    norm["hash"] = sha256
    included += len(sha256)
    context_only += (md5 + sha1)

    # --- file names ---
    files = _dedupe([_clean(v) for v in (iocs.get("file", []) or []) if _clean(v)])
    norm["file"] = files
    included += len(files)

    # --- ip_port ---
    ip_ports = []
    for v in (iocs.get("ip_port", []) or []):
        s = _clean(v)
        if not s:
            continue
        # tolerate whitespace, but must be ip:port
        if ":" not in s:
            invalid += 1
            continue
        ip, port = s.rsplit(":", 1)
        ip = ip.strip()
        port = port.strip()
        if not ip or not port.isdigit():
            invalid += 1
            continue
        ip_ports.append(f"{ip}:{int(port)}")
    ip_ports = _dedupe(ip_ports)
    norm["ip_port"] = ip_ports
    included += len(ip_ports)

    # --- ip only ---
    ips_only = _dedupe([_clean(v) for v in (iocs.get("ip", []) or []) if _clean(v)])
    norm["ip"] = ips_only
    included += len(ips_only)

    # --- domain normalization (lower + strip trailing dot) ---
    domains = []
    for v in (iocs.get("domain", []) or []):
        s = _clean(v)
        if not s:
            continue
        s = s.strip().rstrip(".").lower()
        # basic guard: must contain a dot
        if "." not in s:
            invalid += 1
            continue
        domains.append(s)
    domains = _dedupe(domains)
    norm["domain"] = domains
    included += len(domains)

    # --- url normalization (strip trailing punctuation) ---
    urls = []
    for v in (iocs.get("url", []) or []):
        s = _clean(v)
        if not s:
            continue
        s = s.strip()
        # common trailing punctuation artifacts
        s = s.rstrip(".,);]")
        # normalize scheme case
        s = re.sub(r"^HTTPS?://", lambda m: m.group(0).lower(), s)
        urls.append(s)
    urls = _dedupe(urls)
    norm["url"] = urls
    included += len(urls)

    stats = {
        "included": int(included),
        "context_only": int(context_only),
        "invalid": int(invalid),
        "sha256": int(len(sha256)),
        "sha1": int(sha1),
        "md5": int(md5),
        "ip_port": int(len(ip_ports)),
        "ip": int(len(ips_only)),
        "domain": int(len(domains)),
        "url": int(len(urls)),
        "file": int(len(files)),
    }
    return norm, stats


def build_ioc_sweep_queries_cql(iocs: Dict[str, List[str]], qlang_label: str = "CrowdStrike LogScale (CQL)") -> tuple[List[HuntQuery], Dict[str, int]]:
    """Build deterministic IOC sweep queries in LogScale CQL and return (queries, stats).

    Policy:
      - SHA256 hashes are queryable (SHA256HashData)
      - MD5/SHA1 are retained for context but not used in queries
      - Domains/URLs are best-effort via CommandLine regex matches (ProcessRollup2)
      - IP:Port pairing is enforced using OR-of-pairs to reduce false positives
    """
    norm, stats = normalize_iocs(iocs)
    out: List[HuntQuery] = []

    # --- SHA256 hashes (chunked) ---
    sha256 = norm.get("hash", []) or []
    if sha256:
        for idx, ch in enumerate(_chunk(sha256, 200), start=1):
            out.append(
                HuntQuery(
                    title=f"IOC — SHA256 Hashes ({idx})",
                    description="Find executions where the SHA256 file hash matches an IOC (SHA256HashData).",
                    query_language=qlang_label,
                    query=(
                        "#event_simpleName=ProcessRollup2\n"
                        f"| in(field=SHA256HashData, values={ch})\n"
                        "| groupBy([@timestamp, ComputerName, UserName, FileName, FilePath, ImageFileName, CommandLine, ParentBaseFileName, ParentCommandLine, SHA256HashData], limit=20000)"
                    ),
                )
            )

    # --- File names (chunked) ---
    files = norm.get("file", []) or []
    if files:
        for idx, ch in enumerate(_chunk(files, 200), start=1):
            out.append(
                HuntQuery(
                    title=f"IOC — File Names ({idx})",
                    description="Find process executions where FileName matches an IOC file name.",
                    query_language=qlang_label,
                    query=(
                        "#event_simpleName=ProcessRollup2\n"
                        f"| in(field=FileName, values={ch})\n"
                        "| groupBy([@timestamp, ComputerName, UserName, FileName, FilePath, ImageFileName, CommandLine, ParentBaseFileName, ParentCommandLine, SHA256HashData], limit=20000)"
                    ),
                )
            )

    # --- IP:Port pairs (enforced) ---
    ip_ports = norm.get("ip_port", []) or []
    if ip_ports:
        # Build OR-of-pairs expression
        pair_terms = []
        for s in ip_ports:
            ip, port = s.rsplit(":", 1)
            try:
                port_i = int(port)
            except Exception:
                continue
            pair_terms.append(f'(RemoteAddressIP4="{ip}" and RPort={port_i})')
        if pair_terms:
            expr = " or ".join(pair_terms)
            out.append(
                HuntQuery(
                    title="IOC — Network Connections to IOC IP:Port",
                    description="Find network connections matching exact IOC IP:port pairs (RemoteAddressIP4 + RPort).",
                    query_language=qlang_label,
                    query=(
                        f'#event_simpleName=NetworkConnectIP4 ({expr})\n'
                        "| groupBy([@timestamp, ComputerName, UserName, ContextBaseFileName, LocalAddressIP4, RemoteAddressIP4, RPort], limit=20000)"
                    ),
                )
            )

    # --- IP only ---
    ips_only = norm.get("ip", []) or []
    if ips_only:
        out.append(
            HuntQuery(
                title="IOC — Network Connections to IOC IP",
                description="Find network connections to IOC IPs (port-agnostic).",
                query_language=qlang_label,
                query=(
                    "#event_simpleName=NetworkConnectIP4\n"
                    f"| in(field=RemoteAddressIP4, values={ips_only})\n"
                    "| groupBy([@timestamp, ComputerName, UserName, ContextBaseFileName, LocalAddressIP4, RemoteAddressIP4, RPort], limit=20000)"
                ),
            )
        )

    # --- Domains ---
    domains = norm.get("domain", []) or []
    if domains:
        # keep regex manageable by chunking
        for idx, ch in enumerate(_chunk(domains, 50), start=1):
            parts = [re.escape(d) for d in ch]
            dom_re = "|".join(parts)
            out.append(
                HuntQuery(
                    title=f"IOC — Domain Strings in CommandLine ({idx})",
                    description="Best-effort: find ProcessRollup2 CommandLine containing IOC domain strings.",
                    query_language=qlang_label,
                    query=(
                        f"#event_simpleName=ProcessRollup2 CommandLine=/{dom_re}/i\n"
                        "| groupBy([@timestamp, ComputerName, UserName, FileName, FilePath, ImageFileName, CommandLine, ParentBaseFileName, ParentCommandLine, SHA256HashData], limit=20000)"
                    ),
                )
            )

    # --- URLs ---
    urls = norm.get("url", []) or []
    if urls:
        for idx, ch in enumerate(_chunk(urls, 25), start=1):
            parts = [re.escape(u) for u in ch]
            url_re = "|".join(parts)
            out.append(
                HuntQuery(
                    title=f"IOC — URL Strings in CommandLine ({idx})",
                    description="Best-effort: find ProcessRollup2 CommandLine containing IOC URLs.",
                    query_language=qlang_label,
                    query=(
                        f"#event_simpleName=ProcessRollup2 CommandLine=/{url_re}/i\n"
                        "| groupBy([@timestamp, ComputerName, UserName, FileName, FilePath, ImageFileName, CommandLine, ParentBaseFileName, ParentCommandLine, SHA256HashData], limit=20000)"
                    ),
                )
            )

    return out, stats
