from __future__ import annotations

from typing import Dict, List, Tuple, Any

from byo_secai.models import HuntQuery

# We reuse IOC normalization logic from the CQL builder to keep behavior consistent.
try:
    from byo_secai.query_builders.cql import normalize_iocs, _chunk  # type: ignore
except Exception:  # pragma: no cover
    normalize_iocs = None  # type: ignore
    _chunk = None  # type: ignore


def _or_conditions_ip_port(pairs: List[Tuple[str, int]], ip_field: str, port_field: str) -> str:
    """Build KQL-safe OR conditions for (ip,port) pairs."""
    conds = []
    for ip, port in pairs:
        ip_s = ip.replace('"', '\\"')
        conds.append(f'({ip_field} == "{ip_s}" and {port_field} == {int(port)})')
    if not conds:
        return "false"
    return " or ".join(conds)


def _q(v: str) -> str:
    return '"' + (v or "").replace('"', '\\\"') + '"'

def build_ioc_sweep_queries_kql(
    iocs: Dict[str, List[str]],
    qlang_label: str = "KQL",
) -> tuple[List[HuntQuery], Dict[str, int]]:
    """Build deterministic IOC sweep queries in KQL and return (queries, stats).

    Notes:
      - Uses Microsoft Defender-style tables (DeviceProcessEvents / DeviceNetworkEvents) as a sensible default.
      - Queries are still useful for KQL-based systems with minor table/field adjustments.
      - SHA256 hashes are queryable; MD5/SHA1 are counted but not queried by default.
      - IP:Port pairing is preserved using explicit OR-of-pairs to reduce false positives.
    """
    if normalize_iocs is None:
        norm = iocs or {}
        stats: Dict[str, int] = {"included": 0, "ignored": 0}
    else:
        norm, stats = normalize_iocs(iocs)

    out: List[HuntQuery] = []

    # --- SHA256 hashes (chunked) ---
    sha256 = norm.get("hash", []) or []
    if sha256:
        for idx, ch in enumerate(_chunk(sha256, 200), start=1):
            out.append(
                HuntQuery(
                    title=f"IOC — SHA256 Hashes ({idx})",
                    description="Find process executions where the SHA256 file hash matches an IOC.",
                    query_language=qlang_label,
                    query=(
                        "// Microsoft Defender for Endpoint (adjust table/fields as needed)\n"
                        "DeviceProcessEvents\n"
                        f"| where SHA256 in~ ({', '.join([_q(h) for h in ch])})\n"
                        "| project Timestamp, DeviceName, AccountName, FileName, FolderPath, ProcessCommandLine, SHA256\n"
                        "| sort by Timestamp desc\n"
                    ),
                )
            )

    # --- Domains / URLs (best-effort) ---
    domains = norm.get("domain", []) or []
    urls = norm.get("url", []) or []
    # Prefer RemoteUrl for URLs; also search command line for both.
    if domains or urls:
        vals = domains + urls
        # chunk to keep query size reasonable
        for idx, ch in enumerate(_chunk(vals, 50), start=1):
            quoted = ", ".join([_q(v) for v in ch])
            out.append(
                HuntQuery(
                    title=f"IOC — Domains/URLs ({idx})",
                    description="Find network events or process command lines referencing IOC domains/URLs (best-effort).",
                    query_language=qlang_label,
                    query=(
                        "// Network + process evidence for IOC domains/URLs (best-effort)\n"
                        "union isfuzzy=true\n"
                        "(\n"
                        "  DeviceNetworkEvents\n"
                        f"  | where RemoteUrl has_any ({quoted})\n"
                        "  | project Timestamp, DeviceName, InitiatingProcessAccountName, InitiatingProcessFileName, InitiatingProcessCommandLine, RemoteUrl, RemoteIP, RemotePort\n"
                        "),\n"
                        "(\n"
                        "  DeviceProcessEvents\n"
                        f"  | where ProcessCommandLine has_any ({quoted})\n"
                        "  | project Timestamp, DeviceName, AccountName, FileName, FolderPath, ProcessCommandLine, SHA256\n"
                        ")\n"
                        "| sort by Timestamp desc\n"
                    ),
                )
            )

    # --- IP:Port pairs (preserve pairing) ---
    ip_ports = norm.get("ip_port", []) or []
    pairs: List[Tuple[str, int]] = []
    for s in ip_ports:
        try:
            ip, port_s = s.rsplit(":", 1)
            port = int(port_s)
            pairs.append((ip, port))
        except Exception:
            continue

    if pairs:
        for idx, ch in enumerate(_chunk(pairs, 50), start=1):
            out.append(
                HuntQuery(
                    title=f"IOC — Network Connections IP:Port ({idx})",
                    description="Find network events matching IOC RemoteIP + RemotePort pairs.",
                    query_language=qlang_label,
                    query=(
                        "// Network connections matching IOC RemoteIP+RemotePort pairs (Defender schema)\n"
                        "DeviceNetworkEvents\n"
                        f"| where {_or_conditions_ip_port(ch, 'RemoteIP', 'RemotePort')}\n"
                        "| project Timestamp, DeviceName, InitiatingProcessAccountName, InitiatingProcessFileName, InitiatingProcessCommandLine, RemoteIP, RemotePort, RemoteUrl\n"
                        "| sort by Timestamp desc\n"
                    ),
                )
            )

    return out, stats
