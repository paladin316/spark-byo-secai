"""Deterministic query router for CrowdStrike LogScale CQL.

Goal: pick *query blueprints* based on extracted signals (IOCs + behavior keywords),
then render queries from templates so titles and logic never drift.

This avoids asking an LLM to invent query structures.
"""

from __future__ import annotations

import json
from typing import Dict, List, Sequence

from ..models import HuntQuery

# Keep small + stable (v1).
_SUSP_CHILDREN = [
    "powershell.exe",
    "cmd.exe",
    "wscript.exe",
    "cscript.exe",
    "rundll32.exe",
    "mshta.exe",
    "regsvr32.exe",
    "curl.exe",
    "bitsadmin.exe",
    "python.exe",
    "node.exe",
]


def _dedupe(seq: Sequence[str]) -> List[str]:
    seen = set()
    out: List[str] = []
    for x in seq or []:
        s = str(x or "").strip()
        if not s:
            continue
        if s in seen:
            continue
        seen.add(s)
        out.append(s)
    return out


def _first(seq: Sequence[str]) -> str:
    for x in seq or []:
        s = str(x or "").strip()
        if s:
            return s
    return ""


def _json_list(values: Sequence[str]) -> str:
    """Render a LogScale-friendly JSON string array using double quotes."""
    vals: List[str] = []
    for v in values or []:
        s = str(v or "").strip()
        if not s:
            continue
        vals.append(s)
    return json.dumps(vals)


def build_routed_hunt_queries_cql(
    iocs: Dict[str, List[str]] | None,
    behavior_keywords: List[str] | None = None,
    qlang_label: str = "CrowdStrike LogScale (CQL)",
    desired: int = 3,
) -> List[HuntQuery]:
    """Return a small set of *non-IOC-sweep* hunt queries using deterministic blueprints.

    Notes:
      - IOC sweeps (hash/file/ip/ip:port) are handled elsewhere (Section 4 locked).
      - These queries focus on attribution (process <-> dns/network correlation)
        and behavior pivots (suspicious child process chains).
    """
    desired = max(0, int(desired or 0))
    if desired <= 0:
        return []

    iocs = iocs or {}
    kw = " ".join([str(k or "").lower() for k in (behavior_keywords or [])])

    ips = _dedupe(iocs.get("ip", []) or [])
    ip_ports = _dedupe(iocs.get("ip_port", []) or [])
    domains = _dedupe([str(d or "").strip().rstrip(".").lower() for d in (iocs.get("domain", []) or []) if str(d or "").strip()])
    files = _dedupe([str(f or "").strip() for f in (iocs.get("file", []) or []) if str(f or "").strip()])

    out: List[HuntQuery] = []

    # 1) ProcessRollup2 + DnsRequest correlation (optionally filter DomainName)
    if domains or ("dns" in kw) or ("domain" in kw):
        dom_filter = ""
        if domains:
            dom_filter = f"\n| in(field=DomainName, values={_json_list(domains[:200])})"

        out.append(
            HuntQuery(
                title="Behavior — Process executions correlated with DNS requests",
                description="Correlate ProcessRollup2 executions with DnsRequest events to attribute DNS lookups to a process (Falcon UPID join).",
                query_language=qlang_label,
                query=(
                    "(#event_simpleName=ProcessRollup2 OR #event_simpleName=DnsRequest) event_platform=Win\n"
                    "| case{\n"
                    "    TargetProcessId=\"*\" | falconPID:=TargetProcessId;\n"
                    "    ContextProcessId=\"*\" | falconPID:=ContextProcessId;\n"
                    "}\n"
                    "| fileName:=concat([FileName, ContextBaseFileName, ImageFileName])"
                    f"{dom_filter}\n"
                    "| selfJoinFilter([aid, falconPID], where=[{#event_simpleName=ProcessRollup2}, {#event_simpleName=DnsRequest}], prefilter=true)\n"
                    "| groupBy([aid, falconPID], function=([\n"
                    "    collect([@timestamp, ComputerName, UserName, fileName, DomainName, CommandLine]),\n"
                    "    count(#event_simpleName, distinct=true, as=eventCount)\n"
                    "]), limit=20000)\n"
                    "| eventCount > 1\n"
                    "| drop([eventCount])"
                ),
            )
        )

    # 2) ProcessRollup2 + NetworkConnectIP4 correlation (no IP filter; rely on IOC query for exact IP/IP:port)
    if (ips or ip_ports) or ("c2" in kw) or ("beacon" in kw) or ("network" in kw) or ("port" in kw):
        out.append(
            HuntQuery(
                title="Behavior — Process executions correlated with network connections",
                description="Correlate ProcessRollup2 executions with NetworkConnectIP4 to attribute outbound connections to a process (Falcon UPID join).",
                query_language=qlang_label,
                query=(
                    "(#event_simpleName=ProcessRollup2 OR #event_simpleName=NetworkConnectIP4) event_platform=Win\n"
                    "| case{\n"
                    "    TargetProcessId=\"*\" | falconPID:=TargetProcessId;\n"
                    "    ContextProcessId=\"*\" | falconPID:=ContextProcessId;\n"
                    "}\n"
                    "| fileName:=concat([FileName, ContextBaseFileName, ImageFileName])\n"
                    "| selfJoinFilter([aid, falconPID], where=[{#event_simpleName=ProcessRollup2}, {#event_simpleName=NetworkConnectIP4}], prefilter=true)\n"
                    "| groupBy([aid, falconPID], function=([\n"
                    "    collect([@timestamp, ComputerName, UserName, fileName, CommandLine, RemoteAddressIP4, RPort, LocalAddressIP4]),\n"
                    "    count(#event_simpleName, distinct=true, as=eventCount)\n"
                    "]), limit=20000)\n"
                    "| eventCount > 1\n"
                    "| drop([eventCount])"
                ),
            )
        )

    # 3) Suspicious children spawned by an IOC binary (or a common LOLBin)
    parent = _first(files)
    if not parent:
        for cand in ["powershell.exe", "cmd.exe", "rundll32.exe", "mshta.exe", "wscript.exe", "cscript.exe"]:
            if cand in kw:
                parent = cand
                break

    if parent:
        out.append(
            HuntQuery(
                title=f"Behavior — Suspicious child processes spawned by {parent}",
                description="Identify suspicious child processes spawned by a parent process pivot (common LOLBins and execution chains).",
                query_language=qlang_label,
                query=(
                    "#event_simpleName=ProcessRollup2 event_platform=Win\n"
                    f"ParentBaseFileName={parent}\n"
                    f"| in(field=FileName, values={_json_list(_SUSP_CHILDREN)})\n"
                    "| groupBy([@timestamp, ComputerName, UserName, ParentBaseFileName, ParentCommandLine, FileName, CommandLine, ImageHashSha256, SHA256HashData], limit=20000)"
                ),
            )
        )

    # Trim to desired count while preserving priority order.
    return out[:desired]
