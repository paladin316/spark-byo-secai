"""CQL Core Blueprint Set (v1).

This module defines the small, deterministic set of CQL "primitives" BYO-SecAI supports
for v1 hunt package generation.

Design goals:
  - Avoid free-form query generation.
  - Use stable, reusable templates.
  - Keep output explainable and easy to validate.
  - Stay "core-only": no helper macros (e.g., $falcon/helper:*).

Notes:
  - These are *blueprints*, not full queries. Rendering happens in router_cql.py
    and IOC sweep builders.
  - Blueprints can be expanded in later phases (advanced builder, enrich helpers, etc.).
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import List, Optional


@dataclass(frozen=True)
class CqlBlueprint:
    """A supported query primitive for CQL generation."""

    blueprint_id: str
    name: str
    description: str
    requires_join: bool = False
    # Informational: event types typically involved (not enforced here).
    event_types: Optional[List[str]] = None


# v1: 8–10 primitives that cover the majority of practical hunts.
CORE_CQL_BLUEPRINTS: List[CqlBlueprint] = [
    CqlBlueprint(
        blueprint_id="CQL_NET_IP_PORT",
        name="NetworkConnectIP4 by RemoteAddressIP4 + RPort",
        description="Exact outbound connection matches for known IOC IP:port pairs.",
        requires_join=False,
        event_types=["NetworkConnectIP4"],
    ),
    CqlBlueprint(
        blueprint_id="CQL_NET_IP",
        name="NetworkConnectIP4 by RemoteAddressIP4",
        description="Outbound connection matches for known IOC IPs (port unknown).",
        requires_join=False,
        event_types=["NetworkConnectIP4"],
    ),
    CqlBlueprint(
        blueprint_id="CQL_PROC_FILENAME",
        name="ProcessRollup2 by FileName",
        description="Process execution matches by exact file name (e.g., rclone.exe).",
        requires_join=False,
        event_types=["ProcessRollup2"],
    ),
    CqlBlueprint(
        blueprint_id="CQL_PROC_CMDLINE_REGEX",
        name="ProcessRollup2 by CommandLine regex",
        description="Process execution matches by command-line fragments using regex().",
        requires_join=False,
        event_types=["ProcessRollup2"],
    ),
    CqlBlueprint(
        blueprint_id="CQL_PROC_PARENT_CHILD_ALLOWLIST",
        name="ProcessRollup2 by ParentBaseFileName + suspicious child allowlist",
        description="High-signal parent->child pivots (e.g., Telegram.exe spawning LOLBins).",
        requires_join=False,
        event_types=["ProcessRollup2"],
    ),
    CqlBlueprint(
        blueprint_id="CQL_HASH_SHA256",
        name="SHA256HashData hash hunt",
        description="Match process executions (or related telemetry) using SHA256HashData.",
        requires_join=False,
        event_types=["ProcessRollup2"],
    ),
    CqlBlueprint(
        blueprint_id="CQL_DNS_DOMAIN",
        name="DnsRequest by DomainName",
        description="Direct DNS request matching for known domains (when telemetry exists).",
        requires_join=False,
        event_types=["DnsRequest"],
    ),
    CqlBlueprint(
        blueprint_id="CQL_PROC_DNS_CORRELATION",
        name="ProcessRollup2 ↔ DnsRequest correlation",
        description="Attribute DNS lookups to the process context (aid + Falcon PID join).",
        requires_join=True,
        event_types=["ProcessRollup2", "DnsRequest"],
    ),
    CqlBlueprint(
        blueprint_id="CQL_PROC_NET_CORRELATION",
        name="ProcessRollup2 ↔ NetworkConnectIP4 correlation",
        description="Attribute outbound network connections to the process context (aid + Falcon PID join).",
        requires_join=True,
        event_types=["ProcessRollup2", "NetworkConnectIP4"],
    ),
]


def list_core_blueprints() -> List[CqlBlueprint]:
    """Return the supported v1 blueprint set."""
    return list(CORE_CQL_BLUEPRINTS)
