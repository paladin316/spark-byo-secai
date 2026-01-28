"""Query linter and enforcement gates.

v1 scope: enforce "CQL core-only" output:
  - no $falcon/helper macros (or any $-macro prefixes)
  - no internal placeholder tokens (#required_*, etc.)
  - correlated blueprints MUST include a join (selfJoinFilter) and multi-event header

This module is intentionally conservative: it blocks known-bad constructs without trying
to fully parse CQL.
"""

from __future__ import annotations

import re
from typing import Iterable, List, Tuple

from .models import HuntQuery


_DISALLOWED_SUBSTRINGS = [
    "$falcon/",
    "helper:",
    "#required_",
    "|#event_simpleName=",  # invalid: pipe before event header
]

# Any "$<word>/" macro prefix is excluded in v1 (e.g., $falcon/helper:enrich)
_DISALLOWED_MACRO_RE = re.compile(r"\$[a-zA-Z0-9_\-]+\/")


def lint_cql_core(query: str) -> List[str]:
    """Return a list of violations for core-only CQL."""
    q = (query or "").strip()
    v: List[str] = []
    if not q:
        v.append("empty query")
        return v

    lower = q.lower()

    for s in _DISALLOWED_SUBSTRINGS:
        if s.lower() in lower:
            v.append(f"disallowed token: {s}")

    if _DISALLOWED_MACRO_RE.search(q):
        v.append("disallowed macro prefix ($*/...)")

    return v


def _looks_correlated_title(title: str) -> bool:
    t = (title or "").lower()
    return ("correlat" in t) or ("↔" in t) or ("join" in t)


def lint_correlated_requires_join(title: str, query: str) -> List[str]:
    """If the query is *supposed* to be correlated, ensure it has correlation structure."""
    if not _looks_correlated_title(title):
        return []

    q = (query or "")
    lower = q.lower()
    v: List[str] = []

    # Must include join operator
    if "selfjoinfilter" not in lower:
        v.append("correlated query missing selfJoinFilter")

    # Must include multi-event header (simple heuristic)
    if "(#event_simplename=" not in lower and " or #event_simplename=" not in lower:
        v.append("correlated query missing multi-event header (OR)")

    return v


def enforce_cql_core_only(queries: Iterable[HuntQuery]) -> None:
    """Raise ValueError if any query violates core-only rules."""
    problems: List[Tuple[str, str]] = []

    for q in (queries or []):
        v = []
        v.extend(lint_cql_core(getattr(q, "query", "")))
        v.extend(lint_correlated_requires_join(getattr(q, "title", ""), getattr(q, "query", "")))
        if v:
            problems.append((getattr(q, "title", "Untitled"), "; ".join(v)))

    if problems:
        lines = ["CQL core-only lint failed:"]
        for title, msg in problems[:25]:
            lines.append(f"- {title}: {msg}")
        raise ValueError("\n".join(lines))


def patch_correlated_downgrades(
    queries: List[HuntQuery],
    routed_queries: List[HuntQuery],
) -> List[HuntQuery]:
    """Replace downgraded correlated queries with routed (template-based) versions.

    This prevents the mismatch where the title claims correlation but the query is PR2-only.
    """
    if not queries:
        return queries or []

    routed_by_title = {q.title.strip(): q for q in (routed_queries or []) if (q.title or "").strip()}

    patched: List[HuntQuery] = []
    for q in queries:
        title = (q.title or "").strip()
        if _looks_correlated_title(title):
            vio = lint_correlated_requires_join(title, q.query)
            if vio and title in routed_by_title:
                patched.append(routed_by_title[title])
                continue
        patched.append(q)

    return patched
