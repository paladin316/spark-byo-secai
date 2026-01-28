from __future__ import annotations

import re
from dataclasses import dataclass, asdict
from typing import Dict, List, Tuple


@dataclass
class BehaviorProfile:
    """Heuristic behavior extraction for behavior-first intel.

    This is intentionally deterministic and local-only.
    It extracts concrete pivots (tools, actions, targets, artifacts) that we can
    force into query-generation prompts and validate against.
    """

    tools: List[str]
    actions: List[str]
    targets: List[str]
    artifacts: List[str]
    keywords: List[str]

    def to_dict(self) -> Dict:
        return asdict(self)


_EXE_RE = re.compile(r"\b[a-zA-Z0-9_.-]+\.(?:exe|dll)\b", re.IGNORECASE)
_PATH_RE = re.compile(r"[a-zA-Z]:\\[^\s\"']+", re.IGNORECASE)


# Common behavior tokens that tend to matter in threat-hunting prompts.
_ACTION_TOKENS = [
    "start backup",
    "backup",
    "systemstate",
    "system state",
    "create",
    "copy",
    "dump",
    "save",
    "export",
    "shadowcopy",
    "shadow copy",
    "ntds",
    "lsass",
    "minidump",
    "comsvcs",
    "rundll32",
]

_TARGET_TOKENS = [
    "ntds.dit",
    "c:\\windows\\ntds",
    "c:\\windows\\ntds\\ntds.dit",
    "sam",
    "security",
    "system",
    "lsass.exe",
    "c:\\windows\\system32\\comsvcs.dll",
]

_NUM_TOKEN_RE = re.compile(r"#\d{1,8}\b")


def extract_behaviors(text: str, max_each: int = 12) -> BehaviorProfile:
    t = (text or "")
    t_l = t.lower()

    # Tools
    tools = []
    for m in _EXE_RE.findall(t):
        v = m.strip()
        if not v:
            continue
        v_norm = v.lower()
        # Prefer .exe, but keep dlls if they look relevant
        if v_norm.endswith(".exe") or v_norm.endswith(".dll"):
            if v_norm not in [x.lower() for x in tools]:
                tools.append(v)
        if len(tools) >= max_each:
            break

    # Actions
    actions = []
    for tok in _ACTION_TOKENS:
        if tok in t_l and tok not in actions:
            actions.append(tok)
        if len(actions) >= max_each:
            break

    # Targets
    targets = []
    for tok in _TARGET_TOKENS:
        if tok in t_l and tok not in targets:
            targets.append(tok)
        if len(targets) >= max_each:
            break

    # Artifacts (paths)
    artifacts = []
    for m in _PATH_RE.findall(t):
        p = m.strip().rstrip(".,;:)")
        if p and p.lower() not in [x.lower() for x in artifacts]:
            artifacts.append(p)
        if len(artifacts) >= max_each:
            break

    # Keywords: union-ish of the above for quick prompting
    keywords = []
    for v in (tools + actions + targets):
        if v and v.lower() not in [x.lower() for x in keywords]:
            keywords.append(v)
        if len(keywords) >= (max_each * 2):
            break

    # Numeric / switch tokens used in behavior-first detections (e.g., '#24', '#65560')
    for m in _NUM_TOKEN_RE.findall(t):
        if m and m.lower() not in [x.lower() for x in keywords]:
            keywords.append(m)
        if len(keywords) >= (max_each * 2):
            break

    return BehaviorProfile(
        tools=tools,
        actions=actions,
        targets=targets,
        artifacts=artifacts,
        keywords=keywords,
    )


def build_behavior_checklist(profile: BehaviorProfile) -> Dict[str, List[str]]:
    """Return a checklist dict that must be satisfied by generated queries."""

    required_any = []
    # If we saw specific tooling, require at least one tool token.
    if profile.tools:
        required_any.extend(profile.tools[:6])

    required_context = []
    # If targets/actions exist, require at least one of them in CommandLine/regex.
    if profile.targets:
        required_context.extend(profile.targets[:6])
    if profile.actions:
        required_context.extend(profile.actions[:6])

    # Loader relationships (heuristic): if an .exe loads / invokes a .dll in command line,
    # require the query to include *both* pivots.
    relationships: List[str] = []
    exes = [t for t in (profile.tools or []) if t.lower().endswith(".exe")]
    dlls = [t for t in (profile.tools or []) if t.lower().endswith(".dll")]
    if exes and dlls:
        # Keep it small: first exe with up to 3 dlls
        exe = exes[0]
        for d in dlls[:3]:
            relationships.append(f"loader:{exe} -> module:{d}")

    return {
        "required_any": required_any,
        "required_context": required_context,
        "required_relationships": relationships,
    }


def evaluate_query_against_behaviors(query_text: str, checklist: Dict[str, List[str]]) -> Tuple[bool, List[str]]:
    """Return (passes, missing_reasons)."""
    q = (query_text or "")
    q_l = q.lower()

    missing: List[str] = []

    req_any = checklist.get("required_any") or []
    if req_any:
        if not any(tok.lower() in q_l for tok in req_any if tok):
            missing.append("Missing required tool/keyword (required_any)")

    req_ctx = checklist.get("required_context") or []
    if req_ctx:
        if not any(tok.lower() in q_l for tok in req_ctx if tok):
            missing.append("Missing required behavior tokens (required_context)")

    # Relationship gate (best-effort)
    rels = checklist.get("required_relationships") or []
    for r in rels:
        try:
            # format: loader:<exe> -> module:<dll>
            parts = r.split("->")
            loader = parts[0].split(":", 1)[1].strip() if parts else ""
            module = parts[1].split(":", 1)[1].strip() if len(parts) > 1 else ""
            if loader and loader.lower() not in q_l:
                missing.append(f"Missing loader pivot: {loader}")
            if module and module.lower() not in q_l:
                missing.append(f"Missing module pivot: {module}")
        except Exception:
            continue

    return (len(missing) == 0), missing
