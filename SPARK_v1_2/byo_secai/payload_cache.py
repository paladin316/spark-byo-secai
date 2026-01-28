"""Per-run payload cache.

Streamlit will always rerun scripts on navigation. This cache makes reruns
cheap by storing the *computed* payloads (e.g., rendered markdown) keyed by
run_id + a stable fingerprint of the inputs.
"""

from __future__ import annotations

import hashlib
import json
from typing import Any, Dict, Optional

import streamlit as st


def _fingerprint(obj: Dict[str, Any]) -> str:
    try:
        raw = json.dumps(obj, sort_keys=True, default=str).encode("utf-8")
    except Exception:
        raw = repr(obj).encode("utf-8")
    return hashlib.sha256(raw).hexdigest()


def _cache() -> Dict[str, Any]:
    st.session_state.setdefault("payload_cache", {})
    return st.session_state["payload_cache"]


def make_key(view: str, run_id: str, inputs: Dict[str, Any]) -> str:
    return f"{view}:{run_id}:{_fingerprint(inputs)}"


def get(view: str, run_id: str, inputs: Dict[str, Any]) -> Optional[Any]:
    return _cache().get(make_key(view, run_id, inputs))


def set(view: str, run_id: str, inputs: Dict[str, Any], payload: Any) -> None:
    _cache()[make_key(view, run_id, inputs)] = payload


def clear_run(run_id: str) -> None:
    """Remove cached payloads for a run (called when a new run is executed)."""
    c = _cache()
    keys = [k for k in c.keys() if f":{run_id}:" in k]
    for k in keys:
        c.pop(k, None)
