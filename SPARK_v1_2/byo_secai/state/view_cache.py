from __future__ import annotations

from typing import Any
import streamlit as st


def cache_get(view: str, run_id: str, key: str) -> Any | None:
    """Get cached payload for a view within a run context."""
    vc = st.session_state.get("view_cache", {})
    return vc.get(str(run_id), {}).get(str(view), {}).get(str(key))


def cache_set(view: str, run_id: str, key: str, payload: Any) -> None:
    """Set cached payload for a view within a run context."""
    vc = st.session_state.setdefault("view_cache", {})
    vc.setdefault(str(run_id), {}).setdefault(str(view), {})[str(key)] = payload


def cache_clear(run_id: str | None = None) -> None:
    """Clear cached payloads.

    If run_id is provided, clears only that run context; otherwise clears all.
    """
    if run_id is None:
        st.session_state["view_cache"] = {}
        return
    vc = st.session_state.get("view_cache", {})
    vc.pop(str(run_id), None)
    st.session_state["view_cache"] = vc
