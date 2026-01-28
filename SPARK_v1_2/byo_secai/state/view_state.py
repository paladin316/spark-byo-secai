from __future__ import annotations

from typing import Any
import streamlit as st


def state_get(view: str, run_id: str, key: str, default: Any = None) -> Any:
    """Get view UI state for a given run context."""
    vs = st.session_state.get("view_state", {})
    return vs.get(str(run_id), {}).get(str(view), {}).get(str(key), default)


def state_set(view: str, run_id: str, key: str, value: Any) -> None:
    """Set view UI state for a given run context."""
    vs = st.session_state.setdefault("view_state", {})
    vs.setdefault(str(run_id), {}).setdefault(str(view), {})[str(key)] = value


def state_clear(run_id: str | None = None) -> None:
    """Clear saved view state.

    If run_id is provided, clears only that run context; otherwise clears all.
    """
    if run_id is None:
        st.session_state["view_state"] = {}
        return
    vs = st.session_state.get("view_state", {})
    vs.pop(str(run_id), None)
    st.session_state["view_state"] = vs
