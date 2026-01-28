from __future__ import annotations

import uuid
import streamlit as st


def ensure_active_run() -> str:
    """Ensure an active run id exists in session_state.

    We use a stable default so view state can persist even before the
    first explicit run is executed.
    """
    if "active_run_id" not in st.session_state:
        st.session_state["active_run_id"] = "no_run"
    return str(st.session_state["active_run_id"]) or "no_run"


def get_active_run_id() -> str:
    return ensure_active_run()


def set_active_run_id(run_id: str) -> str:
    run_id = (run_id or "").strip() or "no_run"
    st.session_state["active_run_id"] = run_id
    return run_id


def start_new_run(run_id: str | None = None) -> str:
    """Start a new run context and invalidate per-run UI caches.

    If a run_id is provided (e.g., a persisted RUN artifact id), we use it.
    Otherwise we generate a UUID.
    """
    new_id = (run_id or "").strip() or str(uuid.uuid4())
    st.session_state["active_run_id"] = new_id

    # Invalidate per-run view caches/state so pages feel "sticky" until a new run.
    st.session_state["view_cache"] = {}
    st.session_state["view_state"] = {}
    # Invalidate computed payloads (rendered markdown, tables, etc.).
    st.session_state["payload_cache"] = {}
    return new_id
