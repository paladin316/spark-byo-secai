from __future__ import annotations

import time
from contextlib import contextmanager
from dataclasses import dataclass
from typing import Iterator, List, Dict, Any

import streamlit as st


@dataclass
class ViewTiming:
    view: str
    ms: float
    ts: float


def _timings() -> List[Dict[str, Any]]:
    st.session_state.setdefault("view_timings", [])
    return st.session_state["view_timings"]


def _steps() -> List[Dict[str, Any]]:
    st.session_state.setdefault("step_timings", [])
    return st.session_state["step_timings"]


@contextmanager
def view_timer(view_name: str) -> Iterator[None]:
    """Measure wall time for a view render and store it in session_state."""
    t0 = time.perf_counter()
    # Track current view so step timers can attach to it.
    st.session_state["_perf_current_view"] = view_name
    # Clear step timings for the current render (we keep a global log too).
    st.session_state["_perf_current_steps"] = []
    try:
        yield
    finally:
        dt = (time.perf_counter() - t0) * 1000.0
        _timings().append({"view": view_name, "ms": float(dt), "ts": time.time()})
        # Keep the list small to avoid session bloat.
        if len(st.session_state["view_timings"]) > 200:
            st.session_state["view_timings"] = st.session_state["view_timings"][-200:]


@contextmanager
def step_timer(step_name: str) -> Iterator[None]:
    """Measure a named step inside a view.

    Steps are recorded for the active view (set by view_timer).
    """
    t0 = time.perf_counter()
    try:
        yield
    finally:
        dt = (time.perf_counter() - t0) * 1000.0
        view = st.session_state.get("_perf_current_view", "?")
        row = {"view": view, "step": step_name, "ms": float(dt), "ts": time.time()}
        _steps().append(row)
        # Also keep the per-render list for the panel.
        st.session_state.setdefault("_perf_current_steps", []).append(row)
        # Keep the list small to avoid session bloat.
        if len(st.session_state["step_timings"]) > 400:
            st.session_state["step_timings"] = st.session_state["step_timings"][-400:]


def render_perf_panel(location: str = "sidebar") -> None:
    """Render a lightweight per-view performance panel."""
    timings = list(reversed(_timings()))
    last = timings[0] if timings else None

    target = st.sidebar if location == "sidebar" else st
    with target.expander("Performance (per view)", expanded=False):
        if not last:
            st.caption("No timings captured yet.")
            return

        st.metric("Last view", last.get("view", "?"), f"{last.get('ms', 0.0):.0f} ms")

        # Show last ~15 entries
        rows = []
        for e in timings[:15]:
            rows.append({"view": e.get("view"), "ms": round(float(e.get("ms", 0.0)), 1)})
        st.dataframe(rows, hide_index=True, width="stretch")

        # Step breakdown for the *current* render of the last view.
        st.markdown("**Step breakdown (last render)**")
        cur_steps = list(reversed(st.session_state.get("_perf_current_steps", []) or []))
        if cur_steps:
            srows = []
            for e in cur_steps[:20]:
                srows.append({"step": e.get("step"), "ms": round(float(e.get("ms", 0.0)), 1)})
            st.dataframe(srows, hide_index=True, width="stretch")
        else:
            st.caption("No step timings for this view yet.")

        c1, c2 = st.columns(2)
        with c1:
            if st.button("Clear", key="perf_clear"):
                st.session_state["view_timings"] = []
                st.session_state["step_timings"] = []
                st.rerun()
        with c2:
            st.caption("Counts last 200 renders")
