"""Lightweight app state helpers.

Phase 6.3.6 introduces the concept of an "active run" that acts as a
cache-invalidation boundary for UI state.

We keep this minimal and Streamlit-native (st.session_state).
"""

from .run import ensure_active_run, get_active_run_id, set_active_run_id, start_new_run
from .view_cache import cache_get, cache_set, cache_clear
from .view_state import state_get, state_set, state_clear

__all__ = [
    "ensure_active_run",
    "get_active_run_id",
    "set_active_run_id",
    "start_new_run",
    "cache_get",
    "cache_set",
    "cache_clear",
    "state_get",
    "state_set",
    "state_clear",
]
