from __future__ import annotations

import json
from byo_secai.config import scrub_config_for_display
import streamlit as st


def render(cfg) -> None:
    st.subheader("Debug")

    st.markdown("### UI")
    try:
        cfg.show_breadcrumbs = st.checkbox(
            "Show artifact breadcrumbs (Intel → Hunt → Run → Finding → ADS)",
            value=bool(getattr(cfg, "show_breadcrumbs", False)),
            help="If enabled, each view shows a clickable artifact chain banner. Off by default.",
        )
    except Exception:
        pass

    col1, col2 = st.columns([1, 2])
    with col1:
        if st.button("Clear Streamlit cache"):
            try:
                st.cache_data.clear()
            except Exception:
                pass
            try:
                st.cache_resource.clear()
            except Exception:
                pass
            st.success("Cleared caches")

    with col2:
        st.caption("Cache clear forces fresh loads on next interaction.")

    with st.expander("Current config (session)", expanded=False):
        try:
            if hasattr(cfg, "model_dump"):
                data = cfg.model_dump()
            else:
                data = cfg.__dict__
            data = scrub_config_for_display(data if isinstance(data, dict) else dict(data))
            st.code(json.dumps(data, indent=2, ensure_ascii=False), language="json")
        except Exception as e:
            st.error(f"Unable to dump config: {e}")
