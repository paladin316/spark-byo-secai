from __future__ import annotations

import streamlit as st


def render(cfg) -> None:
    st.subheader("Hunt generation defaults")

    st.caption("Performance")
    cfg.render_cache_enabled = st.checkbox(
        "Enable HTML render cache for artifact views (faster navigation)",
        value=bool(getattr(cfg, "render_cache_enabled", False)),
        help="When enabled, Intel Briefs / Hunt Packages / ADS views will reuse cached HTML snapshots keyed by artifact_id and updated_at.",
    )
    st.markdown("---")

    cfg.query_language = st.selectbox(
        "Query language",
        options=["CQL", "SPL", "KQL"],
        index=["CQL", "SPL", "KQL"].index(cfg.query_language) if cfg.query_language in ["CQL", "SPL", "KQL"] else 0,
        help="Default is CrowdStrike LogScale CQL. You can switch to SPL/KQL for other environments.",
    )

    if (cfg.query_language or "").upper().strip() == "KQL":
        cfg.kql_profile = st.selectbox(
            "KQL schema profile",
            options=["MDE", "SENTINEL", "HYBRID"],
            index=["MDE", "SENTINEL", "HYBRID"].index(getattr(cfg, "kql_profile", "MDE"))
            if getattr(cfg, "kql_profile", "MDE") in ["MDE", "SENTINEL", "HYBRID"]
            else 0,
            help=(
                "KQL tables/fields vary by platform. MDE uses Device* tables. "
                "SENTINEL uses SecurityEvent/Sysmon-style tables. HYBRID emits both variants."
            ),
        )
    colq1, colq2 = st.columns(2)
    with colq1:
        cfg.hunt_min_queries = st.number_input(
            "Min hunt queries",
            min_value=1,
            max_value=10,
            value=int(cfg.hunt_min_queries),
            step=1,
        )
    with colq2:
        cfg.hunt_max_queries = st.number_input(
            "Max hunt queries",
            min_value=1,
            max_value=15,
            value=int(cfg.hunt_max_queries),
            step=1,
        )

    if cfg.hunt_max_queries < cfg.hunt_min_queries:
        cfg.hunt_max_queries = cfg.hunt_min_queries