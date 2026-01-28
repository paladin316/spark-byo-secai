from __future__ import annotations

import streamlit as st


def render(cfg) -> None:
    st.subheader("Web Search")
    st.caption(
        "Optional: allow the Workspace chat to fetch small public-web snippets for time-sensitive questions. "
        "Off by default (privacy-first)."
    )

    cfg.web_enabled = st.checkbox(
        "Enable web search (default off)",
        value=bool(getattr(cfg, "web_enabled", False)),
        help="When enabled, the Workspace can include web snippets as sources.",
    )

    w1, w2, w3 = st.columns([1, 1, 1])
    with w1:
        cfg.web_provider = st.selectbox(
            "Provider",
            options=["duckduckgo", "bing", "tavily", "serpapi"],
            index=["duckduckgo", "bing", "tavily", "serpapi"].index(str(getattr(cfg, "web_provider", "duckduckgo")).lower())
            if str(getattr(cfg, "web_provider", "duckduckgo")).lower() in ["duckduckgo", "bing", "tavily", "serpapi"]
            else 0,
            help="duckduckgo requires no key. bing/tavily/serpapi require an API key.",
        )
    with w2:
        cfg.web_max_results = st.number_input(
            "Max sources",
            min_value=1,
            max_value=10,
            value=int(getattr(cfg, "web_max_results", 5)),
            step=1,
        )
    with w3:
        cfg.web_timeout_s = st.number_input(
            "Web timeout (s)",
            min_value=5,
            max_value=60,
            value=int(getattr(cfg, "web_timeout_s", 15)),
            step=1,
        )

    with st.expander("API keys (only for key-based providers)", expanded=False):
        cfg.bing_api_key = st.text_input("Bing API key", value=str(getattr(cfg, "bing_api_key", "")), type="password")
        cfg.tavily_api_key = st.text_input("Tavily API key", value=str(getattr(cfg, "tavily_api_key", "")), type="password")
        cfg.serpapi_api_key = st.text_input("SerpAPI key", value=str(getattr(cfg, "serpapi_api_key", "")), type="password")
        st.caption(
            "These keys are treated as secrets and are not saved to data/config.yaml. "
            "To persist them, set env vars (BING_SEARCH_API_KEY, TAVILY_API_KEY, SERPAPI_API_KEY) "
            "or place them in the project-root api_config.yaml."
        )
