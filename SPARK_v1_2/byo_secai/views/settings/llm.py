from __future__ import annotations

import requests
import streamlit as st

from byo_secai.llm import OllamaLLM
from byo_secai import workflow


@st.cache_data(show_spinner=False, ttl=10)
def _cached_tags(host: str):
    r = requests.get(host.rstrip("/") + "/api/tags", timeout=5)
    r.raise_for_status()
    return r.json()


@st.cache_data(show_spinner=False, ttl=5)
def _cached_probe(host: str, model: str, temperature: float, timeout_s: int):
    return OllamaLLM(host, model, temperature, timeout_s).probe()


def render(cfg) -> None:
    st.subheader("LLM + Templates")
    st.write("Configure your local Ollama endpoint used for draft generation.")

    colA, colB = st.columns([2, 2])
    with colA:
        cfg.ollama_host = st.text_input("Ollama Host", value=cfg.ollama_host)
    with colB:
        # Populate model choices from /api/tags when possible
        try:
            tags = _cached_tags(cfg.ollama_host)
            models = sorted({m.get("name") for m in tags.get("models", []) if m.get("name")})
        except Exception:
            models = []
        if models and cfg.ollama_model not in models:
            models = [cfg.ollama_model] + models
        cfg.ollama_model = st.selectbox("Ollama Model", options=models or [cfg.ollama_model], index=0)

    cfg.fetch_source_urls = st.checkbox(
        "Fetch URL sources (online) and pass extracts to the model",
        value=cfg.fetch_source_urls,
    )
    cfg.max_source_chars = st.slider(
        "Max source extract characters",
        min_value=2000,
        max_value=12000,
        value=int(min(max(int(cfg.max_source_chars), 2000), 12000)),
        step=1000,
    )
    cfg.show_llm_errors = st.checkbox("Show LLM error details when fallback occurs", value=cfg.show_llm_errors)

    st.markdown("---")
    st.subheader("Workflow templates (v1.0)")
    st.caption(
        "Advanced: point to a folder containing template files (e.g., ADS_Template.txt) to override bundled templates. "
        "Leave blank to use built-in templates."
    )
    cfg.template_dir_override = st.text_input(
        "Template folder override (path)",
        value=getattr(cfg, "template_dir_override", "") or "",
        placeholder="C:/path/to/templates",
    )
    try:
        workflow.set_template_dir_override(cfg.template_dir_override)
    except Exception:
        pass

    with st.expander("Template overview", expanded=False):
        st.markdown(
            """These templates are bundled with the Phase 5.x package and used during artifact generation.

| Stage | Primary Owner | AI Role | Template |
| --- | --- | --- | --- |
| Research intake | Human | None | (N/A) |
| Threat Intel Brief | Human | Drafting + context | Threat_Intel_Brief_Report_Template.md |
| TTP selection | **Human only** | Advisory only | (N/A) |
| Threat Hunt Package | Human | Query generation | Threat_Hunt_Package_Template.md |
| Hunt execution | **Human only** | None | Threat_Hunt_Report_Template.md |
| Findings | **Human only** | None | (N/A) |
| Hunt / IR Report | Human | Drafting assistance | Threat_Hunt_IR_Report_Template.md |
| ADS | Human / Detection Eng | Drafting assistance | ADS_Template.txt |
"""
        )

    st.markdown("---")
    st.subheader("Connection")

    cfg.ollama_temperature = st.slider("Temperature", 0.0, 1.0, float(cfg.ollama_temperature), 0.05)
    cfg.ollama_request_timeout_s = st.slider("Request timeout (seconds)", 10, 240, int(cfg.ollama_request_timeout_s), 10)

    llm_probe = _cached_probe(cfg.ollama_host, cfg.ollama_model, cfg.ollama_temperature, cfg.ollama_request_timeout_s)
    if llm_probe.get("ok"):
        st.success("LLM: Ollama reachable")
    else:
        st.warning("LLM: Ollama not confirmed (will fall back to Stub mode)")

    with st.expander("Connection details", expanded=False):
        st.write(f"Host: `{llm_probe.get('host')}`")
        st.write(f"Root reachable: `{llm_probe.get('root_ok')}`")
        st.write(f"/api/tags OK: `{llm_probe.get('tags_ok')}`")
        st.write(f"/api/generate present: `{llm_probe.get('generate_endpoint')}`")
        st.write(f"/api/chat present: `{llm_probe.get('chat_endpoint')}`")
        st.write(f"/v1/chat/completions present: `{llm_probe.get('openai_endpoint')}`")
        if llm_probe.get("error"):
            st.error(llm_probe.get("error"))

    c1, c2 = st.columns([1, 2])
    with c1:
        if st.button("Test generation"):
            test_llm = OllamaLLM(cfg.ollama_host, cfg.ollama_model, cfg.ollama_temperature, cfg.ollama_request_timeout_s)
            try:
                resp = test_llm.generate("Say 'connection ok' in 3 words.", system="You are a connectivity test.")
                st.success(f"Generated OK (mode={resp.mode}, model={resp.model})")
                st.code(resp.text)
            except Exception as e:
                st.error(f"Generation test failed: {e}")
