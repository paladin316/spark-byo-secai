from __future__ import annotations

import os
import json
from pathlib import Path
import re

import streamlit as st
from byo_secai.logging_utils import init_logging, get_logger
from byo_secai.utils.prompt_injection import scan_content, sanitize_content

import html

def spark_banner(kind: str, msg: str):
    """Render a tight SPARK-styled banner. kind = info|warn|ok|risk"""
    esc = html.escape(str(msg)).replace('\n', '<br>')
    st.markdown(f"<div class='spark-banner {kind}'>{esc}</div>", unsafe_allow_html=True)

def spark_info(msg: str):
    spark_banner('info', msg)

def spark_warn(msg: str):
    spark_banner('warn', msg)

def spark_ok(msg: str):
    spark_banner('ok', msg)

def spark_risk(msg: str):
    spark_banner('risk', msg)



# Streamlit compatibility: _rerun() was removed in newer Streamlit.
def _rerun() -> None:
    """Rerun the Streamlit script across Streamlit versions."""
    if hasattr(st, "rerun"):
        st.rerun()
        return
    if hasattr(st, "experimental_rerun"):
        st.experimental_rerun()
        return


# --- Phase 5.3 (RESET from Phase 5.2): Per-Intel query language selector (pre-generation) ---
QUERY_LANG_DISPLAY = [
    "CrowdStrike LogScale CQL",
    "SPL",
    "KQL",
    "SQL",
    "OSQuery",
    "Pseudocode",
]

QUERY_LANG_TO_WORKFLOW = {
    "CrowdStrike LogScale CQL": "CQL",
    "SPL": "SPL",
    "KQL": "KQL",
    "SQL": "SQL",
    "OSQuery": "OSQuery",
    "Pseudocode": "Pseudocode",
}

def select_query_language_for_intel(cfg, intel_id: str) -> str:
    """Returns workflow query_language (e.g., CQL/SPL/KQL/SQL/OSQuery/Pseudocode) remembered per intel."""
    # Per-intel session key
    key = f"intel_query_lang_{intel_id}"
    if key not in st.session_state:
        # default comes from Settings if present; otherwise CQL
        cfg_default = str(getattr(cfg, "query_language", "CQL") or "CQL")
        if cfg_default == "CQL" or cfg_default in ("CrowdStrike LogScale (CQL)", "CrowdStrike LogScale CQL"):
            st.session_state[key] = "CrowdStrike LogScale CQL"
        elif cfg_default in QUERY_LANG_DISPLAY:
            st.session_state[key] = cfg_default
        else:
            st.session_state[key] = "CrowdStrike LogScale CQL"

    selected_display = st.selectbox(
        "Query language (enforced for generation)",
        options=QUERY_LANG_DISPLAY,
        index=QUERY_LANG_DISPLAY.index(st.session_state[key]) if st.session_state[key] in QUERY_LANG_DISPLAY else 0,
        help="Remembered per Intel Brief and applied before generating the Hunt Package.",
        key=f"qlang_select_{intel_id}",
    )
    st.session_state[key] = selected_display
    return str(QUERY_LANG_TO_WORKFLOW.get(selected_display, "CQL"))
# --- end Phase 5.3 RESET helpers ---

import requests

from byo_secai.config import AppConfig, apply_config_overrides, load_config_yaml, get_last_loaded_config_path, get_last_loaded_api_config_path
from byo_secai.llm import OllamaLLM, StubLLM
from byo_secai.models import ApprovalStatus, ArtifactType, Severity, IntelBrief, HuntPackage
from byo_secai.storage import Storage
from byo_secai.ui import app_header, set_page, toast_if_any, render_artifact_chain_banner

from byo_secai import workflow
from byo_secai import ingest
from byo_secai.rag import RagIndex, default_rag_dir, default_rag_library_dir, collect_library_documents
from byo_secai.notebook import NotebookStore, NotebookCell, nb_to_markdown
from byo_secai.web_search import search_web
from byo_secai.ui_cache import list_ids_cached, load_artifact_json_cached
from byo_secai.payload_cache import get as payload_get, set as payload_set
from byo_secai.perf import step_timer
from byo_secai import payload_cache
import time as _time


# ---------------------------------------------------------------------------
# SPARK UI branding helpers (layout + header/footer + assistant panel)
# ---------------------------------------------------------------------------

SPARK_UI_TITLE = "SPARK"
SPARK_UI_TAGLINE = "Analyst-Driven Threat Intelligence → Hunt → Detection"
SPARK_UI_FOOTER = "AI-augmented • Analyst-validated • Powered by BYO-SECAI"


def spark_header(cfg: AppConfig) -> None:
    """Consistent SPARK header across all pages."""
    # Keep cfg.phase_label available as a subtle sub-line (optional).
    app_header(SPARK_UI_TITLE, SPARK_UI_TAGLINE)


def render_footer() -> None:
    st.markdown(
        f"""
        <div class="spark-footer">{SPARK_UI_FOOTER}</div>
        """,
        unsafe_allow_html=True,
    )


def render_main(main_fn) -> None:
    """Render a page's main content (centered/max-width via CSS)."""
    main_fn()



@st.cache_data(show_spinner=False, ttl=3600)
def cached_fetch_sources_text(
    sources: tuple[str, ...],
    max_chars: int,
    cfg_dict: dict,
) -> str:
    """Cache URL fetch + extract so navigation reruns stay fast.

    Note: Streamlit caching requires hashable inputs. We pass cfg as a dict and
    reconstruct AppConfig inside the cached function.
    """
    from byo_secai.config import AppConfig
    cfg = AppConfig.from_dict(cfg_dict or {})
    return workflow.fetch_sources_text(list(sources or ()), max_chars=int(max_chars), cfg=cfg)


@st.cache_data(show_spinner=False, ttl=10)
def cached_tags(host: str):
    """Cache /api/tags briefly to avoid repeated network calls on reruns."""
    r = requests.get(host.rstrip("/") + "/api/tags", timeout=5)
    r.raise_for_status()
    return r.json()


@st.cache_data(show_spinner=False, ttl=5)
def cached_probe(host: str, model: str, temperature: float, timeout_s: int):
    """Cache LLM probe briefly; otherwise Streamlit reruns can feel laggy."""
    return OllamaLLM(host, model, temperature, timeout_s).probe()


def get_cfg() -> AppConfig:
    if "cfg" not in st.session_state:
        base = AppConfig()
        overrides = load_config_yaml()
        st.session_state["cfg"] = apply_config_overrides(base, overrides)
        # Startup log: confirm which config files were loaded
        try:
            init_logging(st.session_state["cfg"].data_dir)
            log = get_logger()
            log.info("Config loaded: data_config=%s api_config=%s", get_last_loaded_config_path(), get_last_loaded_api_config_path())
        except Exception:
            pass

        # Backwards compatibility: if a user only sets web_enabled, treat it as
        # the default-on preference.
        try:
            cfg = st.session_state["cfg"]
            if bool(getattr(cfg, "web_enabled", False)) and not bool(getattr(cfg, "web_enabled_by_default", False)):
                cfg.web_enabled_by_default = True
        except Exception:
            pass
        # Apply template override early so workflow renderers pick it up
        try:
            workflow.set_template_dir_override(st.session_state["cfg"].template_dir_override)
        except Exception:
            pass
        # Phase 6: local RAG is wired in lazily (only when explicitly used).
        # Do NOT load or build the index during Settings/nav reruns.
    return st.session_state["cfg"]


def get_storage() -> Storage:
    cfg = get_cfg()
    init_logging(cfg.data_dir)
    log = get_logger()
    log.debug('get_storage(): data_dir=%s', cfg.data_dir)
    st.session_state.setdefault("timings", [])
    if "storage" not in st.session_state:
        st.session_state["storage"] = Storage(cfg.data_dir)
        try:
            # Build index once for fast navigation
            if not st.session_state["storage"].load_index():
                st.session_state["storage"].rebuild_index()
        except Exception:
            pass
    return st.session_state["storage"]


# ---------------------------------------------------------------------------
# Link repair helpers (Runs ↔ Findings ↔ ADS)
# ---------------------------------------------------------------------------

def _repair_run_links(store: Storage, run) -> None:
    """Backfill missing linked_* fields on a Run.

    Older artifacts may have missing link fields; repairing them makes
    breadcrumb navigation and scoped dropdowns work predictably.
    """
    changed = False
    if getattr(run, "linked_hunt_id", None) is None:
        run.linked_hunt_id = ""
        changed = True
    if getattr(run, "linked_intel_id", None) is None:
        run.linked_intel_id = ""
        changed = True

    if not getattr(run, "linked_intel_id", "") and getattr(run, "linked_hunt_id", ""):
        try:
            hunt = store.load(ArtifactType.HUNT_PACKAGE, run.linked_hunt_id)
            if hunt and getattr(hunt, "linked_intel_id", ""):
                run.linked_intel_id = getattr(hunt, "linked_intel_id", "")
                changed = True
        except Exception:
            pass

    if changed:
        try:
            run.meta.updated_at = workflow.utc_now()
            store.save(run, ArtifactType.RUN, run.meta.id)
        except Exception:
            pass


def _repair_finding_links(store: Storage, finding) -> None:
    """Backfill missing linked_* fields on a Finding."""
    changed = False
    if getattr(finding, "linked_run_id", None) is None:
        finding.linked_run_id = ""
        changed = True
    if getattr(finding, "linked_hunt_id", None) is None:
        finding.linked_hunt_id = ""
        changed = True
    if getattr(finding, "linked_intel_id", None) is None:
        finding.linked_intel_id = ""
        changed = True

    # Prefer deriving from the linked Run first.
    if (not getattr(finding, "linked_hunt_id", "") or not getattr(finding, "linked_intel_id", "")) and getattr(finding, "linked_run_id", ""):
        try:
            run = store.load(ArtifactType.RUN, finding.linked_run_id)
            if run:
                if not finding.linked_hunt_id and getattr(run, "linked_hunt_id", ""):
                    finding.linked_hunt_id = getattr(run, "linked_hunt_id", "")
                    changed = True
                if not finding.linked_intel_id and getattr(run, "linked_intel_id", ""):
                    finding.linked_intel_id = getattr(run, "linked_intel_id", "")
                    changed = True
        except Exception:
            pass

    # If still missing intel, derive from hunt.
    if not getattr(finding, "linked_intel_id", "") and getattr(finding, "linked_hunt_id", ""):
        try:
            hunt = store.load(ArtifactType.HUNT_PACKAGE, finding.linked_hunt_id)
            if hunt and getattr(hunt, "linked_intel_id", ""):
                finding.linked_intel_id = getattr(hunt, "linked_intel_id", "")
                changed = True
        except Exception:
            pass

    if changed:
        try:
            finding.meta.updated_at = workflow.utc_now()
            store.save(finding, ArtifactType.FINDING, finding.meta.id)
        except Exception:
            pass


def _repair_ads_links(store: Storage, ads) -> None:
    """Backfill missing linked_* fields on an ADS."""
    changed = False
    if getattr(ads, "linked_finding_id", None) is None:
        ads.linked_finding_id = ""
        changed = True
    if getattr(ads, "linked_run_id", None) is None:
        ads.linked_run_id = ""
        changed = True
    if getattr(ads, "linked_hunt_id", None) is None:
        ads.linked_hunt_id = ""
        changed = True
    if getattr(ads, "linked_intel_id", None) is None:
        ads.linked_intel_id = ""
        changed = True

    # Derive from linked Finding.
    if (not ads.linked_run_id or not ads.linked_hunt_id or not ads.linked_intel_id) and ads.linked_finding_id:
        try:
            f = store.load(ArtifactType.FINDING, ads.linked_finding_id)
            if f:
                if not ads.linked_run_id and getattr(f, "linked_run_id", ""):
                    ads.linked_run_id = getattr(f, "linked_run_id", "")
                    changed = True
                if not ads.linked_hunt_id and getattr(f, "linked_hunt_id", ""):
                    ads.linked_hunt_id = getattr(f, "linked_hunt_id", "")
                    changed = True
                if not ads.linked_intel_id and getattr(f, "linked_intel_id", ""):
                    ads.linked_intel_id = getattr(f, "linked_intel_id", "")
                    changed = True
        except Exception:
            pass

    if changed:
        try:
            ads.meta.updated_at = workflow.utc_now()
            store.save(ads, ArtifactType.ADS, ads.meta.id)
        except Exception:
            pass


def _artifact_to_rag_text(obj) -> str:
    """Best-effort stringify for RAG indexing.

    We keep it simple: dump the model to JSON and remove noisy whitespace.
    """
    try:
        if hasattr(obj, "model_dump"):
            data = obj.model_dump()
        elif isinstance(obj, dict):
            data = obj
        else:
            data = str(obj)
        return json.dumps(data, ensure_ascii=False)
    except Exception:
        try:
            return str(obj)
        except Exception:
            return ""


def get_rag() -> RagIndex | None:
    """Load (or build) the local RAG index and wire it into the workflow layer."""
    cfg = get_cfg()
    store = get_storage()

    # If disabled, do not load/build anything.
    if not bool(getattr(cfg, "rag_enabled", True)):
        try:
            workflow.set_rag(None, enabled=False, top_k=int(getattr(cfg, "rag_top_k", 6)))
        except Exception:
            pass
        return None

    # Cache in session_state so reruns don't reload large pickle files repeatedly.
    if "rag" in st.session_state:
        return st.session_state["rag"]

    rag_dir = default_rag_dir(cfg.data_dir)
    rag = RagIndex(rag_dir)

    # Load only. Rebuild is manual from Settings.
    rag.load()

    st.session_state["rag"] = rag
    # Wire into workflow (even if empty; workflow handles it)
    try:
        workflow.set_rag(rag, enabled=True, top_k=int(getattr(cfg, "rag_top_k", 6)))
    except Exception:
        pass
    return rag


# --- Performance helpers (Phase 5.4.8) ---
@st.cache_data(show_spinner=False)
def _load_index_cached(data_dir: str):
    """Load the global artifact index for fast navigation/search."""
    p = Path(data_dir) / "_index.json"
    if not p.exists():
        return []
    try:
        return json.loads(p.read_text(encoding="utf-8")) or []
    except Exception:
        return []

@st.cache_data(show_spinner=False)
def _list_ids_cached(data_dir: str, artifact_type_value: str):
    rows = _load_index_cached(data_dir)
    ids = [r.get("id") for r in rows if isinstance(r, dict) and r.get("type") == artifact_type_value and isinstance(r.get("id"), str)]
    # fall back to empty; caller may fall back to store.list_ids
    return sorted(list(set(ids)))

def _invalidate_caches():
    try:
        st.cache_data.clear()
    except Exception:
        pass



@st.cache_resource(show_spinner=False)
def _cached_ollama_llm(host: str, model: str, temperature: float, timeout_s: int):
    """Create (and cache) the LLM client object.

    IMPORTANT: this must be non-blocking for navigation. No health checks here.
    """
    return OllamaLLM(host, model, temperature, timeout_s)


def _ollama_fast_ok(host: str) -> bool:
    """Fast-fail probe used only when the user triggers generation.

    Keep this very small so a missing/local LLM does not make the UI feel slow.
    """
    import requests

    h = (host or "").rstrip("/")
    if not h:
        return False
    try:
        r = requests.get(f"{h}/api/tags", timeout=0.5)
        return r.status_code == 200
    except Exception:
        return False


def get_llm():
    """Return a cached LLM object WITHOUT probing health.

    This is safe to call on view render.
    """
    from byo_secai.perf import step_timer

    with step_timer("llm:get_llm"):
        cfg = get_cfg()
        host = getattr(cfg, "ollama_host", "") or ""
        model = getattr(cfg, "ollama_model", "llama3.1")
        temp = float(getattr(cfg, "ollama_temperature", 0.2))
        timeout_s = int(getattr(cfg, "ollama_request_timeout_s", 60))
        if not host:
            return StubLLM(model="stub")
        return _cached_ollama_llm(host, model, temp, timeout_s)


def get_llm_for_generate():
    """Return an LLM suitable for generation.

    Performs a fast-fail probe. If Ollama is unavailable, returns StubLLM.
    """
    from byo_secai.perf import step_timer

    cfg = get_cfg()
    host = getattr(cfg, "ollama_host", "") or ""

    # Cache probe result briefly to avoid repeated checks during a single run.
    now = _time.time()
    probe = st.session_state.get("ollama_probe", {}) if isinstance(st.session_state.get("ollama_probe"), dict) else {}
    if probe.get("host") == host and (now - float(probe.get("ts", 0))) < 5:
        ok = bool(probe.get("ok"))
    else:
        with step_timer("llm:fast_probe"):
            ok = _ollama_fast_ok(host)
        st.session_state["ollama_probe"] = {"host": host, "ok": ok, "ts": now}

    if not ok:
        return StubLLM(model="stub")
    return get_llm()


def ensure_nav_default():
    # IMPORTANT: set defaults before creating widgets with these keys.
    # Also handle deferred navigation requests (can't modify widget keys after instantiation).
    if "_nav_target" in st.session_state:
        st.session_state["nav"] = st.session_state["_nav_target"]
        del st.session_state["_nav_target"]

    if "nav" not in st.session_state:
        st.session_state["nav"] = "Dashboard"

    # Phase 6.3.6: establish an "active run" boundary for view caching.
    try:
        from byo_secai.state.run import ensure_active_run
        ensure_active_run()
    except Exception:
        pass


def render_sidebar():
    st.sidebar.markdown("### SPARK")
    st.sidebar.caption("powered by BYO-SecAI")

    choice = st.sidebar.radio(
        "Navigate",
        ["Dashboard", "Intel Briefs", "Hunt Packages", "Runs", "Findings", "ADS", "Workspace", "Artifacts", "Settings"],
        key="nav",
    )

    # Quick actions (moved from per-view dashboard buttons to save space)
    with st.sidebar.expander("Quick Actions", expanded=False):
        if st.button("➕ New Intel Brief", type="secondary", key="qa_new_intel", use_container_width=True):
            st.session_state["_reset_intel_inputs"] = True
            st.session_state["_reset_intel_view"] = True
            st.session_state["_nav_target"] = "Intel Briefs"
            st.rerun()
        if st.button("📦 View Artifacts", type="secondary", key="qa_view_artifacts", use_container_width=True):
            st.session_state["_nav_target"] = "Artifacts"
            st.rerun()

    st.sidebar.markdown("---")
    st.sidebar.caption("Local-first demo. Artifacts are stored under ./data/")

    # Config visibility: show which config.yaml we loaded and whether keys are present.
    from byo_secai.config import get_last_loaded_config_path
    cfg_dict = load_config_yaml() or {}
    cfg_path = get_last_loaded_config_path()
    with st.sidebar.expander("Config status", expanded=False):
        st.caption(f"Loaded config: {cfg_path or 'None'}")
        if isinstance(cfg_dict, dict):
            # Do NOT print keys; just show presence.
            vt_ok = bool(cfg_dict.get('virustotal_api_key')) or bool(os.environ.get('VT_API_KEY') or os.environ.get('VIRUSTOTAL_API_KEY'))
            ab_ok = bool(cfg_dict.get('abuseipdb_api_key')) or bool(os.environ.get('ABUSEIPDB_API_KEY') or os.environ.get('ABUSE_IPDB_API_KEY'))
            us_ok = bool(cfg_dict.get('urlscan_api_key')) or bool(os.environ.get('URLSCAN_API_KEY'))
            st.write(f"VirusTotal key present: {vt_ok}")
            st.write(f"AbuseIPDB key present: {ab_ok}")
            st.write(f"urlscan key present: {us_ok}")
            plugins = cfg_dict.get('plugins') if isinstance(cfg_dict.get('plugins'), dict) else {}
            if plugins:
                st.write("Plugins enabled:")
                st.json(plugins)
        else:
            st.caption("config.yaml parsed to a non-dict; check YAML formatting.")
    with st.sidebar.expander('Debug log', expanded=False):
        log_path = Path(get_cfg().data_dir) / 'byo_secai_debug.log'
        if log_path.exists():
            try:
                tail = log_path.read_text(encoding='utf-8', errors='ignore').splitlines()[-200:]
                st.code('\n'.join(tail), language='text')
            except Exception as e:
                st.warning(f'Unable to read log: {e}')
        else:
            st.caption('No log file yet. Generate an artifact to create it.')
    return choice


def render_dashboard():
    store = get_storage()
    cfg = get_cfg()

    intel = store.list_ids(ArtifactType.INTEL_BRIEF)
    hunts = store.list_ids(ArtifactType.HUNT_PACKAGE)
    runs = store.list_ids(ArtifactType.RUN)
    findings = store.list_ids(ArtifactType.FINDING)
    ads = store.list_ids(ArtifactType.ADS)

    c1, c2, c3, c4, c5 = st.columns(5)
    c1.metric("Intel", len(intel))
    c2.metric("Hunts", len(hunts))
    c3.metric("Runs", len(runs))
    c4.metric("Findings", len(findings))
    c5.metric("ADS", len(ads))

    # Tight, contract-styled divider + single-line lifecycle hint (no extra rows / tips).
    st.markdown('<div class="spark-divider"></div>', unsafe_allow_html=True)
    st.markdown(
        '<div style="color: var(--spark-muted); font-size: 0.95rem;">'
        'Create an Intel Brief → approve it → generate a Hunt Package → run it → review Findings → generate ADS → export artifacts.'
        '</div>',
        unsafe_allow_html=True,
    )


def render_intel():
    log = get_logger()
    log.debug('render_intel(): entered')
    store = get_storage()
    cfg = get_cfg()

    # ---- Intel input reset (must run BEFORE widgets are created) ----
    # Streamlit disallows mutating session_state keys tied to widgets after the
    # widget is instantiated. We set a flag on successful generation and clear
    # the widget-bound keys on the next rerun *before* creating the widgets.
    if st.session_state.get("_reset_intel_inputs", False):
        for k in ["intel_topic", "intel_sources", "intel_pasted"]:
            if k in st.session_state:
                st.session_state[k] = ""
        # Force a fresh uploader widget instance (clears previous uploads)
        st.session_state["intel_upload_key"] = int(st.session_state.get("intel_upload_key", 0)) + 1
        st.session_state["_reset_intel_inputs"] = False

    # ---- Intel view reset (hide previously rendered report) ----
    # When the user clicks "New Intel Brief" we want the right-hand view to
    # stop rendering the previously selected intel and return to a clean slate.
    # We do this by selecting a placeholder option *before* the selectbox is created.
    if st.session_state.get("_reset_intel_view", False):
        st.session_state["intel_selected"] = "(New Intel Brief)"
        # Clear any cached rendered outputs that might be persisted in session_state
        for k in ["rendered_intel_md", "rendered_intel_html", "intel_last_rendered_id"]:
            if k in st.session_state:
                del st.session_state[k]
        st.session_state["_reset_intel_view"] = False

    st.subheader("Intel Briefs")

    # Quick action to start a fresh draft and clear the right-hand report view.
    # (We use a flag and rerun to avoid mutating widget-bound keys after creation.)
    if st.button("➕ New Intel Brief (reset view)", type="secondary", width="stretch", key="intel_new_reset"):
        st.session_state["_reset_intel_inputs"] = True
        st.session_state["_reset_intel_view"] = True
        st.rerun()

    # Stable widget keys so we can safely reset/auto-select between runs.
    if "intel_upload_key" not in st.session_state:
        st.session_state["intel_upload_key"] = 0

    with st.expander("Create a new Intel Brief", expanded=True):
        topic = st.text_input(
            "Topic",
            placeholder="e.g., STORM-0501 expanding into hybrid cloud",
            key="intel_topic",
        )
        sources_txt = st.text_area(
            "Sources (one per line)",
            height=120,
            placeholder="Paste URLs (one per line) or notes here",
            key="intel_sources",
        )
        sources = [s.strip() for s in sources_txt.splitlines() if s.strip()]

    # Phase 5.4: Additional Intel Inputs (files + pasted text)
    st.subheader("Additional Intel Inputs")
    uploaded_files = st.file_uploader(
        "Upload supporting files (PDF, DOCX, XLSX/XLSM, CSV, TXT, MD, LOG, DOC, XLS)",
        type=["pdf","docx","xlsx","xlsm","csv","txt","md","log","doc","xls"],
        accept_multiple_files=True,
        key=f"intel_upload_{st.session_state['intel_upload_key']}",
    )
    pasted_text = st.text_area(
        "Paste raw intel text (optional)",
        height=120,
        placeholder="Paste notes, snippets, or extracted text here...",
        key="intel_pasted",
    )

    # Phase 5.4 UX: keep the submit button near file upload/paste area
    enrich_default = bool(load_config_yaml().get("enrich_iocs_default", False))
    enrich_iocs = st.checkbox(
        "Enrich extracted IOCs (optional: VT / AbuseIPDB / urlscan)",
        value=enrich_default,
        help="Runs local plugin enrichments on extracted IOCs. Requires API keys in byo_secai/config.yaml.",
    )
    gen_here = st.button("Generate Intel Brief draft", type="primary", key="intel_generate_here")
    
    extra_sources_parts = []
    extra_warnings = []
    if uploaded_files:
        for f in uploaded_files:
            data = f.getvalue()
            extracted, warns = ingest.extract_text_from_upload(f.name, data)
            if extracted.strip():
                extra_sources_parts.append(f"# File: {f.name}\n{extracted}")
            for w in warns:
                extra_warnings.append(f"{f.name}: {w}")

    if pasted_text and pasted_text.strip():
        extra_sources_parts.append(f"# Pasted Text\n{pasted_text.strip()}")

    if extra_warnings:
        with st.expander("Ingest warnings", expanded=False):
            for w in extra_warnings:
                st.warning(w)

    # FIXED: Indentation for the generation block
    gen_top = False  # removed duplicate button
    if gen_here:
        log.info('Intel generation triggered')
        llm = get_llm_for_generate()
        iid = store.new_id("intel")
        source_text = None
        url_errors: list[str] = []
        if cfg.fetch_source_urls and sources:
            try:
                # IMPORTANT: pass cfg so proxy/TLS settings are honored by fetch_url_text()
                source_text, url_errors = workflow.fetch_sources_text(
                    list(sources),
                    max_chars=int(cfg.max_source_chars),
                    timeout_s=12,
                    cfg=cfg,
                    return_errors=True,
                )
            except Exception as _e:
                source_text, url_errors = None, [f"URL fetch failed: {_e}"]
        
        prog = st.progress(0)
        preview = st.empty()
        buf: list[str] = []

        def _on_token(chunk: str):
            buf.append(chunk)
            # preview.code("".join(buf), language="markdown")
            pct = min(0.95, len("".join(buf)) / 8000)
            prog.progress(int(pct * 100))

        t0 = _time.perf_counter()
        if 'extra_sources_parts' in locals() and extra_sources_parts:
            merged = "\n\n".join(extra_sources_parts)
            source_text = ((source_text or "") + "\n\n" + merged).strip()

        # --- v1.2.1: Prompt Injection Scan (inputs + fetched sources) ---
        _scan_enabled = True
        try:
            _scan_enabled = bool(load_config_yaml().get("prompt_injection_scan_enabled", True))
        except Exception:
            _scan_enabled = True

        if _scan_enabled and (source_text or '').strip():
            _src_name = "Intel Inputs (URLs / uploads / pasted text)"
            _scan = scan_content(
                source_text,
                source={"type": "intel_inputs", "name": _src_name},
            )
            _fp = _scan.get("fingerprint", "unknown")
            _decision_key = f"pi_decision_{_fp}"

            # Render banner + gating controls (analyst-first, not alarmist)
            if (_scan.get("score", 0) or 0) >= int((_scan.get("thresholds") or {}).get("low", 1)):
                _risk = str(_scan.get("risk_level") or "LOW").upper()
                _score = int(_scan.get("score") or 0)
                _thr = _scan.get("thresholds") or {}
                if _risk == "HIGH":
                    spark_risk("Input check: high-risk instruction smuggling")
                    st.caption(
                        "This source includes patterns commonly used to manipulate AI behavior or request sensitive data. "
                        "SPARK will not process it automatically unless you explicitly choose how to proceed."
                    )
                elif _risk == "MEDIUM":
                    spark_warn("Input check: possible prompt injection")
                    st.caption(
                        "This source contains instruction-style text that can steer AI output. "
                        "Recommended: sanitize the source before generating artifacts."
                    )
                else:
                    spark_info("Input check: minor instruction-like text")
                    st.caption(
                        "SPARK noticed a few patterns that can steer AI output. You can continue normally, or sanitize the source before processing."
                    )

                with st.expander("What SPARK found", expanded=False):
                    st.write(
                        "These are heuristic matches. They don't prove malicious intent — they mark content that often causes drift "
                        "or unsafe behavior in AI-assisted workflows."
                    )
                    st.write(f"**Risk:** `{_risk}`  |  **Score:** `{_score}`  |  **Thresholds:** low={_thr.get('low')} / medium={_thr.get('medium')} / high={_thr.get('high')}")
                    for _m in (_scan.get("matches") or []):
                        rid = _m.get("rule_id", "")
                        title = _m.get("title", "")
                        cnt = _m.get("count", 0)
                        st.write(f"- **{rid}** — {title} (hits: {cnt})")
                        for sn in (_m.get("snippets") or [])[:3]:
                            st.code(sn, language="text")

                _decision = st.session_state.get(_decision_key)

                # If we have a medium/high signal and no decision yet, stop here and ask the analyst to choose.
                if (_risk in ["MEDIUM", "HIGH"]) and not _decision:
                    col1, col2, col3 = st.columns([1.3, 1.3, 1.0])
                    with col1:
                        if st.button("Sanitize & continue", type="primary", key=f"pi_sanitize_{_fp}"):
                            st.session_state[_decision_key] = "sanitize"
                            _rerun()
                    with col2:
                        if _risk == "HIGH":
                            ack = st.checkbox(
                                "I understand this input may try to steer AI behavior. Continue anyway.",
                                key=f"pi_ack_{_fp}",
                            )
                            if ack and st.button("Continue as-is", key=f"pi_allow_{_fp}"):
                                st.session_state[_decision_key] = "allow"
                                _rerun()
                        else:
                            if st.button("Continue as-is", key=f"pi_allow_{_fp}"):
                                st.session_state[_decision_key] = "allow"
                                _rerun()
                    with col3:
                        if st.button("Cancel", key=f"pi_cancel_{_fp}"):
                            st.session_state[_decision_key] = "cancel"
                            _rerun()
                    st.stop()

                # Apply decision
                if _decision == "cancel":
                    spark_info("Generation cancelled.")
                    st.stop()
                if _decision == "sanitize":
                    _mode = "quote_wrap" if _risk != "HIGH" else "strip_lines"
                    source_text = sanitize_content(source_text, _scan, mode=_mode)

        # --- end Prompt Injection Scan ---
        if url_errors:
            with st.expander("URL fetch issues", expanded=False):
                for e in url_errors[:25]:
                    st.warning(e)
            


        # Fail closed if URL extraction produced too little usable text and the user
        # didn't provide any other content (upload/paste). This prevents generating
        # empty/generic intel briefs that look "successful" but have no substance.
        if cfg.fetch_source_urls and sources:
            _st = (source_text or "").strip()
            if len(_st) < 800 and not (uploaded_files or (pasted_text and pasted_text.strip())):
                st.error(
                    "URL extraction returned too little readable content to safely generate an Intel Brief. "
                    "This often happens on JS-rendered, paywalled, or bot-protected pages."
                )
                # Medium is a frequent offender: guide the user to a reliable workflow.
                if any(("medium.com" in (s or "").lower()) or ("detect.fyi" in (s or "").lower()) for s in (sources or [])):
                    spark_info("Tip: For Medium/detect.fyi, open the page in your browser and use Ctrl+P → Save as PDF, then upload the PDF here.")
                if url_errors:
                    with st.expander("URL fetch details", expanded=False):
                        for e in url_errors[:50]:
                            st.code(e)
                st.stop()
        _res = workflow.generate_intel_brief(
            llm,
            iid,
            topic=topic or "Untitled Topic",
            sources=sources,
            source_text=source_text,
            cfg=cfg,
            on_token=_on_token,
        )
        if isinstance(_res, tuple):
            intel, _raw_intel = _res[0], _res[1] if len(_res) > 1 else ''
        else:
            intel, _raw_intel = _res, ''
        dt = _time.perf_counter() - t0
        prog.progress(100)
        intel.meta.timings_s["intel_generate"] = round(float(dt), 3)
        store.save(intel, ArtifactType.INTEL_BRIEF, intel.meta.id)
        try:
            cfg = get_cfg()
            workflow.write_assistant_suggestions(cfg.data_dir, ArtifactType.INTEL_BRIEF, intel.meta.id, {
                'llm_raw_markdown': _raw_intel,
                'generated_at': workflow.utc_now(),
            })
        except Exception:
            pass
        _invalidate_caches()

        # Persist extracted IOCs as a stable sidecar for query builders
        try:
            workflow.write_intel_iocs_sidecar(store, intel.meta.id, getattr(intel, 'iocs', {}) or {})
            # also store as a first-class artifact (optional)
            try:
                from byo_secai.models import IntelIOCs
                store.save(IntelIOCs(meta=intel.meta, intel_id=intel.meta.id, iocs=getattr(intel, 'iocs', {}) or {}), ArtifactType.INTEL_IOCS, intel.meta.id)
            except Exception:
                pass
        except Exception as _e:
            log.exception('Failed to persist IOC sidecar: %s', _e)


        # Optional: IOC enrichment plugins + persistence
        if enrich_iocs:
            try:
                _enrich_box = st.empty()
                _enrich_box.info('Running IOC enrichment plugins...')
                enrich_res = workflow.run_ioc_enrichment(intel.iocs)
                epath = workflow.enrichment_path(cfg.data_dir, intel.meta.id)
                epath.write_text(json.dumps(enrich_res, indent=2), encoding='utf-8')
                # Write at-a-glance plugin summary CSVs
                rep_dir = Path(cfg.data_dir) / 'evidence' / 'intel' / intel.meta.id
                rep_map = workflow.write_plugin_summary_reports(enrich_res, rep_dir, intel.meta.id)
                st.success('Summary reports: ' + ', '.join([Path(p).name for p in rep_map.values()]))
                st.success(f"Enrichment saved: {epath.name}")
                _enrich_box.empty()
            except Exception as e:
                log.exception('IOC enrichment failed')
                st.warning(f"IOC enrichment failed: {e}")
                try:
                    _enrich_box.empty()
                except Exception:
                    pass

        st.session_state["timings"].append({"step": "intel_generate", "artifact": intel.meta.id, "seconds": round(float(dt), 3)})
        st.success(f"Created {intel.meta.id} ({llm.__class__.__name__})")

        # UX: auto-select the new Intel Brief + reset the input widgets on the next rerun.
        # (We must not mutate widget keys after they are instantiated.)
        st.session_state["intel_selected"] = intel.meta.id
        st.session_state["_reset_intel_inputs"] = True
        st.rerun()

    from byo_secai.state.run import get_active_run_id
    run_id = get_active_run_id()

    with step_timer("storage:list_ids:intel"):
        ids = list_ids_cached(cfg.data_dir, ArtifactType.INTEL_BRIEF.value)
        if not ids:
            ids = store.list_ids(ArtifactType.INTEL_BRIEF)
    if not ids:
        spark_warn("No intel briefs yet.")
        return

    # Persist selection across reruns; but when a new brief is created we overwrite
    # the selection so the view updates immediately.
    placeholder = "(New Intel Brief)"
    options = [placeholder] + ids
    if "intel_selected" not in st.session_state:
        st.session_state["intel_selected"] = placeholder
    if st.session_state["intel_selected"] not in options:
        st.session_state["intel_selected"] = placeholder
    selected = st.selectbox("Select Intel Brief", options, key="intel_selected")

    # If placeholder is selected, don't render a previous report.
    if selected == placeholder:
        spark_info("Start a new Intel Brief above or select an existing one from the list.")
        return

    with step_timer("storage:load_selected:intel"):
        intel_obj = load_artifact_json_cached(cfg.data_dir, ArtifactType.INTEL_BRIEF.value, selected)
        intel = IntelBrief.model_validate(intel_obj) if intel_obj else store.load(ArtifactType.INTEL_BRIEF, selected)

    if not intel:
        spark_risk("Selected intel brief could not be loaded.")
        return

    # IOC Table (extracted)
    if getattr(intel, "iocs", None):
        with st.expander("Extracted IOCs (auto)", expanded=False):
            for k, vals in intel.iocs.items():
                if vals:
                    st.markdown(f"**{k}**")
                    st.code("\n".join(vals), language="text")
    # Enrichment results (if saved)
    try:
        epath = workflow.enrichment_path(cfg.data_dir, selected)
        if epath.exists():
            with st.expander("IOC Enrichment Results (saved)", expanded=False):
                st.code(epath.read_text(encoding="utf-8"), language="json")
    except Exception:
        pass

    # Plugin Summary Reports (CSV) if present
    rep_dir = Path(cfg.data_dir) / "evidence" / "intel" / selected
    if rep_dir.exists():
        csvs = sorted([p for p in rep_dir.glob("*.csv")])
        if csvs:
            with st.expander("Plugin Summary Reports (CSV)", expanded=False):
                for p in csvs:
                    st.download_button(
                        label=f"Download {p.name}",
                        data=p.read_bytes(),
                        file_name=p.name,
                        mime="text/csv",
                        key=f"dl_{p.name}",
                    )


    # FIXED: Layout and success message logic
    c1, c2 = st.columns([1, 1])
    with c1:
        st.write(f"**Status:** {intel.approval.value}")
    with c2:
        if intel.approval == ApprovalStatus.DRAFT:
            # NOTE: This view renders inside a list; widget keys must be stable + unique per intel artifact.
            if st.button(
                "✅ Mark Approved",
                width="stretch",
                key=f"intel_mark_approved_{intel.meta.id}",
            ):
                # Approval gate: re-validate contract compliance at approval time.
                # UX: keep the UI visibly "working" while auto-fix/repair runs so users don't spam-click.
                with st.spinner("Validating + auto-fixing Intel Brief for approval..."):
                    cfg = get_cfg()
                    mode = (getattr(cfg, "contract_enforcement_mode", "off") or "off").strip().lower()
                    violations = []
                    try:
                        if mode != "off":
                            from byo_secai.contract_framework import load_contract, validate_intel_brief, format_violations, summarize_intel_brief

                            profile = getattr(cfg, "intel_brief_contract_profile", "intel_brief_v1_1")
                            contract, _cpath = load_contract(profile, contract_dir_override=getattr(cfg, "contract_dir_override", ""))
                            violations = validate_intel_brief(intel, contract)
                            if violations:
                                msg = format_violations(violations)
                                log.warning("[APPROVAL_GATE] intel_brief non_compliant id=%s mode=%s violations=%s", intel.meta.id, mode, len(violations))
                                # Record an audit trail entry
                                try:
                                    intel.meta.history.append({
                                        "ts": workflow.utc_now(),
                                        "actor": "system",
                                        "action": "approval_contract_validation_failed",
                                        "note": (msg or "validation failed")[:2000],
                                    })
                                except Exception:
                                    pass

                            # Phase 6.5.7: try bounded auto-correct (silent) for safe narrative fields.
                            try:
                                ac_enabled = bool(getattr(cfg, "approval_autocorrect_enabled", False))
                                ac_max = int(getattr(cfg, "approval_autocorrect_max_attempts", 0) or 0)
                                fail_open = bool(getattr(cfg, "approval_fail_open_after_autocorrect", False))
                            except Exception:
                                ac_enabled, ac_max, fail_open = False, 0, False

                            if mode == "strict" and ac_enabled and ac_max > 0:
                                try:
                                    llm = get_llm_for_generate()
                                except Exception:
                                    llm = None
                                try:
                                    for _i in range(ac_max):
                                        intel, violations, ac_meta = workflow.autocorrect_intel_brief_for_approval(llm, intel, cfg, violations)
                                        if not violations:
                                            break
                                except Exception as _ac_e:
                                    log.exception("[APPROVAL_GATE] intel_brief autocorrect error: %s", _ac_e)

                                if not violations:
                                    # Silent success; continue approval flow.
                                    try:
                                        summary = summarize_intel_brief(intel, contract)
                                        log.info("[APPROVAL_GATE] intel_brief autocorrect_pass id=%s summary=%s", intel.meta.id, summary)
                                    except Exception:
                                        pass
                                else:
                                    # Recompute message after auto-correct attempts.
                                    msg = format_violations(violations)

                            # Phase 6.5.8.5: deterministic non-destructive repair (additive-only) to guarantee invariants.
                            try:
                                from byo_secai.intel_invariants import repair_intel_brief
                                intel, _repairs = repair_intel_brief(intel)
                                if _repairs:
                                    try:
                                        intel.meta.history.append({
                                            "ts": workflow.utc_now(),
                                            "actor": "system",
                                            "action": "intel_repair_applied",
                                            "note": (",".join(_repairs))[:2000],
                                        })
                                    except Exception:
                                        pass
                                # Re-run contract validation after repair (best-effort).
                                if mode != "off" and contract is not None:
                                    violations = validate_intel_brief(intel, contract)
                                    if violations:
                                        msg = format_violations(violations)
                            except Exception as _rep_e:
                                try:
                                    log.exception("[APPROVAL_GATE] intel_brief repair error: %s", _rep_e)
                                except Exception:
                                    pass

                            if violations:
                                if mode == "strict":
                                    # If configured, fail-open after bounded auto-correct attempts.
                                    if fail_open:
                                        warn = (
                                            "⚠️ **Approved with validation warnings**\n\n"
                                            "This Intel Brief did not fully satisfy the contract checks. We approved it so you can continue to Hunt Package generation, but you should fix the draft when you can.\n\n"
                                            "**What failed:**\n"
                                            f"{msg}\n\n"
                                            "**How to fix:** Open *Edit Draft*, update the missing sections, and re-approve.\n"
                                            "Tip: auto-correct only touches safe narrative sections (Gaps/Alternative/Appendix/MITRE), and it will never modify Evidence/IOCs."
                                        )
                                        st.warning(warn)
                                        try:
                                            intel.meta.history.append({
                                                "ts": workflow.utc_now(),
                                                "actor": "system",
                                                "action": "approved_fail_open_with_contract_warnings",
                                                "note": f"warnings={len(violations)}",
                                            })
                                        except Exception:
                                            pass
                                    else:
                                        st.error("Cannot approve: contract validation failed. Fix the draft or relax enforcement mode.\n\n" + (msg or ""))
                                        intel.meta.updated_at = workflow.utc_now()
                                        store.save(intel, ArtifactType.INTEL_BRIEF, intel.meta.id)
                                        st.rerun()
                                elif mode == "warn":
                                    st.warning("Approving with contract warnings:\n\n" + (msg or ""))
                                    try:
                                        intel.meta.history.append({
                                            "ts": workflow.utc_now(),
                                            "actor": "user",
                                            "action": "approved_with_contract_warnings",
                                            "note": f"warnings={len(violations)}",
                                        })
                                    except Exception:
                                        pass
                        else:
                            # Helpful: log a short "why this passed" summary.
                            try:
                                summary = summarize_intel_brief(intel, contract)
                                log.info("[APPROVAL_GATE] intel_brief passed id=%s summary=%s", intel.meta.id, summary)
                            except Exception:
                                pass
                    except Exception as _e:
                        log.exception("[APPROVAL_GATE] intel_brief validation error: %s", _e)

                # If strict mode and violations exist:
                # - If fail-open is enabled, proceed to approve with warnings.
                # - Otherwise, keep as Draft and show an error.
                approved_ok = True
                if mode == "strict" and violations:
                    approved_ok = bool(getattr(cfg, "approval_fail_open_after_autocorrect", False))
                    if approved_ok:
                        log.info("[APPROVAL_GATE] intel_brief fail-open enabled; proceeding id=%s violations=%s", intel.meta.id, len(violations))
                    else:
                        spark_risk("Approval blocked by contract checks. Use Edit Draft to fix the sections listed above, then re-approve.")

                if approved_ok:
                    intel.approval = ApprovalStatus.APPROVED
                    intel.meta.updated_at = workflow.utc_now()
                    store.save(intel, ArtifactType.INTEL_BRIEF, intel.meta.id)

                    # Persist extracted IOCs as a stable sidecar for query builders
                    try:
                        workflow.write_intel_iocs_sidecar(store, intel.meta.id, getattr(intel, "iocs", {}) or {})
                        # also store as a first-class artifact (optional)
                        try:
                            from byo_secai.models import IntelIOCs

                            store.save(
                                IntelIOCs(
                                    meta=intel.meta,
                                    intel_id=intel.meta.id,
                                    iocs=getattr(intel, "iocs", {}) or {},
                                ),
                                ArtifactType.INTEL_IOCS,
                                intel.meta.id,
                            )
                        except Exception:
                            pass
                    except Exception as _e:
                        log.exception("Failed to persist intel IOC sidecar: %s", _e)

                    spark_ok("Intel Brief approved.")
                    st.rerun()
        else:
            st.button(
                "✅ Approved",
                width="stretch",
                disabled=True,
                key=f"intel_approved_{intel.meta.id}",
            )
            with st.expander("Advanced", expanded=False):
                if st.button(
                    "↩ Set back to Draft",
                    width="stretch",
                    key=f"intel_set_draft_{intel.meta.id}",
                ):
                    intel.approval = ApprovalStatus.DRAFT
                    intel.meta.updated_at = workflow.utc_now()
                    store.save(intel, ArtifactType.INTEL_BRIEF, intel.meta.id)
                    spark_info("Intel Brief set back to Draft.")
                    st.rerun()
    st.markdown("---")
    tab_report, tab_edit, tab_diff, tab_suggest = st.tabs(["Rendered Report", "Edit Draft", "Diff (Hunt ↔ ADS)", "Assistant Suggestions"])
    with tab_report:
        # Load linked intel for deterministic Hunt Report rendering
        intel_for_render = None
        try:
            if getattr(hunt, "linked_intel_id", None):
                intel_for_render = store.load(ArtifactType.INTEL_BRIEF, hunt.linked_intel_id)
        except Exception:
            intel_for_render = None

        inputs = {"intel_id": selected, "updated_at": getattr(intel.meta, "updated_at", ""), "approval": intel.approval.value}
        cached = payload_get("IntelBriefs:rendered", run_id, inputs)
        # Optional HTML snapshot cache (faster navigation)
        try:
            from byo_secai.render_cache import load_html, save_html_from_markdown
            import streamlit.components.v1 as components
        except Exception:
            load_html = None  # type: ignore
            save_html_from_markdown = None  # type: ignore
            components = None  # type: ignore

        if getattr(cfg, "render_cache_enabled", False) and load_html and components:
            with step_timer("render_cache:load_html:intel"):
                html = load_html(cfg.data_dir, ArtifactType.INTEL_BRIEF.value, selected, getattr(intel.meta, "updated_at", ""))
            if html:
                components.html(html, height=900, scrolling=True)
            else:
                if cached and isinstance(cached, str):
                    rendered = cached
                else:
                    with step_timer("render:intel_markdown"):
                        rendered = workflow.render_intel_markdown(intel)
                    payload_set("IntelBriefs:rendered", run_id, inputs, rendered)
                if save_html_from_markdown:
                    with step_timer("render_cache:save_html:intel"):
                        save_html_from_markdown(cfg.data_dir, ArtifactType.INTEL_BRIEF.value, selected, getattr(intel.meta, "updated_at", ""), rendered)
                components.html(load_html(cfg.data_dir, ArtifactType.INTEL_BRIEF.value, selected, getattr(intel.meta, "updated_at", "")) or "", height=900, scrolling=True)
        else:
            if cached and isinstance(cached, str):
                st.markdown(cached)
            else:
                with step_timer("render:intel_markdown"):
                    rendered = workflow.render_intel_markdown(intel)
                payload_set("IntelBriefs:rendered", run_id, inputs, rendered)
                st.markdown(rendered)

    with tab_edit:
        if intel.approval == ApprovalStatus.APPROVED:
            spark_warn("This Intel Brief is **Approved**. Edits are allowed and will update the approved artifact.")
            with st.expander("Advanced", expanded=False):
                if st.button("✏️ Revise (clone to Draft)", type="secondary", width="stretch", key=f"revise_clone_{intel.meta.id}"):
                    new_id = store.new_id("intel")
                    cloned = intel.model_copy(deep=True)
                    cloned.meta.id = new_id
                    cloned.meta.title = f"Intel Brief: {cloned.topic or cloned.title or 'Untitled'}"
                    cloned.meta.created_at = workflow.utc_now()
                    cloned.meta.updated_at = cloned.meta.created_at
                    cloned.approval = ApprovalStatus.DRAFT
                    store.save(cloned, ArtifactType.INTEL_BRIEF, new_id)
                    st.session_state["toast"] = f"Created draft copy: {new_id}"
                    st.rerun()

        with st.form("intel_edit_form", clear_on_submit=False):
            keep_approved = True
            if intel.approval == ApprovalStatus.APPROVED:
                keep_approved = st.checkbox("Keep status as Approved", value=True)

            intel.topic = st.text_input("Topic", value=intel.topic or intel.title)
            intel.title = st.text_input("Title (optional)", value=intel.title)

            src_text = "\n".join(intel.sources or [])
            src_text = st.text_area("Sources (one per line)", value=src_text, height=120)
            intel.sources = [s.strip() for s in (src_text or "").splitlines() if s.strip()]

            intel.bluf = st.text_area("BLUF", value=intel.bluf, height=140)
            intel.background = st.text_area("Background", value=intel.background, height=140)
            intel.threat_description = st.text_area("Threat Description", value=intel.threat_description, height=180)
            intel.evidence_and_indicators = st.text_area("Evidence and Indicators", value=intel.evidence_and_indicators, height=180)
            intel.impact_assessment = st.text_area("Impact Assessment", value=intel.impact_assessment, height=140)
            intel.recommended_actions = st.text_area("Recommended Actions", value=intel.recommended_actions, height=140)

            submitted = st.form_submit_button("💾 Save", type="primary")
            if submitted:
                intel.meta.updated_at = workflow.utc_now()
                workflow.record_history(intel.meta, "save", actor=(st.session_state.get("operator") or ""))
                if intel.approval == ApprovalStatus.APPROVED and not keep_approved:
                    intel.approval = ApprovalStatus.DRAFT
                store.save(intel, ArtifactType.INTEL_BRIEF, intel.meta.id)
                st.session_state["toast"] = "Saved Intel Brief."
                st.rerun()

    with tab_suggest:
        cfg = get_cfg()
        sugg = workflow.read_assistant_suggestions(cfg.data_dir, ArtifactType.INTEL_BRIEF, intel.meta.id) if intel else {}
        md = (sugg or {}).get('llm_raw_markdown') or ''
        if md.strip():
            st.caption('Assistant suggestions (non-authoritative).')
            st.markdown(md)
        else:
            st.info('No assistant suggestions stored for this Intel Brief.')




def render_hunts():
    store = get_storage()
    cfg = get_cfg()
    from byo_secai.state.run import get_active_run_id
    from byo_secai.state.view_state import state_get, state_set
    run_ctx = get_active_run_id()

    st.subheader("Hunt Packages")

    with step_timer("storage:list_ids:intel_for_hunts"):
        intel_ids = list_ids_cached(cfg.data_dir, ArtifactType.INTEL_BRIEF.value)
        if not intel_ids:
            intel_ids = store.list_ids(ArtifactType.INTEL_BRIEF)

    approved = []
    with step_timer("storage:load_approved_intel"):
        for iid in intel_ids:
            obj = load_artifact_json_cached(cfg.data_dir, ArtifactType.INTEL_BRIEF.value, iid)
            if not obj:
                continue
            try:
                # Fast-path: check approval field without full rendering work.
                if str((obj.get("approval") or "")).upper().endswith("APPROVED"):
                    approved.append(IntelBrief.model_validate(obj))
            except Exception:
                # fallback to robust load
                i = store.load(ArtifactType.INTEL_BRIEF, iid)
                if i and i.approval == ApprovalStatus.APPROVED:
                    approved.append(i)

    with st.expander("Generate Hunt Package from Approved Intel", expanded=True):
        if not approved:
            spark_warn("No approved intel briefs found. Approve one on the Intel Briefs page first.")
        else:
            intel_choice = st.selectbox("Approved Intel", [i.meta.id for i in approved])
            # SHA-256 IOC coverage (hash sweeps use SHA256HashData; SHA-256 only)
            with step_timer("storage:load_selected_intel_for_hunt"):
                _obj = load_artifact_json_cached(cfg.data_dir, ArtifactType.INTEL_BRIEF.value, intel_choice) if intel_choice else None
                _intel_obj = IntelBrief.model_validate(_obj) if _obj else (store.load(ArtifactType.INTEL_BRIEF, intel_choice) if intel_choice else None)
            _hashes = getattr(_intel_obj, 'iocs', {}).get('hash', []) if _intel_obj else []
            _sha256 = [h.strip().lower() for h in (_hashes or []) if re.fullmatch(r'[A-Fa-f0-9]{64}', (h or '').strip())]
            _ignored = [h for h in (_hashes or []) if (h or '').strip() and not re.fullmatch(r'[A-Fa-f0-9]{64}', (h or '').strip())]
            st.caption(f"SHA-256 hashes included: {len(_sha256)} | ignored (non-SHA256): {len(_ignored)}")

            # Phase 5.3 (RESET): choose language BEFORE generation (remembered per Intel)
            workflow_query_lang = select_query_language_for_intel(cfg, intel_choice)
            # Phase 6.3: optional CQL grounding via Knowledge Library (dictionary + examples)
            use_grounding = False
            if str(workflow_query_lang).strip().upper() == "CQL":
                use_grounding = st.checkbox(
                    "Ground CQL with Knowledge Library (dictionary + examples)",
                    value=bool(getattr(cfg, "cql_grounding_enabled", True)),
                    help="Reduces drift by retrieving relevant chunks from data/rag/library (dictionary/, examples/, ads/).",
                )
            if st.button("Generate Hunt Package", type="primary", key="generate_hunt_package"):
                llm = get_llm_for_generate()
                with step_timer("storage:load_intel_for_generation"):
                    _obj2 = load_artifact_json_cached(cfg.data_dir, ArtifactType.INTEL_BRIEF.value, intel_choice)
                    intel = IntelBrief.model_validate(_obj2) if _obj2 else store.load(ArtifactType.INTEL_BRIEF, intel_choice)
                hid = store.new_id("hunt")
                rag = get_rag()
                sources_text = workflow.fetch_sources_text(
                    intel.sources,
                    max_chars=int(cfg.max_source_chars),
                    timeout_s=int(cfg.ollama_request_timeout_s),
                    cfg=cfg,
                ) if (cfg.fetch_source_urls and intel.sources) else ""
                import time

                prog = st.progress(0)
                preview = st.empty()
                buf: list[str] = []

                def _on_token(chunk: str):
                    buf.append(chunk)
                    # preview.code("".join(buf), language="markdown")
                    pct = min(0.95, len("".join(buf)) / 9000)
                    prog.progress(int(pct * 100))

                t0 = _time.perf_counter()
                _res = workflow.generate_hunt_package(
                    llm,
                    hid,
                    intel,
                    sources_text=sources_text,
                    cfg=cfg,
                    query_language=str(workflow_query_lang),
                    min_queries=int(cfg.hunt_min_queries),
                    max_queries=int(cfg.hunt_max_queries),
                    rag_index=rag,
                    ground_queries=bool(use_grounding),
                    grounding_debug=bool(getattr(cfg, "cql_grounding_debug", True)),
                    grounding_top_k_dictionary=int(getattr(cfg, "cql_grounding_top_k_dictionary", 5)),
                    grounding_top_k_examples=int(getattr(cfg, "cql_grounding_top_k_examples", 5)),
                    on_token=_on_token,
                )
                if isinstance(_res, tuple):
                    hunt, _raw_hunt = _res[0], _res[1] if len(_res) > 1 else ''
                    _grounding = _res[2] if len(_res) > 2 else {}
                else:
                    hunt, _raw_hunt = _res, ''
                    _grounding = {}
                dt = _time.perf_counter() - t0
                prog.progress(100)
                hunt.meta.timings_s["hunt_generate"] = round(float(dt), 3)
                store.save(hunt, ArtifactType.HUNT_PACKAGE, hunt.meta.id)
                try:
                    cfg = get_cfg()
                    workflow.write_assistant_suggestions(cfg.data_dir, ArtifactType.HUNT_PACKAGE, hunt.meta.id, {
                        'llm_raw_markdown': _raw_hunt,
                        'generated_at': workflow.utc_now(),
                        'cql_grounding': _grounding,
                    })
                except Exception:
                    pass
                _invalidate_caches()
                st.session_state["timings"].append({"step": "hunt_generate", "artifact": hunt.meta.id, "seconds": round(float(dt), 3)})
                # Auto-select the newly created hunt so the user doesn't stay
                # on a previously selected report.
                state_set("Hunt Packages", run_ctx, "selected_hunt", hunt.meta.id)
                st.session_state["toast"] = f"Created {hunt.meta.id} ({llm.__class__.__name__})"
                st.rerun()

    with step_timer("storage:list_ids:hunts"):
        ids = list_ids_cached(cfg.data_dir, ArtifactType.HUNT_PACKAGE.value)
        if not ids:
            ids = store.list_ids(ArtifactType.HUNT_PACKAGE)
    if not ids:
        spark_warn("No hunt packages yet.")
        return

    _default = state_get("Hunt Packages", run_ctx, "selected_hunt", ids[0] if ids else "")
    try:
        _idx = ids.index(_default) if _default in ids else 0
    except Exception:
        _idx = 0
    selected = st.selectbox("Select Hunt Package", ids, index=_idx, key=f"hunt_selected_{run_ctx}")
    state_set("Hunt Packages", run_ctx, "selected_hunt", selected)
    with step_timer("storage:load_selected:hunt"):
        hunt_obj = load_artifact_json_cached(cfg.data_dir, ArtifactType.HUNT_PACKAGE.value, selected)
        hunt = HuntPackage.model_validate(hunt_obj) if hunt_obj else store.load(ArtifactType.HUNT_PACKAGE, selected)

    # Approval controls
    c1, c2 = st.columns([1, 1])
    with c1:
        st.write(f"**Status:** {hunt.approval.value}")

        # Surface contract validation warnings (if any)
        try:
            warn = (getattr(getattr(hunt, "meta", None), "links", {}) or {}).get("contract_warnings", "")
            if str(warn).strip():
                st.warning("Approved with validation warnings\n\n" + str(warn).strip())
        except Exception:
            pass
        # Optional: artifact-chain breadcrumbs (off by default)
        try:
            if bool(getattr(cfg, "show_breadcrumbs", False)):
                render_artifact_chain_banner(st, intel_id=getattr(hunt, "linked_intel_id", ""), hunt_id=hunt.meta.id)
        except Exception:
            pass
    with c2:
        if hunt.approval == ApprovalStatus.DRAFT:
            if st.button("✅ Mark Approved", type="primary", width="stretch", key=f"hunt_mark_approved_{hunt.meta.id}"):
                # Validation gate: block bad telemetry before approval
                violations: list[str] = []
                for q in (hunt.queries or []):
                    errs = workflow.validate_cql_query(q.query or "")
                    if errs:
                        violations.append(f"{q.title or 'untitled'}: " + "; ".join(errs))
                if violations:
                    st.error("Validation failed (fix before approving):\n- " + "\n- ".join(violations))
                else:
                    hunt.approval = ApprovalStatus.APPROVED
                    hunt.meta.updated_at = workflow.utc_now()
                    store.save(hunt, ArtifactType.HUNT_PACKAGE, hunt.meta.id)
                    spark_ok("Hunt Package approved.")
                    st.rerun()
        else:
            st.button("✅ Approved", width="stretch", disabled=True, key=f"approved_{hunt.meta.id}")
            with st.expander("Advanced", expanded=False):
                if st.button("✏️ Revise (clone to Draft)", type="secondary", width="stretch", key=f"revise_clone_top_{hunt.meta.id}"):
                    new_id = store.new_id("hunt")
                    cloned = hunt.model_copy(deep=True)
                    cloned.meta.id = new_id
                    cloned.meta.created_at = workflow.utc_now()
                    cloned.meta.updated_at = cloned.meta.created_at
                    cloned.approval = ApprovalStatus.DRAFT
                    store.save(cloned, ArtifactType.HUNT_PACKAGE, new_id)
                    st.session_state["toast"] = f"Created draft copy: {new_id}"
                    st.rerun()

    st.markdown("---")

    tab_report, tab_edit, tab_suggest = st.tabs(["Rendered Report", "Edit Draft", "Assistant Suggestions"])
    with tab_report:
        inputs = {"hunt_id": hunt.meta.id, "updated_at": getattr(hunt.meta, "updated_at", ""), "approval": hunt.approval.value}
        # Load linked intel for deterministic Hunt Report rendering
        intel_for_render = None
        try:
            if getattr(hunt, "linked_intel_id", None):
                intel_for_render = store.load(ArtifactType.INTEL_BRIEF, hunt.linked_intel_id)
        except Exception:
            intel_for_render = None

        cached = payload_get("HuntPackages:rendered_report_v1", run_ctx, inputs)
        # Optional HTML snapshot cache (faster navigation)
        try:
            from byo_secai.render_cache import load_html, save_html_from_markdown
            import streamlit.components.v1 as components
        except Exception:
            load_html = None  # type: ignore
            save_html_from_markdown = None  # type: ignore
            components = None  # type: ignore

        if getattr(cfg, "render_cache_enabled", False) and load_html and components:
            with step_timer("render_cache:load_html:hunt"):
                html = load_html(cfg.data_dir, ArtifactType.HUNT_PACKAGE.value, hunt.meta.id, getattr(hunt.meta, "updated_at", ""))
            if html:
                components.html(html, height=900, scrolling=True)
            else:
                if cached and isinstance(cached, str):
                    md = cached
                else:
                    with step_timer("render:hunt_markdown"):
                        md = workflow.render_hunt_report_markdown(hunt, intel=intel_for_render)
                    payload_set("HuntPackages:rendered_report_v1", run_ctx, inputs, md)
                if save_html_from_markdown:
                    with step_timer("render_cache:save_html:hunt"):
                        save_html_from_markdown(cfg.data_dir, ArtifactType.HUNT_PACKAGE.value, hunt.meta.id, getattr(hunt.meta, "updated_at", ""), md)
                components.html(load_html(cfg.data_dir, ArtifactType.HUNT_PACKAGE.value, hunt.meta.id, getattr(hunt.meta, "updated_at", "")) or "", height=900, scrolling=True)
        else:
            if cached and isinstance(cached, str):
                st.markdown(cached)
            else:
                with step_timer("render:hunt_markdown"):
                    md = workflow.render_hunt_report_markdown(hunt, intel=intel_for_render)
                payload_set("HuntPackages:rendered_report_v1", run_ctx, inputs, md)
                st.markdown(md)

        # Executive export (gated - no placeholders)
        st.markdown("---")
        if st.button("Export ADS (Executive)", type="primary", width="stretch", key=f"export_ads_exec_{hunt.meta.id}"):
            md = cached_md if (cached_md and isinstance(cached_md, str)) else workflow.render_ads_markdown(ads)
            violations = workflow.validate_no_tbd(md)
            if violations:
                st.error("Export blocked. Fix placeholders before executive export:\n- " + "\n- ".join(violations))
            else:
                export_path = store.export_markdown(ArtifactType.ADS, ads.meta.id, md)
                st.success(f"Exported to {export_path}")
                st.download_button(
                    "Download export",
                    data=Path(export_path).read_bytes(),
                    file_name=os.path.basename(export_path),
                    mime="text/markdown",
                    key=f"dl_ads_{ads.meta.id}",
                )

    with tab_edit:
        if hunt.approval == ApprovalStatus.APPROVED:
            spark_warn("This Hunt Package is **Approved**. Edits are allowed and will update the approved artifact.")
            with st.expander("Advanced", expanded=False):
                if st.button("✏️ Revise (clone to Draft)", type="secondary", width="stretch", key=f"revise_clone_edit_{hunt.meta.id}"):
                    new_id = store.new_id("hunt")
                    cloned = hunt.model_copy(deep=True)
                    cloned.meta.id = new_id
                    cloned.meta.title = f"Hunt Package: {cloned.meta.title}"
                    cloned.meta.created_at = workflow.utc_now()
                    cloned.meta.updated_at = cloned.meta.created_at
                    cloned.approval = ApprovalStatus.DRAFT
                    store.save(cloned, ArtifactType.HUNT_PACKAGE, new_id)
                    st.session_state["toast"] = f"Created draft copy: {new_id}"
                    st.rerun()

        with st.form("hunt_edit_form", clear_on_submit=False):
            keep_approved = True
            if hunt.approval == ApprovalStatus.APPROVED:
                keep_approved = st.checkbox("Keep status as Approved", value=True)

            hunt.objective = st.text_area("Objective", value=hunt.objective, height=120)
            hyp_text = "\n".join(hunt.hypotheses or [])
            hyp_text = st.text_area("Hypotheses (one per line)", value=hyp_text, height=120)
            hunt.hypotheses = [h.strip("- ").strip() for h in (hyp_text or "").splitlines() if h.strip()]

            ds_text = "\n".join(hunt.data_sources or [])
            ds_text = st.text_area("Data sources / telemetry (one per line)", value=ds_text, height=120)
            hunt.data_sources = [d.strip("- ").strip() for d in (ds_text or "").splitlines() if d.strip()]

            hunt.scope_notes = st.text_area("Scope notes", value=hunt.scope_notes, height=120)
            hunt.execution_notes = st.text_area("Execution notes", value=hunt.execution_notes, height=120)

            st.markdown("#### Hunt Queries (structured)")
            if not hunt.queries:
                st.caption("No queries yet. Generate a Hunt Package or add queries below.")

            # Allow editing existing queries
            for i, q in enumerate(hunt.queries or [], start=1):
                with st.expander(f"Query {i}: {q.title or 'untitled'}", expanded=False):
                    q.title = st.text_input(f"Title {i}", value=q.title, key=f"hq_title_{hunt.meta.id}_{i}")
                    q.description = st.text_area(
                        f"Purpose {i}",
                        value=q.description,
                        height=100,
                        key=f"hq_desc_{hunt.meta.id}_{i}",
                    )
                    q.query = st.text_area(
                        f"Query logic {i}",
                        value=q.query,
                        height=160,
                        key=f"hq_query_{hunt.meta.id}_{i}",
                    )
                    hunt.queries[i - 1] = q

            # Add a new query row
            with st.expander("➕ Add a new query", expanded=False):
                new_title = st.text_input("New query title", value="")
                new_purpose = st.text_area("New query purpose", value="", height=80)
                new_logic = st.text_area("New query logic", value="#event_simpleName=ProcessRollup2\n| groupBy([ComputerName], limit=20000)", height=120)
                if st.form_submit_button("Add to Hunt", type="secondary"):
                    from byo_secai.models import HuntQuery
                    hunt.queries.append(HuntQuery(title=new_title.strip() or "New Query", description=new_purpose.strip(), query=new_logic.strip(), query_language="CrowdStrike LogScale CQL"))
                    st.session_state["toast"] = "Query added (remember to Save)."
                    st.rerun()

            submitted = st.form_submit_button("💾 Save", type="primary")
            if submitted:
                # Update the rendered markdown to keep Section 4 in sync with structured queries.
                try:
                    base_md = hunt.rendered_markdown or workflow.render_hunt_markdown(hunt)
                    hunt.rendered_markdown = workflow._inject_section4(base_md, hunt, qlang_label="CQL")
                except Exception:
                    pass

                # Validation gate on save (warn-only)
                violations: list[str] = []
                for q in (hunt.queries or []):
                    errs = workflow.validate_cql_query(q.query or "")
                    if errs:
                        violations.append(f"{q.title or 'untitled'}: " + "; ".join(errs))
                if violations:
                    st.warning("Saved, but validation warnings exist:\n- " + "\n- ".join(violations))

                hunt.meta.updated_at = workflow.utc_now()
                workflow.record_history(hunt.meta, "save", actor=(st.session_state.get("operator") or ""))
                if hunt.approval == ApprovalStatus.APPROVED and not keep_approved:
                    hunt.approval = ApprovalStatus.DRAFT
                store.save(hunt, ArtifactType.HUNT_PACKAGE, hunt.meta.id)
                st.session_state["toast"] = "Saved Hunt Package."
                st.rerun()

    with tab_suggest:
        cfg = get_cfg()
        sugg = workflow.read_assistant_suggestions(cfg.data_dir, ArtifactType.HUNT_PACKAGE, hunt.meta.id) if hunt else {}
        md = (sugg or {}).get('llm_raw_markdown') or ''
        grounding = (sugg or {}).get('cql_grounding') or {}
        beh = (grounding or {}).get('behavior') or {}
        trans = (grounding or {}).get('telemetry_translation') or {}

        # Phase 6.3.1: behavior debug panel (what we extracted + whether queries met those behaviors)
        if beh:
            with st.expander("Behavior Debug (extracted + checklist)", expanded=False):
                st.write("**Behavior extracted:**")
                st.json((beh or {}).get("extracted") or {})
                st.write("**Checklist:**")
                st.json((beh or {}).get("checklist") or {})
                st.write("**Queries satisfied behaviors:**")
                rows = (beh or {}).get("results") or []
                if rows:
                    for r in rows:
                        title = r.get("title") or "(untitled)"
                        passes = bool(r.get("passes"))
                        tag = "YES" if passes else "NO"
                        st.markdown(f"- **{title}** → **{tag}**")
                        missing = r.get("missing") or []
                        if missing and not passes:
                            st.caption("Missing: " + "; ".join([str(m) for m in missing]))
                else:
                    spark_info("No behavior evaluation rows were stored for this artifact.")

        # Phase 6.3.2: telemetry translation debug (ECS/Sigma/CIM -> CrowdStrike pivots)
        if trans:
            with st.expander("Telemetry Translation Debug (ECS/Sigma/CIM → CrowdStrike)", expanded=False):
                st.write("**Schema detected:**")
                st.json((trans or {}).get("schema_detected") or {})
                st.write("**Replacements:**")
                reps = (trans or {}).get("replacements") or []
                if reps:
                    st.json(reps)
                else:
                    spark_info("No field replacements were applied.")
                st.write("**Dropped (no equivalent):**")
                dropped = (trans or {}).get("dropped") or []
                if dropped:
                    st.json(dropped)
                else:
                    st.caption("None")

        if md.strip():
            st.caption('Assistant suggestions (non-authoritative).')
            st.markdown(md)
        else:
            st.info('No assistant suggestions stored for this Hunt Package.')



def render_runs():
    store = get_storage()
    from byo_secai.state.run import start_new_run, set_active_run_id
    from byo_secai.state.view_state import state_get, state_set
    run_ctx = set_active_run_id(st.session_state.get("active_run_id", "no_run"))

    st.subheader("Runs")

    hunt_ids = store.list_ids(ArtifactType.HUNT_PACKAGE)
    with st.expander("Start a new Run", expanded=True):
        if not hunt_ids:
            spark_warn("No hunt packages found. Create one first.")
        else:
            hunt_choice = st.selectbox("Hunt Package", hunt_ids)
            if st.button("▶️ Start Run", type="primary", key="start_run"):
                hunt = store.load(ArtifactType.HUNT_PACKAGE, hunt_choice)
                rid = store.new_id("run")
                run = workflow.simulate_run(rid, hunt)
                store.save(run, ArtifactType.RUN, run.meta.id)

                # Phase 6.3.6: new run invalidates per-view caches/state
                start_new_run(run.meta.id)

                # auto-generate findings (mock)
                findings = workflow.generate_findings_from_run(run, hunt, intel=store.load(ArtifactType.INTEL_BRIEF, getattr(run, 'linked_intel_id', '') or ''))
                for f in findings:
                    store.save(f, ArtifactType.FINDING, f.meta.id)
                    run.findings_created.append(f.meta.id)

                store.save(run, ArtifactType.RUN, run.meta.id)
                # Auto-select the newly created run and reset the view so users
                # don't stay on a previously selected run/report.
                state_set("Runs", run.meta.id, "selected_run", run.meta.id)
                st.session_state["toast"] = f"Run complete. Created {len(findings)} finding(s)."
                st.rerun()

    ids = store.list_ids(ArtifactType.RUN)
    if not ids:
        spark_warn("No runs yet.")
        return

    st.caption("Run Reports Library: searchable archive of prior runs and their IR-style drafts.")
    q = st.text_input("Search runs (id, linked hunt, notes, report text)", value="")
    ql = (q or "").lower().strip()
    filtered = []
    for rid in ids:
        r = store.load(ArtifactType.RUN, rid)
        blob = " ".join([
            rid,
            getattr(r, "linked_hunt_id", ""),
            getattr(r, "run_notes", ""),
            getattr(r, "report_markdown", ""),
        ]).lower()
        if not ql or ql in blob:
            filtered.append(rid)
    if not filtered:
        spark_warn("No runs matched your search.")
        return

    _default = state_get("Runs", run_ctx, "selected_run", filtered[0] if filtered else "")
    try:
        _idx = filtered.index(_default) if _default in filtered else 0
    except Exception:
        _idx = 0
    selected = st.selectbox("Select Run", filtered, index=_idx, key=f"runs_selected_{run_ctx}")
    state_set("Runs", run_ctx, "selected_run", selected)
    # Viewing a different run updates context, but does NOT invalidate caches.
    set_active_run_id(selected)
    run = store.load(ArtifactType.RUN, selected)

    # Backfill missing link fields (older artifacts) so downstream pages can scope correctly.
    try:
        _repair_run_links(store, run)
    except Exception:
        pass

    # Track current investigation chain context for cross-page scoping.
    st.session_state["active_hunt_id"] = getattr(run, "linked_hunt_id", "") or ""
    st.session_state["active_intel_id"] = getattr(run, "linked_intel_id", "") or ""

    # Optional: artifact-chain breadcrumbs (off by default)
    try:
        if bool(getattr(get_cfg(), "show_breadcrumbs", False)):
            render_artifact_chain_banner(st, intel_id=getattr(run, "linked_intel_id", ""), hunt_id=getattr(run, "linked_hunt_id", ""), run_id=run.meta.id)
    except Exception:
        pass

    # Make this run the active context for "sticky" view state.
    set_active_run_id(run.meta.id)
    state_set("Runs", run.meta.id, "selected_run", run.meta.id)

    st.write(f"**Status:** {run.status.value}  |  Linked Hunt: `{run.linked_hunt_id}`")

    tab_details, tab_report = st.tabs(["Run Details", "Run Report (IR Draft)"])

    with tab_details:
        st.markdown("---")
        for s in run.steps:
            st.write(f"- **{s.name}** — {s.status}: {s.detail}")

        with st.expander("Execution context (editable)", expanded=True):
            with st.form("run_context_form", clear_on_submit=False):
                # Use picker-style inputs to prevent timestamp typos.
                import datetime as _dt

                def _parse_iso(s: str):
                    try:
                        return _dt.datetime.fromisoformat((s or "").replace("Z", "+00:00"))
                    except Exception:
                        return None

                use_picker = st.checkbox("Use date/time picker", value=True, help="Prevents timestamp input errors; saves ISO-8601 strings.")
                if use_picker:
                    cts1, cts2 = st.columns(2)
                    cur_s = _parse_iso(getattr(run, "time_window_start", ""))
                    cur_e = _parse_iso(getattr(run, "time_window_end", ""))
                    now_dt = _dt.datetime.now().replace(microsecond=0)
                    default_start_dt = (now_dt - _dt.timedelta(days=30))
                    default_end_dt = now_dt
                    with cts1:
                        d1 = st.date_input("Start date", value=(cur_s.date() if cur_s else default_start_dt.date()))
                        t1 = st.time_input("Start time", value=(cur_s.time() if cur_s else default_start_dt.time()))
                    with cts2:
                        d2 = st.date_input("End date", value=(cur_e.date() if cur_e else default_end_dt.date()))
                        t2 = st.time_input("End time", value=(cur_e.time() if cur_e else default_end_dt.time()))
                    run.time_window_start = _dt.datetime.combine(d1, t1).isoformat()
                    run.time_window_end = _dt.datetime.combine(d2, t2).isoformat()
                    st.caption(f"Saved as: start={run.time_window_start} | end={run.time_window_end}")
                else:
                    run.time_window_start = st.text_input("Time window start (ISO-8601)", value=getattr(run, "time_window_start", ""))
                    run.time_window_end = st.text_input("Time window end (ISO-8601)", value=getattr(run, "time_window_end", ""))
                run.operator = st.text_input("Operator", value=getattr(run, "operator", ""))
                run.run_notes = st.text_area("Run notes", value=getattr(run, "run_notes", ""), height=160)
                if st.form_submit_button("💾 Save Run", type="primary"):
                    run.meta.updated_at = workflow.utc_now()
                    store.save(run, ArtifactType.RUN, run.meta.id)
                    st.session_state["toast"] = "Saved run context."
                    st.rerun()

        if run.findings_created:
            st.markdown("---")
            st.write("**Findings created:**")
            for fid in run.findings_created:
                st.code(fid)

    with tab_report:
        # Gather linked hunt + findings for deterministic draft generation
        hunt = store.load(ArtifactType.HUNT_PACKAGE, run.linked_hunt_id) if run.linked_hunt_id else None
        findings = []
        for fid in (run.findings_created or []):
            f = store.load(ArtifactType.FINDING, fid)
            if f:
                findings.append(f)

        c1, c2 = st.columns([1, 1])
        with c1:
            st.write(f"**Report status:** {getattr(run, 'report_approval', ApprovalStatus.DRAFT).value}")
        with c2:
            if getattr(run, "report_approval", ApprovalStatus.DRAFT) == ApprovalStatus.DRAFT:
                if st.button("✅ Mark Report Approved", type="primary", width="stretch", key="mark_report_approved"):
                    run.report_approval = ApprovalStatus.APPROVED
                    run.meta.updated_at = workflow.utc_now()
                    store.save(run, ArtifactType.RUN, run.meta.id)
                    st.session_state["toast"] = "Approved run report."
                    st.rerun()
            else:
                # Use the run id for stable widget identity in this view.
                st.button("✅ Approved", width="stretch", disabled=True, key=f"approved_{run.meta.id}")

        if st.button("🧾 Generate / Refresh Report Draft", type="primary", key="gen_refresh_report"):
            # Load linked intel (optional) to populate report narrative fields
            intel = None
            try:
                if hunt and getattr(hunt, "linked_intel_id", None):
                    intel = store.load(ArtifactType.INTEL_BRIEF, hunt.linked_intel_id)
            except Exception:
                intel = None

            run.report_markdown = workflow.render_run_ir_report_markdown(run, hunt, findings, intel=intel)
            run.report_approval = ApprovalStatus.DRAFT
            run.meta.updated_at = workflow.utc_now()
            store.save(run, ArtifactType.RUN, run.meta.id)
            st.session_state["toast"] = "Generated report draft (editable)."
            st.rerun()

        # Editable report body
        if getattr(run, "report_approval", ApprovalStatus.DRAFT) == ApprovalStatus.APPROVED:
            st.markdown(run.report_markdown or "(no report saved)")
        else:
            with st.form("run_report_edit_form", clear_on_submit=False):
                run.report_markdown = st.text_area("Run report markdown", value=getattr(run, "report_markdown", ""), height=420)
                if st.form_submit_button("💾 Save Report Draft", type="primary"):
                    run.meta.updated_at = workflow.utc_now()
                    store.save(run, ArtifactType.RUN, run.meta.id)
                    st.session_state["toast"] = "Saved report draft."
                    st.rerun()

        if run.report_markdown:
            st.markdown("---")
            if st.button("Export Run Report", type="primary", width="stretch", key="export_run_report"):
                violations = workflow.validate_no_tbd(run.report_markdown)
                if violations:
                    st.error("Executive export blocked. Fix placeholders first:\n- " + "\n- ".join(violations))
                    return
                export_path = store.export_markdown(ArtifactType.RUN, run.meta.id, run.report_markdown)
                st.success(f"Exported to {export_path}")
                st.download_button(
                    "Download export",
                    data=Path(export_path).read_bytes(),
                    file_name=os.path.basename(export_path),
                    mime="text/markdown",
                    key=f"dl_runrep_{run.meta.id}",
                )


def render_findings():
    store = get_storage()
    from byo_secai.state.run import get_active_run_id
    from byo_secai.state.view_state import state_get, state_set
    run_ctx = get_active_run_id()

    st.subheader("Findings")

    ids = store.list_ids(ArtifactType.FINDING)
    if not ids:
        spark_warn("No findings yet. Run a hunt first.")
        return

    # Scoping matters once you have lots of artifacts.
    # Default: active run (most precise). Also allow active hunt (all runs) or all.
    hunt_ctx = (st.session_state.get("active_hunt_id") or "").strip()
    scope = st.radio(
        "Scope",
        options=["Active Run", "Active Hunt", "All"],
        horizontal=True,
        index=0,
        help="Active Run = only findings for the currently selected run. Active Hunt = findings across all runs of the linked hunt.",
        key=f"findings_scope_{run_ctx}",
    )

    ids_ctx: list[str] = []
    if scope == "Active Run" and run_ctx and run_ctx != "no_run":
        for fid in ids:
            f = store.load(ArtifactType.FINDING, fid)
            if not f:
                continue
            try:
                _repair_finding_links(store, f)
            except Exception:
                pass
            if getattr(f, "linked_run_id", "") == run_ctx:
                ids_ctx.append(fid)
        if ids_ctx:
            st.caption(f"Showing {len(ids_ctx)} finding(s) for active run `{run_ctx}`")
        else:
            st.info(f"No findings are linked to active run `{run_ctx}`. Switch scope to Active Hunt or All.")

    elif scope == "Active Hunt" and hunt_ctx:
        for fid in ids:
            f = store.load(ArtifactType.FINDING, fid)
            if not f:
                continue
            try:
                _repair_finding_links(store, f)
            except Exception:
                pass
            if getattr(f, "linked_hunt_id", "") == hunt_ctx:
                ids_ctx.append(fid)
        st.caption(f"Showing {len(ids_ctx)} finding(s) for active hunt `{hunt_ctx}`")

    display_ids = ids_ctx if ids_ctx else ids

    _default = state_get("Findings", run_ctx, "selected_finding", display_ids[0] if display_ids else "")
    try:
        _idx = display_ids.index(_default) if _default in display_ids else 0
    except Exception:
        _idx = 0
    selected = st.selectbox("Select Finding", display_ids, index=_idx, key=f"finding_selected_{run_ctx}")
    state_set("Findings", run_ctx, "selected_finding", selected)
    finding = store.load(ArtifactType.FINDING, selected)

    try:
        _repair_finding_links(store, finding)
    except Exception:
        pass

    try:
        if bool(getattr(get_cfg(), "show_breadcrumbs", False)):
            render_artifact_chain_banner(st, intel_id=getattr(finding, "linked_intel_id", ""), hunt_id=getattr(finding, "linked_hunt_id", ""), run_id=getattr(finding, "linked_run_id", ""), finding_id=finding.meta.id)
    except Exception:
        pass

    c1, c2, c3 = st.columns([2, 1, 1])
    with c1:
        st.write(f"**Status:** {getattr(finding, 'approval', ApprovalStatus.DRAFT).value}  |  **Severity:** {finding.severity.value}  |  **Confidence:** {finding.confidence}")
    with c2:
        if st.button("➡️ Generate ADS", type="primary", width="stretch"):
            st.session_state["ads_seed_finding"] = finding.meta.id
            st.session_state["_nav_target"] = "ADS"
            st.rerun()
    with c3:
        if getattr(finding, "approval", ApprovalStatus.DRAFT) == ApprovalStatus.DRAFT:
            if st.button("✅ Mark Approved", type="primary", width="stretch", key=f"finding_mark_approved_{finding.meta.id}"):
                finding.approval = ApprovalStatus.APPROVED
                finding.meta.updated_at = workflow.utc_now()
                store.save(finding, ArtifactType.FINDING, finding.meta.id)
                st.session_state["toast"] = "Approved finding."
                st.rerun()
        else:
            st.button("✅ Approved", width="stretch", disabled=True, key=f"approved_{finding.meta.id}")

    st.markdown("---")
    tab_report, tab_edit, tab_diff, tab_suggest = st.tabs(["Rendered Report", "Edit Draft", "Diff (Hunt ↔ ADS)", "Assistant Suggestions"])
    with tab_report:
        st.markdown(workflow.render_finding_markdown(finding))

    with tab_edit:
        if getattr(finding, "approval", ApprovalStatus.DRAFT) == ApprovalStatus.APPROVED:
            spark_warn("This Finding is **Approved**. Edits are allowed and will update the approved artifact.")

        with st.form("finding_edit_form", clear_on_submit=False):
            keep_approved = True
            if getattr(finding, "approval", ApprovalStatus.DRAFT) == ApprovalStatus.APPROVED:
                keep_approved = st.checkbox("Keep status as Approved", value=True)

            finding.meta.title = st.text_input("Title", value=finding.meta.title)
            finding.description = st.text_area("Description", value=finding.description, height=160)
            finding.confidence = st.selectbox("Confidence", options=["Low","Medium","High"], index=["Low","Medium","High"].index(finding.confidence) if finding.confidence in ["Low","Medium","High"] else 1)
            sev_vals = list(Severity)
            finding.severity = st.selectbox(
                "Severity",
                options=sev_vals,
                index=sev_vals.index(finding.severity) if finding.severity in sev_vals else 1,
                format_func=lambda s: s.value,
            )
            ev = "\n".join(finding.evidence or [])
            ev = st.text_area("Evidence (one per line)", value=ev, height=140)
            finding.evidence = [e.strip() for e in (ev or "").splitlines() if e.strip()]
            mt = "\n".join(finding.mitre_techniques or [])
            mt = st.text_area("MITRE Techniques (one per line)", value=mt, height=120)
            finding.mitre_techniques = [t.strip() for t in (mt or "").splitlines() if t.strip()]
            finding.analyst_notes = st.text_area("Analyst notes", value=finding.analyst_notes, height=140)
            if st.form_submit_button("💾 Save", type="primary"):
                finding.meta.updated_at = workflow.utc_now()
                workflow.record_history(finding.meta, "save", actor=(st.session_state.get("operator") or ""))
                if getattr(finding, "approval", ApprovalStatus.DRAFT) == ApprovalStatus.APPROVED and not keep_approved:
                    finding.approval = ApprovalStatus.DRAFT
                store.save(finding, ArtifactType.FINDING, finding.meta.id)
                st.session_state["toast"] = "Saved finding."
                st.rerun()


def render_ads():
    store = get_storage()
    from byo_secai.state.run import get_active_run_id
    from byo_secai.state.view_state import state_get, state_set
    run_ctx = get_active_run_id()

    st.subheader("Alert & Detection Strategy")

    finding_ids = store.list_ids(ArtifactType.FINDING)
    if not finding_ids:
        spark_warn("No findings yet.")
        return

    # Scope control: default to the current run context, but allow widening.
    # This prevents the ADS page from feeling "stuck" when multiple Findings exist.
    scopes = ["Active Run", "Active Hunt", "All"]
    default_scope = "All"
    if run_ctx and run_ctx != "no_run":
        default_scope = "Active Run"
    scope = st.radio("Scope", scopes, index=scopes.index(default_scope), horizontal=True, key=f"ads_scope_{run_ctx}")

    active_hunt_id = st.session_state.get("active_hunt_id", "")
    display_finding_ids: list[str] = []
    if scope == "Active Run" and run_ctx and run_ctx != "no_run":
        for fid in finding_ids:
            f = store.load(ArtifactType.FINDING, fid)
            if f and getattr(f, "linked_run_id", "") == run_ctx:
                display_finding_ids.append(fid)
        st.caption(f"Showing {len(display_finding_ids)} finding(s) for active run `{run_ctx}`")
    elif scope == "Active Hunt" and active_hunt_id:
        for fid in finding_ids:
            f = store.load(ArtifactType.FINDING, fid)
            if f and getattr(f, "linked_hunt_id", "") == active_hunt_id:
                display_finding_ids.append(fid)
        st.caption(f"Showing {len(display_finding_ids)} finding(s) for active hunt `{active_hunt_id}`")
    else:
        display_finding_ids = list(finding_ids)

    # If the chosen scope has no findings (e.g., active run cleared), fall back to All.
    if not display_finding_ids:
        display_finding_ids = list(finding_ids)
        st.caption("Showing %s finding(s) (All)" % len(display_finding_ids))

    seed = st.session_state.pop("ads_seed_finding", None)
    default_index = 0
    if seed and seed in display_finding_ids:
        default_index = display_finding_ids.index(seed)

    _def_f = state_get("ADS", run_ctx, "seed_finding", display_finding_ids[default_index] if display_finding_ids else "")
    if seed and seed in display_finding_ids:
        _def_f = seed
    try:
        _f_idx = display_finding_ids.index(_def_f) if _def_f in display_finding_ids else default_index
    except Exception:
        _f_idx = default_index
    finding_choice = st.selectbox("Finding", display_finding_ids, index=_f_idx, key=f"ads_finding_{run_ctx}")
    state_set("ADS", run_ctx, "seed_finding", finding_choice)
    finding = store.load(ArtifactType.FINDING, finding_choice)
    try:
        _repair_finding_links(store, finding)
    except Exception:
        pass

    # Keep chain context available across pages.
    st.session_state["active_hunt_id"] = getattr(finding, "linked_hunt_id", "") or st.session_state.get("active_hunt_id", "")
    st.session_state["active_intel_id"] = getattr(finding, "linked_intel_id", "") or st.session_state.get("active_intel_id", "")

    if st.button("Generate ADS draft", type="primary"):
        llm = get_llm_for_generate()
        aid = store.new_id("ads")
        ads = workflow.generate_ads(llm, aid, finding)
        store.save(ads, ArtifactType.ADS, ads.meta.id)
        st.success(f"Created {ads.meta.id} ({llm.__class__.__name__})")

    ids = store.list_ids(ArtifactType.ADS)
    if not ids:
        spark_info("No ADS artifacts yet.")
        return

    # Scope ADS selection to the current finding (best) or active run (fallback).
    ads_ids_ctx: list[str] = []
    try:
        for aid in ids:
            a = store.load(ArtifactType.ADS, aid)
            if not a:
                continue
            if finding_choice and getattr(a, "linked_finding_id", "") == finding_choice:
                ads_ids_ctx.append(aid)
        if not ads_ids_ctx and run_ctx and run_ctx != "no_run":
            for aid in ids:
                a = store.load(ArtifactType.ADS, aid)
                if a and getattr(a, "linked_run_id", "") == run_ctx:
                    ads_ids_ctx.append(aid)
    except Exception:
        ads_ids_ctx = []

    display_ads_ids = ads_ids_ctx if ads_ids_ctx else ids
    if ads_ids_ctx:
        st.caption(f"Showing {len(display_ads_ids)} ADS artifact(s) for current context")

    _def_ads = state_get("ADS", run_ctx, "selected_ads", display_ads_ids[0] if display_ads_ids else "")
    try:
        _a_idx = display_ads_ids.index(_def_ads) if _def_ads in display_ads_ids else 0
    except Exception:
        _a_idx = 0
    selected = st.selectbox("Select ADS", display_ads_ids, index=_a_idx, key=f"ads_selected_{run_ctx}")
    state_set("ADS", run_ctx, "selected_ads", selected)
    ads = store.load(ArtifactType.ADS, selected)

    try:
        _repair_ads_links(store, ads)
    except Exception:
        pass

    try:
        if bool(getattr(get_cfg(), "show_breadcrumbs", False)):
            render_artifact_chain_banner(st, intel_id=getattr(ads, "linked_intel_id", ""), hunt_id=getattr(ads, "linked_hunt_id", ""), run_id=getattr(ads, "linked_run_id", ""), finding_id=getattr(ads, "linked_finding_id", ""), ads_id=ads.meta.id)
    except Exception:
        pass

    c1, c2 = st.columns([1, 1])
    with c1:
        st.write(f"**Status:** {getattr(ads, 'approval', ApprovalStatus.DRAFT).value}")
        st.caption(f"Linked Finding: `{ads.linked_finding_id}`")
        st.caption(f"Lifecycle: **{getattr(ads, 'lifecycle_status', '') or 'Draft'}**")
    with c2:
        if getattr(ads, "approval", ApprovalStatus.DRAFT) == ApprovalStatus.DRAFT:
            if st.button("✅ Mark Approved", type="primary", width="stretch", key=f"finding_mark_approved_{finding.meta.id}"):
                # Validation gate for embedded CQL (if present).
                # ADS.cql is the canonical field in v1, but may hold other query languages (e.g., KQL)
                # depending on which query builder produced the draft. Only run CQL drift validation
                # when the content looks like CrowdStrike LogScale CQL (#event_simpleName / groupBy()).
                violations: list[str] = []
                qtxt = (getattr(ads, "cql", "") or "").strip()
                if qtxt:
                    looks_like_cql = ("#event_simpleName" in qtxt) or ("| groupBy(" in qtxt)
                    if looks_like_cql:
                        errs = workflow.validate_cql_query(qtxt)
                        if errs:
                            violations.append("ADS CQL: " + "; ".join(errs))
                if violations:
                    st.error("Validation failed (fix before approving):\n- " + "\n- ".join(violations))
                else:
                    ads.approval = ApprovalStatus.APPROVED
                    ads.meta.updated_at = workflow.utc_now()
                    store.save(ads, ArtifactType.ADS, ads.meta.id)
                    st.session_state["toast"] = "Approved ADS."
                    st.rerun()
        else:
            st.button("✅ Approved", width="stretch", disabled=True, key=f"approved_{finding.meta.id}")

    st.markdown("---")
    tab_report, tab_edit, tab_diff, tab_suggest = st.tabs(["Rendered Report", "Edit Draft", "Diff (Hunt ↔ ADS)", "Assistant Suggestions"])
    with tab_report:
        cfg = get_cfg()
        inputs = {"ads_id": ads.meta.id, "updated_at": getattr(ads.meta, "updated_at", ""), "approval": getattr(ads, "approval", ApprovalStatus.DRAFT).value}
        try:
            from byo_secai.payload_cache import payload_get, payload_set
            from byo_secai.state.run import get_active_run_id
            run_id = get_active_run_id()
        except Exception:
            payload_get = None  # type: ignore
            payload_set = None  # type: ignore
            run_id = "none"

        cached_md = None
        if payload_get:
            cached_md = payload_get("ADS:rendered", run_id, inputs)

        # Optional HTML snapshot cache
        try:
            from byo_secai.render_cache import load_html, save_html_from_markdown
            import streamlit.components.v1 as components
        except Exception:
            load_html = None  # type: ignore
            save_html_from_markdown = None  # type: ignore
            components = None  # type: ignore

        if getattr(cfg, "render_cache_enabled", False) and load_html and components:
            with step_timer("render_cache:load_html:ads"):
                html = load_html(cfg.data_dir, ArtifactType.ADS.value, ads.meta.id, getattr(ads.meta, "updated_at", ""))
            if html:
                components.html(html, height=900, scrolling=True)
            else:
                if cached_md and isinstance(cached_md, str):
                    md = cached_md
                else:
                    with step_timer("render:ads_markdown"):
                        md = workflow.render_ads_markdown(ads)
                    if payload_set:
                        payload_set("ADS:rendered", run_id, inputs, md)
                if save_html_from_markdown:
                    with step_timer("render_cache:save_html:ads"):
                        save_html_from_markdown(cfg.data_dir, ArtifactType.ADS.value, ads.meta.id, getattr(ads.meta, "updated_at", ""), md)
                components.html(load_html(cfg.data_dir, ArtifactType.ADS.value, ads.meta.id, getattr(ads.meta, "updated_at", "")) or "", height=900, scrolling=True)
        else:
            if cached_md and isinstance(cached_md, str):
                st.markdown(cached_md)
            else:
                with step_timer("render:ads_markdown"):
                    md = workflow.render_ads_markdown(ads)
                if payload_set:
                    payload_set("ADS:rendered", run_id, inputs, md)
                st.markdown(md)

        st.markdown("---")
        # Executive export gate: block exports if placeholders exist
        md_export = cached_md if (cached_md and isinstance(cached_md, str)) else workflow.render_ads_markdown(ads)
        if st.button("Export ADS (Executive)", type="primary", width="stretch", key=f"exp_ads_{ads.meta.id}"):
            violations = workflow.validate_no_tbd(md_export)
            if violations:
                st.error("Executive export blocked. Fix placeholders first:\n- " + "\n- ".join(violations))
            else:
                export_path = store.export_markdown(ArtifactType.ADS, ads.meta.id, md_export)
                st.success(f"Exported to {export_path}")
                st.download_button(
                    "Download export",
                    data=Path(export_path).read_bytes(),
                    file_name=os.path.basename(export_path),
                    mime="text/markdown",
                    key=f"dl_ads_{ads.meta.id}",
                )

    with tab_edit:
        keep_approved = True
        if getattr(ads, "approval", ApprovalStatus.DRAFT) == ApprovalStatus.APPROVED:
            spark_warn("This ADS is **Approved**. Edits are allowed and will update the approved artifact.")

        # Pull linked finding (for Categorization context)
        linked_finding = None
        try:
            if getattr(ads, "linked_finding_id", ""):
                linked_finding = store.load(ArtifactType.FINDING, ads.linked_finding_id)
        except Exception:
            linked_finding = None

        mitre = []
        if linked_finding is not None:
            mitre = list(getattr(linked_finding, "mitre_techniques", []) or [])

        with st.form("ads_edit_form", clear_on_submit=False):
            if getattr(ads, "approval", ApprovalStatus.DRAFT) == ApprovalStatus.APPROVED:
                keep_approved = st.checkbox("Keep status as Approved", value=True)
            else:
                keep_approved = True

            st.caption("Edit the report sections. Approved artifacts can be edited; use the checkbox above to keep or revert status.")

            # Title (metadata)
            ads.meta.title = st.text_input("Title", value=ads.meta.title)

            st.markdown("## Goal")
            ads.detection_goal = st.text_area(
                "Goal (what we are trying to detect / prevent)",
                value=ads.detection_goal,
                height=120,
            )

            st.markdown("## Categorization")
            st.caption("Auto-populated from the linked Finding by default; editable here for ADS ownership and long-term drift control.")
            # Seed ADS MITRE fields on first open if empty
            if (not getattr(ads, "mitre_techniques", None)) and mitre:
                ads.mitre_techniques = list(mitre)
            tactics_txt = "\n".join(getattr(ads, "mitre_tactics", []) or [])
            techs_txt = "\n".join(getattr(ads, "mitre_techniques", []) or [])
            tactics_txt = st.text_area("Tactic(s) (one per line)", value=tactics_txt, height=90)
            techs_txt = st.text_area("Technique(s) (one per line)", value=techs_txt, height=110)
            ads.mitre_tactics = [t.strip() for t in (tactics_txt or "").splitlines() if t.strip()]
            ads.mitre_techniques = [t.strip() for t in (techs_txt or "").splitlines() if t.strip()]

            st.markdown("## Strategy Abstract")
            ads.logic = st.text_area(
                "Strategy abstract / detection logic (high level)",
                value=ads.logic,
                height=180,
            )

            st.markdown("## Technical Context")
            ads.technical_context = st.text_area(
                "Technical context (detailed background for responders)",
                value=getattr(ads, "technical_context", ""),
                height=200,
            )

            st.markdown("## Blind Spots and Assumptions")
            st.markdown("### Visibility Requirements")
            # Keep the structured telemetry list, but also allow a rich, editable visibility requirements subsection.
            tele = "\n".join(ads.telemetry or [])
            tele = st.text_area("Telemetry required (one per line)", value=tele, height=120)
            ads.telemetry = [t.strip() for t in (tele or "").splitlines() if t.strip()]

            ads.visibility_requirements = st.text_area(
                "Visibility Requirements (narrative)",
                value=getattr(ads, "visibility_requirements", ""),
                height=200,
            )

            st.markdown("### Blind spots")
            ads.blind_spots = st.text_area(
                "Blind spots (what can cause this ADS to not fire?)",
                value=getattr(ads, "blind_spots", ""),
                height=170,
            )

            st.markdown("## Lifecycle")
            st.caption("Operational state (separate from content approval).")
            from byo_secai.models import ADSLifecycleStatus
            cur = getattr(ads, "lifecycle_status", ADSLifecycleStatus.DRAFT)
            ads.lifecycle_status = st.selectbox(
                "Lifecycle status",
                options=[s for s in ADSLifecycleStatus],
                index=[s for s in ADSLifecycleStatus].index(cur) if cur in [s for s in ADSLifecycleStatus] else 0,
                format_func=lambda x: x.value,
            )
            ads.detection_id = st.text_input("Detection ID (external reference)", value=getattr(ads, "detection_id", ""))

            st.markdown("## False Positives")
            ads.tuning = st.text_area("False positives / tuning notes", value=ads.tuning, height=140)

            st.markdown("## Validation")
            ads.validation = st.text_area("Validation plan / tests", value=ads.validation, height=140)

            st.markdown("## Response")
            ads.deployment_notes = st.text_area("Response / deployment notes", value=ads.deployment_notes, height=140)

            st.markdown("## Example ADS Query")
            st.markdown("### CrowdStrike Detection Query")
            ads.cql = st.text_area("Example LogScale CQL", value=ads.cql, height=220)

            submitted = st.form_submit_button("💾 Save", type="primary")
            if submitted:
                # Validation gate (warn-only) for embedded CQL
                if ads.cql.strip():
                    errs = workflow.validate_cql_query(ads.cql)
                    if errs:
                        st.warning("Saved, but validation warnings exist: " + "; ".join(errs))
                ads.meta.updated_at = workflow.utc_now()

                # Lifecycle timestamps (set when first entering a state)
                try:
                    from byo_secai.models import ADSLifecycleStatus
                    now_ts = ads.meta.updated_at
                    ls = getattr(ads, "lifecycle_status", ADSLifecycleStatus.DRAFT)
                    if ls == ADSLifecycleStatus.PROMOTED and not getattr(ads, "promoted_at", ""):
                        ads.promoted_at = now_ts
                    if ls == ADSLifecycleStatus.DEPLOYED and not getattr(ads, "deployed_at", ""):
                        ads.deployed_at = now_ts
                    if ls == ADSLifecycleStatus.TUNED and not getattr(ads, "tuned_at", ""):
                        ads.tuned_at = now_ts
                    if ls == ADSLifecycleStatus.RETIRED and not getattr(ads, "retired_at", ""):
                        ads.retired_at = now_ts
                except Exception:
                    pass
                workflow.record_history(ads.meta, "save", actor=(st.session_state.get("operator") or ""))
                if getattr(ads, "approval", ApprovalStatus.DRAFT) == ApprovalStatus.APPROVED and not keep_approved:
                    ads.approval = ApprovalStatus.DRAFT
                store.save(ads, ArtifactType.ADS, ads.meta.id)
                st.session_state["toast"] = "Saved ADS."
                st.rerun()

    with tab_diff:
        # Diff view: Hunt queries vs ADS logic/query
        try:
            f = store.load(ArtifactType.FINDING, ads.linked_finding_id) if getattr(ads, "linked_finding_id", "") else None
            r = store.load(ArtifactType.RUN, getattr(f, "linked_run_id", "")) if f else None
            h = store.load(ArtifactType.HUNT_PACKAGE, getattr(r, "linked_hunt_id", "")) if r else None
        except Exception:
            f, r, h = None, None, None

        if not h:
            spark_info("No linked Hunt Package found for diff. (Need Finding → Run → Hunt linkage.)")
        else:
            left, right = st.columns([1, 1])
            with left:
                st.markdown("### Hunt Package Queries")
                for q in getattr(h, "queries", []) or []:
                    st.markdown(f"**{q.title}**")
                    if q.description:
                        st.caption(q.description)
                    st.code((q.query or "").rstrip(), language="cql")
                    st.markdown("---")
            with right:
                st.markdown("### ADS Logic + Query")
                st.markdown("**Strategy Abstract**")
                st.code((getattr(ads, "logic", "") or "").rstrip())
                st.markdown("**Detection Query**")
                st.code((getattr(ads, "cql", "") or "").rstrip(), language="cql")

                # Lightweight mismatch hints (deterministic)
                st.markdown("---")
                st.markdown("### Drift hints")
                hunt_titles = " ".join([(q.title or "") for q in (getattr(h, "queries", []) or [])]).lower()
                ads_text = f"{getattr(ads,'logic','')}\n{getattr(ads,'cql','')}".lower()
                missing = []
                for token in ["rclone", "psexec", "ntds", "wbadmin", "setup_wm", "creds", "dll"]:
                    if token in hunt_titles and token not in ads_text:
                        missing.append(token)
                if missing:
                    st.warning("Potential gaps: hunt mentions these tokens but ADS does not: " + ", ".join(sorted(set(missing))))
                else:
                    spark_ok("No obvious drift tokens detected (heuristic check).")

    with tab_suggest:
        spark_info("Assistant Suggestions are not implemented yet in this phase.")


def render_settings():
    cfg = get_cfg()
    store = get_storage()

    st.subheader("Settings")
    st.caption("Settings are split into subviews so we only execute the section you're working in.")

    from importlib import import_module

    views = {
        "LLM + Templates": "byo_secai.views.settings.llm",
        "Hunt defaults": "byo_secai.views.settings.hunt_defaults",
        "Local RAG": "byo_secai.views.settings.local_rag",
        "Network": "byo_secai.views.settings.network",
        "Web Search": "byo_secai.views.settings.web_search",
        "Demo utilities": "byo_secai.views.settings.demo_utils",
        "Debug": "byo_secai.views.settings.debug",
    }

    choice = st.radio(
        "Settings sections",
        list(views.keys()),
        horizontal=True,
        key="settings_subview",
    )

    mod = import_module(views[choice])
    # Each module exposes render(...)
    if choice in ("Local RAG", "Demo utilities"):
        mod.render(cfg, store)
    else:
        mod.render(cfg)

    st.markdown("---")
    left, right = st.columns([1, 2])
    with left:
        if st.button("Save settings", type="primary", use_container_width=True):
            from byo_secai.config import save_config_yaml
            p = save_config_yaml(cfg)
            st.success(f"Saved to {p}")
    with right:
        st.caption(
            "Settings are persisted to data/config.yaml so they survive restarts. "
            "Secrets (API keys) are loaded from config.yaml but are not written by the UI."
        )


def render_workspace():
    cfg = get_cfg()
    llm = get_llm()
    rag = get_rag()

    st.subheader("Workspace")
    st.caption("Chat-first workspace with per-notebook memory, optional RAG per message, and inline notes/query blocks.")

    store = NotebookStore(cfg.data_dir)

    # --- notebook selection / creation ---
    ids = store.list_ids()
    top_l, top_r = st.columns([2, 2])
    with top_l:
        selected = st.selectbox("Notebook", options=["(new)"] + ids, index=0)
    with top_r:
        new_title = st.text_input("Title", value="", placeholder="Threat Hunt Workspace - ...")
        new_id = st.text_input("New notebook ID", value="", placeholder="workspace_YYYYMMDD")
        if st.button("Create", type="primary"):
            nid = (new_id or "").strip() or f"workspace_{_time.strftime('%Y%m%d')}"
            nb = store.create(nid, title=(new_title.strip() or nid))
            st.session_state["workspace_active"] = nb.notebook_id
            spark_ok("Notebook created")
            _rerun()

    active_id = st.session_state.get("workspace_active")
    if selected != "(new)":
        active_id = selected
        st.session_state["workspace_active"] = active_id

    if not active_id:
        spark_info("Create a notebook to start.")
        return

    nb = store.load(active_id)
    if nb is None:
        spark_warn("Notebook not found. Create a new one.")
        return

    # --- top actions ---
    a1, a2, a3 = st.columns([1, 1, 2])
    with a1:
        if st.button("Save", type="primary"):
            store.save(nb)
            spark_ok("Saved")
    with a2:
        if st.button("Export MD", type="primary"):
            md = nb_to_markdown(nb)
            out_dir = Path(cfg.data_dir) / "exports" / "workspace"
            out_dir.mkdir(parents=True, exist_ok=True)
            out_path = out_dir / f"{nb.notebook_id}.md"
            out_path.write_text(md, encoding="utf-8")
            st.success(f"Exported: {out_path}")
            st.code(md, language="markdown")
    with a3:
        nb.title = st.text_input("Notebook title", value=nb.title)

    st.markdown("---")

    # --- controls ---
    c1, c2, c3, c4, c5 = st.columns([1, 1, 1, 1, 1])
    with c1:
        use_rag = st.checkbox(
            "Use RAG",
            value=bool(getattr(cfg, "rag_enabled", True)),
            help="Retrieves context from your Knowledge Library before answering.",
        )
    with c2:
        web_default = st.checkbox(
            "Web",
            value=bool(getattr(cfg, "web_enabled_by_default", False)),
            help=(
                "If enabled, the chat can fetch public-web snippets for time-sensitive questions. "
                "You can override per message below. To make this default-on, set web_enabled_by_default: true in config.yaml."
            ),
        )
    with c3:
        max_ctx_msgs = st.number_input("Memory depth", min_value=4, max_value=40, value=12, step=1)
    with c4:
        composer_mode = st.selectbox("Add", options=["Chat", "Note", "Query"], index=0)
    with c5:
        if st.button("Clear session", type="secondary"):
            nb.cells = []
            store.save(nb)
            _rerun()

    # --- render timeline ---
    def _cell_key(ix: int) -> str:
        return f"ws_{nb.notebook_id}_{ix}"

    for idx, c in enumerate(nb.cells):
        ctype = (c.cell_type or "").strip().lower()

        # Legacy mapping
        if ctype in {"markdown", "notes"}:
            ctype = "note"

        if ctype == "chat":
            role = ((c.meta or {}).get("role") or "assistant").strip().lower()
            try:
                with st.chat_message("user" if role == "user" else "assistant"):
                    st.markdown((c.content or "").strip() or " ")
                    retrieved = (c.meta or {}).get("retrieved") or []
                    if retrieved and role != "user":
                        with st.expander("Retrieved context", expanded=False):
                            for r in retrieved:
                                if not isinstance(r, dict):
                                    continue
                                src = r.get("source") or "(unknown)"
                                score = r.get("score")
                                txt = (r.get("text") or "").strip()
                                if score is not None:
                                    st.markdown(f"- ({src} | {score}) {txt}")
                                else:
                                    st.markdown(f"- ({src}) {txt}")
                    web_sources = (c.meta or {}).get("web_sources") or []
                    if web_sources and role != "user":
                        with st.expander("Web sources", expanded=False):
                            for i, s in enumerate(web_sources, start=1):
                                if not isinstance(s, dict):
                                    continue
                                title = (s.get("title") or "(untitled)").strip()
                                url = (s.get("url") or "").strip()
                                snippet = (s.get("snippet") or "").strip()
                                if url:
                                    st.markdown(f"[{i}] [{title}]({url})")
                                else:
                                    st.markdown(f"[{i}] {title}")
                                if snippet:
                                    st.caption(snippet)
            except Exception:
                st.markdown(f"**{role}:** {(c.content or '').strip()}")
            continue

        if ctype == "note":
            with st.container():
                st.markdown((c.content or "").strip() or "")
            continue

        if ctype == "query":
            lang = (c.meta or {}).get("language") or "text"
            st.code((c.content or "").rstrip(), language=str(lang).lower())
            continue

        # fallback
        st.markdown((c.content or "").strip() or "")

    st.markdown("---")

    # --- composer ---
    if composer_mode == "Chat":
        # Per-message override: users can choose local-only vs local+web for the next send.
        use_web_for_next = st.checkbox(
            "Use web for next message",
            value=bool(web_default),
            help="If checked, BYO-SecAI will fetch small snippets from the selected web provider and ask the LLM to answer with citations like [1], [2].",
            key=f"ws_use_web_next_{nb.notebook_id}",
        )
        user_msg = st.chat_input("Ask anything (hunts, detections, investigations, artifacts)...")
        if user_msg:
            # append user chat cell
            nb.cells.append(NotebookCell(cell_id=f"cell_{len(nb.cells)+1:03d}", cell_type="chat", content=user_msg, meta={"role": "user"}))

            # Gather recent chat messages for memory
            recent_chat = []
            for cc in reversed(nb.cells):
                if (cc.cell_type or "").strip().lower() != "chat":
                    continue
                role = ((cc.meta or {}).get("role") or "assistant").strip().lower()
                txt = (cc.content or "").strip()
                if not txt:
                    continue
                recent_chat.append((role, txt))
                if len(recent_chat) >= int(max_ctx_msgs):
                    break
            recent_chat = list(reversed(recent_chat))

            convo_lines = []
            for role, txt in recent_chat:
                convo_lines.append(f"{role.upper()}: {txt}")

            # RAG retrieval
            retrieved_meta = []
            ctx_lines = []
            if use_rag and rag is not None:
                try:
                    for ch, score in rag.query(user_msg, top_k=int(getattr(cfg, "rag_top_k", 6))):
                        src = f"{ch.source_type}:{ch.source_id}"
                        ctx_lines.append(f"- ({src} | {score:.3f}) {ch.text}")
                        retrieved_meta.append({"source": src, "score": f"{score:.3f}", "text": ch.text})
                except Exception:
                    pass

            system = (
                "You are a threat hunting assistant inside BYO-SecAI. "
                "Be practical and operational. "
                "If Knowledge Library context is provided, ground your answer in it. "
                "If web sources are provided, cite them inline using bracket numbers like [1], [2] and do not invent sources. "
                "If a user asks you to read a URL, you may only claim you read it if page text was fetched and included below. "
                "Never claim you checked internal systems unless the user provided that data. "
                "Do not invent telemetry fields. If unsure, say what you would verify."
            )
            # Always-allowed URL reading (user-provided URLs) for Workspace.
            # This does NOT perform a web search; it only fetches the text of URLs the user pasted.
            page_texts: list[tuple[str, str]] = []
            try:
                allow_url_read = bool(getattr(cfg, "workspace_url_read_enabled", True))
                if allow_url_read:
                    urls_in_msg = re.findall(r"https?://\S+", user_msg or "")
                    wants_page = any(k in (user_msg or "").lower() for k in [
                        "read this", "summarize", "review this", "what does this say", "analyze this page",
                        "create a description", "describe this article", "use this article",
                    ])
                    if urls_in_msg and wants_page:
                        from byo_secai.web_search import fetch_url_text
                        for u in urls_in_msg[:2]:
                            txt = fetch_url_text(
                                u,
                                timeout_s=int(getattr(cfg, "web_timeout_s", 15)),
                                max_chars=int(getattr(cfg, "max_source_chars", 6000)),
                                cache_ttl_s=int(getattr(cfg, "web_cache_ttl_s", 1800)),
                            cfg=cfg,
                            )
                            if txt:
                                page_texts.append((u, txt))
                            else:
                                st.warning(
                                    "Couldn’t ingest this page with safe defaults. "
                                    "Recommended: Print → Save as PDF (or copy to .txt/.md) and upload it. "
                                    "Optional (advanced): enable third-party fetch fallback (r.jina.ai) or JS-rendered ingestion (Playwright) in Settings → Network, then retry."
                                )
            except Exception:
                page_texts = []



            # Optional web search / page fetch
            web_sources = []
            web_lines = []
            if bool(use_web_for_next):
                try:
                    web_sources = search_web(
                        query=user_msg,
                        provider_name=str(getattr(cfg, "web_provider", "duckduckgo")),
                        max_results=int(getattr(cfg, "web_max_results", 5)),
                        timeout_s=int(getattr(cfg, "web_timeout_s", 15)),
                        keys={
                            "bing_api_key": str(getattr(cfg, "bing_api_key", "")),
                            "tavily_api_key": str(getattr(cfg, "tavily_api_key", "")),
                            "serpapi_api_key": str(getattr(cfg, "serpapi_api_key", "")),
                        },
                        cache_ttl_s=int(getattr(cfg, "web_cache_ttl_s", 1800)),
                        cfg=cfg,
                    )
                except Exception:
                    web_sources = []

                # Optional: fetch full page text (web mode).
                page_texts_web: list[tuple[str, str]] = []
                try:
                    if bool(getattr(cfg, "web_fetch_pages", False)):
                        urls = re.findall(r"https?://\S+", user_msg)
                        wants_page = any(k in (user_msg or "").lower() for k in ["read this", "summarize", "review this", "what does this say", "analyze this page"])
                        if wants_page and urls:
                            from byo_secai.web_search import fetch_url_text
                            for u in urls[:2]:
                                txt = fetch_url_text(
                                    u,
                                    timeout_s=int(getattr(cfg, "web_timeout_s", 15)),
                                    max_chars=int(getattr(cfg, "max_source_chars", 6000)),
                                    cache_ttl_s=int(getattr(cfg, "web_cache_ttl_s", 1800)),
                                cfg=cfg,
                                )
                                if txt:
                                    page_texts_web.append((u, txt))
                except Exception:
                    page_texts_web = []

                for i, s in enumerate(web_sources or [], start=1):
                    if not isinstance(s, dict):
                        continue
                    title = (s.get("title") or "(untitled)").strip()
                    url = (s.get("url") or "").strip()
                    snippet = (s.get("snippet") or "").strip()
                    if url:
                        web_lines.append(f"[{i}] {title} — {url}\n    {snippet}".rstrip())
                    else:
                        web_lines.append(f"[{i}] {title}\n    {snippet}".rstrip())

                for u, txt in (page_texts or []):
                    web_lines.append(f"[PAGE] {u}\n    " + txt.replace("\n", " ")[:8000])
                for u, txt in (locals().get('page_texts_web') or []):
                    web_lines.append(f"[PAGE] {u}\n    " + txt.replace("\n", " ")[:8000])

            prompt = (
                "Conversation (most recent last):\n" + ("\n".join(convo_lines) if convo_lines else "(none)") +
                "\n\nRetrieved context (Knowledge Library):\n" + ("\n".join(ctx_lines) if ctx_lines else "(none)") +
                "\n\nWeb sources:\n" + ("\n".join(web_lines) if web_lines else "(none)") +
                "\n\nUser question:\n" + user_msg
            )

            resp = llm.generate(prompt=prompt, system=system)
            answer = (resp.text or "").strip() or "(no response)"
            nb.cells.append(NotebookCell(
                cell_id=f"cell_{len(nb.cells)+1:03d}",
                cell_type="chat",
                content=answer,
                meta={"role": "assistant", "retrieved": retrieved_meta, "web_sources": web_sources},
            ))
            store.save(nb)
            _rerun()

    elif composer_mode == "Note":
        note_txt = st.text_area("Note", value="", height=140, placeholder="Write a note (markdown supported)...")
        if st.button("Add note", type="primary"):
            if note_txt.strip():
                nb.cells.append(NotebookCell(cell_id=f"cell_{len(nb.cells)+1:03d}", cell_type="note", content=note_txt.strip(), meta={}))
                store.save(nb)
                _rerun()
            else:
                spark_warn("Note is empty.")

    else:  # Query
        q1, q2 = st.columns([1, 2])
        with q1:
            qlang = st.selectbox("Language", options=["CQL", "SPL", "KQL", "SQL", "OSQuery", "text"], index=0)
        with q2:
            qtxt = st.text_area("Query", value="", height=140, placeholder="Paste a query...")
        if st.button("Add query", type="primary"):
            if qtxt.strip():
                nb.cells.append(NotebookCell(cell_id=f"cell_{len(nb.cells)+1:03d}", cell_type="query", content=qtxt.rstrip(), meta={"language": qlang}))
                store.save(nb)
                _rerun()
            else:
                spark_warn("Query is empty.")

    return


def main():
    set_page()
    ensure_nav_default()

    cfg = get_cfg()
    # NOTE: Do NOT wire/load RAG on app/page load.
    # RAG is loaded lazily only by features that explicitly need it.

    # SPARK branded header + quick dashboard strip
    spark_header(cfg)
    with st.container():
        render_dashboard()

    # Phase 6: Command Bar removed (keep the UI clean; navigation lives in the sidebar)
    toast_if_any()

    st.markdown("---")

    def _render_home():
        st.markdown(
            """
            <div class="spark-card">
              <div class="spark-title">Home</div>
              <div class="spark-rule"></div>
              <div style="color: var(--spark-text); font-size: 0.95rem;">
                SPARK is a local-first, analyst-controlled workbench for turning operational threat intelligence into hunt packages,
                validated findings, and detection strategies.
              </div>
            </div>
            """,
            unsafe_allow_html=True,
        )
        st.markdown("\n")
        st.markdown("**Workflow:** Intel → Hunt Packages → Runs → Findings → ADS")
        st.caption("Navigate using the left sidebar. Each page is isolated for speed and stability.")

    render_main(_render_home)
    render_footer()


if __name__ == "__main__":
    main()