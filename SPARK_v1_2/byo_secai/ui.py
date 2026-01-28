from __future__ import annotations

import os
import time
from pathlib import Path

import streamlit as st

from .models import ArtifactType
from .storage import Storage


def set_page():
    # set_page() is called before get_cfg() on most pages, so we read the
    # persisted config directly to keep the browser tab title consistent.
    try:
        from .config import load_config_yaml
        cfg = load_config_yaml() or {}
        title = str(cfg.get("app_title") or "SPARK")
    except Exception:
        title = "SPARK"

    # Prefer a real favicon if available (falls back to emoji for compatibility).
    page_icon = "🛰️"
    try:
        from PIL import Image
        icon_path = Path(__file__).resolve().parents[1] / "assets" / "branding" / "favicon.png"
        if icon_path.exists():
            page_icon = Image.open(icon_path)
    except Exception:
        page_icon = "🛰️"

    st.set_page_config(page_title=title, page_icon=page_icon, layout="wide")

    # Apply SPARK UI branding consistently across all pages.
    try:
        apply_spark_branding()
    except Exception:
        pass


def apply_spark_branding():
    """Apply SPARK branding (dark, restrained, contract-driven).

    Goals:
    - Centered/max-width "workbench" feel (like the mockup)
    - Color contract tokens exposed as CSS variables (prevents drift)
    - Minimal, Streamlit-friendly polish (cards, inputs, buttons)
    """
    st.markdown(
        """
        <style>
:root {
  /* ---- SPARK Color Contract (tokens) ---- */
  --spark-purple-600: #4A0BAB;
  --spark-purple-500: #7327E6;
  --spark-purple-400: #8A55F0;
  --spark-purple-300: #B394FA;

  --spark-blue-600:   #264BB3;
  --spark-blue-500:   #2E5CDA;
  --spark-blue-400:   #4B70E6;

  /* Muted teal for non-commit actions (fits contract's "info" family) */
  --spark-teal-600:   #0F5F66;
  --spark-teal-500:   #167A83;
  --spark-teal-400:   #1F96A1;

  --spark-amber-600:  #B45309;
  --spark-amber-500:  #D97706;
  --spark-amber-400:  #F59E0B;

  --spark-red-600:    #B91C1C;
  --spark-red-500:    #DC2626;
  --spark-red-400:    #EF4444;

  --spark-green-600:  #15803D;
  --spark-green-500:  #16A34A;
  --spark-green-400:  #22C55E;

  --spark-gray-900:   #0F1115;
  --spark-gray-800:   #141823;
  --spark-gray-700:   #1B2130;
  --spark-gray-600:   #2A3243;
  --spark-gray-500:   #4B5563;
  --spark-gray-400:   #9CA3AF;
  --spark-gray-300:   #CBD5E1;
  --spark-gray-200:   #E5E7EB;

  /* ---- Semantic aliases (use these in CSS) ---- */
  --spark-bg:         var(--spark-gray-900);
  --spark-panel:      var(--spark-gray-800);
  --spark-panel-2:    var(--spark-gray-700);
  --spark-border:     rgba(255,255,255,0.08);
  --spark-text:       var(--spark-gray-200);
  --spark-muted:      var(--spark-gray-400);

  /* Contract mapping */
  --spark-commit:     var(--spark-purple-500); /* Generate / Approve / Export / Save */
  --spark-info:       var(--spark-blue-500);   /* info + neutral banners */
  --spark-action:     var(--spark-teal-500);   /* non-commit actions */
  --spark-tab:        #7C8AA6;                 /* slate */
  --spark-tab-active: var(--spark-info);
}

/* App background */
.stApp {
  background: var(--spark-bg);
  color: var(--spark-text);
}

/* Centered workbench feel (max-width) */
.block-container {
  max-width: 1180px;
  padding-top: 1.55rem;
  padding-bottom: 2.2rem;
}

/* Hide the default "app" entry in Streamlit's multipage nav (top item). */
section[data-testid="stSidebar"] [data-testid="stSidebarNav"] li:first-child {
  display: none;
}

/* Sidebar */
section[data-testid="stSidebar"] {
  background: #0B0E13;
  border-right: 1px solid var(--spark-border);
}

/* Sidebar nav: selected + hover states */
section[data-testid="stSidebar"] [data-testid="stSidebarNav"] a {
  border-radius: 10px;
  padding: 0.42rem 0.62rem;
  color: var(--spark-gray-200);
}
section[data-testid="stSidebar"] [data-testid="stSidebarNav"] a:hover {
  background: rgba(46, 92, 218, 0.10); /* blue @ 10% */
}
section[data-testid="stSidebar"] [data-testid="stSidebarNav"] a[aria-current="page"] {
  background: rgba(115, 39, 230, 0.16);
  border: 1px solid rgba(115, 39, 230, 0.26);
}

/* Headings */
h1, h2, h3, h4 { letter-spacing: 0.2px; }
h1 { margin-bottom: 0.12rem; }
h2 { margin-top: 1.05rem; }

/* Tighten metric row spacing */
div[data-testid="stMetric"] {
  padding-top: 0.05rem;
  padding-bottom: 0.05rem;
}
div[data-testid="stMetric"] > div { row-gap: 0.08rem; }

/* Divider (tight) */
.spark-divider {
  height: 1px;
  background: rgba(255,255,255,0.08);
  margin: 0.40rem 0 0.95rem 0;
  border-radius: 1px;
}

/* Card utility */
.spark-card {
  background: linear-gradient(180deg, var(--spark-panel), var(--spark-panel-2));
  border: 1px solid var(--spark-border);
  border-radius: 14px;
  padding: 12px 12px;
  box-shadow: 0 6px 18px rgba(0,0,0,0.35);
}

/* Footer */
.spark-footer {
  margin-top: 1.15rem;
  padding-top: 0.65rem;
  border-top: 1px solid var(--spark-border);
  color: var(--spark-muted);
  font-size: 0.86rem;
  text-align: center;
}

/* Inputs: dark, tight, consistent */
.stTextInput input,
.stTextArea textarea,
.stSelectbox div[data-baseweb="select"] > div,
.stMultiSelect div[data-baseweb="select"] > div {
  background: rgba(255,255,255,0.03) !important;
  border: 1px solid rgba(255,255,255,0.10) !important;
  border-radius: 10px !important;
  color: var(--spark-text) !important;
}
.stTextInput input:focus,
.stTextArea textarea:focus {
  outline: none !important;
  border-color: rgba(46,92,218,0.55) !important;
  box-shadow: 0 0 0 2px rgba(46,92,218,0.18) !important;
}

/* Markdown spacing */
div[data-testid="stMarkdownContainer"] p { margin-bottom: 0.30rem; }

/* ---------- Buttons (contract mapping) ---------- */
button[data-testid^="baseButton-"] {
  border-radius: 9px !important;
  padding: 0.34rem 0.72rem !important;
  font-weight: 650 !important;
  border: 1px solid rgba(255,255,255,0.12) !important;
}

/* Default (secondary) = muted teal */
button[data-testid="baseButton-secondary"] {
  background: rgba(22,122,131,0.16) !important;
  color: var(--spark-text) !important;
  border-color: rgba(31,150,161,0.35) !important;
}
button[data-testid="baseButton-secondary"]:hover {
  background: rgba(22,122,131,0.26) !important;
  border-color: rgba(31,150,161,0.55) !important;
}

/* Primary (commit) = purple */
button[data-testid="baseButton-primary"] {
  background: var(--spark-commit) !important;
  color: white !important;
  border-color: rgba(115, 39, 230, 0.35) !important;
}
button[data-testid="baseButton-primary"]:hover {
  background: var(--spark-purple-400) !important;
  border-color: rgba(138, 85, 240, 0.55) !important;
}
button[data-testid="baseButton-primary"]:active,
button[data-testid="baseButton-secondary"]:active {
  transform: translateY(1px);
}

/* Reduce "bulky" gaps around buttons */
div[data-testid="stButton"] { margin-top: 0.05rem; margin-bottom: 0.06rem; }

/* Checkbox accent stays brand */
input[type="checkbox"] { accent-color: var(--spark-commit); }

/* ---------- Tabs (blue/slate, not purple) ---------- */
button[data-baseweb="tab"] {
  color: var(--spark-tab) !important;
  font-weight: 600 !important;
}
button[data-baseweb="tab"][aria-selected="true"] {
  color: var(--spark-tab-active) !important;
}
div[data-baseweb="tab-highlight"] {
  background-color: var(--spark-tab-active) !important;
}

/* ---------- Banners (custom, used by app.py helpers) ---------- */
.spark-banner {
  border-radius: 10px;
  border: 1px solid rgba(255,255,255,0.10);
  padding: 0.42rem 0.65rem;
  margin: 0.28rem 0 0.52rem 0;
}
.spark-banner.info {
  background: rgba(46,92,218,0.12);
  border-left: 3px solid rgba(46,92,218,0.90);
}
.spark-banner.warn {
  background: rgba(217,119,6,0.14);
  border-left: 3px solid rgba(217,119,6,0.95);
}
.spark-banner.ok {
  background: rgba(34,197,94,0.10);
  border-left: 3px solid rgba(34,197,94,0.85);
}
.spark-banner.risk {
  background: rgba(220,38,38,0.12);
  border-left: 3px solid rgba(220,38,38,0.90);
}

/* Streamlit alerts: make them tighter (if they appear) */
div[data-testid="stAlert"] {
  border-radius: 12px;
  border: 1px solid rgba(255,255,255,0.10);
}

/* Header icon + alignment */
.spark-header { padding: 0.20rem 0 0.45rem 0; }
.spark-header-title { display: flex; align-items: center; gap: 10px; }
.spark-header-badge {
  width: 34px;
  height: 34px;
  border-radius: 10px;
  display: flex;
  align-items: center;
  justify-content: center;
  background: rgba(46, 92, 218, 0.16);
  border: 1px solid rgba(46, 92, 218, 0.32);
  box-shadow: 0 6px 18px rgba(0,0,0,0.25);
}
.spark-header-icon {
  width: 18px;
  height: 18px;
  opacity: 0.96;
  filter: invert(1) brightness(1.15);
}
</style>
        """,
        unsafe_allow_html=True,
    )
    # Hard-hide Streamlit's sidebar "Performance (per view)" dev panel (release polish).
    try:
        import streamlit.components.v1 as components
        components.html(
            """
            <script>
            (function() {
              const hidePerf = () => {
                const side = window.parent.document.querySelector('section[data-testid="stSidebar"]');
                if (!side) return;
                const candidates = side.querySelectorAll('div[data-testid="stExpander"], details, summary');
                candidates.forEach((el) => {
                  const t = (el.innerText || '').trim();
                  if (t.includes('Performance (per view)')) {
                    // Hide the closest expander/details container.
                    const container = el.closest('div[data-testid="stExpander"]') || el.closest('details') || el.parentElement;
                    if (container) container.style.display = 'none';
                  }
                });
              };
              hidePerf();
              // Keep trying briefly in case Streamlit renders it after our first run.
              let n = 0;
              const id = setInterval(() => {
                hidePerf();
                n++;
                if (n > 20) clearInterval(id);
              }, 250);
            })();
            </script>
            """,
            height=0,
            width=0,
        )
    except Exception:
        pass




def app_header(title: str, subtitle: str | None = None):
    """Top-of-page SPARK header (brand icon + title + optional subtitle)."""
    icon_html = ""
    try:
        import base64
        icon_path = Path(__file__).resolve().parents[1] / "assets" / "branding" / "spark_logo_tertiary_icon.svg"
        if icon_path.exists():
            svg = icon_path.read_text(encoding="utf-8")
            b64 = base64.b64encode(svg.encode("utf-8")).decode("ascii")
            icon_html = (
                f'<div class="spark-header-badge">'
                f'<img class="spark-header-icon" src="data:image/svg+xml;base64,{b64}" alt="SPARK" />'
                f'</div>'
            )
    except Exception:
        icon_html = ""

    st.markdown(
        f"""
        <div class="spark-header">
          <div class="spark-header-title">
            {icon_html}
            <div style="font-size: 1.85rem; font-weight: 750; letter-spacing: 0.2px;">{title}</div>
          </div>
          {f'<div style="color: var(--spark-muted); margin-top: -0.15rem; font-size: 0.98rem;">{subtitle}</div>' if subtitle else ''}
        </div>
        """,
        unsafe_allow_html=True,
    )


def _set_console(kind: str, status: str, output_md: str | None = None, download_path: str | None = None):
    st.session_state["cmd_last_kind"] = kind
    st.session_state["cmd_last_status"] = status
    st.session_state["cmd_last_output_md"] = output_md or ""
    st.session_state["cmd_last_download_path"] = download_path or ""


def _export_all(store: Storage) -> Path:
    ts = int(time.time())
    out_path = store.exports_dir / f"export_{ts}.md"

    # Keep this simple and demo-friendly: bundle summary + IDs.
    lines: list[str] = []
    lines.append("# SPARK — Export Bundle")
    lines.append("")
    lines.append(f"**Date:** {time.strftime('%Y-%m-%d')}\n")

    def _count(t: ArtifactType) -> int:
        return len(store.list_ids(t))

    lines.append("## Inventory")
    lines.append("")
    lines.append(f"- Intel Briefs: {_count(ArtifactType.INTEL_BRIEF)}")
    lines.append(f"- Hunt Packages: {_count(ArtifactType.HUNT_PACKAGE)}")
    lines.append(f"- Runs: {_count(ArtifactType.RUN)}")
    lines.append(f"- Findings: {_count(ArtifactType.FINDING)}")
    lines.append(f"- ADS: {_count(ArtifactType.ADS)}")
    lines.append("")

    for t in [ArtifactType.INTEL_BRIEF, ArtifactType.HUNT_PACKAGE, ArtifactType.RUN, ArtifactType.FINDING, ArtifactType.ADS]:
        ids = store.list_ids(t)
        if not ids:
            continue
        lines.append(f"## {t.value.replace('_', ' ').title()}")
        lines.append("")
        for aid in ids:
            lines.append(f"- `{aid}`")
        lines.append("")

    out_path.write_text("\n".join(lines), encoding="utf-8")
    return out_path


def _run_command(cmd: str, store: Storage):
    cmd = (cmd or "").strip()
    if not cmd:
        _set_console("(none)", "No command entered.")
        return

    token = cmd.split()[0].lower()

    if token in ["/help", "help", "?"]:
        md = """# Command Bar Help

Supported commands:

- `/help` — show this help
- `/go intel` | `/go hunts` | `/go runs` | `/go findings` | `/go ads` | `/go artifacts` | `/go settings`
- `/export_all` — prepare a single markdown bundle of all artifacts
"""
        _set_console("help", "OK", md)
        return

    if token == "/go" and len(cmd.split()) >= 2:
        dest = cmd.split()[1].lower()
        mapping = {
            "dashboard": "Dashboard",
            "intel": "Intel Briefs",
            "briefs": "Intel Briefs",
            "hunts": "Hunt Packages",
            "hunt": "Hunt Packages",
            "runs": "Runs",
            "findings": "Findings",
            "ads": "ADS",
            "artifacts": "Artifacts",
            "settings": "Settings",
        }
        if dest in mapping:
            st.session_state["nav"] = mapping[dest]
            _set_console("nav", f"Navigated to {mapping[dest]}.")
        else:
            _set_console("nav", f"Unknown destination: {dest}. Try `/help`.")
        return

    if token in ["/export_all", "/export", "export_all"]:
        try:
            p = _export_all(store)
            _set_console("export", f"Prepared download: {p.name}", p.read_text(encoding="utf-8"), str(p))
        except Exception as e:
            _set_console("export", f"Export failed: {e}")
        return

    _set_console("unknown", f"Unknown command: {cmd}. Try `/help`.")


def command_bar(store: Storage):
    """Top-of-app command bar (Phase 4-style), kept lightweight for demo."""

    st.subheader("Command Bar")
    cmd = st.text_input(
        "Command",
        value=st.session_state.get("cmd_text", ""),
        key="cmd_text",
        placeholder="/help | /go intel | /export_all",
        label_visibility="visible",
    )

    if st.button("Run"):
        _run_command(cmd, store)

    kind = st.session_state.get("cmd_last_kind", "")
    status = st.session_state.get("cmd_last_status", "")
    output_md = st.session_state.get("cmd_last_output_md", "")
    download_path = st.session_state.get("cmd_last_download_path", "")

    if any([kind, status, output_md, download_path]):
        title = "Console Output" if not download_path else f"Console Output — Prepared download: {os.path.basename(download_path)}"
        with st.expander(title, expanded=True):
            st.write(f"**Last:** `{st.session_state.get('cmd_text','')}`  |  **Kind:** `{kind}`  |  **Status:** {status}")
            if output_md:
                st.caption("Output (Markdown)")
                st.code(output_md)
                with st.expander("Rendered preview", expanded=False):
                    st.markdown(output_md)

            if download_path and Path(download_path).exists():
                st.download_button(
                    "Download",
                    data=Path(download_path).read_bytes(),
                    file_name=os.path.basename(download_path),
                    mime="text/markdown",
                )


def toast_if_any():
    msg = st.session_state.pop("toast", None)
    if msg:
        st.toast(msg)


# ---------------------------------------------------------------------------
# Linked context helpers (UI)
# ---------------------------------------------------------------------------

def format_artifact_chain(intel_id: str = "", hunt_id: str = "", run_id: str = "", finding_id: str = "", ads_id: str = "") -> str:
    parts = []
    if intel_id: parts.append(f"Intel `{intel_id}`")
    if hunt_id: parts.append(f"Hunt `{hunt_id}`")
    if run_id: parts.append(f"Run `{run_id}`")
    if finding_id: parts.append(f"Finding `{finding_id}`")
    if ads_id: parts.append(f"ADS `{ads_id}`")
    return " → ".join(parts) if parts else ""


def render_artifact_chain_banner(st, intel_id: str = "", hunt_id: str = "", run_id: str = "", finding_id: str = "", ads_id: str = "") -> None:
    """Render a linked context banner.

    By default this renders a clickable breadcrumb that helps users jump
    between Intel → Hunt → Run → Finding → ADS.
    """
    parts = []
    if intel_id:
        parts.append(("Intel", intel_id))
    if hunt_id:
        parts.append(("Hunt", hunt_id))
    if run_id:
        parts.append(("Run", run_id))
    if finding_id:
        parts.append(("Finding", finding_id))
    if ads_id:
        parts.append(("ADS", ads_id))

    if not parts:
        return

    # Try to render as a clickable breadcrumb. If anything fails (older
    # Streamlit versions, unexpected state), fall back to a simple caption.
    try:
        import streamlit as _st
        # NOTE: Do not mutate global "active run" context just by rendering.
        # Only change navigation context when the user actually clicks.
        from byo_secai.state.run import set_active_run_id
        from byo_secai.state.view_state import state_set

        # We use run_id (if present) as the "active run" boundary when navigating.
        active_ctx = (run_id or "no_run")

        cols = _st.columns([1] * len(parts))
        for i, (label, aid) in enumerate(parts):
            with cols[i]:
                # Use a stable key per view render.
                k = f"crumb_{label.lower()}_{aid}"
                # Avoid Streamlit-specific kwargs that vary by version (e.g., button type).
                if _st.button(f"{label}: {aid}", key=k, help="Jump to this artifact"):
                    # Seed per-view defaults for the destination page.
                    # Also update active run boundary if we have one.
                    set_active_run_id(active_ctx)
                    if label == "Intel":
                        _st.session_state["intel_selected"] = aid
                        _st.session_state["_nav_target"] = "Intel Briefs"
                    elif label == "Hunt":
                        state_set("Hunt Packages", active_ctx, "selected_hunt", aid)
                        _st.session_state["_nav_target"] = "Hunt Packages"
                    elif label == "Run":
                        state_set("Runs", active_ctx, "selected_run", aid)
                        _st.session_state["_nav_target"] = "Runs"
                    elif label == "Finding":
                        state_set("Findings", active_ctx, "selected_finding", aid)
                        _st.session_state["_nav_target"] = "Findings"
                    elif label == "ADS":
                        state_set("ADS", active_ctx, "selected_ads", aid)
                        _st.session_state["_nav_target"] = "ADS"
                    _st.rerun()

        # Add a lightweight textual chain under the buttons.
        _st.caption(format_artifact_chain(intel_id=intel_id, hunt_id=hunt_id, run_id=run_id, finding_id=finding_id, ads_id=ads_id))
        return
    except Exception:
        pass

    # Fallback: plain caption only
    chain = format_artifact_chain(intel_id=intel_id, hunt_id=hunt_id, run_id=run_id, finding_id=finding_id, ads_id=ads_id)
    if chain:
        st.caption(chain)