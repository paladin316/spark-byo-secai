"""
SPARK (Powered by BYO-SECAI) — Streamlit Community "Simulation Mode"
File: app_sim.py

- Preserves SPARK look/feel (nav + header counters + Intel form layout)
- Uses demo_profiles/* for deterministic, resource-safe outputs
- No RAG rebuilds, no persistence, no arbitrary library ingestion

Deploy (Streamlit Community Cloud):
- Main file path: app_sim.py
"""

from __future__ import annotations

import json
import re
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Tuple

import streamlit as st

APP_TITLE = "SPARK"
APP_ICON = "🧠"
DEMO_ROOT = Path("demo_profiles")

NAV_ITEMS = [
    "Intel Briefs",
    "Hunt Packages",
    "Runs",
    "Findings",
    "ADS",
    "Workspace",
    "Artifacts",
    "Settings",
]

PLACEHOLDER_PATTERN = re.compile(r"\{\{([A-Z0-9_]+)\}\}")


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def render_placeholders(md: str, mapping: Dict[str, str]) -> str:
    def repl(m: re.Match) -> str:
        k = m.group(1).upper()
        return mapping.get(k, m.group(0))
    return PLACEHOLDER_PATTERN.sub(repl, md)


def try_load_css() -> None:
    css_candidates = [
        Path("assets/branding/style.css"),
        Path("assets/style.css"),
        Path("docs/assets/style.css"),
        Path("ui/style.css"),
        Path("style.css"),
    ]
    for p in css_candidates:
        if p.exists():
            st.markdown(f"<style>{p.read_text(encoding='utf-8')}</style>", unsafe_allow_html=True)
            return


def sidebar_logo() -> None:
    logo_candidates = [
        Path("assets/branding/logo.png"),
        Path("assets/branding/logo.webp"),
        Path("docs/assets/logo.png"),
        Path("docs/assets/logo.webp"),
    ]
    for p in logo_candidates:
        if p.exists():
            st.sidebar.image(str(p), use_container_width=True)
            return


def simulation_banner() -> None:
    st.info(
        "Simulation Mode: This is a guided walkthrough with selected functionality disabled for system requirements and performance. "
        "Use it to turn the knobs and review what SPARK outputs look like.",
        icon="ℹ️",
    )


def tour_callout(text: str) -> None:
    st.info(text, icon="🧭")


@dataclass
class DemoProfile:
    profile_id: str
    name: str
    description: str
    seed: Dict[str, object]
    outputs: Dict[str, str]  # keys: intel, hunt, report, ads
    kb_docs: Dict[str, str]


def safe_read(p: Path) -> str:
    try:
        return p.read_text(encoding="utf-8")
    except Exception:
        return ""


def load_profiles() -> Dict[str, DemoProfile]:
    profiles: Dict[str, DemoProfile] = {}
    if not DEMO_ROOT.exists():
        return profiles

    for d in sorted([p for p in DEMO_ROOT.iterdir() if p.is_dir()]):
        pid = d.name
        seed_path = d / "seed.json"
        if not seed_path.exists():
            continue

        try:
            seed = json.loads(seed_path.read_text(encoding="utf-8"))
            if not isinstance(seed, dict):
                continue
        except Exception:
            continue

        meta = {}
        meta_path = d / "profile.json"
        if meta_path.exists():
            try:
                meta = json.loads(meta_path.read_text(encoding="utf-8"))
            except Exception:
                meta = {}

        name = str(meta.get("name", pid))
        desc = str(meta.get("description", "Demo profile"))
        outputs_dir = d / "outputs"
        outputs = {
            "intel": safe_read(outputs_dir / "intel_brief.md"),
            "hunt": safe_read(outputs_dir / "hunt_package.md"),
            "report": safe_read(outputs_dir / "hunt_report.md"),
            "ads": safe_read(outputs_dir / "ads.md"),
        }

        kb_docs: Dict[str, str] = {}
        kb_dir = d / "kb"
        if kb_dir.exists():
            for md in sorted(kb_dir.glob("*.md")):
                kb_docs[md.stem] = safe_read(md)

        profiles[pid] = DemoProfile(pid, name, desc, seed, outputs, kb_docs)

    return profiles


def run_id(profile_id: str) -> str:
    ts = datetime.utcnow().strftime("%Y%m%d-%H%M%S")
    return f"run_sim_{profile_id}_{ts}"


def keyword_retrieve(question: str, docs: Dict[str, str], k: int = 3) -> List[Tuple[str, str]]:
    q = re.findall(r"[a-z0-9]{3,}", question.lower())
    qset = set(q)
    scored: List[Tuple[int, str, str]] = []
    for title, text in docs.items():
        words = re.findall(r"[a-z0-9]{3,}", (text or "").lower())
        score = len(qset.intersection(set(words)))
        scored.append((score, title, text))
    scored.sort(key=lambda x: x[0], reverse=True)

    out: List[Tuple[str, str]] = []
    for score, title, text in scored[:k]:
        excerpt = (text or "").strip().replace("\n", " ")
        excerpt = excerpt[:240] + ("…" if len(excerpt) > 240 else "")
        out.append((title, excerpt))
    return out



def sanitize_markdown_fences(md: str) -> str:
    """
    Defensive fix for demo content: ensures code fences don't swallow later sections.
    - If a fence is open and we hit a top-level numbered section (e.g., "5. Findings"), close the fence.
    - If a fence is still open at EOF, close it.
    """
    lines = (md or "").splitlines()
    out = []
    in_fence = False
    for line in lines:
        if line.strip().startswith("```"):
            in_fence = not in_fence
            out.append(line)
            continue
        if in_fence and re.match(r"^\s*\d+\.\s+\S", line):
            out.append("```")
            in_fence = False
            out.append(line)
            continue
        out.append(line)
    if in_fence:
        out.append("```")
    return "\n".join(out)


# ---------------- UI Shell ----------------
st.set_page_config(page_title=APP_TITLE, page_icon=APP_ICON, layout="wide")
try_load_css()

profiles = load_profiles()
if not profiles:
    st.error("No demo profiles found. Add demo_profiles/<profile_id>/seed.json and outputs/*.md")
    st.stop()

# Session state
if "sim" not in st.session_state:
    st.session_state.sim = {
        "profile_id": next(iter(profiles.keys())),
        "topic": None,
        "sources": None,
        "environment": "Windows",
        "confidence": "High",
        "strictness": "High",
        "data_sources": ["EDR", "DNS"],
        "time_window": "Last 30 days",
        "org_name": "Metropolis Financial Group",
        "run_id": None,
        "rendered": None,
        "findings_summary": None,
        "chat": [],
        "tour_enabled": True,
        "tour_step": 0,
        "tour_dismissed": False,
    }


def tour_enabled() -> bool:
    return bool(st.session_state.sim.get("tour_enabled")) and not bool(st.session_state.sim.get("tour_dismissed"))


def advance_tour(step: int) -> None:
    st.session_state.sim["tour_step"] = max(int(st.session_state.sim.get("tour_step", 0)), step)


# Sidebar (match SPARK navigation labels)
sidebar_logo()
st.sidebar.markdown("### SPARK")
st.sidebar.caption("Analyst-Driven Threat Intelligence → Hunt → Detection")

view = st.sidebar.radio("", NAV_ITEMS, index=0)

st.sidebar.divider()
st.sidebar.markdown("**Demo Profile**")
pid = st.sidebar.selectbox(
    "Profile",
    options=list(profiles.keys()),
    format_func=lambda x: f"{profiles[x].name} ({x})",
    index=list(profiles.keys()).index(st.session_state.sim["profile_id"]),
)
st.session_state.sim["profile_id"] = pid
profile = profiles[pid]
st.sidebar.caption(profile.description)

# Guided walkthrough controls
with st.sidebar.expander("Guided Walkthrough", expanded=False):
    st.session_state.sim["tour_enabled"] = st.toggle(
        "Enable guided callouts", value=bool(st.session_state.sim.get("tour_enabled", True))
    )
    cA, cB = st.columns(2)
    with cA:
        if st.button("Restart", use_container_width=True):
            st.session_state.sim["tour_step"] = 0
            st.session_state.sim["tour_dismissed"] = False
    with cB:
        if st.button("Dismiss", use_container_width=True):
            st.session_state.sim["tour_dismissed"] = True

# Knobs (kept in sidebar, but lightweight)
with st.sidebar.expander("Simulation Knobs", expanded=False):
    st.session_state.sim["environment"] = st.selectbox("Environment", ["Windows", "Azure", "Hybrid"], index=0)
    st.session_state.sim["confidence"] = st.selectbox("Confidence", ["Low", "Medium", "High"], index=2)
    st.session_state.sim["strictness"] = st.selectbox("Strictness", ["Low", "Medium", "High"], index=2)
    st.session_state.sim["data_sources"] = st.multiselect(
        "Telemetry Available",
        ["EDR", "DNS", "Proxy", "Identity", "O365", "Cloud Activity", "Firewall"],
        default=st.session_state.sim["data_sources"],
    )
    st.session_state.sim["time_window"] = st.selectbox("Time Window", ["Last 7 days", "Last 14 days", "Last 30 days"], index=2)

with st.sidebar.expander("Local-only Features", expanded=False):
    st.button("Rebuild RAG", disabled=True, help="Requires Local Mode")
    st.button("Ingest Library", disabled=True, help="Requires Local Mode")
    st.button("Persist Workspace", disabled=True, help="Requires Local Mode")

# Header (match screenshot feel: SPARK + counters)
st.markdown("## SPARK")
st.caption("Analyst-Driven Threat Intelligence → Hunt → Detection")

c1, c2, c3, c4, c5 = st.columns(5)
for c, label in zip([c1, c2, c3, c4, c5], ["Intel", "Hunts", "Runs", "Findings", "ADS"]):
    with c:
        st.caption(label)
        st.markdown("### 0")

st.markdown("---")
st.caption("Create an Intel Brief → approve it → generate a Hunt Package → run it → review Findings → generate ADS → export artifacts.")
st.markdown("")


def build_mapping() -> Dict[str, str]:
    topic = st.session_state.sim.get("topic") or str(profile.seed.get("topic", "LockBit Ransomware"))
    org = st.session_state.sim.get("org_name") or str(profile.seed.get("org_name", "Metropolis Financial Group"))
    sources = st.session_state.sim.get("sources") or ""
    rid = st.session_state.sim.get("run_id") or "run_sim_pending"

    return {
        "TOPIC": topic,
        "ORG_NAME": org,
        "ENVIRONMENT": st.session_state.sim["environment"],
        "CONFIDENCE": st.session_state.sim["confidence"],
        "STRICTNESS": st.session_state.sim["strictness"],
        "DATA_SOURCES": ", ".join(st.session_state.sim["data_sources"]) if st.session_state.sim["data_sources"] else "None (Simulation)",
        "TIME_WINDOW": st.session_state.sim["time_window"],
        "RUN_ID": rid,
        "SOURCES": sources.strip() or "(none provided)",
        "TIMESTAMP": utc_now_iso(),
    }


def simulate_generate() -> None:
    rid = run_id(profile.profile_id)
    st.session_state.sim["run_id"] = rid
    mapping = build_mapping()

    rendered = {
        "intel": render_placeholders(profile.outputs["intel"], mapping),
        "hunt": sanitize_markdown_fences(render_placeholders(profile.outputs["hunt"], mapping)),
        "report": sanitize_markdown_fences(render_placeholders(profile.outputs["report"], mapping)),
        "ads": sanitize_markdown_fences(render_placeholders(profile.outputs["ads"], mapping)),
    }
    st.session_state.sim["rendered"] = rendered

    finding = "Confirmed malicious execution pattern (Simulation)" if "Confirmed Malicious" in rendered["report"] else "No confirmed findings (Simulation)"
    st.session_state.sim["findings_summary"] = finding


# --------------- Views ---------------

if view == "Intel Briefs":
    simulation_banner()
    if tour_enabled() and int(st.session_state.sim.get("tour_step", 0)) <= 0:
        tour_callout("Step 1/6: Enter a Topic + Sources, then click **Generate Intel Brief (Simulation)** to load the demo lifecycle.")

    st.markdown("## Intel Briefs")
    st.button("➕  New Intel Brief (reset view)", use_container_width=True)

    with st.expander("Create a new Intel Brief", expanded=True):
        topic_default = st.session_state.sim.get("topic") or str(profile.seed.get("topic", "LockBit Ransomware"))
        topic = st.text_input("Topic", value=topic_default, placeholder="e.g., STORM-0501 expanding into hybrid cloud")
        st.session_state.sim["topic"] = topic

        sources = st.text_area(
            "Sources (one per line)",
            value=st.session_state.sim.get("sources") or "",
            placeholder="Paste URLs (one per line) or notes here",
            height=110,
        )
        st.session_state.sim["sources"] = sources

    st.markdown("### Additional Intel Inputs")
    st.caption("Upload supporting files (PDF, DOCX, XLSX/XLSM, CSV, TXT, MD, LOG) — **Simulation Mode accepts files for workflow demonstration only**.")
    st.file_uploader("Drag and drop files here", accept_multiple_files=True)

    st.text_area("Paste raw intel text (optional)", value="", height=120)

    colA, colB = st.columns([1, 2])
    with colA:
        if st.button("Generate Intel Brief (Simulation)", type="primary", use_container_width=True):
            prog = st.progress(0, text="Starting…")
            for i, step in enumerate(["Ingest", "Normalize", "Extract Behaviors", "Map ATT&CK", "Draft Intel Brief"], start=1):
                prog.progress(int(i / 5 * 100), text=step)
                time.sleep(0.15)
            prog.empty()

            simulate_generate()
            st.success(f"Intel Brief generated (Simulation) • {st.session_state.sim['run_id']}")
            advance_tour(1)

    with colB:
        st.caption("Note: Simulation Mode does not fetch URLs, parse uploads, or persist state. It renders pre-canned demo artifacts with your inputs.")

    if st.session_state.sim.get("rendered"):
        if tour_enabled() and int(st.session_state.sim.get("tour_step", 0)) == 1:
            tour_callout("Step 2/6: Next, click **Hunt Packages** in the left navigation to review the generated hunt package.")
        st.markdown("---")
        st.markdown(st.session_state.sim["rendered"]["intel"])

elif view == "Hunt Packages":
    simulation_banner()
    if st.session_state.sim.get("rendered"):
        advance_tour(2)
    if tour_enabled() and int(st.session_state.sim.get("tour_step", 0)) == 2:
        tour_callout("Step 3/6: Review the Hunt Package. Next, go to **Runs** to see the simulated execution output.")

    st.markdown("## Hunt Packages")
    if not st.session_state.sim.get("rendered"):
        st.info("Generate an Intel Brief first (Simulation) to populate the Hunt Package.")
    else:
        st.markdown(st.session_state.sim["rendered"]["hunt"])

elif view == "Runs":
    simulation_banner()
    if st.session_state.sim.get("rendered"):
        advance_tour(3)
    if tour_enabled() and int(st.session_state.sim.get("tour_step", 0)) == 3:
        tour_callout("Step 4/6: This is the simulated run output. Next, go to **Findings** to review the evidence and disposition.")

    st.markdown("## Runs")
    if not st.session_state.sim.get("rendered"):
        st.info("Generate an Intel Brief first (Simulation) to create a simulated Run.")
    else:
        st.write({"Run ID": st.session_state.sim["run_id"], "Status": "Completed (Simulation)", "Time": utc_now_iso()})
        st.markdown("---")
        st.markdown(st.session_state.sim["rendered"]["report"])

elif view == "Findings":
    simulation_banner()
    if st.session_state.sim.get("rendered"):
        advance_tour(4)
    if tour_enabled() and int(st.session_state.sim.get("tour_step", 0)) == 4:
        tour_callout("Step 5/6: Findings summarize what was observed. Next, go to **ADS** to see how the detection strategy is captured.")

    st.markdown("## Findings")
    if not st.session_state.sim.get("rendered"):
        st.info("Generate an Intel Brief first (Simulation) to produce simulated Findings.")
    else:
        st.success(st.session_state.sim.get("findings_summary") or "Findings available (Simulation)")
        st.markdown("---")
        st.markdown("### Evidence (from Hunt / IR Report)")
        st.markdown(st.session_state.sim["rendered"]["report"])

elif view == "ADS":
    simulation_banner()
    if st.session_state.sim.get("rendered"):
        advance_tour(5)
    if tour_enabled() and int(st.session_state.sim.get("tour_step", 0)) == 5:
        tour_callout("Step 6/6: Review the ADS (includes Query Starters + Response Playbook). Next, open **Workspace** to see the grounded chat experience.")

    st.markdown("## ADS")
    if not st.session_state.sim.get("rendered"):
        st.info("Generate an Intel Brief first (Simulation) to populate ADS.")
    else:
        st.markdown(st.session_state.sim["rendered"]["ads"])

elif view == "Workspace":
    simulation_banner()
    if st.session_state.sim.get("rendered"):
        advance_tour(6)

    st.markdown("## Workspace")
    st.caption("Chat is grounded only in the demo artifacts loaded this session. No external calls.")

    def load_sample_convo() -> None:
        st.session_state.sim["chat"] = [
            {"role": "user", "content": "What’s the highest-signal hypothesis for this LockBit scenario?"},
            {
                "role": "assistant",
                "content": "In Simulation Mode, the highest-signal framing is behavior-first: **malicious execution + credential access (LSASS) + lateral movement** preceding encryption impact. Review the Hunt Package hypotheses and the IR report disposition to see how it’s justified.",
                "sources": ["Hunt Package", "Hunt / IR Report"],
            },
            {"role": "user", "content": "What telemetry do I need to validate this quickly?"},
            {
                "role": "assistant",
                "content": "Start with **EDR process lineage** (parent/child + command line), **network connections** from suspicious processes, and any **credential access indicators**. In the ADS, check the Telemetry section and the Query Starters pulled from the Hunt Package.",
                "sources": ["ADS", "Hunt Package"],
            },
            {"role": "user", "content": "If we confirm this is real, what are the first response steps?"},
            {
                "role": "assistant",
                "content": "Use the **Response Playbook** in the ADS: validate → contain host/account → preserve evidence → scope → eradicate/recover. The goal is to prevent encryption impact and limit spread.",
                "sources": ["ADS"],
            },
        ]

    topA, topB, topC = st.columns([1, 1, 2])
    with topA:
        if st.button("Load sample conversation", use_container_width=True):
            load_sample_convo()
    with topB:
        if st.button("Clear chat", use_container_width=True):
            st.session_state.sim["chat"] = []
    with topC:
        st.caption("Tip: Load the sample conversation to see how the Workspace behaves in Simulation Mode.")

    if tour_enabled() and int(st.session_state.sim.get("tour_step", 0)) >= 6 and not st.session_state.sim["chat"]:
        tour_callout("You’re at the end of the guided walkthrough. Click **Load sample conversation** to see a grounded threat hunting chat flow.")

    for msg in st.session_state.sim["chat"]:
        with st.chat_message(msg["role"]):
            st.markdown(msg["content"])
            if msg.get("sources"):
                st.caption("Sources (Simulation): " + " • ".join(msg["sources"]))

    q = st.chat_input("Ask about the scenario, hunt approach, or ADS intent…")
    if q:
        st.session_state.sim["chat"].append({"role": "user", "content": q})
        with st.chat_message("user"):
            st.markdown(q)

        corpus: Dict[str, str] = {}
        if st.session_state.sim.get("rendered"):
            r = st.session_state.sim["rendered"]
            corpus.update(
                {
                    "Intel Brief": r["intel"],
                    "Hunt Package": r["hunt"],
                    "Hunt / IR Report": r["report"],
                    "ADS": r["ads"],
                }
            )
        corpus.update(profile.kb_docs or {})

        retrieved = keyword_retrieve(q, corpus, k=3)
        sources = [t for t, _ in retrieved if t]

        answer_parts = ["Simulation Mode: I’m answering using only the demo artifacts/notes loaded in this session."]
        if not st.session_state.sim.get("rendered"):
            answer_parts.append("Generate an Intel Brief first to load the demo artifacts into this session.")
        else:
            answer_parts.append("Most relevant context from the loaded demo content:")
            for title, excerpt in retrieved:
                answer_parts.append(f"- **{title}**: {excerpt}")

        answer = "\n\n".join(answer_parts)

        st.session_state.sim["chat"].append({"role": "assistant", "content": answer, "sources": sources})
        with st.chat_message("assistant"):
            st.markdown(answer)
            if sources:
                st.caption("Sources (Simulation): " + " • ".join(sources))

elif view == "Artifacts":
    simulation_banner()
    st.markdown("## Artifacts")
    st.caption("Read-only export preview (Simulation).")
    if not st.session_state.sim.get("rendered"):
        st.info("Generate an Intel Brief first (Simulation) to view artifacts.")
    else:
        r = st.session_state.sim["rendered"]
        st.download_button("Download Intel Brief (MD)", data=r["intel"].encode("utf-8"), file_name="intel_brief.md")
        st.download_button("Download Hunt Package (MD)", data=r["hunt"].encode("utf-8"), file_name="hunt_package.md")
        st.download_button("Download Hunt / IR Report (MD)", data=r["report"].encode("utf-8"), file_name="hunt_report.md")
        st.download_button("Download ADS (MD)", data=r["ads"].encode("utf-8"), file_name="ads.md")

elif view == "Settings":
    simulation_banner()
    st.markdown("## Settings")
    st.caption("Simulation Mode settings are limited by design.")
    st.write({"Mode": "Simulation", "RAG rebuild": "Disabled", "Persistent state": "Disabled", "Arbitrary ingestion": "Disabled"})
    st.markdown("### Fictional Demo Org")
    org = st.text_input("Organization Name", value=st.session_state.sim.get("org_name") or "Metropolis Financial Group")
    st.session_state.sim["org_name"] = org

st.markdown("---")
st.caption(
    "SPARK (Powered by BYO-SECAI) • Analyst-Driven • AI-Augmented • Human-Validated • Local-First\n\n"
    "This Streamlit Community deployment is a **simulation demo** to preserve reliability and appearance. "
    "For full functionality (RAG library ingestion, persistent workspace state, and real processing), run SPARK locally."
)
