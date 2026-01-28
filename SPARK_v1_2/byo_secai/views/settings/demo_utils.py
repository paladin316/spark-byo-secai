from __future__ import annotations

import streamlit as st


def render(cfg, store) -> None:
    st.subheader("Demo utilities")

    # --- prod-safe guardrails ---
    prod_safe = bool(getattr(cfg, "prod_safe_mode", True))
    allow_cfg = bool(getattr(cfg, "allow_dangerous_actions", False))
    unlocked = bool(st.session_state.get("dangerous_unlocked", False))
    dangerous_allowed = (not prod_safe) or allow_cfg or unlocked

    if prod_safe and not dangerous_allowed:
        st.info(
            "Production-safe mode is enabled. Destructive actions are locked. "
            "To use reset tools, unlock them for this session below."
        )
        with st.expander("Unlock destructive actions (this session)", expanded=False):
            st.caption("This does not change config.yaml — it only unlocks reset tools for this browser session.")
            ack = st.checkbox("I understand this can permanently delete local data.", key="danger_ack")
            phrase = st.text_input("Type UNLOCK to enable", value="", key="danger_phrase")
            if st.button("Unlock", type="primary", disabled=not (ack and phrase.strip().upper() == "UNLOCK")):
                st.session_state["dangerous_unlocked"] = True
                st.success("Unlocked destructive actions for this session.")

    # --- confirmation modal ---
    def _do_reset(mode: str) -> None:
        actor = str(st.session_state.get("operator") or "")
        store.append_audit("reset", actor=actor, scope=mode, note="Triggered from Settings → Demo utilities")
        store.reset(mode)
        # Clear cached singletons so the app recreates them against the fresh data_dir
        st.session_state.pop("storage", None)
        st.session_state.pop("rag", None)
        st.session_state.pop("workspace_store", None)
        st.success("Reset complete. Reloading…")
        try:
            st.rerun()
        except Exception:
            st.experimental_rerun()

    if "show_reset_confirm" not in st.session_state:
        st.session_state["show_reset_confirm"] = False

    reset_clicked = st.button(
        "Reset local data…",
        type="secondary",
        disabled=not dangerous_allowed,
        help="Deletes local JSON artifacts under your data directory. Use with care.",
    )

    if reset_clicked:
        st.session_state["show_reset_confirm"] = True

    if st.session_state.get("show_reset_confirm"):
        # Streamlit dialog is the cleanest "modal" pattern when available.
        try:
            @st.dialog("Confirm reset")
            def _confirm_dialog():
                st.warning("This action permanently deletes local data on disk.")
                choice = st.radio(
                    "Select scope",
                    options=[
                        "Everything (delete ./data)",
                        "Intel only (Intel Briefs + Intel IOCs)",
                        "Artifacts only (Hunts/Runs/Findings/ADS)",
                    ],
                    index=0,
                )
                mode = "all"
                if choice.startswith("Intel"):
                    mode = "intel"
                elif choice.startswith("Artifacts"):
                    mode = "artifacts"

                st.caption("Type RESET to confirm.")
                phrase = st.text_input("Confirmation", value="", key="reset_confirm_phrase")
                col_a, col_b = st.columns([1, 1])
                with col_a:
                    if st.button("Cancel"):
                        st.session_state["show_reset_confirm"] = False
                        return
                with col_b:
                    if st.button("Reset now", type="primary", disabled=(phrase.strip().upper() != "RESET")):
                        st.session_state["show_reset_confirm"] = False
                        _do_reset(mode)

            _confirm_dialog()
        except Exception:
            # Fallback for older Streamlit: inline confirmation
            st.warning("Confirm reset")
            scope = st.selectbox(
                "Scope",
                options=["all", "intel", "artifacts"],
                index=0,
                help="all=intel+artifacts; intel=Intel Briefs + Intel IOCs; artifacts=Hunts/Runs/Findings/ADS",
            )
            phrase = st.text_input("Type RESET to confirm", value="", key="reset_confirm_phrase_inline")
            c1, c2 = st.columns([1, 1])
            with c1:
                if st.button("Cancel", key="reset_cancel_inline"):
                    st.session_state["show_reset_confirm"] = False
            with c2:
                if st.button("Reset now", type="primary", key="reset_ok_inline", disabled=(phrase.strip().upper() != "RESET")):
                    st.session_state["show_reset_confirm"] = False
                    _do_reset(scope)

    # --- audit timeline ---
    audit = store.read_audit(limit=25)
    if audit:
        with st.expander("Audit timeline (global)", expanded=False):
            st.caption("Global events like bulk resets. Per-artifact edits are stored in each artifact's meta.history.")
            st.table(list(reversed(audit)))

    timings = st.session_state.get("timings", [])
    if timings:
        with st.expander("Performance (last runs)", expanded=False):
            st.caption("Durations are measured around each step and saved with the artifact metadata when available.")
            st.table(timings[-10:])