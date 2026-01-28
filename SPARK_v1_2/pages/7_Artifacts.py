import streamlit as st

from byo_secai.perf import view_timer, render_perf_panel

from app import set_page, ensure_nav_default, get_cfg, spark_header, render_dashboard, get_storage, render_main, render_footer


def render_artifacts_page():
    """Artifacts browser.

    In the multi-page layout, we avoid importing view functions from app.py.
    This page renders its own lightweight artifacts explorer.
    """
    store = get_storage()
    rows = store.load_index() or []

    st.subheader("Artifacts")
    if st.button("Rebuild artifact index", help="Rescan data/artifacts and rebuild _index.json"):
        with st.spinner("Rebuilding index..."):
            store.rebuild_index()
        st.success("Index rebuilt")
        st.rerun()

    # Filters
    types = sorted({r.get("type") for r in rows if isinstance(r, dict) and r.get("type")})
    c1, c2 = st.columns([2, 3])
    with c1:
        type_filter = st.selectbox("Type", options=["(all)"] + types, index=0)
    with c2:
        text = st.text_input("Search (id/title)", value="")

    def _match(r: dict) -> bool:
        if type_filter != "(all)" and r.get("type") != type_filter:
            return False
        if text:
            hay = f"{r.get('id','')} {r.get('title','')}".lower()
            if text.lower() not in hay:
                return False
        return True

    filtered = [r for r in rows if isinstance(r, dict) and _match(r)]
    st.caption(f"Showing {len(filtered)} of {len(rows)} artifacts")

    # Display index table
    st.dataframe(filtered, hide_index=True, width="stretch")

    # Select an artifact to inspect
    ids = [r.get("id") for r in filtered if r.get("id")]
    if not ids:
        st.info("No artifacts match the current filters.")
        return

    selected_id = st.selectbox("Inspect artifact", options=ids)
    sel = next((r for r in filtered if r.get("id") == selected_id), None)
    if not sel:
        return

    st.markdown('<div class="spark-divider"></div>', unsafe_allow_html=True)
    st.subheader("Artifact details")
    st.json(sel)

    # Load and show raw JSON
    atype = sel.get("type")
    if atype:
        try:
            # Storage.load expects ArtifactType enum; resolve by value.
            from byo_secai.models import ArtifactType

            art_type = ArtifactType(atype)
            model = store.load(art_type, selected_id)
            if model is not None:
                if hasattr(model, "model_dump"):
                    st.subheader("Artifact JSON")
                    st.json(model.model_dump())
        except Exception as e:
            st.warning(f"Could not load artifact JSON: {e}")


def main():
    set_page()
    ensure_nav_default()
    cfg = get_cfg()

    spark_header(cfg)
    with st.container():
        render_dashboard()

    render_perf_panel("sidebar")
    st.markdown('<div class="spark-divider"></div>', unsafe_allow_html=True)

    with view_timer("Artifacts"):
        render_main(render_artifacts_page)

    render_footer()


if __name__ == "__main__":
    main()
