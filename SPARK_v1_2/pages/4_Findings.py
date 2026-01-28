import streamlit as st

from byo_secai.perf import view_timer, render_perf_panel

from app import set_page, ensure_nav_default, get_cfg, spark_header, render_dashboard, render_findings, render_main, render_footer


def main():
    set_page()
    ensure_nav_default()
    cfg = get_cfg()

    spark_header(cfg)
    with st.container():
        render_dashboard()

    render_perf_panel("sidebar")
    st.markdown('<div class="spark-divider"></div>', unsafe_allow_html=True)

    with view_timer("Findings"):
        render_main(render_findings)

    render_footer()


if __name__ == "__main__":
    main()
