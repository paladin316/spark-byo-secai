
from __future__ import annotations

import streamlit as st

def render(cfg) -> None:
    st.subheader("Network")
    st.caption("Proxy + TLS settings apply to outbound HTTP fetches (web search + URL page fetch). Safe-by-default.")

    # --- Proxy ---
    st.markdown("### Proxy")
    try:
        net = getattr(cfg, "network", None)
        if net is None:
            st.warning("Network config model not available in this build.")
            return
        px = net.proxy
    except Exception:
        st.warning("Network proxy config not available.")
        return

    px.enabled = st.checkbox(
        "Enable proxy support",
        value=bool(getattr(px, "enabled", False)),
        help="When enabled, SPARK can route outbound HTTP traffic through a proxy (corporate or local).",
    )

    modes = ["off", "env", "explicit", "winhttp"]
    mode_help = {
        "off": "No explicit proxy config. Requests may still use environment variables if set.",
        "env": "Use environment variables (HTTP_PROXY/HTTPS_PROXY/NO_PROXY).",
        "explicit": "Use proxy URLs set below.",
        "winhttp": "Windows only: best-effort WinHTTP proxy discovery (netsh winhttp show proxy).",
    }
    cur_mode = str(getattr(px, "mode", "off") or "off").lower()
    if cur_mode not in modes:
        cur_mode = "off"

    px.mode = st.selectbox(
        "Proxy mode",
        options=modes,
        index=modes.index(cur_mode),
        help=mode_help.get(cur_mode, ""),
        disabled=not bool(px.enabled),
    )

    cols = st.columns([1, 1])
    with cols[0]:
        px.http = st.text_input(
            "HTTP proxy",
            value=str(getattr(px, "http", "") or ""),
            placeholder="http://proxy.corp:8080",
            disabled=(not px.enabled) or (px.mode != "explicit"),
        )
    with cols[1]:
        px.https = st.text_input(
            "HTTPS proxy",
            value=str(getattr(px, "https", "") or ""),
            placeholder="http://proxy.corp:8080",
            disabled=(not px.enabled) or (px.mode != "explicit"),
        )

    px.no_proxy = st.text_input(
        "NO_PROXY / bypass list",
        value=str(getattr(px, "no_proxy", "") or ""),
        placeholder="localhost,127.0.0.1,.corp,10.0.0.0/8,192.168.0.0/16",
        help="Comma-separated hosts/domains/CIDRs to bypass the proxy (best-effort).",
        disabled=not bool(px.enabled),
    )

    with st.expander("Proxy authentication (optional)", expanded=False):
        px.username = st.text_input(
            "Proxy username",
            value=str(getattr(px, "username", "") or ""),
            disabled=(not px.enabled) or (px.mode != "explicit"),
        )
        px.password = st.text_input(
            "Proxy password",
            value=str(getattr(px, "password", "") or ""),
            type="password",
            disabled=(not px.enabled) or (px.mode != "explicit"),
        )
        st.caption("Note: NTLM/Kerberos proxy auth is optional and environment-dependent. If your proxy requires NTLM, install requests-ntlm and re-try, or use system proxy settings.")

    # Quick network/proxy diagnostic so users can confirm egress behavior.
    st.markdown("#### Proxy test")
    st.caption("Runs a small HTTPS request using the same client used for URL ingestion. Useful to confirm proxy routing.")

    # Configurable test URL (default is stable + low-risk). Stored in config so teams can point it at an allowed endpoint.
    default_test_url = getattr(px, "test_url", "") or "https://www.iana.org/"
    px.test_url = st.text_input(
        "Proxy test URL",
        value=default_test_url,
        help="Optional. Use a URL that your environment allows (e.g., a corporate allow-listed site).",
    ).strip() or "https://www.iana.org/"

    # Only perform the request when the user clicks the button (avoid duplicate calls on Streamlit reruns).
    if st.button("Run proxy test", key="run_proxy_test"):
        try:
            from byo_secai.web_search import _build_requests_session, _scrub_proxy_url
            s = _build_requests_session(cfg)

            p_http = _scrub_proxy_url(str((s.proxies or {}).get("http", "")))
            p_https = _scrub_proxy_url(str((s.proxies or {}).get("https", "")))

            details = {
                "trust_env": bool(getattr(s, "trust_env", False)),
                "http_proxy": p_http or "(none)",
                "https_proxy": p_https or "(none)",
                "verify": str(getattr(s, "verify", True)),
                "test_url": px.test_url,
            }

            # Persist the last result so it displays without re-firing on rerender.
            st.session_state["proxy_test_last_details"] = details

            r = s.get(px.test_url, timeout=8, allow_redirects=True)
            st.session_state["proxy_test_last_ok"] = True
            st.session_state["proxy_test_last_msg"] = f"Proxy test OK: HTTP {r.status_code} from {px.test_url}"
        except Exception as e:
            st.session_state["proxy_test_last_ok"] = False
            st.session_state["proxy_test_last_msg"] = f"Proxy test failed: {e}"

    # Display last test result (if any) without triggering a new request.
    if "proxy_test_last_details" in st.session_state:
        st.write(st.session_state.get("proxy_test_last_details", {}))
    if "proxy_test_last_ok" in st.session_state and "proxy_test_last_msg" in st.session_state:
        if st.session_state.get("proxy_test_last_ok"):
            st.success(st.session_state.get("proxy_test_last_msg"))
        else:
            st.error(st.session_state.get("proxy_test_last_msg"))


    # --- TLS ---
    st.markdown("### TLS")
    try:
        tls = net.tls
    except Exception:
        tls = None

    if tls is None:
        st.warning("Network TLS config not available.")
    else:
        tls.verify = st.checkbox(
            "Verify TLS certificates",
            value=bool(getattr(tls, "verify", True)),
            help="Disable only for debugging. Prefer adding a corporate CA bundle instead.",
        )
        tls.ca_bundle_path = st.text_input(
            "CA bundle path (PEM)",
            value=str(getattr(tls, "ca_bundle_path", "") or ""),
            placeholder="C:\\path\\corp_root_ca.pem or /etc/ssl/certs/corp.pem",
            help="If set, this PEM bundle is used for TLS verification.",
        )

    st.markdown("---")

    st.markdown("### Safe-by-default ingestion controls")
    cfg.web_enable_third_party_fetch_fallback = st.checkbox(
        "Enable third-party fetch fallback (r.jina.ai)",
        value=bool(getattr(cfg, "web_enable_third_party_fetch_fallback", False)),
        help="If enabled, SPARK may send the target URL to a third-party text proxy to bypass blocks. Off by default.",
    )
    cfg.web_enable_js_rendered_page_ingestion = st.checkbox(
        "Enable JS-rendered page ingestion (Playwright)",
        value=bool(getattr(cfg, "web_enable_js_rendered_page_ingestion", False)),
        help="If enabled and Playwright is installed, SPARK can render JS-heavy pages. Off by default.",
    )
    cfg.allow_legacy_office_conversion = st.checkbox(
        "Allow legacy Office conversion (.doc/.xls via LibreOffice)",
        value=bool(getattr(cfg, "allow_legacy_office_conversion", False)),
        help="Disabled by default for safety. Enable only in trusted environments.",
    )

    st.info(
        "If a URL can't be ingested with safe defaults, export it and upload it instead: "
        "Print → Save as PDF, or copy/paste into a .txt/.md file."
    )
