from __future__ import annotations

"""Lightweight web search abstraction for Phase 6.2.

Default provider is DuckDuckGo (no key). Optional providers support API keys.

This module is intentionally shallow: it uses snippets and titles and only
returns a small number of results to keep the UI responsive and minimize data
leaving the host.
"""

from dataclasses import dataclass
from typing import Any, Dict, List, Optional
import os
import re
import time
import subprocess
import platform
import logging

import requests


log = logging.getLogger(__name__)




# Shared requests session (proxy-aware)
_SESSION: requests.Session | None = None
_SESSION_FINGERPRINT: str = ""

def _scrub_proxy_url(url: str) -> str:
    try:
        u = (url or "").strip()
        return re.sub(r'^(https?://)([^/@:]+):([^/@]+)@', r'\1***:***@', u, flags=re.I)
    except Exception:
        return (url or "")

def _parse_winhttp_proxy() -> tuple[dict, str]:
    """Windows best-effort WinHTTP proxy detection (netsh)."""
    if platform.system().lower() != "windows":
        return ({}, "")
    try:
        proc = subprocess.run(
            ["netsh", "winhttp", "show", "proxy"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=5,
            check=False,
        )
        out = (proc.stdout or b"").decode("utf-8", errors="ignore")
        if "Direct access" in out:
            return ({}, "")
        proxies: dict = {}
        m = re.search(r"Proxy Server\(s\)\s*:\s*(.+)", out, re.I)
        if m:
            val = (m.group(1) or "").strip()
            if "=" in val:
                parts = [p.strip() for p in val.split(";") if p.strip()]
                for p in parts:
                    if "=" in p:
                        scheme, addr = p.split("=", 1)
                        scheme = scheme.strip().lower()
                        addr = addr.strip()
                        if addr and not addr.lower().startswith("http"):
                            addr = "http://" + addr
                        if scheme in ("http","https"):
                            proxies[scheme] = addr
            else:
                addr = val
                if addr and not addr.lower().startswith("http"):
                    addr = "http://" + addr
                if addr:
                    proxies["http"] = addr
                    proxies["https"] = addr

        m2 = re.search(r"Bypass List\s*:\s*(.+)", out, re.I)
        no_proxy = ""
        if m2:
            no_proxy = (m2.group(1) or "").strip()
            if no_proxy == "<local>":
                no_proxy = "localhost,127.0.0.1"
        return (proxies, no_proxy)
    except Exception:
        return ({}, "")

def _build_requests_session(cfg=None) -> requests.Session:
    """Return a shared requests.Session configured for proxy + TLS."""
    global _SESSION, _SESSION_FINGERPRINT

    proxies: dict = {}
    verify: bool | str = True
    trust_env: bool = False
    fp_parts: list[str] = ["default"]

    try:
        net = getattr(cfg, "network", None) if cfg is not None else None
        px = getattr(net, "proxy", None) if net is not None else None
        tls = getattr(net, "tls", None) if net is not None else None

        if tls is not None:
            ca = str(getattr(tls, "ca_bundle_path", "") or "").strip()
            if ca:
                verify = ca
                fp_parts.append("ca:"+ca)
            else:
                verify = bool(getattr(tls, "verify", True))
                fp_parts.append("verify:"+str(bool(verify)))

        mode = "off"
        enabled = False
        if px is not None:
            enabled = bool(getattr(px, "enabled", False))
            mode = str(getattr(px, "mode", "off") or "off").strip().lower()
        if not enabled:
            mode = "off"

        if mode == "explicit":
            # In explicit mode we do NOT want environment variables to
            # silently override the configured proxies.
            trust_env = False
            http_px = str(getattr(px, "http", "") or "").strip()
            https_px = str(getattr(px, "https", "") or "").strip()
            user = str(getattr(px, "username", "") or "").strip()
            pw = str(getattr(px, "password", "") or "").strip()

            def _inject(u: str) -> str:
                if not u:
                    return u
                if user and pw and "@" not in u:
                    return re.sub(r"^(https?://)", r"\1" + user + ":" + pw + "@", u, flags=re.I)
                return u

            if http_px:
                proxies["http"] = _inject(http_px)
            if https_px:
                proxies["https"] = _inject(https_px)

            np = str(getattr(px, "no_proxy", "") or "").strip()
            if np:
                os.environ["NO_PROXY"] = np
                os.environ["no_proxy"] = np

            fp_parts.append("explicit:"+_scrub_proxy_url(http_px)+":"+_scrub_proxy_url(https_px)+":np:"+np)

        elif mode == "env":
            trust_env = True
            np = str(getattr(px, "no_proxy", "") or "").strip() if px is not None else ""
            if np:
                os.environ["NO_PROXY"] = np
                os.environ["no_proxy"] = np
            fp_parts.append("env:np:"+np)

        elif mode == "winhttp":
            trust_env = False
            win_proxies, win_np = _parse_winhttp_proxy()
            proxies.update(win_proxies or {})
            if win_np:
                os.environ["NO_PROXY"] = win_np
                os.environ["no_proxy"] = win_np
            fp_parts.append("winhttp:"+",".join(sorted([_scrub_proxy_url(str(v)) for v in proxies.values()]))+":np:"+win_np)

    except Exception:
        pass

    fp = "|".join(fp_parts)
    if _SESSION is None or fp != _SESSION_FINGERPRINT:
        s = requests.Session()
        # Only trust environment proxies when explicitly requested.
        s.trust_env = bool(trust_env)
        if proxies:
            s.proxies.update(proxies)
        s.verify = verify
        _SESSION = s
        _SESSION_FINGERPRINT = fp
        try:
            # Scrub proxy secrets and keep logs safe.
            p_http = _scrub_proxy_url(str(proxies.get("http", "")))
            p_https = _scrub_proxy_url(str(proxies.get("https", "")))
            log.info(
                "HTTP session configured: trust_env=%s http_proxy=%s https_proxy=%s tls_verify=%s",
                bool(trust_env),
                p_http or "(none)",
                p_https or "(none)",
                str(verify),
            )
        except Exception:
            pass
    return _SESSION

# In-process cache to keep Streamlit reruns snappy.
# Key: (provider, query/max_results) or ("fetch", url)
_CACHE: Dict[str, Dict[str, Any]] = {}


def _cache_get(key: str, ttl_s: int) -> Optional[Any]:
    try:
        ent = _CACHE.get(key) or {}
        ts = float(ent.get("ts") or 0)
        if ttl_s > 0 and (time.time() - ts) <= float(ttl_s):
            return ent.get("value")
    except Exception:
        return None
    return None


def _cache_set(key: str, value: Any) -> None:
    try:
        _CACHE[key] = {"ts": time.time(), "value": value}
    except Exception:
        pass


@dataclass
class WebResult:
    title: str
    url: str
    snippet: str
    provider: str

    def as_dict(self) -> Dict[str, Any]:
        return {
            "title": self.title,
            "url": self.url,
            "snippet": self.snippet,
            "provider": self.provider,
        }


class WebSearchProvider:
    name: str = "base"

    def search(self, query: str, max_results: int = 5, timeout_s: int = 15, cfg=None) -> List[WebResult]:
        raise NotImplementedError


class DuckDuckGoProvider(WebSearchProvider):
    """HTML-scrape provider using DuckDuckGo's HTML endpoint (no key)."""

    name = "duckduckgo"

    def search(self, query: str, max_results: int = 5, timeout_s: int = 15, cfg=None) -> List[WebResult]:
        # Use the lightweight HTML interface to avoid JS.
        url = "https://duckduckgo.com/html/"
        headers = {
            "User-Agent": "Mozilla/5.0 (BYO-SecAI; +https://example.invalid)",
        }
        try:
            s = _build_requests_session(cfg)
            r = s.post(url, data={"q": query}, headers=headers, timeout=timeout_s)
            r.raise_for_status()
            html = r.text or ""
        except Exception:
            return []

        # Minimal parsing without BeautifulSoup (works in constrained envs).
        # DuckDuckGo HTML results typically include anchors like:
        # <a rel="nofollow" class="result__a" href="...">Title</a>
        # and snippets in <a class="result__snippet"> or <div class="result__snippet">.
        results: List[WebResult] = []
        # Find result blocks
        blocks = re.split(r"<div class=\"result__body\">", html)
        for b in blocks[1:]:
            if len(results) >= max_results:
                break
            m_link = re.search(r"<a[^>]+class=\"result__a\"[^>]+href=\"([^\"]+)\"[^>]*>(.*?)</a>", b, re.I | re.S)
            if not m_link:
                continue
            href = m_link.group(1).strip()
            title = _strip_html(m_link.group(2)).strip()
            m_snip = re.search(r"result__snippet\"[^>]*>(.*?)</(?:a|div)>", b, re.I | re.S)
            snippet = _strip_html(m_snip.group(1)).strip() if m_snip else ""

            if not href or not title:
                continue
            results.append(WebResult(title=title, url=href, snippet=snippet, provider=self.name))
        return results


class BingProvider(WebSearchProvider):
    name = "bing"

    def __init__(self, api_key: str | None = None):
        self.api_key = api_key or os.getenv("BING_SEARCH_API_KEY", "")

    def search(self, query: str, max_results: int = 5, timeout_s: int = 15, cfg=None) -> List[WebResult]:
        if not self.api_key:
            return []
        endpoint = os.getenv("BING_SEARCH_ENDPOINT", "https://api.bing.microsoft.com/v7.0/search")
        headers = {"Ocp-Apim-Subscription-Key": self.api_key}
        params = {"q": query, "count": int(max_results), "textDecorations": False, "textFormat": "Raw"}
        try:
            s = _build_requests_session(cfg)
            r = s.get(endpoint, headers=headers, params=params, timeout=timeout_s)
            r.raise_for_status()
            data = r.json() or {}
        except Exception:
            return []
        out: List[WebResult] = []
        for item in ((data.get("webPages") or {}).get("value") or []):
            if len(out) >= max_results:
                break
            out.append(
                WebResult(
                    title=str(item.get("name") or "").strip(),
                    url=str(item.get("url") or "").strip(),
                    snippet=str(item.get("snippet") or "").strip(),
                    provider=self.name,
                )
            )
        return [r for r in out if r.url and r.title]


class TavilyProvider(WebSearchProvider):
    name = "tavily"

    def __init__(self, api_key: str | None = None):
        self.api_key = api_key or os.getenv("TAVILY_API_KEY", "")

    def search(self, query: str, max_results: int = 5, timeout_s: int = 20, cfg=None) -> List[WebResult]:
        if not self.api_key:
            return []
        endpoint = os.getenv("TAVILY_ENDPOINT", "https://api.tavily.com/search")
        payload = {
            "api_key": self.api_key,
            "query": query,
            "max_results": int(max_results),
            "include_answer": False,
            "include_raw_content": False,
        }
        try:
            s = _build_requests_session(cfg)
            r = s.post(endpoint, json=payload, timeout=timeout_s)
            r.raise_for_status()
            data = r.json() or {}
        except Exception:
            return []
        out: List[WebResult] = []
        for item in (data.get("results") or []):
            if len(out) >= max_results:
                break
            out.append(
                WebResult(
                    title=str(item.get("title") or "").strip(),
                    url=str(item.get("url") or "").strip(),
                    snippet=str(item.get("content") or "").strip(),
                    provider=self.name,
                )
            )
        return [r for r in out if r.url and r.title]


class SerpAPIProvider(WebSearchProvider):
    name = "serpapi"

    def __init__(self, api_key: str | None = None):
        self.api_key = api_key or os.getenv("SERPAPI_API_KEY", "")

    def search(self, query: str, max_results: int = 5, timeout_s: int = 20, cfg=None) -> List[WebResult]:
        if not self.api_key:
            return []
        endpoint = os.getenv("SERPAPI_ENDPOINT", "https://serpapi.com/search.json")
        params = {
            "engine": "google",
            "q": query,
            "api_key": self.api_key,
            "num": int(max_results),
        }
        try:
            s = _build_requests_session(cfg)
            r = s.get(endpoint, params=params, timeout=timeout_s)
            r.raise_for_status()
            data = r.json() or {}
        except Exception:
            return []
        out: List[WebResult] = []
        for item in (data.get("organic_results") or []):
            if len(out) >= max_results:
                break
            out.append(
                WebResult(
                    title=str(item.get("title") or "").strip(),
                    url=str(item.get("link") or "").strip(),
                    snippet=str(item.get("snippet") or "").strip(),
                    provider=self.name,
                )
            )
        return [r for r in out if r.url and r.title]


def get_provider(name: str, keys: Optional[Dict[str, str]] = None) -> WebSearchProvider:
    n = (name or "duckduckgo").strip().lower()
    keys = keys or {}
    if n in ("ddg", "duckduckgo", "duck-duck-go"):
        return DuckDuckGoProvider()
    if n in ("bing", "microsoft"):
        return BingProvider(api_key=keys.get("bing_api_key") or "")
    if n in ("tavily",):
        return TavilyProvider(api_key=keys.get("tavily_api_key") or "")
    if n in ("serpapi", "serp"):
        return SerpAPIProvider(api_key=keys.get("serpapi_api_key") or "")
    return DuckDuckGoProvider()


def search_web(
    query: str,
    provider_name: str = "duckduckgo",
    max_results: int = 5,
    timeout_s: int = 15,
    keys: Optional[Dict[str, str]] = None,
    cache_ttl_s: int = 1800,
    cfg=None,
) -> List[Dict[str, Any]]:
    """Convenience wrapper returning list[dict] for storage/UI."""
    cache_key = f"search::{provider_name}::{int(max_results)}::{(query or '').strip().lower()}"
    cached = _cache_get(cache_key, ttl_s=int(cache_ttl_s))
    if isinstance(cached, list):
        return cached

    prov = get_provider(provider_name, keys=keys)
    started = time.time()
    res = prov.search(query=query, max_results=max_results, timeout_s=timeout_s, cfg=cfg)
    # De-dupe by URL
    seen = set()
    out: List[Dict[str, Any]] = []
    for r in res:
        u = (r.url or "").strip()
        if not u or u in seen:
            continue
        seen.add(u)
        out.append(r.as_dict())
    # Attach lightweight timing metadata
    dt = time.time() - started
    for r in out:
        r["_elapsed_s"] = round(dt, 3)
    _cache_set(cache_key, out)
    return out


def fetch_url_text(url: str, timeout_s: int = 20, max_chars: int = 12000, cache_ttl_s: int = 1800, cfg=None) -> str:
    """Fetch a URL and return a cleaned text version.

    Conservative, production-minded behavior:
      - Best-effort with short timeouts.
      - Avoid caching empty results (so retries can succeed).
      - Uses a lightweight proxy fallback (r.jina.ai) for some blocked pages.
      - Optional Playwright JS render as a last resort (if installed).
    """
    u = (url or "").strip()
    if not u or not re.match(r"^https?://", u, flags=re.I):
        return ""

    cache_key = f"fetch::{u}"
    cached = _cache_get(cache_key, ttl_s=int(cache_ttl_s))
    if isinstance(cached, str) and cached.strip():
        return cached

    headers = {
        "User-Agent": (
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
            "AppleWebKit/537.36 (KHTML, like Gecko) "
            "Chrome/120.0 Safari/537.36"
        ),
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.9",
        # Prefer encodings we can reliably decode. Some sites will still return br/zstd.
        "Accept-Encoding": "gzip, deflate, br",
        "Cache-Control": "no-cache",
        "Pragma": "no-cache",
    }

    def _decode_response(resp) -> str:
        """Return decoded HTML text from a requests response (handles zstd/br edge cases)."""
        try:
            enc = (resp.headers.get("content-encoding") or "").lower()
        except Exception:
            enc = ""

        # Normal path: requests decoding
        try:
            return resp.text or ""
        except Exception:
            pass

        # brotli manual decode (best-effort)
        if "br" in enc:
            try:
                import brotli  # optional dependency

                raw = brotli.decompress(resp.content or b"")
                charset = "utf-8"
                ctype = (resp.headers.get("content-type") or "").lower()
                m = re.search(r"charset=([\w\-]+)", ctype)
                if m:
                    charset = m.group(1)
                return raw.decode(charset, errors="replace")
            except Exception:
                pass

        # zstd manual decode (best-effort)
        if "zstd" in enc:
            try:
                import zstandard as zstd  # optional dependency

                dctx = zstd.ZstdDecompressor()
                raw = dctx.decompress(resp.content)
                charset = "utf-8"
                ctype = (resp.headers.get("content-type") or "").lower()
                m = re.search(r"charset=([\w\-]+)", ctype)
                if m:
                    charset = m.group(1)
                return raw.decode(charset, errors="replace")
            except Exception:
                return ""

        # Last resort: decode bytes as utf-8
        try:
            return (resp.content or b"").decode("utf-8", errors="replace")
        except Exception:
            return ""

    html = ""
    from_proxy = False

    # Direct fetch
    try:
        s = _build_requests_session(cfg)
        try:
            # Per-fetch egress hint (scrubbed) so users can confirm proxy usage.
            p_http = _scrub_proxy_url(str((s.proxies or {}).get("http", "")))
            p_https = _scrub_proxy_url(str((s.proxies or {}).get("https", "")))
            via_proxy = bool(p_http or p_https or getattr(s, "trust_env", False))
            log.info(
                "FETCH url=%s via_proxy=%s trust_env=%s http_proxy=%s https_proxy=%s",
                u,
                via_proxy,
                bool(getattr(s, "trust_env", False)),
                p_http or "(none)",
                p_https or "(none)",
            )
        except Exception:
            pass
        r = s.get(u, headers=headers, timeout=int(timeout_s), allow_redirects=True)
        r.raise_for_status()
        html = _decode_response(r) or ""
    except Exception:
        html = ""

    # Proxy fallback (returns plain text) — OFF by default
    allow_third_party = bool(getattr(cfg, "web_enable_third_party_fetch_fallback", False)) if cfg is not None else False
    if allow_third_party and (not html.strip()):
        try:
            if u.lower().startswith("https://"):
                proxy = "https://r.jina.ai/https://" + u[len("https://") :]
            else:
                proxy = "https://r.jina.ai/http://" + u[len("http://") :]

            s = _build_requests_session(cfg)
            r2 = s.get(proxy, headers=headers, timeout=int(timeout_s), allow_redirects=True)
            r2.raise_for_status()
            html = _decode_response(r2) or ""
            from_proxy = True
        except Exception:
            html = ""
            from_proxy = False

    # Optional JS render last (Playwright is an optional dependency).
    # We capture BOTH HTML and rendered innerText when possible.
    rendered_text = ""
    allow_js = bool(getattr(cfg, "web_enable_js_rendered_page_ingestion", False)) if cfg is not None else False
    if allow_js and (not html.strip()):
        html, rendered_text = _fetch_url_playwright(u, timeout_s=timeout_s, cfg=cfg)
        from_proxy = False

    # Convert to text
    if from_proxy:
        text = (html or "").strip()
    else:
        # Layer 1: DOM-targeted extraction (prioritizes Indicators/code/tables)
        text = _extract_dom_targeted_text(html, url=u).strip() if html else ""
        # Layer 2: rendered innerText fallback (still not OCR)
        # Use it when DOM extraction is empty/too short, or when we appear to have missed Indicators.
        if rendered_text:
            low = (text or "").lower()
            missed_indicators = ("indicators" in (rendered_text or "").lower()) and ("indicators" not in low)
            if (not text.strip()) or len(text) < 800 or missed_indicators:
                text = (rendered_text or "").strip()

    if max_chars and len(text) > int(max_chars):
        text = text[: int(max_chars)]

    if text.strip():
        _cache_set(cache_key, text)
    return text


def _fetch_url_playwright(url: str, timeout_s: int = 20, cfg=None) -> tuple[str, str]:
    """Best-effort JS render using Playwright (optional dependency).

    This is a LAST resort. It only runs if Playwright is installed and a browser
    runtime has been provisioned (run: `playwright install`).

    Returns a tuple: (raw_html, rendered_inner_text)
      - raw_html: from `page.content()`
      - rendered_inner_text: from `document.body.innerText` (more robust than HTML parsing)
    """
    try:
        from playwright.sync_api import sync_playwright
    except Exception:
        return "", ""

    # keep timeouts sane (ms)
    nav_timeout_ms = int(max(5, min(int(timeout_s), 60)) * 1000)

    try:
        with sync_playwright() as p:
            proxy_cfg = None
            try:
                s = _build_requests_session(cfg)
                px = getattr(s, "proxies", {}) if s is not None else {}
                server = (px.get("https") or px.get("http") or "") if isinstance(px, dict) else ""
                if server:
                    proxy_cfg = {"server": str(server)}
            except Exception:
                proxy_cfg = None

            browser = p.chromium.launch(headless=True, proxy=proxy_cfg) if proxy_cfg else p.chromium.launch(headless=True)
            page = browser.new_page()
            page.set_default_navigation_timeout(nav_timeout_ms)
            page.set_default_timeout(nav_timeout_ms)
            page.goto(url, wait_until="networkidle")
            html = page.content() or ""
            try:
                inner_text = page.evaluate("() => document.body ? document.body.innerText : ''") or ""
            except Exception:
                inner_text = ""
            browser.close()
            return html, inner_text
    except Exception:
        return "", ""


def _extract_dom_targeted_text(html: str, url: str = "") -> str:
    """Layer-1 extraction: parse DOM and prioritize high-value content.

    Goals:
      - Preserve code/pre blocks and tables.
      - Pull 'Indicators' style sections earlier so downstream truncation doesn't drop them.
      - Fall back safely to a readable text strip if BeautifulSoup isn't available.
    """
    try:
        from bs4 import BeautifulSoup  # type: ignore
    except Exception:
        return _strip_html(html)

    try:
        soup = BeautifulSoup(html or "", "html.parser")

        # Remove obvious non-content
        for tag in soup(["script", "style", "noscript", "header", "footer", "nav", "form", "aside"]):
            try:
                tag.decompose()
            except Exception:
                pass

        selectors = [
            "article",
            "main",
            "div.entry-content",
            "div.post-content",
            "div.post-entry",
            "div.td-post-content",
            "div.wp-block-post-content",
            "div#content",
            "div#primary",
        ]
        node = None
        for sel in selectors:
            try:
                node = soup.select_one(sel)
            except Exception:
                node = None
            if node and (node.get_text(" ", strip=True) or "").strip():
                break

        root = node or soup

        # 1) Indicators / IOCs section slice
        indicators_text = ""
        try:
            # Match headings that contain 'Indicators' or 'IOCs'
            headings = root.find_all(["h1", "h2", "h3", "h4"])
            target = None
            for h in headings:
                t = (h.get_text(" ", strip=True) or "").strip().lower()
                if not t:
                    continue
                if "indicator" in t or "ioc" in t or "iocs" in t:
                    target = h
                    break
            if target is not None:
                lvl = target.name
                parts: list[str] = []
                cur = target
                # capture until next same-or-higher level header
                while cur is not None:
                    cur = cur.find_next_sibling()
                    if cur is None:
                        break
                    if getattr(cur, "name", "") in ["h1", "h2", "h3", "h4"]:
                        # stop when we hit another major section
                        break
                    txt = cur.get_text("\n", strip=True) if hasattr(cur, "get_text") else ""
                    if txt:
                        parts.append(txt)
                if parts:
                    indicators_text = "\n".join(parts).strip()
        except Exception:
            indicators_text = ""

        # 2) code/pre blocks (high signal)
        code_parts: list[str] = []
        try:
            for pre in root.find_all(["pre", "code"]):
                t = pre.get_text("\n", strip=True)
                if t and len(t) > 10:
                    code_parts.append(t)
        except Exception:
            code_parts = []

        # 3) tables
        table_parts: list[str] = []
        try:
            for table in root.find_all("table"):
                rows = []
                for tr in table.find_all("tr"):
                    cells = [c.get_text(" ", strip=True) for c in tr.find_all(["th", "td"])]
                    cells = [c for c in cells if c]
                    if cells:
                        rows.append("\t".join(cells))
                if rows:
                    table_parts.append("\n".join(rows))
        except Exception:
            table_parts = []

        # 4) full readable text
        full_text = ""
        try:
            full_text = root.get_text("\n", strip=True)
        except Exception:
            full_text = _strip_html(html)

        # Assemble with priority ordering so truncation keeps IOCs/MITRE-ish content.
        out_parts: list[str] = []
        if indicators_text:
            out_parts.append("[SECTION: Indicators]\n" + indicators_text)
        if code_parts:
            out_parts.append("[SECTION: Code Blocks]\n" + "\n\n".join(code_parts[:25]))
        if table_parts:
            out_parts.append("[SECTION: Tables]\n" + "\n\n".join(table_parts[:10]))
        if full_text:
            out_parts.append("[SECTION: Body]\n" + full_text)

        text = "\n\n".join(out_parts).strip()
        text = re.sub(r"\n{3,}", "\n\n", text).strip()
        return text if text else _strip_html(html)
    except Exception:
        return _extract_readable_text(html, url=url)




def _extract_readable_text(html: str, url: str = "") -> str:
    """Best-effort readable text extraction from HTML.

    Prefer common article containers (WordPress, blogs) and fall back to a simple tag strip.
    """
    try:
        from bs4 import BeautifulSoup  # type: ignore
    except Exception:
        return _strip_html(html)

    try:
        soup = BeautifulSoup(html or "", "html.parser")
        # Remove obvious non-content
        for tag in soup(["script", "style", "noscript", "header", "footer", "nav", "form", "aside"]):
            try:
                tag.decompose()
            except Exception:
                pass

        selectors = [
            "article",
            "main",
            "div.entry-content",
            "div.post-content",
            "div.post-entry",
            "div.td-post-content",
            "div.wp-block-post-content",
            "div#content",
            "div#primary",
        ]
        node = None
        for sel in selectors:
            try:
                node = soup.select_one(sel)
            except Exception:
                node = None
            if node and (node.get_text(" ", strip=True) or "").strip():
                break

        text = ""
        if node:
            text = node.get_text("\n", strip=True)
        else:
            text = soup.get_text("\n", strip=True)

        text = re.sub(r"\n{3,}", "\n\n", text).strip()
        return text if text else _strip_html(html)
    except Exception:
        return _strip_html(html)


def _strip_html(s: str) -> str:
    s = re.sub(r"<script.*?</script>", " ", s, flags=re.I | re.S)
    s = re.sub(r"<style.*?</style>", " ", s, flags=re.I | re.S)
    s = re.sub(r"<[^>]+>", " ", s)
    s = re.sub(r"\s+", " ", s)
    return s.replace("&amp;", "&").replace("&quot;", '"').replace("&#39;", "'").replace("&lt;", "<").replace("&gt;", ">")