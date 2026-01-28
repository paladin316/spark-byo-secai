from __future__ import annotations

from .plugin_utils import supported_iocs

import os
import time
import urllib.parse
import requests

from ..config import load_config_yaml


def _get_api_key() -> str | None:
    # Env var wins.
    key = os.environ.get("URLSCAN_API_KEY")
    if key:
        return key.strip() or None
    cfg = load_config_yaml() or {}
    if isinstance(cfg, dict):
        k = cfg.get("urlscan_api_key") or cfg.get("URLSCAN_API_KEY")
        if isinstance(k, str):
            return k.strip() or None
    return None


def _get_mode() -> str:
    """search (default) or submit"""
    cfg = load_config_yaml() or {}
    if isinstance(cfg, dict):
        mode = (cfg.get("urlscan_mode") or cfg.get("urlscan", {}).get("mode") if isinstance(cfg.get("urlscan"), dict) else None)
        if isinstance(mode, str) and mode.strip():
            return mode.strip().lower()
    return "search"


def _headers(api_key: str) -> dict:
    # urlscan docs: use API-Key header (not x-api-key). citeturn2search0
    return {
        "API-Key": api_key,
        "User-Agent": "BYO-SecAI/Phase5_4 (IOC Enrichment)",
        "Accept": "application/json",
    }


def _search(q: str, api_key: str, size: int = 1) -> dict:
    # Search API endpoint: GET /api/v1/search?q=... citeturn2search1
    url = "https://urlscan.io/api/v1/search/"
    r = requests.get(url, headers=_headers(api_key), params={"q": q, "size": size}, timeout=20)
    # best-effort backoff on 429
    if r.status_code == 429:
        # small backoff; caller can retry later
        return {"error": f"HTTP 429 rate limited for search", "status_code": 429}
    if r.status_code != 200:
        return {"error": f"HTTP {r.status_code}: {r.text}", "status_code": r.status_code}
    try:
        return r.json()
    except Exception as e:
        return {"error": f"Failed to parse JSON: {e}", "status_code": r.status_code}


def _escape_query_value(val: str) -> str:
    # We keep it simple: wrap in quotes; urlscan uses Elasticsearch Query String; values lowercased in index. citeturn0view0
    v = (val or "").strip()
    v = v.replace('"', '\\"')
    return f'"{v}"'


def _ioc_to_query(ioc: str, ioc_type: str) -> str:
    # Use stable fields from search docs
    if ioc_type == "url":
        # Prefer task.url (original URL tasked)
        return f"task.url:{_escape_query_value(ioc)}"
    if ioc_type == "domain":
        return f"page.domain:{_escape_query_value(ioc)}"
    if ioc_type == "ip":
        return f"page.ip:{_escape_query_value(ioc)}"
    return ""


@supported_iocs("url", "domain", "ip")
def run(ioc: str) -> dict:
    """Search urlscan.io for an existing scan related to the IOC.

    We default to Search API to avoid unnecessary submissions and to align with best practices
    (search before submit). citeturn2search0turn2search1
    """
    api_key = _get_api_key()
    if not api_key:
        return {"error": "URLSCAN_API_KEY not set in env or config.yaml"}

    # Determine IOC type via lightweight heuristics (caller also sets type in envelope)
    ioc_s = (ioc or "").strip()
    ioc_type = "url"
    if "://" not in ioc_s and "/" not in ioc_s and "." in ioc_s:
        # could be domain
        ioc_type = "domain"
    if ioc_s.count(".") >= 3 and all(p.isdigit() for p in ioc_s.split(".") if p):
        ioc_type = "ip"

    mode = _get_mode()
    if mode != "search":
        # Keep legacy submit behavior available, but not default.
        submit_url = "https://urlscan.io/api/v1/scan/"
        payload = {"url": ioc_s, "visibility": "public"}
        r = requests.post(submit_url, headers=_headers(api_key) | {"Content-Type": "application/json"}, json=payload, timeout=30)
        if r.status_code == 429:
            return {"error": "HTTP 429 rate limited for submit", "status_code": 429}
        if r.status_code not in (200, 201):
            return {"error": f"HTTP {r.status_code}: {r.text}", "status_code": r.status_code}
        try:
            data = r.json()
        except Exception as e:
            return {"error": f"Failed to parse JSON: {e}", "status_code": r.status_code}
        return {"mode": "submit", "uuid": data.get("uuid"), "result": data.get("result"), "api": data}

    q = _ioc_to_query(ioc_s, ioc_type)
    if not q:
        return {"error": f"IOC type not supported for search: {ioc_type}"}

    data = _search(q, api_key, size=1)
    if data.get("error"):
        return data

    results = data.get("results") or []
    if not results:
        return {"mode": "search", "found": False, "query": q}

    hit = results[0] if isinstance(results[0], dict) else {}
    task = hit.get("task") or {}
    uuid = task.get("uuid") or hit.get("_id")
    result_url = hit.get("result") or hit.get("page", {}).get("url")

    return {
        "mode": "search",
        "found": True,
        "query": q,
        "uuid": uuid,
        "result_url": result_url,
        "hit": hit,
    }
