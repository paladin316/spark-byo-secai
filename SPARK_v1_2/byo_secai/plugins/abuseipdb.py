from __future__ import annotations

from .plugin_utils import supported_iocs

import os
import requests

from ..config import load_config_yaml, get_last_loaded_config_path


def _get_api_key() -> str | None:
    # Env var wins.
    key = os.environ.get("ABUSEIPDB_API_KEY") or os.environ.get("ABUSE_IPDB_API_KEY")
    if key:
        return key
    cfg = load_config_yaml() or {}
    if not isinstance(cfg, dict):
        return None

    key = (cfg.get("abuseipdb_api_key") or None)
    if key:
        return key
    plugins = cfg.get("plugins") if isinstance(cfg.get("plugins"), dict) else {}
    if isinstance(plugins, dict):
        ab = plugins.get("abuseipdb")
        if isinstance(ab, dict):
            return ab.get("api_key") or None
    return None


@supported_iocs("ip")
def run(ioc: str) -> dict:
    """Query AbuseIPDB for an IP address."""

    api_key = _get_api_key()
    if not api_key:
        cfg_path = get_last_loaded_config_path()
        hint = f" (loaded config: {cfg_path})" if cfg_path else " (no config.yaml found)"
        return {"source": "abuseipdb", "ioc": ioc, "error": f"Missing AbuseIPDB API key{hint}. Set ABUSEIPDB_API_KEY env var or abuseipdb_api_key in config.yaml."}

    url = "https://api.abuseipdb.com/api/v2/check"
    headers = {"Accept": "application/json", "Key": api_key}
    params = {"ipAddress": ioc, "maxAgeInDays": 90}

    try:
        resp = requests.get(url, headers=headers, params=params, timeout=30)
    except requests.RequestException as e:
        return {"source": "abuseipdb", "ioc": ioc, "error": f"Request failed: {e}"}

    if resp.status_code == 200:
        data = resp.json().get("data")
        return {"source": "abuseipdb", "ioc": ioc, "result": data}
    return {"source": "abuseipdb", "ioc": ioc, "error": resp.text}
