from .plugin_utils import supported_iocs
import os
import requests
import base64
import re

from ..config import load_config_yaml, get_last_loaded_config_path

def _get_api_key() -> str | None:
    # Env var wins.
    key = os.environ.get("VT_API_KEY") or os.environ.get("VIRUSTOTAL_API_KEY")
    if key:
        return key
    cfg = load_config_yaml() or {}
    if isinstance(cfg, dict):
        # Support both the flat keys and a nested structure (future-proof).
        key = (cfg.get("virustotal_api_key") or None)
        if key:
            return key
        plugins = cfg.get("plugins") if isinstance(cfg.get("plugins"), dict) else {}
        # Some configs use plugins.virustotal.api_key
        if isinstance(plugins, dict):
            vt = plugins.get("virustotal")
            if isinstance(vt, dict):
                return vt.get("api_key") or None
    return None
@supported_iocs('ip', 'hash', 'url')
def run(ioc: str) -> dict:
    """
    Query VirusTotal for an IP or SHA256 hash.
    Returns a dict with 'source', 'ioc', and either 'result' or 'error'.
    """
    api_key = _get_api_key()
    if not api_key:
        cfg_path = get_last_loaded_config_path()
        hint = f" (loaded config: {cfg_path})" if cfg_path else " (no config.yaml found)"
        return {"source": "virustotal", "ioc": ioc, "error": f"Missing VirusTotal API key{hint}. Set VT_API_KEY env var or virustotal_api_key in config.yaml."}

    # Normalize URL-style IOC
    if re.match(r'^https?://', ioc):
        # VT requires a URL identifier: base64(url) without padding
        url_id = base64.urlsafe_b64encode(ioc.encode()).decode().strip('=')
        endpoint = f"urls/{url_id}"
    # File hash?
    elif re.match(r'^[0-9A-Fa-f]{64}$', ioc):
        endpoint = f"files/{ioc}"
    # Fallback to IP
    else:
        endpoint = f"ip_addresses/{ioc}"

    url = f"https://www.virustotal.com/api/v3/{endpoint}"
    headers = {"x-apikey": api_key}

    try:
        resp = requests.get(url, headers=headers, timeout=30)
    except requests.RequestException as e:
        return {"source": "virustotal", "ioc": ioc, "error": f"Request failed: {e}"}

    if resp.status_code == 200:
        data = resp.json().get("data")
        return {"source": "virustotal", "ioc": ioc, "result": data}
    else:
        return {"source": "virustotal", "ioc": ioc, "error": resp.text}
