import os
import re
import pkgutil
import importlib
import ipaddress

from ..config import load_config_yaml

PLUGIN_PACKAGE = 'byo_secai.plugins'

def normalize_ioc(ioc: str) -> str:
    """
    Normalize common defanging patterns:
    - Replace '[.]' and '(.)' with '.'
    - Replace 'hxxp://' with 'http://', 'hxxps://' with 'https://'
    """
    s = ioc.strip()
    s = s.replace('hxxps://', 'https://').replace('hxxp://', 'http://')
    s = s.replace('[.]', '.').replace('(.)', '.')
    return s


def detect_ioc_type(ioc: str) -> str:
    """
    Identify IOC types for plugin routing.

    Guardrails:
    - Treat common executable/script extensions as *file* (avoid filenames as domains).
    - Split IP:PORT as ip_port.
    - AbuseIPDB should only receive ip (not ip_port) — routing handles that.
    """
    if not ioc:
        return "unknown"
    s = ioc.strip().strip("[](){}<>.,;\"'")

    # Hashes
    if re.fullmatch(r"[A-Fa-f0-9]{32}", s) or re.fullmatch(r"[A-Fa-f0-9]{40}", s) or re.fullmatch(r"[A-Fa-f0-9]{64}", s):
        return "hash"

    # URLs
    if re.match(r"^https?://", s, flags=re.I):
        return "url"

    # Files (hard guardrail: don't treat as domain)
    if re.search(r"\.(exe|dll|sys|bat|ps1|vbs|js|jar|zip|rar|7z)$", s, flags=re.I):
        return "file"

    # IP:PORT
    if re.fullmatch(r"\d{1,3}(?:\.\d{1,3}){3}:\d{1,5}", s):
        ip, port = s.split(":", 1)
        try:
            ipaddress.ip_address(ip)
            p = int(port)
            if 1 <= p <= 65535:
                return "ip_port"
        except Exception:
            pass

    # IP
    try:
        ipaddress.ip_address(s)
        return "ip"
    except ValueError:
        pass

    # Domain (basic sanity: has dot, no slashes, and TLD-ish suffix)
    if "/" not in s and "." in s and "@" not in s:
        tld = s.rsplit(".", 1)[-1].lower()
        # prevent obvious filename extensions from being classified as domains
        if tld in {"exe","dll","sys","bat","ps1","vbs","js","zip","rar","7z"}:
            return "file"
        if 2 <= len(tld) <= 24 and tld.isalpha():
            return "domain"

    return "unknown"


def discover_plugins() -> list:
    """Return a list of plugin names found in the plugins package."""
    cfg = load_config_yaml() or {}
    enabled = (cfg.get("plugins") or {}) if isinstance(cfg, dict) else {}

    package = importlib.import_module(PLUGIN_PACKAGE)
    path = package.__path__
    names = []
    for _, name, ispkg in pkgutil.iter_modules(path):
        if name in ('plugin_loader', 'plugin_utils'):
            continue
        # Respect config.yaml plugin toggles (default to enabled unless explicitly false).
        if isinstance(enabled, dict) and name in enabled and enabled.get(name) is False:
            continue
        names.append(name)
    return names


def run_plugins_for_ioc(ioc: str) -> dict:
    """
    Run only the plugins whose `run` function has declared support for this IOC type.
    Gracefully handle import errors and unsupported IOC types.
    """
    ioc_type = detect_ioc_type(ioc)
    results = {}

    def _coerce_ioc(src_ioc: str, src_type: str, target_type: str) -> str | None:
        """Coerce an IOC into a different supported type when safe.

        This is primarily to handle ip:port indicators from intel reports.
        Some plugins (e.g., AbuseIPDB) only accept raw IPs, not IP+Port.
        """
        s = normalize_ioc(src_ioc)
        if src_type == "ip_port" and target_type == "ip":
            if ":" in s:
                return s.split(":", 1)[0].strip()
            if "|" in s:
                return s.split("|", 1)[0].strip()
        return None

    for name in discover_plugins():
        # Attempt to import the plugin module
        try:
            module = importlib.import_module(f"{PLUGIN_PACKAGE}.{name}")
        except ImportError as e:
            results[name] = {
                'source': name,
                'ioc': ioc,
                'error': f"Failed to import plugin: {e}"
            }
            continue

        run_fn = getattr(module, 'run', None)
        if run_fn is None:
            results[name] = {
                'source': name,
                'ioc': ioc,
                'error': 'Plugin has no run(ioc) function'
            }
            continue

        # Check IOC support
        supported = getattr(run_fn, 'supported_iocs', set())

        # If the exact type isn't supported, try safe coercions (e.g., ip_port -> ip).
        exec_ioc = ioc
        exec_type = ioc_type
        coerced_from: str | None = None

        if exec_type not in supported:
            if exec_type == "ip_port" and "ip" in supported:
                coerced = _coerce_ioc(exec_ioc, exec_type, "ip")
                if coerced:
                    coerced_from = exec_ioc
                    exec_ioc = coerced
                    exec_type = "ip"

        if exec_type not in supported:
            results[name] = {
                'source': name,
                'ioc': ioc,
                'ioc_type': ioc_type,
                'skipped': f"{ioc_type} not supported"
            }
            continue

        # Execute plugin
        try:
            res = run_fn(exec_ioc)
            meta = getattr(module, 'meta', lambda: {})()
            if isinstance(res, dict):
                res.setdefault('source', name)
                # Preserve the original IOC string for callers/UI.
                res.setdefault('ioc', ioc)
                if coerced_from is not None:
                    res.setdefault('coerced_ioc', exec_ioc)
                res['meta'] = meta
                results[name] = res
            else:
                results[name] = {
                    'source': name,
                    'ioc': ioc,
                    'ioc_type': ioc_type,
                    'exec_ioc': exec_ioc,
                    'exec_ioc_type': exec_type,
                    'coerced_from': coerced_from,
                    'result': res,
                    'meta': meta
                }
        except Exception as e:
            results[name] = {
                'source': name,
                'ioc': ioc,
                'ioc_type': ioc_type,
                'error': str(e)
            }
    return results
