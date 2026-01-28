from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict
import re
import os
import shutil


# Keep track of which config.yaml was actually loaded. This is critical for
# debugging "I set my API keys but it says missing" situations.
_LAST_LOADED_CONFIG_PATH: str | None = None
_LAST_LOADED_API_CONFIG_PATH: str | None = None


def _set_last_loaded_config_path(p: Path | None) -> None:
    global _LAST_LOADED_CONFIG_PATH
    _LAST_LOADED_CONFIG_PATH = str(p) if p is not None else None


def get_last_loaded_config_path() -> str | None:
    return _LAST_LOADED_CONFIG_PATH


def _set_last_loaded_api_config_path(p: Path | None) -> None:
    global _LAST_LOADED_API_CONFIG_PATH
    _LAST_LOADED_API_CONFIG_PATH = str(p) if p is not None else None


def get_last_loaded_api_config_path() -> str | None:
    return _LAST_LOADED_API_CONFIG_PATH


# Secrets are sourced from root/api_config.yaml (NOT data/config.yaml).
_SECRET_KEYS = {
    "virustotal_api_key",
    "abuseipdb_api_key",
    "urlscan_api_key",
    "bing_api_key",
    "tavily_api_key",
    "serpapi_api_key",
}


def get_api_config_path() -> Path:
    """Return the root API config path.

    This file is intentionally separate from data/config.yaml so the Settings UI
    can persist preferences without ever overwriting secrets.
    """
    try:
        return (Path.cwd() / "api_config.yaml").resolve()
    except Exception:
        return Path("api_config.yaml")


def migrate_legacy_root_config_to_api_config() -> None:
    """One-time migration: root/config.yaml -> root/api_config.yaml.

    Clean migration:
      - Extract ONLY secret/API-key fields from legacy root/config.yaml
      - Write them to root/api_config.yaml
      - Preserve the legacy file as config.yaml.migrated (best-effort)

    We do NOT continue supporting root/config.yaml for normal config loading.
    """
    try:
        api_p = get_api_config_path()
        legacy = (Path.cwd() / "config.yaml").resolve()

        if api_p.exists() or (not legacy.exists()):
            return

        raw = legacy.read_text(encoding="utf-8", errors="ignore")

        # Parse legacy YAML (best-effort)
        data = {}
        try:
            import yaml as _yaml  # type: ignore
            data = _yaml.safe_load(raw) or {}
            if not isinstance(data, dict):
                data = {}
        except Exception:
            # Minimal flat parse
            for line in raw.splitlines():
                line = line.split("#", 1)[0].strip()
                if not line or ":" not in line:
                    continue
                k, v = line.split(":", 1)
                data[k.strip()] = v.strip().strip('"').strip("'")

        secrets = {k: data.get(k, "") for k in _SECRET_KEYS if k in data}
        if not secrets:
            # Nothing to migrate; still preserve legacy file to avoid confusion.
            try:
                legacy.rename(legacy.with_suffix(".yaml.migrated"))
            except Exception:
                pass
            return

        # Write api_config.yaml with secrets only
        try:
            api_p.write_text(_safe_yaml_dump(secrets), encoding="utf-8")
        except Exception:
            return

        # Preserve legacy file
        try:
            legacy.rename(legacy.with_suffix(".yaml.migrated"))
        except Exception:
            # If rename fails, attempt to delete (best-effort) to enforce new model.
            try:
                legacy.unlink()
            except Exception:
                pass
    except Exception:
        return



def load_api_config_yaml() -> Dict[str, Any]:
    """Load root/api_config.yaml as a dict.

    Only secret keys are returned.
    """
    migrate_legacy_root_config_to_api_config()
    p = get_api_config_path()
    if not p.exists():
        _set_last_loaded_api_config_path(None)
        return {}
    _set_last_loaded_api_config_path(p)
    raw = p.read_text(encoding="utf-8", errors="ignore")

    try:
        import yaml as _yaml  # type: ignore
        data = _yaml.safe_load(raw) or {}
        data = data if isinstance(data, dict) else {}
    except Exception:
        # Minimal parse (flat key: value only)
        data = {}
        for line in raw.splitlines():
            line = line.split("#", 1)[0].strip()
            if not line or ":" not in line:
                continue
            k, v = line.split(":", 1)
            data[k.strip()] = v.strip().strip('"').strip("'")

    # Return only secrets
    out: Dict[str, Any] = {}
    for k in _SECRET_KEYS:
        if k in data:
            out[k] = data.get(k)
    return out


# ---------------------------------------------------------------------------
# Persistent config (data/config.yaml)
# ---------------------------------------------------------------------------

def get_persisted_config_path(data_dir: str | None = None) -> Path:
    """Return the persisted config path.

    By design, the user-editable config lives under the data directory so it
    survives upgrades/unzips.
    """
    d = (data_dir or os.environ.get("BYO_SECAI_DATA_DIR") or "data").strip() or "data"
    return Path(d) / "config.yaml"


def ensure_persisted_config_exists(data_dir: str | None = None) -> Path:
    """Create data/config.yaml if missing.

    Seeding strategy (clean + consistent):
      1) Start from bundled defaults (byo_secai/config.yaml)
      2) Strip secret keys (API keys) so data/config.yaml stays non-sensitive

    API keys are sourced from root/api_config.yaml at runtime.
    """
    p = get_persisted_config_path(data_dir)
    try:
        p.parent.mkdir(parents=True, exist_ok=True)
    except Exception:
        # If we can't create the folder, just return the intended path.
        return p

    if p.exists():
        return p

    def _deep_merge(base: Dict[str, Any], override: Dict[str, Any]) -> Dict[str, Any]:
        """Recursively merge override onto base (override wins)."""
        out: Dict[str, Any] = dict(base or {})
        for k, v in (override or {}).items():
            if isinstance(v, dict) and isinstance(out.get(k), dict):
                out[k] = _deep_merge(out.get(k, {}), v)  # type: ignore[arg-type]
            else:
                out[k] = v
        return out

    def _load_yaml_dict(path: Path) -> Dict[str, Any]:
        if not path.exists():
            return {}
        try:
            import yaml as _yaml  # type: ignore
            data = _yaml.safe_load(path.read_text(encoding="utf-8", errors="ignore")) or {}
            return data if isinstance(data, dict) else {}
        except Exception:
            # Fall back to our own minimal loader.
            try:
                return load_config_yaml(str(path)) or {}
            except Exception:
                return {}

    # Bundled defaults
    bundled = Path(__file__).resolve().parent / "config.yaml"
    base = _load_yaml_dict(bundled)

    seeded = dict(base)
    # Keep secrets out of persisted config by design.
    for k in list(seeded.keys()):
        if k in _SECRET_KEYS:
            seeded.pop(k, None)

    # Write seeded config.
    try:
        p.write_text(_safe_yaml_dump(seeded), encoding="utf-8")
    except Exception:
        # Best effort; caller will handle missing file.
        pass

    return p


def _safe_yaml_dump(data: Dict[str, Any]) -> str:
    """Dump YAML with PyYAML when available; otherwise a simple key: value writer."""
    try:
        import yaml as _yaml  # type: ignore
        return _yaml.safe_dump(data, sort_keys=False, allow_unicode=True)
    except Exception:
        # Minimal fallback; good enough for our flat + one-level dict config.
        lines: list[str] = []
        for k, v in (data or {}).items():
            if isinstance(v, dict):
                lines.append(f"{k}:")
                for kk, vv in v.items():
                    vv_s = "true" if vv is True else "false" if vv is False else "" if vv is None else str(vv)
                    # quote strings with ':' or '#'
                    if isinstance(vv, str) and (":" in vv_s or "#" in vv_s):
                        vv_s = f'"{vv_s}"'
                    lines.append(f"  {kk}: {vv_s}")
            else:
                vv_s = "true" if v is True else "false" if v is False else "" if v is None else str(v)
                if isinstance(v, str) and (":" in vv_s or "#" in vv_s):
                    vv_s = f'"{vv_s}"'
                lines.append(f"{k}: {vv_s}")
        return "\n".join(lines) + "\n"


def _config_from_appcfg(cfg: "AppConfig") -> Dict[str, Any]:
    """Convert an AppConfig to a dict of persisted config keys."""
    keys = [
        # Storage
        "data_dir",

        # Branding
        "app_title",
        "app_subtitle",
        "report_footer",
        "phase_label",

        # Templates
        "template_dir_override",

        # Ollama
        "ollama_host",
        "ollama_model",
        "ollama_temperature",
        "ollama_request_timeout_s",
        "fetch_source_urls",
        "max_source_chars",
        "show_llm_errors",

        # Hunt defaults
        "query_language",
        "kql_profile",
        "hunt_min_queries",
        "hunt_max_queries",
        "render_cache_enabled",
        # Approval gate auto-correct
        "approval_autocorrect_enabled",
        "approval_autocorrect_max_attempts",
        "approval_fail_open_after_autocorrect",
        "approval_autocorrect_prompt_pack",
        # Hunt mapping + glue + auto-correct
        "hunt_glue_enabled",
        "hunt_glue_prompt_pack",
        "hunt_autocorrect_enabled",
        "hunt_autocorrect_max_attempts",
        "hunt_fail_open_after_autocorrect",
        "hunt_autocorrect_prompt_pack",



        # Local RAG
        "rag_enabled",
        "rag_top_k",
        "rag_chunk_chars",
        "rag_overlap_chars",

        # Web search
        "web_enabled",
        "web_enabled_by_default",
        "web_fetch_pages",
        "web_cache_ttl_s",
        "web_provider",
        "web_max_results",
        "web_enable_third_party_fetch_fallback",
        "web_enable_js_rendered_page_ingestion",
        "web_timeout_s",
        # NOTE: API keys are treated as secrets and are not written by the UI.
        # Keep them in root/api_config.yaml and manage them manually.

        # CQL grounding
        "cql_grounding_enabled",
        "cql_grounding_top_k_dictionary",
        "cql_grounding_top_k_examples",
        "cql_grounding_debug",

        # Safety
        "prod_safe_mode",
        "allow_dangerous_actions",
        "allow_legacy_office_conversion",
    ]

    out: Dict[str, Any] = {}
    for k in keys:
        try:
            out[k] = getattr(cfg, k)
        except Exception:
            pass

    # Nested network config
    try:
        out["network"] = {
            "proxy": {
                "enabled": bool(getattr(getattr(cfg, "network").proxy, "enabled", False)),
                "mode": str(getattr(getattr(cfg, "network").proxy, "mode", "off")),
                "http": str(getattr(getattr(cfg, "network").proxy, "http", "")),
                "https": str(getattr(getattr(cfg, "network").proxy, "https", "")),
                "no_proxy": str(getattr(getattr(cfg, "network").proxy, "no_proxy", "")),
                "username": str(getattr(getattr(cfg, "network").proxy, "username", "")),
                "password": str(getattr(getattr(cfg, "network").proxy, "password", "")),
            },
            "tls": {
                "verify": bool(getattr(getattr(cfg, "network").tls, "verify", True)),
                "ca_bundle_path": str(getattr(getattr(cfg, "network").tls, "ca_bundle_path", "")),
            },
        }
    except Exception:
        pass

    return out


def save_config_yaml(cfg: "AppConfig", data_dir: str | None = None) -> Path:
    """Persist current settings to data/config.yaml.

    We merge onto the currently-loaded data/config.yaml so we don't destroy
    unrelated runtime keys that aren't exposed in the Settings UI.

    Secrets (API keys) are never written here; keep them in root/api_config.yaml.
    """
    ensure_persisted_config_exists(data_dir)
    p = get_persisted_config_path(data_dir)

    existing = load_config_yaml(str(p), include_api_secrets=False) or {}
    if not isinstance(existing, dict):
        existing = {}

    # Ensure secrets do not land in the persisted file.
    for k in list(existing.keys()):
        if k in _SECRET_KEYS:
            existing.pop(k, None)

    merged = dict(existing)
    merged.update(_config_from_appcfg(cfg))

    # Atomic write: write tmp then replace.
    tmp = p.with_suffix(".yaml.tmp")
    tmp.write_text(_safe_yaml_dump(merged), encoding="utf-8")
    tmp.replace(p)
    _set_last_loaded_config_path(p)
    return p


def load_config_yaml(path: str | None = None, *, include_api_secrets: bool = True) -> Dict[str, Any]:
    """Load a YAML config file as a dict.

    Config is optional for demo mode, but becomes the source of truth once you
    wire in IOC enrichment plugins and API keys.
    """
    # Prefer PyYAML when available, but keep a tiny fallback parser so
    # the demo doesn't hard-fail if PyYAML isn't installed in a user's venv.
    yaml = None
    try:
        import yaml as _yaml  # type: ignore
        yaml = _yaml
    except Exception:
        yaml = None

    # Default behavior (no explicit path): prefer persisted config under data/.
    if path is None:
        persisted = ensure_persisted_config_exists()
        p = persisted.resolve()
    else:
        p = Path(path).resolve()

    if not p.exists():
        # Try the common locations in this repo layout (bundled defaults).
        here = Path(__file__).resolve().parent
        # NOTE: We intentionally do NOT support a legacy root/config.yaml.
        candidates = [here / "config.yaml"]
        for c in candidates:
            if c.exists():
                p = c
                break
        else:
            _set_last_loaded_config_path(None)
            cfg: Dict[str, Any] = {}
            # Still allow API secrets overlay (for callers that only care about keys).
            if include_api_secrets:
                cfg.update(load_api_config_yaml())
            return cfg

    _set_last_loaded_config_path(p)
    raw = p.read_text(encoding="utf-8", errors="ignore")

    # PyYAML path
    if yaml is not None:
        try:
            data = yaml.safe_load(raw) or {}
            cfg = data if isinstance(data, dict) else {}
            if include_api_secrets:
                cfg = dict(cfg)
                cfg.update(load_api_config_yaml())
            return cfg
        except Exception:
            # fall back to simple parser
            pass

    # Minimal YAML fallback parser:
    # - supports "key: value" pairs
    # - supports one-level nested dict for "plugins:" style blocks
    out: Dict[str, Any] = {}
    cur_map: Dict[str, Any] | None = None
    for line in raw.splitlines():
        # strip comments
        line = line.split("#", 1)[0].rstrip("\n")
        if not line.strip():
            continue

        # section header (e.g., "plugins:")
        if re.match(r"^[A-Za-z0-9_\-]+:\s*$", line.strip()):
            key = line.strip()[:-1].strip()
            cur_map = {}
            out[key] = cur_map
            continue

        m = re.match(r"^(\s*)([A-Za-z0-9_\-]+)\s*:\s*(.*)$", line)
        if not m:
            continue
        indent, key, val = m.group(1), m.group(2), (m.group(3) or "").strip()

        # basic scalars
        def _coerce(v: str):
            if v.lower() in ("true", "false"):
                return v.lower() == "true"
            if re.fullmatch(r"-?\d+", v):
                try:
                    return int(v)
                except Exception:
                    return v
            if re.fullmatch(r"-?\d+\.\d+", v):
                try:
                    return float(v)
                except Exception:
                    return v
            # strip quotes
            if (v.startswith('"') and v.endswith('"')) or (v.startswith("'") and v.endswith("'")):
                return v[1:-1]
            return v

        target = out
        # treat indented key-values as part of last section dict
        if indent and cur_map is not None:
            target = cur_map
        elif indent:
            # indented but no active section, ignore
            continue
        else:
            cur_map = None

        target[key] = _coerce(val)

    if include_api_secrets:
        out.update(load_api_config_yaml())
    return out


def apply_config_overrides(cfg: "AppConfig", overrides: Dict[str, Any]) -> "AppConfig":
    """Apply known config.yaml keys onto an AppConfig instance."""
    if not overrides:
        return cfg

    # Nested network config (proxy + tls)
    try:
        n = overrides.get("network") or {}
        if isinstance(n, dict):
            px = n.get("proxy") or {}
            if isinstance(px, dict):
                cfg.network.proxy.enabled = bool(px.get("enabled", getattr(cfg.network.proxy, "enabled", False)))
                cfg.network.proxy.mode = str(px.get("mode", getattr(cfg.network.proxy, "mode", "off")) or "off").strip().lower()
                for k in ("http","https","no_proxy","username","password","test_url"):
                    if k in px:
                        setattr(cfg.network.proxy, k, px.get(k) or "")
            tls = n.get("tls") or {}
            if isinstance(tls, dict):
                if "verify" in tls:
                    cfg.network.tls.verify = bool(tls.get("verify"))
                if "ca_bundle_path" in tls:
                    cfg.network.tls.ca_bundle_path = str(tls.get("ca_bundle_path") or "")
    except Exception:
        pass

    for key in (
        "data_dir",
        "ollama_host",
        "ollama_model",
        "ollama_temperature",
        "ollama_request_timeout_s",
        "fetch_source_urls",
        "max_source_chars",
        "query_language",
        "kql_profile",
        "hunt_min_queries",
        "hunt_max_queries",
        "show_llm_errors",
        "app_title",
        "app_subtitle",
        "report_footer",
        "phase_label",
        "template_dir_override",

        # Contract framework (contracts + prompt packs)
        "contract_dir_override",
        "prompt_dir_override",
        "prompt_pack",
        "contract_enforcement_mode",
        "contract_regen_attempts",
        "intel_brief_contract_profile",
        "hunt_package_contract_profile",
        "run_contract_profile",
        "finding_contract_profile",
        "ads_contract_profile",

        # Phase 6 (RAG)
        "rag_enabled",
        "rag_top_k",
        "rag_chunk_chars",
        "rag_overlap_chars",

        # Phase 6.2 (Web search)
        "web_enabled",
        "web_enabled_by_default",
        "web_fetch_pages",
        "web_cache_ttl_s",
        "web_provider",
        "web_max_results",
        "web_enable_third_party_fetch_fallback",
        "web_enable_js_rendered_page_ingestion",
        "web_timeout_s",
        "bing_api_key",
        "tavily_api_key",
        "serpapi_api_key",

        # Phase 6.3 (CQL grounding)
        "cql_grounding_enabled",
        "cql_grounding_top_k_dictionary",
        "cql_grounding_top_k_examples",
        "cql_grounding_debug",

        # Phase 6.3.8 (optional HTML render cache)
        "render_cache_enabled",

        # Phase 6.5.7 (approval gate auto-correct)
        "approval_autocorrect_enabled",
        "approval_autocorrect_max_attempts",
        "approval_fail_open_after_autocorrect",
        "approval_autocorrect_prompt_pack",


        # Safety / destructive actions
        "prod_safe_mode",
        "allow_dangerous_actions",
    ):
        if key in overrides:
            try:
                setattr(cfg, key, overrides[key])
            except Exception:
                pass
    return cfg



@dataclass
class NetworkProxyConfig:
    mode: str = "off"      # off | env | explicit | winhttp
    enabled: bool = False
    http: str = ""
    https: str = ""
    no_proxy: str = ""
    username: str = ""
    password: str = ""
    test_url: str = "https://www.iana.org/"

@dataclass
class NetworkTLSConfig:
    verify: bool = True
    ca_bundle_path: str = ""

@dataclass
class NetworkConfig:
    proxy: NetworkProxyConfig = field(default_factory=NetworkProxyConfig)
    tls: NetworkTLSConfig = field(default_factory=NetworkTLSConfig)

def scrub_proxy_url(url: str) -> str:
    """Remove credentials from a proxy URL for safe logging/UI."""
    try:
        u = (url or "").strip()
        return re.sub(r'^(https?://)([^/@:]+):([^/@]+)@', r'\1***:***@', u, flags=re.I)
    except Exception:
        return (url or "")

def scrub_config_for_display(data: Dict[str, Any]) -> Dict[str, Any]:
    """Deep copy + mask sensitive fields for UI/log display."""
    try:
        import copy
        d = copy.deepcopy(data)
    except Exception:
        d = dict(data or {})
    try:
        net = (d.get("network") or {})
        if isinstance(net, dict):
            px = (net.get("proxy") or {})
            if isinstance(px, dict):
                if px.get("password"):
                    px["password"] = "***"
                for k in ("http","https"):
                    if isinstance(px.get(k), str) and px.get(k):
                        px[k] = scrub_proxy_url(px[k])
                net["proxy"] = px
            d["network"] = net
    except Exception:
        pass
    return d

@dataclass
class AppConfig:
    # Storage
    data_dir: str = "data"


    # Optional: override the bundled templates folder (advanced users)
    template_dir_override: str = ""

    # Contracts + prompt packs (advanced)
    # Optional: point to a folder containing contract YAML files under ./contracts
    # Example: <override>/contracts/intel_brief_v1_1.yaml
    contract_dir_override: str = ""
    # Optional: point to a folder containing prompt packs under ./prompt_packs
    # Example: <override>/prompt_packs/default/intel_brief.system.txt
    prompt_dir_override: str = ""
    # Which prompt pack to use (default: bundled "default")
    prompt_pack: str = "default"
    # strict: block approval/export (and optionally draft) when non-compliant
    # warn: allow save but surface violations
    # off: disable contract enforcement
    contract_enforcement_mode: str = "strict"
    # How many regen attempts to perform after an initial validation failure
    contract_regen_attempts: int = 2
    # Contract profile name for Intel Briefs (maps to contracts/<profile>.yaml)
    intel_brief_contract_profile: str = "intel_brief_v1_2"
    # Contract profile name for Hunt Packages (maps to contracts/<profile>.yaml)
    hunt_package_contract_profile: str = "threat_hunt_v1_0"
    # Contract profile name for Run reports
    run_contract_profile: str = "run_v1_1"
    # Contract profile name for Findings
    finding_contract_profile: str = "finding_v1_1"
    # Contract profile name for ADS
    ads_contract_profile: str = "ads_v1_1"
    # Phase 6.5.7 (approval gate auto-correct)
    # When enabled, the app will try to silently repair non-compliant Intel Brief sections
    # at approval time (bounded attempts).
    approval_autocorrect_enabled: bool = True
    approval_autocorrect_max_attempts: int = 2
    # If strict mode still fails after auto-correct, allow proceeding while surfacing warnings.
    approval_fail_open_after_autocorrect: bool = True
    # Prompt pack folder used for approval-time auto-correct (byo_secai/prompt_packs/<pack>).
    approval_autocorrect_prompt_pack: str = "autocorrect"


    # Phase 6 (local RAG)
    rag_enabled: bool = True
    rag_top_k: int = 6
    # Chunking for the local index (characters). Keep light for demo responsiveness.
    rag_chunk_chars: int = 1200
    rag_overlap_chars: int = 200

    # Phase 6.2 (web search) — OFF by default (privacy-first)
    # Backwards compatible: web_enabled is treated as "enabled_by_default".
    web_enabled: bool = False
    # If true, Workspace pre-checks "Web" and the per-message toggle by default.
    web_enabled_by_default: bool = False
    # If true, Workspace can fetch full page text for a URL when explicitly requested.
    # Otherwise, it will only use search snippets.
    web_fetch_pages: bool = False
    # Simple in-process cache TTL (seconds) for web search and page fetch.
    web_cache_ttl_s: int = 1800
    web_provider: str = "duckduckgo"  # duckduckgo | bing | tavily | serpapi
    web_max_results: int = 5
    web_timeout_s: int = 15

    # Web fetch fallbacks (safe-by-default)
    web_enable_third_party_fetch_fallback: bool = False
    web_enable_js_rendered_page_ingestion: bool = False

    # Network egress (proxy + TLS)
    network: NetworkConfig = field(default_factory=NetworkConfig)

    # Upload ingestion safety
    allow_legacy_office_conversion: bool = False


    # Phase 6.3.8 (optional): cache rendered artifact views as lightweight HTML
    # files on disk to make navigation feel instant. Off by default.
    render_cache_enabled: bool = False

    # UI
    # If true, render the clickable artifact-chain breadcrumbs on views.
    # Default off (some users prefer a cleaner UI and explicit dropdown navigation).
    show_breadcrumbs: bool = False
    # Optional API keys (also read from env vars in providers)
    bing_api_key: str = ""
    tavily_api_key: str = ""
    serpapi_api_key: str = ""

    # Phase 6.3 (CQL grounding for hunt generation)
    # When enabled, Hunt Package generation will retrieve relevant chunks from the
    # Knowledge Library (CrowdStrike dictionary + your saved queries) and use those
    # as a grounding layer to reduce drift.
    cql_grounding_enabled: bool = True
    cql_grounding_top_k_dictionary: int = 5
    cql_grounding_top_k_examples: int = 5
    cql_grounding_debug: bool = True

    # Safety
    # Production-safe mode disables destructive actions (like deleting data)
    # unless explicitly unlocked in the UI (or allow_dangerous_actions=true in config).
    prod_safe_mode: bool = True
    allow_dangerous_actions: bool = False

    # Ollama
    ollama_host: str = "http://localhost:11434"
    ollama_model: str = "llama3.1"
    ollama_temperature: float = 0.2
    ollama_request_timeout_s: int = 60

    # Source ingestion (optional online fetch)
    fetch_source_urls: bool = False
    # Keep this modest by default for snappy UI; you can raise it in Settings if needed.
    max_source_chars: int = 6000

    # Hunt generation preferences
    # Default to CrowdStrike LogScale CQL for this project.
    # Allowed: CQL, SPL, KQL (the UI offers these options).
    query_language: str = "CQL"

    # KQL generation preferences
    # KQL is schema-dependent; this tells the generator + validator which table/field
    # conventions to use.
    # Allowed: MDE (Microsoft Defender for Endpoint), SENTINEL (SecurityEvent/Sysmon), HYBRID (Sentinel + Defender)
    kql_profile: str = "MDE"

    # How many distinct hunt queries to generate by default. The model may return fewer,
    # but we ask for a target between these bounds.
    hunt_min_queries: int = 2
    hunt_max_queries: int = 7

    # Debug
    show_llm_errors: bool = True

    # UX
    app_title: str = "SPARK"
    app_subtitle: str = "powered by BYO-SecAI"
    report_footer: str = "Generated by SPARK (powered by BYO-SecAI)"
    phase_label: str = "Phase 6.5.4 — Approval Gates + Convergent Regen + Semantic Anchors"

    # Backwards-compatible aliases used by some UI code
    @property
    def request_timeout_s(self) -> int:
        return self.ollama_request_timeout_s

    @request_timeout_s.setter
    def request_timeout_s(self, v: int) -> None:
        self.ollama_request_timeout_s = int(v)

    @property
    def max_source_extract_chars(self) -> int:
        return self.max_source_chars

    @max_source_extract_chars.setter
    def max_source_extract_chars(self, v: int) -> None:
        self.max_source_chars = int(v)