from __future__ import annotations

import os

from ..config import load_config_yaml


def run(ioc: str) -> dict:
    """Optional YARA scanning plugin.

    NOTE: This plugin is disabled by default via config.yaml.
    It is intentionally dependency-light at import time; it only imports
    the `yara` module when run() is called.
    """

    # YARA only makes sense against a file path
    if not os.path.isfile(ioc):
        return {"source": "yara_scanner", "ioc": ioc, "error": "IOC is not a file path"}

    cfg = load_config_yaml() or {}
    yara_dir = "yara_rules"
    if isinstance(cfg, dict):
        yara_dir = cfg.get("yara_rules_dir") or yara_dir

    try:
        import yara  # type: ignore
    except Exception as e:
        return {"source": "yara_scanner", "ioc": ioc, "error": f"yara module not installed: {e}"}

    if not os.path.isdir(yara_dir):
        return {"source": "yara_scanner", "ioc": ioc, "error": "yara_rules_dir not found"}

    rule_files = {
        os.path.splitext(fn)[0]: os.path.join(yara_dir, fn)
        for fn in os.listdir(yara_dir)
        if fn.lower().endswith((".yar", ".yara"))
    }
    if not rule_files:
        return {"source": "yara_scanner", "ioc": ioc, "error": "No rules found in yara_rules_dir"}

    try:
        rules = yara.compile(filepaths=rule_files)
        matches = rules.match(ioc)
        return {"source": "yara_scanner", "ioc": ioc, "result": [m.rule for m in matches]}
    except Exception as e:
        return {"source": "yara_scanner", "ioc": ioc, "error": str(e)}
