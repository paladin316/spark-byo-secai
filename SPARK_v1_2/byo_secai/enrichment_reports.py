from __future__ import annotations

import csv
import datetime as _dt
from pathlib import Path
from typing import Any, Dict, Tuple

from .plugins.plugin_loader import detect_ioc_type


def _now_tag() -> str:
    return _dt.datetime.now().strftime("%Y%m%d_%H%M%S")


def _vt_gui_link(ioc: str, ioc_type: str) -> str:
    # Best-effort GUI links
    if ioc_type == "ip":
        return f"https://www.virustotal.com/gui/ip-address/{ioc}"
    if ioc_type == "hash":
        return f"https://www.virustotal.com/gui/file/{ioc}"
    if ioc_type == "url":
        return f"https://www.virustotal.com/gui/search/{ioc}"
    if ioc_type == "domain":
        return f"https://www.virustotal.com/gui/domain/{ioc}"
    if ioc_type == "ip_port":
        # strip port for VT GUI
        ip = ioc.split(':')[0].split('|')[0].strip()
        return f"https://www.virustotal.com/gui/ip-address/{ip}"
    return f"https://www.virustotal.com/gui/search/{ioc}"


def write_plugin_summary_reports(
    enrichment_results: Dict[str, Dict[str, Any]],
    out_dir: str | Path,
    intel_id: str,
) -> Dict[str, str]:
    """Create at-a-glance CSV summary reports per plugin.

    Returns a dict mapping plugin_name -> file path (string).
    """
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    tag = _now_tag()

    # Collect entries per plugin
    per_plugin: Dict[str, list[Tuple[str, dict]]] = {}
    for ioc, plugins in (enrichment_results or {}).items():
        if not isinstance(plugins, dict):
            continue
        for plugin_name, payload in plugins.items():
            per_plugin.setdefault(plugin_name, []).append((ioc, payload if isinstance(payload, dict) else {"raw": payload}))

    written: Dict[str, str] = {}

    for plugin_name, rows in per_plugin.items():
        # Choose schema based on plugin
        if plugin_name == "virustotal":
            fields = ["ioc", "ioc_type", "malicious_count", "vt_link", "source", "status", "error"]
            fname = f"vt_report_{intel_id}_{tag}.csv"
        elif plugin_name == "abuseipdb":
            fields = ["ioc", "ioc_type", "abuse_confidence_score", "countryCode", "isp", "domain", "totalReports", "source", "status", "error"]
            fname = f"abuseipdb_report_{intel_id}_{tag}.csv"
        elif plugin_name == "urlscan":
            fields = ["ioc", "ioc_type", "task_uuid", "result_url", "source", "status", "error"]
            fname = f"urlscan_report_{intel_id}_{tag}.csv"
        elif plugin_name == "yara_scanner":
            fields = ["ioc", "ioc_type", "matches", "source", "status", "error"]
            fname = f"yara_report_{intel_id}_{tag}.csv"
        else:
            fields = ["ioc", "ioc_type", "source", "status", "error"]
            fname = f"{plugin_name}_report_{intel_id}_{tag}.csv"

        out_path = out_dir / fname

        with open(out_path, "w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=fields)
            writer.writeheader()
            for ioc, payload in rows:
                source = payload.get("source", plugin_name)
                status = "ok" if payload.get("result") is not None and not payload.get("error") and not payload.get("skipped") else "skipped" if payload.get("skipped") else "error" if payload.get("error") else "unknown"
                ioc_type = payload.get("ioc_type") or payload.get("type") or detect_ioc_type(ioc) or "unknown"
                # Some payloads store original ioc only, infer minimal type
                row = {"ioc": ioc, "ioc_type": ioc_type, "source": source, "status": status, "error": payload.get("error") or payload.get("skipped")}

                if plugin_name == "virustotal":
                    mal = None
                    vt_link = _vt_gui_link(ioc, ioc_type)
                    res = payload.get("result") or {}
                    try:
                        attrs = res.get("attributes") or {}
                        stats = attrs.get("last_analysis_stats") or {}
                        mal = stats.get("malicious")
                    except Exception:
                        mal = None
                    row.update({"malicious_count": mal, "vt_link": vt_link})
                elif plugin_name == "abuseipdb":
                    res = payload.get("result") or {}
                    row.update({
                        "abuse_confidence_score": res.get("abuseConfidenceScore"),
                        "countryCode": res.get("countryCode"),
                        "isp": res.get("isp"),
                        "domain": res.get("domain"),
                        "totalReports": res.get("totalReports"),
                    })
                elif plugin_name == "urlscan":
                    res = payload.get("result") or {}
                    # urlscan typically returns uuid and result url; best-effort
                    row.update({
                        "task_uuid": res.get("uuid") or res.get("task_uuid"),
                        "result_url": res.get("result") or res.get("result_url") or res.get("url"),
                    })
                elif plugin_name == "yara_scanner":
                    res = payload.get("result") or {}
                    matches = None
                    if isinstance(res, dict):
                        matches = res.get("matches")
                    row.update({"matches": matches})

                writer.writerow({k: row.get(k) for k in fields})

        written[plugin_name] = str(out_path)

    return written
