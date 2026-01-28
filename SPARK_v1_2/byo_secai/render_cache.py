from __future__ import annotations

"""Optional on-disk HTML snapshots for fast view rendering.

Streamlit pages rerun on navigation. This module makes those reruns cheap
by reusing a pre-rendered HTML snapshot keyed by:

  (artifact_type, artifact_id, updated_at)

Snapshots are best-effort. If anything fails, callers should fall back to
normal markdown rendering.
"""

from dataclasses import dataclass
from pathlib import Path
from typing import Optional


def _safe_filename(s: str) -> str:
    return "".join(c for c in (s or "") if c.isalnum() or c in ("-", "_", "."))[:200] or "unknown"


def cache_root(data_dir: str) -> Path:
    return Path(data_dir) / "render_cache"


def cache_path(data_dir: str, artifact_type: str, artifact_id: str, updated_at: str) -> Path:
    at = _safe_filename(artifact_type)
    aid = _safe_filename(artifact_id)
    ts = _safe_filename(updated_at)
    return cache_root(data_dir) / at / aid / f"{ts}.html"


def load_html(data_dir: str, artifact_type: str, artifact_id: str, updated_at: str) -> Optional[str]:
    p = cache_path(data_dir, artifact_type, artifact_id, updated_at)
    if not p.exists():
        return None
    try:
        return p.read_text(encoding="utf-8", errors="ignore")
    except Exception:
        return None


def _markdown_to_html(md: str) -> str:
    md = md or ""
    try:
        import markdown2  # type: ignore

        body = markdown2.markdown(md, extras=["fenced-code-blocks", "tables", "strike", "task_list"])  # type: ignore
    except Exception:
        import html

        body = "<pre style='white-space:pre-wrap'>" + html.escape(md) + "</pre>"

    return (
        "<!doctype html>\n"
        "<html><head><meta charset='utf-8'>"
        "<meta name='viewport' content='width=device-width, initial-scale=1'>"
        "<style>body{font-family:system-ui,-apple-system,Segoe UI,Roboto,Arial,sans-serif; padding:16px;}"
        "code,pre{font-family:ui-monospace,SFMono-Regular,Menlo,Monaco,Consolas,monospace;}"
        "pre{overflow-x:auto;} table{border-collapse:collapse;} td,th{border:1px solid #6664; padding:6px;}"
        "</style></head><body>"
        + body
        + "</body></html>"
    )


def save_html_from_markdown(
    data_dir: str,
    artifact_type: str,
    artifact_id: str,
    updated_at: str,
    markdown_text: str,
) -> Optional[Path]:
    p = cache_path(data_dir, artifact_type, artifact_id, updated_at)
    try:
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(_markdown_to_html(markdown_text), encoding="utf-8")
        return p
    except Exception:
        return None
