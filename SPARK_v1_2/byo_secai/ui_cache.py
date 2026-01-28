"""Streamlit-friendly cached loaders.

These helpers keep page reruns cheap by caching expensive *I/O* and parsing
steps (index reads, JSON reads, template reads).

Notes
-----
* Cache keys include mtimes so edits invalidate automatically.
* Inputs are primitives to keep Streamlit's cache stable.
"""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any, Dict, List, Optional

import streamlit as st


def _index_path(data_dir: str) -> Path:
    return Path(data_dir) / "_index.json"


@st.cache_data(show_spinner=False)
def load_index_rows(data_dir: str, index_mtime_ns: int) -> List[Dict[str, Any]]:
    """Load the global artifact index.

    index_mtime_ns is included to invalidate when the index changes.
    """
    p = _index_path(data_dir)
    try:
        if not p.exists():
            return []
        raw = p.read_text(encoding="utf-8", errors="ignore")
        rows = json.loads(raw)
        return rows if isinstance(rows, list) else []
    except Exception:
        return []


def list_ids_cached(data_dir: str, artifact_type_value: str) -> List[str]:
    """List artifact IDs using the cached global index."""
    p = _index_path(data_dir)
    try:
        mtime = p.stat().st_mtime_ns if p.exists() else 0
    except Exception:
        mtime = 0
    rows = load_index_rows(data_dir, int(mtime))
    ids = [
        r.get("id")
        for r in rows
        if isinstance(r, dict)
        and r.get("type") == artifact_type_value
        and isinstance(r.get("id"), str)
    ]
    return sorted(list(set(ids)))


def _artifact_path(data_dir: str, artifact_type_value: str, artifact_id: str) -> Path:
    return Path(data_dir) / "artifacts" / artifact_type_value / f"{artifact_id}.json"


@st.cache_data(show_spinner=False)
def load_artifact_json(data_dir: str, artifact_type_value: str, artifact_id: str, mtime_ns: int) -> Optional[Dict[str, Any]]:
    """Load and parse an artifact JSON file.

    Returns a dict (raw JSON) so it remains robust/pickle-friendly.
    """
    p = _artifact_path(data_dir, artifact_type_value, artifact_id)
    try:
        if not p.exists():
            return None
        raw = p.read_text(encoding="utf-8", errors="ignore")
        obj = json.loads(raw)
        return obj if isinstance(obj, dict) else None
    except Exception:
        return None


def load_artifact_json_cached(data_dir: str, artifact_type_value: str, artifact_id: str) -> Optional[Dict[str, Any]]:
    """Convenience wrapper that auto-includes mtime in the cache key."""
    p = _artifact_path(data_dir, artifact_type_value, artifact_id)
    try:
        mtime = p.stat().st_mtime_ns if p.exists() else 0
    except Exception:
        mtime = 0
    return load_artifact_json(data_dir, artifact_type_value, artifact_id, int(mtime))


@st.cache_data(show_spinner=False)
def load_template_text(template_dir: str, filename: str, mtime_ns: int) -> str:
    """Load a template file as text, cached by its mtime."""
    p = Path(template_dir) / filename
    try:
        if not p.exists():
            return ""
        return p.read_text(encoding="utf-8", errors="ignore")
    except Exception:
        return ""


def load_template_text_cached(template_dir: str, filename: str) -> str:
    p = Path(template_dir) / filename
    try:
        mtime = p.stat().st_mtime_ns if p.exists() else 0
    except Exception:
        mtime = 0
    return load_template_text(template_dir, filename, int(mtime))
