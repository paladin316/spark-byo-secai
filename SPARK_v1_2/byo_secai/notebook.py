from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional

from .workflow import utc_now


@dataclass
class NotebookCell:
    cell_id: str
    # Extensible. Phase 6.1 uses a chat-first timeline:
    #  - chat: meta.role in {'user','assistant'}, optional meta.retrieved[]
    #  - note: markdown note (also accepts legacy 'markdown' and 'notes')
    #  - query: code block (meta.language)
    cell_type: str
    content: str = ""
    meta: Dict[str, Any] = field(default_factory=dict)


@dataclass
class ThreatHuntNotebook:
    notebook_id: str
    title: str
    created_at: str
    updated_at: str
    cells: List[NotebookCell] = field(default_factory=list)


class NotebookStore:
    def __init__(self, data_dir: str):
        self.root = Path(data_dir).expanduser().resolve() / "notebooks"
        self.root.mkdir(parents=True, exist_ok=True)

    def _path(self, notebook_id: str) -> Path:
        return self.root / f"{notebook_id}.json"

    def list_ids(self) -> List[str]:
        out = []
        for p in sorted(self.root.glob("*.json")):
            out.append(p.stem)
        return out

    def load(self, notebook_id: str) -> Optional[ThreatHuntNotebook]:
        p = self._path(notebook_id)
        if not p.exists():
            return None
        try:
            data = json.loads(p.read_text(encoding="utf-8"))
            cells = [NotebookCell(**c) for c in (data.get("cells") or []) if isinstance(c, dict)]
            return ThreatHuntNotebook(
                notebook_id=data.get("notebook_id") or notebook_id,
                title=data.get("title") or notebook_id,
                created_at=data.get("created_at") or utc_now(),
                updated_at=data.get("updated_at") or utc_now(),
                cells=cells,
            )
        except Exception:
            return None

    def save(self, nb: ThreatHuntNotebook) -> None:
        nb.updated_at = utc_now()
        p = self._path(nb.notebook_id)
        payload = {
            "notebook_id": nb.notebook_id,
            "title": nb.title,
            "created_at": nb.created_at,
            "updated_at": nb.updated_at,
            "cells": [c.__dict__ for c in nb.cells],
        }
        p.write_text(json.dumps(payload, indent=2), encoding="utf-8")

    def create(self, notebook_id: str, title: str) -> ThreatHuntNotebook:
        now = utc_now()
        nb = ThreatHuntNotebook(notebook_id=notebook_id, title=title, created_at=now, updated_at=now, cells=[])
        self.save(nb)
        return nb


def nb_to_markdown(nb: ThreatHuntNotebook) -> str:
    lines: List[str] = []
    lines.append(f"# {nb.title}")
    lines.append("")
    lines.append(f"- Notebook ID: {nb.notebook_id}")
    lines.append(f"- Updated: {nb.updated_at}")
    lines.append("")
    def _as_note(md: str) -> None:
        md = (md or "").rstrip()
        if md:
            lines.append(md)
            lines.append("")

    for c in nb.cells:
        ctype = (c.cell_type or "").strip().lower()

        # --- chat timeline ---
        if ctype == "chat":
            role = ((c.meta or {}).get("role") or "assistant").strip().lower()
            label = "User" if role == "user" else "Assistant"
            lines.append(f"## {label}")
            lines.append("")
            lines.append((c.content or "").rstrip())
            lines.append("")

            # Optional retrieved context (stored on assistant cells)
            retrieved = (c.meta or {}).get("retrieved") or []
            if isinstance(retrieved, list) and retrieved:
                lines.append("<details>")
                lines.append("<summary>Retrieved context</summary>")
                lines.append("")
                for r in retrieved:
                    if not isinstance(r, dict):
                        continue
                    src = r.get("source") or "(unknown)"
                    score = r.get("score")
                    text = (r.get("text") or "").strip()
                    if score is not None:
                        lines.append(f"- ({src} | {score}) {text}")
                    else:
                        lines.append(f"- ({src}) {text}")
                lines.append("")
                lines.append("</details>")
                lines.append("")

            # Optional web sources (stored on assistant cells)
            web_sources = (c.meta or {}).get("web_sources") or []
            if isinstance(web_sources, list) and web_sources:
                lines.append("<details>")
                lines.append("<summary>Web sources</summary>")
                lines.append("")
                for i, s in enumerate(web_sources, start=1):
                    if not isinstance(s, dict):
                        continue
                    title = (s.get("title") or "(untitled)").strip()
                    url = (s.get("url") or "").strip()
                    snippet = (s.get("snippet") or "").strip()
                    if url:
                        lines.append(f"[{i}] {title} — {url}")
                    else:
                        lines.append(f"[{i}] {title}")
                    if snippet:
                        lines.append(f"    - {snippet}")
                lines.append("")
                lines.append("</details>")
                lines.append("")

            continue

        # --- notes / markdown ---
        if ctype in {"note", "notes", "markdown"}:
            _as_note(c.content)
            continue

        # --- query blocks ---
        if ctype == "query":
            lang = (c.meta or {}).get("language") or "text"
            lines.append(f"```{lang}")
            lines.append((c.content or "").rstrip())
            lines.append("```")
            lines.append("")
            continue

        # --- fallback ---
        _as_note(c.content)
    return "\n".join(lines).strip() + "\n"
