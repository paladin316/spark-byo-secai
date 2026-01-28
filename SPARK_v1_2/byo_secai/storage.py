from __future__ import annotations

import json
import shutil
import uuid
from pathlib import Path
from typing import Dict, List, Optional, Type, TypeVar

from pydantic import BaseModel

from .logging_utils import get_logger
from .models import ADS, Finding, HuntPackage, IntelBrief, Run, ArtifactType, IntelIOCs

T = TypeVar("T", bound=BaseModel)

logger = get_logger()

_TYPE_MAP: Dict[ArtifactType, Type[BaseModel]] = {
    ArtifactType.INTEL_BRIEF: IntelBrief,
    ArtifactType.INTEL_IOCS: IntelIOCs,
    ArtifactType.HUNT_PACKAGE: HuntPackage,
    ArtifactType.RUN: Run,
    ArtifactType.FINDING: Finding,
    ArtifactType.ADS: ADS,
}


class Storage:
    """Simple JSON-on-disk storage with a lightweight global index."""

    def __init__(self, data_dir: str = "data"):
        self.data_dir = Path(data_dir)
        self.artifacts_dir = self.data_dir / "artifacts"
        self.exports_dir = self.data_dir / "exports"
        self.artifacts_dir.mkdir(parents=True, exist_ok=True)
        self.exports_dir.mkdir(parents=True, exist_ok=True)

        # Global audit log (best-effort). JSON Lines so we can append safely.
        self.audit_log_path = self.data_dir / "_audit_log.jsonl"
        if not self.audit_log_path.exists():
            try:
                self.audit_log_path.write_text("", encoding="utf-8")
            except Exception:
                pass

        self.index_path = self.data_dir / "_index.json"
        if not self.index_path.exists():
            self.index_path.write_text("[]", encoding="utf-8")

    def _type_dir(self, artifact_type: ArtifactType) -> Path:
        d = self.artifacts_dir / artifact_type.value
        d.mkdir(parents=True, exist_ok=True)
        return d

    # -------- Index helpers --------
    def load_index(self) -> List[Dict]:
        try:
            raw = self.index_path.read_text(encoding="utf-8")
            data = json.loads(raw)
            return data if isinstance(data, list) else []
        except Exception:
            return []

    def write_index(self, rows: List[Dict]) -> None:
        self.index_path.write_text(json.dumps(rows, indent=2), encoding="utf-8")

    def upsert_index_row(self, artifact_type: ArtifactType, model: BaseModel, artifact_id: str) -> None:
        rows = self.load_index()
        rows = [
            r for r in rows
            if not (isinstance(r, dict) and r.get("id") == artifact_id and r.get("type") == artifact_type.value)
        ]

        meta = getattr(model, "meta", None)
        title = getattr(meta, "title", "") if meta else ""
        approval_obj = getattr(model, "approval", None)
        approval = approval_obj.value if hasattr(approval_obj, "value") else (str(approval_obj) if approval_obj else "")
        updated_at = getattr(meta, "updated_at", "") if meta else ""
        created_at = getattr(meta, "created_at", "") if meta else ""

        links: Dict[str, str] = {}
        for k in [
            "linked_intel_id", "linked_hunt_id", "linked_run_id",
            "linked_finding_id", "linked_ads_id", "linked_intel", "linked_hunt"
        ]:
            if hasattr(model, k):
                v = getattr(model, k)
                if v:
                    links[k] = v

        rows.append({
            "id": artifact_id,
            "type": artifact_type.value,
            "title": title,
            "approval": approval,
            "created_at": created_at,
            "updated_at": updated_at,
            "links": links,
        })
        rows.sort(key=lambda r: (r.get("type", ""), r.get("updated_at", ""), r.get("id", "")))
        self.write_index(rows)

    def list_ids_indexed(self, artifact_type: ArtifactType) -> List[str]:
        rows = self.load_index()
        ids = [
            r.get("id") for r in rows
            if isinstance(r, dict) and r.get("type") == artifact_type.value and isinstance(r.get("id"), str)
        ]
        return sorted(list(set(ids)))

    def rebuild_index(self) -> None:
        rows: List[Dict] = []
        for atype in ArtifactType:
            d = self._type_dir(atype)
            if not d.exists():
                continue
            for p in d.glob("*.json"):
                name = p.name
                if name.endswith(".enrichment.json") or name.endswith(".iocs.json") or name.endswith(".assistant.json"):
                    continue
                aid = p.stem
                try:
                    m = self.load(atype, aid)
                    if m is None:
                        continue
                    meta = getattr(m, "meta", None)
                    title = getattr(meta, "title", "") if meta else ""
                    approval_obj = getattr(m, "approval", None)
                    approval = approval_obj.value if hasattr(approval_obj, "value") else (str(approval_obj) if approval_obj else "")
                    updated_at = getattr(meta, "updated_at", "") if meta else ""
                    created_at = getattr(meta, "created_at", "") if meta else ""
                    links: Dict[str, str] = {}
                    for k in ["linked_intel_id","linked_hunt_id","linked_run_id","linked_finding_id","linked_ads_id"]:
                        if hasattr(m, k):
                            v = getattr(m, k)
                            if v:
                                links[k] = v
                    rows.append({
                        "id": aid,
                        "type": atype.value,
                        "title": title,
                        "approval": approval,
                        "created_at": created_at,
                        "updated_at": updated_at,
                        "links": links,
                    })
                except Exception:
                    continue
        rows.sort(key=lambda r: (r.get("type", ""), r.get("updated_at", ""), r.get("id", "")))
        self.write_index(rows)

    # -------- Core ops --------
    def new_id(self, prefix: str) -> str:
        return f"{prefix}_{uuid.uuid4().hex[:10]}"

    def save(self, model: BaseModel, artifact_type: ArtifactType, artifact_id: str) -> Path:
        path = self._type_dir(artifact_type) / f"{artifact_id}.json"
        path.write_text(model.model_dump_json(indent=2), encoding="utf-8")
        try:
            self.upsert_index_row(artifact_type, model, artifact_id)
        except Exception:
            pass
        return path

    def load(self, artifact_type: ArtifactType, artifact_id: str) -> Optional[BaseModel]:
        path = self._type_dir(artifact_type) / f"{artifact_id}.json"
        if not path.exists():
            return None
        cls = _TYPE_MAP[artifact_type]
        raw = path.read_text(encoding="utf-8")
        return cls.model_validate_json(raw)

    def list_ids(self, artifact_type: ArtifactType) -> List[str]:
        """Return artifact IDs for a type.

        NOTE: We *union* index + on-disk scan.

        Why: the global index is best-effort. If the index is partially out of date
        (common when upgrading packages or copying artifact folders between runs),
        relying on it alone can undercount artifacts and hide items in dropdowns.
        """
        indexed: List[str] = []
        try:
            indexed = self.list_ids_indexed(artifact_type)
        except Exception:
            indexed = []

        d = self._type_dir(artifact_type)
        disk: List[str] = []
        if d.exists():
            for fp in d.glob("*.json"):
                name = fp.name
                if name.endswith(".enrichment.json") or name.endswith(".iocs.json") or name.endswith(".assistant.json"):
                    continue
                disk.append(fp.stem)

        # Union to avoid missing artifacts when index is stale.
        return sorted(list(set(indexed) | set(disk)))

    def list_all(self, artifact_type: ArtifactType) -> List[BaseModel]:
        return [m for aid in self.list_ids(artifact_type) if (m := self.load(artifact_type, aid)) is not None]

    def export_markdown(self, artifact_type: ArtifactType, artifact_id: str, markdown: str) -> Path:
        type_dir = self.exports_dir / artifact_type.value
        type_dir.mkdir(parents=True, exist_ok=True)
        out_path = type_dir / f"{artifact_id}.md"
        out_path.write_text(markdown, encoding="utf-8")
        return out_path

    def delete(self, artifact_type: ArtifactType, artifact_id: str) -> None:
        path = self._type_dir(artifact_type) / f"{artifact_id}.json"
        if path.exists():
            path.unlink()
        try:
            rows = self.load_index()
            rows = [r for r in rows if not (isinstance(r, dict) and r.get("id") == artifact_id and r.get("type") == artifact_type.value)]
            self.write_index(rows)
        except Exception:
            pass

    # -------- Destructive ops (Settings/Demo utilities) --------
    def append_audit(self, action: str, actor: str = "", scope: str = "", note: str = "") -> None:
        """Append a global audit entry.

        This is separate from per-artifact meta.history, and is intended for
        operations like bulk resets.
        """
        try:
            from .workflow import utc_now  # local import to avoid cycles

            entry = {
                "ts": utc_now(),
                "actor": actor or "",
                "action": action,
            }
            if scope:
                entry["scope"] = scope
            if note:
                entry["note"] = note
            line = json.dumps(entry, ensure_ascii=False)
            with self.audit_log_path.open("a", encoding="utf-8") as f:
                f.write(line + "\n")
        except Exception:
            pass

    def read_audit(self, limit: int = 50) -> List[Dict]:
        try:
            if not self.audit_log_path.exists():
                return []
            lines = self.audit_log_path.read_text(encoding="utf-8", errors="ignore").splitlines()
            out: List[Dict] = []
            for ln in lines[-max(1, int(limit)) :]:
                try:
                    d = json.loads(ln)
                    if isinstance(d, dict):
                        out.append(d)
                except Exception:
                    continue
            return out
        except Exception:
            return []

    def reset(self, mode: str = "all") -> None:
        """Reset persisted data.

        mode:
          - "all": delete entire data_dir contents (recreate structure)
          - "intel": delete only intel_brief + intel_iocs
          - "artifacts": delete hunt/run/finding/ads (keeps intel)
        """
        mode = (mode or "all").strip().lower()

        def _rm(p: Path) -> None:
            try:
                if p.exists():
                    shutil.rmtree(p, ignore_errors=True)
            except Exception:
                pass

        if mode == "all":
            _rm(self.data_dir)
            self.data_dir.mkdir(parents=True, exist_ok=True)
            self.artifacts_dir = self.data_dir / "artifacts"
            self.exports_dir = self.data_dir / "exports"
            self.artifacts_dir.mkdir(parents=True, exist_ok=True)
            self.exports_dir.mkdir(parents=True, exist_ok=True)
            self.index_path = self.data_dir / "_index.json"
            if not self.index_path.exists():
                self.index_path.write_text("[]", encoding="utf-8")
            # recreate audit log
            self.audit_log_path = self.data_dir / "_audit_log.jsonl"
            try:
                self.audit_log_path.write_text("", encoding="utf-8")
            except Exception:
                pass
            return

        # selective modes
        if mode == "intel":
            for at in (ArtifactType.INTEL_BRIEF, ArtifactType.INTEL_IOCS):
                _rm(self.artifacts_dir / at.value)
            # exports for intel
            _rm(self.exports_dir / ArtifactType.INTEL_BRIEF.value)
            _rm(self.exports_dir / ArtifactType.INTEL_IOCS.value)
        elif mode == "artifacts":
            for at in (ArtifactType.HUNT_PACKAGE, ArtifactType.RUN, ArtifactType.FINDING, ArtifactType.ADS):
                _rm(self.artifacts_dir / at.value)
                _rm(self.exports_dir / at.value)

        # rebuild index after selective deletes
        try:
            self.rebuild_index()
        except Exception:
            pass

    # Backwards compatibility (older UI expected this name)
    def delete_data_dir(self) -> None:
        """Delete ./data and recreate structure (alias for reset(mode='all'))."""
        self.reset("all")
