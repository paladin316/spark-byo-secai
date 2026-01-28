from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Dict, List, Tuple


@dataclass
class SchemaDetection:
    elastic_ecs: bool = False
    sigma: bool = False
    splunk_cim: bool = False

    def to_dict(self) -> Dict:
        return {
            "elastic_ecs": bool(self.elastic_ecs),
            "sigma": bool(self.sigma),
            "splunk_cim": bool(self.splunk_cim),
        }


# --- Mapping tables ---------------------------------------------------------

# Elastic ECS -> CrowdStrike LogScale (ProcessRollup2 / friends)
# NOTE: This is a *prompt-side* translation for grounding and consistency.
# It is not an ingestion mapping and does not claim 1:1 fidelity.
ECS_TO_CS: Dict[str, str | None] = {
    # Core process pivots
    "process.command_line": "CommandLine",
    "process.args": "CommandLine",  # best-effort; CS has CommandLine but not args array
    "process.executable": "FilePath",
    "process.name": "FileName",
    "process.pid": "ProcessId_decimal",
    "process.parent.command_line": "ParentCommandLine",
    "process.parent.executable": "ParentFilePath",
    "process.parent.name": "ParentBaseFileName",
    # PE metadata (no direct CS equivalent in this demo corpus)
    "process.pe.original_file_name": None,
    "process.pe.company": None,
    "process.pe.product": None,
    "process.pe.description": None,
}


# Splunk CIM (Endpoint / Processes node) -> CrowdStrike
CIM_TO_CS: Dict[str, str | None] = {
    "process": "CommandLine",
    "process_name": "FileName",
    "process_path": "FilePath",
    "process_exec": "FileName",
    "process_id": "ProcessId_decimal",
    "parent_process": "ParentCommandLine",
    "parent_process_name": "ParentBaseFileName",
    "parent_process_path": "ParentFilePath",
    # Common CIM hash field
    "file_hash": "SHA256HashData",
}


# Sigma "generic" fields -> CrowdStrike-ish pivots
SIGMA_TO_CS: Dict[str, str | None] = {
    "Image": "FilePath",
    "CommandLine": "CommandLine",
    "ParentImage": "ParentFilePath",
    "ParentCommandLine": "ParentCommandLine",
    # Sigma often uses OriginalFileName (Sysmon) — not present in CS demo corpus
    "OriginalFileName": None,
}


# --- Detection heuristics ---------------------------------------------------

_ECS_HINTS = (
    "process.command_line",
    "process.executable",
    "process.pe.",
)

_SIGMA_HINTS = (
    "detection:",
    "selection:",
    "condition:",
    "|endswith",
    "|contains",
    "Image|",
)

_CIM_HINTS = (
    "process_name",
    "parent_process_name",
    "datamodel=",
    "Endpoint.Processes",
    "Processes",
)


def detect_source_schema(text: str) -> SchemaDetection:
    t = (text or "")
    t_l = t.lower()

    ecs = any(h in t_l for h in _ECS_HINTS)
    sigma = any(h.lower() in t_l for h in _SIGMA_HINTS)
    cim = any(h.lower() in t_l for h in _CIM_HINTS)
    return SchemaDetection(elastic_ecs=ecs, sigma=sigma, splunk_cim=cim)


# --- Translation ------------------------------------------------------------

_ECS_FIELD_RE = re.compile(r"\bprocess(?:\.[a-z0-9_]+)+(?:\.[a-z0-9_]+)*\b", re.IGNORECASE)
_CIM_FIELD_RE = re.compile(r"\b(?:process_name|process_path|process_exec|process_id|parent_process(?:_name|_path)?|file_hash|process)\b")
_SIGMA_FIELD_RE = re.compile(r"\b(?:Image|CommandLine|ParentImage|ParentCommandLine|OriginalFileName)\b")


def translate_fields_to_crowdstrike(text: str) -> Tuple[str, Dict]:
    """Translate foreign schema fields in free-text intel to CS-friendly pivots.

    Returns: (translated_text, debug_dict)
      - debug_dict includes schema detection, replacements, and drops.
    """
    raw = (text or "")
    det = detect_source_schema(raw)

    replacements: List[Dict] = []
    drops: List[str] = []

    out = raw

    # Elastic ECS replacements
    if det.elastic_ecs:
        # Replace longest-first to avoid partial shadowing
        ecs_fields = sorted(set(_ECS_FIELD_RE.findall(out)), key=lambda s: len(s), reverse=True)
        for f in ecs_fields:
            key = f.lower()
            mapped = ECS_TO_CS.get(key)
            if mapped is None:
                # drop occurrences (remove the field token, keep surrounding operators intact)
                out = re.sub(rf"\b{re.escape(f)}\b\s*[:=]", "", out)
                drops.append(f)
                continue
            if mapped:
                out = re.sub(rf"\b{re.escape(f)}\b", mapped, out)
                replacements.append({"from": f, "to": mapped, "schema": "Elastic ECS"})

    # Splunk CIM replacements
    if det.splunk_cim:
        cim_fields = sorted(set(_CIM_FIELD_RE.findall(out)), key=lambda s: len(s), reverse=True)
        for f in cim_fields:
            mapped = CIM_TO_CS.get(f)
            if mapped is None:
                out = re.sub(rf"\b{re.escape(f)}\b\s*[:=]", "", out)
                drops.append(f)
                continue
            if mapped:
                out = re.sub(rf"\b{re.escape(f)}\b", mapped, out)
                replacements.append({"from": f, "to": mapped, "schema": "Splunk CIM"})

    # Sigma replacements
    if det.sigma:
        sigma_fields = sorted(set(_SIGMA_FIELD_RE.findall(out)), key=lambda s: len(s), reverse=True)
        for f in sigma_fields:
            mapped = SIGMA_TO_CS.get(f)
            if mapped is None:
                out = re.sub(rf"\b{re.escape(f)}\b\s*[:=]", "", out)
                drops.append(f)
                continue
            if mapped:
                out = re.sub(rf"\b{re.escape(f)}\b", mapped, out)
                replacements.append({"from": f, "to": mapped, "schema": "Sigma"})

    debug = {
        "schema_detected": det.to_dict(),
        "replacements": replacements,
        "dropped": sorted(set(drops)),
    }
    return out, debug
