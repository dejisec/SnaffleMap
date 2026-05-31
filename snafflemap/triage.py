"""Triage sidecar format: load, validate, merge (last-write-wins), suppression."""

from __future__ import annotations

import fnmatch
import json
from pathlib import Path

SCHEMA = "snafflemap-triage/1"
VALID_STATUSES = {"new", "triaged", "confirmed-loot", "false-positive", "reported"}
VALID_SUPPRESSION_KINDS = {"rule", "path", "detector"}


class TriageError(Exception):
    """Raised when a triage sidecar is malformed."""


def empty_sidecar(report_name: str) -> dict:
    return {
        "schema": SCHEMA,
        "report_name": report_name,
        "exported_at": "",
        "triage": {},
        "suppressions": [],
    }


def validate_sidecar(data: object) -> None:
    if not isinstance(data, dict):
        raise TriageError("sidecar must be a JSON object")
    if data.get("schema") != SCHEMA:
        raise TriageError(f"unsupported schema: {data.get('schema')!r}")
    triage = data.get("triage", {})
    if not isinstance(triage, dict):
        raise TriageError("'triage' must be an object")
    for fid, entry in triage.items():
        if not isinstance(entry, dict):
            raise TriageError(f"triage[{fid}] must be an object")
        status = entry.get("status")
        if status is not None and status not in VALID_STATUSES:
            raise TriageError(f"triage[{fid}] invalid status {status!r}")
    supps = data.get("suppressions", [])
    if not isinstance(supps, list):
        raise TriageError("'suppressions' must be a list")
    for s in supps:
        if not isinstance(s, dict) or s.get("kind") not in VALID_SUPPRESSION_KINDS:
            raise TriageError(f"invalid suppression entry: {s!r}")


def load_sidecar(path) -> dict:
    path = Path(path)
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise TriageError(f"cannot read triage file {path}: {exc}") from exc
    validate_sidecar(data)
    data.setdefault("triage", {})
    data.setdefault("suppressions", [])
    return data


def _merge_notes(a_notes, b_notes) -> list:
    seen = set()
    out = []
    for note in [*(a_notes or []), *(b_notes or [])]:
        key = (note.get("by"), note.get("at"), note.get("text"))
        if key in seen:
            continue
        seen.add(key)
        out.append(note)
    return out


def merge_sidecars(a: dict, b: dict) -> dict:
    """Merge two sidecars: per-finding last-write-wins by updated_at; notes unioned.

    Suppressions are unioned by (kind, value).
    """
    out_triage: dict = {}
    for fid in set(a.get("triage", {})) | set(b.get("triage", {})):
        ea = a.get("triage", {}).get(fid)
        eb = b.get("triage", {}).get(fid)
        if ea and eb:
            winner = (
                eb if (eb.get("updated_at", "") >= ea.get("updated_at", "")) else ea
            )
            merged = dict(winner)
            merged["notes"] = _merge_notes(ea.get("notes"), eb.get("notes"))
            out_triage[fid] = merged
        else:
            out_triage[fid] = dict(ea or eb)

    supp_map = {}
    for s in [*a.get("suppressions", []), *b.get("suppressions", [])]:
        supp_map[(s.get("kind"), s.get("value"))] = s

    return {
        "schema": SCHEMA,
        "report_name": b.get("report_name") or a.get("report_name") or "",
        "exported_at": b.get("exported_at") or a.get("exported_at") or "",
        "triage": out_triage,
        "suppressions": list(supp_map.values()),
    }


def finding_matches_suppression(
    suppression: dict, *, rule_name: str, path: str, detector_ids: list[str]
) -> bool:
    """Return True if a finding matches one suppression entry."""
    kind = suppression.get("kind")
    value = suppression.get("value", "")
    if kind == "rule":
        return value.lower() == rule_name.lower()
    if kind == "path":
        return fnmatch.fnmatch(path, value)
    if kind == "detector":
        return value in detector_ids
    return False
