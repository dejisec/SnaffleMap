"""JSONL exporter for SnaffleMap — one finding per line, round-trippable."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Union

from snafflemap.models import DirResult, FileResult, ResultSet, ShareResult


def _file_record(fr: FileResult) -> dict:
    return {
        "id": fr.finding_id,
        "type": "file",
        "severity": fr.severity.value,
        "rule_name": fr.rule_name,
        "can_read": fr.can_read,
        "can_write": fr.can_write,
        "can_modify": fr.can_modify,
        "matched_string": fr.matched_string,
        "file_size": fr.file_size,
        "modified_date": fr.modified_date.isoformat(),
        "file_path": fr.file_path,
        "alt_filename": fr.alt_filename,
        "match_context": fr.match_context,
        "hostname": fr.hostname,
        "share_name": fr.share_name,
        "extension": fr.extension,
        "source_line": fr.source_line,
        "sources": list(fr.sources),
    }


def _share_record(sr: ShareResult) -> dict:
    return {
        "id": sr.finding_id,
        "type": "share",
        "severity": sr.severity.value,
        "share_path": sr.share_path,
        "can_read": sr.can_read,
        "can_write": sr.can_write,
        "can_modify": sr.can_modify,
        "hostname": sr.hostname,
        "share_name": sr.share_name,
        "source_line": sr.source_line,
        "sources": list(sr.sources),
    }


def _dir_record(dr: DirResult) -> dict:
    return {
        "id": dr.finding_id,
        "type": "dir",
        "severity": dr.severity.value,
        "dir_path": dr.dir_path,
        "hostname": dr.hostname,
        "source_line": dr.source_line,
        "sources": list(dr.sources),
    }


def _enrichment_block(enr) -> dict:
    return {
        "score": {
            "value": enr.score.value,
            "tier": enr.score.tier,
            "breakdown": [[name, pts] for name, pts in enr.score.breakdown],
        },
        "detectors": [
            {
                "id": h.id,
                "label": h.label,
                "category": h.category,
                "why": h.why,
                "action": h.action,
                "crackable": h.crackable,
                "remediation": h.remediation,
            }
            for h in enr.detectors
        ],
        "credentials": [
            {
                "type": c.type,
                "username": c.username,
                "secret": c.secret,
                "crackable": c.crackable,
                "hashcat_mode": c.hashcat_mode,
            }
            for c in enr.credentials
        ],
    }


def export(
    result_set: ResultSet,
    path: Union[str, Path],
    enrichment=None,
    delta=None,
    resolved=None,
) -> None:
    """Write each finding as one JSON object per line (UTF-8).

    *enrichment* adds an ``enrichment`` block; *delta* (dict id->status) adds a
    ``delta_status`` field; *resolved* (list of baseline records) is appended with
    ``delta_status`` = ``"resolved"``.
    """
    path = Path(path)

    def decorate(record: dict, finding) -> dict:
        if enrichment is not None:
            enr = enrichment.get(finding.finding_id)
            if enr is not None:
                record["enrichment"] = _enrichment_block(enr)
        if delta is not None:
            record["delta_status"] = delta.get(finding.finding_id)
        return record

    with path.open("w", encoding="utf-8") as f:
        for fr in result_set.files:
            f.write(
                json.dumps(decorate(_file_record(fr), fr), ensure_ascii=False) + "\n"
            )
        for sr in result_set.shares:
            f.write(
                json.dumps(decorate(_share_record(sr), sr), ensure_ascii=False) + "\n"
            )
        for dr in result_set.dirs:
            f.write(
                json.dumps(decorate(_dir_record(dr), dr), ensure_ascii=False) + "\n"
            )
        for rec in resolved or []:
            out = dict(rec)
            out["delta_status"] = "resolved"
            f.write(json.dumps(out, ensure_ascii=False) + "\n")
