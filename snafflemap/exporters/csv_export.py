"""CSV exporter for SnaffleMap results."""

from __future__ import annotations

import csv
from pathlib import Path
from typing import Union

from snafflemap.models import ResultSet, FileResult, ShareResult, DirResult

# Union schema columns for all result types
_FIELDNAMES = [
    "type",
    "severity",
    "rule_name",
    "can_read",
    "can_write",
    "can_modify",
    "matched_string",
    "file_size",
    "modified_date",
    "file_path",
    "alt_filename",
    "match_context",
    "hostname",
    "share_name",
    "extension",
    "source_line",
]


def _file_row(fr: FileResult) -> dict:
    return {
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
        "alt_filename": fr.alt_filename if fr.alt_filename is not None else "",
        "match_context": fr.match_context,
        "hostname": fr.hostname,
        "share_name": fr.share_name,
        "extension": fr.extension,
        "source_line": fr.source_line if fr.source_line is not None else "",
    }


def _share_row(sr: ShareResult) -> dict:
    return {
        "type": "share",
        "severity": sr.severity.value,
        "rule_name": "",
        "can_read": sr.can_read,
        "can_write": sr.can_write,
        "can_modify": sr.can_modify,
        "matched_string": "",
        "file_size": "",
        "modified_date": "",
        "file_path": sr.share_path,
        "alt_filename": "",
        "match_context": "",
        "hostname": sr.hostname,
        "share_name": sr.share_name,
        "extension": "",
        "source_line": sr.source_line if sr.source_line is not None else "",
    }


def _dir_row(dr: DirResult) -> dict:
    return {
        "type": "dir",
        "severity": dr.severity.value,
        "rule_name": "",
        "can_read": "",
        "can_write": "",
        "can_modify": "",
        "matched_string": "",
        "file_size": "",
        "modified_date": "",
        "file_path": dr.dir_path,
        "alt_filename": "",
        "match_context": "",
        "hostname": dr.hostname,
        "share_name": "",
        "extension": "",
        "source_line": dr.source_line if dr.source_line is not None else "",
    }


def export(result_set: ResultSet, path: Union[str, Path]) -> None:
    """Export ResultSet to a CSV file with UTF-8 BOM encoding."""
    path = Path(path)

    with path.open("w", encoding="utf-8-sig", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=_FIELDNAMES)
        writer.writeheader()

        for fr in result_set.files:
            writer.writerow(_file_row(fr))

        for sr in result_set.shares:
            writer.writerow(_share_row(sr))

        for dr in result_set.dirs:
            writer.writerow(_dir_row(dr))
