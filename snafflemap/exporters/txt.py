"""TXT exporter for SnaffleMap results."""

from __future__ import annotations

from collections import defaultdict
from pathlib import Path
from typing import Union

from tabulate import tabulate

from snafflemap.exporters._utils import human_size
from snafflemap.models import ResultSet, Severity, FileResult

# Severity display order: most severe first
_SEVERITY_ORDER = [
    Severity.BLACK,
    Severity.RED,
    Severity.YELLOW,
    Severity.GREEN,
    Severity.GRAY,
]


def _perms(fr: FileResult) -> str:
    """Concatenate R/W/M permission flags."""
    flags = ""
    if fr.can_read:
        flags += "R"
    if fr.can_write:
        flags += "W"
    if fr.can_modify:
        flags += "M"
    return flags


def _truncate(text: str, width: int) -> str:
    """Truncate text to width characters, appending '...' if over."""
    if len(text) <= width:
        return text
    return text[:width] + "..."


def export(
    result_set: ResultSet,
    path: Union[str, Path],
    *,
    snippet_width: int = 80,
) -> None:
    """Export ResultSet to a plain-text report file."""
    path = Path(path)
    lines: list[str] = []

    # ------------------------------------------------------------------
    # FILE RESULTS grouped by severity
    # ------------------------------------------------------------------
    by_severity: dict[Severity, list[FileResult]] = defaultdict(list)
    for fr in result_set.files:
        by_severity[fr.severity].append(fr)

    for sev in _SEVERITY_ORDER:
        file_list = by_severity.get(sev, [])
        if not file_list:
            continue

        count = len(file_list)
        header = f"{sev.value} ({count} finding{'s' if count != 1 else ''})"
        sep = "=" * len(header)
        lines.append(sep)
        lines.append(header)
        lines.append(sep)
        lines.append("")

        rows = []
        for fr in file_list:
            snippet = _truncate(fr.match_context, snippet_width)
            date_str = fr.modified_date.strftime("%Y-%m-%d %H:%M")
            rows.append(
                [
                    fr.rule_name,
                    _perms(fr),
                    fr.file_path,
                    human_size(fr.file_size),
                    date_str,
                    snippet,
                ]
            )

        table = tabulate(
            rows,
            headers=["Rule", "Perms", "Path", "Size", "Modified", "Snippet"],
            tablefmt="simple",
        )
        lines.append(table)
        lines.append("")

    # ------------------------------------------------------------------
    # SHARES table
    # ------------------------------------------------------------------
    lines.append("=" * 30)
    lines.append("SHARES")
    lines.append("=" * 30)
    lines.append("")

    share_rows = []
    for sr in result_set.shares:
        sev_perms = ""
        if sr.can_read:
            sev_perms += "R"
        if sr.can_write:
            sev_perms += "W"
        if sr.can_modify:
            sev_perms += "M"
        share_rows.append([sr.severity.value, sr.share_path, sev_perms])

    if share_rows:
        lines.append(
            tabulate(
                share_rows,
                headers=["Severity", "Share Path", "Perms"],
                tablefmt="simple",
            )
        )
    else:
        lines.append("(none)")
    lines.append("")

    # ------------------------------------------------------------------
    # DIRECTORIES table
    # ------------------------------------------------------------------
    lines.append("=" * 30)
    lines.append("DIRECTORIES")
    lines.append("=" * 30)
    lines.append("")

    dir_rows = []
    for dr in result_set.dirs:
        dir_rows.append([dr.severity.value, dr.dir_path])

    if dir_rows:
        lines.append(
            tabulate(
                dir_rows,
                headers=["Severity", "Directory Path"],
                tablefmt="simple",
            )
        )
    else:
        lines.append("(none)")
    lines.append("")

    # ------------------------------------------------------------------
    # Write file
    # ------------------------------------------------------------------
    path.write_text("\n".join(lines), encoding="utf-8")
