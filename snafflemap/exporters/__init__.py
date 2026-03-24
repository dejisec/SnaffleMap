"""Export modules for SnaffleMap."""

from snafflemap.exporters import csv_export, html, report as report, txt
from snafflemap.models import ResultSet, Severity


def export_split(
    result_set: ResultSet,
    base_path: str,
    format: str,
    **kwargs,
) -> list[str]:
    """Export separate files per severity. Returns list of created file paths."""
    from pathlib import Path

    base = Path(base_path)
    stem = base.stem
    suffix = base.suffix
    parent = base.parent

    exporters_map = {
        "txt": txt.export,
        "csv": csv_export.export,
        "html": html.export,
    }
    exporter = exporters_map.get(format)
    if exporter is None:
        raise ValueError(f"Split not supported for format: {format}")

    created: list[str] = []
    for sev in Severity:
        filtered = ResultSet(
            files=[f for f in result_set.files if f.severity == sev],
            shares=[s for s in result_set.shares if s.severity == sev],
            dirs=[d for d in result_set.dirs if d.severity == sev],
            warnings=result_set.warnings,
        )
        if filtered.total_findings == 0:
            continue
        out_path = parent / f"{stem}-{sev.value}{suffix}"
        exporter(filtered, str(out_path), **kwargs)
        created.append(str(out_path))
    return created
