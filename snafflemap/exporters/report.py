from __future__ import annotations

from collections import Counter
from pathlib import Path

from jinja2 import Environment, PackageLoader

from snafflemap.exporters._utils import human_size
from snafflemap.models import DirResult, FileResult, ResultSet, Severity, ShareResult


def _group_by(items: list, key_fn) -> dict[str, list]:
    groups: dict[str, list] = {}
    for item in items:
        k = key_fn(item)
        groups.setdefault(k, []).append(item)
    return groups


def export(result_set: ResultSet, path: str | Path) -> None:
    path = Path(path)
    env = Environment(loader=PackageLoader("snafflemap", "templates"), autoescape=True, trim_blocks=True, lstrip_blocks=True)
    env.filters["human_size"] = human_size
    template = env.get_template("report.html.j2")
    host_counts = Counter(f.hostname for f in result_set.files if f.hostname)
    rule_counts = Counter(f.rule_name for f in result_set.files)
    html = template.render(
        result_set=result_set,
        severities=list(Severity),
        severity_counts=result_set.severity_counts,
        files_by_severity=_group_by(result_set.files, lambda f: f.severity.value),
        files_by_host=_group_by(result_set.files, lambda f: f.hostname or "unknown"),
        files_by_rule=_group_by(result_set.files, lambda f: f.rule_name),
        shares_by_severity=_group_by(result_set.shares, lambda s: s.severity.value),
        shares_by_host=_group_by(result_set.shares, lambda s: s.hostname or "unknown"),
        dirs_by_severity=_group_by(result_set.dirs, lambda d: d.severity.value),
        dirs_by_host=_group_by(result_set.dirs, lambda d: d.hostname or "unknown"),
        top_hosts=host_counts.most_common(5),
        top_rules=rule_counts.most_common(5),
        stats={
            "total_findings": result_set.total_findings,
            "file_count": result_set.file_count,
            "share_count": result_set.share_count,
            "dir_count": result_set.dir_count,
            "unique_hosts": len(result_set.unique_hosts),
            "unique_shares": len(result_set.unique_shares),
            "date_range": result_set.date_range,
        },
    )
    path.write_text(html, encoding="utf-8")
