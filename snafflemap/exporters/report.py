from __future__ import annotations

import json as _json
import re
from pathlib import Path

from jinja2 import Environment, PackageLoader

from snafflemap.exporters._utils import human_size
from snafflemap.models import ResultSet


_REPORT_DIR = Path(__file__).resolve().parent.parent / "templates" / "report"
_JS_ORDER = [
    "dom.js",
    "data.js",
    "query.js",
    "facets.js",
    "sortgroup.js",
    "store.js",
    "list.js",
    "detail.js",
    "rail.js",
    "map.js",
    "report.js",
    "triage.js",
    "app.js",
]


def _read_assets() -> tuple[str, str]:
    """Return (css_text, concatenated_js_text) read from the modular source dir."""
    css = (_REPORT_DIR / "app.css").read_text(encoding="utf-8")
    js_parts = [
        (_REPORT_DIR / "js" / name).read_text(encoding="utf-8") for name in _JS_ORDER
    ]
    return css, "\n".join(js_parts)


def _json_for_script(obj) -> str:
    """Serialize to JSON safe to embed in an HTML <script> element.

    Escapes <, >, & (and U+2028/U+2029) so a literal </script> or HTML in the
    data cannot break out of the script element. JSON.parse decodes the \\uXXXX
    escapes transparently.
    """
    text = _json.dumps(obj, ensure_ascii=False)
    return (
        text.replace("<", "\\u003c")
        .replace(">", "\\u003e")
        .replace("&", "\\u0026")
        .replace(" ", "\\u2028")
        .replace(" ", "\\u2029")
    )


def _meta_for(finding, enrichment, delta=None) -> dict:
    path = (
        getattr(finding, "file_path", None)
        or getattr(finding, "share_path", None)
        or getattr(finding, "dir_path", "")
    )
    ftype = (
        "file"
        if hasattr(finding, "file_path")
        else "share"
        if hasattr(finding, "share_path")
        else "dir"
    )
    actions = []
    crackable = False
    detector_ids: list[str] = []
    score = 0
    tier = "Low"
    if enrichment is not None:
        enr = enrichment.get(finding.finding_id)
        if enr is not None:
            score = enr.score.value
            tier = enr.score.tier
            for hit in enr.detectors:
                actions.append({"label": hit.label, "cmd": hit.action})
                crackable = crackable or hit.crackable
                detector_ids.append(hit.id)
    modified = getattr(finding, "modified_date", None)
    return {
        "path": path,
        "host": getattr(finding, "hostname", ""),
        "share": getattr(finding, "share_name", ""),
        "type": ftype,
        "crackable": crackable,
        "writable": bool(
            getattr(finding, "can_write", False)
            or getattr(finding, "can_modify", False)
        ),
        "actions": actions,
        "rule": getattr(finding, "rule_name", ""),
        "detector_ids": detector_ids,
        "severity": finding.severity.value,
        "score": score,
        "tier": tier,
        "size": getattr(finding, "file_size", None),
        "modified": modified.isoformat() if modified is not None else "",
        "matched": getattr(finding, "matched_string", "") or "",
        "snippet": getattr(finding, "match_context", "") or "",
        "sources": list(getattr(finding, "sources", ())),
        "delta_status": (delta or {}).get(finding.finding_id),
    }


def _delta_counts(delta: dict | None) -> dict[str, int]:
    """Count occurrences of each delta status."""
    counts: dict[str, int] = {"new": 0, "persisted": 0, "escalated": 0}
    for status in (delta or {}).values():
        if status in counts:
            counts[status] += 1
        else:
            counts[status] = counts.get(status, 0) + 1
    return counts


def export(
    result_set: ResultSet,
    path: str | Path,
    *,
    enrichment=None,
    triage=None,
    suppressions=None,
    report_name: str = "report",
    delta=None,
    resolved=None,
) -> None:
    path = Path(path)
    env = Environment(
        loader=PackageLoader("snafflemap", "templates"),
        autoescape=True,
        trim_blocks=True,
        lstrip_blocks=True,
    )
    env.filters["human_size"] = human_size
    template = env.get_template("report/shell.html.j2")
    app_css, app_js = _read_assets()
    # Defuse any literal </script> inside the JS so it can't close the inline
    # <script> element. The backslash form is identical in JS string/regex
    # contexts but is not recognized as a tag close by the HTML parser.
    app_js = re.sub(r"</(script)", r"<\\/\1", app_js, flags=re.IGNORECASE)

    meta = {
        fnd.finding_id: _meta_for(fnd, enrichment, delta)
        for fnd in (*result_set.files, *result_set.shares, *result_set.dirs)
    }
    sm_data = {
        "report_id": report_name,
        "triage": triage or {},
        "suppressions": suppressions or [],
        "resolved": resolved or [],
        "meta": meta,
    }

    html = template.render(
        report_id=report_name,
        app_css=app_css,
        app_js=app_js,
        sm_data_json=_json_for_script(sm_data),
    )
    path.write_text(html, encoding="utf-8")
