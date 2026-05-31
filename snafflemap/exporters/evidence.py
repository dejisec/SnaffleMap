"""Evidence-pack exporter: deliverable Markdown + print-ready HTML, with redaction."""

from __future__ import annotations

from pathlib import Path
from typing import Union

from jinja2 import Environment, PackageLoader

from snafflemap.exporters._utils import human_size

_CATEGORY_REMEDIATION = {
    "credentials": "Rotate the exposed credential and restrict read access to the file/share.",
    "key": "Revoke and reissue the key material; restrict access to the keystore.",
    "config": "Remove secrets from configuration; use a secrets manager and tighten ACLs.",
    "database": "Rotate the database credentials and restrict access to the data file/share.",
    "cloud": "Revoke the exposed cloud credentials/tokens and rotate affected keys.",
    "backup": "Restrict access to backups and ensure they do not contain plaintext secrets.",
    "source-control": "Purge secrets from the repository/history and rotate any exposed credentials.",
}
_GENERIC_REMEDIATION = (
    "Restrict access to this resource and remove or rotate any exposed secrets."
)


def redact_secret(value: str, mode: str) -> str:
    """Mask *value* per *mode*: none (raw), full ([REDACTED]), partial (first/last 2)."""
    if mode == "none" or not value:
        return value
    if mode == "full":
        return "[REDACTED]"
    if len(value) <= 4:
        return "…"
    return value[:2] + "…" + value[-2:]


def _remediation_for(detectors, category: str | None) -> str:
    for h in detectors:
        if getattr(h, "remediation", None):
            return h.remediation
    if category and category in _CATEGORY_REMEDIATION:
        return _CATEGORY_REMEDIATION[category]
    return _GENERIC_REMEDIATION


def _finding_view(finding, enr, redact: str) -> dict:
    path = (
        getattr(finding, "file_path", None)
        or getattr(finding, "share_path", None)
        or getattr(finding, "dir_path", "")
    )
    fname = path.rsplit("\\", 1)[-1] if "\\" in path else path
    detectors = list(enr.detectors) if enr else []
    creds = []
    for c in enr.credentials if enr else []:
        creds.append(
            {
                "type": c.type,
                "username": c.username,
                "secret": redact_secret(c.secret, redact),
                "crackable": c.crackable,
            }
        )
    category = detectors[0].category if detectors else None
    title = (
        detectors[0].label if detectors else getattr(finding, "rule_name", "") or fname
    )
    snippet = redact_secret(getattr(finding, "matched_string", "") or "", redact)
    context = getattr(finding, "match_context", "") or ""
    if redact != "none" and creds:
        # also mask the raw secret if it appears verbatim in the context
        for c in enr.credentials if enr else []:
            if c.secret:
                context = context.replace(c.secret, redact_secret(c.secret, redact))
    size = getattr(finding, "file_size", None)
    return {
        "id": finding.finding_id,
        "title": title,
        "severity": finding.severity.value,
        "score": enr.score.value if enr else 0,
        "tier": enr.score.tier if enr else "Low",
        "host": getattr(finding, "hostname", ""),
        "path": path,
        "size": human_size(size) if size else "",
        "why": detectors[0].why if detectors else "",
        "action": detectors[0].action if detectors else "",
        "credentials": creds,
        "snippet": snippet,
        "context": context,
        "remediation": _remediation_for(detectors, category),
        "sources": list(getattr(finding, "sources", ())),
    }


def _render_markdown(views: list[dict]) -> str:
    lines: list[str] = [
        "# SnaffleMap Evidence Pack",
        "",
        f"{len(views)} finding(s).",
        "",
    ]
    for v in views:
        lines += [
            f"## {v['title']} — {v['severity']} ({v['tier']} {v['score']})",
            "",
            f"- **Host:** {v['host']}",
            f"- **Path:** `{v['path']}`",
            f"- **Score:** {v['score']}/100 ({v['tier']})",
        ]
        if v["why"]:
            lines.append(f"- **Why it matters:** {v['why']}")
        if v["action"]:
            lines.append(f"- **Recommended action:** `{v['action']}`")
        if v["credentials"]:
            lines.append("- **Credentials:**")
            for c in v["credentials"]:
                user = f"{c['username']} : " if c["username"] else ""
                lines.append(f"  - {c['type']}: {user}`{c['secret']}`")
        if v["snippet"]:
            lines += ["- **Matched:**", "", "  ```", f"  {v['snippet']}", "  ```"]
        if v["context"] and v["context"] != v["snippet"]:
            lines += ["- **Context:**", "", "  ```", f"  {v['context']}", "  ```"]
        lines += [
            f"- **Remediation:** {v['remediation']}",
            f"- **Sources:** {', '.join(v['sources'])}",
            f"- **Finding ID:** `{v['id']}`",
            "",
        ]
    return "\n".join(lines)


def export(
    result_set,
    path: Union[str, Path],
    *,
    enrichment=None,
    redact: str = "none",
    split: bool = False,
) -> None:
    """Write an evidence pack: combined Markdown + print-ready HTML (and per-finding
    Markdown files when *split* is True)."""
    path = Path(path)
    findings = [*result_set.files, *result_set.shares, *result_set.dirs]
    views = [
        _finding_view(f, (enrichment or {}).get(f.finding_id), redact) for f in findings
    ]

    path.write_text(_render_markdown(views), encoding="utf-8")

    # print-ready HTML sibling
    env = Environment(
        loader=PackageLoader("snafflemap", "templates"),
        autoescape=True,
        trim_blocks=True,
        lstrip_blocks=True,
    )
    template = env.get_template("evidence.html.j2")
    html = template.render(views=views, count=len(views))
    path.with_suffix(".html").write_text(html, encoding="utf-8")

    if split:
        out_dir = path.parent / "evidence"
        out_dir.mkdir(parents=True, exist_ok=True)
        for v in views:
            (out_dir / f"{v['id']}.md").write_text(
                _render_markdown([v]), encoding="utf-8"
            )
