from __future__ import annotations
import sys
from pathlib import Path
import click
from snafflemap.filters import FilterChain
from snafflemap.models import ResultSet, Severity
from snafflemap.parsers import ParseError, parse
from snafflemap.sorters import apply_sort


def _parse_size(value: str) -> int:
    value = value.strip().upper()
    multipliers = {"K": 1024, "M": 1024**2, "G": 1024**3}
    for suffix, mult in multipliers.items():
        if value.endswith(suffix):
            return int(float(value[:-1]) * mult)
    return int(value)


def _echo(msg: str, quiet: bool, **kwargs) -> None:
    if not quiet:
        click.echo(msg, **kwargs)


@click.command()
@click.argument("input_files", type=click.Path(exists=True), nargs=-1)
@click.option(
    "-o",
    "--output-dir",
    type=click.Path(),
    default=".",
    show_default=True,
    help="Directory for output files.",
)
@click.option(
    "-n",
    "--name",
    "name",
    default=None,
    metavar="NAME",
    help="Base name for output files (default: first input's stem).",
)
@click.option(
    "-f",
    "--format",
    "fmt",
    type=click.Choice(["txt", "csv", "html", "report", "jsonl", "evidence", "all"]),
    default="txt",
    show_default=True,
    help="Export format.",
)
@click.option(
    "--input-format",
    type=click.Choice(["tsv", "json", "jsonl"]),
    default=None,
    help="Force input format (auto-detected if omitted).",
)
@click.option(
    "--split",
    is_flag=True,
    help="Split output into separate files per severity level.",
)
@click.option(
    "-s",
    "--severity",
    default=None,
    metavar="LEVELS",
    help="Comma-separated severity levels to include (Black,Red,Yellow,Green,Gray).",
)
@click.option(
    "--exclude-severity",
    default=None,
    metavar="LEVELS",
    help="Comma-separated severity levels to exclude.",
)
@click.option(
    "--fail-on",
    "fail_on",
    default=None,
    metavar="LEVELS",
    help="Exit 2 if any surviving finding is at one of these severities.",
)
@click.option(
    "--hostname",
    default=None,
    metavar="PATTERN",
    help="Filter by hostname (glob pattern or /regex/).",
)
@click.option(
    "--share",
    default=None,
    metavar="NAME",
    help="Filter by share name (case-insensitive substring).",
)
@click.option(
    "--rule",
    default=None,
    metavar="NAME",
    help="Filter by Snaffler rule name (case-insensitive substring).",
)
@click.option(
    "--ext",
    default=None,
    metavar="EXTS",
    help="Comma-separated file extensions to include (e.g. .kdbx,.pfx).",
)
@click.option(
    "--keyword",
    default=None,
    metavar="TEXT",
    help="Search match context and matched string (case-insensitive).",
)
@click.option(
    "--size-min",
    default=None,
    metavar="SIZE",
    help="Minimum file size with optional K/M/G suffix (e.g. 1M).",
)
@click.option(
    "--size-max",
    default=None,
    metavar="SIZE",
    help="Maximum file size with optional K/M/G suffix (e.g. 500K).",
)
@click.option(
    "--date-after",
    default=None,
    metavar="DATE",
    help="Only files modified after this ISO 8601 date (e.g. 2026-01-01).",
)
@click.option(
    "--date-before",
    default=None,
    metavar="DATE",
    help="Only files modified before this ISO 8601 date.",
)
@click.option(
    "--no-dedup",
    is_flag=True,
    help="Skip deduplication of results.",
)
@click.option(
    "--strict",
    is_flag=True,
    help="Fail on malformed input lines instead of skipping them.",
)
@click.option(
    "--unescape",
    is_flag=True,
    help="Unescape C-style sequences (\\n, \\t) in match context.",
)
@click.option(
    "--sort-by",
    default="severity",
    show_default=True,
    metavar="KEYS",
    help="Comma-separated sort keys: severity, modified, path, rule, size, score.",
)
@click.option(
    "--catalog",
    "catalog_path",
    type=click.Path(exists=True),
    default=None,
    metavar="FILE",
    help="Custom detector/extractor catalog (TOML) merged over the built-ins.",
)
@click.option(
    "--min-score",
    "min_score",
    type=int,
    default=None,
    metavar="N",
    help="Keep only findings with an exploitability score >= N (0-100).",
)
@click.option(
    "--tier",
    "tier",
    default=None,
    metavar="LEVELS",
    help="Keep only findings in these tiers (Critical,High,Medium,Low).",
)
@click.option(
    "--triage",
    "triage_path",
    type=click.Path(exists=True),
    default=None,
    metavar="FILE",
    help="Triage sidecar (JSON) to pre-apply to the report by finding_id.",
)
@click.option(
    "--suppress",
    "suppress_path",
    type=click.Path(exists=True),
    default=None,
    metavar="FILE",
    help="Suppression list (triage JSON) merged into the report.",
)
@click.option(
    "--delta",
    "delta_path",
    type=click.Path(exists=True),
    default=None,
    metavar="FILE",
    help="Baseline JSONL to diff against (annotates findings new/persisted/escalated/resolved).",
)
@click.option(
    "--delta-only",
    "delta_only",
    type=click.Choice(["new", "persisted", "escalated", "resolved"]),
    default=None,
    help="Keep only findings with this delta status (requires --delta).",
)
@click.option(
    "--evidence-split", is_flag=True, help="Evidence: one Markdown file per finding."
)
@click.option(
    "--redact",
    "redact",
    type=click.Choice(["none", "partial", "full"]),
    default="none",
    show_default=True,
    help="Evidence: mask extracted secrets (none|partial|full).",
)
@click.option(
    "--snippet-width",
    type=int,
    default=80,
    show_default=True,
    metavar="COLS",
    help="Max width for match snippets in txt output.",
)
@click.option("-v", "--verbose", is_flag=True, help="Show parse warnings on stderr.")
@click.option("-q", "--quiet", is_flag=True, help="Suppress all status messages.")
def main(
    input_files,
    output_dir,
    name,
    fmt,
    input_format,
    split,
    severity,
    exclude_severity,
    fail_on,
    hostname,
    share,
    rule,
    ext,
    keyword,
    size_min,
    size_max,
    date_after,
    date_before,
    no_dedup,
    strict,
    unescape,
    sort_by,
    catalog_path,
    min_score,
    tier,
    triage_path,
    suppress_path,
    delta_path,
    delta_only,
    evidence_split,
    redact,
    snippet_width,
    verbose,
    quiet,
):
    """Parse, filter, sort, and export Snaffler output.

    \b
    Reads Snaffler TSV (-y flag) and JSON (-t JSON flag) output.
    Deduplicates, filters, sorts, and exports to text, CSV,
    static HTML, or a self-contained interactive HTML report.

    \b
    INPUT_FILE is a Snaffler output file (.tsv or .json).
    The input format is auto-detected unless --input-format is set.
    """
    from datetime import datetime, timezone
    from snafflemap.exporters import (
        csv_export,
        evidence,
        html,
        jsonl,
        report,
        txt,
        export_split,
    )

    out_dir = Path(output_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    fail_on_levels = None
    if fail_on:
        try:
            fail_on_levels = {
                Severity.from_string(s.strip()) for s in fail_on.split(",")
            }
        except ValueError as exc:
            click.echo(f"Error: invalid --fail-on severity: {exc}", err=True)
            sys.exit(1)

    if delta_only and not delta_path:
        click.echo("Error: --delta-only requires --delta", err=True)
        sys.exit(1)

    from snafflemap.analysis.catalog import CatalogError, builtin_catalog, load_catalog

    _VALID_TIERS = {"Critical", "High", "Medium", "Low"}
    tiers = None
    if tier:
        tiers = {t.strip().capitalize() for t in tier.split(",")}
        invalid = tiers - _VALID_TIERS
        if invalid:
            click.echo(
                f"Error: invalid --tier value(s): {', '.join(sorted(invalid))}",
                err=True,
            )
            sys.exit(1)

    try:
        catalog = load_catalog(catalog_path) if catalog_path else builtin_catalog()
    except CatalogError as exc:
        click.echo(f"Error: invalid catalog: {exc}", err=True)
        sys.exit(1)

    from snafflemap.triage import TriageError, load_sidecar, merge_sidecars

    triage_seed = {}
    suppressions = []
    try:
        if triage_path:
            sc = load_sidecar(triage_path)
            triage_seed = sc.get("triage", {})
            suppressions = sc.get("suppressions", [])
        if suppress_path:
            ssc = load_sidecar(suppress_path)
            # union suppressions; suppress file's triage is ignored
            merged = (
                merge_sidecars(
                    {
                        "schema": sc.get("schema")
                        if triage_path
                        else "snafflemap-triage/1",
                        "triage": {},
                        "suppressions": suppressions,
                    },
                    {
                        "schema": ssc.get("schema"),
                        "triage": {},
                        "suppressions": ssc.get("suppressions", []),
                    },
                )
                if triage_path
                else ssc
            )
            suppressions = merged.get("suppressions", ssc.get("suppressions", []))
    except TriageError as exc:
        click.echo(f"Error: invalid triage file: {exc}", err=True)
        sys.exit(1)

    from snafflemap.parsers import merge

    if not input_files:
        click.echo("Error: at least one INPUT_FILE is required.", err=True)
        sys.exit(1)

    parsed: list = []
    for input_file in input_files:
        _echo(f"Parsing {input_file}...", quiet, err=True)
        try:
            rs = parse(
                input_file, format=input_format, strict=strict, unescape=unescape
            )
        except ParseError as exc:
            click.echo(f"Error: {exc}", err=True)
            sys.exit(1)
        if verbose and not quiet and rs.warnings:
            for w in rs.warnings:
                click.echo(f"  Warning: {w}", err=True)
        parsed.append(rs)

    result_set = merge(parsed, dedup=not no_dedup)

    chain = FilterChain()
    if severity:
        levels = [Severity.from_string(s.strip()) for s in severity.split(",")]
        chain = chain.severity(*levels)
    if exclude_severity:
        levels = [Severity.from_string(s.strip()) for s in exclude_severity.split(",")]
        chain = chain.exclude_severity(*levels)
    if hostname:
        chain = chain.hostname(hostname)
    if share:
        chain = chain.share(share)
    if rule:
        chain = chain.rule(rule)
    if ext:
        exts = [e.strip() for e in ext.split(",")]
        chain = chain.extension(*exts)
    if keyword:
        chain = chain.keyword(keyword)
    if size_min or size_max:
        try:
            min_val = _parse_size(size_min) if size_min else None
            max_val = _parse_size(size_max) if size_max else None
        except ValueError:
            click.echo(
                "Error: --size-min/--size-max must be a number with optional K/M/G suffix (e.g. 1M, 500K)",
                err=True,
            )
            sys.exit(1)
        chain = chain.size(min=min_val, max=max_val)
    if date_after or date_before:
        try:
            after_dt = (
                datetime.fromisoformat(date_after).replace(tzinfo=timezone.utc)
                if date_after
                else None
            )
            before_dt = (
                datetime.fromisoformat(date_before).replace(tzinfo=timezone.utc)
                if date_before
                else None
            )
        except ValueError:
            click.echo(
                "Error: --date-after/--date-before must be ISO 8601 format (e.g. 2024-01-01)",
                err=True,
            )
            sys.exit(1)
        chain = chain.date(after=after_dt, before=before_dt)
    result_set = chain.apply(result_set)

    from snafflemap.analysis.enrich import enrich, filter_by_score

    enrichment = enrich(result_set, catalog)
    if min_score is not None or tiers is not None:
        result_set = filter_by_score(
            result_set, enrichment, min_score=min_score, tiers=tiers
        )

    sort_keys = [k.strip() for k in sort_by.split(",")]
    result_set = apply_sort(result_set, sort_keys, enrichment=enrichment)

    delta_map = None
    resolved = []
    if delta_path:
        from snafflemap.delta import compute_delta, load_baseline

        baseline = load_baseline(delta_path)
        delta_map, resolved = compute_delta(result_set, enrichment, baseline)
        counts = {"new": 0, "persisted": 0, "escalated": 0}
        for status in delta_map.values():
            counts[status] = counts.get(status, 0) + 1
        _echo(
            f"Delta: +{counts['new']} new · {counts['persisted']} persisted · "
            f"{counts['escalated']} escalated · {len(resolved)} resolved",
            quiet,
            err=True,
        )
        if delta_only:
            if delta_only == "resolved":
                result_set = ResultSet(
                    files=[], shares=[], dirs=[], warnings=result_set.warnings
                )
            else:
                keep = {fid for fid, st in delta_map.items() if st == delta_only}
                result_set = ResultSet(
                    files=[f for f in result_set.files if f.finding_id in keep],
                    shares=[s for s in result_set.shares if s.finding_id in keep],
                    dirs=[d for d in result_set.dirs if d.finding_id in keep],
                    warnings=result_set.warnings,
                )

    if not quiet:
        counts = result_set.severity_counts
        _echo(f"\nResults: {result_set.total_findings} findings", quiet, err=True)
        for sev in Severity:
            c = counts.get(sev, 0)
            if c > 0:
                color_map = {
                    "Black": "magenta",
                    "Red": "red",
                    "Yellow": "yellow",
                    "Green": "green",
                    "Gray": "white",
                }
                label = click.style(sev.value, fg=color_map.get(sev.value, "white"))
                click.echo(f"  {label}: {c}", err=True)

    input_stem = name if name else Path(input_files[0]).stem
    formats = ["txt", "csv", "html", "report", "jsonl"] if fmt == "all" else [fmt]

    if snippet_width != 80 and "txt" not in formats:
        _echo("Warning: --snippet-width only affects txt output", quiet, err=True)

    for export_fmt in formats:
        if split and export_fmt in ("report", "evidence"):
            _echo(
                f"Warning: --split is not supported for {export_fmt} format, ignoring",
                quiet,
                err=True,
            )
        if split and export_fmt not in ("report", "evidence"):
            suffix_map = {"txt": ".txt", "csv": ".csv", "html": ".html"}
            base = out_dir / f"{input_stem}{suffix_map[export_fmt]}"
            kwargs = {}
            if export_fmt == "txt":
                kwargs["snippet_width"] = snippet_width
            created = export_split(result_set, str(base), export_fmt, **kwargs)
            for p in created:
                _echo(f"  Written: {p}", quiet, err=True)
        else:
            match export_fmt:
                case "txt":
                    out = out_dir / f"{input_stem}.txt"
                    txt.export(result_set, str(out), snippet_width=snippet_width)
                case "csv":
                    out = out_dir / f"{input_stem}.csv"
                    csv_export.export(result_set, str(out))
                case "html":
                    out = out_dir / f"{input_stem}.html"
                    html.export(result_set, str(out))
                case "report":
                    out = out_dir / f"{input_stem}-report.html"
                    report.export(
                        result_set,
                        str(out),
                        enrichment=enrichment,
                        triage=triage_seed,
                        suppressions=suppressions,
                        report_name=input_stem,
                        delta=delta_map,
                        resolved=resolved,
                    )
                case "jsonl":
                    out = out_dir / f"{input_stem}.jsonl"
                    jsonl.export(
                        result_set,
                        str(out),
                        enrichment=enrichment,
                        delta=delta_map,
                        resolved=resolved,
                    )
                case "evidence":
                    out = out_dir / f"{input_stem}.md"
                    evidence.export(
                        result_set,
                        str(out),
                        enrichment=enrichment,
                        redact=redact,
                        split=evidence_split,
                    )
            _echo(f"  Written: {out}", quiet, err=True)

    if fail_on_levels:
        tripped = any(
            r.severity in fail_on_levels
            for r in (*result_set.files, *result_set.shares, *result_set.dirs)
        )
        if tripped:
            _echo(
                f"--fail-on: findings at {', '.join(sorted(g.value for g in fail_on_levels))} present",
                quiet,
                err=True,
            )
            sys.exit(2)
