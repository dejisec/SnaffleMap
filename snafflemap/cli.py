from __future__ import annotations
import sys
from pathlib import Path
import click
from snafflemap.filters import FilterChain
from snafflemap.models import Severity
from snafflemap.parsers import ParseError, deduplicate, parse
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
@click.argument("input_file", type=click.Path(exists=True))
@click.option(
    "-o",
    "--output-dir",
    type=click.Path(),
    default=".",
    show_default=True,
    help="Directory for output files.",
)
@click.option(
    "-f",
    "--format",
    "fmt",
    type=click.Choice(["txt", "csv", "html", "report", "all"]),
    default="txt",
    show_default=True,
    help="Export format.",
)
@click.option(
    "--input-format",
    type=click.Choice(["tsv", "json"]),
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
    help="Comma-separated sort keys: severity, modified, path, rule, size.",
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
    input_file,
    output_dir,
    fmt,
    input_format,
    split,
    severity,
    exclude_severity,
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
    from snafflemap.exporters import csv_export, html, report, txt, export_split

    out_dir = Path(output_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    _echo(f"Parsing {input_file}...", quiet, err=True)
    try:
        result_set = parse(
            input_file, format=input_format, strict=strict, unescape=unescape
        )
    except ParseError as exc:
        click.echo(f"Error: {exc}", err=True)
        sys.exit(1)

    if verbose and not quiet and result_set.warnings:
        for w in result_set.warnings:
            click.echo(f"  Warning: {w}", err=True)

    if not no_dedup:
        result_set = deduplicate(result_set)

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

    sort_keys = [k.strip() for k in sort_by.split(",")]
    result_set = apply_sort(result_set, sort_keys)

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

    input_stem = Path(input_file).stem
    formats = ["txt", "csv", "html", "report"] if fmt == "all" else [fmt]

    if snippet_width != 80 and "txt" not in formats:
        _echo("Warning: --snippet-width only affects txt output", quiet, err=True)

    for export_fmt in formats:
        if split and export_fmt == "report":
            _echo(
                "Warning: --split is not supported for report format, ignoring",
                quiet,
                err=True,
            )
        if split and export_fmt != "report":
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
                    report.export(result_set, str(out))
            _echo(f"  Written: {out}", quiet, err=True)
