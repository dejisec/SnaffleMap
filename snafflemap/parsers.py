"""Parsers for SnaffleMap: TSV and JSON Snaffler output formats."""

from __future__ import annotations

import dataclasses
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Generator

from snafflemap.models import DirResult, FileResult, ResultSet, Severity, ShareResult


class ParseError(Exception):
    """Raised in strict mode when a line or entry cannot be parsed."""

    def __init__(self, message: str, line_number: int | None = None) -> None:
        super().__init__(message)
        self.line_number = line_number


def _unescape_match_context(text: str) -> str:
    """Unescape Snaffler's backslash-escaped match context.

    Snaffler escapes all special characters in match context: ``\\ `` → space,
    ``\\n`` → newline, ``\\t`` → tab, ``\\\\`` → backslash, ``\\$`` → ``$``,
    etc.  Any ``\\X`` is replaced with the literal character ``X``, with
    special handling for ``\\n``, ``\\r``, and ``\\t``.
    """
    result: list[str] = []
    i = 0
    while i < len(text):
        if text[i] == "\\" and i + 1 < len(text):
            nxt = text[i + 1]
            if nxt == "n":
                result.append("\n")
            elif nxt == "r":
                result.append("\r")
            elif nxt == "t":
                result.append("\t")
            else:
                result.append(nxt)
            i += 2
        else:
            result.append(text[i])
            i += 1
    return "".join(result)


_DATE_FORMATS = (
    "%Y-%m-%dT%H:%M:%SZ",
    "%Y-%m-%d %H:%M:%SZ",
    "%Y-%m-%dT%H:%M:%S",
    "%Y-%m-%d %H:%M:%S",
    "%Y-%m-%dT%H:%M:%S.%fZ",
    "%Y-%m-%dT%H:%M:%S.%f",
)


def _parse_date(raw: str) -> datetime:
    """Parse a date string into a UTC-aware datetime."""
    raw = raw.strip()
    # .NET timestamps can have 7-digit fractional seconds; Python %f only
    # supports 6 digits.  Truncate to 6 if longer.
    import re as _re

    raw = _re.sub(r"(\.\d{6})\d+", r"\1", raw)
    # Python's %z handles 'Z' only in 3.11+; handle it manually for portability.
    for fmt in _DATE_FORMATS:
        try:
            dt = datetime.strptime(raw, fmt)
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            return dt
        except ValueError:
            continue
    # Last resort: try datetime.fromisoformat (handles +HH:MM offsets in Python 3.7+)
    try:
        dt = datetime.fromisoformat(raw)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt
    except ValueError:
        pass
    raise ValueError(f"Cannot parse date: {raw!r}")


def _parse_tsv_line(
    raw_line: str,
    line_number: int,
    unescape: bool,
) -> FileResult | ShareResult | DirResult | None:
    """Parse one TSV line and return the appropriate result object.

    Returns None for blank lines and log lines ([Info], [Error]).
    Raises ValueError with a description if the line is malformed.
    """
    line = raw_line.rstrip("\n\r")
    if not line.strip():
        return None

    fields = line.split("\t")
    n = len(fields)

    # Lines with fewer than 3 tab-separated fields are not Snaffler results
    # (status update continuation lines, trailing "Done.", etc.) — skip silently.
    if n < 3:
        return None

    type_marker = fields[2].strip()

    if type_marker in ("[Info]", "[Error]"):
        return None

    if type_marker == "[File]":
        if n < 12:
            raise ValueError(f"File result needs 12+ fields, got {n}")
        severity = Severity.from_string(fields[3])
        rule_name = fields[4]
        can_read = fields[5].strip().upper() == "R"
        can_write = fields[6].strip().upper() == "W"
        can_modify = fields[7].strip().upper() == "M"
        matched_string = fields[8]
        file_size = int(fields[9])
        modified_date = _parse_date(fields[10])
        file_path = fields[11]
        alt_filename = fields[12] if n > 12 and fields[12] else None
        match_context = fields[13] if n > 13 else ""
        if unescape:
            match_context = _unescape_match_context(match_context)
        return FileResult(
            severity=severity,
            rule_name=rule_name,
            can_read=can_read,
            can_write=can_write,
            can_modify=can_modify,
            matched_string=matched_string,
            file_size=file_size,
            modified_date=modified_date,
            file_path=file_path,
            alt_filename=alt_filename,
            match_context=match_context,
            source_line=line_number,
        )

    elif type_marker == "[Share]":
        if n < 5:
            raise ValueError(f"Share result needs 5+ fields, got {n}")
        severity = Severity.from_string(fields[3])
        share_path = fields[4]
        perms = fields[5].upper() if n > 5 else ""
        can_read = "R" in perms
        can_write = "W" in perms
        can_modify = "M" in perms
        return ShareResult(
            severity=severity,
            share_path=share_path,
            can_read=can_read,
            can_write=can_write,
            can_modify=can_modify,
            source_line=line_number,
        )

    elif type_marker == "[Dir]":
        if n < 5:
            raise ValueError(f"Dir result needs 5 fields, got {n}")
        severity = Severity.from_string(fields[3])
        dir_path = fields[4]
        return DirResult(
            severity=severity,
            dir_path=dir_path,
            source_line=line_number,
        )

    else:
        # Unknown type marker — skip silently (could be [Trace], [Debug], etc.)
        return None


def parse_tsv(
    path: Path | str,
    *,
    strict: bool = False,
    unescape: bool = False,
) -> ResultSet:
    """Parse a Snaffler TSV file and return a ResultSet.

    Parameters
    ----------
    path:
        Path to the TSV file.
    strict:
        If True, raise ParseError on the first malformed line.
        If False (default), skip malformed lines and collect warnings.
    unescape:
        If True, run _unescape_match_context on match_context fields.
    """
    path = Path(path)
    files: list[FileResult] = []
    shares: list[ShareResult] = []
    dirs: list[DirResult] = []
    parse_warnings: list[str] = []

    with path.open(encoding="utf-8-sig", errors="replace") as fh:
        for line_number, raw_line in enumerate(fh, start=1):
            try:
                result = _parse_tsv_line(raw_line, line_number, unescape)
                if result is None:
                    continue
                if isinstance(result, FileResult):
                    files.append(result)
                elif isinstance(result, ShareResult):
                    shares.append(result)
                elif isinstance(result, DirResult):
                    dirs.append(result)
            except (ValueError, IndexError) as exc:
                if strict:
                    raise ParseError(
                        f"Line {line_number}: {exc}", line_number=line_number
                    ) from exc
                parse_warnings.append(f"Line {line_number}: {exc}")

    src = (path.name,)
    return ResultSet(
        files=[dataclasses.replace(f, sources=src) for f in files],
        shares=[dataclasses.replace(s, sources=src) for s in shares],
        dirs=[dataclasses.replace(d, sources=src) for d in dirs],
        warnings=parse_warnings if parse_warnings else None,
    )


def _parse_json_entry(
    entry: dict,
    index: int,
    unescape: bool,
) -> FileResult | ShareResult | DirResult | None:
    """Convert one JSON entry dict to a result object or None."""
    event = entry.get("eventProperties", {})
    if not event:
        return None

    # Real Snaffler format: severity key -> {Type, DateTime, ResultType: {...}}
    # Unwrap if we find a dict value with a "Type" key.
    if (
        "FileResult" not in event
        and "ShareResult" not in event
        and "DirResult" not in event
    ):
        for _key, val in event.items():
            if isinstance(val, dict) and "Type" in val:
                result_type = val["Type"]
                if result_type in val:
                    event = {result_type: val[result_type]}
                break

    if "FileResult" in event:
        fr = event["FileResult"]
        rule = fr.get("MatchedRule", {})
        severity = Severity.from_string(rule.get("Triage", "Gray"))
        rule_name = rule.get("RuleName", "")

        rw = fr.get("RwStatus", {})
        can_read = bool(rw.get("CanRead", False))
        can_write = bool(rw.get("CanWrite", False))
        can_modify = bool(rw.get("CanModify", False))

        text = fr.get("TextResult", {})
        matched_strings = text.get("MatchedStrings", [])
        matched_string = matched_strings[0] if matched_strings else ""
        match_context = text.get("MatchContext", "")
        if unescape:
            match_context = _unescape_match_context(match_context)

        info = fr.get("FileInfo", {})
        file_size = int(info.get("Length", 0))
        modified_date = _parse_date(info.get("LastWriteTime", "1970-01-01T00:00:00Z"))
        file_path = info.get("FullName", "")

        alt_info = fr.get("AlternativeFileInfo", {})
        alt_raw = alt_info.get("AlternativeFullFileName") if alt_info else None
        alt_filename = alt_raw if alt_raw else None

        return FileResult(
            severity=severity,
            rule_name=rule_name,
            can_read=can_read,
            can_write=can_write,
            can_modify=can_modify,
            matched_string=matched_string,
            file_size=file_size,
            modified_date=modified_date,
            file_path=file_path,
            alt_filename=alt_filename,
            match_context=match_context,
            source_line=index,
        )

    elif "ShareResult" in event:
        sr = event["ShareResult"]
        severity = Severity.from_string(sr.get("Triage", "Gray"))
        share_path = sr.get("SharePath", "")
        can_read = bool(sr.get("RootReadable", False))
        can_write = bool(sr.get("RootWritable", False))
        can_modify = bool(sr.get("RootModifyable", False))
        return ShareResult(
            severity=severity,
            share_path=share_path,
            can_read=can_read,
            can_write=can_write,
            can_modify=can_modify,
            source_line=index,
        )

    elif "DirResult" in event:
        dr = event["DirResult"]
        severity = Severity.from_string(dr.get("Triage", "Gray"))
        dir_path = dr.get("DirPath", "")
        return DirResult(
            severity=severity,
            dir_path=dir_path,
            source_line=index,
        )

    return None


def parse_json(
    path: Path | str,
    *,
    strict: bool = False,
    unescape: bool = False,
) -> ResultSet:
    """Parse a Snaffler JSON file and return a ResultSet.

    Parameters
    ----------
    path:
        Path to the JSON file with {"entries": [...]} structure.
    strict:
        If True, raise ParseError on malformed entries.
        If False (default), skip bad entries and collect warnings.
    unescape:
        If True, unescape match_context fields.
    """
    path = Path(path)
    files: list[FileResult] = []
    shares: list[ShareResult] = []
    dirs: list[DirResult] = []
    parse_warnings: list[str] = []

    with path.open(encoding="utf-8-sig", errors="replace") as fh:
        data = json.load(fh)

    # Support bare array, {"entries": [...]}, or any single-list-valued wrapper
    if isinstance(data, list):
        entries = data
    elif isinstance(data, dict):
        entries = data.get("entries")
        if entries is None:
            for v in data.values():
                if isinstance(v, list):
                    entries = v
                    break
        if entries is None:
            entries = []
    else:
        entries = []

    for index, entry in enumerate(entries, start=1):
        try:
            result = _parse_json_entry(entry, index, unescape)
            if result is None:
                continue
            if isinstance(result, FileResult):
                files.append(result)
            elif isinstance(result, ShareResult):
                shares.append(result)
            elif isinstance(result, DirResult):
                dirs.append(result)
        except (ValueError, KeyError, TypeError, IndexError) as exc:
            if strict:
                raise ParseError(f"Entry {index}: {exc}", line_number=index) from exc
            parse_warnings.append(f"Entry {index}: {exc}")

    total = len(files) + len(shares) + len(dirs)
    if total == 0:
        parse_warnings.append("No results parsed from JSON file.")

    src = (path.name,)
    return ResultSet(
        files=[dataclasses.replace(f, sources=src) for f in files],
        shares=[dataclasses.replace(s, sources=src) for s in shares],
        dirs=[dataclasses.replace(d, sources=src) for d in dirs],
        warnings=parse_warnings if parse_warnings else None,
    )


def parse_jsonl(
    path: Path | str,
    *,
    strict: bool = False,
    unescape: bool = False,
) -> ResultSet:
    """Parse a SnaffleMap JSONL file (one finding object per line)."""
    path = Path(path)
    files: list[FileResult] = []
    shares: list[ShareResult] = []
    dirs: list[DirResult] = []
    parse_warnings: list[str] = []

    with path.open(encoding="utf-8-sig", errors="replace") as fh:
        for line_number, raw in enumerate(fh, start=1):
            raw = raw.strip()
            if not raw:
                continue
            try:
                rec = json.loads(raw)
                rtype = rec.get("type")
                src = tuple(rec.get("sources", []) or ())
                if rtype == "file":
                    ctx = rec.get("match_context", "")
                    if unescape:
                        ctx = _unescape_match_context(ctx)
                    files.append(
                        FileResult(
                            severity=Severity.from_string(rec["severity"]),
                            rule_name=rec.get("rule_name", ""),
                            can_read=bool(rec.get("can_read", False)),
                            can_write=bool(rec.get("can_write", False)),
                            can_modify=bool(rec.get("can_modify", False)),
                            matched_string=rec.get("matched_string", ""),
                            file_size=int(rec.get("file_size", 0)),
                            modified_date=_parse_date(
                                rec.get("modified_date", "1970-01-01T00:00:00Z")
                            ),
                            file_path=rec.get("file_path", ""),
                            alt_filename=rec.get("alt_filename"),
                            match_context=ctx,
                            source_line=rec.get("source_line"),
                            sources=src,
                        )
                    )
                elif rtype == "share":
                    shares.append(
                        ShareResult(
                            severity=Severity.from_string(rec["severity"]),
                            share_path=rec.get("share_path", ""),
                            can_read=bool(rec.get("can_read", False)),
                            can_write=bool(rec.get("can_write", False)),
                            can_modify=bool(rec.get("can_modify", False)),
                            source_line=rec.get("source_line"),
                            sources=src,
                        )
                    )
                elif rtype == "dir":
                    dirs.append(
                        DirResult(
                            severity=Severity.from_string(rec["severity"]),
                            dir_path=rec.get("dir_path", ""),
                            source_line=rec.get("source_line"),
                            sources=src,
                        )
                    )
            except (ValueError, KeyError, TypeError) as exc:
                if strict:
                    raise ParseError(
                        f"Line {line_number}: {exc}", line_number=line_number
                    ) from exc
                parse_warnings.append(f"Line {line_number}: {exc}")

    return ResultSet(
        files=files,
        shares=shares,
        dirs=dirs,
        warnings=parse_warnings if parse_warnings else None,
    )


def detect_format(path: Path | str) -> str:
    """Return "json" or "tsv" based on file extension and content sniffing.

    Resolution order:
    1. If the file extension is .json → "json"
    2. If the first non-empty line contains a tab → "tsv" (Snaffler TSV
       always has tab-separated fields; JSON never has raw tabs)
    3. If the first non-empty line starts with ``{`` or ``[`` → "json"
    4. Otherwise → "tsv"
    """
    path = Path(path)
    if path.suffix.lower() == ".jsonl":
        return "jsonl"
    if path.suffix.lower() == ".json":
        return "json"

    try:
        with path.open(encoding="utf-8-sig", errors="replace") as fh:
            for line in fh:
                stripped = line.strip()
                if stripped:
                    if "\t" in stripped:
                        return "tsv"
                    if stripped[0] in ("{", "["):
                        return "json"
                    break
    except (OSError, UnicodeDecodeError):
        pass

    return "tsv"


def parse(
    path: Path | str,
    *,
    format: str | None = None,
    strict: bool = False,
    unescape: bool = False,
) -> ResultSet:
    """Parse a Snaffler output file, auto-detecting or using the given format.

    Parameters
    ----------
    path:
        Path to the file to parse.
    format:
        Force "tsv" or "json".  If None, auto-detect via detect_format().
    strict:
        Propagated to the underlying parser.
    unescape:
        Propagated to the underlying parser.
    """
    fmt = format if format is not None else detect_format(path)
    if fmt == "jsonl":
        return parse_jsonl(path, strict=strict, unescape=unescape)
    if fmt == "json":
        return parse_json(path, strict=strict, unescape=unescape)
    return parse_tsv(path, strict=strict, unescape=unescape)


def parse_iter(
    path: Path | str,
    *,
    format: str | None = None,
    strict: bool = False,
    unescape: bool = False,
) -> Generator[FileResult | ShareResult | DirResult, None, None]:
    """Yield individual results from a Snaffler output file.

    For TSV files this is truly streaming (line-by-line).
    For JSON files the whole document is loaded, then results are yielded.
    """
    path = Path(path)
    fmt = format if format is not None else detect_format(path)

    if fmt == "json":
        rs = parse_json(path, strict=strict, unescape=unescape)
        yield from rs.files
        yield from rs.shares
        yield from rs.dirs
        return

    with path.open(encoding="utf-8-sig", errors="replace") as fh:
        for line_number, raw_line in enumerate(fh, start=1):
            try:
                result = _parse_tsv_line(raw_line, line_number, unescape)
                if result is not None:
                    yield result
            except (ValueError, IndexError):
                if strict:
                    raise ParseError(
                        f"Line {line_number}: malformed", line_number=line_number
                    )
                pass


def _dedup_by_id(items: list) -> list:
    """Collapse items sharing a finding_id: keep highest severity, union sources.

    Preserves first-appearance order.
    """
    best: dict[str, object] = {}
    sources: dict[str, set[str]] = {}
    order: list[str] = []
    for it in items:
        fid = it.finding_id
        if fid not in best:
            best[fid] = it
            sources[fid] = set(it.sources)
            order.append(fid)
        else:
            sources[fid].update(it.sources)
            if it.severity.sort_key < best[fid].severity.sort_key:
                best[fid] = it
    return [
        dataclasses.replace(best[fid], sources=tuple(sorted(sources[fid])))
        for fid in order
    ]


def deduplicate(result_set: ResultSet) -> ResultSet:
    """Return a new ResultSet with duplicate FileResults collapsed by finding_id.

    Files sharing a finding_id (same path + rule + matched string) collapse to the
    highest-severity instance, unioning their sources. ShareResults and DirResults
    pass through unchanged.
    """
    return ResultSet(
        files=_dedup_by_id(result_set.files),
        shares=list(result_set.shares),
        dirs=list(result_set.dirs),
        warnings=result_set.warnings,
    )


def merge(result_sets: list[ResultSet], *, dedup: bool = True) -> ResultSet:
    """Concatenate multiple ResultSets into one.

    When dedup=True (default), findings of every type sharing a finding_id are
    collapsed to the highest-severity instance with their sources unioned.
    Warnings from all sets are concatenated.
    """
    files = [f for rs in result_sets for f in rs.files]
    shares = [s for rs in result_sets for s in rs.shares]
    dirs = [d for rs in result_sets for d in rs.dirs]
    warnings = [w for rs in result_sets for w in (rs.warnings or [])]
    if dedup:
        files = _dedup_by_id(files)
        shares = _dedup_by_id(shares)
        dirs = _dedup_by_id(dirs)
    return ResultSet(files=files, shares=shares, dirs=dirs, warnings=warnings or None)
