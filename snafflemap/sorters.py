"""Sorters for SnaffleMap result sets.

Public API
----------
apply_sort(result_set, keys) -> ResultSet
    Sort the files, shares, and dirs lists in *result_set* independently,
    using *keys* as an ordered list of sort criteria (first = primary).
"""

from __future__ import annotations

from snafflemap.models import ResultSet


def _file_key_for(key: str):
    """Return a single-attribute key function for a FileResult."""
    match key:
        case "severity":
            return lambda f: f.severity.sort_key
        case "modified":
            return lambda f: f.modified_date
        case "path":
            return lambda f: f.file_path.lower()
        case "rule":
            return lambda f: f.rule_name.lower()
        case "size":
            return lambda f: f.file_size
        case _:
            return None


def _share_key_for(key: str):
    """Return a single-attribute key function for a ShareResult, or None."""
    match key:
        case "severity":
            return lambda s: s.severity.sort_key
        case "path":
            return lambda s: s.share_path.lower()
        case _:
            return None


def _dir_key_for(key: str):
    """Return a single-attribute key function for a DirResult, or None."""
    match key:
        case "severity":
            return lambda d: d.severity.sort_key
        case "path":
            return lambda d: d.dir_path.lower()
        case _:
            return None


def _build_file_key(keys: list[str]):
    """Build a tuple key function for FileResult from a list of key names."""
    extractors = [_file_key_for(k) for k in keys if _file_key_for(k) is not None]
    if not extractors:
        # No valid keys — return a constant so sort is a stable no-op
        return lambda f: ()
    return lambda f: tuple(fn(f) for fn in extractors)


def _build_share_key(keys: list[str]):
    """Build a tuple key function for ShareResult.

    Unknown keys are ignored.  If none of the supplied keys are valid the
    fallback is (severity, path).
    """
    extractors = [_share_key_for(k) for k in keys if _share_key_for(k) is not None]
    if not extractors:
        # Fallback: severity then path
        extractors = [lambda s: s.severity.sort_key, lambda s: s.share_path.lower()]
    return lambda s: tuple(fn(s) for fn in extractors)


def _build_dir_key(keys: list[str]):
    """Build a tuple key function for DirResult.

    Unknown keys are ignored.  If none of the supplied keys are valid the
    fallback is (severity, path).
    """
    extractors = [_dir_key_for(k) for k in keys if _dir_key_for(k) is not None]
    if not extractors:
        # Fallback: severity then path
        extractors = [lambda d: d.severity.sort_key, lambda d: d.dir_path.lower()]
    return lambda d: tuple(fn(d) for fn in extractors)


def _score_key(enrichment):
    """Return a key fn that sorts by descending enrichment score (highest first)."""
    if not enrichment:
        return lambda r: 0

    def key(r):
        e = enrichment.get(r.finding_id)
        return -(e.score.value if e is not None else 0)

    return key


def apply_sort(result_set: ResultSet, keys: list[str], enrichment=None) -> ResultSet:
    """Return a new ResultSet with each list independently sorted by *keys*.

    Supported keys: "severity", "modified", "path", "rule", "size" (files), plus
    "score" (all types) when *enrichment* (finding_id -> Enrichment) is supplied.
    Unknown keys are ignored. "score" sorts highest-first.
    """

    def build(base_builder, keys_):
        score_in = "score" in keys_
        non_score = [k for k in keys_ if k != "score"]
        base = base_builder(non_score)
        if not score_in:
            return base
        skey = _score_key(enrichment)
        # score is applied as the PRIMARY key (listed first), base keys break ties
        return lambda r: (skey(r), base(r))

    sorted_files = sorted(result_set.files, key=build(_build_file_key, keys))
    sorted_shares = sorted(result_set.shares, key=build(_build_share_key, keys))
    sorted_dirs = sorted(result_set.dirs, key=build(_build_dir_key, keys))

    return ResultSet(
        files=sorted_files,
        shares=sorted_shares,
        dirs=sorted_dirs,
        warnings=result_set.warnings,
    )
