"""FilterChain: composable, chainable filters for SnaffleMap ResultSets."""

from __future__ import annotations

import fnmatch
import re
from datetime import datetime
from typing import Callable

from snafflemap.models import DirResult, FileResult, ResultSet, Severity, ShareResult

# Type aliases
_Predicate = Callable[[object], bool]
_AppliesTo = frozenset[type]

_ALL_TYPES: _AppliesTo = frozenset({FileResult, ShareResult, DirResult})
_FILE_SHARE: _AppliesTo = frozenset({FileResult, ShareResult})
_FILE_ONLY: _AppliesTo = frozenset({FileResult})


class FilterChain:
    """Composable filter chain for ResultSet objects.

    Each method appends a ``(predicate, applies_to)`` pair to an internal list.
    ``.apply()`` evaluates all predicates against each result using AND logic.
    Predicates whose ``applies_to`` set does not include the result type are
    skipped — that type passes through unfiltered for that predicate.
    """

    def __init__(self) -> None:
        self._filters: list[tuple[_Predicate, _AppliesTo]] = []

    # ------------------------------------------------------------------
    # Internal helper
    # ------------------------------------------------------------------

    def _add(self, predicate: _Predicate, applies_to: _AppliesTo) -> "FilterChain":
        self._filters.append((predicate, applies_to))
        return self

    # ------------------------------------------------------------------
    # Filter methods
    # ------------------------------------------------------------------

    def severity(self, *levels: Severity) -> "FilterChain":
        """Keep only results whose severity is one of *levels*. Applies to all types."""
        level_set = frozenset(levels)
        return self._add(lambda r: r.severity in level_set, _ALL_TYPES)

    def exclude_severity(self, *levels: Severity) -> "FilterChain":
        """Remove results whose severity is one of *levels*. Applies to all types."""
        level_set = frozenset(levels)
        return self._add(lambda r: r.severity not in level_set, _ALL_TYPES)

    def hostname(self, pattern: str) -> "FilterChain":
        """Filter by hostname.

        If *pattern* is wrapped in ``/…/`` treat as a case-insensitive regex;
        otherwise use glob matching (case-sensitive, via :func:`fnmatch.fnmatch`).
        Applies to all types.
        """
        if pattern.startswith("/") and pattern.endswith("/") and len(pattern) >= 2:
            regex_pat = pattern[1:-1]
            compiled = re.compile(regex_pat, re.IGNORECASE)

            def pred(r: object) -> bool:
                return bool(compiled.search(r.hostname))
        else:
            _p = pattern

            def pred(r: object, p: str = _p) -> bool:
                return fnmatch.fnmatch(r.hostname, p)

        return self._add(pred, _ALL_TYPES)

    def share(self, name: str) -> "FilterChain":
        """Keep results whose share_name contains *name* (case-insensitive).

        Applies to FileResult and ShareResult only; DirResult passes through.
        """
        lower = name.lower()
        return self._add(lambda r: lower in r.share_name.lower(), _FILE_SHARE)

    def rule(self, name: str) -> "FilterChain":
        """Keep FileResults whose rule_name contains *name* (case-insensitive).

        Applies to FileResult only.
        """
        lower = name.lower()
        return self._add(lambda r: lower in r.rule_name.lower(), _FILE_ONLY)

    def extension(self, *exts: str) -> "FilterChain":
        """Keep FileResults whose extension matches one of *exts*.

        Leading dot is added automatically if missing (``bat`` → ``.bat``).
        Applies to FileResult only.
        """
        normalised = frozenset(e if e.startswith(".") else f".{e}" for e in exts)
        return self._add(lambda r: r.extension in normalised, _FILE_ONLY)

    def keyword(self, text: str) -> "FilterChain":
        """Keep FileResults where *text* appears (case-insensitive) in either
        ``match_context`` or ``matched_string``. Applies to FileResult only.
        """
        lower = text.lower()
        return self._add(
            lambda r: (
                lower in r.match_context.lower() or lower in r.matched_string.lower()
            ),
            _FILE_ONLY,
        )

    def size(self, min: int | None = None, max: int | None = None) -> "FilterChain":
        """Keep FileResults whose file_size is within [*min*, *max*] (inclusive).

        Pass ``None`` to leave a bound open. Applies to FileResult only.
        """

        def _size_pred(r: object, _min=min, _max=max) -> bool:
            sz = r.file_size  # type: ignore[attr-defined]
            if _min is not None and sz < _min:
                return False
            if _max is not None and sz > _max:
                return False
            return True

        return self._add(_size_pred, _FILE_ONLY)

    def date(
        self,
        after: datetime | None = None,
        before: datetime | None = None,
    ) -> "FilterChain":
        """Keep FileResults whose modified_date falls in [*after*, *before*] (inclusive).

        Pass ``None`` to leave a bound open. Applies to FileResult only.
        """

        def _date_pred(r: object, _after=after, _before=before) -> bool:
            dt = r.modified_date  # type: ignore[attr-defined]
            if _after is not None and dt < _after:
                return False
            if _before is not None and dt > _before:
                return False
            return True

        return self._add(_date_pred, _FILE_ONLY)

    # ------------------------------------------------------------------
    # Apply
    # ------------------------------------------------------------------

    def apply(self, data: ResultSet) -> ResultSet:
        """Run all filters against *data* and return a new ResultSet.

        For each result, every predicate whose ``applies_to`` set contains
        ``type(result)`` is evaluated. The result is kept only if **all**
        applicable predicates return ``True`` (AND logic). Predicates that
        do not apply to a type are skipped — that type is unaffected by those
        predicates.

        The original *data* is never mutated.
        """

        def _keep(result: object) -> bool:
            t = type(result)
            for pred, applies_to in self._filters:
                if t in applies_to:
                    if not pred(result):
                        return False
            return True

        return ResultSet(
            files=[f for f in data.files if _keep(f)],
            shares=[s for s in data.shares if _keep(s)],
            dirs=[d for d in data.dirs if _keep(d)],
            warnings=data.warnings,
        )
