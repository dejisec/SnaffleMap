"""Run detectors against a finding to produce DetectorHits."""

from __future__ import annotations

import ntpath
import re

from snafflemap.analysis.models import Detector, DetectorHit


def _basename(path: str) -> str:
    # Snaffler paths are Windows UNC; use ntpath so backslashes split correctly.
    return ntpath.basename(path)


def _matches_any(patterns: tuple[str, ...], text: str) -> bool:
    return any(re.search(p, text, re.IGNORECASE) for p in patterns)


def _signal_fires(
    detector: Detector, *, basename: str, ext: str, path: str, rule_name: str
) -> bool:
    if detector.filename_patterns and _matches_any(
        detector.filename_patterns, basename
    ):
        return True
    if detector.ext and ext.lower() in {e.lower() for e in detector.ext}:
        return True
    if detector.path_patterns and _matches_any(detector.path_patterns, path):
        return True
    if detector.rule_names:
        rl = rule_name.lower()
        if any(rn.lower() in rl for rn in detector.rule_names):
            return True
    return False


def classify(finding, detectors) -> list[DetectorHit]:
    """Return the DetectorHits that fire for *finding*.

    A detector fires when at least one of its filename/ext/path/rule_name signals
    matches AND (it has no context_patterns, or at least one matches the finding's
    match_context + matched_string).
    """
    path = (
        getattr(finding, "file_path", None)
        or getattr(finding, "share_path", None)
        or getattr(finding, "dir_path", "")
    )
    basename = _basename(path)
    ext = getattr(finding, "extension", "") or ""
    rule_name = getattr(finding, "rule_name", "") or ""
    context_text = "{} {}".format(
        getattr(finding, "match_context", "") or "",
        getattr(finding, "matched_string", "") or "",
    )

    hits: list[DetectorHit] = []
    for d in detectors:
        if not _signal_fires(
            d, basename=basename, ext=ext, path=path, rule_name=rule_name
        ):
            continue
        if d.context_patterns and not _matches_any(d.context_patterns, context_text):
            continue
        hits.append(
            DetectorHit(
                id=d.id,
                label=d.label,
                category=d.category,
                why=d.why,
                action=d.action,
                crackable=d.crackable,
                weight=d.weight,
                remediation=d.remediation,
            )
        )
    return hits
