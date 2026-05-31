"""Orchestrate classification, extraction, and scoring into an Enrichment map."""

from __future__ import annotations

from datetime import datetime, timezone

from snafflemap.analysis.classify import classify
from snafflemap.analysis.credentials import extract_credentials
from snafflemap.analysis.models import Catalog, Enrichment
from snafflemap.analysis.score import score
from snafflemap.models import ResultSet


def enrich(
    result_set: ResultSet, catalog: Catalog, *, now: datetime | None = None
) -> dict[str, Enrichment]:
    """Return a dict of finding_id -> Enrichment for every finding in *result_set*."""
    if now is None:
        now = datetime.now(timezone.utc)

    out: dict[str, Enrichment] = {}
    for finding in (*result_set.files, *result_set.shares, *result_set.dirs):
        hits = classify(finding, catalog.detectors)
        creds = extract_credentials(finding, catalog.extractors)
        sc = score(finding, hits, creds, now=now)
        out[finding.finding_id] = Enrichment(
            finding_id=finding.finding_id,
            detectors=tuple(hits),
            credentials=tuple(creds),
            score=sc,
        )
    return out


def filter_by_score(
    result_set: ResultSet,
    enrichment: dict[str, Enrichment],
    *,
    min_score: int | None = None,
    tiers: set[str] | None = None,
) -> ResultSet:
    """Return a ResultSet keeping only findings that satisfy the score/tier gates."""

    def keep(finding) -> bool:
        e = enrichment.get(finding.finding_id)
        if e is None:
            return False
        if min_score is not None and e.score.value < min_score:
            return False
        if tiers is not None and e.score.tier not in tiers:
            return False
        return True

    return ResultSet(
        files=[f for f in result_set.files if keep(f)],
        shares=[s for s in result_set.shares if keep(s)],
        dirs=[d for d in result_set.dirs if keep(d)],
        warnings=result_set.warnings,
    )
