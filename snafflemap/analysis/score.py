"""Compute an exploitability score for a finding + its enrichment."""

from __future__ import annotations

from datetime import datetime, timezone

from snafflemap.analysis.models import Score
from snafflemap.models import Severity

_SEVERITY_POINTS = {
    Severity.BLACK: 40,
    Severity.RED: 28,
    Severity.YELLOW: 16,
    Severity.GREEN: 6,
    Severity.GRAY: 0,
}


def _tier(value: int) -> str:
    if value >= 75:
        return "Critical"
    if value >= 50:
        return "High"
    if value >= 25:
        return "Medium"
    return "Low"


def score(finding, hits, creds, *, now: datetime | None = None) -> Score:
    """Return the exploitability Score for *finding*.

    Weights: severity (Black 40 … Gray 0), best detector weight, crackable +15,
    any credential +12, write/modify access +12, recency (<30d +5, <365d +2).
    Capped at 100; tier from thresholds Critical≥75 / High≥50 / Medium≥25 / Low.
    """
    if now is None:
        now = datetime.now(timezone.utc)

    breakdown: list[tuple[str, int]] = []

    sev_pts = _SEVERITY_POINTS.get(finding.severity, 0)
    if sev_pts:
        breakdown.append((f"severity:{finding.severity.value}", sev_pts))

    if hits:
        best = max(hits, key=lambda h: h.weight)
        if best.weight:
            breakdown.append((f"detector:{best.id}", best.weight))

    crackable = any(h.crackable for h in hits) or any(c.crackable for c in creds)
    if crackable:
        breakdown.append(("crackable", 15))

    if creds:
        breakdown.append(("credential", 12))

    if getattr(finding, "can_write", False) or getattr(finding, "can_modify", False):
        breakdown.append(("write-access", 12))

    modified = getattr(finding, "modified_date", None)
    if modified is not None:
        age_days = (now - modified).days
        if 0 < age_days < 30:
            breakdown.append(("recency:<30d", 5))
        elif 0 < age_days < 365:
            breakdown.append(("recency:<365d", 2))

    value = min(100, sum(pts for _, pts in breakdown))
    return Score(value=value, tier=_tier(value), breakdown=tuple(breakdown))
