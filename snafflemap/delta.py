"""Delta engine: classify the current findings against a JSONL baseline."""

from __future__ import annotations

import json
from pathlib import Path

from snafflemap.models import ResultSet, Severity


def load_baseline(path) -> dict[str, dict]:
    """Load a SnaffleMap JSONL baseline into a dict keyed by finding id.

    Reads the raw records (so the enrichment block, if present, is available).
    Malformed lines are skipped.
    """
    path = Path(path)
    base: dict[str, dict] = {}
    with path.open(encoding="utf-8-sig", errors="replace") as fh:
        for raw in fh:
            raw = raw.strip()
            if not raw:
                continue
            try:
                rec = json.loads(raw)
            except json.JSONDecodeError:
                continue
            fid = rec.get("id")
            if fid:
                base[fid] = rec
    return base


def _base_score(rec: dict):
    enr = rec.get("enrichment")
    if not enr:
        return None
    score = enr.get("score")
    if not score:
        return None
    return score.get("value")


def compute_delta(
    result_set: ResultSet, enrichment: dict, baseline: dict[str, dict]
) -> tuple[dict[str, str], list[dict]]:
    """Return (delta_status by finding_id, resolved baseline records).

    Status per current finding:
      new       — not in baseline
      escalated — in baseline and severity OR score rose (more severe / higher)
      persisted — in baseline, neither rose
    Resolved    — baseline ids absent from the current set (full baseline records).
    """
    delta: dict[str, str] = {}
    current_ids: set[str] = set()

    for finding in (*result_set.files, *result_set.shares, *result_set.dirs):
        fid = finding.finding_id
        current_ids.add(fid)
        base = baseline.get(fid)
        if base is None:
            delta[fid] = "new"
            continue
        sev_rose = False
        try:
            base_sev_key = Severity.from_string(base.get("severity", "Gray")).sort_key
            sev_rose = finding.severity.sort_key < base_sev_key
        except ValueError:
            sev_rose = False
        score_rose = False
        base_score = _base_score(base)
        if base_score is not None:
            enr = enrichment.get(fid)
            cur_score = enr.score.value if enr is not None else 0
            score_rose = cur_score > base_score
        delta[fid] = "escalated" if (sev_rose or score_rose) else "persisted"

    resolved = [rec for fid, rec in baseline.items() if fid not in current_ids]
    return delta, resolved
