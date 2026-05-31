"""Tests for exploitability scoring."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

from snafflemap.analysis.models import Credential, DetectorHit
from snafflemap.analysis.score import score
from snafflemap.models import FileResult, Severity, ShareResult

NOW = datetime(2026, 1, 1, tzinfo=timezone.utc)


def _file(sev=Severity.GRAY, modified=NOW, can_write=False):
    return FileResult(
        severity=sev,
        rule_name="R",
        can_read=True,
        can_write=can_write,
        can_modify=False,
        matched_string="x",
        file_size=1,
        modified_date=modified,
        file_path=r"\\H\S\f",
        alt_filename=None,
        match_context="c",
        source_line=1,
    )


def _hit(weight=20, crackable=False):
    return DetectorHit(
        id="d",
        label="L",
        category="c",
        why="w",
        action="a",
        crackable=crackable,
        weight=weight,
    )


def _cred(crackable=False):
    return Credential(
        type="t",
        secret="s",
        username=None,
        raw_context="c",
        crackable=crackable,
        finding_id="x",
        source="f",
    )


def test_severity_weights():
    assert score(_file(Severity.BLACK), [], [], now=NOW).value == 40
    assert score(_file(Severity.RED), [], [], now=NOW).value == 28
    assert score(_file(Severity.GRAY), [], [], now=NOW).value == 0


def test_detector_adds_max_weight():
    s = score(_file(Severity.GRAY), [_hit(20), _hit(15)], [], now=NOW)
    assert s.value == 20


def test_crackable_and_credential_and_write():
    s = score(
        _file(Severity.GRAY, can_write=True),
        [_hit(0, crackable=True)],
        [_cred()],
        now=NOW,
    )
    # crackable +15, credential +12, write +12 = 39
    assert s.value == 39


def test_recency_buckets():
    recent = score(
        _file(Severity.GRAY, modified=NOW - timedelta(days=10)), [], [], now=NOW
    )
    midold = score(
        _file(Severity.GRAY, modified=NOW - timedelta(days=200)), [], [], now=NOW
    )
    ancient = score(
        _file(Severity.GRAY, modified=NOW - timedelta(days=2000)), [], [], now=NOW
    )
    assert recent.value == 5
    assert midold.value == 2
    assert ancient.value == 0


def test_capped_at_100_and_tiers():
    s = score(
        _file(Severity.BLACK, can_write=True, modified=NOW),
        [_hit(40, crackable=True)],
        [_cred(crackable=True)],
        now=NOW,
    )
    assert s.value == 100
    assert s.tier == "Critical"


def test_tier_thresholds():
    assert (
        score(_file(Severity.BLACK), [], [], now=NOW).tier == "Medium"
    )  # 40 -> Medium
    assert score(_file(Severity.GRAY), [], [], now=NOW).tier == "Low"


def test_breakdown_records_factors():
    s = score(_file(Severity.RED), [], [], now=NOW)
    assert ("severity:Red", 28) in s.breakdown


def test_shares_have_no_recency_or_size():
    s = ShareResult(
        severity=Severity.BLACK,
        share_path=r"\\H\S",
        can_read=True,
        can_write=True,
        can_modify=False,
        source_line=1,
    )
    out = score(s, [], [], now=NOW)
    # severity 40 + write 12 = 52
    assert out.value == 52
