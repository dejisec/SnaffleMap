"""Tests for the enrichment orchestrator and score filtering."""

from __future__ import annotations

from datetime import datetime, timezone

from snafflemap.analysis.catalog import builtin_catalog
from snafflemap.analysis.enrich import enrich, filter_by_score
from snafflemap.models import FileResult, ResultSet, Severity

NOW = datetime(2026, 1, 1, tzinfo=timezone.utc)


def _file(path, sev=Severity.BLACK, ctx="", matched=""):
    return FileResult(
        severity=sev,
        rule_name="R",
        can_read=True,
        can_write=False,
        can_modify=False,
        matched_string=matched,
        file_size=1,
        modified_date=datetime(2025, 1, 1, tzinfo=timezone.utc),
        file_path=path,
        alt_filename=None,
        match_context=ctx,
        source_line=1,
    )


def test_enrich_keys_by_finding_id():
    f = _file(r"\\DC\SYSVOL\Groups.xml", ctx='cpassword="AAAA"')
    rs = ResultSet(files=[f], shares=[], dirs=[])
    enr = enrich(rs, builtin_catalog(), now=NOW)
    assert f.finding_id in enr
    e = enr[f.finding_id]
    assert any(h.id == "gpp-cpassword" for h in e.detectors)
    assert any(c.type == "gpp-cpassword" for c in e.credentials)
    assert e.score.value > 0


def test_enrich_covers_all_findings():
    files = [_file(r"\\H\S\a.txt", Severity.GRAY), _file(r"\\H\S\b.kdbx")]
    rs = ResultSet(files=files, shares=[], dirs=[])
    enr = enrich(rs, builtin_catalog(), now=NOW)
    assert len(enr) == 2


def test_filter_by_min_score():
    low = _file(r"\\H\S\a.txt", Severity.GRAY)
    high = _file(r"\\DC\SYSVOL\Groups.xml", ctx='cpassword="AAAA"')
    rs = ResultSet(files=[low, high], shares=[], dirs=[])
    enr = enrich(rs, builtin_catalog(), now=NOW)
    out = filter_by_score(rs, enr, min_score=50)
    assert [f.finding_id for f in out.files] == [high.finding_id]


def test_filter_by_tier():
    low = _file(r"\\H\S\a.txt", Severity.GRAY)
    high = _file(r"\\DC\SYSVOL\Groups.xml", ctx='cpassword="AAAA"')
    rs = ResultSet(files=[low, high], shares=[], dirs=[])
    enr = enrich(rs, builtin_catalog(), now=NOW)
    out = filter_by_score(rs, enr, tiers={"Critical"})
    assert all(enr[f.finding_id].score.tier == "Critical" for f in out.files)
