"""Tests for the delta engine."""

from __future__ import annotations

import json
from datetime import datetime, timezone

from snafflemap.analysis.models import Enrichment, Score
from snafflemap.delta import compute_delta, load_baseline
from snafflemap.models import FileResult, ResultSet, Severity


def _file(path, sev=Severity.RED, matched="x"):
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
        match_context="c",
        source_line=1,
    )


def _enr(rs, scores):
    """Build an enrichment map giving each finding a score from *scores* (by path)."""
    out = {}
    for f in rs.files:
        v = scores.get(f.file_path, 0)
        out[f.finding_id] = Enrichment(finding_id=f.finding_id, score=Score(v, "x", ()))
    return out


def _baseline_dict(entries):
    """entries: list of (FileResult, score_or_None) -> baseline index dict."""
    base = {}
    for f, score in entries:
        rec = {
            "id": f.finding_id,
            "type": "file",
            "severity": f.severity.value,
            "file_path": f.file_path,
            "rule_name": f.rule_name,
            "sources": [],
        }
        if score is not None:
            rec["enrichment"] = {"score": {"value": score, "tier": "x"}}
        base[f.finding_id] = rec
    return base


class TestComputeDelta:
    def test_new_finding(self):
        cur = _file(r"\\H\S\new")
        rs = ResultSet(files=[cur], shares=[], dirs=[])
        dmap, resolved = compute_delta(rs, _enr(rs, {}), {})
        assert dmap[cur.finding_id] == "new"
        assert resolved == []

    def test_persisted_unchanged(self):
        f = _file(r"\\H\S\a")
        rs = ResultSet(files=[f], shares=[], dirs=[])
        base = _baseline_dict([(f, 50)])
        dmap, _ = compute_delta(rs, _enr(rs, {r"\\H\S\a": 50}), base)
        assert dmap[f.finding_id] == "persisted"

    def test_escalated_by_severity(self):
        # same id (path+rule+matched) but more severe now than baseline
        f_now = _file(r"\\H\S\a", sev=Severity.BLACK)
        f_base = _file(
            r"\\H\S\a", sev=Severity.YELLOW
        )  # same finding_id (sev not in id)
        rs = ResultSet(files=[f_now], shares=[], dirs=[])
        base = _baseline_dict([(f_base, 50)])
        dmap, _ = compute_delta(rs, _enr(rs, {r"\\H\S\a": 50}), base)
        assert dmap[f_now.finding_id] == "escalated"

    def test_escalated_by_score(self):
        f = _file(r"\\H\S\a")
        rs = ResultSet(files=[f], shares=[], dirs=[])
        base = _baseline_dict([(f, 40)])
        dmap, _ = compute_delta(rs, _enr(rs, {r"\\H\S\a": 90}), base)
        assert dmap[f.finding_id] == "escalated"

    def test_severity_drop_is_persisted(self):
        f_now = _file(r"\\H\S\a", sev=Severity.GREEN)
        f_base = _file(r"\\H\S\a", sev=Severity.RED)
        rs = ResultSet(files=[f_now], shares=[], dirs=[])
        base = _baseline_dict([(f_base, 50)])
        dmap, _ = compute_delta(rs, _enr(rs, {r"\\H\S\a": 50}), base)
        assert dmap[f_now.finding_id] == "persisted"

    def test_no_score_baseline_falls_back_to_severity(self):
        f = _file(r"\\H\S\a")
        rs = ResultSet(files=[f], shares=[], dirs=[])
        base = _baseline_dict([(f, None)])  # baseline predates B: no score
        dmap, _ = compute_delta(rs, _enr(rs, {r"\\H\S\a": 99}), base)
        # score can't be compared -> severity unchanged -> persisted
        assert dmap[f.finding_id] == "persisted"

    def test_resolved_reconstructed_from_baseline(self):
        gone = _file(r"\\H\S\gone")
        present = _file(r"\\H\S\here")
        rs = ResultSet(files=[present], shares=[], dirs=[])
        base = _baseline_dict([(gone, 50), (present, 50)])
        dmap, resolved = compute_delta(rs, _enr(rs, {r"\\H\S\here": 50}), base)
        assert dmap[present.finding_id] == "persisted"
        assert len(resolved) == 1
        assert resolved[0]["file_path"] == r"\\H\S\gone"


def test_load_baseline_indexes_by_id(tmp_path):
    p = tmp_path / "b.jsonl"
    p.write_text(
        json.dumps({"id": "abc", "type": "file", "severity": "Red"})
        + "\n"
        + json.dumps({"id": "def", "type": "share", "severity": "Black"})
        + "\n",
        encoding="utf-8",
    )
    base = load_baseline(p)
    assert set(base) == {"abc", "def"}
    assert base["abc"]["severity"] == "Red"
