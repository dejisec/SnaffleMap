"""Tests for finding_id-based dedup and cross-file merge."""

from __future__ import annotations

import dataclasses
from datetime import datetime, timezone
from pathlib import Path

from snafflemap.models import FileResult, ResultSet, Severity, ShareResult
from snafflemap.parsers import deduplicate, merge, parse_tsv

FIXTURES = Path(__file__).parent / "fixtures"


def _file(path, sev=Severity.RED, rule="Rule", matched="x", sources=()):
    return FileResult(
        severity=sev,
        rule_name=rule,
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
        sources=sources,
    )


class TestDedupById:
    def test_same_id_collapses_keeping_highest_severity(self):
        p = r"\\H\S\f"
        rs = ResultSet(
            files=[_file(p, Severity.YELLOW), _file(p, Severity.BLACK)],
            shares=[],
            dirs=[],
        )
        out = deduplicate(rs)
        assert out.file_count == 1
        assert out.files[0].severity is Severity.BLACK

    def test_different_rules_same_path_not_collapsed(self):
        p = r"\\H\S\f"
        rs = ResultSet(
            files=[_file(p, rule="A"), _file(p, rule="B")], shares=[], dirs=[]
        )
        out = deduplicate(rs)
        assert out.file_count == 2

    def test_sources_unioned_on_collapse(self):
        p = r"\\H\S\f"
        rs = ResultSet(
            files=[_file(p, sources=("a.tsv",)), _file(p, sources=("b.tsv",))],
            shares=[],
            dirs=[],
        )
        out = deduplicate(rs)
        assert out.files[0].sources == ("a.tsv", "b.tsv")


class TestParserSources:
    def test_tsv_findings_tagged_with_filename(self):
        rs = parse_tsv(FIXTURES / "sample.tsv")
        assert rs.files
        assert all(f.sources == ("sample.tsv",) for f in rs.files)
        assert all(s.sources == ("sample.tsv",) for s in rs.shares)


class TestMerge:
    def test_merge_unions_sources_for_same_finding(self):
        p = r"\\H\S\f"
        rs1 = ResultSet(files=[_file(p, sources=("a.tsv",))], shares=[], dirs=[])
        rs2 = ResultSet(files=[_file(p, sources=("b.tsv",))], shares=[], dirs=[])
        out = merge([rs1, rs2])
        assert out.file_count == 1
        assert out.files[0].sources == ("a.tsv", "b.tsv")

    def test_merge_keeps_max_severity(self):
        p = r"\\H\S\f"
        rs1 = ResultSet(
            files=[_file(p, Severity.GRAY, sources=("a",))], shares=[], dirs=[]
        )
        rs2 = ResultSet(
            files=[_file(p, Severity.BLACK, sources=("b",))], shares=[], dirs=[]
        )
        out = merge([rs1, rs2])
        assert out.files[0].severity is Severity.BLACK

    def test_merge_dedups_shares_and_dirs(self):
        s = ShareResult(
            severity=Severity.RED,
            share_path=r"\\H\S",
            can_read=True,
            can_write=False,
            can_modify=False,
            source_line=1,
            sources=("a",),
        )
        s2 = dataclasses.replace(s, sources=("b",))
        rs1 = ResultSet(files=[], shares=[s], dirs=[])
        rs2 = ResultSet(files=[], shares=[s2], dirs=[])
        out = merge([rs1, rs2])
        assert out.share_count == 1
        assert out.shares[0].sources == ("a", "b")

    def test_merge_no_dedup_concatenates(self):
        p = r"\\H\S\f"
        rs1 = ResultSet(files=[_file(p)], shares=[], dirs=[])
        rs2 = ResultSet(files=[_file(p)], shares=[], dirs=[])
        out = merge([rs1, rs2], dedup=False)
        assert out.file_count == 2

    def test_merge_collects_warnings(self):
        rs1 = ResultSet(files=[], shares=[], dirs=[], warnings=["w1"])
        rs2 = ResultSet(files=[], shares=[], dirs=[], warnings=["w2"])
        out = merge([rs1, rs2])
        assert out.warnings == ["w1", "w2"]

    def test_merge_source_union_is_sorted(self):
        p = r"\\H\S\f"
        rs1 = ResultSet(files=[_file(p, sources=("z.tsv",))], shares=[], dirs=[])
        rs2 = ResultSet(files=[_file(p, sources=("a.tsv",))], shares=[], dirs=[])
        out = merge([rs1, rs2])
        assert out.files[0].sources == ("a.tsv", "z.tsv")
