"""Tests for stable finding identity (FileResult/ShareResult/DirResult.finding_id)."""

from __future__ import annotations

from datetime import datetime, timezone

from snafflemap.models import DirResult, FileResult, Severity, ShareResult


def _file(path=r"\\H\S\f.txt", rule="Rule", matched="secret", sev=Severity.RED):
    return FileResult(
        severity=sev,
        rule_name=rule,
        can_read=True,
        can_write=False,
        can_modify=False,
        matched_string=matched,
        file_size=10,
        modified_date=datetime(2025, 1, 1, tzinfo=timezone.utc),
        file_path=path,
        alt_filename=None,
        match_context="ctx",
        source_line=1,
    )


class TestFindingId:
    def test_is_deterministic(self):
        assert _file().finding_id == _file().finding_id

    def test_is_16_hex_chars(self):
        fid = _file().finding_id
        assert len(fid) == 16
        assert all(c in "0123456789abcdef" for c in fid)

    def test_changes_with_path(self):
        assert _file(path=r"\\H\S\a").finding_id != _file(path=r"\\H\S\b").finding_id

    def test_changes_with_rule(self):
        assert _file(rule="A").finding_id != _file(rule="B").finding_id

    def test_changes_with_matched_string(self):
        assert _file(matched="aaa").finding_id != _file(matched="bbb").finding_id

    def test_stable_across_severity(self):
        # Severity is NOT part of identity
        assert (
            _file(sev=Severity.BLACK).finding_id == _file(sev=Severity.GRAY).finding_id
        )

    def test_whitespace_normalised(self):
        # TSV vs JSON whitespace differences must yield the same id
        assert _file(matched="a  b\tc").finding_id == _file(matched="a b c").finding_id

    def test_empty_matched_falls_back_to_path_rule(self):
        # Empty matched_string => id is path+rule only, and stable
        assert _file(matched="").finding_id == _file(matched="   ").finding_id

    def test_share_and_dir_ids(self):
        s = ShareResult(
            severity=Severity.RED,
            share_path=r"\\H\S",
            can_read=True,
            can_write=False,
            can_modify=False,
            source_line=1,
        )
        d = DirResult(severity=Severity.RED, dir_path=r"\\H\S\dir", source_line=1)
        assert len(s.finding_id) == 16 and len(d.finding_id) == 16
        assert s.finding_id != d.finding_id


class TestSourcesField:
    def test_file_sources_default_empty(self):
        assert _file().sources == ()

    def test_sources_not_in_identity(self):
        import dataclasses

        a = _file()
        b = dataclasses.replace(a, sources=("x.tsv",))
        assert a.finding_id == b.finding_id


class TestFindingIdGolden:
    def test_file_golden_hash(self):
        # Pins the exact hashing recipe so a silent change to the algorithm is caught.
        import hashlib

        expected = hashlib.sha1(
            "File\0\\\\H\\S\\f.txt\0Rule\0secret".encode("utf-8")
        ).hexdigest()[:16]
        assert _file().finding_id == expected
