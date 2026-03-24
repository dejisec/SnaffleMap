"""Tests for snafflemap.models — Severity, FileResult, ShareResult, DirResult, ResultSet."""

from __future__ import annotations

import pytest
from datetime import datetime

from snafflemap.models import (
    Severity,
    FileResult,
    ShareResult,
    DirResult,
    ResultSet,
)


# ---------------------------------------------------------------------------
# Severity
# ---------------------------------------------------------------------------


class TestSeverity:
    def test_values(self):
        assert Severity.BLACK.value == "Black"
        assert Severity.RED.value == "Red"
        assert Severity.YELLOW.value == "Yellow"
        assert Severity.GREEN.value == "Green"
        assert Severity.GRAY.value == "Gray"

    def test_sort_key_ordering(self):
        """Black is most severe (0), Gray is least severe (4)."""
        assert Severity.BLACK.sort_key == 0
        assert Severity.RED.sort_key == 1
        assert Severity.YELLOW.sort_key == 2
        assert Severity.GREEN.sort_key == 3
        assert Severity.GRAY.sort_key == 4

    def test_sort_key_ordering_comparison(self):
        """sort_key allows correct ordering from most to least severe."""
        severities = [
            Severity.GRAY,
            Severity.GREEN,
            Severity.BLACK,
            Severity.YELLOW,
            Severity.RED,
        ]
        sorted_sevs = sorted(severities, key=lambda s: s.sort_key)
        assert sorted_sevs == [
            Severity.BLACK,
            Severity.RED,
            Severity.YELLOW,
            Severity.GREEN,
            Severity.GRAY,
        ]

    def test_from_string_exact(self):
        assert Severity.from_string("Black") is Severity.BLACK
        assert Severity.from_string("Red") is Severity.RED
        assert Severity.from_string("Yellow") is Severity.YELLOW
        assert Severity.from_string("Green") is Severity.GREEN
        assert Severity.from_string("Gray") is Severity.GRAY

    def test_from_string_case_insensitive(self):
        assert Severity.from_string("black") is Severity.BLACK
        assert Severity.from_string("BLACK") is Severity.BLACK
        assert Severity.from_string("RED") is Severity.RED
        assert Severity.from_string("yellow") is Severity.YELLOW
        assert Severity.from_string("GREEN") is Severity.GREEN
        assert Severity.from_string("gray") is Severity.GRAY

    def test_from_string_strips_whitespace(self):
        assert Severity.from_string("  Red  ") is Severity.RED
        assert Severity.from_string("\tBlack\n") is Severity.BLACK

    def test_from_string_invalid_raises(self):
        with pytest.raises(ValueError, match="Unknown severity"):
            Severity.from_string("Purple")

    def test_from_string_empty_raises(self):
        with pytest.raises(ValueError):
            Severity.from_string("")


# ---------------------------------------------------------------------------
# FileResult
# ---------------------------------------------------------------------------

_DT = datetime(2024, 6, 15, 10, 30, 0)

_FILE_UNC = FileResult(
    severity=Severity.RED,
    rule_name="KeepConfigSecrets",
    can_read=True,
    can_write=False,
    can_modify=False,
    matched_string="password=hunter2",
    file_size=4096,
    modified_date=_DT,
    file_path=r"\\DC01\SYSVOL\scripts\login.bat",
    alt_filename=None,
    match_context="password=hunter2 in login script",
    source_line=42,
)


class TestFileResult:
    def test_creation_basic_fields(self):
        assert _FILE_UNC.severity is Severity.RED
        assert _FILE_UNC.rule_name == "KeepConfigSecrets"
        assert _FILE_UNC.can_read is True
        assert _FILE_UNC.can_write is False
        assert _FILE_UNC.can_modify is False
        assert _FILE_UNC.matched_string == "password=hunter2"
        assert _FILE_UNC.file_size == 4096
        assert _FILE_UNC.modified_date == _DT
        assert _FILE_UNC.file_path == r"\\DC01\SYSVOL\scripts\login.bat"
        assert _FILE_UNC.alt_filename is None
        assert _FILE_UNC.match_context == "password=hunter2 in login script"
        assert _FILE_UNC.source_line == 42

    def test_hostname_from_unc(self):
        assert _FILE_UNC.hostname == "DC01"

    def test_share_name_from_unc(self):
        assert _FILE_UNC.share_name == "SYSVOL"

    def test_extension_from_unc(self):
        assert _FILE_UNC.extension == ".bat"

    def test_non_unc_path_hostname_empty(self):
        f = FileResult(
            severity=Severity.GREEN,
            rule_name="SomeRule",
            can_read=True,
            can_write=False,
            can_modify=False,
            matched_string="",
            file_size=0,
            modified_date=_DT,
            file_path="/local/path/file.txt",
            alt_filename=None,
            match_context="",
            source_line=None,
        )
        assert f.hostname == ""
        assert f.share_name == ""
        assert f.extension == ".txt"

    def test_extension_no_extension(self):
        f = FileResult(
            severity=Severity.GRAY,
            rule_name="NoExt",
            can_read=False,
            can_write=False,
            can_modify=False,
            matched_string="",
            file_size=0,
            modified_date=_DT,
            file_path=r"\\HOST\share\somefile",
            alt_filename=None,
            match_context="",
            source_line=None,
        )
        assert f.extension == ""

    def test_alt_filename_set(self):
        f = FileResult(
            severity=Severity.BLACK,
            rule_name="SomeRule",
            can_read=True,
            can_write=True,
            can_modify=True,
            matched_string="secret",
            file_size=100,
            modified_date=_DT,
            file_path=r"\\FILESVR\HR$\data.zip",
            alt_filename="archive.zip",
            match_context="secret inside zip",
            source_line=1,
        )
        assert f.alt_filename == "archive.zip"

    def test_is_frozen(self):
        with pytest.raises((AttributeError, TypeError)):
            _FILE_UNC.severity = Severity.GREEN  # type: ignore[misc]

    def test_source_line_none(self):
        f = FileResult(
            severity=Severity.YELLOW,
            rule_name="Rule",
            can_read=False,
            can_write=False,
            can_modify=False,
            matched_string="x",
            file_size=1,
            modified_date=_DT,
            file_path=r"\\DC01\SYSVOL\x.txt",
            alt_filename=None,
            match_context="",
            source_line=None,
        )
        assert f.source_line is None


# ---------------------------------------------------------------------------
# ShareResult
# ---------------------------------------------------------------------------

_SHARE = ShareResult(
    severity=Severity.YELLOW,
    share_path=r"\\FILESVR\HR$",
    can_read=True,
    can_write=True,
    can_modify=False,
    source_line=7,
)


class TestShareResult:
    def test_creation(self):
        assert _SHARE.severity is Severity.YELLOW
        assert _SHARE.share_path == r"\\FILESVR\HR$"
        assert _SHARE.can_read is True
        assert _SHARE.can_write is True
        assert _SHARE.can_modify is False
        assert _SHARE.source_line == 7

    def test_hostname(self):
        assert _SHARE.hostname == "FILESVR"

    def test_share_name(self):
        assert _SHARE.share_name == "HR$"

    def test_non_unc_share(self):
        s = ShareResult(
            severity=Severity.GRAY,
            share_path="not-a-unc",
            can_read=False,
            can_write=False,
            can_modify=False,
            source_line=None,
        )
        assert s.hostname == ""
        assert s.share_name == ""

    def test_is_frozen(self):
        with pytest.raises((AttributeError, TypeError)):
            _SHARE.severity = Severity.BLACK  # type: ignore[misc]


# ---------------------------------------------------------------------------
# DirResult
# ---------------------------------------------------------------------------

_DIR = DirResult(
    severity=Severity.GREEN,
    dir_path=r"\\APPSVR\Data\Public",
    source_line=99,
)


class TestDirResult:
    def test_creation(self):
        assert _DIR.severity is Severity.GREEN
        assert _DIR.dir_path == r"\\APPSVR\Data\Public"
        assert _DIR.source_line == 99

    def test_hostname(self):
        assert _DIR.hostname == "APPSVR"

    def test_non_unc_dir(self):
        d = DirResult(
            severity=Severity.GRAY,
            dir_path="/mnt/share",
            source_line=None,
        )
        assert d.hostname == ""

    def test_is_frozen(self):
        with pytest.raises((AttributeError, TypeError)):
            _DIR.severity = Severity.RED  # type: ignore[misc]


# ---------------------------------------------------------------------------
# ResultSet
# ---------------------------------------------------------------------------


def _make_file(severity=Severity.RED, path=r"\\DC01\SYSVOL\a.bat", dt=None):
    return FileResult(
        severity=severity,
        rule_name="Rule",
        can_read=True,
        can_write=False,
        can_modify=False,
        matched_string="x",
        file_size=100,
        modified_date=dt or datetime(2024, 1, 1),
        file_path=path,
        alt_filename=None,
        match_context="ctx",
        source_line=1,
    )


def _make_share(severity=Severity.YELLOW, path=r"\\FILESVR\HR$"):
    return ShareResult(
        severity=severity,
        share_path=path,
        can_read=True,
        can_write=False,
        can_modify=False,
        source_line=2,
    )


def _make_dir(severity=Severity.GREEN, path=r"\\APPSVR\Data\Public"):
    return DirResult(
        severity=severity,
        dir_path=path,
        source_line=3,
    )


class TestResultSet:
    def test_counts(self):
        rs = ResultSet(
            files=[_make_file(), _make_file()],
            shares=[_make_share()],
            dirs=[_make_dir(), _make_dir(), _make_dir()],
        )
        assert rs.file_count == 2
        assert rs.share_count == 1
        assert rs.dir_count == 3
        assert rs.total_findings == 6

    def test_empty_counts(self):
        rs = ResultSet(files=[], shares=[], dirs=[])
        assert rs.total_findings == 0
        assert rs.file_count == 0
        assert rs.share_count == 0
        assert rs.dir_count == 0

    def test_severity_counts(self):
        rs = ResultSet(
            files=[
                _make_file(Severity.RED),
                _make_file(Severity.RED),
                _make_file(Severity.BLACK),
            ],
            shares=[
                _make_share(Severity.YELLOW),
                _make_share(Severity.RED),
            ],
            dirs=[
                _make_dir(Severity.GREEN),
            ],
        )
        counts = rs.severity_counts
        assert counts[Severity.BLACK] == 1
        assert counts[Severity.RED] == 3
        assert counts[Severity.YELLOW] == 1
        assert counts[Severity.GREEN] == 1
        assert counts.get(Severity.GRAY, 0) == 0

    def test_severity_counts_all_zeros_in_empty(self):
        rs = ResultSet(files=[], shares=[], dirs=[])
        counts = rs.severity_counts
        # All severities should sum to 0
        assert sum(counts.values()) == 0

    def test_unique_hosts_from_all_types(self):
        rs = ResultSet(
            files=[_make_file(path=r"\\DC01\SYSVOL\a.bat")],
            shares=[_make_share(path=r"\\FILESVR\HR$")],
            dirs=[_make_dir(path=r"\\APPSVR\Data\Public")],
        )
        assert rs.unique_hosts == {"DC01", "FILESVR", "APPSVR"}

    def test_unique_hosts_deduplicates(self):
        rs = ResultSet(
            files=[
                _make_file(path=r"\\DC01\SYSVOL\a.bat"),
                _make_file(path=r"\\DC01\SYSVOL\b.bat"),
            ],
            shares=[_make_share(path=r"\\DC01\NETLOGON")],
            dirs=[],
        )
        assert rs.unique_hosts == {"DC01"}

    def test_unique_hosts_excludes_empty(self):
        rs = ResultSet(
            files=[
                FileResult(
                    severity=Severity.GRAY,
                    rule_name="r",
                    can_read=False,
                    can_write=False,
                    can_modify=False,
                    matched_string="",
                    file_size=0,
                    modified_date=datetime(2024, 1, 1),
                    file_path="/local/path.txt",
                    alt_filename=None,
                    match_context="",
                    source_line=None,
                )
            ],
            shares=[],
            dirs=[],
        )
        # Non-UNC path yields hostname="" which should NOT be in unique_hosts
        assert "" not in rs.unique_hosts

    def test_unique_shares_from_files_and_shares(self):
        rs = ResultSet(
            files=[_make_file(path=r"\\DC01\SYSVOL\a.bat")],
            shares=[_make_share(path=r"\\FILESVR\HR$")],
            dirs=[_make_dir(path=r"\\APPSVR\Data\Public")],  # DirResult NOT included
        )
        # SYSVOL from file, HR$ from share — DirResult does not contribute
        assert rs.unique_shares == {"SYSVOL", "HR$"}

    def test_unique_shares_deduplicates(self):
        rs = ResultSet(
            files=[
                _make_file(path=r"\\DC01\SYSVOL\a.bat"),
                _make_file(path=r"\\DC02\SYSVOL\b.bat"),
            ],
            shares=[_make_share(path=r"\\FILESVR\SYSVOL")],
            dirs=[],
        )
        assert rs.unique_shares == {"SYSVOL"}

    def test_date_range_two_files(self):
        dt_early = datetime(2023, 1, 1)
        dt_late = datetime(2024, 12, 31)
        rs = ResultSet(
            files=[
                _make_file(dt=dt_late),
                _make_file(dt=dt_early),
            ],
            shares=[],
            dirs=[],
        )
        min_dt, max_dt = rs.date_range
        assert min_dt == dt_early
        assert max_dt == dt_late

    def test_date_range_single_file(self):
        dt = datetime(2024, 6, 15)
        rs = ResultSet(files=[_make_file(dt=dt)], shares=[], dirs=[])
        assert rs.date_range == (dt, dt)

    def test_date_range_empty_returns_none(self):
        rs = ResultSet(files=[], shares=[], dirs=[])
        assert rs.date_range is None

    def test_warnings_default_none(self):
        rs = ResultSet(files=[], shares=[], dirs=[])
        assert rs.warnings is None

    def test_warnings_set(self):
        rs = ResultSet(files=[], shares=[], dirs=[], warnings=["something odd"])
        assert rs.warnings == ["something odd"]

    def test_resultset_is_mutable(self):
        """ResultSet is NOT frozen — it should allow attribute assignment."""
        rs = ResultSet(files=[], shares=[], dirs=[])
        f = _make_file()
        rs.files.append(f)
        assert rs.file_count == 1
