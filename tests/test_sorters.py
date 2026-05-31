"""Tests for snafflemap.sorters — apply_sort."""

from __future__ import annotations

from datetime import datetime


from snafflemap.models import (
    DirResult,
    FileResult,
    ResultSet,
    Severity,
    ShareResult,
)
from snafflemap.sorters import apply_sort


def _make_file(
    severity: Severity = Severity.RED,
    path: str = r"\\DC01\SYSVOL\a.bat",
    dt: datetime | None = None,
    rule: str = "RuleA",
    size: int = 100,
) -> FileResult:
    return FileResult(
        severity=severity,
        rule_name=rule,
        can_read=True,
        can_write=False,
        can_modify=False,
        matched_string="x",
        file_size=size,
        modified_date=dt or datetime(2024, 1, 1),
        file_path=path,
        alt_filename=None,
        match_context="ctx",
        source_line=1,
    )


def _make_share(
    severity: Severity = Severity.YELLOW,
    path: str = r"\\FILESVR\HR$",
) -> ShareResult:
    return ShareResult(
        severity=severity,
        share_path=path,
        can_read=True,
        can_write=False,
        can_modify=False,
        source_line=2,
    )


def _make_dir(
    severity: Severity = Severity.GREEN,
    path: str = r"\\APPSVR\Data\Public",
) -> DirResult:
    return DirResult(
        severity=severity,
        dir_path=path,
        source_line=3,
    )


class TestSortFilesBySeverity:
    def test_sort_by_severity_ascending(self):
        """Black (0) comes before Red (1) before Yellow (2)."""
        f_yellow = _make_file(Severity.YELLOW)
        f_black = _make_file(Severity.BLACK)
        f_red = _make_file(Severity.RED)
        rs = ResultSet(files=[f_yellow, f_black, f_red], shares=[], dirs=[])
        result = apply_sort(rs, ["severity"])
        assert result.files == [f_black, f_red, f_yellow]

    def test_sort_by_severity_already_sorted_unchanged(self):
        f_black = _make_file(Severity.BLACK)
        f_gray = _make_file(Severity.GRAY)
        rs = ResultSet(files=[f_black, f_gray], shares=[], dirs=[])
        result = apply_sort(rs, ["severity"])
        assert result.files == [f_black, f_gray]

    def test_sort_by_severity_all_same_preserves_relative_order(self):
        """Equal severity items maintain their relative order (stable sort)."""
        f1 = _make_file(Severity.RED, path=r"\\H\S\a.txt")
        f2 = _make_file(Severity.RED, path=r"\\H\S\b.txt")
        rs = ResultSet(files=[f1, f2], shares=[], dirs=[])
        result = apply_sort(rs, ["severity"])
        assert result.files == [f1, f2]


class TestSortFilesByModified:
    def test_sort_by_modified_oldest_first(self):
        dt_old = datetime(2022, 1, 1)
        dt_mid = datetime(2023, 6, 15)
        dt_new = datetime(2024, 12, 31)
        f_new = _make_file(dt=dt_new)
        f_old = _make_file(dt=dt_old)
        f_mid = _make_file(dt=dt_mid)
        rs = ResultSet(files=[f_new, f_old, f_mid], shares=[], dirs=[])
        result = apply_sort(rs, ["modified"])
        assert result.files == [f_old, f_mid, f_new]

    def test_sort_by_modified_single_file(self):
        f = _make_file(dt=datetime(2023, 3, 3))
        rs = ResultSet(files=[f], shares=[], dirs=[])
        result = apply_sort(rs, ["modified"])
        assert result.files == [f]


class TestSortFilesByPath:
    def test_sort_by_path_case_insensitive(self):
        f_z = _make_file(path=r"\\H\S\zebra.txt")
        f_a = _make_file(path=r"\\H\S\Apple.txt")
        f_m = _make_file(path=r"\\H\S\mango.txt")
        rs = ResultSet(files=[f_z, f_a, f_m], shares=[], dirs=[])
        result = apply_sort(rs, ["path"])
        assert result.files == [f_a, f_m, f_z]

    def test_sort_by_path_all_lowercase(self):
        f1 = _make_file(path=r"\\H\S\aardvark.log")
        f2 = _make_file(path=r"\\H\S\zebra.log")
        rs = ResultSet(files=[f2, f1], shares=[], dirs=[])
        result = apply_sort(rs, ["path"])
        assert result.files == [f1, f2]


class TestSortFilesByRule:
    def test_sort_by_rule_case_insensitive(self):
        f_z = _make_file(rule="ZoomConfig")
        f_a = _make_file(rule="AwsKeys")
        f_k = _make_file(rule="keepSecrets")
        rs = ResultSet(files=[f_z, f_a, f_k], shares=[], dirs=[])
        result = apply_sort(rs, ["rule"])
        assert result.files == [f_a, f_k, f_z]

    def test_sort_by_rule_same_rule_stable(self):
        f1 = _make_file(rule="SameRule", path=r"\\H\S\first.txt")
        f2 = _make_file(rule="SameRule", path=r"\\H\S\second.txt")
        rs = ResultSet(files=[f1, f2], shares=[], dirs=[])
        result = apply_sort(rs, ["rule"])
        assert result.files == [f1, f2]


class TestSortFilesBySize:
    def test_sort_by_size_ascending(self):
        f_big = _make_file(size=9999)
        f_small = _make_file(size=1)
        f_mid = _make_file(size=500)
        rs = ResultSet(files=[f_big, f_small, f_mid], shares=[], dirs=[])
        result = apply_sort(rs, ["size"])
        assert result.files == [f_small, f_mid, f_big]

    def test_sort_by_size_equal_sizes_stable(self):
        f1 = _make_file(size=100, path=r"\\H\S\a.txt")
        f2 = _make_file(size=100, path=r"\\H\S\b.txt")
        rs = ResultSet(files=[f1, f2], shares=[], dirs=[])
        result = apply_sort(rs, ["size"])
        assert result.files == [f1, f2]


class TestSortFilesCompositeKeys:
    def test_severity_then_modified(self):
        """Primary: severity. Secondary: modified date (oldest first)."""
        dt_early = datetime(2022, 1, 1)
        dt_late = datetime(2024, 1, 1)
        # Two RED files, one old one new; one BLACK file
        f_red_late = _make_file(Severity.RED, dt=dt_late, path=r"\\H\S\c.txt")
        f_red_early = _make_file(Severity.RED, dt=dt_early, path=r"\\H\S\a.txt")
        f_black = _make_file(Severity.BLACK, dt=dt_late, path=r"\\H\S\b.txt")
        rs = ResultSet(files=[f_red_late, f_red_early, f_black], shares=[], dirs=[])
        result = apply_sort(rs, ["severity", "modified"])
        assert result.files == [f_black, f_red_early, f_red_late]

    def test_severity_then_path(self):
        """Primary: severity. Secondary: file path (alphabetical)."""
        f_red_z = _make_file(Severity.RED, path=r"\\H\S\z.txt")
        f_red_a = _make_file(Severity.RED, path=r"\\H\S\a.txt")
        f_black = _make_file(Severity.BLACK, path=r"\\H\S\m.txt")
        rs = ResultSet(files=[f_red_z, f_red_a, f_black], shares=[], dirs=[])
        result = apply_sort(rs, ["severity", "path"])
        assert result.files == [f_black, f_red_a, f_red_z]

    def test_rule_then_size(self):
        """Primary: rule name. Secondary: file size."""
        f_b_big = _make_file(rule="BRule", size=500)
        f_b_small = _make_file(rule="BRule", size=10)
        f_a = _make_file(rule="ARule", size=999)
        rs = ResultSet(files=[f_b_big, f_b_small, f_a], shares=[], dirs=[])
        result = apply_sort(rs, ["rule", "size"])
        assert result.files == [f_a, f_b_small, f_b_big]

    def test_three_keys(self):
        """Three-level sort: severity -> rule -> path."""
        dt = datetime(2024, 1, 1)
        f1 = _make_file(Severity.RED, rule="BRule", path=r"\\H\S\z.txt", dt=dt)
        f2 = _make_file(Severity.RED, rule="BRule", path=r"\\H\S\a.txt", dt=dt)
        f3 = _make_file(Severity.RED, rule="ARule", path=r"\\H\S\m.txt", dt=dt)
        f4 = _make_file(Severity.BLACK, rule="ZRule", path=r"\\H\S\z.txt", dt=dt)
        rs = ResultSet(files=[f1, f2, f3, f4], shares=[], dirs=[])
        result = apply_sort(rs, ["severity", "rule", "path"])
        assert result.files == [f4, f3, f2, f1]


class TestSortShares:
    def test_sort_shares_by_severity(self):
        s_yellow = _make_share(Severity.YELLOW)
        s_black = _make_share(Severity.BLACK)
        s_green = _make_share(Severity.GREEN)
        rs = ResultSet(files=[], shares=[s_yellow, s_black, s_green], dirs=[])
        result = apply_sort(rs, ["severity"])
        assert result.shares == [s_black, s_yellow, s_green]

    def test_sort_shares_by_path(self):
        s_z = _make_share(path=r"\\H\Zebra")
        s_a = _make_share(path=r"\\H\Alpha")
        s_m = _make_share(path=r"\\H\Mango")
        rs = ResultSet(files=[], shares=[s_z, s_a, s_m], dirs=[])
        result = apply_sort(rs, ["path"])
        assert result.shares == [s_a, s_m, s_z]

    def test_sort_shares_unknown_key_falls_back_to_severity_path(self):
        """Unknown keys are ignored; fallback is (severity, path)."""
        s1 = _make_share(Severity.RED, path=r"\\H\Beta")
        s2 = _make_share(Severity.RED, path=r"\\H\Alpha")
        s3 = _make_share(Severity.BLACK, path=r"\\H\Zeta")
        rs = ResultSet(files=[], shares=[s1, s2, s3], dirs=[])
        result = apply_sort(rs, ["size"])  # "size" not valid for shares
        assert result.shares == [s3, s2, s1]

    def test_sort_shares_empty(self):
        rs = ResultSet(files=[], shares=[], dirs=[])
        result = apply_sort(rs, ["severity"])
        assert result.shares == []


class TestSortDirs:
    def test_sort_dirs_by_severity(self):
        d_green = _make_dir(Severity.GREEN)
        d_black = _make_dir(Severity.BLACK)
        d_red = _make_dir(Severity.RED)
        rs = ResultSet(files=[], shares=[], dirs=[d_green, d_black, d_red])
        result = apply_sort(rs, ["severity"])
        assert result.dirs == [d_black, d_red, d_green]

    def test_sort_dirs_by_path(self):
        d_z = _make_dir(path=r"\\H\S\Zebra")
        d_a = _make_dir(path=r"\\H\S\Apple")
        d_m = _make_dir(path=r"\\H\S\mango")
        rs = ResultSet(files=[], shares=[], dirs=[d_z, d_a, d_m])
        result = apply_sort(rs, ["path"])
        # case-insensitive: Apple < mango < Zebra
        assert result.dirs == [d_a, d_m, d_z]

    def test_sort_dirs_unknown_key_falls_back_to_severity_path(self):
        """Unknown keys for dirs fall back to (severity, path)."""
        d1 = _make_dir(Severity.YELLOW, path=r"\\H\S\Beta")
        d2 = _make_dir(Severity.YELLOW, path=r"\\H\S\Alpha")
        d3 = _make_dir(Severity.BLACK, path=r"\\H\S\Zeta")
        rs = ResultSet(files=[], shares=[], dirs=[d1, d2, d3])
        result = apply_sort(rs, ["modified"])  # "modified" not valid for dirs
        assert result.dirs == [d3, d2, d1]

    def test_sort_dirs_empty(self):
        rs = ResultSet(files=[], shares=[], dirs=[])
        result = apply_sort(rs, ["path"])
        assert result.dirs == []


class TestSortIndependence:
    def test_files_shares_dirs_sorted_independently(self):
        """Sorting must not mix result types; each list is sorted on its own."""
        f = _make_file(Severity.GRAY)
        s = _make_share(Severity.BLACK)
        d = _make_dir(Severity.RED)
        rs = ResultSet(files=[f], shares=[s], dirs=[d])
        result = apply_sort(rs, ["severity"])
        assert result.files == [f]
        assert result.shares == [s]
        assert result.dirs == [d]

    def test_returns_new_result_set(self):
        """apply_sort should return a ResultSet (either new or same instance is fine,
        but the lists must reflect the sort order)."""
        f1 = _make_file(Severity.YELLOW)
        f2 = _make_file(Severity.BLACK)
        rs = ResultSet(files=[f1, f2], shares=[], dirs=[])
        result = apply_sort(rs, ["severity"])
        assert isinstance(result, ResultSet)
        assert result.files[0].severity is Severity.BLACK

    def test_empty_keys_list_leaves_order_unchanged(self):
        """Passing an empty keys list should not crash and should return the same order."""
        f1 = _make_file(Severity.YELLOW, path=r"\\H\S\b.txt")
        f2 = _make_file(Severity.BLACK, path=r"\\H\S\a.txt")
        rs = ResultSet(files=[f1, f2], shares=[], dirs=[])
        result = apply_sort(rs, [])
        # With no keys, files stay in original order (stable no-op sort)
        assert result.files == [f1, f2]

    def test_original_result_set_not_mutated(self):
        """The original ResultSet's lists must not be modified in-place."""
        f1 = _make_file(Severity.YELLOW)
        f2 = _make_file(Severity.BLACK)
        original_files = [f1, f2]
        rs = ResultSet(files=list(original_files), shares=[], dirs=[])
        apply_sort(rs, ["severity"])
        # Original list order preserved
        assert rs.files == original_files


class TestScoreSort:
    def test_score_key_sorts_highest_first(self):
        from datetime import datetime, timezone

        from snafflemap.analysis.models import Enrichment, Score
        from snafflemap.models import FileResult, ResultSet, Severity
        from snafflemap.sorters import apply_sort

        def mk(path, val):
            f = FileResult(
                severity=Severity.RED,
                rule_name="R",
                can_read=True,
                can_write=False,
                can_modify=False,
                matched_string=path,
                file_size=1,
                modified_date=datetime(2025, 1, 1, tzinfo=timezone.utc),
                file_path=path,
                alt_filename=None,
                match_context="c",
                source_line=1,
            )
            return f, Enrichment(finding_id=f.finding_id, score=Score(val, "x", ()))

        a, ea = mk(r"\\H\S\a", 10)
        b, eb = mk(r"\\H\S\b", 90)
        rs = ResultSet(files=[a, b], shares=[], dirs=[])
        enr = {ea.finding_id: ea, eb.finding_id: eb}
        out = apply_sort(rs, ["score"], enrichment=enr)
        assert [f.file_path for f in out.files] == [r"\\H\S\b", r"\\H\S\a"]

    def test_score_key_ignored_without_enrichment(self):
        # apply_sort must still work when enrichment is omitted (score key -> no-op)
        from snafflemap.models import ResultSet
        from snafflemap.sorters import apply_sort

        out = apply_sort(ResultSet(files=[], shares=[], dirs=[]), ["score"])
        assert out.files == []
