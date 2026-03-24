"""Tests for snafflemap.filters — FilterChain composable filter."""

from __future__ import annotations

from datetime import datetime


from snafflemap.models import (
    DirResult,
    FileResult,
    ResultSet,
    Severity,
    ShareResult,
)
from snafflemap.filters import FilterChain


# ---------------------------------------------------------------------------
# Helpers / fixtures
# ---------------------------------------------------------------------------

_DT_BASE = datetime(2024, 6, 15, 12, 0, 0)
_DT_EARLY = datetime(2023, 1, 1)
_DT_LATE = datetime(2025, 12, 31)


def make_file(
    severity=Severity.RED,
    rule_name="TestRule",
    file_path=r"\\DC01\SYSVOL\scripts\login.bat",
    matched_string="password=hunter2",
    match_context="password=hunter2 in login script",
    file_size=4096,
    modified_date=_DT_BASE,
):
    return FileResult(
        severity=severity,
        rule_name=rule_name,
        can_read=True,
        can_write=False,
        can_modify=False,
        matched_string=matched_string,
        file_size=file_size,
        modified_date=modified_date,
        file_path=file_path,
        alt_filename=None,
        match_context=match_context,
        source_line=1,
    )


def make_share(
    severity=Severity.YELLOW,
    share_path=r"\\FILESVR\HR$",
):
    return ShareResult(
        severity=severity,
        share_path=share_path,
        can_read=True,
        can_write=False,
        can_modify=False,
        source_line=2,
    )


def make_dir(
    severity=Severity.GREEN,
    dir_path=r"\\APPSVR\Data\Public",
):
    return DirResult(
        severity=severity,
        dir_path=dir_path,
        source_line=3,
    )


def make_rs(files=None, shares=None, dirs=None):
    return ResultSet(
        files=files or [],
        shares=shares or [],
        dirs=dirs or [],
    )


# ---------------------------------------------------------------------------
# FilterChain instantiation
# ---------------------------------------------------------------------------


class TestFilterChainBasic:
    def test_instantiation(self):
        fc = FilterChain()
        assert fc is not None

    def test_apply_empty_chain_returns_all(self):
        rs = make_rs(
            files=[make_file()],
            shares=[make_share()],
            dirs=[make_dir()],
        )
        result = FilterChain().apply(rs)
        assert len(result.files) == 1
        assert len(result.shares) == 1
        assert len(result.dirs) == 1

    def test_apply_returns_result_set(self):
        rs = make_rs(files=[make_file()])
        result = FilterChain().apply(rs)
        assert isinstance(result, ResultSet)

    def test_apply_does_not_mutate_original(self):
        rs = make_rs(files=[make_file(), make_file(severity=Severity.GREEN)])
        FilterChain().severity(Severity.RED).apply(rs)
        assert len(rs.files) == 2  # original unchanged


# ---------------------------------------------------------------------------
# .severity() — include only matching levels (applies to ALL types)
# ---------------------------------------------------------------------------


class TestSeverityFilter:
    def test_severity_single_level_files(self):
        rs = make_rs(
            files=[
                make_file(severity=Severity.RED),
                make_file(severity=Severity.GREEN),
                make_file(severity=Severity.BLACK),
            ]
        )
        result = FilterChain().severity(Severity.RED).apply(rs)
        assert len(result.files) == 1
        assert result.files[0].severity is Severity.RED

    def test_severity_multiple_levels(self):
        rs = make_rs(
            files=[
                make_file(severity=Severity.RED),
                make_file(severity=Severity.BLACK),
                make_file(severity=Severity.GREEN),
            ]
        )
        result = FilterChain().severity(Severity.RED, Severity.BLACK).apply(rs)
        assert len(result.files) == 2

    def test_severity_applies_to_shares(self):
        rs = make_rs(
            shares=[
                make_share(severity=Severity.RED),
                make_share(severity=Severity.YELLOW),
            ]
        )
        result = FilterChain().severity(Severity.RED).apply(rs)
        assert len(result.shares) == 1
        assert result.shares[0].severity is Severity.RED

    def test_severity_applies_to_dirs(self):
        rs = make_rs(
            dirs=[
                make_dir(severity=Severity.GREEN),
                make_dir(severity=Severity.GRAY),
            ]
        )
        result = FilterChain().severity(Severity.GREEN).apply(rs)
        assert len(result.dirs) == 1
        assert result.dirs[0].severity is Severity.GREEN

    def test_severity_applies_to_all_types(self):
        """severity filter removes from files, shares, and dirs simultaneously."""
        rs = make_rs(
            files=[
                make_file(severity=Severity.RED),
                make_file(severity=Severity.GREEN),
            ],
            shares=[
                make_share(severity=Severity.RED),
                make_share(severity=Severity.YELLOW),
            ],
            dirs=[make_dir(severity=Severity.RED), make_dir(severity=Severity.GREEN)],
        )
        result = FilterChain().severity(Severity.RED).apply(rs)
        assert len(result.files) == 1
        assert len(result.shares) == 1
        assert len(result.dirs) == 1
        assert result.files[0].severity is Severity.RED
        assert result.shares[0].severity is Severity.RED
        assert result.dirs[0].severity is Severity.RED

    def test_severity_no_match_returns_empty(self):
        rs = make_rs(files=[make_file(severity=Severity.GREEN)])
        result = FilterChain().severity(Severity.BLACK).apply(rs)
        assert len(result.files) == 0

    def test_method_returns_self(self):
        fc = FilterChain()
        assert fc.severity(Severity.RED) is fc


# ---------------------------------------------------------------------------
# .exclude_severity() — exclude matching levels (applies to ALL types)
# ---------------------------------------------------------------------------


class TestExcludeSeverityFilter:
    def test_exclude_single_level(self):
        rs = make_rs(
            files=[
                make_file(severity=Severity.RED),
                make_file(severity=Severity.GREEN),
                make_file(severity=Severity.GRAY),
            ]
        )
        result = FilterChain().exclude_severity(Severity.GRAY).apply(rs)
        assert len(result.files) == 2
        assert all(f.severity is not Severity.GRAY for f in result.files)

    def test_exclude_multiple_levels(self):
        rs = make_rs(
            files=[
                make_file(severity=Severity.RED),
                make_file(severity=Severity.GREEN),
                make_file(severity=Severity.GRAY),
            ]
        )
        result = FilterChain().exclude_severity(Severity.GREEN, Severity.GRAY).apply(rs)
        assert len(result.files) == 1
        assert result.files[0].severity is Severity.RED

    def test_exclude_severity_applies_to_shares(self):
        rs = make_rs(
            shares=[
                make_share(severity=Severity.RED),
                make_share(severity=Severity.GRAY),
            ]
        )
        result = FilterChain().exclude_severity(Severity.GRAY).apply(rs)
        assert len(result.shares) == 1
        assert result.shares[0].severity is Severity.RED

    def test_exclude_severity_applies_to_dirs(self):
        rs = make_rs(
            dirs=[
                make_dir(severity=Severity.GREEN),
                make_dir(severity=Severity.GRAY),
            ]
        )
        result = FilterChain().exclude_severity(Severity.GRAY).apply(rs)
        assert len(result.dirs) == 1
        assert result.dirs[0].severity is Severity.GREEN

    def test_method_returns_self(self):
        fc = FilterChain()
        assert fc.exclude_severity(Severity.GRAY) is fc


# ---------------------------------------------------------------------------
# .hostname() — glob and regex (applies to ALL types)
# ---------------------------------------------------------------------------


class TestHostnameFilter:
    def test_hostname_glob_exact(self):
        rs = make_rs(
            files=[
                make_file(file_path=r"\\DC01\SYSVOL\a.bat"),
                make_file(file_path=r"\\FILESVR\HR$\b.txt"),
            ]
        )
        result = FilterChain().hostname("DC01").apply(rs)
        assert len(result.files) == 1
        assert result.files[0].hostname == "DC01"

    def test_hostname_glob_wildcard(self):
        rs = make_rs(
            files=[
                make_file(file_path=r"\\DC01\SYSVOL\a.bat"),
                make_file(file_path=r"\\DC02\SYSVOL\b.bat"),
                make_file(file_path=r"\\FILESVR\HR$\c.txt"),
            ]
        )
        result = FilterChain().hostname("DC*").apply(rs)
        assert len(result.files) == 2

    def test_hostname_glob_question_mark(self):
        rs = make_rs(
            files=[
                make_file(file_path=r"\\DC01\SYSVOL\a.bat"),
                make_file(file_path=r"\\DC02\SYSVOL\b.bat"),
                make_file(file_path=r"\\FILESVR\HR$\c.txt"),
            ]
        )
        result = FilterChain().hostname("DC0?").apply(rs)
        assert len(result.files) == 2

    def test_hostname_regex(self):
        rs = make_rs(
            files=[
                make_file(file_path=r"\\DC01\SYSVOL\a.bat"),
                make_file(file_path=r"\\DC02\SYSVOL\b.bat"),
                make_file(file_path=r"\\FILESVR\HR$\c.txt"),
            ]
        )
        result = FilterChain().hostname(r"/DC\d+/").apply(rs)
        assert len(result.files) == 2

    def test_hostname_regex_case_insensitive(self):
        rs = make_rs(
            files=[
                make_file(file_path=r"\\DC01\SYSVOL\a.bat"),
                make_file(file_path=r"\\FILESVR\HR$\c.txt"),
            ]
        )
        result = FilterChain().hostname(r"/dc\d+/").apply(rs)
        assert len(result.files) == 1
        assert result.files[0].hostname == "DC01"

    def test_hostname_applies_to_shares(self):
        rs = make_rs(
            shares=[
                make_share(share_path=r"\\DC01\NETLOGON"),
                make_share(share_path=r"\\FILESVR\HR$"),
            ]
        )
        result = FilterChain().hostname("DC01").apply(rs)
        assert len(result.shares) == 1
        assert result.shares[0].hostname == "DC01"

    def test_hostname_applies_to_dirs(self):
        rs = make_rs(
            dirs=[
                make_dir(dir_path=r"\\DC01\SYSVOL\scripts"),
                make_dir(dir_path=r"\\APPSVR\Data\Public"),
            ]
        )
        result = FilterChain().hostname("DC01").apply(rs)
        assert len(result.dirs) == 1
        assert result.dirs[0].hostname == "DC01"

    def test_method_returns_self(self):
        fc = FilterChain()
        assert fc.hostname("DC*") is fc


# ---------------------------------------------------------------------------
# .share() — substring match on share_name (FileResult + ShareResult only)
# ---------------------------------------------------------------------------


class TestShareFilter:
    def test_share_substring_match(self):
        rs = make_rs(
            files=[
                make_file(file_path=r"\\DC01\SYSVOL\a.bat"),
                make_file(file_path=r"\\FILESVR\HR$\b.txt"),
            ]
        )
        result = FilterChain().share("SYSVOL").apply(rs)
        assert len(result.files) == 1
        assert result.files[0].share_name == "SYSVOL"

    def test_share_case_insensitive(self):
        rs = make_rs(
            files=[
                make_file(file_path=r"\\DC01\SYSVOL\a.bat"),
            ]
        )
        result = FilterChain().share("sysvol").apply(rs)
        assert len(result.files) == 1

    def test_share_partial_match(self):
        rs = make_rs(
            files=[
                make_file(file_path=r"\\DC01\SYSVOL\a.bat"),
                make_file(file_path=r"\\FILESVR\HR$\b.txt"),
            ]
        )
        result = FilterChain().share("SYS").apply(rs)
        assert len(result.files) == 1

    def test_share_applies_to_share_results(self):
        rs = make_rs(
            shares=[
                make_share(share_path=r"\\DC01\SYSVOL"),
                make_share(share_path=r"\\FILESVR\HR$"),
            ]
        )
        result = FilterChain().share("SYSVOL").apply(rs)
        assert len(result.shares) == 1
        assert result.shares[0].share_name == "SYSVOL"

    def test_share_does_not_filter_dirs(self):
        """DirResult has no share_name — share filter must NOT remove dirs."""
        rs = make_rs(
            files=[make_file(file_path=r"\\DC01\SYSVOL\a.bat")],
            dirs=[make_dir(dir_path=r"\\APPSVR\Data\Public")],
        )
        result = FilterChain().share("SYSVOL").apply(rs)
        assert len(result.files) == 1
        assert len(result.dirs) == 1  # dirs pass through unaffected

    def test_method_returns_self(self):
        fc = FilterChain()
        assert fc.share("SYSVOL") is fc


# ---------------------------------------------------------------------------
# .rule() — substring match on rule_name (FileResult only)
# ---------------------------------------------------------------------------


class TestRuleFilter:
    def test_rule_substring_match(self):
        rs = make_rs(
            files=[
                make_file(rule_name="KeepConfigSecrets"),
                make_file(rule_name="SensitiveKeyword"),
            ]
        )
        result = FilterChain().rule("Config").apply(rs)
        assert len(result.files) == 1
        assert result.files[0].rule_name == "KeepConfigSecrets"

    def test_rule_case_insensitive(self):
        rs = make_rs(
            files=[
                make_file(rule_name="KeepConfigSecrets"),
            ]
        )
        result = FilterChain().rule("config").apply(rs)
        assert len(result.files) == 1

    def test_rule_does_not_filter_shares(self):
        """ShareResult has no rule_name — rule filter must NOT remove shares."""
        rs = make_rs(
            files=[make_file(rule_name="KeepConfigSecrets")],
            shares=[make_share()],
        )
        result = FilterChain().rule("Config").apply(rs)
        assert len(result.files) == 1
        assert len(result.shares) == 1  # shares pass through unaffected

    def test_rule_does_not_filter_dirs(self):
        """DirResult has no rule_name — rule filter must NOT remove dirs."""
        rs = make_rs(
            files=[make_file(rule_name="KeepConfigSecrets")],
            dirs=[make_dir()],
        )
        result = FilterChain().rule("Config").apply(rs)
        assert len(result.files) == 1
        assert len(result.dirs) == 1  # dirs pass through unaffected

    def test_method_returns_self(self):
        fc = FilterChain()
        assert fc.rule("Config") is fc


# ---------------------------------------------------------------------------
# .extension() — file extension match (FileResult only)
# ---------------------------------------------------------------------------


class TestExtensionFilter:
    def test_extension_with_dot(self):
        rs = make_rs(
            files=[
                make_file(file_path=r"\\DC01\SYSVOL\login.bat"),
                make_file(file_path=r"\\DC01\SYSVOL\config.xml"),
            ]
        )
        result = FilterChain().extension(".bat").apply(rs)
        assert len(result.files) == 1
        assert result.files[0].extension == ".bat"

    def test_extension_without_dot_normalized(self):
        """Extension without leading dot should be normalized to include it."""
        rs = make_rs(
            files=[
                make_file(file_path=r"\\DC01\SYSVOL\login.bat"),
                make_file(file_path=r"\\DC01\SYSVOL\config.xml"),
            ]
        )
        result = FilterChain().extension("bat").apply(rs)
        assert len(result.files) == 1
        assert result.files[0].extension == ".bat"

    def test_extension_multiple(self):
        rs = make_rs(
            files=[
                make_file(file_path=r"\\DC01\SYSVOL\login.bat"),
                make_file(file_path=r"\\DC01\SYSVOL\config.xml"),
                make_file(file_path=r"\\DC01\SYSVOL\notes.txt"),
            ]
        )
        result = FilterChain().extension(".bat", ".xml").apply(rs)
        assert len(result.files) == 2

    def test_extension_does_not_filter_shares(self):
        """ShareResult has no extension — extension filter must NOT remove shares."""
        rs = make_rs(
            files=[make_file(file_path=r"\\DC01\SYSVOL\login.bat")],
            shares=[make_share()],
        )
        result = FilterChain().extension(".bat").apply(rs)
        assert len(result.files) == 1
        assert len(result.shares) == 1  # shares pass through unaffected

    def test_extension_does_not_filter_dirs(self):
        """DirResult has no extension — extension filter must NOT remove dirs."""
        rs = make_rs(
            files=[make_file(file_path=r"\\DC01\SYSVOL\login.bat")],
            dirs=[make_dir()],
        )
        result = FilterChain().extension(".bat").apply(rs)
        assert len(result.files) == 1
        assert len(result.dirs) == 1  # dirs pass through unaffected

    def test_method_returns_self(self):
        fc = FilterChain()
        assert fc.extension(".bat") is fc


# ---------------------------------------------------------------------------
# .keyword() — substring in match_context OR matched_string (FileResult only)
# ---------------------------------------------------------------------------


class TestKeywordFilter:
    def test_keyword_in_match_context(self):
        rs = make_rs(
            files=[
                make_file(
                    match_context="password=hunter2 in login", matched_string="foo"
                ),
                make_file(match_context="harmless content", matched_string="bar"),
            ]
        )
        result = FilterChain().keyword("password").apply(rs)
        assert len(result.files) == 1
        assert "password" in result.files[0].match_context

    def test_keyword_in_matched_string(self):
        rs = make_rs(
            files=[
                make_file(
                    match_context="some context", matched_string="secret_token_abc"
                ),
                make_file(match_context="other context", matched_string="nothing_here"),
            ]
        )
        result = FilterChain().keyword("secret_token").apply(rs)
        assert len(result.files) == 1
        assert "secret_token" in result.files[0].matched_string

    def test_keyword_case_insensitive(self):
        rs = make_rs(
            files=[
                make_file(match_context="PASSWORD=hunter2", matched_string="x"),
            ]
        )
        result = FilterChain().keyword("password").apply(rs)
        assert len(result.files) == 1

    def test_keyword_or_logic(self):
        """Matches if keyword is in EITHER field (not both required)."""
        rs = make_rs(
            files=[
                make_file(match_context="clean context", matched_string="secret_value"),
                make_file(match_context="clean context", matched_string="nothing"),
            ]
        )
        result = FilterChain().keyword("secret_value").apply(rs)
        assert len(result.files) == 1

    def test_keyword_no_match_excluded(self):
        rs = make_rs(
            files=[
                make_file(match_context="hello world", matched_string="foo"),
            ]
        )
        result = FilterChain().keyword("password").apply(rs)
        assert len(result.files) == 0

    def test_keyword_does_not_filter_shares(self):
        rs = make_rs(
            files=[make_file(match_context="password here", matched_string="x")],
            shares=[make_share()],
        )
        result = FilterChain().keyword("password").apply(rs)
        assert len(result.files) == 1
        assert len(result.shares) == 1  # shares pass through unaffected

    def test_keyword_does_not_filter_dirs(self):
        rs = make_rs(
            files=[make_file(match_context="password here", matched_string="x")],
            dirs=[make_dir()],
        )
        result = FilterChain().keyword("password").apply(rs)
        assert len(result.files) == 1
        assert len(result.dirs) == 1  # dirs pass through unaffected

    def test_method_returns_self(self):
        fc = FilterChain()
        assert fc.keyword("password") is fc


# ---------------------------------------------------------------------------
# .size() — file size range in bytes (FileResult only)
# ---------------------------------------------------------------------------


class TestSizeFilter:
    def test_size_min_only(self):
        rs = make_rs(
            files=[
                make_file(file_size=100),
                make_file(file_size=5000),
                make_file(file_size=10000),
            ]
        )
        result = FilterChain().size(min=1000).apply(rs)
        assert len(result.files) == 2
        assert all(f.file_size >= 1000 for f in result.files)

    def test_size_max_only(self):
        rs = make_rs(
            files=[
                make_file(file_size=100),
                make_file(file_size=5000),
                make_file(file_size=10000),
            ]
        )
        result = FilterChain().size(max=4999).apply(rs)
        assert len(result.files) == 1
        assert result.files[0].file_size == 100

    def test_size_min_and_max(self):
        rs = make_rs(
            files=[
                make_file(file_size=100),
                make_file(file_size=5000),
                make_file(file_size=10000),
            ]
        )
        result = FilterChain().size(min=1000, max=9000).apply(rs)
        assert len(result.files) == 1
        assert result.files[0].file_size == 5000

    def test_size_boundary_inclusive(self):
        rs = make_rs(
            files=[
                make_file(file_size=1000),
                make_file(file_size=9000),
            ]
        )
        result = FilterChain().size(min=1000, max=9000).apply(rs)
        assert len(result.files) == 2

    def test_size_does_not_filter_shares(self):
        rs = make_rs(
            files=[make_file(file_size=5000)],
            shares=[make_share()],
        )
        result = FilterChain().size(min=1000).apply(rs)
        assert len(result.files) == 1
        assert len(result.shares) == 1  # shares pass through unaffected

    def test_size_does_not_filter_dirs(self):
        rs = make_rs(
            files=[make_file(file_size=5000)],
            dirs=[make_dir()],
        )
        result = FilterChain().size(min=1000).apply(rs)
        assert len(result.files) == 1
        assert len(result.dirs) == 1  # dirs pass through unaffected

    def test_method_returns_self(self):
        fc = FilterChain()
        assert fc.size(min=0) is fc


# ---------------------------------------------------------------------------
# .date() — modified date range (FileResult only)
# ---------------------------------------------------------------------------


class TestDateFilter:
    def test_date_after_only(self):
        rs = make_rs(
            files=[
                make_file(modified_date=_DT_EARLY),
                make_file(modified_date=_DT_BASE),
                make_file(modified_date=_DT_LATE),
            ]
        )
        result = FilterChain().date(after=datetime(2024, 1, 1)).apply(rs)
        assert len(result.files) == 2
        assert all(f.modified_date >= datetime(2024, 1, 1) for f in result.files)

    def test_date_before_only(self):
        rs = make_rs(
            files=[
                make_file(modified_date=_DT_EARLY),
                make_file(modified_date=_DT_BASE),
                make_file(modified_date=_DT_LATE),
            ]
        )
        result = FilterChain().date(before=datetime(2024, 12, 31)).apply(rs)
        assert len(result.files) == 2
        assert all(f.modified_date <= datetime(2024, 12, 31) for f in result.files)

    def test_date_after_and_before(self):
        rs = make_rs(
            files=[
                make_file(modified_date=_DT_EARLY),
                make_file(modified_date=_DT_BASE),
                make_file(modified_date=_DT_LATE),
            ]
        )
        result = (
            FilterChain()
            .date(
                after=datetime(2024, 1, 1),
                before=datetime(2024, 12, 31),
            )
            .apply(rs)
        )
        assert len(result.files) == 1
        assert result.files[0].modified_date == _DT_BASE

    def test_date_boundary_inclusive(self):
        rs = make_rs(
            files=[
                make_file(modified_date=_DT_BASE),
            ]
        )
        result = FilterChain().date(after=_DT_BASE, before=_DT_BASE).apply(rs)
        assert len(result.files) == 1

    def test_date_does_not_filter_shares(self):
        rs = make_rs(
            files=[make_file(modified_date=_DT_BASE)],
            shares=[make_share()],
        )
        result = FilterChain().date(after=datetime(2020, 1, 1)).apply(rs)
        assert len(result.files) == 1
        assert len(result.shares) == 1  # shares pass through unaffected

    def test_date_does_not_filter_dirs(self):
        rs = make_rs(
            files=[make_file(modified_date=_DT_BASE)],
            dirs=[make_dir()],
        )
        result = FilterChain().date(after=datetime(2020, 1, 1)).apply(rs)
        assert len(result.files) == 1
        assert len(result.dirs) == 1  # dirs pass through unaffected

    def test_method_returns_self(self):
        fc = FilterChain()
        assert fc.date(after=datetime(2024, 1, 1)) is fc


# ---------------------------------------------------------------------------
# Method chaining / AND logic
# ---------------------------------------------------------------------------


class TestChaining:
    def test_chain_severity_and_hostname(self):
        rs = make_rs(
            files=[
                make_file(severity=Severity.RED, file_path=r"\\DC01\SYSVOL\a.bat"),
                make_file(severity=Severity.RED, file_path=r"\\FILESVR\HR$\b.txt"),
                make_file(severity=Severity.GREEN, file_path=r"\\DC01\SYSVOL\c.xml"),
            ]
        )
        result = FilterChain().severity(Severity.RED).hostname("DC01").apply(rs)
        assert len(result.files) == 1
        assert result.files[0].severity is Severity.RED
        assert result.files[0].hostname == "DC01"

    def test_chain_rule_and_extension(self):
        rs = make_rs(
            files=[
                make_file(rule_name="ConfigRule", file_path=r"\\DC01\SYSVOL\login.bat"),
                make_file(
                    rule_name="ConfigRule", file_path=r"\\DC01\SYSVOL\config.xml"
                ),
                make_file(rule_name="OtherRule", file_path=r"\\DC01\SYSVOL\other.bat"),
            ]
        )
        result = FilterChain().rule("Config").extension(".bat").apply(rs)
        assert len(result.files) == 1
        assert result.files[0].rule_name == "ConfigRule"
        assert result.files[0].extension == ".bat"

    def test_chain_size_and_date(self):
        rs = make_rs(
            files=[
                make_file(file_size=5000, modified_date=_DT_BASE),
                make_file(file_size=100, modified_date=_DT_BASE),
                make_file(file_size=5000, modified_date=_DT_EARLY),
            ]
        )
        result = FilterChain().size(min=1000).date(after=datetime(2024, 1, 1)).apply(rs)
        assert len(result.files) == 1
        assert result.files[0].file_size == 5000
        assert result.files[0].modified_date == _DT_BASE

    def test_chain_all_methods(self):
        """All filters in one chain — only perfectly matching file survives."""
        perfect = make_file(
            severity=Severity.RED,
            rule_name="KeepConfigSecrets",
            file_path=r"\\DC01\SYSVOL\login.bat",
            matched_string="password=secret",
            match_context="password in config",
            file_size=5000,
            modified_date=_DT_BASE,
        )
        noise = make_file(
            severity=Severity.GREEN,
            rule_name="OtherRule",
            file_path=r"\\FILESVR\HR$\other.xml",
            matched_string="nothing",
            match_context="nothing here",
            file_size=100,
            modified_date=_DT_EARLY,
        )
        rs = make_rs(files=[perfect, noise])
        result = (
            FilterChain()
            .severity(Severity.RED)
            .hostname("DC01")
            .share("SYSVOL")
            .rule("Config")
            .extension(".bat")
            .keyword("password")
            .size(min=1000, max=9000)
            .date(after=datetime(2024, 1, 1))
            .apply(rs)
        )
        assert len(result.files) == 1
        assert result.files[0] is perfect

    def test_chain_is_and_not_or(self):
        """Both conditions must be true — AND, not OR."""
        rs = make_rs(
            files=[
                make_file(severity=Severity.RED, file_path=r"\\DC01\SYSVOL\a.bat"),
                make_file(severity=Severity.GREEN, file_path=r"\\FILESVR\HR$\b.txt"),
            ]
        )
        # RED matches first, DC01 matches first — but not both together for second
        result = FilterChain().severity(Severity.RED).hostname("FILESVR").apply(rs)
        assert len(result.files) == 0


# ---------------------------------------------------------------------------
# Filter scope: inapplicable types pass through unfiltered
# ---------------------------------------------------------------------------


class TestFilterScope:
    def test_extension_does_not_affect_shares_or_dirs(self):
        """Extension filter applies ONLY to FileResult; shares/dirs are untouched."""
        rs = make_rs(
            files=[
                make_file(file_path=r"\\DC01\SYSVOL\login.bat"),
                make_file(file_path=r"\\DC01\SYSVOL\config.xml"),
            ],
            shares=[make_share(), make_share()],
            dirs=[make_dir(), make_dir(), make_dir()],
        )
        result = FilterChain().extension(".bat").apply(rs)
        assert len(result.files) == 1  # filtered
        assert len(result.shares) == 2  # unchanged
        assert len(result.dirs) == 3  # unchanged

    def test_rule_does_not_affect_shares_or_dirs(self):
        rs = make_rs(
            files=[
                make_file(rule_name="KeepConfigSecrets"),
                make_file(rule_name="OtherRule"),
            ],
            shares=[make_share(), make_share()],
            dirs=[make_dir()],
        )
        result = FilterChain().rule("Config").apply(rs)
        assert len(result.files) == 1
        assert len(result.shares) == 2
        assert len(result.dirs) == 1

    def test_keyword_does_not_affect_shares_or_dirs(self):
        rs = make_rs(
            files=[
                make_file(match_context="password here", matched_string="x"),
                make_file(match_context="nothing", matched_string="nothing"),
            ],
            shares=[make_share()],
            dirs=[make_dir()],
        )
        result = FilterChain().keyword("password").apply(rs)
        assert len(result.files) == 1
        assert len(result.shares) == 1
        assert len(result.dirs) == 1

    def test_size_does_not_affect_shares_or_dirs(self):
        rs = make_rs(
            files=[
                make_file(file_size=5000),
                make_file(file_size=50),
            ],
            shares=[make_share(), make_share()],
            dirs=[make_dir()],
        )
        result = FilterChain().size(min=1000).apply(rs)
        assert len(result.files) == 1
        assert len(result.shares) == 2
        assert len(result.dirs) == 1

    def test_date_does_not_affect_shares_or_dirs(self):
        rs = make_rs(
            files=[
                make_file(modified_date=_DT_LATE),
                make_file(modified_date=_DT_EARLY),
            ],
            shares=[make_share()],
            dirs=[make_dir(), make_dir()],
        )
        result = FilterChain().date(after=datetime(2025, 1, 1)).apply(rs)
        assert len(result.files) == 1
        assert len(result.shares) == 1
        assert len(result.dirs) == 2

    def test_share_filter_does_not_affect_dirs(self):
        rs = make_rs(
            files=[make_file(file_path=r"\\DC01\SYSVOL\a.bat")],
            shares=[make_share(share_path=r"\\DC01\SYSVOL")],
            dirs=[make_dir(), make_dir()],
        )
        result = FilterChain().share("SYSVOL").apply(rs)
        assert len(result.files) == 1
        assert len(result.shares) == 1
        assert len(result.dirs) == 2  # dirs pass through unaffected

    def test_severity_filter_applies_to_all_types(self):
        """severity applies to ALL types — this is different from file-only filters."""
        rs = make_rs(
            files=[
                make_file(severity=Severity.RED),
                make_file(severity=Severity.GREEN),
            ],
            shares=[
                make_share(severity=Severity.RED),
                make_share(severity=Severity.GREEN),
            ],
            dirs=[make_dir(severity=Severity.RED), make_dir(severity=Severity.GREEN)],
        )
        result = FilterChain().severity(Severity.RED).apply(rs)
        assert len(result.files) == 1
        assert len(result.shares) == 1
        assert len(result.dirs) == 1
