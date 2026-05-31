"""Tests for snafflemap.parsers — parse_tsv, parse_json, detect_format, parse,
parse_iter, deduplicate, _unescape_match_context, ParseError."""

from __future__ import annotations

import json
from pathlib import Path
from datetime import datetime, timezone

import pytest

from snafflemap.models import Severity, FileResult, ShareResult, DirResult
from snafflemap.parsers import (
    ParseError,
    _unescape_match_context,
    deduplicate,
    detect_format,
    parse,
    parse_iter,
    parse_json,
    parse_tsv,
)


class TestParseTsvFileResults:
    def test_parse_tsv_file_results(self, sample_tsv):
        rs = parse_tsv(sample_tsv)
        assert rs.file_count == 6

        f = rs.files[0]
        assert f.severity is Severity.RED
        assert f.rule_name == "KeepPsCredentials"
        assert f.can_read is True
        assert f.can_write is False
        assert f.can_modify is False
        assert f.matched_string == "-SecureString"
        assert f.file_size == 416
        assert (
            f.file_path == r"\\Etihad-DC01.mancity.local\TeamDocs\IT\backup-script.ps1"
        )
        assert f.source_line == 8

    def test_file_result_modified_date_is_utc(self, sample_tsv):
        rs = parse_tsv(sample_tsv)
        dt = rs.files[0].modified_date
        assert isinstance(dt, datetime)
        # Must be timezone-aware (UTC)
        assert dt.tzinfo is not None
        assert dt.tzinfo == timezone.utc or dt.utcoffset().total_seconds() == 0

    def test_file_result_alt_filename_empty_is_none(self, sample_tsv):
        rs = parse_tsv(sample_tsv)
        # First file has empty alt_filename field → None; match_context gets the value
        assert rs.files[0].alt_filename is None

    def test_file_result_match_context_escaped(self, sample_tsv):
        rs = parse_tsv(sample_tsv)
        # First file: match_context has Snaffler backslash escaping (not unescaped by default)
        ctx = rs.files[0].match_context
        assert r"\$BackupPass" in ctx

    def test_file_result_second_row_permissions(self, sample_tsv):
        rs = parse_tsv(sample_tsv)
        f = rs.files[1]  # Green KeepNameContainsGreen R → read=T, write=F, modify=F
        assert f.severity is Severity.GREEN
        assert f.rule_name == "KeepNameContainsGreen"
        assert f.can_read is True
        assert f.can_write is False
        assert f.can_modify is False

    def test_file_result_black_severity(self, sample_tsv):
        rs = parse_tsv(sample_tsv)
        # Fifth file is Black KeepPassOrKeyInCode (Groups.xml with cpassword)
        f = rs.files[4]
        assert f.severity is Severity.BLACK
        assert f.rule_name == "KeepPassOrKeyInCode"
        assert f.can_read is True
        assert f.can_write is False
        assert f.can_modify is False


class TestParseTsvShareResults:
    def test_parse_tsv_share_results(self, sample_tsv):
        rs = parse_tsv(sample_tsv)
        assert rs.share_count == 4

        s = rs.shares[0]
        assert s.severity is Severity.GREEN
        assert s.share_path == r"\\Etihad-DC01.mancity.local\NETLOGON"
        assert s.can_read is True
        assert s.can_write is False
        assert s.can_modify is False

    def test_share_result_second(self, sample_tsv):
        rs = parse_tsv(sample_tsv)
        s = rs.shares[1]
        assert s.severity is Severity.GREEN
        assert s.share_path == r"\\Etihad-DC01.mancity.local\SYSVOL"
        assert s.can_read is True
        assert s.can_write is False
        assert s.can_modify is False

    def test_share_result_black_no_perms(self, sample_tsv):
        rs = parse_tsv(sample_tsv)
        s = rs.shares[2]
        assert s.severity is Severity.BLACK
        assert s.share_path == r"\\Foden-PC01.mancity.local\ADMIN$"
        assert s.can_read is False
        assert s.can_write is False
        assert s.can_modify is False

    def test_share_source_line(self, sample_tsv):
        rs = parse_tsv(sample_tsv)
        # First share is on line 4 of sample.tsv
        assert rs.shares[0].source_line == 4


class TestParseTsvDirResults:
    def test_parse_tsv_dir_results(self, sample_tsv):
        rs = parse_tsv(sample_tsv)
        assert rs.dir_count == 0

    def test_parse_tsv_skips_info_lines(self, sample_tsv):
        rs = parse_tsv(sample_tsv)
        # Info, Error, status update continuation lines, and Done. are all silently
        # skipped — no warnings generated for clean Snaffler output
        assert rs.warnings is None or len(rs.warnings) == 0


class TestParseTsvLenientMode:
    def test_parse_tsv_lenient_skips_malformed(self, malformed_tsv):
        rs = parse_tsv(malformed_tsv)  # default strict=False
        # Line 1 (Info) silently skipped, lines 2 and 7 are valid FileResults
        # line 3 (garbage, no tabs) silently skipped
        # line 4 (bad file_size "not_a_number") and line 5 (too few File fields)
        # are malformed → warnings
        # line 6 (starts with tab, unknown type marker) silently skipped
        assert rs.file_count == 2
        assert rs.warnings is not None
        assert len(rs.warnings) >= 2

    def test_lenient_warnings_mention_line_numbers(self, malformed_tsv):
        rs = parse_tsv(malformed_tsv)
        # At least one warning should contain a line number reference
        combined = " ".join(rs.warnings)
        assert any(c.isdigit() for c in combined)

    def test_lenient_valid_files_are_correct(self, malformed_tsv):
        rs = parse_tsv(malformed_tsv)
        paths = [f.file_path for f in rs.files]
        assert r"\\Etihad-DC01.mancity.local\TeamDocs\file.xml" in paths
        assert r"\\Foden-PC01.mancity.local\ADMIN$\good.txt" in paths


class TestParseTsvStrictMode:
    def test_parse_tsv_strict_raises(self, malformed_tsv):
        with pytest.raises(ParseError):
            parse_tsv(malformed_tsv, strict=True)

    def test_parse_tsv_strict_error_has_line_number(self, malformed_tsv):
        with pytest.raises(ParseError) as exc_info:
            parse_tsv(malformed_tsv, strict=True)
        assert exc_info.value.line_number is not None
        assert exc_info.value.line_number >= 1

    def test_parse_tsv_strict_clean_file_ok(self, sample_tsv):
        rs = parse_tsv(sample_tsv, strict=True)
        assert rs.file_count == 6


class TestParseJsonFileResult:
    def test_parse_json_file_result_count(self, sample_json):
        rs = parse_json(sample_json)
        assert rs.file_count == 3

    def test_parse_json_file_result_red(self, sample_json):
        rs = parse_json(sample_json)
        f = rs.files[0]
        assert f.severity is Severity.RED
        assert f.rule_name == "KeepPsCredentials"
        assert f.can_read is True
        assert f.can_write is False
        assert f.can_modify is False
        assert f.matched_string == "-SecureString"
        assert f.file_size == 416
        assert (
            f.file_path == r"\\Etihad-DC01.mancity.local\TeamDocs\IT\backup-script.ps1"
        )
        assert f.alt_filename is None

    def test_parse_json_file_result_yellow(self, sample_json):
        rs = parse_json(sample_json)
        f = rs.files[1]
        assert f.severity is Severity.YELLOW
        assert f.rule_name == "KeepDatabaseByExtension"
        assert f.file_size == 192512
        assert (
            f.file_path
            == r"\\Foden-PC01.mancity.local\C$\ProgramData\USOPrivate\UpdateStore\store.bak"
        )

    def test_parse_json_file_result_green(self, sample_json):
        rs = parse_json(sample_json)
        f = rs.files[2]
        assert f.severity is Severity.GREEN
        assert f.rule_name == "KeepNameContainsGreen"
        assert f.matched_string == "credential"
        assert f.match_context == "RoamingCredentialSettings.xml"

    def test_parse_json_file_date_is_utc(self, sample_json):
        rs = parse_json(sample_json)
        dt = rs.files[0].modified_date
        assert isinstance(dt, datetime)
        assert dt.tzinfo is not None


class TestParseJsonShareResult:
    def test_parse_json_share_result_count(self, sample_json):
        rs = parse_json(sample_json)
        assert rs.share_count == 2

    def test_parse_json_share_result_green(self, sample_json):
        rs = parse_json(sample_json)
        s = rs.shares[0]
        assert s.severity is Severity.GREEN
        assert s.share_path == r"\\Etihad-DC01.mancity.local\CertEnroll"
        assert s.can_read is True
        assert s.can_write is False
        assert s.can_modify is False

    def test_parse_json_share_result_black(self, sample_json):
        rs = parse_json(sample_json)
        s = rs.shares[1]
        assert s.severity is Severity.BLACK
        assert s.share_path == r"\\Foden-PC01.mancity.local\ADMIN$"
        assert s.can_read is False
        assert s.can_write is False
        assert s.can_modify is False


class TestParseJsonDirResult:
    def test_parse_json_no_dir_results(self, sample_json):
        rs = parse_json(sample_json)
        assert rs.dir_count == 0


class TestParseJsonSkipsNonResults:
    def test_skips_info_and_error_entries(self, sample_json):
        rs = parse_json(sample_json)
        # 10 entries total: 4 with empty eventProperties (Info/Error/Done/message-only)
        # are silently skipped — no warnings for a clean file
        assert rs.warnings is None

    def test_skips_message_only_file_entries(self, sample_json):
        # Entry 5 has [File] in message but empty eventProperties — must be skipped
        rs = parse_json(sample_json)
        # Only 3 file results with actual eventProperties data
        assert rs.file_count == 3


class TestParseJsonEmptyWarns:
    def test_parse_json_empty_warns(self, tmp_path):
        empty_json = tmp_path / "empty.json"
        empty_json.write_text(json.dumps({"entries": []}), encoding="utf-8")
        rs = parse_json(empty_json)
        assert rs.warnings is not None
        assert len(rs.warnings) > 0

    def test_parse_json_bare_empty_array(self, tmp_path):
        empty_json = tmp_path / "empty.json"
        empty_json.write_text("[]", encoding="utf-8")
        rs = parse_json(empty_json)
        assert rs.warnings is not None


class TestParseJsonFlatFormat:
    """Backward compatibility: flat eventProperties format still works."""

    def test_flat_file_result(self, tmp_path):
        data = {
            "entries": [
                {
                    "eventProperties": {
                        "FileResult": {
                            "FileInfo": {
                                "FullName": "\\\\DC01\\SYSVOL\\login.bat",
                                "Length": 100,
                                "LastWriteTime": "2025-06-15T12:00:00Z",
                            },
                            "TextResult": {
                                "MatchedStrings": ["pass"],
                                "MatchContext": "ctx",
                            },
                            "RwStatus": {
                                "CanRead": True,
                                "CanWrite": False,
                                "CanModify": False,
                            },
                            "MatchedRule": {"RuleName": "Rule", "Triage": "Red"},
                        }
                    }
                }
            ]
        }
        jf = tmp_path / "flat.json"
        jf.write_text(json.dumps(data), encoding="utf-8")
        rs = parse_json(jf)
        assert rs.file_count == 1
        assert rs.files[0].severity is Severity.RED

    def test_flat_share_result(self, tmp_path):
        data = {
            "entries": [
                {
                    "eventProperties": {
                        "ShareResult": {
                            "SharePath": "\\\\FILESVR\\HR$",
                            "RootReadable": True,
                            "RootWritable": True,
                            "RootModifyable": False,
                            "Triage": "Yellow",
                        }
                    }
                }
            ]
        }
        jf = tmp_path / "flat.json"
        jf.write_text(json.dumps(data), encoding="utf-8")
        rs = parse_json(jf)
        assert rs.share_count == 1
        assert rs.shares[0].severity is Severity.YELLOW


class TestParseJsonBareArray:
    """JSON files that are bare arrays (no wrapper object)."""

    def test_bare_array_parses(self, tmp_path):
        data = [
            {
                "time": "2026-03-23 18:16:41",
                "level": "Warn",
                "message": "...",
                "eventProperties": {
                    "Green": {
                        "DateTime": "2026-03-24T01:16:41Z",
                        "Type": "ShareResult",
                        "ShareResult": {
                            "SharePath": "\\\\DC01\\NETLOGON",
                            "Listable": True,
                            "RootWritable": False,
                            "RootReadable": True,
                            "RootModifyable": False,
                            "Triage": "Green",
                        },
                    }
                },
            }
        ]
        jf = tmp_path / "bare.json"
        jf.write_text(json.dumps(data), encoding="utf-8")
        rs = parse_json(jf)
        assert rs.share_count == 1
        assert rs.shares[0].share_path == r"\\DC01\NETLOGON"


class TestDetectFormat:
    def test_detect_format_tsv(self, sample_tsv):
        assert detect_format(sample_tsv) == "tsv"

    def test_detect_format_json_by_extension(self, sample_json):
        assert detect_format(sample_json) == "json"

    def test_detect_format_json_by_content(self, tmp_path):
        f = tmp_path / "noext"
        f.write_text('{"entries": []}', encoding="utf-8")
        assert detect_format(f) == "json"

    def test_detect_format_json_array_by_content(self, tmp_path):
        f = tmp_path / "noext"
        f.write_text("[]\n", encoding="utf-8")
        assert detect_format(f) == "json"

    def test_detect_format_tsv_no_json_extension(self, tmp_path):
        f = tmp_path / "data.tsv"
        f.write_text(
            "[ORG\\user@PC]\t2025-06-15 12:00:00Z\t[File]\tBlack\tKeepPassConfig\tR\n",
            encoding="utf-8",
        )
        assert detect_format(f) == "tsv"


class TestParseAutoDetect:
    def test_parse_auto_tsv(self, sample_tsv):
        rs = parse(sample_tsv)
        assert rs.file_count == 6
        assert rs.share_count == 4
        assert rs.dir_count == 0

    def test_parse_auto_json(self, sample_json):
        rs = parse(sample_json)
        assert rs.file_count == 3
        assert rs.share_count == 2
        assert rs.dir_count == 0

    def test_parse_force_format_tsv(self, sample_tsv):
        rs = parse(sample_tsv, format="tsv")
        assert rs.file_count == 6

    def test_parse_force_format_json(self, sample_json):
        rs = parse(sample_json, format="json")
        assert rs.file_count == 3

    def test_parse_force_format_overrides_extension(self, sample_tsv, tmp_path):
        # A .json extension file whose content is actually TSV — forcing TSV must work
        data = Path(sample_tsv).read_text(encoding="utf-8")
        fake = tmp_path / "data.json"
        fake.write_text(data, encoding="utf-8")
        rs = parse(fake, format="tsv")
        assert rs.file_count == 6


class TestParseIter:
    def test_parse_iter_yields_results_tsv(self, sample_tsv):
        results = list(parse_iter(sample_tsv))
        # 6 files + 4 shares + 0 dirs = 10
        assert len(results) == 10

    def test_parse_iter_result_types_tsv(self, sample_tsv):
        results = list(parse_iter(sample_tsv))
        file_results = [r for r in results if isinstance(r, FileResult)]
        share_results = [r for r in results if isinstance(r, ShareResult)]
        dir_results = [r for r in results if isinstance(r, DirResult)]
        assert len(file_results) == 6
        assert len(share_results) == 4
        assert len(dir_results) == 0

    def test_parse_iter_json(self, sample_json):
        results = list(parse_iter(sample_json))
        # 3 files + 2 shares = 5
        assert len(results) == 5

    def test_parse_iter_is_generator(self, sample_tsv):
        import types

        result = parse_iter(sample_tsv)
        assert isinstance(result, types.GeneratorType)

    def test_parse_iter_lenient_skips_malformed(self, malformed_tsv):
        results = list(parse_iter(malformed_tsv))
        # 2 valid FileResults, rest skipped
        assert len(results) == 2


class TestUnescapeFunction:
    def test_unescape_match_context_newline(self):
        result = _unescape_match_context(r"line1\nline2")
        assert result == "line1\nline2"

    def test_unescape_match_context_tab(self):
        result = _unescape_match_context(r"col1\tcol2")
        assert result == "col1\tcol2"

    def test_unescape_match_context_crlf(self):
        result = _unescape_match_context(r"line1\r\nline2")
        assert result == "line1\r\nline2"

    def test_unescape_match_context_no_escapes(self):
        result = _unescape_match_context("plain text")
        assert result == "plain text"

    def test_unescape_match_context_mixed(self):
        result = _unescape_match_context(r"a\r\nb\nc\td")
        assert result == "a\r\nb\nc\td"

    def test_unescape_escaped_space(self):
        result = _unescape_match_context(r"\$BackupPass\ =\ 'secret'")
        assert result == "$BackupPass = 'secret'"

    def test_unescape_backslash(self):
        result = _unescape_match_context(r"MANCITY\\p\.guardiola")
        assert result == r"MANCITY\p.guardiola"

    def test_unescape_snaffler_real_context(self):
        # Real Snaffler match context with multiple escape types
        raw = r"\$type\ =\ Add-Type\ -PassThru\r\n"
        result = _unescape_match_context(raw)
        assert result == "$type = Add-Type -PassThru\r\n"

    def test_unescape_trailing_backslash(self):
        # Trailing backslash with nothing after it — kept as-is
        result = _unescape_match_context("end\\")
        assert result == "end\\"


class TestParseUnescape:
    def test_parse_tsv_unescape_applies_to_match_context(self, tmp_path):
        # Real Snaffler format with escaped spaces and newlines in match_context
        line = "[MANCITY\\p.foden@Foden-PC01]\t2026-03-24 00:47:19Z\t[File]\tRed\tKeepPsCredentials\tR\t\t\t-SecureString\t416\t2026-03-24 00:04:39Z\t\\\\DC01\\TeamDocs\\script.ps1\t\t\\$BackupPass\\ =\\ 'secret'\\n\n"
        tsv_file = tmp_path / "test.tsv"
        tsv_file.write_text(line, encoding="utf-8")
        rs = parse_tsv(tsv_file, unescape=True)
        assert len(rs.files) == 1
        assert "$BackupPass = 'secret'\n" == rs.files[0].match_context

    def test_parse_tsv_no_unescape_keeps_literal(self, tmp_path):
        line = "[MANCITY\\p.foden@Foden-PC01]\t2026-03-24 00:47:19Z\t[File]\tRed\tKeepPsCredentials\tR\t\t\t-SecureString\t416\t2026-03-24 00:04:39Z\t\\\\DC01\\TeamDocs\\script.ps1\t\t\\$BackupPass\\ =\\ 'secret'\\n\n"
        tsv_file = tmp_path / "test.tsv"
        tsv_file.write_text(line, encoding="utf-8")
        rs = parse_tsv(tsv_file, unescape=False)
        assert r"\$BackupPass" in rs.files[0].match_context

    def test_parse_json_unescape_applies(self, tmp_path):
        entry = {
            "entries": [
                {
                    "eventProperties": {
                        "FileResult": {
                            "FileInfo": {
                                "FullName": "\\\\DC01\\SYSVOL\\login.bat",
                                "Length": 100,
                                "LastWriteTime": "2025-06-15T12:00:00Z",
                            },
                            "TextResult": {
                                "MatchedStrings": ["pass"],
                                "MatchContext": r"line1\nline2",
                            },
                            "RwStatus": {
                                "CanRead": True,
                                "CanWrite": False,
                                "CanModify": False,
                            },
                            "MatchedRule": {"RuleName": "Rule", "Triage": "Green"},
                            "AlternativeFileInfo": {"AlternativeFullFileName": None},
                        }
                    }
                }
            ]
        }
        jf = tmp_path / "test.json"
        jf.write_text(json.dumps(entry), encoding="utf-8")
        rs = parse_json(jf, unescape=True)
        assert "\n" in rs.files[0].match_context


class TestDeduplicate:
    def _make_file(self, path, severity, line=1):
        return FileResult(
            severity=severity,
            rule_name="Rule",
            can_read=True,
            can_write=False,
            can_modify=False,
            matched_string="x",
            file_size=100,
            modified_date=datetime(2025, 1, 1, tzinfo=timezone.utc),
            file_path=path,
            alt_filename=None,
            match_context="ctx",
            source_line=line,
        )

    def test_deduplicate_keeps_highest_severity(self):
        path = r"\\DC01\SYSVOL\login.bat"
        low = self._make_file(path, Severity.YELLOW, line=1)
        high = self._make_file(path, Severity.BLACK, line=2)
        rs_in = __import__("snafflemap.models", fromlist=["ResultSet"]).ResultSet(
            files=[low, high], shares=[], dirs=[]
        )
        rs_out = deduplicate(rs_in)
        assert rs_out.file_count == 1
        assert rs_out.files[0].severity is Severity.BLACK

    def test_deduplicate_unique_paths_unchanged(self):
        f1 = self._make_file(r"\\DC01\SYSVOL\a.bat", Severity.RED, line=1)
        f2 = self._make_file(r"\\DC01\SYSVOL\b.bat", Severity.YELLOW, line=2)
        rs_in = __import__("snafflemap.models", fromlist=["ResultSet"]).ResultSet(
            files=[f1, f2], shares=[], dirs=[]
        )
        rs_out = deduplicate(rs_in)
        assert rs_out.file_count == 2

    def test_deduplicate_shares_pass_through(self):
        s = ShareResult(
            severity=Severity.YELLOW,
            share_path=r"\\FILESVR\HR$",
            can_read=True,
            can_write=False,
            can_modify=False,
            source_line=1,
        )
        rs_in = __import__("snafflemap.models", fromlist=["ResultSet"]).ResultSet(
            files=[], shares=[s, s], dirs=[]
        )
        rs_out = deduplicate(rs_in)
        assert rs_out.share_count == 2

    def test_deduplicate_dirs_pass_through(self):
        d = DirResult(severity=Severity.RED, dir_path=r"\\DC01\SYSVOL", source_line=1)
        rs_in = __import__("snafflemap.models", fromlist=["ResultSet"]).ResultSet(
            files=[], shares=[], dirs=[d, d]
        )
        rs_out = deduplicate(rs_in)
        assert rs_out.dir_count == 2

    def test_deduplicate_three_duplicates_keeps_one(self):
        path = r"\\DC01\SYSVOL\login.bat"
        f1 = self._make_file(path, Severity.GRAY, line=1)
        f2 = self._make_file(path, Severity.BLACK, line=2)
        f3 = self._make_file(path, Severity.RED, line=3)
        rs_in = __import__("snafflemap.models", fromlist=["ResultSet"]).ResultSet(
            files=[f1, f2, f3], shares=[], dirs=[]
        )
        rs_out = deduplicate(rs_in)
        assert rs_out.file_count == 1
        assert rs_out.files[0].severity is Severity.BLACK


class TestParseError:
    def test_parse_error_is_exception(self):
        err = ParseError("something went wrong", line_number=5)
        assert isinstance(err, Exception)
        assert err.line_number == 5

    def test_parse_error_message(self):
        err = ParseError("bad line", line_number=3)
        assert "bad line" in str(err)

    def test_parse_error_no_line_number(self):
        err = ParseError("oops")
        assert err.line_number is None


class TestEncodingAndDetection:
    def test_detect_format_tsv_with_json_like_content(self, tmp_path):
        """TSV line starting with [ should be detected as TSV if it has tabs."""
        f = tmp_path / "tricky.log"
        f.write_text(
            "[MANCITY\\p.foden@Foden-PC01]\t2026-03-24 00:47:19Z\t[File]\tRed\tRuleName\tR\t\t\tkey\t100"
            "\t2026-03-24 00:04:39Z\t\\\\H\\S\\f.txt\t\tcontext\n"
        )
        assert detect_format(f) == "tsv"

    def test_detect_format_json_no_tabs(self, tmp_path):
        """JSON first line has no tabs, starts with { → still detected as JSON."""
        f = tmp_path / "data.log"
        f.write_text('{"entries": []}\n')
        assert detect_format(f) == "json"

    def test_detect_format_survives_encoding_errors(self, tmp_path):
        """File with non-UTF-8 bytes should not crash detect_format."""
        f = tmp_path / "bad.log"
        f.write_bytes(
            b"Black\tRule\tR\t\t\tx\t100\t2025-01-01 00:00:00Z"
            b"\t\\\\H\\S\\f.txt\t\tbad byte \x97 here\n"
        )
        assert detect_format(f) == "tsv"

    def test_parse_tsv_with_non_utf8_bytes(self, tmp_path):
        """TSV file with non-UTF-8 bytes should parse without crashing."""
        f = tmp_path / "nonutf8.tsv"
        f.write_bytes(
            b"[ORG\\user@PC]\t2025-01-01 00:00:00Z\t[File]\tRed\tRuleName\tR\t\t\tkey\t100"
            b"\t2025-01-01 00:00:00Z\t\\\\HOST\\Share\\file.txt\t\tbad \x97 byte\n"
        )
        result = parse(str(f))
        assert result.file_count == 1
        # The 0x97 byte is replaced with U+FFFD
        assert "\ufffd" in result.files[0].match_context

    def test_parse_iter_with_non_utf8_bytes(self, tmp_path):
        """Streaming parser also handles non-UTF-8 bytes."""
        f = tmp_path / "nonutf8.tsv"
        f.write_bytes(
            b"[ORG\\user@PC]\t2025-01-01 00:00:00Z\t[File]\tRed\tRule\tR\t\t\tkey\t100"
            b"\t2025-01-01 00:00:00Z\t\\\\H\\S\\f.txt\t\t\x97\n"
        )
        results = list(parse_iter(str(f)))
        assert len(results) == 1


class TestParseJsonl:
    def test_detect_format_jsonl_by_extension(self, tmp_path):
        f = tmp_path / "x.jsonl"
        f.write_text(
            '{"type":"dir","severity":"Green","dir_path":"\\\\H\\\\S"}\n',
            encoding="utf-8",
        )
        assert detect_format(f) == "jsonl"

    def test_parse_jsonl_counts(self):
        from snafflemap.parsers import parse_jsonl

        rs = parse_jsonl(Path(__file__).parent / "fixtures" / "sample.jsonl")
        assert rs.file_count == 1
        assert rs.share_count == 1
        assert rs.dir_count == 1

    def test_jsonl_round_trip(self, sample_tsv, tmp_path):
        from snafflemap.exporters import jsonl as jsonl_exporter
        from snafflemap.parsers import parse_jsonl

        rs = parse_tsv(sample_tsv)
        out = tmp_path / "rt.jsonl"
        jsonl_exporter.export(rs, str(out))
        rs2 = parse_jsonl(out)
        assert rs2.file_count == rs.file_count
        assert rs2.share_count == rs.share_count
        assert {f.finding_id for f in rs2.files} == {f.finding_id for f in rs.files}
