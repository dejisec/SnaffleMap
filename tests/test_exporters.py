"""Tests for TXT, CSV, and JSON exporters."""

from __future__ import annotations

import csv
from datetime import datetime, timezone


from snafflemap.models import FileResult, ShareResult, DirResult, ResultSet, Severity


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _fr(
    severity=Severity.RED,
    rule="Rule1",
    path=r"\\H\S\file.txt",
    size=1024,
    context="some context",
):
    return FileResult(
        severity=severity,
        rule_name=rule,
        can_read=True,
        can_write=False,
        can_modify=False,
        matched_string="match",
        file_size=size,
        modified_date=datetime(2025, 6, 1, tzinfo=timezone.utc),
        file_path=path,
        alt_filename=None,
        match_context=context,
        source_line=1,
    )


def _sample_rs():
    return ResultSet(
        files=[_fr(Severity.BLACK), _fr(Severity.RED), _fr(Severity.GREEN)],
        shares=[ShareResult(Severity.YELLOW, r"\\H\Share", True, False, False, 1)],
        dirs=[DirResult(Severity.GREEN, r"\\H\Dir", 1)],
    )


# ---------------------------------------------------------------------------
# TXT Exporter Tests
# ---------------------------------------------------------------------------


class TestTxtExporter:
    def test_export_creates_file(self, tmp_path):
        from snafflemap.exporters.txt import export

        out = tmp_path / "report.txt"
        export(_sample_rs(), out)
        assert out.exists()
        assert out.stat().st_size > 0

    def test_contains_severity_section_headers(self, tmp_path):
        from snafflemap.exporters.txt import export

        out = tmp_path / "report.txt"
        export(_sample_rs(), out)
        content = out.read_text(encoding="utf-8")

        # Should have section headers for severities that have file results
        assert "Black" in content
        assert "Red" in content
        assert "Green" in content

        # Should have "=" separator lines
        assert "=" * 10 in content or "=" * 5 in content  # some = line exists

    def test_contains_share_section(self, tmp_path):
        from snafflemap.exporters.txt import export

        out = tmp_path / "report.txt"
        export(_sample_rs(), out)
        content = out.read_text(encoding="utf-8")

        assert "SHARES" in content
        # Share path should appear
        assert r"\\H\Share" in content

    def test_contains_directories_section(self, tmp_path):
        from snafflemap.exporters.txt import export

        out = tmp_path / "report.txt"
        export(_sample_rs(), out)
        content = out.read_text(encoding="utf-8")

        assert "DIRECTORIES" in content or "DIR" in content

    def test_snippet_truncation(self, tmp_path):
        from snafflemap.exporters.txt import export

        long_context = "A" * 100
        rs = ResultSet(
            files=[_fr(context=long_context)],
            shares=[],
            dirs=[],
        )
        out = tmp_path / "report.txt"
        export(rs, out, snippet_width=20)
        content = out.read_text(encoding="utf-8")

        # The snippet should be truncated and end with "..."
        assert "A" * 20 in content
        assert "..." in content
        # Full long string should not appear
        assert "A" * 100 not in content

    def test_file_size_human_readable(self, tmp_path):
        from snafflemap.exporters.txt import export

        rs = ResultSet(
            files=[
                _fr(size=500),  # 500 B
                _fr(size=2048),  # 2.0 KB
                _fr(size=1048576),  # 1.0 MB
            ],
            shares=[],
            dirs=[],
        )
        out = tmp_path / "report.txt"
        export(rs, out)
        content = out.read_text(encoding="utf-8")

        assert "B" in content  # some size unit present
        assert "KB" in content or "MB" in content

    def test_perms_flags(self, tmp_path):
        from snafflemap.exporters.txt import export

        fr = FileResult(
            severity=Severity.RED,
            rule_name="R1",
            can_read=True,
            can_write=True,
            can_modify=False,
            matched_string="x",
            file_size=100,
            modified_date=datetime(2025, 1, 1, tzinfo=timezone.utc),
            file_path=r"\\H\S\f.txt",
            alt_filename=None,
            match_context="ctx",
            source_line=1,
        )
        rs = ResultSet(files=[fr], shares=[], dirs=[])
        out = tmp_path / "report.txt"
        export(rs, out)
        content = out.read_text(encoding="utf-8")
        # R and W flags set, M not set
        assert "RW" in content

    def test_utf8_encoding(self, tmp_path):
        from snafflemap.exporters.txt import export

        fr = _fr(context="caf\u00e9 p\u00e0ssword")
        rs = ResultSet(files=[fr], shares=[], dirs=[])
        out = tmp_path / "report.txt"
        export(rs, out)
        content = out.read_bytes()
        # Should decode fine as UTF-8
        text = content.decode("utf-8")
        assert "caf" in text


# ---------------------------------------------------------------------------
# CSV Exporter Tests
# ---------------------------------------------------------------------------


class TestCsvExporter:
    def test_export_creates_file(self, tmp_path):
        from snafflemap.exporters.csv_export import export

        out = tmp_path / "report.csv"
        export(_sample_rs(), out)
        assert out.exists()
        assert out.stat().st_size > 0

    def test_header_and_row_count(self, tmp_path):
        from snafflemap.exporters.csv_export import export

        out = tmp_path / "report.csv"
        export(_sample_rs(), out)

        with open(out, encoding="utf-8-sig", newline="") as f:
            reader = csv.DictReader(f)
            rows = list(reader)

        # 3 files + 1 share + 1 dir = 5 data rows
        assert len(rows) == 5

        # Header columns must include union schema
        expected_cols = {
            "type",
            "severity",
            "rule_name",
            "can_read",
            "can_write",
            "can_modify",
            "matched_string",
            "file_size",
            "modified_date",
            "file_path",
            "alt_filename",
            "match_context",
            "hostname",
            "share_name",
            "extension",
            "source_line",
        }
        assert expected_cols.issubset(set(reader.fieldnames or []))

    def test_file_row_derived_fields(self, tmp_path):
        from snafflemap.exporters.csv_export import export

        rs = ResultSet(
            files=[_fr(path=r"\\MYHOST\MyShare\data.txt")],
            shares=[],
            dirs=[],
        )
        out = tmp_path / "report.csv"
        export(rs, out)

        with open(out, encoding="utf-8-sig", newline="") as f:
            reader = csv.DictReader(f)
            rows = list(reader)

        assert len(rows) == 1
        row = rows[0]
        assert row["type"] == "file"
        assert row["hostname"] == "MYHOST"
        assert row["share_name"] == "MyShare"
        assert row["extension"] == ".txt"

    def test_share_row_empty_file_fields(self, tmp_path):
        from snafflemap.exporters.csv_export import export

        rs = ResultSet(
            files=[],
            shares=[ShareResult(Severity.YELLOW, r"\\H\Share", True, False, False, 1)],
            dirs=[],
        )
        out = tmp_path / "report.csv"
        export(rs, out)

        with open(out, encoding="utf-8-sig", newline="") as f:
            reader = csv.DictReader(f)
            rows = list(reader)

        assert len(rows) == 1
        row = rows[0]
        assert row["type"] == "share"
        assert row["severity"] == "Yellow"
        # File-specific fields should be empty
        assert row["rule_name"] == ""
        assert row["file_size"] == ""
        assert row["extension"] == ""
        assert row["match_context"] == ""

    def test_dir_row(self, tmp_path):
        from snafflemap.exporters.csv_export import export

        rs = ResultSet(
            files=[],
            shares=[],
            dirs=[DirResult(Severity.GREEN, r"\\H\Dir", 1)],
        )
        out = tmp_path / "report.csv"
        export(rs, out)

        with open(out, encoding="utf-8-sig", newline="") as f:
            reader = csv.DictReader(f)
            rows = list(reader)

        assert len(rows) == 1
        row = rows[0]
        assert row["type"] == "dir"
        assert row["file_path"] == r"\\H\Dir"
        assert row["severity"] == "Green"

    def test_file_row_modified_date_iso(self, tmp_path):
        from snafflemap.exporters.csv_export import export

        rs = ResultSet(files=[_fr()], shares=[], dirs=[])
        out = tmp_path / "report.csv"
        export(rs, out)

        with open(out, encoding="utf-8-sig", newline="") as f:
            reader = csv.DictReader(f)
            rows = list(reader)

        # modified_date should be ISO 8601 format
        assert "2025-06-01" in rows[0]["modified_date"]

    def test_utf8_bom_encoding(self, tmp_path):
        from snafflemap.exporters.csv_export import export

        out = tmp_path / "report.csv"
        export(_sample_rs(), out)

        raw = out.read_bytes()
        # UTF-8 BOM: EF BB BF
        assert raw[:3] == b"\xef\xbb\xbf"


# ---------------------------------------------------------------------------
# HTML Exporter Tests
# ---------------------------------------------------------------------------


class TestHtmlExporter:
    def test_export_creates_file(self, tmp_path):
        from snafflemap.exporters.html import export

        out = tmp_path / "output.html"
        export(_sample_rs(), str(out))
        assert out.exists()
        content = out.read_text()
        assert len(content) > 0

    def test_export_contains_html_structure(self, tmp_path):
        from snafflemap.exporters.html import export

        out = tmp_path / "output.html"
        export(_sample_rs(), str(out))
        content = out.read_text()
        assert "<html" in content
        assert "<table" in content
        assert "</html>" in content

    def test_export_contains_severity_colors(self, tmp_path):
        from snafflemap.exporters.html import export

        out = tmp_path / "output.html"
        export(_sample_rs(), str(out))
        content = out.read_text()
        assert "Black" in content
        assert "Red" in content

    def test_export_no_javascript(self, tmp_path):
        from snafflemap.exporters.html import export

        out = tmp_path / "output.html"
        export(_sample_rs(), str(out))
        content = out.read_text()
        assert "<script" not in content


# ---------------------------------------------------------------------------
# Report Exporter Tests
# ---------------------------------------------------------------------------


class TestReportExporter:
    def test_export_creates_file(self, tmp_path):
        from snafflemap.exporters.report import export

        out = tmp_path / "report.html"
        export(_sample_rs(), str(out))
        assert out.exists()

    def test_export_self_contained(self, tmp_path):
        from snafflemap.exporters.report import export

        out = tmp_path / "report.html"
        export(_sample_rs(), str(out))
        content = out.read_text()
        assert "<style" in content
        assert "<script" in content
        assert 'src="http' not in content
        assert 'href="http' not in content

    def test_export_has_dashboard(self, tmp_path):
        from snafflemap.exporters.report import export

        out = tmp_path / "report.html"
        export(_sample_rs(), str(out))
        content = out.read_text()
        assert "Total" in content or "total" in content

    def test_export_has_tabs(self, tmp_path):
        from snafflemap.exporters.report import export

        out = tmp_path / "report.html"
        export(_sample_rs(), str(out))
        content = out.read_text()
        assert "severity" in content.lower()
        assert "host" in content.lower()

    def test_export_has_review_checkboxes(self, tmp_path):
        from snafflemap.exporters.report import export

        out = tmp_path / "report.html"
        export(_sample_rs(), str(out))
        content = out.read_text()
        assert 'type="checkbox"' in content

    def test_export_has_search(self, tmp_path):
        from snafflemap.exporters.report import export

        out = tmp_path / "report.html"
        export(_sample_rs(), str(out))
        content = out.read_text()
        assert "search" in content.lower() or "filter" in content.lower()

    def test_export_has_file_links(self, tmp_path):
        from snafflemap.exporters.report import export

        out = tmp_path / "report.html"
        export(_sample_rs(), str(out))
        content = out.read_text()
        assert "file://" in content

    def test_export_has_save_button(self, tmp_path):
        from snafflemap.exporters.report import export

        out = tmp_path / "report.html"
        export(_sample_rs(), str(out))
        content = out.read_text()
        assert "save" in content.lower() or "Save" in content

    def test_export_has_dark_mode(self, tmp_path):
        from snafflemap.exporters.report import export

        out = tmp_path / "report.html"
        export(_sample_rs(), str(out))
        content = out.read_text()
        assert "dark" in content.lower()

    def test_export_has_svg_chart(self, tmp_path):
        from snafflemap.exporters.report import export

        out = tmp_path / "report.html"
        export(_sample_rs(), str(out))
        content = out.read_text()
        assert "<svg" in content
