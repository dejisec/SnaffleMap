"""Tests for the evidence-pack exporter."""

from __future__ import annotations

from datetime import datetime, timezone

from snafflemap.analysis.catalog import builtin_catalog
from snafflemap.analysis.enrich import enrich
from snafflemap.exporters import evidence
from snafflemap.exporters.evidence import redact_secret
from snafflemap.models import FileResult, ResultSet, Severity


def _gpp():
    f = FileResult(
        severity=Severity.BLACK,
        rule_name="KeepX",
        can_read=True,
        can_write=False,
        can_modify=False,
        matched_string="P@ssw0rd!",
        file_size=1,
        modified_date=datetime(2025, 1, 1, tzinfo=timezone.utc),
        file_path=r"\\DC\SYSVOL\Groups.xml",
        alt_filename=None,
        match_context='cpassword="edBSHOwx"',
        source_line=1,
    )
    return f


class TestRedact:
    def test_none_passthrough(self):
        assert redact_secret("P@ssw0rd!", "none") == "P@ssw0rd!"

    def test_full(self):
        assert redact_secret("P@ssw0rd!", "full") == "[REDACTED]"

    def test_partial(self):
        assert redact_secret("P@ssw0rd!", "partial") == "P@…d!"

    def test_partial_short(self):
        assert redact_secret("ab", "partial") == "…"


class TestEvidence:
    def _render(self, tmp_path, redact="none"):
        f = _gpp()
        rs = ResultSet(files=[f], shares=[], dirs=[])
        enr = enrich(
            rs, builtin_catalog(), now=datetime(2026, 1, 1, tzinfo=timezone.utc)
        )
        out = tmp_path / "evidence.md"
        evidence.export(rs, str(out), enrichment=enr, redact=redact)
        return f, out

    def test_markdown_sections(self, tmp_path):
        f, out = self._render(tmp_path)
        md = out.read_text(encoding="utf-8")
        assert "Groups.xml" in md
        assert "Black" in md
        assert f.finding_id in md
        assert "Remediation" in md
        # sibling print-ready html is written too
        assert (tmp_path / "evidence.html").exists()
        # context block renders when context differs from matched string
        assert "Context" in md

    def test_redaction_full_masks_secret(self, tmp_path):
        f, out = self._render(tmp_path, redact="full")
        md = out.read_text(encoding="utf-8")
        assert "P@ssw0rd!" not in md
        assert "[REDACTED]" in md
        html = (tmp_path / "evidence.html").read_text(encoding="utf-8")
        assert "P@ssw0rd!" not in html
        assert "[REDACTED]" in html

    def test_split_writes_per_finding(self, tmp_path):
        f = _gpp()
        rs = ResultSet(files=[f], shares=[], dirs=[])
        enr = enrich(
            rs, builtin_catalog(), now=datetime(2026, 1, 1, tzinfo=timezone.utc)
        )
        out = tmp_path / "evidence.md"
        evidence.export(rs, str(out), enrichment=enr, split=True)
        per = tmp_path / "evidence" / f"{f.finding_id}.md"
        assert per.exists()
        assert "Groups.xml" in per.read_text(encoding="utf-8")
