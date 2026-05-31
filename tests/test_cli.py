from pathlib import Path
from click.testing import CliRunner
from snafflemap.cli import main

FIXTURES = Path(__file__).parent / "fixtures"


def test_cli_help():
    result = CliRunner().invoke(main, ["--help"])
    assert result.exit_code == 0
    assert "INPUT_FILE" in result.output
    assert "Snaffler" in result.output
    # Short flags present
    assert "-f," in result.output
    assert "-o," in result.output
    assert "-s," in result.output
    assert "-v," in result.output
    assert "-q," in result.output
    # Metavar hints present
    assert "LEVELS" in result.output
    assert "PATTERN" in result.output
    assert "SIZE" in result.output
    assert "DATE" in result.output
    assert "KEYS" in result.output
    assert "COLS" in result.output
    # Defaults shown
    assert "default:" in result.output


def test_cli_txt_output(tmp_path):
    result = CliRunner().invoke(
        main,
        [
            str(FIXTURES / "sample.tsv"),
            "--format",
            "txt",
            "--output-dir",
            str(tmp_path),
        ],
    )
    assert result.exit_code == 0
    assert len(list(tmp_path.glob("*.txt"))) == 1


def test_cli_csv_output(tmp_path):
    result = CliRunner().invoke(
        main,
        [
            str(FIXTURES / "sample.tsv"),
            "--format",
            "csv",
            "--output-dir",
            str(tmp_path),
        ],
    )
    assert result.exit_code == 0
    assert len(list(tmp_path.glob("*.csv"))) == 1


def test_cli_html_output(tmp_path):
    result = CliRunner().invoke(
        main,
        [
            str(FIXTURES / "sample.tsv"),
            "--format",
            "html",
            "--output-dir",
            str(tmp_path),
        ],
    )
    assert result.exit_code == 0
    files = list(tmp_path.glob("*.html"))
    assert len(files) == 1
    assert "<script" not in files[0].read_text()


def test_cli_report_output(tmp_path):
    result = CliRunner().invoke(
        main,
        [
            str(FIXTURES / "sample.tsv"),
            "--format",
            "report",
            "--output-dir",
            str(tmp_path),
        ],
    )
    assert result.exit_code == 0
    assert len(list(tmp_path.glob("*.html"))) == 1


def test_cli_json_input(tmp_path):
    result = CliRunner().invoke(
        main,
        [
            str(FIXTURES / "sample.json"),
            "--format",
            "txt",
            "--output-dir",
            str(tmp_path),
        ],
    )
    assert result.exit_code == 0


def test_cli_severity_filter(tmp_path):
    result = CliRunner().invoke(
        main,
        [
            str(FIXTURES / "sample.tsv"),
            "--severity",
            "Black,Red",
            "--format",
            "txt",
            "--output-dir",
            str(tmp_path),
        ],
    )
    assert result.exit_code == 0


def test_cli_format_all(tmp_path):
    result = CliRunner().invoke(
        main,
        [
            str(FIXTURES / "sample.tsv"),
            "--format",
            "all",
            "--output-dir",
            str(tmp_path),
        ],
    )
    assert result.exit_code == 0
    extensions = {p.suffix for p in tmp_path.iterdir()}
    assert ".txt" in extensions
    assert ".csv" in extensions
    assert ".html" in extensions


def test_cli_split(tmp_path):
    result = CliRunner().invoke(
        main,
        [
            str(FIXTURES / "sample.tsv"),
            "--format",
            "txt",
            "--split",
            "--output-dir",
            str(tmp_path),
        ],
    )
    assert result.exit_code == 0
    assert len(list(tmp_path.glob("*.txt"))) > 1


def test_cli_strict_malformed(tmp_path):
    result = CliRunner().invoke(
        main,
        [
            str(FIXTURES / "malformed.tsv"),
            "--strict",
            "--format",
            "txt",
            "--output-dir",
            str(tmp_path),
        ],
    )
    assert result.exit_code != 0


def test_cli_no_dedup(tmp_path):
    result = CliRunner().invoke(
        main,
        [
            str(FIXTURES / "sample.tsv"),
            "--no-dedup",
            "--format",
            "txt",
            "--output-dir",
            str(tmp_path),
        ],
    )
    assert result.exit_code == 0


def test_cli_unescape(tmp_path):
    result = CliRunner().invoke(
        main,
        [
            str(FIXTURES / "sample.tsv"),
            "--unescape",
            "--format",
            "txt",
            "--output-dir",
            str(tmp_path),
        ],
    )
    assert result.exit_code == 0


def test_cli_quiet(tmp_path):
    result = CliRunner().invoke(
        main,
        [
            str(FIXTURES / "sample.tsv"),
            "--quiet",
            "--format",
            "txt",
            "--output-dir",
            str(tmp_path),
        ],
    )
    assert result.exit_code == 0
    assert len(result.output.strip()) == 0


def test_cli_short_flags(tmp_path):
    result = CliRunner().invoke(
        main,
        [
            str(FIXTURES / "sample.tsv"),
            "-f",
            "txt",
            "-o",
            str(tmp_path),
            "-q",
        ],
    )
    assert result.exit_code == 0
    assert len(result.output.strip()) == 0
    assert len(list(tmp_path.glob("*.txt"))) == 1


def test_cli_short_severity_flag(tmp_path):
    result = CliRunner().invoke(
        main,
        [
            str(FIXTURES / "sample.tsv"),
            "-s",
            "Black,Red",
            "-f",
            "txt",
            "-o",
            str(tmp_path),
        ],
    )
    assert result.exit_code == 0


def test_cli_verbose_quiet_together(tmp_path):
    """When both --verbose and --quiet are set, quiet wins."""
    result = CliRunner().invoke(
        main,
        [
            str(FIXTURES / "sample.tsv"),
            "-v",
            "-q",
            "-f",
            "txt",
            "-o",
            str(tmp_path),
        ],
    )
    assert result.exit_code == 0
    assert len(result.output.strip()) == 0


def test_cli_bad_size_min(tmp_path):
    result = CliRunner().invoke(
        main,
        [
            str(FIXTURES / "sample.tsv"),
            "--size-min",
            "abc",
            "-f",
            "txt",
            "-o",
            str(tmp_path),
        ],
    )
    assert result.exit_code != 0


def test_cli_bad_date(tmp_path):
    result = CliRunner().invoke(
        main,
        [
            str(FIXTURES / "sample.tsv"),
            "--date-after",
            "not-a-date",
            "-f",
            "txt",
            "-o",
            str(tmp_path),
        ],
    )
    assert result.exit_code != 0


def test_cli_snippet_width_ignored_warning(tmp_path):
    """--snippet-width warns when format is not txt."""
    result = CliRunner().invoke(
        main,
        [
            str(FIXTURES / "sample.tsv"),
            "--snippet-width",
            "40",
            "-f",
            "csv",
            "-o",
            str(tmp_path),
        ],
    )
    assert result.exit_code == 0
    assert "snippet-width" in result.output


def test_cli_split_report_warning(tmp_path):
    """--split with report format warns that it's ignored."""
    result = CliRunner().invoke(
        main,
        [
            str(FIXTURES / "sample.tsv"),
            "--split",
            "-f",
            "report",
            "-o",
            str(tmp_path),
        ],
    )
    assert result.exit_code == 0
    assert "split" in result.output.lower()


def test_cli_split_txt_no_warning(tmp_path):
    """--split with txt format should NOT warn."""
    result = CliRunner().invoke(
        main,
        [
            str(FIXTURES / "sample.tsv"),
            "--split",
            "-f",
            "txt",
            "-o",
            str(tmp_path),
        ],
    )
    assert result.exit_code == 0
    assert "not supported" not in result.output


def test_full_pipeline_tsv(tmp_path):
    result = CliRunner().invoke(
        main,
        [
            str(FIXTURES / "sample.tsv"),
            "--format",
            "all",
            "--severity",
            "Black,Red,Yellow",
            "--sort-by",
            "severity,modified",
            "--output-dir",
            str(tmp_path),
        ],
    )
    assert result.exit_code == 0
    assert (tmp_path / "sample.txt").exists()
    assert (tmp_path / "sample.csv").exists()
    assert (tmp_path / "sample.html").exists()
    assert (tmp_path / "sample-report.html").exists()


def test_full_pipeline_json_input(tmp_path):
    result = CliRunner().invoke(
        main,
        [
            str(FIXTURES / "sample.json"),
            "--format",
            "report",
            "--output-dir",
            str(tmp_path),
        ],
    )
    assert result.exit_code == 0
    report_file = tmp_path / "sample-report.html"
    assert report_file.exists()
    content = report_file.read_text()
    assert 'id="sm-app"' in content
    assert "KeepPsCredentials" in content


class TestJsonlFormat:
    def test_format_jsonl_writes_file(self, sample_tsv, tmp_path):
        from click.testing import CliRunner

        from snafflemap.cli import main

        runner = CliRunner()
        result = runner.invoke(
            main, [str(sample_tsv), "-f", "jsonl", "-o", str(tmp_path)]
        )
        assert result.exit_code == 0
        out = tmp_path / "sample.jsonl"
        assert out.exists()
        assert out.read_text(encoding="utf-8").strip()


class TestMultiFile:
    def test_two_files_merge_into_one_report(self, sample_tsv, tmp_path):
        from click.testing import CliRunner

        from snafflemap.cli import main

        runner = CliRunner()
        result = runner.invoke(
            main,
            [
                str(sample_tsv),
                str(sample_tsv),
                "-f",
                "jsonl",
                "-o",
                str(tmp_path),
                "-n",
                "engagement",
            ],
        )
        assert result.exit_code == 0
        out = tmp_path / "engagement.jsonl"
        assert out.exists()
        # Same file twice => findings dedup by id, so line count == single-file count
        runner.invoke(
            main,
            [str(sample_tsv), "-f", "jsonl", "-o", str(tmp_path), "-n", "single"],
        )
        single = tmp_path / "single.jsonl"
        merged_lines = [ln for ln in out.read_text().splitlines() if ln.strip()]
        single_lines = [ln for ln in single.read_text().splitlines() if ln.strip()]
        assert len(merged_lines) == len(single_lines)

    def test_no_input_files_errors(self, tmp_path):
        from click.testing import CliRunner

        from snafflemap.cli import main

        runner = CliRunner()
        result = runner.invoke(main, ["-f", "txt", "-o", str(tmp_path)])
        assert result.exit_code != 0


class TestFailOn:
    def test_fail_on_triggers_exit_2(self, sample_tsv, tmp_path):
        from click.testing import CliRunner

        from snafflemap.cli import main

        runner = CliRunner()
        # sample.tsv contains Black findings
        result = runner.invoke(
            main,
            [str(sample_tsv), "-f", "txt", "-o", str(tmp_path), "--fail-on", "Black"],
        )
        assert result.exit_code == 2

    def test_fail_on_not_triggered_exit_0(self, sample_tsv, tmp_path):
        from click.testing import CliRunner

        from snafflemap.cli import main

        runner = CliRunner()
        # Keep only Green, then gate on Black — nothing should trip it
        result = runner.invoke(
            main,
            [
                str(sample_tsv),
                "-f",
                "txt",
                "-o",
                str(tmp_path),
                "--severity",
                "Green",
                "--fail-on",
                "Black",
            ],
        )
        assert result.exit_code == 0


class TestFailOnValidation:
    def test_invalid_fail_on_level_exits_1_cleanly(self, sample_tsv, tmp_path):
        from click.testing import CliRunner

        from snafflemap.cli import main

        runner = CliRunner()
        result = runner.invoke(
            main,
            [str(sample_tsv), "-f", "txt", "-o", str(tmp_path), "--fail-on", "Purple"],
        )
        assert result.exit_code == 1
        assert (
            "invalid --fail-on" in result.output.lower()
            or "unknown severity" in result.output.lower()
        )
        # Must not leak a raw traceback
        assert "Traceback" not in result.output


class TestParseErrorExit:
    def test_strict_parse_error_exits_1(self, malformed_tsv, tmp_path):
        from click.testing import CliRunner

        from snafflemap.cli import main

        runner = CliRunner()
        result = runner.invoke(
            main, [str(malformed_tsv), "-f", "txt", "-o", str(tmp_path), "--strict"]
        )
        assert result.exit_code == 1


class TestEnrichmentCli:
    def test_jsonl_has_enrichment_by_default(self, sample_tsv, tmp_path):
        from click.testing import CliRunner

        from snafflemap.cli import main

        runner = CliRunner()
        result = runner.invoke(
            main, [str(sample_tsv), "-f", "jsonl", "-o", str(tmp_path), "-n", "e"]
        )
        assert result.exit_code == 0
        import json

        lines = [
            ln for ln in (tmp_path / "e.jsonl").read_text().splitlines() if ln.strip()
        ]
        rec = json.loads(lines[0])
        assert "enrichment" in rec and "score" in rec["enrichment"]

    def test_min_score_filters(self, sample_tsv, tmp_path):
        from click.testing import CliRunner

        from snafflemap.cli import main

        runner = CliRunner()
        # A very high threshold should drop everything -> empty jsonl
        result = runner.invoke(
            main,
            [
                str(sample_tsv),
                "-f",
                "jsonl",
                "-o",
                str(tmp_path),
                "-n",
                "hi",
                "--min-score",
                "999",
            ],
        )
        assert result.exit_code == 0
        body = (tmp_path / "hi.jsonl").read_text().strip()
        assert body == ""

    def test_invalid_tier_exits_1(self, sample_tsv, tmp_path):
        from click.testing import CliRunner

        from snafflemap.cli import main

        runner = CliRunner()
        result = runner.invoke(
            main, [str(sample_tsv), "-f", "txt", "-o", str(tmp_path), "--tier", "Bogus"]
        )
        assert result.exit_code == 1

    def test_bad_catalog_exits_1(self, sample_tsv, tmp_path):
        from click.testing import CliRunner

        from snafflemap.cli import main

        bad = tmp_path / "bad.toml"
        bad.write_text('[[detector]]\nid = "x"\n', encoding="utf-8")  # missing fields
        runner = CliRunner()
        result = runner.invoke(
            main,
            [str(sample_tsv), "-f", "txt", "-o", str(tmp_path), "--catalog", str(bad)],
        )
        assert result.exit_code == 1


class TestTriageCli:
    def test_triage_seed_baked_into_report(self, sample_tsv, tmp_path):
        import json
        import re

        from click.testing import CliRunner

        from snafflemap.cli import main
        from snafflemap.parsers import parse_tsv
        from snafflemap.triage import SCHEMA

        # Build a triage sidecar referencing the first file finding's id
        rs = parse_tsv(sample_tsv)
        fid = rs.files[0].finding_id
        sidecar = {
            "schema": SCHEMA,
            "report_name": "eng",
            "exported_at": "t",
            "triage": {fid: {"status": "confirmed-loot", "updated_at": "t"}},
            "suppressions": [],
        }
        tj = tmp_path / "t.json"
        tj.write_text(json.dumps(sidecar), encoding="utf-8")

        runner = CliRunner()
        result = runner.invoke(
            main,
            [
                str(sample_tsv),
                "-f",
                "report",
                "-o",
                str(tmp_path),
                "-n",
                "eng",
                "--triage",
                str(tj),
            ],
        )
        assert result.exit_code == 0
        html = (tmp_path / "eng-report.html").read_text(encoding="utf-8")
        m = re.search(
            r'<script id="sm-data" type="application/json">(.*?)</script>', html, re.S
        )
        data = json.loads(m.group(1))
        assert data["triage"][fid]["status"] == "confirmed-loot"

    def test_bad_triage_file_exits_1(self, sample_tsv, tmp_path):
        from click.testing import CliRunner

        from snafflemap.cli import main

        bad = tmp_path / "bad.json"
        bad.write_text("{not json", encoding="utf-8")
        runner = CliRunner()
        result = runner.invoke(
            main,
            [
                str(sample_tsv),
                "-f",
                "report",
                "-o",
                str(tmp_path),
                "--triage",
                str(bad),
            ],
        )
        assert result.exit_code == 1


class TestDeltaCli:
    def _baseline(self, sample_tsv, tmp_path):
        from click.testing import CliRunner

        from snafflemap.cli import main

        runner = CliRunner()
        runner.invoke(
            main, [str(sample_tsv), "-f", "jsonl", "-o", str(tmp_path), "-n", "base"]
        )
        return tmp_path / "base.jsonl"

    def test_delta_annotates_jsonl(self, sample_tsv, tmp_path):
        import json

        from click.testing import CliRunner

        from snafflemap.cli import main

        base = self._baseline(sample_tsv, tmp_path)
        runner = CliRunner()
        # same input vs its own baseline -> everything persisted, nothing new
        result = runner.invoke(
            main,
            [
                str(sample_tsv),
                "-f",
                "jsonl",
                "-o",
                str(tmp_path),
                "-n",
                "cur",
                "--delta",
                str(base),
            ],
        )
        assert result.exit_code == 0
        recs = [
            json.loads(line)
            for line in (tmp_path / "cur.jsonl").read_text().splitlines()
            if line.strip()
        ]
        assert recs and all(r.get("delta_status") == "persisted" for r in recs)

    def test_delta_only_new_filters(self, sample_tsv, tmp_path):
        from click.testing import CliRunner

        from snafflemap.cli import main

        base = self._baseline(sample_tsv, tmp_path)
        runner = CliRunner()
        result = runner.invoke(
            main,
            [
                str(sample_tsv),
                "-f",
                "jsonl",
                "-o",
                str(tmp_path),
                "-n",
                "newonly",
                "--delta",
                str(base),
                "--delta-only",
                "new",
            ],
        )
        assert result.exit_code == 0
        body = (tmp_path / "newonly.jsonl").read_text().strip()
        # nothing is new (same scan) -> empty current set
        assert body == ""

    def test_delta_only_without_delta_exits_1(self, sample_tsv, tmp_path):
        from click.testing import CliRunner

        from snafflemap.cli import main

        runner = CliRunner()
        result = runner.invoke(
            main,
            [str(sample_tsv), "-f", "txt", "-o", str(tmp_path), "--delta-only", "new"],
        )
        assert result.exit_code == 1

    def test_delta_summary_on_stderr(self, sample_tsv, tmp_path):
        from click.testing import CliRunner

        from snafflemap.cli import main

        base = self._baseline(sample_tsv, tmp_path)
        runner = CliRunner()
        result = runner.invoke(
            main,
            [
                str(sample_tsv),
                "-f",
                "txt",
                "-o",
                str(tmp_path),
                "-n",
                "sum",
                "--delta",
                str(base),
            ],
        )
        assert result.exit_code == 0
        assert "persisted" in result.output.lower()


class TestEvidenceCli:
    def test_evidence_format_writes_md_and_html(self, sample_tsv, tmp_path):
        from click.testing import CliRunner

        from snafflemap.cli import main

        runner = CliRunner()
        result = runner.invoke(
            main, [str(sample_tsv), "-f", "evidence", "-o", str(tmp_path), "-n", "ev"]
        )
        assert result.exit_code == 0
        assert (tmp_path / "ev.md").exists()
        assert (tmp_path / "ev.html").exists()

    def test_evidence_excluded_from_all(self, sample_tsv, tmp_path):
        from click.testing import CliRunner

        from snafflemap.cli import main

        runner = CliRunner()
        runner.invoke(
            main, [str(sample_tsv), "-f", "all", "-o", str(tmp_path), "-n", "a"]
        )
        # 'all' must NOT produce evidence
        assert not (tmp_path / "a.md").exists()

    def test_redact_full_masks(self, sample_tsv, tmp_path):
        from click.testing import CliRunner

        from snafflemap.cli import main

        runner = CliRunner()
        runner.invoke(
            main,
            [
                str(sample_tsv),
                "-f",
                "evidence",
                "-o",
                str(tmp_path),
                "-n",
                "red",
                "--redact",
                "full",
            ],
        )
        md = (tmp_path / "red.md").read_text(encoding="utf-8")
        # No raw cpassword-style secret leaks; [REDACTED] appears if any creds were extracted
        assert "edBSHOw" not in md
