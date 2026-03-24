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
            "-f", "txt",
            "-o", str(tmp_path),
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
            "-s", "Black,Red",
            "-f", "txt",
            "-o", str(tmp_path),
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
            "-f", "txt",
            "-o", str(tmp_path),
        ],
    )
    assert result.exit_code == 0
    assert len(result.output.strip()) == 0


def test_cli_bad_size_min(tmp_path):
    result = CliRunner().invoke(
        main,
        [
            str(FIXTURES / "sample.tsv"),
            "--size-min", "abc",
            "-f", "txt",
            "-o", str(tmp_path),
        ],
    )
    assert result.exit_code != 0


def test_cli_bad_date(tmp_path):
    result = CliRunner().invoke(
        main,
        [
            str(FIXTURES / "sample.tsv"),
            "--date-after", "not-a-date",
            "-f", "txt",
            "-o", str(tmp_path),
        ],
    )
    assert result.exit_code != 0


def test_cli_snippet_width_ignored_warning(tmp_path):
    """--snippet-width warns when format is not txt."""
    result = CliRunner().invoke(
        main,
        [
            str(FIXTURES / "sample.tsv"),
            "--snippet-width", "40",
            "-f", "csv",
            "-o", str(tmp_path),
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
            "-f", "report",
            "-o", str(tmp_path),
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
            "-f", "txt",
            "-o", str(tmp_path),
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
    assert "<svg" in content
    assert "KeepPsCredentials" in content
