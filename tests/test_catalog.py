"""Tests for the detection/extraction catalog."""

from __future__ import annotations

from datetime import datetime, timezone

from snafflemap.analysis.catalog import builtin_catalog
from snafflemap.analysis.classify import classify
from snafflemap.analysis.credentials import extract_credentials
from snafflemap.models import FileResult, Severity


def _file(path, ctx="", matched=""):
    return FileResult(
        severity=Severity.BLACK,
        rule_name="R",
        can_read=True,
        can_write=False,
        can_modify=False,
        matched_string=matched,
        file_size=1,
        modified_date=datetime(2025, 1, 1, tzinfo=timezone.utc),
        file_path=path,
        alt_filename=None,
        match_context=ctx,
        source_line=1,
    )


def test_builtin_catalog_nonempty_and_valid():
    cat = builtin_catalog()
    assert len(cat.detectors) >= 15
    assert len(cat.extractors) >= 6
    # ids are unique
    ids = [d.id for d in cat.detectors]
    assert len(ids) == len(set(ids))
    # every detector has at least one signal source
    for d in cat.detectors:
        assert d.filename_patterns or d.ext or d.path_patterns or d.rule_names
    # every extractor regex contains a 'secret' named group
    for e in cat.extractors:
        assert "(?P<secret>" in e.regex


def test_gpp_cpassword_detected_and_extracted():
    cat = builtin_catalog()
    f = _file(r"\\DC\SYSVOL\dom\Groups.xml", ctx='cpassword="edBSHOw"')
    hits = classify(f, cat.detectors)
    assert any(h.id == "gpp-cpassword" for h in hits)
    creds = extract_credentials(f, cat.extractors)
    assert any(c.type == "gpp-cpassword" for c in creds)


def test_kdbx_detected():
    cat = builtin_catalog()
    hits = classify(_file(r"\\H\S\secrets.kdbx"), cat.detectors)
    assert any(h.id == "kdbx" for h in hits)


def test_aws_key_extracted():
    cat = builtin_catalog()
    f = _file(r"\\H\S\creds.txt", ctx="AKIAIOSFODNN7EXAMPLE")
    creds = extract_credentials(f, cat.extractors)
    assert any(c.type == "aws-access-key" for c in creds)


class TestLoadCatalog:
    def test_merges_and_adds_custom_detector(self, tmp_path):
        from snafflemap.analysis.catalog import load_catalog

        toml = tmp_path / "c.toml"
        toml.write_text(
            "[[detector]]\n"
            'id = "my-thing"\n'
            'label = "Custom"\n'
            'category = "credentials"\n'
            'why = "w"\n'
            'action = "a"\n'
            'ext = [".myz"]\n'
            "weight = 21\n"
            "\n"
            "[[extractor]]\n"
            'id = "my-token"\n'
            'type = "custom-token"\n'
            'regex = "Tok_(?P<secret>[A-Z0-9]+)"\n',
            encoding="utf-8",
        )
        cat = load_catalog(toml)
        ids = {d.id for d in cat.detectors}
        assert "my-thing" in ids
        assert "gpp-cpassword" in ids  # built-ins still present
        assert any(e.id == "my-token" for e in cat.extractors)

    def test_same_id_overrides_builtin(self, tmp_path):
        from snafflemap.analysis.catalog import load_catalog

        toml = tmp_path / "c.toml"
        toml.write_text(
            "[[detector]]\n"
            'id = "kdbx"\n'
            'label = "Overridden"\n'
            'category = "credentials"\n'
            'why = "w"\n'
            'action = "a"\n'
            'ext = [".kdbx"]\n',
            encoding="utf-8",
        )
        cat = load_catalog(toml)
        kdbx = [d for d in cat.detectors if d.id == "kdbx"]
        assert len(kdbx) == 1
        assert kdbx[0].label == "Overridden"

    def test_invalid_catalog_raises_value_error(self, tmp_path):
        from snafflemap.analysis.catalog import CatalogError, load_catalog

        toml = tmp_path / "bad.toml"
        # detector missing required 'action'
        toml.write_text(
            '[[detector]]\nid = "x"\nlabel = "X"\ncategory = "config"\nwhy = "w"\n',
            encoding="utf-8",
        )
        import pytest

        with pytest.raises(CatalogError):
            load_catalog(toml)
