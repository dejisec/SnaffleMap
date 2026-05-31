"""Tests for credential extractors."""

from __future__ import annotations

from datetime import datetime, timezone

from snafflemap.analysis.credentials import extract_credentials
from snafflemap.analysis.models import Extractor
from snafflemap.models import FileResult, Severity, ShareResult


def _file(matched="", ctx="", path=r"\\H\S\f", sources=("run.tsv",)):
    return FileResult(
        severity=Severity.RED,
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
        sources=sources,
    )


PWD = Extractor(
    id="pwd",
    type="password-assignment",
    regex=r"(?i)password\s*=\s*(?P<secret>[^\s;\"']{3,})",
)
USERPWD = Extractor(
    id="uri",
    type="db-uri",
    regex=r"(?P<scheme>mysql|postgres)://(?P<user>[^:@\s]+):(?P<secret>.+)@",
)


def test_extracts_password_assignment():
    creds = extract_credentials(_file(ctx="Password=Sup3rSecret;"), [PWD])
    assert len(creds) == 1
    assert creds[0].secret == "Sup3rSecret"
    assert creds[0].type == "password-assignment"
    assert creds[0].username is None
    assert creds[0].finding_id == _file(ctx="Password=Sup3rSecret;").finding_id
    assert creds[0].source == "run.tsv"


def test_extracts_username_group():
    creds = extract_credentials(_file(ctx="mysql://sa:p@ss@db"), [USERPWD])
    assert creds[0].username == "sa"
    assert creds[0].secret == "p@ss"


def test_no_false_positive_when_absent():
    assert extract_credentials(_file(ctx="nothing here"), [PWD, USERPWD]) == []


def test_dedupes_same_type_and_secret():
    # Same secret appears in both matched_string and context -> single credential
    creds = extract_credentials(
        _file(matched="password=AAAA", ctx="password=AAAA"), [PWD]
    )
    assert len(creds) == 1


def test_shares_yield_nothing():
    s = ShareResult(
        severity=Severity.RED,
        share_path=r"\\H\S",
        can_read=True,
        can_write=False,
        can_modify=False,
        source_line=1,
    )
    assert extract_credentials(s, [PWD]) == []


class TestBuiltinUriSecretsWithAtSign:
    def test_db_uri_password_with_at_sign(self):
        from snafflemap.analysis.catalog import builtin_catalog

        cat = builtin_catalog()
        f = _file(ctx="mongodb://admin:p@ssw0rd@dbhost:27017/app")
        creds = [
            c for c in extract_credentials(f, cat.extractors) if c.type == "db-uri"
        ]
        assert creds, "expected a db-uri credential"
        assert creds[0].secret == "p@ssw0rd"
        assert creds[0].username == "admin"

    def test_git_cred_url_password_with_at_sign(self):
        from snafflemap.analysis.catalog import builtin_catalog

        cat = builtin_catalog()
        f = _file(ctx="https://deploy:p@ss@github.com/org/repo.git")
        creds = [
            c
            for c in extract_credentials(f, cat.extractors)
            if c.type == "git-credential-url"
        ]
        assert creds, "expected a git-credential-url credential"
        assert creds[0].secret == "p@ss"
        assert creds[0].username == "deploy"
