"""Tests for detector classification logic."""

from __future__ import annotations

from datetime import datetime, timezone

from snafflemap.analysis.classify import classify
from snafflemap.analysis.models import Detector
from snafflemap.models import DirResult, FileResult, Severity, ShareResult


def _file(path=r"\\H\S\Groups.xml", rule="KeepX", matched="x", ctx="ctx"):
    return FileResult(
        severity=Severity.RED,
        rule_name=rule,
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


GPP = Detector(
    id="gpp",
    label="GPP cpassword",
    category="credentials",
    why="w",
    action="a",
    filename_patterns=(r"^Groups\.xml$",),
    context_patterns=("cpassword",),
)
KDBX = Detector(
    id="kdbx",
    label="KeePass",
    category="credentials",
    why="w",
    action="a",
    ext=(".kdbx",),
)
BYRULE = Detector(
    id="byrule",
    label="R",
    category="config",
    why="w",
    action="a",
    rule_names=("keepx",),
)


def test_filename_and_context_both_required():
    # filename matches but context lacks 'cpassword' -> no hit
    assert classify(_file(ctx="nothing"), [GPP]) == []
    # filename matches AND context has cpassword -> hit
    hits = classify(_file(ctx="cpassword=AAAA"), [GPP])
    assert [h.id for h in hits] == ["gpp"]


def test_ext_signal():
    f = _file(path=r"\\H\S\secrets.kdbx", ctx="")
    assert [h.id for h in classify(f, [KDBX])] == ["kdbx"]


def test_rule_name_cross_reference():
    assert [h.id for h in classify(_file(rule="KeepX"), [BYRULE])] == ["byrule"]


def test_no_signal_no_hit():
    f = _file(path=r"\\H\S\boring.txt", rule="Other", ctx="")
    assert classify(f, [KDBX, BYRULE]) == []


def test_builtin_private_key_detector_fires_on_inline_key():
    # Regression for D-2: Snaffler's KeepInlinePrivateKey rule surfaces an
    # extensionless id_rsa whose context holds BEGIN RSA PRIVATE KEY. The
    # built-in private-key detector must classify it.
    from snafflemap.analysis.catalog import builtin_catalog

    cat = builtin_catalog()
    f = _file(
        path=r"\\H\IT\id_rsa",
        rule="KeepInlinePrivateKey",
        matched="-----BEGIN RSA PRIVATE KEY-----",
        ctx="-----BEGIN RSA PRIVATE KEY-----",
    )
    assert "private-key" in [h.id for h in classify(f, cat.detectors)]


def test_builtin_private_key_detector_fires_on_ssh_key_filename():
    # Regression for D-2: KeepSSHKeysByFileName matches the bare filename
    # (context is just "id_rsa", no key body). Still a private key.
    from snafflemap.analysis.catalog import builtin_catalog

    cat = builtin_catalog()
    f = _file(
        path=r"\\H\IT\id_rsa",
        rule="KeepSSHKeysByFileName",
        matched="id_rsa",
        ctx="id_rsa",
    )
    assert "private-key" in [h.id for h in classify(f, cat.detectors)]


def test_shares_and_dirs_do_not_crash():
    s = ShareResult(
        severity=Severity.RED,
        share_path=r"\\H\S",
        can_read=True,
        can_write=False,
        can_modify=False,
        source_line=1,
    )
    d = DirResult(severity=Severity.RED, dir_path=r"\\H\S\d", source_line=1)
    assert classify(s, [GPP, KDBX]) == []
    assert classify(d, [GPP, KDBX]) == []


def test_hit_carries_detector_fields():
    h = classify(_file(ctx="cpassword=AAAA"), [GPP])[0]
    assert h.label == "GPP cpassword" and h.category == "credentials"


def test_hit_carries_remediation():
    from snafflemap.analysis.classify import classify
    from snafflemap.analysis.models import Detector

    d = Detector(
        id="r",
        label="R",
        category="config",
        why="w",
        action="a",
        ext=(".x",),
        remediation="rotate it",
    )
    f = _file(path=r"\\H\S\f.x", ctx="")
    hits = classify(f, [d])
    assert hits and hits[0].remediation == "rotate it"


def test_hit_remediation_none_by_default():
    from snafflemap.analysis.classify import classify
    from snafflemap.analysis.models import Detector

    d = Detector(id="r", label="R", category="config", why="w", action="a", ext=(".x",))
    f = _file(path=r"\\H\S\f.x", ctx="")
    assert classify(f, [d])[0].remediation is None
