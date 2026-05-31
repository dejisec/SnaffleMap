"""Tests for analysis dataclasses."""

from __future__ import annotations

from snafflemap.analysis.models import (
    Catalog,
    Credential,
    Detector,
    DetectorHit,
    Enrichment,
    Extractor,
    Score,
)


def test_detector_defaults():
    d = Detector(id="x", label="X", category="config", why="w", action="a")
    assert d.crackable is False
    assert d.weight == 20
    assert d.remediation is None
    assert d.ext == () and d.context_patterns == ()


def test_score_and_enrichment_compose():
    hit = DetectorHit(
        id="x",
        label="X",
        category="config",
        why="w",
        action="a",
        crackable=False,
        weight=20,
    )
    cred = Credential(
        type="t",
        secret="s",
        username=None,
        raw_context="ctx",
        crackable=True,
        finding_id="abc",
        source="f.tsv",
        hashcat_mode=None,
    )
    sc = Score(value=72, tier="High", breakdown=(("severity:Red", 28),))
    enr = Enrichment(finding_id="abc", detectors=(hit,), credentials=(cred,), score=sc)
    assert enr.score.tier == "High"
    assert enr.detectors[0].weight == 20
    assert enr.credentials[0].crackable is True


def test_extractor_and_catalog():
    e = Extractor(id="e", type="t", regex="(?P<secret>x)")
    cat = Catalog(detectors=(), extractors=(e,))
    assert cat.extractors[0].crackable is False
