"""Dataclasses for the detection & enrichment engine."""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(frozen=True)
class Detector:
    id: str
    label: str
    category: str
    why: str
    action: str
    crackable: bool = False
    weight: int = 20
    remediation: str | None = None
    filename_patterns: tuple[str, ...] = ()
    ext: tuple[str, ...] = ()
    path_patterns: tuple[str, ...] = ()
    context_patterns: tuple[str, ...] = ()
    rule_names: tuple[str, ...] = ()


@dataclass(frozen=True)
class DetectorHit:
    id: str
    label: str
    category: str
    why: str
    action: str
    crackable: bool
    weight: int
    remediation: str | None = None


@dataclass(frozen=True)
class Extractor:
    id: str
    type: str
    regex: str
    crackable: bool = False
    hashcat_mode: str | None = None


@dataclass(frozen=True)
class Credential:
    type: str
    secret: str
    username: str | None
    raw_context: str
    crackable: bool
    finding_id: str
    source: str
    hashcat_mode: str | None = None


@dataclass(frozen=True)
class Score:
    value: int
    tier: str
    breakdown: tuple[tuple[str, int], ...] = ()


@dataclass(frozen=True)
class Enrichment:
    finding_id: str
    detectors: tuple[DetectorHit, ...] = ()
    credentials: tuple[Credential, ...] = ()
    score: Score = field(default_factory=lambda: Score(0, "Low", ()))


@dataclass(frozen=True)
class Catalog:
    detectors: tuple[Detector, ...] = ()
    extractors: tuple[Extractor, ...] = ()
