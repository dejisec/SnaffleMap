"""Data models for SnaffleMap: Severity, FileResult, ShareResult, DirResult, ResultSet."""

from __future__ import annotations

import enum
import hashlib
import os
import re
from dataclasses import dataclass
from datetime import datetime

_SEVERITY_ORDER = {"Black": 0, "Red": 1, "Yellow": 2, "Green": 3, "Gray": 4}


class Severity(enum.Enum):
    BLACK = "Black"
    RED = "Red"
    YELLOW = "Yellow"
    GREEN = "Green"
    GRAY = "Gray"

    @property
    def sort_key(self) -> int:
        return _SEVERITY_ORDER[self.value]

    @classmethod
    def from_string(cls, s: str) -> Severity:
        for member in cls:
            if member.value.lower() == s.strip().lower():
                return member
        raise ValueError(f"Unknown severity: {s!r}")


_UNC_RE = re.compile(r"^\\\\([^\\]+)\\([^\\]+)")


def _parse_unc(path: str) -> tuple[str, str]:
    """Return (hostname, share_name) from a UNC path, or ("", "") if not UNC."""
    m = _UNC_RE.match(path)
    if m:
        return m.group(1), m.group(2)
    return "", ""


def _norm_matched(s: str) -> str:
    """Collapse all whitespace runs to single spaces and strip ends.

    Applied to matched strings so TSV and JSON inputs yield identical IDs.
    """
    return " ".join(s.split())


def _hash_id(parts: tuple[str, ...]) -> str:
    """Return the first 16 hex chars of the SHA-1 of NUL-joined parts."""
    digest = hashlib.sha1("\0".join(parts).encode("utf-8", "replace"))
    return digest.hexdigest()[:16]


@dataclass(frozen=True)
class FileResult:
    severity: Severity
    rule_name: str
    can_read: bool
    can_write: bool
    can_modify: bool
    matched_string: str
    file_size: int
    modified_date: datetime
    file_path: str
    alt_filename: str | None
    match_context: str
    source_line: int | None
    sources: tuple[str, ...] = ()

    @property
    def hostname(self) -> str:
        return _parse_unc(self.file_path)[0]

    @property
    def share_name(self) -> str:
        return _parse_unc(self.file_path)[1]

    @property
    def extension(self) -> str:
        return os.path.splitext(self.file_path)[1]

    @property
    def finding_id(self) -> str:
        norm = _norm_matched(self.matched_string)
        parts = ["File", self.file_path, self.rule_name]
        if norm:
            parts.append(norm)
        return _hash_id(tuple(parts))


@dataclass(frozen=True)
class ShareResult:
    severity: Severity
    share_path: str
    can_read: bool
    can_write: bool
    can_modify: bool
    source_line: int | None
    sources: tuple[str, ...] = ()

    @property
    def hostname(self) -> str:
        return _parse_unc(self.share_path)[0]

    @property
    def share_name(self) -> str:
        return _parse_unc(self.share_path)[1]

    @property
    def finding_id(self) -> str:
        return _hash_id(("Share", self.share_path))


@dataclass(frozen=True)
class DirResult:
    severity: Severity
    dir_path: str
    source_line: int | None
    sources: tuple[str, ...] = ()

    @property
    def hostname(self) -> str:
        return _parse_unc(self.dir_path)[0]

    @property
    def finding_id(self) -> str:
        return _hash_id(("Dir", self.dir_path))


@dataclass
class ResultSet:
    files: list[FileResult]
    shares: list[ShareResult]
    dirs: list[DirResult]
    warnings: list[str] | None = None

    @property
    def file_count(self) -> int:
        return len(self.files)

    @property
    def share_count(self) -> int:
        return len(self.shares)

    @property
    def dir_count(self) -> int:
        return len(self.dirs)

    @property
    def total_findings(self) -> int:
        return self.file_count + self.share_count + self.dir_count

    @property
    def severity_counts(self) -> dict[Severity, int]:
        counts: dict[Severity, int] = {s: 0 for s in Severity}
        for result in (*self.files, *self.shares, *self.dirs):
            counts[result.severity] += 1
        return counts

    @property
    def unique_hosts(self) -> set[str]:
        hosts: set[str] = set()
        for f in self.files:
            if f.hostname:
                hosts.add(f.hostname)
        for s in self.shares:
            if s.hostname:
                hosts.add(s.hostname)
        for d in self.dirs:
            if d.hostname:
                hosts.add(d.hostname)
        return hosts

    @property
    def unique_shares(self) -> set[str]:
        shares: set[str] = set()
        for f in self.files:
            if f.share_name:
                shares.add(f.share_name)
        for s in self.shares:
            if s.share_name:
                shares.add(s.share_name)
        return shares

    @property
    def date_range(self) -> tuple[datetime, datetime] | None:
        if not self.files:
            return None
        dates = [f.modified_date for f in self.files]
        return min(dates), max(dates)
