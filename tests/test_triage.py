"""Tests for the triage sidecar: load/validate/merge/suppression."""

from __future__ import annotations

import json

import pytest

from snafflemap.triage import (
    SCHEMA,
    TriageError,
    empty_sidecar,
    finding_matches_suppression,
    load_sidecar,
    merge_sidecars,
    validate_sidecar,
)


def _sc(triage=None, suppressions=None, name="eng"):
    return {
        "schema": SCHEMA,
        "report_name": name,
        "exported_at": "2026-01-01T00:00:00Z",
        "triage": triage or {},
        "suppressions": suppressions or [],
    }


class TestValidate:
    def test_empty_sidecar_is_valid(self):
        validate_sidecar(empty_sidecar("eng"))

    def test_bad_schema_rejected(self):
        with pytest.raises(TriageError):
            validate_sidecar({"schema": "nope", "triage": {}})

    def test_bad_status_rejected(self):
        sc = _sc(
            triage={"abc": {"status": "bogus", "updated_at": "2026-01-01T00:00:00Z"}}
        )
        with pytest.raises(TriageError):
            validate_sidecar(sc)

    def test_load_roundtrip(self, tmp_path):
        p = tmp_path / "t.json"
        p.write_text(
            json.dumps(
                _sc(
                    triage={
                        "a": {"status": "triaged", "updated_at": "2026-01-01T00:00:00Z"}
                    }
                )
            ),
            encoding="utf-8",
        )
        sc = load_sidecar(p)
        assert sc["triage"]["a"]["status"] == "triaged"

    def test_load_invalid_json_raises(self, tmp_path):
        p = tmp_path / "bad.json"
        p.write_text("{not json", encoding="utf-8")
        with pytest.raises(TriageError):
            load_sidecar(p)


class TestMerge:
    def test_lww_newer_wins(self):
        a = _sc(
            triage={
                "x": {
                    "status": "confirmed-loot",
                    "updated_at": "2026-01-01T10:00:00Z",
                    "updated_by": "ann",
                }
            }
        )
        b = _sc(
            triage={
                "x": {
                    "status": "false-positive",
                    "updated_at": "2026-01-01T10:05:00Z",
                    "updated_by": "bob",
                }
            }
        )
        out = merge_sidecars(a, b)
        assert out["triage"]["x"]["status"] == "false-positive"

    def test_older_does_not_overwrite(self):
        a = _sc(
            triage={
                "x": {"status": "confirmed-loot", "updated_at": "2026-01-01T10:05:00Z"}
            }
        )
        b = _sc(triage={"x": {"status": "new", "updated_at": "2026-01-01T09:00:00Z"}})
        out = merge_sidecars(a, b)
        assert out["triage"]["x"]["status"] == "confirmed-loot"

    def test_notes_preserved_from_both(self):
        a = _sc(
            triage={
                "x": {
                    "status": "triaged",
                    "updated_at": "2026-01-01T10:00:00Z",
                    "notes": [{"by": "ann", "at": "t1", "text": "looks real"}],
                }
            }
        )
        b = _sc(
            triage={
                "x": {
                    "status": "false-positive",
                    "updated_at": "2026-01-01T10:05:00Z",
                    "notes": [{"by": "bob", "at": "t2", "text": "decoy"}],
                }
            }
        )
        out = merge_sidecars(a, b)
        texts = {n["text"] for n in out["triage"]["x"]["notes"]}
        assert texts == {"looks real", "decoy"}

    def test_disjoint_findings_both_kept(self):
        a = _sc(triage={"x": {"status": "triaged", "updated_at": "t"}})
        b = _sc(triage={"y": {"status": "reported", "updated_at": "t"}})
        out = merge_sidecars(a, b)
        assert set(out["triage"]) == {"x", "y"}

    def test_suppressions_unioned(self):
        a = _sc(suppressions=[{"kind": "rule", "value": "R1"}])
        b = _sc(
            suppressions=[
                {"kind": "detector", "value": "kdbx"},
                {"kind": "rule", "value": "R1"},
            ]
        )
        out = merge_sidecars(a, b)
        assert {(s["kind"], s["value"]) for s in out["suppressions"]} == {
            ("rule", "R1"),
            ("detector", "kdbx"),
        }


class TestSuppressionMatch:
    def test_rule_match(self):
        s = {"kind": "rule", "value": "KeepX"}
        assert finding_matches_suppression(
            s, rule_name="KeepX", path=r"\\h\s\f", detector_ids=[]
        )
        assert not finding_matches_suppression(
            s, rule_name="Other", path=r"\\h\s\f", detector_ids=[]
        )

    def test_path_glob_match(self):
        s = {"kind": "path", "value": r"\\*\backups\*"}
        assert finding_matches_suppression(
            s, rule_name="R", path=r"\\dc01\backups\old.zip", detector_ids=[]
        )
        assert not finding_matches_suppression(
            s, rule_name="R", path=r"\\dc01\share\f.txt", detector_ids=[]
        )

    def test_detector_match(self):
        s = {"kind": "detector", "value": "kdbx"}
        assert finding_matches_suppression(
            s, rule_name="R", path=r"\\h\s\f", detector_ids=["kdbx"]
        )
        assert not finding_matches_suppression(
            s, rule_name="R", path=r"\\h\s\f", detector_ids=["gpp-cpassword"]
        )
