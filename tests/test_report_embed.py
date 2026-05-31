"""Tests that the report embeds finding ids and the sm-data blob."""

from __future__ import annotations

import json
import re
from datetime import datetime, timezone

from snafflemap.exporters import report
from snafflemap.models import FileResult, ResultSet, Severity


def _file(path=r"\\DC\SYSVOL\Groups.xml"):
    return FileResult(
        severity=Severity.BLACK,
        rule_name="KeepX",
        can_read=True,
        can_write=False,
        can_modify=False,
        matched_string="x",
        file_size=1,
        modified_date=datetime(2025, 1, 1, tzinfo=timezone.utc),
        file_path=path,
        alt_filename=None,
        match_context="ctx",
        source_line=1,
    )


def _render(tmp_path, **kwargs):
    f = _file()
    rs = ResultSet(files=[f], shares=[], dirs=[])
    out = tmp_path / "r.html"
    report.export(rs, str(out), **kwargs)
    return f, out.read_text(encoding="utf-8")


def test_finding_id_embedded_in_data(tmp_path):
    # The list view is rendered client-side from sm-data, so the finding id is
    # carried in the embedded JSON rather than in server-rendered row markup.
    f, html = _render(tmp_path)
    m = re.search(
        r'<script id="sm-data" type="application/json">(.*?)</script>', html, re.S
    )
    assert m, "sm-data blob missing"
    data = json.loads(m.group(1))
    assert f.finding_id in data["meta"]


def test_embeds_sm_data_blob(tmp_path):
    f, html = _render(tmp_path, report_name="eng")
    m = re.search(
        r'<script id="sm-data" type="application/json">(.*?)</script>', html, re.S
    )
    assert m, "sm-data blob missing"
    data = json.loads(m.group(1))
    assert data["report_id"] == "eng"
    assert f.finding_id in data["meta"]
    assert data["meta"][f.finding_id]["path"] == f.file_path


def test_triage_seed_embedded(tmp_path):
    f = _file()
    rs = ResultSet(files=[f], shares=[], dirs=[])
    out = tmp_path / "r.html"
    seed = {f.finding_id: {"status": "confirmed-loot", "updated_at": "t"}}
    report.export(rs, str(out), triage=seed)
    html = out.read_text(encoding="utf-8")
    m = re.search(
        r'<script id="sm-data" type="application/json">(.*?)</script>', html, re.S
    )
    data = json.loads(m.group(1))
    assert data["triage"][f.finding_id]["status"] == "confirmed-loot"


def test_meta_includes_detector_actions_from_enrichment(tmp_path):
    import dataclasses

    from snafflemap.analysis.catalog import builtin_catalog
    from snafflemap.analysis.enrich import enrich

    # match_context must contain "cpassword" so the gpp-cpassword detector fires
    f = dataclasses.replace(
        _file(path=r"\\DC\SYSVOL\Groups.xml"),
        match_context="cpassword=AES_ENCRYPTED_BLOB",
        matched_string="cpassword",
    )
    rs = ResultSet(files=[f], shares=[], dirs=[])
    enr = enrich(rs, builtin_catalog(), now=datetime(2026, 1, 1, tzinfo=timezone.utc))
    out = tmp_path / "r.html"
    report.export(rs, str(out), enrichment=enr)
    html = out.read_text(encoding="utf-8")
    m = re.search(
        r'<script id="sm-data" type="application/json">(.*?)</script>', html, re.S
    )
    data = json.loads(m.group(1))
    actions = data["meta"][f.finding_id]["actions"]
    assert any("gpp-decrypt" in a["cmd"] for a in actions)


def test_meta_includes_rule_and_detector_ids(tmp_path):
    import dataclasses

    from snafflemap.analysis.catalog import builtin_catalog
    from snafflemap.analysis.enrich import enrich

    f = dataclasses.replace(
        _file(path=r"\\DC\SYSVOL\Groups.xml"),
        match_context="cpassword=AES_ENCRYPTED_BLOB",
        matched_string="cpassword",
    )
    rs = ResultSet(files=[f], shares=[], dirs=[])
    enr = enrich(rs, builtin_catalog(), now=datetime(2026, 1, 1, tzinfo=timezone.utc))
    out = tmp_path / "r.html"
    report.export(rs, str(out), enrichment=enr)
    html = out.read_text(encoding="utf-8")
    m = re.search(
        r'<script id="sm-data" type="application/json">(.*?)</script>', html, re.S
    )
    data = json.loads(m.group(1))
    meta = data["meta"][f.finding_id]
    assert "rule" in meta
    assert "detector_ids" in meta
    assert meta["rule"] == f.rule_name
    assert "gpp-cpassword" in meta["detector_ids"]


def test_meta_rule_and_detector_ids_without_enrichment(tmp_path):
    f, html = _render(tmp_path)
    m = re.search(
        r'<script id="sm-data" type="application/json">(.*?)</script>', html, re.S
    )
    data = json.loads(m.group(1))
    meta = data["meta"][f.finding_id]
    assert "rule" in meta
    assert "detector_ids" in meta
    assert meta["rule"] == f.rule_name
    assert meta["detector_ids"] == []


def test_report_embeds_delta_status(tmp_path):
    # Delta status is carried per-finding in sm-data; the banner / resolved
    # section is rendered client-side in a later task, so we assert the data is
    # embedded rather than the (now removed) server-rendered DOM.
    f = _file()
    rs = ResultSet(files=[f], shares=[], dirs=[])
    delta = {f.finding_id: "escalated"}
    resolved = [
        {
            "id": "gone1",
            "type": "file",
            "severity": "Red",
            "file_path": r"\\H\S\gone",
            "rule_name": "R",
        }
    ]
    out = tmp_path / "r.html"
    report.export(rs, str(out), delta=delta, resolved=resolved)
    html = out.read_text(encoding="utf-8")
    m = re.search(
        r'<script id="sm-data" type="application/json">(.*?)</script>', html, re.S
    )
    assert m, "sm-data blob missing"
    data = json.loads(m.group(1))
    assert data["meta"][f.finding_id]["delta_status"] == "escalated"


def test_meta_includes_display_fields(tmp_path):
    import json
    import re
    from datetime import datetime, timezone

    from snafflemap.analysis.catalog import builtin_catalog
    from snafflemap.analysis.enrich import enrich

    f = _file()
    rs = ResultSet(files=[f], shares=[], dirs=[])
    enr = enrich(rs, builtin_catalog(), now=datetime(2026, 1, 1, tzinfo=timezone.utc))
    out = tmp_path / "r.html"
    report.export(rs, str(out), enrichment=enr, delta={f.finding_id: "escalated"})
    html = out.read_text(encoding="utf-8")
    m = re.search(
        r'<script id="sm-data" type="application/json">(.*?)</script>', html, re.S
    )
    meta = json.loads(m.group(1))["meta"][f.finding_id]
    for key in (
        "severity",
        "score",
        "tier",
        "size",
        "modified",
        "matched",
        "snippet",
        "sources",
        "delta_status",
    ):
        assert key in meta, f"missing {key}"
    assert meta["severity"] == "Black"
    assert meta["delta_status"] == "escalated"
    assert meta["score"] >= 0


def test_sm_data_blob_escapes_script_breakout(tmp_path):
    """A </script> payload in triage data must not break out of the blob (stored-XSS guard)."""
    import json
    import re

    f = _file()
    rs = ResultSet(files=[f], shares=[], dirs=[])
    payload = "pwn</script><img src=x onerror=alert(1)>"
    seed = {
        f.finding_id: {
            "status": "new",
            "updated_at": "t",
            "notes": [{"by": "x", "at": "t", "text": payload}],
        }
    }
    out = tmp_path / "r.html"
    report.export(rs, str(out), triage=seed)
    html = out.read_text(encoding="utf-8")

    # Isolate the sm-data script element.
    m = re.search(
        r'<script id="sm-data" type="application/json">(.*?)</script>', html, re.S
    )
    assert m, "sm-data blob missing"
    blob = m.group(1)
    # The raw payload's </script> must NOT appear literally inside the blob.
    assert "</script>" not in blob
    assert "<img" not in blob
    # But it must still round-trip back to the original text via JSON.parse semantics.
    data = json.loads(blob)
    assert data["triage"][f.finding_id]["notes"][0]["text"] == payload


def test_output_is_self_contained(tmp_path):
    _, html = _render(tmp_path)
    assert "http://" not in html and "https://" not in html
    assert 'src="http' not in html and 'href="http' not in html
    assert "<style>" in html
    assert html.count("<script") >= 2


def test_shell_has_mount_points(tmp_path):
    _, html = _render(tmp_path)
    for anchor in (
        "sm-app",
        "sm-query",
        "sm-list",
        "sm-detail",
        "sm-rail",
        "sm-view-switch",
    ):
        assert f'id="{anchor}"' in html, f"missing mount point {anchor}"


def test_inlined_js_modules_present(tmp_path):
    _, html = _render(tmp_path)
    for marker in ("SM:dom", "SM:data", "SM:query", "SM:app"):
        assert marker in html, f"missing module marker {marker}"


def test_inlined_js_neutralizes_script_close(tmp_path, monkeypatch):
    """A literal </script> inside a JS asset must not break the inline <script> element."""
    from snafflemap.exporters import report as report_mod

    real = report_mod._read_assets

    def fake():
        css, js = real()
        return css, js + '\nvar x = "</script><b>oops</b>";\n'

    monkeypatch.setattr(report_mod, "_read_assets", fake)
    _, html = _render(tmp_path)
    # The dangerous boundary must be escaped in the emitted HTML...
    assert "</script><b>oops</b>" not in html
    assert "<\\/script>" in html  # JS-equivalent, HTML-safe form


def test_actions_menu_buttons_present(tmp_path):
    _, html = _render(tmp_path)
    for bid in ("smActTheme", "smActSave", "smActExport", "smActImport", "smActLoot"):
        assert bid in html, f"missing action id {bid}"


def test_sm_data_embeds_resolved(tmp_path):
    f = _file()
    rs = ResultSet(files=[f], shares=[], dirs=[])
    resolved = [
        {
            "id": "g1",
            "type": "file",
            "severity": "Red",
            "file_path": r"\\H\S\gone.txt",
            "rule_name": "R",
        }
    ]
    out = tmp_path / "r.html"
    report.export(rs, str(out), resolved=resolved)
    html = out.read_text(encoding="utf-8")
    m = re.search(
        r'<script id="sm-data" type="application/json">(.*?)</script>', html, re.S
    )
    data = json.loads(m.group(1))
    assert data["resolved"][0]["file_path"] == r"\\H\S\gone.txt"
