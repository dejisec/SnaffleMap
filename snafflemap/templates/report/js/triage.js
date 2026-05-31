/* SM:triage — bulk-action bar (SMBulk) and actions (SMActions) */
var SMBulk = (function () {
  function selectedIds(APP) { return Object.keys(APP.selection).filter(function (id) { return APP.selection[id]; }); }
  function refresh(APP) {
    var bar = document.getElementById("sm-bulk"); var ids = selectedIds(APP);
    if (!ids.length) { bar.hidden = true; bar.textContent = ""; return; }
    bar.hidden = false; bar.textContent = "";
    bar.appendChild(SMDom.el("span", { text: ids.length + " selected" }));
    var sel = SMDom.el("select", {}, [SMDom.el("option", { value: "", text: "set status…" })]);
    SMStore.STATUSES.forEach(function (s) { sel.appendChild(SMDom.el("option", { value: s, text: s })); });
    sel.addEventListener("change", function () { if (sel.value) { ids.forEach(function (id) { APP.store.setStatus(id, sel.value); }); SMList.render(APP); } });
    bar.appendChild(sel);
    bar.appendChild(SMDom.el("button", { text: "★ Star", onclick: function () { ids.forEach(function (id) { APP.store.toggleStar(id); }); SMList.render(APP); } }));
    bar.appendChild(SMDom.el("button", { text: "✕ Clear", onclick: function () { APP.selection = {}; SMList.render(APP); refresh(APP); } }));
  }
  return { refresh: refresh, selectedIds: selectedIds };
})();

/* SM:actions — triage import/export + loot script download */
var SMActions = (function () {
  function download(content, filename, mime) {
    var blob = new Blob([content], { type: mime }); var a = document.createElement("a");
    a.href = URL.createObjectURL(blob); a.download = filename; document.body.appendChild(a); a.click();
    document.body.removeChild(a); URL.revokeObjectURL(a.href);
  }
  function exportTriage(APP) {
    var sc = SMStore.buildSidecar(APP.store.state.reportId, APP.store.state.triage, APP.store.state.suppressions);
    download(JSON.stringify(sc, null, 2), "triage-" + APP.store.state.reportId + ".json", "application/json");
  }
  function importTriage(APP) {
    var input = document.createElement("input"); input.type = "file"; input.accept = "application/json";
    input.addEventListener("change", function () {
      var f = input.files[0]; if (!f) return; var rd = new FileReader();
      rd.onload = function () {
        try { var data = JSON.parse(rd.result);
          APP.store.state.triage = SMStore.mergeTriage(APP.store.state.triage, data.triage || {});
          (data.suppressions || []).forEach(function (s) {
            if (s && s.kind && s.value && !APP.store.state.suppressions.some(function (e) { return e.kind === s.kind && e.value === s.value; }))
              APP.store.state.suppressions.push(s);
          });
          APP.store.save(); APP.applyQuery(); if (APP.selectedId) SMDetail.render(APP, APP.selectedId);
        } catch (e) { window.alert("Invalid triage JSON"); }
      }; rd.readAsText(f);
    });
    input.click();
  }
  function buildLootScript(recs) {
    var lines = ["#!/usr/bin/env bash", "# SnaffleMap loot retrieval — " + recs.length + " findings", "set -euo pipefail", ""];
    recs.forEach(function (r) {
      var cmds = SMStore.lootCommands(r.path);
      if (cmds.length) { lines.push("# " + r.path); cmds.forEach(function (c) { lines.push(c); }); lines.push(""); }
    });
    return lines.join("\n");
  }
  function lootScript(APP) {
    var ids = SMBulk.selectedIds(APP);
    var recs = ids.length ? APP.model.findings.filter(function (r) { return APP.selection[r.id]; }) : APP.filtered;
    download(buildLootScript(recs), "loot-" + APP.store.state.reportId + ".sh", "text/x-shellscript");
  }
  return { exportTriage: exportTriage, importTriage: importTriage, lootScript: lootScript, buildLootScript: buildLootScript };
})();
if (typeof module !== "undefined" && module.exports) module.exports = SMActions;
if (typeof globalThis !== "undefined") globalThis.SMActions = SMActions;
