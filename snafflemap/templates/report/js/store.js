/* SM:store — triage state, persistence, sidecar, loot commands, saved views */
var SMStore = (function () {
  var STATUSES = ["new", "triaged", "confirmed-loot", "false-positive", "reported"];

  function parseUnc(path) {
    var m = /^\\\\([^\\]+)\\([^\\]+)\\?(.*)$/.exec(path || "");
    if (!m) return { host: "", share: "", restPath: "", file: "" };
    var rest = (m[3] || "").replace(/\\/g, "/");
    return { host: m[1], share: m[2], restPath: rest, file: rest.split("/").pop() || "" };
  }
  function lootCommands(path) {
    var p = parseUnc(path), out = [];
    if (p.host && p.share && (p.restPath || p.file)) {
      var getArg = p.restPath || p.file, outFile = p.file || "file";
      out.push("smbclient //" + p.host + "/" + p.share + " -c 'get \"" + getArg + "\" \"./" + outFile + "\"'");
      out.push("impacket-smbclient ./" + p.host + " -c 'use " + p.share + "; get \"" + getArg + "\"'");
    }
    return out;
  }
  function mergeNotes(a, b) {
    var seen = {}, out = [];
    (a || []).concat(b || []).forEach(function (n) {
      var k = (n.by || "") + "|" + (n.at || "") + "|" + (n.text || "");
      if (!seen[k]) { seen[k] = 1; out.push(n); }
    });
    return out;
  }
  function mergeTriage(base, incoming) {
    var out = {}; Object.keys(base || {}).forEach(function (k) { out[k] = base[k]; });
    Object.keys(incoming || {}).forEach(function (fid) {
      var a = out[fid], b = incoming[fid];
      if (!a) { var nb = {}; Object.keys(b).forEach(function (k) { nb[k] = b[k]; }); out[fid] = nb; return; }
      var winner = (b.updated_at || "") >= (a.updated_at || "") ? b : a;
      var merged = {}; Object.keys(winner).forEach(function (k) { merged[k] = winner[k]; });
      merged.notes = mergeNotes(a.notes, b.notes);
      out[fid] = merged;
    });
    return out;
  }
  function buildSidecar(reportId, triage, suppressions) {
    return { report_id: reportId, triage: triage || {}, suppressions: suppressions || [] };
  }
  function makeBrowserStore(SM) {
    var id = (SM && SM.report_id) || "report";
    var K = { tri: "snafflemap-triage-" + id, sup: "snafflemap-suppress-" + id,
      views: "snafflemap-views-" + id, op: "snafflemap-operator", theme: "snafflemap-theme" };
    function read(key, fallback) { try { return JSON.parse(localStorage.getItem(key) || fallback); } catch (e) { return JSON.parse(fallback); } }
    var state = {
      reportId: id,
      triage: mergeTriage(SM.triage || {}, read(K.tri, "{}")),
      suppressions: (function () {
        var map = {}; (SM.suppressions || []).concat(read(K.sup, "[]")).forEach(function (s) { map[s.kind + "|" + s.value] = s; });
        return Object.values(map);
      })(),
      views: read(K.views, "[]"),
    };
    function operator() {
      var n = localStorage.getItem(K.op);
      if (!n) { n = (window.prompt("Your initials (for triage attribution):", "operator") || "operator").trim() || "operator"; localStorage.setItem(K.op, n); }
      return n;
    }
    function save() { try {
      localStorage.setItem(K.tri, JSON.stringify(state.triage));
      localStorage.setItem(K.sup, JSON.stringify(state.suppressions));
      localStorage.setItem(K.views, JSON.stringify(state.views));
    } catch (e) {} }
    function entry(fid) { return state.triage[fid] || (state.triage[fid] = { status: "new", star: false, tags: [], notes: [] }); }
    function setStatus(fid, status) { var e = entry(fid); e.status = status; e.updated_at = new Date().toISOString(); save(); }
    function toggleStar(fid) { var e = entry(fid); e.star = !e.star; e.updated_at = new Date().toISOString(); save(); }
    function addNote(fid, text) { var e = entry(fid); (e.notes = e.notes || []).push({ by: operator(), at: new Date().toISOString(), text: text }); e.updated_at = new Date().toISOString(); save(); }
    function suppressRule(rule) {
      if (!state.suppressions.some(function (s) { return s.kind === "rule" && s.value === rule; }))
        state.suppressions.push({ kind: "rule", value: rule });
      save();
    }
    function removeSuppression(rule) {
      state.suppressions = state.suppressions.filter(function (s) { return !(s.kind === "rule" && s.value === rule); });
      save();
    }
    function isSuppressed(rec) { return state.suppressions.some(function (s) { return s.kind === "rule" && s.value === rec.rule; }); }
    return { K: K, state: state, save: save, entry: entry, operator: operator,
      setStatus: setStatus, toggleStar: toggleStar, addNote: addNote,
      suppressRule: suppressRule, removeSuppression: removeSuppression, isSuppressed: isSuppressed };
  }
  return { STATUSES: STATUSES, parseUnc: parseUnc, lootCommands: lootCommands,
    mergeNotes: mergeNotes, mergeTriage: mergeTriage, buildSidecar: buildSidecar,
    makeBrowserStore: makeBrowserStore };
})();
if (typeof module !== "undefined" && module.exports) module.exports = SMStore;
if (typeof globalThis !== "undefined") globalThis.SMStore = SMStore;
