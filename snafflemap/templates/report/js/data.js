/* SM:data — parse sm-data into findings + facet indexes (pure) */
var SMData = (function () {
  function ext(path) {
    var base = String(path || "").split(/[\\/]/).pop();
    var dot = base.lastIndexOf(".");
    return dot > 0 ? base.slice(dot).toLowerCase() : "";
  }
  function fileName(path) { return String(path || "").split(/[\\/]/).pop(); }
  function bump(obj, key) { if (key) obj[key] = (obj[key] || 0) + 1; }

  function buildModel(SM) {
    var meta = (SM && SM.meta) || {};
    var index = { host: {}, share: {}, rule: {}, severity: {}, type: {}, status: {}, ext: {} };
    var findings = Object.keys(meta).map(function (id) {
      var m = meta[id];
      var rec = {
        id: id, path: m.path || "", host: m.host || "", share: m.share || "",
        type: m.type || "file", crackable: !!m.crackable, writable: !!m.writable, actions: m.actions || [],
        rule: m.rule || "", detector_ids: m.detector_ids || [], severity: m.severity || "Gray",
        score: m.score || 0, tier: m.tier || "", size: m.size == null ? null : m.size,
        modified: m.modified || "", matched: m.matched || "", snippet: m.snippet || "",
        sources: m.sources || [], delta_status: m.delta_status || null,
      };
      rec.name = fileName(rec.path);
      rec.ext = ext(rec.path);
      rec.hasSnippet = !!rec.snippet;
      bump(index.host, rec.host); bump(index.share, rec.share); bump(index.rule, rec.rule);
      bump(index.severity, rec.severity); bump(index.type, rec.type);
      if (rec.ext) bump(index.ext, rec.ext);
      if (rec.delta_status) bump(index.status, "delta:" + rec.delta_status);
      return rec;
    });
    return { findings: findings, index: index, fileName: fileName };
  }
  return { buildModel: buildModel, ext: ext, fileName: fileName };
})();
if (typeof module !== "undefined" && module.exports) module.exports = SMData;
if (typeof globalThis !== "undefined") globalThis.SMData = SMData;
