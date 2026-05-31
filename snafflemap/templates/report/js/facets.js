/* SM:facets — facet counts + bidirectional query<->facet sync (pure) */
var SMFacets = (function () {
  var FACET_FIELDS = { severity: "severity", host: "host", share: "share",
    rule: "rule", type: "type", status: "delta_status" };

  function computeFacets(findings) {
    var out = {};
    Object.keys(FACET_FIELDS).forEach(function (facet) {
      var prop = FACET_FIELDS[facet], counts = {};
      findings.forEach(function (r) {
        var v = r[prop]; if (v == null || v === "") return;
        counts[v] = (counts[v] || 0) + 1;
      });
      out[facet] = counts;
    });
    return out;
  }
  // The query field name for a facet (severity uses `sev`, status uses `delta`).
  function fieldFor(facet) {
    if (facet === "severity") return "sev";
    if (facet === "status") return "delta";
    return facet;
  }
  function activeFacetValues(query, facet) {
    var field = fieldFor(facet), re = new RegExp("(^|\\s)" + field + ":(\\S+)"), m = re.exec(query || "");
    return m ? m[2].split("|") : [];
  }
  function setFacetValues(query, facet, values) {
    var field = fieldFor(facet);
    var stripped = String(query || "").replace(new RegExp("(^|\\s)" + field + ":\\S+", "g"), "").trim();
    if (!values.length) return stripped;
    var token = field + ":" + values.join("|");
    return (stripped ? stripped + " " : "") + token;
  }
  function toggleFacet(query, facet, value) {
    var vals = activeFacetValues(query, facet);
    var i = vals.indexOf(value);
    if (i === -1) vals.push(value); else vals.splice(i, 1);
    return setFacetValues(query, facet, vals);
  }
  return { FACET_FIELDS: FACET_FIELDS, computeFacets: computeFacets, fieldFor: fieldFor,
    activeFacetValues: activeFacetValues, setFacetValues: setFacetValues, toggleFacet: toggleFacet };
})();
if (typeof module !== "undefined" && module.exports) module.exports = SMFacets;
if (typeof globalThis !== "undefined") globalThis.SMFacets = SMFacets;
