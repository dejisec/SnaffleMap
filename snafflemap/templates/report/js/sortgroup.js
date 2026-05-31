/* SM:sortgroup — sorting + grouping (pure) */
var SMSort = (function () {
  var SEV = { Black: 0, Red: 1, Yellow: 2, Green: 3, Gray: 4 };
  function cmpDefault(a, b) {
    var sa = SEV[a.severity] == null ? 9 : SEV[a.severity];
    var sb = SEV[b.severity] == null ? 9 : SEV[b.severity];
    if (sa !== sb) return sa - sb;
    return (b.score || 0) - (a.score || 0);
  }
  function sortFindings(findings, column, desc) {
    var arr = findings.slice();
    if (!column) { arr.sort(cmpDefault); return arr; }
    arr.sort(function (a, b) {
      if (column === "severity") { var ra = SEV[a.severity] == null ? 9 : SEV[a.severity]; var rb = SEV[b.severity] == null ? 9 : SEV[b.severity]; var d = ra - rb; return desc ? -d : d; }
      var av = a[column], bv = b[column];
      if (typeof av === "number" || typeof bv === "number") {
        var n = (av || 0) - (bv || 0); return desc ? -n : n;
      }
      var s = String(av || "").localeCompare(String(bv || ""));
      return desc ? -s : s;
    });
    return arr;
  }
  function groupFindings(findings, groupKey, sortCol, sortDesc) {
    var sorted = sortFindings(findings, sortCol || null, !!sortDesc);
    if (!groupKey) return [{ key: null, items: sorted }];
    var buckets = {};
    sorted.forEach(function (r) { var k = r[groupKey] || "(none)"; (buckets[k] = buckets[k] || []).push(r); });
    var keys = Object.keys(buckets);
    if (groupKey === "severity") keys.sort(function (a, b) {
      return (SEV[a] == null ? 9 : SEV[a]) - (SEV[b] == null ? 9 : SEV[b]);
    });
    else keys.sort(function (a, b) { return buckets[b].length - buckets[a].length || a.localeCompare(b); });
    return keys.map(function (k) { return { key: k, items: buckets[k] }; });
  }
  return { sortFindings: sortFindings, groupFindings: groupFindings, SEV: SEV };
})();
if (typeof module !== "undefined" && module.exports) module.exports = SMSort;
if (typeof globalThis !== "undefined") globalThis.SMSort = SMSort;
