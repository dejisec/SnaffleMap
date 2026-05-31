/* SM:query — field-qualified query parser + predicate compiler (pure) */
var SMQuery = (function () {
  var FIELDS = ["rule","host","share","path","ext","status","sev","severity","tier",
    "score","size","type","crackable","writable","delta","match","snippet"];

  // Split a query string into [{neg, field, value}]. Honors quotes and a leading '-'.
  function tokenize(q) {
    var tokens = [], re = /(-?)(\w+):"([^"]*)"|(-?)"([^"]*)"|(-?)(\S+)/g, m;
    while ((m = re.exec(q || "")) !== null) {
      var neg, field = null, value;
      if (m[2] != null) { neg = m[1] === "-"; field = m[2].toLowerCase(); value = m[3]; }
      else if (m[5] != null) { neg = m[4] === "-"; value = m[5]; }
      else { var raw = m[7]; neg = m[6] === "-";
        var ci = raw.indexOf(":"), key = ci > 0 ? raw.slice(0, ci).toLowerCase() : "";
        if (ci > 0 && FIELDS.indexOf(key) !== -1) { field = key; value = raw.slice(ci + 1); }
        else value = raw;
      }
      if (field && FIELDS.indexOf(field) === -1) { value = field + ":" + value; field = null; }
      if (value !== "" || field) tokens.push({ neg: neg, field: field, value: value });
    }
    return tokens;
  }
  function wildcard(pat) {
    var rx = pat.split("*").map(function (s) {
      return s.replace(/[.+?^${}()|[\]\\]/g, "\\$&");
    }).join(".*");
    return new RegExp("^" + rx + "$", "i");
  }
  function parseSize(v) {
    var m = /^([0-9.]+)\s*(b|kb|mb|gb)?$/i.exec(v);
    if (!m) return null;
    var mult = { b: 1, kb: 1024, mb: 1048576, gb: 1073741824 }[(m[2] || "b").toLowerCase()];
    return parseFloat(m[1]) * mult;
  }
  function numCmp(value) {           // value like ">80","<1kb","=5","80"
    var m = /^(>=|<=|>|<|=)?(.*)$/.exec(value);
    var op = m[1] || "=";
    var n = parseSize(m[2]); if (n == null) n = parseFloat(m[2]);
    if (isNaN(n)) return function () { return false; };
    return function (x) {
      if (x == null) return false;
      switch (op) { case ">": return x > n; case "<": return x < n;
        case ">=": return x >= n; case "<=": return x <= n; default: return x === n; }
    };
  }
  function strMatch(value, getter) {           // wildcard / OR / substring
    if (value.indexOf("|") !== -1) {
      var alts = value.split("|").map(function (v) { return strMatch(v, getter); });
      return function (r) { return alts.some(function (f) { return f(r); }); };
    }
    if (value.indexOf("*") !== -1) {
      var rx = wildcard(value);
      return function (r) { return rx.test(String(getter(r) || "")); };
    }
    var lc = value.toLowerCase();
    return function (r) { return String(getter(r) || "").toLowerCase().indexOf(lc) !== -1; };
  }
  var GET = {
    rule: function (r) { return r.rule; }, host: function (r) { return r.host; },
    share: function (r) { return r.share; }, path: function (r) { return r.path; },
    ext: function (r) { return r.ext; }, status: function (r) { return r.delta_status; },
    sev: function (r) { return r.severity; }, severity: function (r) { return r.severity; },
    tier: function (r) { return r.tier; }, type: function (r) { return r.type; },
    delta: function (r) { return r.delta_status; }, match: function (r) { return r.matched; },
    snippet: function (r) { return r.snippet; },
  };
  function tokenPredicate(tok) {
    var v = tok.value, f = tok.field, base;
    if (!f) {
      base = function (r) {
        var hay = (r.path + " " + r.rule + " " + r.matched + " " + r.snippet).toLowerCase();
        return hay.indexOf(v.toLowerCase()) !== -1;
      };
    } else if (f === "score") { base = (function (cmp) { return function (r) { return cmp(r.score); }; })(numCmp(v));
    } else if (f === "size") { base = (function (cmp) { return function (r) { return cmp(r.size); }; })(numCmp(v));
    } else if (f === "crackable") { var want = /^(true|1|yes)$/i.test(v);
      base = function (r) { return !!r.crackable === want; };
    } else if (f === "writable") { var wantW = /^(true|1|yes)$/i.test(v);
      base = function (r) { return !!r.writable === wantW; };
    } else if (GET[f]) { base = strMatch(v, GET[f]);
    } else { base = function () { return true; }; }
    return tok.neg ? function (r) { return !base(r); } : base;
  }
  function parseQuery(q) {
    var preds = tokenize(q).map(tokenPredicate);
    return function (r) { return preds.every(function (p) { return p(r); }); };
  }
  return { FIELDS: FIELDS, tokenize: tokenize, parseQuery: parseQuery };
})();
if (typeof module !== "undefined" && module.exports) module.exports = SMQuery;
if (typeof globalThis !== "undefined") globalThis.SMQuery = SMQuery;
