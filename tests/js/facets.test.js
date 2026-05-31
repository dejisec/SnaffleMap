const test = require("node:test");
const assert = require("node:assert");
const SMFacets = require("../../snafflemap/templates/report/js/facets.js");

const recs = [
  { id: "a", severity: "Red", host: "DC01", rule: "Password", type: "file", delta_status: "new" },
  { id: "b", severity: "Black", host: "FS1", rule: "PrivateKey", type: "file", delta_status: null },
  { id: "c", severity: "Red", host: "DC01", rule: "Password", type: "share", delta_status: "new" },
];

test("computeFacets counts each value per facet", () => {
  const f = SMFacets.computeFacets(recs);
  assert.deepStrictEqual(f.severity, { Red: 2, Black: 1 });
  assert.deepStrictEqual(f.host, { DC01: 2, FS1: 1 });
});

test("toggleFacet adds a field token to an empty query", () => {
  assert.strictEqual(SMFacets.toggleFacet("", "host", "DC01"), "host:DC01");
});

test("toggleFacet on an active value removes it", () => {
  assert.strictEqual(SMFacets.toggleFacet("host:DC01", "host", "DC01"), "");
});

test("toggleFacet ORs a second value of the same field", () => {
  assert.strictEqual(SMFacets.toggleFacet("host:DC01", "host", "FS1"), "host:DC01|FS1");
});

test("activeFacetValues reads selections back out of a query", () => {
  assert.deepStrictEqual(SMFacets.activeFacetValues("host:DC01|FS1 sev:red", "host"), ["DC01", "FS1"]);
});
