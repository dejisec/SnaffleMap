const test = require("node:test");
const assert = require("node:assert");
const SMSort = require("../../snafflemap/templates/report/js/sortgroup.js");

const recs = [
  { id: "a", severity: "Red", score: 80, host: "DC01", name: "b.txt" },
  { id: "b", severity: "Black", score: 50, host: "FS1", name: "a.txt" },
  { id: "c", severity: "Red", score: 90, host: "DC01", name: "c.txt" },
];

test("default sort: severity then score desc", () => {
  assert.deepStrictEqual(SMSort.sortFindings(recs, null, false).map((r) => r.id), ["b", "c", "a"]);
});

test("sort by a column ascending", () => {
  assert.deepStrictEqual(SMSort.sortFindings(recs, "name", false).map((r) => r.id), ["b", "a", "c"]);
});

test("sort by a column descending", () => {
  assert.deepStrictEqual(SMSort.sortFindings(recs, "score", true).map((r) => r.id), ["c", "a", "b"]);
});

test("groupBy host yields ordered group buckets", () => {
  const g = SMSort.groupFindings(recs, "host");
  assert.deepStrictEqual(g.map((x) => x.key), ["DC01", "FS1"]);
  assert.deepStrictEqual(g[0].items.map((r) => r.id), ["c", "a"]);
});

test("groupBy null returns a single group", () => {
  const g = SMSort.groupFindings(recs, null);
  assert.strictEqual(g.length, 1);
  assert.strictEqual(g[0].key, null);
});

test("sort by severity column puts Black (rank 0) first ascending", () => {
  const r = [
    { id: "red", severity: "Red" },
    { id: "blk", severity: "Black" },
    { id: "gray", severity: "Gray" },
  ];
  assert.deepStrictEqual(SMSort.sortFindings(r, "severity", false).map((x) => x.id), ["blk", "red", "gray"]);
});

test("sort by severity column descending puts Black last", () => {
  const r = [
    { id: "red", severity: "Red" },
    { id: "blk", severity: "Black" },
  ];
  assert.deepStrictEqual(SMSort.sortFindings(r, "severity", true).map((x) => x.id), ["red", "blk"]);
});

test("groupBy severity orders Black bucket first", () => {
  const r = [
    { id: "1", severity: "Red" },
    { id: "2", severity: "Black" },
    { id: "3", severity: "Yellow" },
  ];
  assert.deepStrictEqual(SMSort.groupFindings(r, "severity").map((g) => g.key), ["Black", "Red", "Yellow"]);
});

test("groupFindings applies the requested column sort within buckets", () => {
  const r = [
    { id: "1", host: "DC01", name: "c.txt" },
    { id: "2", host: "DC01", name: "a.txt" },
    { id: "3", host: "FS1", name: "b.txt" },
  ];
  const g = SMSort.groupFindings(r, "host", "name", false);
  assert.deepStrictEqual(g.find((x) => x.key === "DC01").items.map((x) => x.id), ["2", "1"]);
});

test("groupFindings ungrouped respects an explicit column sort", () => {
  const r = [
    { id: "1", score: 50, severity: "Red" },
    { id: "2", score: 90, severity: "Red" },
  ];
  assert.deepStrictEqual(SMSort.groupFindings(r, null, "score", true)[0].items.map((x) => x.id), ["2", "1"]);
});
