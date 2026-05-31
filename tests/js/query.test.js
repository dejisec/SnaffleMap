const test = require("node:test");
const assert = require("node:assert");
const SMQuery = require("../../snafflemap/templates/report/js/query.js");

test("tokenize splits free words and field:value", () => {
  assert.deepStrictEqual(SMQuery.tokenize("web rule:Password"), [
    { neg: false, field: null, value: "web" },
    { neg: false, field: "rule", value: "Password" },
  ]);
});

test("tokenize handles negation and quoted phrases", () => {
  assert.deepStrictEqual(SMQuery.tokenize('-status:false-positive path:"Program Files"'), [
    { neg: true, field: "status", value: "false-positive" },
    { neg: false, field: "path", value: "Program Files" },
  ]);
});

test("tokenize keeps comparison operators in the value", () => {
  assert.deepStrictEqual(SMQuery.tokenize("score:>80 size:<1mb"), [
    { neg: false, field: "score", value: ">80" },
    { neg: false, field: "size", value: "<1mb" },
  ]);
});

const recs = [
  { id: "a", path: "\\\\DC01\\SYSVOL\\web.config", host: "DC01", share: "SYSVOL",
    rule: "Password", ext: ".config", severity: "Red", tier: "High", score: 80,
    size: 4096, type: "file", crackable: true, writable: false, delta_status: "new",
    matched: "secret", snippet: "pw=secret", name: "web.config" },
  { id: "b", path: "\\\\FS1\\home\\id_rsa", host: "FS1", share: "home",
    rule: "PrivateKey", ext: "", severity: "Black", tier: "Critical", score: 95,
    size: 1675, type: "file", crackable: false, writable: true, delta_status: null,
    matched: "", snippet: "", name: "id_rsa" },
];
function filter(q) { const p = SMQuery.parseQuery(q); return recs.filter(p).map((r) => r.id); }

test("free word matches across path/rule/matched/snippet, case-insensitive", () => {
  assert.deepStrictEqual(filter("SECRET"), ["a"]);
});
test("field match with wildcard", () => {
  assert.deepStrictEqual(filter("host:DC*"), ["a"]);
});
test("negation excludes", () => {
  assert.deepStrictEqual(filter("-rule:Password"), ["b"]);
});
test("severity OR via pipe", () => {
  assert.deepStrictEqual(filter("sev:black|red").sort(), ["a", "b"]);
});
test("numeric score comparison", () => {
  assert.deepStrictEqual(filter("score:>90"), ["b"]);
});
test("size with unit", () => {
  assert.deepStrictEqual(filter("size:>2kb"), ["a"]);
});
test("crackable boolean", () => {
  assert.deepStrictEqual(filter("crackable:true"), ["a"]);
});
test("writable boolean", () => {
  assert.deepStrictEqual(filter("writable:true"), ["b"]);
});
test("delta status", () => {
  assert.deepStrictEqual(filter("delta:new"), ["a"]);
});
test("empty query matches everything", () => {
  assert.deepStrictEqual(filter("").sort(), ["a", "b"]);
});
