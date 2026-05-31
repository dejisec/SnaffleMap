const test = require("node:test");
const assert = require("node:assert");
const SMDom = require("../../snafflemap/templates/report/js/dom.js");

test("escapeText neutralizes HTML", () => {
  assert.strictEqual(SMDom.escapeText('<img src=x onerror=1>'), "&lt;img src=x onerror=1&gt;");
});

test("highlightParts splits around a case-insensitive match", () => {
  const parts = SMDom.highlightParts("aXbXc", "x");
  assert.deepStrictEqual(parts, [
    { t: "a", hit: false }, { t: "X", hit: true },
    { t: "b", hit: false }, { t: "X", hit: true }, { t: "c", hit: false },
  ]);
});

test("highlightParts with empty term returns one plain part", () => {
  assert.deepStrictEqual(SMDom.highlightParts("abc", ""), [{ t: "abc", hit: false }]);
});
