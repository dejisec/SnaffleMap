const test = require("node:test");
const assert = require("node:assert");
const SMData = require("../../snafflemap/templates/report/js/data.js");

const SM = {
  report_id: "eng",
  meta: {
    f1: { path: "\\\\DC01\\SYSVOL\\web.config", host: "DC01", share: "SYSVOL",
          type: "file", rule: "Password", severity: "Red", score: 80, size: 4096,
          snippet: "pw=secret", matched: "secret", detector_ids: ["x"], actions: [], sources: [] },
    f2: { path: "\\\\FS1\\home\\id_rsa", host: "FS1", share: "home",
          type: "file", rule: "PrivateKey", severity: "Black", score: 95, size: 1675,
          snippet: "", matched: "", detector_ids: [], actions: [], sources: [] },
  },
  triage: { f1: { status: "confirmed-loot", star: true, notes: [], tags: [] } },
  suppressions: [],
};

test("buildModel returns one record per meta entry with id attached", () => {
  const m = SMData.buildModel(SM);
  assert.strictEqual(m.findings.length, 2);
  assert.strictEqual(m.findings.find((f) => f.id === "f1").host, "DC01");
});

test("buildModel computes ext and hasSnippet", () => {
  const m = SMData.buildModel(SM);
  const f1 = m.findings.find((f) => f.id === "f1");
  assert.strictEqual(f1.ext, ".config");
  assert.strictEqual(f1.hasSnippet, true);
  assert.strictEqual(m.findings.find((f) => f.id === "f2").hasSnippet, false);
});

test("buildModel indexes distinct hosts/rules/shares with counts", () => {
  const m = SMData.buildModel(SM);
  assert.deepStrictEqual(m.index.host.DC01, 1);
  assert.deepStrictEqual(m.index.rule.PrivateKey, 1);
});
