const test = require("node:test");
const assert = require("node:assert");
const SMStore = require("../../snafflemap/templates/report/js/store.js");

test("mergeTriage prefers newer updated_at and unions notes", () => {
  const a = { f1: { status: "new", updated_at: "2026-01-01", notes: [{ by: "x", at: "t1", text: "a" }] } };
  const b = { f1: { status: "confirmed-loot", updated_at: "2026-02-01", notes: [{ by: "y", at: "t2", text: "b" }] } };
  const out = SMStore.mergeTriage(a, b);
  assert.strictEqual(out.f1.status, "confirmed-loot");
  assert.strictEqual(out.f1.notes.length, 2);
});

test("lootCommands builds smbclient + impacket for a UNC file", () => {
  const cmds = SMStore.lootCommands("\\\\FS1\\home\\sub\\id_rsa");
  const joined = cmds.join("\n");
  assert.match(joined, /smbclient \/\/FS1\/home/);
  assert.match(joined, /impacket-smbclient/);
  assert.match(joined, /id_rsa/);
});

test("parseUnc extracts host/share/rest/file", () => {
  assert.deepStrictEqual(SMStore.parseUnc("\\\\FS1\\home\\a\\b.txt"),
    { host: "FS1", share: "home", restPath: "a/b.txt", file: "b.txt" });
});

test("buildSidecar wraps triage + suppressions with report id", () => {
  const sc = SMStore.buildSidecar("eng", { f1: { status: "new" } }, [{ kind: "rule", value: "X" }]);
  assert.strictEqual(sc.report_id, "eng");
  assert.deepStrictEqual(sc.triage.f1.status, "new");
  assert.deepStrictEqual(sc.suppressions[0].value, "X");
});

test("lootCommands returns [] for a share-root path (no file)", () => {
  assert.deepStrictEqual(SMStore.lootCommands("\\\\H\\S"), []);
});

test("lootCommands returns [] for a non-UNC path", () => {
  assert.deepStrictEqual(SMStore.lootCommands("C:\\Users\\x"), []);
});

test("lootCommands quotes paths containing spaces", () => {
  const joined = SMStore.lootCommands("\\\\H\\S\\my docs\\secret.txt").join("\n");
  assert.match(joined, /get "my docs\/secret\.txt"/);
  // outer -c value must use single quotes so the inner double quotes are literal
  assert.match(joined, /-c 'get /);
});

test("mergeTriage does not mutate incoming for a new fid", () => {
  const incoming = { f1: { status: "new", notes: [] } };
  const out = SMStore.mergeTriage({}, incoming);
  out.f1.status = "reported";
  assert.strictEqual(incoming.f1.status, "new");
});
