const test = require("node:test");
const assert = require("node:assert");
// store.js sets globalThis.SMStore, which triage.js (SMActions) references.
require("../../snafflemap/templates/report/js/store.js");
const SMActions = require("../../snafflemap/templates/report/js/triage.js");

test("buildLootScript emits BOTH smbclient and impacket-smbclient per file", () => {
  // Regression for D-6: the loot script previously emitted only cmds[0]
  // (smbclient), dropping the impacket-smbclient line README promises.
  const recs = [{ path: "\\\\FS1\\home\\sub\\id_rsa" }];
  const script = SMActions.buildLootScript(recs);
  assert.match(script, /smbclient \/\/FS1\/home/);
  assert.match(script, /impacket-smbclient/);
  assert.match(script, /id_rsa/);
});

test("buildLootScript headers the script and counts findings", () => {
  const script = SMActions.buildLootScript([
    { path: "\\\\FS1\\home\\a.txt" },
    { path: "\\\\FS1\\home\\b.txt" },
  ]);
  assert.match(script, /^#!\/usr\/bin\/env bash/);
  assert.match(script, /2 findings/);
});
