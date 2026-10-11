import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

const smoke = await readFile(new URL("./smoke-test.sh", import.meta.url), "utf8");

function block(name) {
  const matched = smoke.match(new RegExp(`${name}_status="\\$\\(request[\\s\\S]*?\\n  "\\$(?:api|participant)_origin[^\\n]*"\\)"`));
  assert.ok(matched, `missing bounded request ${name}`);
  return matched[0];
}

test("manifest is verified before provider mutations and exact fifteen IDs read back", () => {
  assert.ok(smoke.indexOf("statement_ids_json=") < smoke.indexOf("allowlist_status="));
  assert.match(smoke, /\(\$parts \| length\) == 15/);
  assert.match(smoke, /\(\$numbers \| unique \| length\) == 15/);
  assert.match(smoke, /type == "array" and length == 15/);
  assert.match(smoke, /\(\[\.\[\]\.tid\] \| sort\) == \(\$expected \| sort\)/);
  assert.match(smoke, /\(\[range\(0;16\)\] - \.\)\[0\]/);
});

test("trusted requests never mix browser identity inputs or export participant tokens", () => {
  for (const name of ["allowed", "warm", "invalid", "revoked", "vote", "warm_revoked"]) {
    const request = block(name);
    assert.match(request, /X-FNCP-Gateway-Key/);
    assert.match(request, /X-FNCP-Participant-XID/);
    assert.doesNotMatch(request, /--data-urlencode "(?:xid|pid|agid)=/);
    assert.doesNotMatch(request, /xid: \$xid|Authorization: Bearer/);
  }
  assert.doesNotMatch(smoke, /participant_token=|\.auth\.token/);
  for (const response of ["allowed", "vote", "warm"]) {
    assert.ok(smoke.includes(`jq -e 'has("auth") | not' "$work_dir/${response}.json"`));
  }
});

test("suggestions, unknown statements, invalid votes and direct routes are denied", () => {
  for (const [name, status] of [
    ["unknown_vote", "400"], ["invalid_vote", "400"],
    ["suggestion", "404"], ["proxy_suggestion", "405"],
    ["direct_vote", "403"], ["participant", "400"], ["missing_participant", "403"],
  ]) {
    block(name);
    assert.ok(smoke.includes(`expect_status "$${name}_status" "${status}"`));
  }
  assert.match(block("unknown_vote"), /--argjson tid "\$unknown_tid"/);
  assert.match(block("invalid_vote"), /vote: 2/);
});

test("revoked established identity must fail with current allowlist denial", () => {
  assert.match(block("warm_revoked"), /\/api\/v3\/votes/);
  assert.match(smoke, /\.error == "polis_err_xid_not_allowed"' "\$work_dir\/warm-revoked\.json"/);
  assert.match(smoke, /real browser-session assurance not established/);
  assert.match(smoke, /does not test whole-round closure/);
  assert.match(smoke, /lifecycle unchanged/);
  assert.doesNotMatch(smoke, /close_status=|is_active|--request PUT/);
});

test("early failure cleanup revokes only this invocation's generated XID", () => {
  assert.match(smoke, /trap cleanup EXIT/);
  assert.match(smoke, /cleanup_status=.*\$\(request/);
  assert.match(smoke, /participant_xid "\$allowed_xid"/);
  assert.match(smoke, /provider_removed="true"/);
  assert.doesNotMatch(smoke, /replace_all|DELETE FROM|TRUNCATE/);
});
