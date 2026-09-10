import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, writeFileSync, chmodSync, existsSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { ChioBridge } from "../dist/index.js";

function cliFixture(stdout = '{"decision":"allow"}', exit = 0) {
  const root = mkdtempSync(join(tmpdir(), "chio-check-security-"));
  const binary = join(root, "chio");
  const marker = join(root, "invoked");
  writeFileSync(binary, `#!/usr/bin/env bash\ntouch '${marker}'\nprintf '%s' '${stdout}'\nexit ${exit}\n`);
  chmodSync(binary, 0o755);
  return { bridge: ChioBridge.fromCli({ chioBinary: binary }), marker };
}

test("daemon check never calls tools/call or initializes an effecting session", async () => {
  let requests = 0;
  const bridge = ChioBridge.fromDaemon({ token: "token", fetchImpl: async () => { requests++; return new Response("{}"); } });
  await assert.rejects(() => bridge.check({ tool: "write_file", params: { path: "/protected" } }), /cannot be used as a precheck/);
  assert.equal(requests, 0);
});

test("nonzero CLI exit with allow JSON cannot authorize", async () => {
  const { bridge } = cliFixture('{"decision":"allow"}', 7);
  await assert.rejects(() => bridge.check({ tool: "write_file", params: {}, policyPath: "policy" }), /exited 7/);
});

for (const [label, response] of [
  ["malformed JSON", () => new Response("{")],
  ["missing allowed", () => new Response("{}")],
  ["truthy allowed", () => new Response('{"allowed":"true"}')],
  ["HTTP error", () => new Response('{"allowed":true}', {status: 503})],
  ["network interruption", () => { throw new Error("interrupted"); }],
] as const) {
  test(`budget ${label} denies without evaluating downstream`, async () => {
    const { bridge, marker } = cliFixture();
    const prior = globalThis.fetch;
    let calls = 0;
    globalThis.fetch = async () => { calls++; return response(); };
    try {
      const result = await bridge.check({ tool: "write_file", params: {}, policyPath: "policy" }, { capabilityId: "cap", costUsd: 1, trustToken: "token" });
      assert.equal(result.decision, "deny");
      assert.equal(existsSync(marker), false);
      assert.equal(calls, 1, "failed admission must not retry");
    } finally { globalThis.fetch = prior; }
  });
}

test("positive sub-cent budget charge rounds up and valid admission allows evaluation", async () => {
  const { bridge, marker } = cliFixture();
  const prior = globalThis.fetch;
  globalThis.fetch = async (_input, init) => {
    assert.equal(JSON.parse(String(init?.body)).exposureUnits, 1);
    return new Response('{"allowed":true}');
  };
  try {
    assert.equal((await bridge.check({ tool: "read_file", params: {}, policyPath: "policy" }, {capabilityId: "cap", trustToken: "token", costUsd: 0.0001})).decision, "allow");
    assert.equal(existsSync(marker), true);
  } finally { globalThis.fetch = prior; }
});
