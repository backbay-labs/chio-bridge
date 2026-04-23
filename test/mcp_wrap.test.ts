/**
 * Unit tests for `wrapMcp` — covers Wave 3 Gap 1:
 *   - The options bag forwards `--policy`, `--server-id`, and
 *     `--auth-token` to the real `arc mcp serve-http` flag surface.
 *   - The readiness banner match replaces the previous 2s fallback.
 *   - `serverId` defaults to a deterministic sha256(cmd[0]) hash.
 *   - Backward-compat: rejects when no `--policy` is supplied, since
 *     the real CLI's Usage signature requires it.
 *
 * These tests stub the arc binary via `makeFakeChio` so no network is
 * required.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, writeFileSync, chmodSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { ChioBridge } from "../dist/index.js";

function makeFakeChio(scriptBody: string): string {
  const dir = mkdtempSync(join(tmpdir(), "chio-arc-"));
  const binPath = join(dir, "arc");
  writeFileSync(binPath, `#!/usr/bin/env bash\n${scriptBody}\n`, "utf8");
  chmodSync(binPath, 0o755);
  return binPath;
}

test("wrapMcp forwards --policy --server-id --auth-token to arc mcp serve-http", async () => {
  const logPath = join(mkdtempSync(join(tmpdir(), "chio-arc-log-")), "argv.log");
  // Fake arc that records its argv to a file and emits the real banner
  // so `waitForReady` unblocks on the match.
  const chioBinary = makeFakeChio(`
printf '%s\\n' "$@" > "${logPath}"
>&2 echo "remote MCP edge listening on http://127.0.0.1:9876/mcp"
# keep alive so the bridge's .stop() can send SIGTERM.
while true; do sleep 30; done
`);
  const bridge = ChioBridge.fromCli({ chioBinary });
  const wrapped = await bridge.wrapMcp(["node", "hello.mjs"], {
    policy: "/tmp/p.yaml",
    serverId: "custom-server",
    authToken: "tkn-abc",
    listen: "127.0.0.1:0",
  });

  try {
    const fs = await import("node:fs/promises");
    const argv = (await fs.readFile(logPath, "utf8")).trim().split("\n");
    const idxPolicy = argv.indexOf("--policy");
    assert.ok(idxPolicy >= 0, `missing --policy in argv: ${argv.join(" ")}`);
    assert.equal(argv[idxPolicy + 1], "/tmp/p.yaml");
    const idxSid = argv.indexOf("--server-id");
    assert.ok(idxSid >= 0, "missing --server-id");
    assert.equal(argv[idxSid + 1], "custom-server");
    const idxTok = argv.indexOf("--auth-token");
    assert.ok(idxTok >= 0, "missing --auth-token");
    assert.equal(argv[idxTok + 1], "tkn-abc");
    assert.equal(wrapped.url, "http://127.0.0.1:9876/mcp");
    assert.equal(wrapped.authToken, "tkn-abc");
    assert.equal(wrapped.serverId, "custom-server");
    assert.equal(wrapped.policy, "/tmp/p.yaml");
    assert.equal(wrapped.listen, "127.0.0.1:9876");
  } finally {
    await wrapped.stop();
  }
});

test("wrapMcp derives a deterministic serverId from sha256(cmd[0]) when none supplied", async () => {
  const logPath = join(mkdtempSync(join(tmpdir(), "chio-arc-log-")), "argv.log");
  const chioBinary = makeFakeChio(`
printf '%s\\n' "$@" > "${logPath}"
>&2 echo "remote MCP edge listening on http://127.0.0.1:7777/mcp"
while true; do sleep 30; done
`);
  const bridge = ChioBridge.fromCli({ chioBinary });
  const a = await bridge.wrapMcp(["node", "server-a.mjs"], { policy: "/tmp/p.yaml" });
  const bridge2 = ChioBridge.fromCli({ chioBinary });
  const b = await bridge2.wrapMcp(["node", "server-b.mjs"], { policy: "/tmp/p.yaml" });

  try {
    // Same cmd[0] ("node") yields the same serverId.
    assert.equal(a.serverId, b.serverId);
    assert.match(a.serverId, /^chio-wrap-[0-9a-f]{16}$/);
    // Auth tokens are randomly generated when unset.
    assert.match(a.authToken, /^[0-9a-f]{64}$/);
    assert.notEqual(a.authToken, b.authToken);
  } finally {
    await a.stop();
    await b.stop();
  }
});

test("wrapMcp rejects when options.policy is missing (real CLI requires it)", async () => {
  const chioBinary = makeFakeChio(`exit 0`);
  const bridge = ChioBridge.fromCli({ chioBinary });
  await assert.rejects(
    () => bridge.wrapMcp(["node", "hello.mjs"]),
    /options\.policy/,
  );
});

test("wrapMcp surfaces a timeout when the readiness banner never arrives", async () => {
  // Fake arc that never emits "listening on".
  const chioBinary = makeFakeChio(`
while true; do sleep 30; done
`);
  const bridge = ChioBridge.fromCli({ chioBinary });
  await assert.rejects(
    () =>
      bridge.wrapMcp(["node", "server.mjs"], {
        policy: "/tmp/p.yaml",
        readinessTimeoutMs: 250,
      }),
    /mcp_wrap_timeout|did not signal readiness/,
  );
});
