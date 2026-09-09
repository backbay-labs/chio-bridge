import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, writeFileSync, chmodSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { ChioBridge } from "../dist/index.js";
import { ChioCli } from "../dist/client/cli.js";

function makeFakeChio(scriptBody: string): string {
  const dir = mkdtempSync(join(tmpdir(), "chio-arc-"));
  const binPath = join(dir, "arc");
  writeFileSync(binPath, `#!/usr/bin/env bash\n${scriptBody}\n`, "utf8");
  chmodSync(binPath, 0o755);
  return binPath;
}

test("bond() fails on empty receipt database without executing bootstrap effects", async () => {
  // Fake arc: receipt list always returns empty; passport create fails.
  const chioBinary = makeFakeChio(
    [
      "# Emulate arc receipt list --limit 1 (empty DB: no JSON lines)",
      'for a in "$@"; do',
      '  case "$a" in',
      "    list) exit 0 ;;",
      "  esac",
      "done",
      "# Any other subcommand: exit non-zero to mimic no-receipts-found.",
      '>&2 echo "no receipts found for subject"',
      "exit 1",
    ].join("\n"),
  );
  let networkCalls = 0;
  const fetchImpl: typeof fetch = (async () => {
    networkCalls++;
    // Force the daemon.check() seed attempt to fail (ECONNREFUSED).
    throw new Error("ECONNREFUSED");
  }) as unknown as typeof fetch;

  const harnessDir = mkdtempSync(join(tmpdir(), "chio-fake-harness-"));
  // A pre-existing (but non-existent) receipt db path is fine — arc
  // CLI will be mocked and never read the file.
  const bridge = ChioBridge.fromDaemon({
    token: "t",
    fetchImpl,
    mcpEdgeUrl: "http://127.0.0.1:0",
    trustUrl: "http://127.0.0.1:0",
    receiptDbPath: join(harnessDir, "receipts.sqlite"),
  });
  (bridge as unknown as { cli: ChioCli }).cli = new ChioCli(chioBinary);

  // Write a valid policy fixture. We only need to satisfy loadPolicy /
  // lintPolicy; nothing actually reads the rules here since the CLI
  // mock short-circuits before issuing credentials.
  const policyPath = join(harnessDir, "policy.yaml");
  writeFileSync(
    policyPath,
    `hushspec: "0.1.0"\nname: fresh-db-test\nrules:\n  tool_access:\n    enabled: true\n    default: block\n    allow: [echo]\n`,
    "utf8",
  );

  await assert.rejects(
    () => bridge.bond({ policyPath, ttl: "1h", budgetUsd: 50 }),
    /no receipts|passport_create_failed/i,
  );
  assert.equal(networkCalls, 0, "passport creation must not execute bootstrap tools");
});
