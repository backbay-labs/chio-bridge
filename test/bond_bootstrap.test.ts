/**
 * Unit test for Wave 3 Gap 3 — `bond()` on a fresh receipt DB.
 *
 * Reproduces the OpenCode-path chio_init symptom: when the receipt DB
 * has no receipts at all, the pre-Wave-3 bridge passed the
 * freshly-generated subject public key to `arc passport create`, which
 * rejects with `no receipts found for subject <hex>`. The plugin surfaced
 * this as an opaque "not bonded (arc daemon/CLI unreachable)".
 *
 * The fix: when `resolveSubjectPublicKey` falls through to the fresh
 * key AND a daemon is reachable, bond() seeds a bootstrap receipt via
 * an always-allowed `check({tool: "echo"})` against the MCP edge, then
 * re-reads the newest receipt to recover the kernel-minted subject key.
 *
 * This test exercises the fake-arc + fake-daemon layered path so we
 * don't need the real harness online for CI.
 */
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

test("bond() fails fast when the receipt DB is fresh AND the daemon cannot seed", async () => {
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
  const fetchImpl: typeof fetch = (async () => {
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
});

test("bond() on a fresh DB with a working daemon bootstraps a seed receipt automatically", async () => {
  const logPath = join(mkdtempSync(join(tmpdir(), "chio-arc-log-")), "calls.log");

  // Stateful fake arc: first receipt-list call returns empty, subsequent
  // calls return a pre-seeded receipt with a subject_key. passport create
  // writes a valid AgentPassport to --output.
  const listStateFile = join(mkdtempSync(join(tmpdir(), "chio-state-")), "seeded");
  const SUBJECT_HEX =
    "deadbeef00000000deadbeef00000000deadbeef00000000deadbeef00000000";
  const fakeArcScript = [
    'echo "$@" >> "' + logPath + '"',
    'args=("$@")',
    "# Identify the subcommand (first non-flag after any --receipt-db pair)",
    'cmd=""',
    "next_is_val=0",
    'for a in "${args[@]}"; do',
    '  if [[ "${next_is_val}" == "1" ]]; then',
    "    next_is_val=0",
    "    continue",
    "  fi",
    '  case "${a}" in',
    "    --receipt-db) next_is_val=1 ;;",
    "    --*) ;;",
    "    *)",
    '      cmd="${a}"',
    "      break ;;",
    "  esac",
    "done",
    "",
    'case "${cmd}" in',
    "  receipt)",
    '    if [[ -f "' + listStateFile + '" ]]; then',
    '      echo \'{"id":"rcpt_seed","metadata":{"attribution":{"subject_key":"' +
      SUBJECT_HEX +
      "\"}}}'",
    "    fi",
    "    exit 0",
    "    ;;",
    "  passport)",
    '    touch "' + listStateFile + '"',
    '    out=""',
    "    for ((i = 1; i <= $#; i++)); do",
    '      if [[ "${!i}" == "--output" ]]; then',
    "        j=$((i + 1))",
    '        out="${!j}"',
    "      fi",
    "    done",
    '    cat > "${out}" <<EOF',
    "{",
    '  "schema": "arc.agent-passport.v1",',
    '  "subject": "did:chio:' + SUBJECT_HEX + '",',
    '  "credentials": [{"unsigned":{}, "proof":{}}],',
    '  "merkleRoots": [],',
    '  "issuedAt": "2026-01-01T00:00:00Z",',
    '  "validUntil": "2026-02-01T00:00:00Z"',
    "}",
    "EOF",
    '    echo \'{"ok":true}\'',
    "    exit 0",
    "    ;;",
    "esac",
    "exit 2",
  ].join("\n");
  const chioBinary = makeFakeChio(fakeArcScript);

  // Fake MCP edge: the seeding check() call must succeed, and the
  // subsequent passport publish must succeed.
  let seedCalled = false;
  let publishCalled = false;
  const fetchImpl: typeof fetch = (async (input: URL | Request | string, init?: RequestInit) => {
    const url = typeof input === "string" ? input : input instanceof URL ? input.toString() : input.url;
    // MCP edge "initialize" and "tools/call" both hit /mcp.
    if (url.endsWith("/mcp")) {
      seedCalled = true;
      const body = JSON.parse(String(init?.body ?? "{}")) as { method?: string; id?: number };
      if (body.method === "initialize") {
        return new Response(
          JSON.stringify({
            jsonrpc: "2.0",
            id: body.id,
            result: {
              protocolVersion: "2025-06-18",
              capabilities: { tools: {} },
              serverInfo: { name: "fake", version: "0" },
            },
          }),
          { status: 200, headers: { "content-type": "application/json" } },
        );
      }
      if (body.method === "tools/call") {
        return new Response(
          JSON.stringify({
            jsonrpc: "2.0",
            id: body.id,
            result: { content: [{ type: "text", text: "ok" }] },
          }),
          { status: 200, headers: { "content-type": "application/json" } },
        );
      }
      // notifications/initialized and other notifications: 202 empty.
      return new Response(null, { status: 202 });
    }
    if (url.includes("/v1/passport/statuses")) {
      publishCalled = true;
      return new Response(
        JSON.stringify({
          passportId: "pid-bootstrap",
          subject: "did:chio:deadbeef00000000deadbeef00000000deadbeef00000000deadbeef00000000",
          issuers: ["did:chio:issuer00000"],
          issuerCount: 1,
          publishedAt: 1_712_000_000,
          updatedAt: 1_712_000_000,
          status: "active",
          validUntil: "2026-02-01T00:00:00Z",
        }),
        { status: 200, headers: { "content-type": "application/json" } },
      );
    }
    return new Response("{}", { status: 200 });
  }) as unknown as typeof fetch;

  const harnessDir = mkdtempSync(join(tmpdir(), "chio-fake-harness-"));
  const bridge = ChioBridge.fromDaemon({
    token: "tkn",
    fetchImpl,
    mcpEdgeUrl: "http://127.0.0.1:9998",
    trustUrl: "http://127.0.0.1:9999",
    receiptDbPath: join(harnessDir, "receipts.sqlite"),
  });
  (bridge as unknown as { cli: ChioCli }).cli = new ChioCli(chioBinary);

  const policyPath = join(harnessDir, "policy.yaml");
  writeFileSync(
    policyPath,
    `hushspec: "0.1.0"\nname: bootstrap-test\nrules:\n  tool_access:\n    enabled: true\n    default: block\n    allow: [echo]\n`,
    "utf8",
  );

  const passport = await bridge.bond({ policyPath, ttl: "1h", budgetUsd: 50 });
  assert.ok(passport.did.startsWith("did:chio:"));
  assert.equal(passport.status, "active");
  assert.ok(seedCalled, "bootstrap seed check() was not invoked on fresh db");
  assert.ok(publishCalled, "passport publish was not invoked");
});
