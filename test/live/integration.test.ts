/**
 * Live-daemon integration test for @chio/bridge.
 *
 * Gated behind `npm run test:live` so the plain `npm test` path stays
 * fast and offline. Runs the chio-test-harness (real `arc trust serve`
 * + `chio mcp serve-http`) and exercises the legacy public API contract.
 * Protected-host acceptance and delegated execution are separate suites.
 *
 * Preconditions:
 *   - arc binary available (CHIO_BIN, arc on PATH, or
 *     standalone/arc/target/release/arc)
 *   - ports 8931 and 8940 free
 *   - node >= 22 (uses `node:test` + experimental strip-types)
 */

import { test, before, after } from "node:test";
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { existsSync, readFileSync, writeFileSync, mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import { randomUUID } from "node:crypto";
import { ChioClient } from "@chio-protocol/sdk";
import { canonicalizeJson, sha256Hex } from "@chio-protocol/sdk/invariants";
import { ChioBridge, verifyBoundReceipt } from "../../dist/index.js";

// Explicit operator execution for this API compatibility suite. This is not a
// host containment test. The fixture pins the signer from its private local
// kernel identity and checks each request and claimed output. Operator sessions do not
// assert the delegated session delivery-acknowledgement contract.
let session: Awaited<ReturnType<ChioClient["initialize"]>>;
let context: any;
let signer: string;
async function execute(tool: string, args: Record<string, unknown>) {
  const requestId = randomUUID();
  const params = { name: tool, arguments: args, _meta: { chioRequestId: requestId } };
  const response = await session.requestResult<any>("tools/call", params);
  assert.ok("result" in response, "explicit execution must return an evidence envelope");
  const result = response.result;
  const envelope = result?._meta?.chioEvidence;
  assert.equal(envelope?.requestId, requestId, JSON.stringify(result));
  assert.ok(verifyBoundReceipt(envelope?.receipt, { trustedSigners: [signer],
    subjectKey: context.subjectKey, capabilityId: context.capabilityIds[0],
    serverId: "hello-mcp", tool, parameters: args, requestId }), "receipt must bind the trusted caller and request");
  if (envelope.receipt.decision.verdict === "allow") {
    assert.equal(envelope.terminalState, "completed");
    assert.equal(envelope.outputKind, "value");
    assert.equal(envelope.receipt.content_hash, sha256Hex(canonicalizeJson(envelope.output)));

  }
  return envelope;
}

const HERE = dirname(fileURLToPath(import.meta.url));
const HARNESS_DIR = resolve(HERE, "../../../chio-test-harness");
const START_SH = join(HARNESS_DIR, "bin/start.sh");
const STOP_SH = join(HARNESS_DIR, "bin/stop.sh");
const TOKEN_FILE = join(HARNESS_DIR, "var/trust.token");
const CANONICAL_POLICY = join(HARNESS_DIR, "policy/canonical.yaml");
const HELLO_MCP = join(HARNESS_DIR, "hello-mcp/server.mjs");

let bridge: ChioBridge;
let token: string;
let tmpEvidenceDir: string;

before(async () => {
  if (!existsSync(START_SH)) {
    throw new Error(`chio-test-harness not found at ${HARNESS_DIR}`);
  }
  const result = spawnSync("bash", [START_SH], {
    encoding: "utf8",
    timeout: 60_000,
  });
  if (result.status !== 0) {
    throw new Error(
      `start.sh failed (status ${result.status}):\n${result.stdout}\n${result.stderr}`,
    );
  }
  if (!result.stdout.trim().endsWith("READY")) {
    throw new Error(`start.sh did not print READY:\n${result.stdout}`);
  }
  token = readFileSync(TOKEN_FILE, "utf8").trim();
  // Make sure the bridge can locate the chio CLI for passport creation.
  // Prefer an explicit override, then the harness's release build.
  if (!process.env.CHIO_BIN) {
    // Wave 5.0.1: chio-policy re-landed first-class velocity/human_in_loop
    // variants, so the `chio` binary again accepts the canonical harness
    // policy. Prefer `chio` over the legacy `arc` artifact; fall back to
    // `arc` only if `chio` has not been built yet.
    const chioCandidate = resolve(HARNESS_DIR, "../arc/target/release/chio");
    const arcCandidate = resolve(HARNESS_DIR, "../arc/target/release/arc");
    if (existsSync(chioCandidate)) process.env.CHIO_BIN = chioCandidate;
    else if (existsSync(arcCandidate)) process.env.CHIO_BIN = arcCandidate;
  }
  bridge = ChioBridge.fromDaemon({
    trustUrl: "http://127.0.0.1:8940",
    mcpEdgeUrl: "http://127.0.0.1:8931",
    token,
    // Point createPassport()/bond() at the harness's shared receipt DB
    // so `arc passport create` can build a real attested credential
    // without bootstrapping its own subject keypair.
    receiptDbPath: join(HARNESS_DIR, "var", "receipts.sqlite"),
  });
  tmpEvidenceDir = mkdtempSync(join(tmpdir(), "chio-live-"));
  writeFileSync(join(tmpEvidenceDir,"echo-output.json"), JSON.stringify({content:[{type:"text",text:"policy fixture"}],structuredContent:{msg:"policy fixture"}}), {flag:"wx"});
  session = await ChioClient.withStaticBearer("http://127.0.0.1:8931", token).initialize({
    clientInfo: { name: "bridge-live-compatibility", version: "0.3.0" },
  });
  const authority = await session.requestResult<any>("chio/execution-context");
  assert.ok("result" in authority);
  context = authority.result;
  assert.equal(context.capabilityIds.length, 1);
  signer = readFileSync(join(HARNESS_DIR, "var/mcp-sessions.sqlite.kernel.pub"), "utf8").trim();
  assert.match(signer, /^[a-f0-9]{64}$/);
  await execute("echo", { msg: "explicit-passport-evidence" });
});

after(async () => {
  if (session) await session.close();
  spawnSync("bash", [STOP_SH], { encoding: "utf8", timeout: 30_000 });
});

test("loadPolicy parses the canonical HushSpec 0.1.0 harness policy", async () => {
  const spec = await bridge.loadPolicy(CANONICAL_POLICY);
  assert.equal(spec.hushspec, "0.1.0");
  assert.ok(spec.rules && typeof spec.rules === "object");
});

test("bond creates a did:chio passport and publishes lifecycle state", async () => {
  const passport = await bridge.bond({
    policyPath: CANONICAL_POLICY,
    subjectPublicKey: context.subjectKey,
    ttl: "1h",
    budgetUsd: 100,
  });
  assert.ok(
    (passport.did.startsWith("did:chio:") || passport.did.startsWith("did:arc:")),
    `expected did:chio subject, got ${passport.did}`,
  );
  assert.ok(passport.passportId, "expected SHA256 passport artifact id");
  assert.ok((passport.issuer.startsWith("did:chio:") || passport.issuer.startsWith("did:arc:")), "expected did:chio issuer");
  assert.equal(passport.status, "active");
  // Wave D Bug 1: bond() with a budget cap must attach a non-empty
  // capabilityId. The trust plane issues and attenuates the capability
  // so downstream check({capabilityId}) calls can drive the
  // `/v1/budgets/authorize-exposure` mediation endpoint. Older builds
  // returned an empty string.
  assert.ok(
    typeof passport.capabilityId === "string" && passport.capabilityId.length > 0,
    `expected a non-empty capabilityId on the bonded passport, got "${passport.capabilityId}"`,
  );
  // Lifecycle should resolve on a follow-up verify.
  const valid = await bridge.verifyPassport(passport.did);
  assert.equal(valid, true, "expected lifecycle resolve to report active");
  // Wave 5.2 bug fix: status(passportId) against the live trust plane
  // must map `PassportLifecycleRecord.status === "active"` to
  // `bonded: true`, and `validUntil` to `ttlExpiresAt`. Budget/guard
  // fields stay undefined (those aren't surfaced by this endpoint).
  const st = await bridge.status(passport.passportId!);
  assert.equal(st.bonded, true, `expected bonded=true, got ${JSON.stringify(st)}`);
  assert.equal(st.status, "active");
  assert.ok(
    /^\d{4}-\d{2}-\d{2}T/.test(st.ttlExpiresAt),
    `expected RFC3339 ttlExpiresAt, got ${st.ttlExpiresAt}`,
  );
  assert.equal(st.budgetUsedUsd, undefined);
  assert.equal(st.budgetCapUsd, undefined);
  assert.equal(st.guardCount, undefined);
});

test("explicit echo execution returns verified output; check remains policy-only", async () => {
  const envelope = await execute("echo", { msg: "hello" });
  assert.equal(envelope.output.structuredContent.msg, "hello");
  await assert.rejects(bridge.check({ tool: "echo", params: { msg: "no execution" } }), {code:"missing_policy"});
  const verdict = await bridge.check({tool:"echo",params:{msg:"policy only"},policyPath:CANONICAL_POLICY}, {mode:"full",outputFixturePath:join(tmpEvidenceDir,"echo-output.json"),sessionDbPath:join(tmpEvidenceDir,"check-session.sqlite"),receiptDbPath:join(tmpEvidenceDir,"check-receipts.sqlite")});
  assert.equal(verdict.decision, "allow");
});

test("explicit delete_file denial preserves an independently observed disposable file", async () => {
  const resourceDir = mkdtempSync(join(tmpdir(), "chio-live-protected-"));
  const resource = join(resourceDir, "must-survive.txt");
  const original = "independently observed disposable resource\n";
  writeFileSync(resource, original, { flag: "wx" });
  const response = await session.requestResult<any>("tools/call", {name:"delete_file",arguments:{path:resource},_meta:{chioRequestId:randomUUID()}});
  assert.ok("result" in response);
  assert.equal(response.result.isError, true);
  assert.match(response.result.content[0].text, /not authorized by the active capability set/);
  // Capability prefilter denial has no signed execution envelope. The file
  // observer establishes this local negative effect, not an I06 evidence claim.
  assert.equal(readFileSync(resource, "utf8"), original, "denial must preserve the resource");
});

test("receipts.query returns a typed list with cryptographic receipts", async () => {
  // Prime the pump so at least one receipt exists for this run.
  await execute("echo", { msg: "prime" });
  const since = new Date(Date.now() - 60 * 60 * 1000);
  const receipts = await bridge.receipts({ since, limit: 25 });
  assert.ok(Array.isArray(receipts), "receipts() must return an array");
  assert.ok(receipts.length > 0, "explicit completed work must be queryable");
  {
    const r = receipts[0];
    assert.ok(typeof r.id === "string" && r.id.length > 0, "receipt.id missing");
    assert.ok(typeof r.signature === "string", "receipt.signature missing");
  }
});

test("verifyReceipt passes ed25519 verification on a live receipt", async () => {
  const since = new Date(Date.now() - 60 * 60 * 1000);
  const receipts = await bridge.receipts({ since, limit: 50 });
  assert.ok(receipts.length > 0, "missing receipt evidence fails the live gate");
  for (const r of receipts) {
    const ok = await bridge.verifyReceipt(r);
    assert.ok(ok, `verifyReceipt failed for ${r.id}`);
  }
});

test("revoke rejects an unknown subject without inventing a lifecycle record", async () => {
  await assert.rejects(bridge.revoke("did:chio:" + "12".repeat(32)), /no passport lifecycle record/);
});

test("exportEvidence requires an explicit read boundary and writes a real bundle", async () => {
  const out = join(tmpEvidenceDir, "evidence.json");
  const since = new Date(Date.now()-3600000);
  await assert.rejects(bridge.exportEvidence({since, outPath:out} as any), /boundary/i);
  assert.equal(existsSync(out), false);
  await assert.rejects(bridge.exportEvidence({since,outPath:out,readBoundary:{kind:"admin_all"},requireProofs:true}), /checkpoint coverage/);
  assert.equal(existsSync(out), false, "proof-required failure must not create an artifact");
  const written = await bridge.exportEvidence({since,outPath:out,readBoundary:{kind:"admin_all"},requireProofs:false});
  assert.equal(written, out);
  const evidence = JSON.parse(readFileSync(out,"utf8"));
  assert.ok(evidence && typeof evidence === "object");
  assert.ok(evidence.bundle, "kernel must return an evidence bundle");
  assert.ok(evidence.bundle.uncheckpointedReceipts.length > 0, "raw export must disclose incomplete checkpoint coverage");
  // This raw artifact is not promoted to verified evidence.
});

// ---------------------------------------------------------------------------
// Wave 3 gap tests - live integration for the three fixes.
// ---------------------------------------------------------------------------

test(
  "Gap 1: wrapMcp forwards policy/server-id/auth-token and hits ready via the real arc banner",
  { timeout: 15_000 },
  async () => {
    const wrapped = await bridge.wrapMcp(["node", HELLO_MCP], {
      policy: CANONICAL_POLICY,
      authToken: token,
      serverId: "chio-wrap-gap1",
      listen: "127.0.0.1:0",
      readinessTimeoutMs: 5_000,
      extraArgs: ["--server-name", "chio-wrap-gap1", "--session-db", join(tmpEvidenceDir,"wrapped-session.sqlite"), "--control-url", "http://127.0.0.1:8940"],
      env: {...process.env, CHIO_CONTROL_TOKEN:token},
    });
    try {
      // Banner-match recovers the URL directly from arc's own
      //   "remote MCP edge listening on http://<addr>/mcp"
      // output - no more 2s fallback.
      assert.match(wrapped.url, /^http:\/\/127\.0\.0\.1:\d+\/mcp$/);
      assert.equal(wrapped.serverId, "chio-wrap-gap1");
      assert.equal(wrapped.authToken, token);
      // MCP handshake against the wrapped edge using the forwarded
      // bearer. Streamable HTTP servers often respond 200 for
      // tools-capable clients and 202 for notifications; accept both.
      const r = await fetch(wrapped.url, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          Accept: "application/json, text/event-stream",
          Authorization: `Bearer ${token}`,
        },
        body: JSON.stringify({
          jsonrpc: "2.0",
          id: 1,
          method: "initialize",
          params: {
            protocolVersion: "2025-06-18",
            capabilities: {},
            clientInfo: { name: "chio-wrap-gap1", version: "0.0.1" },
          },
        }),
      });
      assert.ok(
        r.ok || r.status === 200 || r.status === 202,
        `wrapped edge initialize returned HTTP ${r.status}`,
      );
    } finally {
      await wrapped.stop();
    }
  },
);

test(
  "Gap 2: verifyPassport round-trips bond -> verify(active) -> revoke -> verify(false)",
  { timeout: 15_000 },
  async () => {
    await execute("echo", { msg: "gap2-prime" });
    const passport = await bridge.bond({
      policyPath: CANONICAL_POLICY,
      subjectPublicKey: context.subjectKey,
      ttl: "1h",
      budgetUsd: 10,
    });
    assert.ok((passport.did.startsWith("did:chio:") || passport.did.startsWith("did:arc:")));
    assert.ok(passport.passportId, "expected passportId from bond()");
    assert.equal(passport.status, "active");
    // Query by the SHA256 passport artifact id so multi-passport
    // subjects don't accidentally satisfy the assertion against a
    // sibling active record.
    const okById = await bridge.verifyPassport({ passportId: passport.passportId! });
    assert.equal(okById, true);
    // Revoke this specific passport via its id (bridge accepts both
    // did:chio subjects and raw passport ids).
    await bridge.revoke(passport.passportId!);
    const afterRevoke = await bridge.verifyPassport({ passportId: passport.passportId! });
    assert.equal(
      afterRevoke,
      false,
      "revoked passportId must verify false",
    );
  },
);

test("bond on a fresh receipt store refuses to manufacture tool evidence", async () => {
  const empty = join(tmpEvidenceDir, "empty-receipts.sqlite");
  const freshBridge = ChioBridge.fromDaemon({trustUrl:"http://127.0.0.1:8940",mcpEdgeUrl:"http://127.0.0.1:8931",token,receiptDbPath:empty});
  await assert.rejects(freshBridge.bond({policyPath:CANONICAL_POLICY,subjectPublicKey:context.subjectKey,ttl:"1h",budgetUsd:25}), {code:"passport_create_failed"});
});

// ---------------------------------------------------------------------------
// Wave 4 gap tests - live integration for the four bridge gaps.
// ---------------------------------------------------------------------------

test(
  "Gap 1 (live): issueCapability with auto-generated subject key returns a real CapabilityToken",
  { timeout: 15_000 },
  async () => {
    // Confirm real explicit execution before administrative issuance.
    await execute("echo", { msg: "gap1-prime" });
    const token = await bridge.issueCapability({
      // No subject / subjectPublicKey: bridge mints an ed25519 keypair.
      scope: {
        grants: [
          {
            server_id: "hello-mcp",
            tool_name: "echo",
            operations: ["invoke"],
            max_invocations: 5,
          },
        ],
      },
      ttl: "10m",
    });
    assert.ok(typeof token.id === "string" && token.id.length > 0, "expected capability id");
    assert.match(
      token.subjectPublicKey ?? "",
      /^[0-9a-f]{64}$/,
      "auto-generated subjectPublicKey should be 32-byte hex",
    );
    assert.match(
      token.subjectPrivateKeyHex ?? "",
      /^[0-9a-f]{64}$/,
      "auto-generated subjectPrivateKeyHex should be 32-byte hex",
    );
  },
);

test(
  "unsupported attenuation fails closed instead of administrative reissuance",
  { timeout: 15_000 },
  async () => {
    await execute("echo", { msg: "gap2-prime" });
    // 1. Issue a parent capability.
    const parent = await bridge.issueCapability({
      scope: {
        grants: [
          { server_id: "hello-mcp", tool_name: "echo", operations: ["invoke"] },
          { server_id: "hello-mcp", tool_name: "paid_action", operations: ["invoke"] },
        ],
      },
      ttl: "10m",
    });
    assert.ok(parent.id);
    await assert.rejects(bridge.attenuate(parent.id, {
      scope: {grants:[{server_id:"hello-mcp",tool_name:"echo",operations:["invoke"]}]},
      subjectPublicKey: parent.subjectPublicKey, ttlSeconds:300,
    }), {code:"unsupported_authority_operation"});
  },
);

test(
  "bond uses configured endpoints and prior explicit evidence",
  { timeout: 20_000 },
  async () => {
    // Re-uses the live harness on 8931/8940. The mechanical assertion
    // is that explicitly forwarding the configured URL produces the
    // same successful bond - the unit test (`Gap 3: ...8931`) covers
    // the leak-detection assertion against a non-default port. Here
    // we just confirm the live happy path stays green.
    const explicitBridge = ChioBridge.fromDaemon({
      trustUrl: "http://127.0.0.1:8940",
      mcpEdgeUrl: "http://127.0.0.1:8931",
      token,
      receiptDbPath: join(HARNESS_DIR, "var", "receipts.sqlite"),
    });
    const passport = await explicitBridge.bond({
      policyPath: CANONICAL_POLICY,
      subjectPublicKey: context.subjectKey,
      ttl: "30m",
      budgetUsd: 5,
    });
    assert.ok((passport.did.startsWith("did:chio:") || passport.did.startsWith("did:arc:")));
    assert.equal(passport.status, "active");
  },
);

test(
  "Gap 4 (live): revokeAllForSubject kills every active passport for a DID",
  { timeout: 25_000 },
  async () => {
    await execute("echo", { msg: "gap4-prime-1" });
    const a = await bridge.bond({
      policyPath: CANONICAL_POLICY,
      subjectPublicKey: context.subjectKey,
      ttl: "30m",
      budgetUsd: 5,
    });
    await execute("echo", { msg: "gap4-prime-2" });
    const b = await bridge.bond({
      policyPath: CANONICAL_POLICY,
      subjectPublicKey: context.subjectKey,
      ttl: "30m",
      budgetUsd: 5,
    });
    // Both bonds use the same harness subject (kernel-minted), so they
    // share a DID. The two passportIds differ - that's the whole point
    // of revokeAllForSubject.
    assert.equal(a.did, b.did, "expected matching subject DIDs across bonds");
    assert.notEqual(a.passportId, b.passportId, "expected distinct passport ids");
    const result = await bridge.revokeAllForSubject(a.did);
    // Both passports should be in the revoked set.
    assert.ok(
      result.revokedPassportIds.includes(a.passportId!),
      `expected ${a.passportId} in ${JSON.stringify(result.revokedPassportIds)}`,
    );
    assert.ok(
      result.revokedPassportIds.includes(b.passportId!),
      `expected ${b.passportId} in ${JSON.stringify(result.revokedPassportIds)}`,
    );
    // Subsequent verifyPassport(did) should report false because the
    // most-recent active record for the DID is now revoked.
    const stillValid = await bridge.verifyPassport(a.did);
    assert.equal(stillValid, false, "expected DID to verify false after revokeAllForSubject");
  },
);

// ---------------------------------------------------------------------------
// Legacy unbound budget authorization remains unavailable with the durable
// authority. Zero-cost checks are policy evaluations, not budget enforcement.
// ---------------------------------------------------------------------------

test(
  "policy-only checks work and legacy unbound budget mutation fails closed",
  { timeout: 20_000 },
  async () => {
    await execute("echo", { msg: "waved-live-prime" });
    const passport = await bridge.bond({
      policyPath: CANONICAL_POLICY,
      subjectPublicKey: context.subjectKey,
      ttl: "30m",
      budgetUsd: 10,
    });
    assert.ok(
      typeof passport.capabilityId === "string" &&
        passport.capabilityId.length > 0,
      `expected non-empty capabilityId after bond, got "${passport.capabilityId}"`,
    );
    const capId = passport.capabilityId;

    // These zero-cost checks do not consume spend or execute an MCP tool.
    // Each independent CLI fixture evaluation has its own durable state. The
    // CLI uses a fixed evaluation request ID, so reusing one store for different
    // parameters correctly produces a retained-operation conflict.
    for (let i = 0; i < 5; i += 1) {
      const v = await bridge.check(
        { tool: "echo", params: { msg: `iter-${i}` }, policyPath: CANONICAL_POLICY },
        { capabilityId: capId, costUsd: 0, mode:"full",outputFixturePath:join(tmpEvidenceDir,"echo-output.json"),sessionDbPath:join(tmpEvidenceDir,`evaluation-${i}-session.sqlite`),receiptDbPath:join(tmpEvidenceDir,`evaluation-${i}-receipts.sqlite`) },
      );
      assert.equal(
        v.decision,
        "allow",
        `iter ${i} expected allow, got ${JSON.stringify(v)}`,
      );
    }
    const unboundCharge = await bridge.check({tool:"echo",params:{msg:"over-budget"},policyPath:CANONICAL_POLICY}, {capabilityId:capId,costUsd:0.01,mode:"full",outputFixturePath:join(tmpEvidenceDir,"echo-output.json"),sessionDbPath:join(tmpEvidenceDir,"check-session.sqlite"),receiptDbPath:join(tmpEvidenceDir,"check-receipts.sqlite")});
    assert.equal(unboundCharge.decision, "deny", "legacy unbound charge must not escape durable admission");
    assert.equal(unboundCharge.guard, "budget");
    assert.match(unboundCharge.reason ?? "", /budget authorization failed: HTTP 500/);

  },
);
