/**
 * Wave 4 unit tests — one mechanical test per closed gap.
 *
 * Gap 1: `IssueCapabilityInput.subjectPublicKey` propagates to the
 *        trust plane; auto-generated ed25519 keypair fallback is
 *        surfaced on the response.
 * Gap 2: `attenuateCapability` runs `issue-narrower-then-revoke-old`
 *        because the trust plane on this build exposes no
 *        `/v1/capabilities/<id>/attenuate` handler.
 * Gap 3: every internal MCP call honours the bridge's configured
 *        `mcpEdgeUrl` — non-default ports must NOT leak to 8931.
 * Gap 4: `revokeAllForSubject(did)` lists, filters, and revokes every
 *        active passport whose subject matches.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, writeFileSync, chmodSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { ChioBridge } from "../dist/index.js";
import { ChioCli } from "../dist/client/cli.js";

type FetchCall = { url: string; init: RequestInit | undefined };

function mockFetch(
  handler: (call: FetchCall) => Response | Promise<Response>,
  record?: FetchCall[],
): typeof fetch {
  const impl = async (input: URL | Request | string, init?: RequestInit) => {
    const url = typeof input === "string" ? input : input instanceof URL ? input.toString() : input.url;
    const call: FetchCall = { url, init };
    record?.push(call);
    return handler(call);
  };
  return impl as unknown as typeof fetch;
}

function makeFakeChio(scriptBody: string): string {
  const dir = mkdtempSync(join(tmpdir(), "chio-arc-"));
  const binPath = join(dir, "arc");
  writeFileSync(binPath, `#!/usr/bin/env bash\n${scriptBody}\n`, "utf8");
  chmodSync(binPath, 0o755);
  return binPath;
}

// ---------------------------------------------------------------------------
// Gap 1
// ---------------------------------------------------------------------------

test("Gap 1: issueCapability auto-generates an ed25519 keypair when subjectPublicKey is omitted", async () => {
  const calls: FetchCall[] = [];
  const fetchImpl = mockFetch((call) => {
    if (/\/v1\/capabilities\/issue$/.test(call.url)) {
      const body = JSON.parse(String(call.init?.body));
      // Real wire shape: subjectPublicKey is REQUIRED (camelCase).
      assert.match(
        body.subjectPublicKey,
        /^[0-9a-f]{64}$/,
        "expected 32-byte hex subjectPublicKey on the wire",
      );
      assert.equal(typeof body.ttlSeconds, "number");
      return new Response(
        JSON.stringify({
          id: "cap_gen",
          issuer: "i",
          subject: "s",
          scope: {},
          issued_at: 1,
          expires_at: 2,
          signature: "",
        }),
        { status: 200, headers: { "content-type": "application/json" } },
      );
    }
    return new Response("{}", { status: 200 });
  }, calls);

  const bridge = ChioBridge.fromDaemon({
    trustUrl: "http://127.0.0.1:8940",
    token: "t",
    fetchImpl,
  });
  // Caller passes neither `subject` nor `subjectPublicKey`. Bridge must
  // mint a fresh ed25519 keypair and surface BOTH halves on the
  // response so the caller can sign downstream presentations.
  const token = await bridge.issueCapability({ scope: { grants: [] } });
  assert.equal(token.id, "cap_gen");
  assert.match(token.subjectPublicKey ?? "", /^[0-9a-f]{64}$/);
  assert.match(token.subjectPrivateKeyHex ?? "", /^[0-9a-f]{64}$/);
  // Wire body matches the response we surface.
  const sentBody = JSON.parse(String(calls[0]!.init?.body));
  assert.equal(sentBody.subjectPublicKey, token.subjectPublicKey);
});

test("Gap 1: issueCapability honours an explicit subjectPublicKey and forwards ttl/runtime evidence", async () => {
  const PUB = "deadbeef".repeat(8);
  const calls: FetchCall[] = [];
  const fetchImpl = mockFetch((call) => {
    if (/\/v1\/capabilities\/issue$/.test(call.url)) {
      const body = JSON.parse(String(call.init?.body));
      assert.equal(body.subjectPublicKey, PUB);
      assert.equal(body.ttlSeconds, 7200, "ttl: '2h' must parse to 7200");
      assert.deepEqual(body.runtimeAttestation, { kind: "fake-evidence" });
      return new Response(
        // Wrapped form: trust plane returns {capability: ...} per
        // IssueCapabilityResponse — bridge accepts both wrapped and bare.
        JSON.stringify({
          capability: {
            id: "cap_explicit",
            issuer: "i",
            subject: "s",
            scope: {},
            issued_at: 1,
            expires_at: 2,
            signature: "",
          },
        }),
        { status: 200, headers: { "content-type": "application/json" } },
      );
    }
    return new Response("{}", { status: 200 });
  }, calls);

  const bridge = ChioBridge.fromDaemon({
    trustUrl: "http://127.0.0.1:8940",
    token: "t",
    fetchImpl,
  });
  const token = await bridge.issueCapability({
    subjectPublicKey: PUB,
    scope: { grants: [] },
    ttl: "2h",
    runtimeAttestation: { kind: "fake-evidence" },
  });
  assert.equal(token.id, "cap_explicit");
  assert.equal(token.subjectPublicKey, PUB);
  // No private key because the caller supplied the public key.
  assert.equal(token.subjectPrivateKeyHex, undefined);
});

// ---------------------------------------------------------------------------
// Gap 2
// ---------------------------------------------------------------------------

test("Gap 2: attenuate hits issue + revoke (no /attenuate endpoint exists on this trust plane build)", async () => {
  const calls: FetchCall[] = [];
  const fetchImpl = mockFetch((call) => {
    if (/\/v1\/capabilities\/issue$/.test(call.url)) {
      const body = JSON.parse(String(call.init?.body));
      // Narrower scope/budget propagate.
      assert.deepEqual(body.scope, { grants: [{ server_id: "fs", tool_name: "read_file" }] });
      assert.equal(body.subjectPublicKey, "ab".repeat(32));
      return new Response(
        JSON.stringify({
          id: "cap_new",
          issuer: "i",
          subject: "s",
          scope: body.scope,
          issued_at: 1,
          expires_at: 2,
          signature: "",
        }),
        { status: 200, headers: { "content-type": "application/json" } },
      );
    }
    if (/\/v1\/revocations$/.test(call.url)) {
      const body = JSON.parse(String(call.init?.body));
      assert.equal(body.capabilityId, "cap_old");
      return new Response(
        JSON.stringify({ capabilityId: "cap_old", revoked: true, newlyRevoked: true }),
        { status: 200, headers: { "content-type": "application/json" } },
      );
    }
    // The attenuate-style endpoint MUST NOT be hit. Anything else: hard 404.
    if (/\/attenuate/.test(call.url)) {
      throw new Error(`attenuate endpoint should not be called: ${call.url}`);
    }
    return new Response("not found", { status: 404 });
  }, calls);
  const bridge = ChioBridge.fromDaemon({
    trustUrl: "http://127.0.0.1:8940",
    token: "t",
    fetchImpl,
  });
  const token = await bridge.attenuate("cap_old", {
    scope: { grants: [{ server_id: "fs", tool_name: "read_file" }] },
    subjectPublicKey: "ab".repeat(32),
  });
  assert.equal(token.id, "cap_new");
  assert.equal(token.subjectPublicKey, "ab".repeat(32));
  // Exactly two POSTs — issue + revoke, in that order.
  assert.equal(calls.length, 2);
  assert.match(calls[0]!.url, /\/v1\/capabilities\/issue$/);
  assert.match(calls[1]!.url, /\/v1\/revocations$/);
});

test("Gap 2: attenuate surfaces a partial-failure error when revoke 5xx's after issue succeeds", async () => {
  const fetchImpl = mockFetch((call) => {
    if (/\/v1\/capabilities\/issue$/.test(call.url)) {
      return new Response(
        JSON.stringify({
          id: "cap_new_partial",
          issuer: "i",
          subject: "s",
          scope: {},
          issued_at: 1,
          expires_at: 2,
          signature: "",
        }),
        { status: 200, headers: { "content-type": "application/json" } },
      );
    }
    if (/\/v1\/revocations$/.test(call.url)) {
      return new Response(
        JSON.stringify({ error: "revocation store offline" }),
        { status: 503, headers: { "content-type": "application/json" } },
      );
    }
    return new Response("nope", { status: 404 });
  });
  const bridge = ChioBridge.fromDaemon({
    trustUrl: "http://127.0.0.1:8940",
    token: "t",
    fetchImpl,
  });
  await assert.rejects(
    () =>
      bridge.attenuate("cap_old_partial", {
        scope: {},
        subjectPublicKey: "cd".repeat(32),
      }),
    /attenuation_partial|cap_new_partial/,
  );
});

// ---------------------------------------------------------------------------
// Gap 3
// ---------------------------------------------------------------------------

test("Gap 3: bond()'s auto-bootstrap MCP call honours the configured mcpEdgeUrl (no leak to default 8931)", async () => {
  // Spin a bridge with a non-default MCP edge port (8939, like the
  // OpenClaw harness). Confirm that the bootstrap seeding call goes
  // there — NOT to the default 8931.
  const SEEN_MCP_HOSTS = new Set<string>();
  const SEEN_TRUST_HOSTS = new Set<string>();
  const SUBJECT_HEX = "feedface".repeat(8);

  const chioBinary = makeFakeChio(
    [
      // First receipt list (cold): empty stdout, exit 0.
      // Subsequent receipt list: emit a JSON receipt with the
      // bootstrap subject key so the caller's keypair gets the
      // kernel-minted identity.
      'state="' + join(mkdtempSync(join(tmpdir(), "chio-state-")), "seeded") + '"',
      'args=("$@")',
      'cmd=""',
      "next_is_val=0",
      'for a in "${args[@]}"; do',
      '  if [[ "${next_is_val}" == "1" ]]; then',
      "    next_is_val=0; continue",
      "  fi",
      '  case "${a}" in',
      "    --receipt-db) next_is_val=1 ;;",
      "    --*) ;;",
      "    *) cmd=\"${a}\"; break ;;",
      "  esac",
      "done",
      'case "${cmd}" in',
      "  receipt)",
      '    if [[ -f "${state}" ]]; then',
      '      echo \'{"id":"r","metadata":{"attribution":{"subject_key":"' +
        SUBJECT_HEX +
        "\"}}}'",
      "    fi",
      "    exit 0 ;;",
      "  passport)",
      '    touch "${state}"',
      '    out=""',
      "    for ((i = 1; i <= $#; i++)); do",
      '      if [[ "${!i}" == "--output" ]]; then j=$((i + 1)); out="${!j}"; fi',
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
      "    exit 0 ;;",
      "esac",
      "exit 2",
    ].join("\n"),
  );

  const fetchImpl: typeof fetch = (async (input: URL | Request | string, init?: RequestInit) => {
    const url = typeof input === "string" ? input : input instanceof URL ? input.toString() : input.url;
    const u = new URL(url);
    if (url.endsWith("/mcp")) {
      SEEN_MCP_HOSTS.add(u.host);
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
      return new Response(null, { status: 202 });
    }
    if (url.includes("/v1/passport/statuses")) {
      SEEN_TRUST_HOSTS.add(u.host);
      return new Response(
        JSON.stringify({
          passportId: "pid-bootstrap",
          subject: `did:chio:${SUBJECT_HEX}`,
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
    // NON-default ports — explicitly NOT 8931 / 8940.
    mcpEdgeUrl: "http://127.0.0.1:8939",
    trustUrl: "http://127.0.0.1:8949",
    receiptDbPath: join(harnessDir, "receipts.sqlite"),
  });
  (bridge as unknown as { cli: ChioCli }).cli = new ChioCli(chioBinary);

  const policyPath = join(harnessDir, "policy.yaml");
  writeFileSync(
    policyPath,
    `hushspec: "0.1.0"\nname: gap3-test\nrules:\n  tool_access:\n    enabled: true\n    default: block\n    allow: [echo]\n`,
    "utf8",
  );

  const passport = await bridge.bond({ policyPath, ttl: "1h", budgetUsd: 5 });
  assert.ok(passport.did.startsWith("did:chio:"), passport.did);
  // The MCP edge call MUST have hit the configured non-default port,
  // and it must NOT have leaked to 8931.
  assert.ok(SEEN_MCP_HOSTS.has("127.0.0.1:8939"), `expected MCP edge hit at 8939, saw: ${[...SEEN_MCP_HOSTS].join(",")}`);
  assert.equal(SEEN_MCP_HOSTS.has("127.0.0.1:8931"), false, "MCP edge URL leaked to default 8931");
  // Trust plane likewise hit the configured non-default port.
  assert.ok(SEEN_TRUST_HOSTS.has("127.0.0.1:8949"));
  assert.equal(SEEN_TRUST_HOSTS.has("127.0.0.1:8940"), false);
});

// ---------------------------------------------------------------------------
// Gap 4
// ---------------------------------------------------------------------------

test("Gap 4: revokeAllForSubject(did) lists statuses, filters by subject, revokes each active record", async () => {
  const SUBJECT = "did:chio:cafef00d".padEnd(72, "0");
  const calls: FetchCall[] = [];
  const fetchImpl = mockFetch((call) => {
    if (call.init?.method === "GET" && /\/v1\/passport\/statuses$/.test(call.url)) {
      return new Response(
        JSON.stringify({
          passports: [
            { passportId: "pid-A-active", subject: SUBJECT, status: "active", validUntil: "2099-01-01T00:00:00Z" },
            { passportId: "pid-B-active", subject: SUBJECT, status: "active", validUntil: "2099-01-01T00:00:00Z" },
            { passportId: "pid-C-revoked", subject: SUBJECT, status: "revoked", validUntil: "2099-01-01T00:00:00Z" },
            { passportId: "pid-D-other", subject: "did:chio:other", status: "active", validUntil: "2099-01-01T00:00:00Z" },
          ],
        }),
        { status: 200, headers: { "content-type": "application/json" } },
      );
    }
    if (/\/v1\/passport\/statuses\/[^/]+\/revoke$/.test(call.url)) {
      return new Response(JSON.stringify({ ok: true }), {
        status: 200,
        headers: { "content-type": "application/json" },
      });
    }
    return new Response("not found", { status: 404 });
  }, calls);
  const bridge = ChioBridge.fromDaemon({
    trustUrl: "http://127.0.0.1:8940",
    token: "t",
    fetchImpl,
  });
  const result = await bridge.revokeAllForSubject(SUBJECT);
  assert.deepEqual(result.revokedPassportIds.sort(), ["pid-A-active", "pid-B-active"]);
  assert.deepEqual(result.failed, []);
  // Verify only the two ACTIVE passports for our subject got POSTed
  // — the revoked one and the other-subject one are skipped.
  const revokeCalls = calls.filter((c) => /\/revoke$/.test(c.url));
  assert.equal(revokeCalls.length, 2);
  assert.ok(revokeCalls.every((c) => c.url.includes(SUBJECT) === false));
  assert.ok(revokeCalls.every((c) => /pid-(A|B)-active/.test(c.url)));
  // Did NOT touch did:chio:other.
  assert.ok(!calls.some((c) => /pid-D-other/.test(c.url)));
});

test("Gap 4: revokeAllForSubject aggregates per-passport failures without throwing the whole call", async () => {
  const SUBJECT = "did:chio:" + "ab".repeat(32);
  const fetchImpl = mockFetch((call) => {
    if (call.init?.method === "GET" && /\/v1\/passport\/statuses$/.test(call.url)) {
      return new Response(
        JSON.stringify({
          passports: [
            { passportId: "pid-ok", subject: SUBJECT, status: "active", validUntil: "2099-01-01T00:00:00Z" },
            { passportId: "pid-bad", subject: SUBJECT, status: "active", validUntil: "2099-01-01T00:00:00Z" },
          ],
        }),
        { status: 200, headers: { "content-type": "application/json" } },
      );
    }
    if (/pid-ok\/revoke$/.test(call.url)) {
      return new Response(JSON.stringify({ ok: true }), { status: 200 });
    }
    if (/pid-bad\/revoke$/.test(call.url)) {
      return new Response(JSON.stringify({ error: "tombstone conflict" }), {
        status: 409,
        headers: { "content-type": "application/json" },
      });
    }
    return new Response("nope", { status: 404 });
  });
  const bridge = ChioBridge.fromDaemon({
    trustUrl: "http://127.0.0.1:8940",
    token: "t",
    fetchImpl,
  });
  const result = await bridge.revokeAllForSubject(SUBJECT);
  assert.deepEqual(result.revokedPassportIds, ["pid-ok"]);
  assert.equal(result.failed.length, 1);
  assert.equal(result.failed[0]!.passportId, "pid-bad");
  assert.match(result.failed[0]!.reason, /HTTP 409|tombstone/);
});

test("Gap 4: revokeAllForSubject rejects non-did:chio input", async () => {
  const bridge = ChioBridge.fromDaemon({
    token: "t",
    fetchImpl: mockFetch(() => new Response("{}", { status: 200 })),
  });
  await assert.rejects(
    () => bridge.revokeAllForSubject("not-a-did"),
    /requires a did:chio\/did:arc subject/,
  );
});
