import { test } from "node:test";
import assert from "node:assert/strict";
import { ChioBridge } from "../dist/index.js";
import { DaemonUnreachableError } from "../dist/errors.js";

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

test("fromDaemon issueCapability posts to /v1/capabilities/issue with bearer", async () => {
  // Wave 4 Gap 1 update: the trust plane DTO is `IssueCapabilityRequest
  // { subjectPublicKey, scope, ttlSeconds }` (camelCase, see
  // arc/crates/chio-cli/src/trust_control/service_types.rs:691). The
  // pre-Wave-4 bridge posted `{subject, scope}`, which the trust plane
  // 422'd as `missing field subjectPublicKey`. The test now asserts the
  // real wire shape; the did:arc suffix is the public key hex.
  const HEX = "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789";
  const calls: FetchCall[] = [];
  const fetchImpl = mockFetch((call) => {
    assert.match(call.url, /\/v1\/capabilities\/issue$/);
    const auth = new Headers(call.init?.headers).get("authorization");
    assert.equal(auth, "Bearer test-token");
    const body = JSON.parse(String(call.init?.body));
    assert.equal(body.subjectPublicKey, HEX);
    assert.deepEqual(body.scope, { grants: [] });
    assert.equal(body.ttlSeconds, 3600); // default ttl when caller omits
    return new Response(
      JSON.stringify({
        id: "cap_1",
        issuer: "did:chio:issuer",
        subject: `did:chio:${HEX}`,
        scope: { grants: [] },
        issued_at: 1,
        expires_at: 2,
        signature: "",
      }),
      { status: 200, headers: { "content-type": "application/json" } },
    );
  }, calls);

  const bridge = ChioBridge.fromDaemon({
    trustUrl: "http://127.0.0.1:8940",
    token: "test-token",
    fetchImpl,
  });
  const token = await bridge.issueCapability({
    subject: `did:chio:${HEX}`,
    scope: { grants: [] },
  });
  assert.equal(token.id, "cap_1");
  // Bridge surfaces the resolved subject public key on the response.
  assert.equal(token.subjectPublicKey, HEX);
  assert.equal(calls.length, 1);
});

test("fromDaemon receipts() queries trust plane /v1/receipts/query", async () => {
  const calls: FetchCall[] = [];
  const fetchImpl = mockFetch((call) => {
    assert.match(call.url, /\/v1\/receipts\/query/);
    return new Response(
      JSON.stringify({ totalCount: 0, receipts: [] }),
      { status: 200, headers: { "content-type": "application/json" } },
    );
  }, calls);

  const bridge = ChioBridge.fromDaemon({
    trustUrl: "http://127.0.0.1:8940",
    token: "t",
    fetchImpl,
  });
  const receipts = await bridge.receipts({ limit: 10 });
  assert.equal(receipts.length, 0);
  assert.equal(calls.length, 1);
});

test("fromDaemon attenuate runs issue-then-revoke against the real trust-plane routes", async () => {
  // Wave 4 Gap 2 update: the arc trust plane on this build has NO
  // `/v1/capabilities/<id>/attenuate` route (we grepped `arc/crates/
  // chio-cli/src/trust_control/` for `attenuat`: only the
  // validate_attenuation core type machinery exists, never bound to
  // an HTTP handler). The bridge implements attenuation as a two-step
  // `issue-narrower-then-revoke-old`, so this test now asserts both
  // POSTs hit real, existing trust-plane routes.
  const calls: FetchCall[] = [];
  const fetchImpl = mockFetch((call) => {
    if (/\/v1\/capabilities\/issue$/.test(call.url)) {
      return new Response(
        JSON.stringify({
          id: "cap_43_narrow",
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
      const body = JSON.parse(String(call.init?.body));
      assert.equal(body.capabilityId, "cap_42");
      return new Response(
        JSON.stringify({ capabilityId: "cap_42", revoked: true, newlyRevoked: true }),
        { status: 200, headers: { "content-type": "application/json" } },
      );
    }
    return new Response("not found", { status: 404 });
  }, calls);
  const bridge = ChioBridge.fromDaemon({
    trustUrl: "http://127.0.0.1:8940",
    token: "t",
    fetchImpl,
  });
  const t = await bridge.attenuate("cap_42", {
    budget: { maxUsd: 5 },
    subjectPublicKey:
      "11112222333344445555666677778888999900001111222233334444555566ff",
  });
  // New token is the narrower issued capability, NOT the old id.
  assert.equal(t.id, "cap_43_narrow");
  // Both wire calls happened.
  assert.equal(calls.length, 2);
  assert.match(calls[0]!.url, /\/v1\/capabilities\/issue$/);
  assert.match(calls[1]!.url, /\/v1\/revocations$/);
});

test("fromDaemon surfaces DaemonUnreachableError when fetch rejects", async () => {
  const fetchImpl: typeof fetch = (async () => {
    throw new Error("ECONNREFUSED");
  }) as unknown as typeof fetch;
  const bridge = ChioBridge.fromDaemon({
    trustUrl: "http://127.0.0.1:8940",
    token: "t",
    fetchImpl,
  });
  await assert.rejects(
    () => bridge.issueCapability({ subject: "did:chio:x", scope: {} }),
    (e: Error) => e instanceof DaemonUnreachableError,
  );
});

test("fromDaemon createPassport errors cleanly when no receipt db is configured", async () => {
  // The real `arc passport create` needs a receipt DB to read from.
  // When the caller neither passes `receiptDbPath` nor sets
  // `CHIO_RECEIPT_DB`/`CHIO_HARNESS_DIR`, the bridge must fail fast
  // rather than attempting a bogus wire call.
  const fetchImpl = mockFetch(() =>
    new Response(JSON.stringify({}), { status: 200 }),
  );
  const bridge = ChioBridge.fromDaemon({ token: "t", fetchImpl });
  const savedDb = process.env.CHIO_RECEIPT_DB;
  const savedHarness = process.env.CHIO_HARNESS_DIR;
  delete process.env.CHIO_RECEIPT_DB;
  delete process.env.CHIO_HARNESS_DIR;
  try {
    await assert.rejects(
      () => bridge.createPassport({}),
      /receipt database path/i,
    );
  } finally {
    if (savedDb !== undefined) process.env.CHIO_RECEIPT_DB = savedDb;
    if (savedHarness !== undefined) process.env.CHIO_HARNESS_DIR = savedHarness;
  }
});

test("fromDaemon status(passportId) maps PassportLifecycleRecord to BondStatus (bonded iff status===active)", async () => {
  // Wave 5.2 bug fix: the pre-5.2 bridge read a fabricated `bonded` key
  // off the trust plane response; the real wire shape is a
  // `PassportLifecycleRecord` (see
  // arc/crates/chio-credentials/src/passport.rs:88-107) carrying
  // `status: "active" | ...` and `validUntil`, with NO `bonded` /
  // `budget_used_usd` / `budget_cap_usd` / `guard_count` fields. This
  // test pins the corrected mapping.
  const PID = "sha256:" + "a".repeat(64);
  const calls: FetchCall[] = [];
  const fetchImpl = mockFetch((call) => {
    assert.match(call.url, /\/v1\/passport\/statuses\/sha256%3A/);
    return new Response(
      JSON.stringify({
        passportId: PID,
        subject: "did:chio:" + "b".repeat(64),
        issuers: ["did:chio:issuer-1"],
        issuerCount: 1,
        publishedAt: 1_700_000_000,
        updatedAt: 1_700_000_100,
        status: "active",
        validUntil: "2099-01-01T00:00:00Z",
      }),
      { status: 200, headers: { "content-type": "application/json" } },
    );
  }, calls);
  const bridge = ChioBridge.fromDaemon({ token: "t", fetchImpl });
  const st = await bridge.status(PID);
  assert.equal(st.bonded, true, "status === 'active' must yield bonded=true");
  assert.equal(st.status, "active");
  assert.equal(st.ttlExpiresAt, "2099-01-01T00:00:00Z");
  // Budget + guard fields are NOT on this endpoint — must be undefined,
  // not fabricated zeros (old bug returned 0/0/7).
  assert.equal(st.budgetUsedUsd, undefined);
  assert.equal(st.budgetCapUsd, undefined);
  assert.equal(st.guardCount, undefined);
});

test("fromDaemon status(passportId) reports bonded=false for non-active lifecycle states", async () => {
  const PID = "sha256:" + "c".repeat(64);
  const fetchImpl = mockFetch(() =>
    new Response(
      JSON.stringify({
        passportId: PID,
        subject: "did:chio:" + "d".repeat(64),
        issuers: ["did:chio:issuer-1"],
        issuerCount: 1,
        publishedAt: 1_700_000_000,
        updatedAt: 1_700_000_200,
        status: "revoked",
        revokedAt: 1_700_000_200,
        revokedReason: "smoke",
        validUntil: "2099-01-01T00:00:00Z",
      }),
      { status: 200, headers: { "content-type": "application/json" } },
    ),
  );
  const bridge = ChioBridge.fromDaemon({ token: "t", fetchImpl });
  const st = await bridge.status(PID);
  assert.equal(st.bonded, false);
  assert.equal(st.status, "revoked");
  assert.equal(st.ttlExpiresAt, "2099-01-01T00:00:00Z");
});

test("fromDaemon propagates HTTP error codes to CapabilityDeniedError", async () => {
  const fetchImpl = mockFetch(() =>
    new Response(JSON.stringify({ error: "forbidden" }), {
      status: 403,
      headers: { "content-type": "application/json" },
    }),
  );
  const bridge = ChioBridge.fromDaemon({ token: "t", fetchImpl });
  await assert.rejects(
    () => bridge.issueCapability({ subject: "did:chio:x", scope: {} }),
    /HTTP 403/,
  );
});
