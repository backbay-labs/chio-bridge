/**
 * Wave D Bug 1 + Bug 2 unit tests: the CLI-mode bond path now issues a
 * real capability against the trust plane, and the check() path threads
 * the capability id through `POST /v1/budgets/authorize-exposure` so a
 * bonded session enforces a cumulative cross-call budget.
 *
 * These tests drive the bridge with fake binaries + a mock fetch impl
 * that records every trust-plane HTTP call, so we can assert:
 *   (a) bond() in CLI mode issues a capability and returns a non-empty
 *       capabilityId.
 *   (b) check({capabilityId, costUsd}) hits
 *       POST /v1/budgets/authorize-exposure with the correct
 *       exposureUnits (cents), and returns `cancelled/velocity` when
 *       the trust plane replies `allowed: false`.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import {
  mkdtempSync,
  writeFileSync,
  chmodSync,
  mkdirSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { ChioBridge } from "../dist/index.js";

type FetchCall = { url: string; init: RequestInit | undefined };

function mockFetch(
  handler: (call: FetchCall) => Response | Promise<Response>,
  record?: FetchCall[],
): typeof fetch {
  const impl = async (input: URL | Request | string, init?: RequestInit) => {
    const url =
      typeof input === "string"
        ? input
        : input instanceof URL
          ? input.toString()
          : input.url;
    const call: FetchCall = { url, init };
    record?.push(call);
    return handler(call);
  };
  return impl as unknown as typeof fetch;
}

/** Fake arc that emulates receipt list + passport create for CLI-mode bond. */
function makeFakeChioForBond(subjectHex: string): string {
  const dir = mkdtempSync(join(tmpdir(), "chio-arc-cli-"));
  const binPath = join(dir, "arc");
  const script = [
    "#!/usr/bin/env bash",
    "# Split off --receipt-db flag, then dispatch on the subcommand.",
    'args=("$@")',
    'cmd=""',
    "next_is_val=0",
    'for a in "${args[@]}"; do',
    '  if [[ "${next_is_val}" == "1" ]]; then next_is_val=0; continue; fi',
    '  case "${a}" in',
    "    --receipt-db) next_is_val=1 ;;",
    "    --*) ;;",
    '    *) cmd="${a}"; break ;;',
    "  esac",
    "done",
    'case "${cmd}" in',
    "  receipt)",
    `    echo '{"id":"rcpt_seed","metadata":{"attribution":{"subject_key":"${subjectHex}"}}}'`,
    "    exit 0",
    "    ;;",
    "  passport)",
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
    `  "subject": "did:chio:${subjectHex}",`,
    '  "credentials": [{"unsigned":{}, "proof":{}}],',
    '  "merkleRoots": [],',
    '  "issuedAt": "2026-01-01T00:00:00Z",',
    '  "validUntil": "2026-02-01T00:00:00Z"',
    "}",
    "EOF",
    `    echo '{"ok":true}'`,
    "    exit 0",
    "    ;;",
    "esac",
    "exit 2",
  ].join("\n");
  writeFileSync(binPath, script, "utf8");
  chmodSync(binPath, 0o755);
  return binPath;
}

test("Wave D Bug 1: CLI-mode bond() issues a real capability id via direct HTTP to the trust plane", async () => {
  const SUBJECT =
    "1212121212121212121212121212121212121212121212121212121212121212";
  const CAP_ID_ISSUE = "cap-bond-issue-abc123";
  const CAP_ID_ATTENUATE = "cap-bond-attenuated-xyz789";

  const chioBinary = makeFakeChioForBond(SUBJECT);
  const harnessDir = mkdtempSync(join(tmpdir(), "chio-waved-"));
  mkdirSync(join(harnessDir, "var"), { recursive: true });
  const calls: FetchCall[] = [];
  // Intercept global fetch so the CLI-mode bond's HTTP path is
  // observable without a real trust plane. Restore on teardown.
  const originalFetch = globalThis.fetch;
  let issueCount = 0;
  globalThis.fetch = mockFetch((call) => {
    if (/\/v1\/capabilities\/issue$/.test(call.url)) {
      issueCount += 1;
      const capId = issueCount === 1 ? CAP_ID_ISSUE : CAP_ID_ATTENUATE;
      return new Response(
        JSON.stringify({
          capability: {
            id: capId,
            subjectPublicKey: SUBJECT,
            scope: JSON.parse(String(call.init?.body)).scope,
          },
        }),
        { status: 200, headers: { "content-type": "application/json" } },
      );
    }
    if (/\/v1\/revocations$/.test(call.url)) {
      return new Response(JSON.stringify({ revoked: true }), {
        status: 200,
        headers: { "content-type": "application/json" },
      });
    }
    return new Response("{}", { status: 200 });
  }, calls);

  try {
    const policyPath = join(harnessDir, "policy.yaml");
    writeFileSync(
      policyPath,
      `hushspec: "0.1.0"
name: waved-bond-test
rules:
  tool_access:
    enabled: true
    default: block
    allow: [get_quote, place_order, get_positions, email_receipt]
`,
      "utf8",
    );
    process.env.CHIO_SERVICE_TOKEN = "fake-service-token";
    process.env.CHIO_TRUST_URL = "http://127.0.0.1:9999";
    process.env.CHIO_RECEIPT_DB = join(harnessDir, "var", "receipts.sqlite");
    const bridge = ChioBridge.fromCli({ chioBinary });
    const passport = await bridge.bond({
      policyPath,
      subjectPublicKey: SUBJECT,
      ttl: "1h",
      budgetUsd: 500,
    });

    assert.ok(
      passport.did.startsWith("did:chio:"),
      `expected did:chio, got ${passport.did}`,
    );
    assert.equal(
      passport.capabilityId,
      CAP_ID_ISSUE,
      `expected issued capability id, got "${passport.capabilityId}"`,
    );

    // Verify the HTTP sequence: two issue calls (first for the scope,
    // second for the narrower budget-bearing scope) plus a revoke.
    const issueCalls = calls.filter((c) => /\/v1\/capabilities\/issue$/.test(c.url));
    assert.equal(issueCalls.length, 1, "budget must be applied on first issuance");
    // The second issue call (attenuation) must include the budget on
    // each grant as max_total_cost = {units: 50000, currency: "USD"}.
    const secondBody = JSON.parse(String(issueCalls[0].init?.body));
    const grants = secondBody.scope?.grants ?? [];
    assert.ok(grants.length >= 1, "expected at least one grant on the wire");
    for (const g of grants) {
      assert.deepEqual(
        g.max_total_cost,
        { units: 50_000, currency: "USD" },
        `expected $500 cap as MonetaryAmount, got ${JSON.stringify(g.max_total_cost)}`,
      );
    }
    const revokeCalls = calls.filter((c) => /\/v1\/revocations$/.test(c.url));
    assert.equal(revokeCalls.length, 0, "bond must not manufacture an attenuation");
  } finally {
    globalThis.fetch = originalFetch;
    delete process.env.CHIO_SERVICE_TOKEN;
    delete process.env.CHIO_TRUST_URL;
    delete process.env.CHIO_RECEIPT_DB;
  }
});

test("Wave D Bug 2: check({capabilityId, costUsd}) hits /v1/budgets/authorize-exposure and cancels past the cap", async () => {
  const harnessDir = mkdtempSync(join(tmpdir(), "chio-waved-check-"));
  const chioBinary = makeFakeChioForBond(
    "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
  );
  // The CLI-mode check() path shells out to `chio check --policy ...
  // --format json`. Swap the fake arc to always return allow.
  writeFileSync(
    chioBinary,
    `#!/usr/bin/env bash\necho '{"decision":"allow"}'\n`,
    "utf8",
  );

  const policyPath = join(harnessDir, "policy.yaml");
  writeFileSync(
    policyPath,
    `hushspec: "0.1.0"
name: waved-check-test
rules:
  tool_access:
    enabled: true
    default: block
    allow: [place_order]
`,
    "utf8",
  );

  const calls: FetchCall[] = [];
  const originalFetch = globalThis.fetch;
  let cumulativeCents = 0;
  const CAP_CENTS = 50_000; // $500
  globalThis.fetch = mockFetch((call) => {
    if (/\/v1\/budgets\/authorize-exposure$/.test(call.url)) {
      const body = JSON.parse(String(call.init?.body));
      const wouldBe = cumulativeCents + Number(body.exposureUnits);
      if (wouldBe > (body.maxTotalExposureUnits ?? CAP_CENTS)) {
        // Over the cap — trust plane replies not allowed, we echo
        // the cumulative (not including this call).
        return new Response(
          JSON.stringify({
            capabilityId: body.capabilityId,
            grantIndex: body.grantIndex,
            allowed: false,
            totalCostExposed: cumulativeCents,
          }),
          { status: 200 },
        );
      }
      cumulativeCents = wouldBe;
      return new Response(
        JSON.stringify({
          capabilityId: body.capabilityId,
          grantIndex: body.grantIndex,
          allowed: true,
          totalCostExposed: cumulativeCents,
        }),
        { status: 200 },
      );
    }
    return new Response("{}", { status: 200 });
  }, calls);

  try {
    process.env.CHIO_SERVICE_TOKEN = "fake";
    process.env.CHIO_TRUST_URL = "http://127.0.0.1:0";
    process.env.CHIO_CAPABILITY_BUDGET_USD = "500";
    const bridge = ChioBridge.fromCli({ chioBinary });
    const capabilityId = "cap-hedge-fund-waved";

    // SPY at $412 — first call should be allow.
    const v1 = await bridge.check(
      {
        tool: "place_order",
        params: { symbol: "SPY", qty: 1 },
        policyPath,
      },
      { capabilityId, costUsd: 412 },
    );
    assert.equal(v1.decision, "allow", `v1: ${JSON.stringify(v1)}`);

    // QQQ at $352 — cumulative would be $764 > $500. Expect cancel.
    const v2 = await bridge.check(
      {
        tool: "place_order",
        params: { symbol: "QQQ", qty: 1 },
        policyPath,
      },
      { capabilityId, costUsd: 352 },
    );
    assert.equal(
      v2.decision,
      "cancelled",
      `expected cancelled on over-budget call, got ${JSON.stringify(v2)}`,
    );
    assert.equal(v2.guard, "velocity");

    // IWM at $196 — still over budget, another cancel.
    const v3 = await bridge.check(
      {
        tool: "place_order",
        params: { symbol: "IWM", qty: 1 },
        policyPath,
      },
      { capabilityId, costUsd: 196 },
    );
    assert.equal(
      v3.decision,
      "cancelled",
      `expected cancelled on over-budget call, got ${JSON.stringify(v3)}`,
    );

    // Verify every authorize-exposure call threaded the same capability id.
    const mediationCalls = calls.filter((c) =>
      /\/v1\/budgets\/authorize-exposure$/.test(c.url),
    );
    assert.equal(mediationCalls.length, 3, "expected 3 mediation calls");
    for (const c of mediationCalls) {
      const body = JSON.parse(String(c.init?.body));
      assert.equal(body.capabilityId, capabilityId);
    }
  } finally {
    globalThis.fetch = originalFetch;
    delete process.env.CHIO_SERVICE_TOKEN;
    delete process.env.CHIO_TRUST_URL;
    delete process.env.CHIO_CAPABILITY_BUDGET_USD;
  }
});
