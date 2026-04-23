/**
 * Unit tests for `verifyPassport` — covers Wave 3 Gap 2.
 *
 * The previous bridge passed the bare DID to `arc passport verify
 * --input`, which expects a file path; CLI-only verification was
 * silently broken. The new API accepts:
 *   - bare DID string (daemon-mode lifecycle lookup)
 *   - `{ file }` (real CLI verify, no daemon required)
 *   - `{ passportId }` (daemon-mode resolve by SHA256 artifact id)
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

test("verifyPassport({ file }) invokes `arc passport verify --input <file>` and returns true on exit 0", async () => {
  const logPath = join(mkdtempSync(join(tmpdir(), "chio-arc-log-")), "argv.log");
  const chioBinary = makeFakeChio(`
printf '%s\\n' "$@" > "${logPath}"
exit 0
`);
  const bridge = ChioBridge.fromCli({ chioBinary });
  const passportPath = "/tmp/passport.json";
  const ok = await bridge.verifyPassport({ file: passportPath });
  assert.equal(ok, true);

  const fs = await import("node:fs/promises");
  const argv = (await fs.readFile(logPath, "utf8")).trim().split("\n");
  assert.deepEqual(argv, ["passport", "verify", "--input", passportPath]);
});

test("verifyPassport({ file }) returns false when arc exits non-zero (e.g. tampered passport)", async () => {
  const chioBinary = makeFakeChio(`
>&2 echo "passport verification failed: signature mismatch"
exit 1
`);
  const bridge = ChioBridge.fromCli({ chioBinary });
  const ok = await bridge.verifyPassport({ file: "/tmp/bad.json" });
  assert.equal(ok, false);
});

test("verifyPassport(did) uses trust plane list lookup and matches `status: active`", async () => {
  const fetchImpl: typeof fetch = (async (input: URL | Request | string) => {
    const url = typeof input === "string" ? input : input instanceof URL ? input.toString() : input.url;
    assert.match(url, /\/v1\/passport\/statuses$/);
    return new Response(
      JSON.stringify({
        passports: [
          {
            passportId: "pid-active",
            subject: "did:chio:alpha",
            status: "active",
            validUntil: "2099-01-01T00:00:00Z",
            issuerCount: 1,
          },
          {
            passportId: "pid-revoked",
            subject: "did:chio:beta",
            status: "revoked",
            validUntil: "2099-01-01T00:00:00Z",
            issuerCount: 1,
          },
        ],
      }),
      { status: 200, headers: { "content-type": "application/json" } },
    );
  }) as unknown as typeof fetch;
  const bridge = ChioBridge.fromDaemon({ token: "t", fetchImpl });
  assert.equal(await bridge.verifyPassport("did:chio:alpha"), true);
  assert.equal(await bridge.verifyPassport("did:chio:beta"), false);
  assert.equal(await bridge.verifyPassport("did:chio:nobody"), false);
});

test("verifyPassport({ passportId }) resolves by SHA256 artifact id", async () => {
  const fetchImpl: typeof fetch = (async () => {
    return new Response(
      JSON.stringify({
        passports: [
          {
            passportId: "abc123",
            subject: "did:chio:alpha",
            status: "active",
            validUntil: "2099-01-01T00:00:00Z",
            issuerCount: 1,
          },
        ],
      }),
      { status: 200, headers: { "content-type": "application/json" } },
    );
  }) as unknown as typeof fetch;
  const bridge = ChioBridge.fromDaemon({ token: "t", fetchImpl });
  assert.equal(await bridge.verifyPassport({ passportId: "abc123" }), true);
  assert.equal(await bridge.verifyPassport({ passportId: "nope" }), false);
});

test("verifyPassport(did) in CLI-only mode throws with an actionable error", async () => {
  const chioBinary = makeFakeChio(`exit 0`);
  const bridge = ChioBridge.fromCli({ chioBinary });
  await assert.rejects(
    () => bridge.verifyPassport("did:chio:abc"),
    /verify_requires_file_or_daemon|pass \{ file:/,
  );
});

test("verifyPassport rejects non-did:chio strings early", async () => {
  const fetchImpl: typeof fetch = (async () =>
    new Response("{}", { status: 200 })) as unknown as typeof fetch;
  const bridge = ChioBridge.fromDaemon({ token: "t", fetchImpl });
  assert.equal(await bridge.verifyPassport("not-a-did"), false);
});
