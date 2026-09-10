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

test("fromCli check() invokes `arc check` and parses JSON allow verdict", async () => {
  const chioBinary = makeFakeChio(`
echo '{"decision":"allow"}'
`);
  const bridge = ChioBridge.fromCli({ chioBinary });
  const v = await bridge.check({
    tool: "read_file",
    params: { path: "/workspace/README.md" },
    policyPath: "/tmp/policy.yaml",
  });
  assert.equal(v.decision, "allow");
});

test("fromCli check() parses deny verdict with reason and guard", async () => {
  const chioBinary = makeFakeChio(`
echo '{"decision":"deny","reason":"forbidden path","guard":"ForbiddenPathGuard"}'
`);
  const bridge = ChioBridge.fromCli({ chioBinary });
  const v = await bridge.check({
    tool: "read_file",
    params: { path: "/etc/passwd" },
    policyPath: "/tmp/p.yaml",
  });
  assert.equal(v.decision, "deny");
  assert.equal(v.guard, "ForbiddenPathGuard");
  assert.match(v.reason ?? "", /forbidden/);
});

test("fromCli check() parses Rust-style tagged verdict objects", async () => {
  const chioBinary = makeFakeChio(`
echo '{"decision":{"Deny":{"reason":"budget","guard":"VelocityGuard"}}}'
`);
  const bridge = ChioBridge.fromCli({ chioBinary });
  const v = await bridge.check({
    tool: "x",
    params: {},
    policyPath: "/tmp/p.yaml",
  });
  assert.equal(v.decision, "deny");
  assert.equal(v.guard, "VelocityGuard");
  assert.match(v.reason ?? "", /budget/);
});

test("fromCli createPassport invokes `arc passport create` with the real flag surface", async () => {
  // The real `arc passport create` requires --subject-public-key,
  // --output, --signing-seed-file and reads receipts from --receipt-db.
  // Our fake writes the minimal AgentPassport JSON the CLI would have
  // produced, to the path following --output. This exercises the real
  // flag wiring without requiring a populated sqlite receipt db.
  const chioBinary = makeFakeChio(`
# Find the --output path and write a passport JSON there, echoing the
# same human prefix the real CLI emits on success.
out=""
for ((i = 1; i <= $#; i++)); do
  if [[ "\${!i}" == "--output" ]]; then
    j=$((i + 1))
    out="\${!j}"
  fi
done
if [[ -z "\${out}" ]]; then
  echo "missing --output" >&2
  exit 2
fi
cat > "\${out}" <<'EOF'
{
  "schema": "arc.agent-passport.v1",
  "subject": "did:chio:abababababababababababababababababababababababababababababababab",
  "credentials": [{"unsigned": {}, "proof": {}}],
  "merkleRoots": [],
  "issuedAt": "2026-01-01T00:00:00Z",
  "validUntil": "2026-02-01T00:00:00Z"
}
EOF
echo '{"subject":"did:chio:abababababababababababababababababababababababababababababababab","credentialCount":1,"validUntil":"2026-02-01T00:00:00Z"}'
`);
  const bridge = ChioBridge.fromCli({ chioBinary });
  const dummyDb = mkdtempSync(join(tmpdir(), "chio-fake-db-"));
  const p = await bridge.createPassport({
    receiptDbPath: join(dummyDb, "receipts.sqlite"),
    subjectPublicKey: "ab".repeat(32),
  });
  assert.ok(p.did.startsWith("did:chio:"), `expected did:chio, got ${p.did}`);
  assert.equal(p.expiresAt, "2026-02-01T00:00:00Z");
});

test("fromCli createPassport rejects non-did:chio subject in passport output", async () => {
  const chioBinary = makeFakeChio(`
out=""
for ((i = 1; i <= $#; i++)); do
  if [[ "\${!i}" == "--output" ]]; then
    j=$((i + 1))
    out="\${!j}"
  fi
done
cat > "\${out}" <<'EOF'
{
  "schema": "arc.agent-passport.v1",
  "subject": "did:web:wrong",
  "credentials": [],
  "merkleRoots": [],
  "issuedAt": "2026-01-01T00:00:00Z",
  "validUntil": "2026-02-01T00:00:00Z"
}
EOF
echo '{"ok":true}'
`);
  const bridge = ChioBridge.fromCli({ chioBinary });
  const dummyDb = mkdtempSync(join(tmpdir(), "chio-fake-db-"));
  await assert.rejects(
    () => bridge.createPassport({ receiptDbPath: join(dummyDb, "receipts.sqlite"), subjectPublicKey: "ab".repeat(32) }),
    /explicit subjectPublicKey/,
  );
});

test("fromCli check() requires policyPath", async () => {
  const chioBinary = makeFakeChio(`exit 0`);
  const bridge = ChioBridge.fromCli({ chioBinary });
  await assert.rejects(
    () => bridge.check({ tool: "x", params: {} }),
    /policyPath/,
  );
});
