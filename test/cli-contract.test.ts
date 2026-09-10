import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { existsSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { ChioCli, type CliResult } from "../dist/client/cli.js";
import { DaemonClient } from "../dist/client/daemon.js";
import { checkCall } from "../dist/check.js";
import { createPassport } from "../dist/passport.js";
import { exportEvidence } from "../dist/receipts.js";

class StubCli extends ChioCli {
  calls: string[][] = [];
  readonly response: CliResult;
  constructor(response: CliResult) { super("/unused/operator-selected-chio"); this.response = response; }
  override async run(args: string[]): Promise<CliResult> { this.calls.push(args); return this.response; }
}
const call = { tool: "echo", params: { message: "fixture only" }, policyPath: "/operator/policy.yaml" };

test("check preserves explicit fixture and durable databases without unsupported trailing format flags", async () => {
  const cli = new StubCli({ exitCode: 0, stdout: '{"verdict":"ALLOW"}', stderr: "" });
  assert.equal((await checkCall(undefined, cli, call, { mode: "full", outputFixturePath: "/operator/output.json",
    sessionDbPath: "/operator/session.sqlite", receiptDbPath: "/operator/receipts.sqlite" })).decision, "allow");
  assert.deepEqual(cli.calls, [["--json", "--receipt-db", "/operator/receipts.sqlite", "--session-db", "/operator/session.sqlite",
    "check", "--mode", "full", "--policy", call.policyPath, "--tool", "echo", "--params", JSON.stringify(call.params),
    "--output-fixture", "/operator/output.json"]]);
});

test("check accepts real denial statuses and cannot turn a nonzero exit into allow", async () => {
  for (const [exitCode, stdout, expected] of [
    [2, '{"verdict":"DENY","reason":"forbidden"}', "deny"],
    [3, '{"verdict":"PENDING_APPROVAL"}', "deny"],
    [2, '{"verdict":"ALLOW"}', "deny"],
    [3, '{"verdict":"ALLOW"}', "deny"],
  ] as const) {
    const cli = new StubCli({ exitCode, stdout, stderr: "" });
    assert.equal((await checkCall(undefined, cli, call)).decision, expected);
    assert.equal(cli.calls.length, 1);
  }
  const malformed = new StubCli({ exitCode: 2, stdout: "", stderr: "unexpected argument" });
  await assert.rejects(checkCall(undefined, malformed, call), /unparseable JSON/);
});

test("check rejects implicit output simulation before invoking the CLI", async () => {
  const cli = new StubCli({ exitCode: 0, stdout: '{"verdict":"ALLOW"}', stderr: "" });
  await assert.rejects(checkCall(undefined, cli, call, { mode: "full" }), /requires outputFixturePath/);
  await assert.rejects(checkCall(undefined, cli, call, { outputFixturePath: "/operator/fixture.json" }), /preflight/);
  assert.equal(cli.calls.length, 0);
});

test("passport creation never infers a subject from the newest receipt", async () => {
  const cli = new StubCli({ exitCode: 0, stdout: '{"metadata":{"attribution":{"subject_key":"other"}}}', stderr: "" });
  await assert.rejects(createPassport(undefined, cli, { receiptDbPath: "/operator/receipts.sqlite" }), { code: "passport_subject_required" });
  assert.equal(cli.calls.length, 0);
  await assert.rejects(createPassport(undefined, cli, { receiptDbPath: "/operator/receipts.sqlite",
    subjectPublicKey: "ab".repeat(32), subject: "did:chio:" + "cd".repeat(32) }), /does not match/);
  assert.equal(cli.calls.length, 0);
});

function responseFor(query: Record<string, unknown>) {
  return { bundle: { query, toolReceipts: [], childReceipts: [], checkpoints: [], capabilityLineage: [],
    inclusionProofs: [], uncheckpointedReceipts: [], childReceiptScope: "full_query_window", retention: {} } };
}

test("evidence export requires explicit scope before any HTTP request or file write", async t => {
  const dir = await mkdtemp(join(tmpdir(), "chio-evidence-contract-")); t.after(() => rm(dir, { recursive: true, force: true }));
  let calls = 0;
  const daemon = new DaemonClient({ token: "fixture-only", fetchImpl: async () => { calls++; throw new Error("must not fetch"); } });
  const outPath = join(dir, "evidence.json");
  await assert.rejects(exportEvidence(daemon, { since: new Date(1000), outPath } as any), { code: "evidence_read_boundary_required" });
  await assert.rejects(exportEvidence(daemon, { since: new Date(1000), outPath,
    readBoundary: { kind: "admin_all", tenant: "must-not-be-ignored" } } as any), { code: "invalid_arg" });
  assert.equal(calls, 0); assert.equal(existsSync(outPath), false);
});

test("evidence export uses the kernel query envelope and preserves the unverified response", async t => {
  const dir = await mkdtemp(join(tmpdir(), "chio-evidence-contract-")); t.after(() => rm(dir, { recursive: true, force: true }));
  const query = { since: 1, until: 2, readBoundary: { kind: "admin_all" } };
  const response = responseFor(query);
  const daemon = new DaemonClient({ token: "fixture-only", fetchImpl: async (_url, init) => {
    assert.deepEqual(JSON.parse(init!.body as string), { query, requireProofs: false });
    return new Response(JSON.stringify(response));
  } });
  const outPath = join(dir, "evidence.json");
  assert.equal(await exportEvidence(daemon, { since: new Date(1000), until: new Date(2000), outPath, readBoundary: { kind: "admin_all" } }), outPath);
  assert.deepEqual(JSON.parse(await readFile(outPath, "utf8")), response);
});

test("evidence export rejects response scope substitution and malformed success without writing", async t => {
  const dir = await mkdtemp(join(tmpdir(), "chio-evidence-contract-")); t.after(() => rm(dir, { recursive: true, force: true }));
  for (const response of [{}, responseFor({ since: 1, readBoundary: { kind: "tenant_scoped", tenant: "other" }, tenant: "other" })]) {
    const daemon = new DaemonClient({ token: "fixture-only", fetchImpl: async () => new Response(JSON.stringify(response)) });
    const outPath = join(dir, "absent.json");
    await assert.rejects(exportEvidence(daemon, { since: new Date(1000), outPath,
      readBoundary: { kind: "tenant_scoped", tenant: "selected" } }), { code: "evidence_invalid" });
    assert.equal(existsSync(outPath), false);
  }
});

test("evidence export does not replace an existing artifact", async t => {
  const dir = await mkdtemp(join(tmpdir(), "chio-evidence-contract-")); t.after(() => rm(dir, { recursive: true, force: true }));
  const outPath = join(dir, "existing.json"); await writeFile(outPath, "prior evidence");
  const daemon = new DaemonClient({ token: "fixture-only", fetchImpl: async () => new Response(JSON.stringify(responseFor({ since: 1, readBoundary: { kind: "admin_all" } }))) });
  await assert.rejects(exportEvidence(daemon, { since: new Date(1000), outPath, readBoundary: { kind: "admin_all" } }), { code: "EEXIST" });
  assert.equal(await readFile(outPath, "utf8"), "prior evidence");
});
