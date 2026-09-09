import test from "node:test";
import assert from "node:assert/strict";
import { createServer } from "node:http";
import { spawn } from "node:child_process";
import { existsSync, lstatSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";

type Scenario = { input?: Record<string, unknown>; credential?: Record<string, unknown>; contextServer?: string; delegated?: Record<string, unknown>; status?: number; malformed?: boolean };
async function prepare(scenario: Scenario = {}) {
  const directory = mkdtempSync(join(tmpdir(), "chio-prepare-test-"));
  const calls: { method: string; authorization: string | undefined; path: string }[] = [];
  let credential: any;
  const subjectKey = "ab".repeat(32);
  const server = createServer(async (request, response) => {
    const chunks: Buffer[] = []; for await (const chunk of request) chunks.push(chunk);
    const raw = Buffer.concat(chunks).toString();
    const body = raw ? JSON.parse(raw) : {};
    calls.push({ method: body.method ?? request.method!, authorization: request.headers.authorization, path: request.url! });
    const send = (value: unknown, status = 200, headers = {}) => { response.writeHead(status, { "Content-Type": "application/json", ...headers }); response.end(JSON.stringify(value)); };
    if (request.method === "DELETE") { response.writeHead(204); response.end(); return; }
    if (request.url === "/admin/sessions/kernel-session/credential") {
      assert.equal(request.headers.authorization, "Bearer private-admin-token");
      assert.deepEqual(body, { ttlSeconds: 300, allowedTools: ["read_file"] });
      if (scenario.status) { send({ error: "unavailable" }, scenario.status); return; }
      if (scenario.malformed) { response.end("malformed credential"); return; }
      const now = Math.floor(Date.now() / 1000);
      credential = { schema: "chio.mcp.session-credential.v1", sessionId: "kernel-session", subjectKey, capabilityIds: ["cap-one"], serverId: "fs", endpointPath: "/mcp", issuedAt: now, expiresAt: now + 300, allowedTools: ["read_file"], bearerToken: "delegated-session-token", ...scenario.credential };
      send(credential); return;
    }
    assert.equal(request.url, "/mcp");
    const delegated = request.headers.authorization === "Bearer delegated-session-token";
    assert.ok(delegated || request.headers.authorization === "Bearer private-bootstrap-token");
    if (body.method === "initialize") { assert.equal(delegated, false); send({ jsonrpc: "2.0", id: body.id, result: { protocolVersion: "2025-11-25", capabilities: {} } }, 200, { "MCP-Session-Id": "kernel-session" }); return; }
    if (body.method === "notifications/initialized") { response.writeHead(202); response.end(); return; }
    assert.equal(request.headers["mcp-session-id"], "kernel-session");
    if (body.method === "chio/execution-context") {
      const { bearerToken: _secret, ...binding } = credential ?? {};
      const context = { schema: "chio.mcp.execution-context.v1", evidenceVersion: "1", subjectKey, capabilityIds: ["cap-one"], serverId: scenario.contextServer ?? "fs", ...(delegated ? { sessionCredential: { ...binding, ...scenario.delegated } } : {}) };
      send({ jsonrpc: "2.0", id: body.id, result: context }); return;
    }
    assert.equal(body.method, "tools/list", "preparation must never execute a protected tool");
    send({ jsonrpc: "2.0", id: body.id, result: { tools: [{ name: "read_file", inputSchema: { type: "object" } }, { name: "write_file", inputSchema: { type: "object" } }] } });
  });
  await new Promise<void>(resolve => server.listen(0, "127.0.0.1", resolve));
  const address = server.address(); assert.ok(address && typeof address === "object");
  const requestPath = join(directory, "operator.json"); const outputPath = join(directory, "gateway.json");
  writeFileSync(requestPath, JSON.stringify({ endpoint: `http://127.0.0.1:${address.port}`, bearerToken: "private-bootstrap-token", adminToken: "private-admin-token", credentialTtlSeconds: 300, trustedSigners: ["cd".repeat(32)], serverId: "fs", journalDir: join(directory, "journal"), sessionId: "logical-host-session", allowedTools: ["read_file"], ...scenario.input }), { mode: 0o600 });
  try {
    const child = spawn(process.execPath, [fileURLToPath(new URL("../dist/prepare-gateway.js", import.meta.url)), requestPath, outputPath]);
    let stdout = ""; let stderr = ""; child.stdout.on("data", data => { stdout += data; }); child.stderr.on("data", data => { stderr += data; });
    const status = await new Promise<number | null>((resolve, reject) => { child.on("error", reject); child.on("close", resolve); });
    const output = existsSync(outputPath) ? readFileSync(outputPath, "utf8") : undefined;
    const mode = existsSync(outputPath) ? lstatSync(outputPath).mode & 0o777 : undefined;
    assert.equal(calls.filter(call => call.method === "tools/call").length, 0);
    assert.equal(calls.filter(call => call.path === "/mcp" && call.authorization === "Bearer private-admin-token").length, 0);
    for (const secret of ["private-admin-token", "private-bootstrap-token"]) { assert.ok(!stdout.includes(secret)); assert.ok(!stderr.includes(secret)); assert.ok(!output?.includes(secret)); }
    return { status, stdout, stderr, output, mode, calls };
  } finally { await new Promise<void>(resolve => server.close(() => resolve())); rmSync(directory, { recursive: true, force: true }); }
}

test("operator preparation persists only a scope-confirmed delegated bearer, without any tool effect", async () => {
  const result = await prepare(); assert.equal(result.status, 0, result.stderr); assert.equal(result.mode, 0o600);
  const config = JSON.parse(result.output!);
  assert.equal(config.execution.bearerToken, "delegated-session-token");
  assert.equal(config.execution.sessionId, "kernel-session");
  assert.equal(config.execution.subjectKey, "ab".repeat(32));
  assert.deepEqual(config.tools.map((tool: any) => tool.name), ["read_file"]);
  assert.deepEqual(config.sessionCredential.allowedTools, ["read_file"]);
  assert.equal(config.sessionCredential.bearerToken, undefined);
  assert.equal(config.sessionCredential.expiresAt - config.sessionCredential.issuedAt, 300);
  assert.equal(result.calls.filter(call => call.method === "initialize").length, 1);
  assert.equal(result.calls.filter(call => call.method === "DELETE").length, 0);
  assert.equal(result.calls.at(-1)?.authorization, "Bearer delegated-session-token");
});

for (const [name, scenario] of [
  ["missing separate admin credential", { input: { adminToken: undefined } }],
  ["admin credential reused as bootstrap bearer", { input: { adminToken: "private-bootstrap-token" } }],
  ["unbounded credential lifetime", { input: { credentialTtlSeconds: 3601 } }],
  ["wrong operator server", { contextServer: "other-server" }],
  ["kernel without credential exchange", { status: 404 }],
  ["malformed credential exchange", { malformed: true }],
  ["foreign session credential", { credential: { sessionId: "another-session" } }],
  ["foreign subject credential", { credential: { subjectKey: "ef".repeat(32) } }],
  ["foreign capability credential", { credential: { capabilityIds: ["other-cap"] } }],
  ["broader credential tool access", { credential: { allowedTools: ["read_file", "write_file"] } }],
  ["foreign credential server", { credential: { serverId: "other-server" } }],
  ["expired credential", { credential: { expiresAt: 1 } }],
  ["bootstrap credential returned by exchange", { credential: { bearerToken: "private-bootstrap-token" } }],
  ["delegated context does not retain restriction", { delegated: { allowedTools: ["write_file"] } }],
] as [string, Scenario][]) test(`preparation refuses ${name} without delivering a config`, async () => {
  const result = await prepare(scenario);
  assert.equal(result.status, 1); assert.equal(result.output, undefined); assert.match(result.stderr, /Gateway preparation failed/);
  if (result.calls.length) assert.equal(result.calls.at(-1)?.method, "DELETE", "failed preparation must close its newly created session");
});
