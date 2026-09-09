// Real kernel/resource test for the final HTTP delivery boundary, not host acceptance.
import assert from "node:assert/strict";
import { createServer } from "node:http";
import { readFileSync, writeFileSync, mkdirSync } from "node:fs";
import { join, resolve, dirname } from "node:path";
import { pathToFileURL } from "node:url";
import { spawnSync } from "node:child_process";
const [packageDir, configPath, operatorPath, output] = process.argv.slice(2);
if (![packageDir, configPath, operatorPath, output].every(p => p && resolve(p) === p)) throw new Error("MODULE_DIR CONFIG OPERATOR NEW_EVIDENCE_DIR required");
mkdirSync(output, {mode: 0o700});
const { startGatewayHttp } = await import(pathToFileURL(join(packageDir, "dist/index.js")));
const config = JSON.parse(readFileSync(configPath)); const owner = JSON.parse(readFileSync(operatorPath));
function command(args) {const p = spawnSync(args[0], args.slice(1), {encoding: "utf8"}); assert.equal(p.status, 0, p.stderr); return p.stdout;}
function observe() {
 return JSON.parse(command(["docker", "run", "--rm", "--network", "none", "--read-only", "--mount", `type=volume,src=${owner.volume},dst=/observe,readonly`, "--mount", `type=volume,src=${owner.auditVolume},dst=/audit,readonly`, "--entrypoint", "node", owner.image, "-e", "const f=require('fs');let files={};for(const n of f.readdirSync('/observe'))if(f.lstatSync('/observe/'+n).isFile())files[n]=f.readFileSync('/observe/'+n,'utf8');console.log(JSON.stringify({files,dispatch:f.readFileSync('/audit/dispatch.jsonl','utf8').split('\\n').filter(Boolean).map(JSON.parse)}))"]));
}
const cases = []; function record(name, data = {}) {cases.push({name, passed: true, ...data}); writeFileSync(join(output, "cases.json"), JSON.stringify(cases, null, 2) + "\n");}
let transport = await startGatewayHttp(config); let drop = true; let cutpoint;
const proxy = createServer(async (request, response) => {
 let body = ""; for await (const chunk of request) body += chunk;
 const message = JSON.parse(body);
 const upstream = await fetch(transport.url, {method: "POST", headers: {"Content-Type": "application/json", Authorization: `Bearer ${transport.token}`, ...(request.headers["mcp-session-id"] ? {"Mcp-Session-Id": request.headers["mcp-session-id"]} : {})}, body});
 const text = await upstream.text();
 if (drop && message.method === "tools/call") {
  const completed = JSON.parse(JSON.parse(text).result.content[0].text); assert.equal(completed.state, "completed");
  cutpoint = {requestId: completed.requestId, receiptId: completed.receipt.id, discardedBytes: Buffer.byteLength(text)};
  response.destroy(); return;
 }
 response.writeHead(upstream.status, {"Content-Type": "application/json", ...(upstream.headers.get("mcp-session-id") ? {"Mcp-Session-Id": upstream.headers.get("mcp-session-id")} : {})}).end(text);
});
await new Promise(r => proxy.listen(0, "127.0.0.1", r));
async function client(url) {
 let session = "";
 async function rpc(id, method, params) {
  const response = await fetch(url, {method: "POST", headers: {"Content-Type": "application/json", Authorization: `Bearer ${transport.token}`, ...(session ? {"Mcp-Session-Id": session} : {})}, body: JSON.stringify({jsonrpc: "2.0", id, method, params})});
  if (method === "initialize") session = response.headers.get("mcp-session-id");
  assert.equal(response.status, 200); return response.json();
 }
 await rpc(0, "initialize", {protocolVersion: "2025-11-25"});
 return {rpc, async call(id, content) {const raw = await rpc(id, "tools/call", {name: "write_file", arguments: {path: "/workspace/host-delivery.txt", content}}); return JSON.parse(raw.result.content[0].text);}};
}
const before = observe();
try {
 let c = await client(`http://127.0.0.1:${proxy.address().port}/mcp`);
 await assert.rejects(() => c.call(1, "original retained effect")); drop = false;
 const committed = observe(); assert.equal(committed.files["host-delivery.txt"], "original retained effect"); assert.equal(committed.dispatch.length, before.dispatch.length + 1); record("response-lost-after-one-real-effect", {cutpoint, resource: committed});
 assert.equal((await c.call(2, "forbidden replacement")).state, "not_dispatched"); assert.deepEqual(observe(), committed); record("new-request-fenced-without-host-proof");
 await transport.close(); transport = await startGatewayHttp(config); c = await client(transport.url);
 assert.equal((await c.call(1, "forbidden after restart")).state, "not_dispatched"); assert.deepEqual(observe(), committed); record("restart-preserves-last-hop-fence");
 const operatorCli = join(packageDir, "dist/gateway-operator.js"); const received = join(dirname(configPath), "operator-received-outcome.json");
 command([process.execPath, operatorCli, "delivery-export", configPath, cutpoint.requestId, received]); assert.deepEqual(observe(), committed); record("operator-export-has-no-effect-and-does-not-acknowledge");
 const original = JSON.parse(readFileSync(received));
 for (const key of ["requestId", "requestHash", "receiptId", "resultHash", "acknowledgement"]) {
  const rejected = await c.rpc(`forged:${key}`, "chio/acknowledge", {...original.outcome.delivery, [key]: "forged"}); assert.ok(rejected.error); assert.deepEqual(observe(), committed); record("forged-proof-refused-" + key);
 }
 await transport.close();
 const acknowledged = JSON.parse(command([process.execPath, operatorCli, "delivery-acknowledge", configPath, received])); assert.equal(acknowledged.acknowledged, true); assert.equal(acknowledged.protectedDispatch, false); assert.deepEqual(observe(), committed); record("explicit-operator-recovery-without-redispatch", {acknowledged});
 transport = await startGatewayHttp(config); c = await client(transport.url);
 const next = await c.call(1, "useful after explicit recovery"); assert.equal(next.state, "completed");
 assert.equal((await c.rpc(2, "chio/acknowledge", next.delivery)).result.acknowledged, true);
 const after = observe(); assert.equal(after.dispatch.length, before.dispatch.length + 2); assert.equal(after.files["host-delivery.txt"], "useful after explicit recovery"); record("new-useful-work-after-explicit-recovery", {resource: after});
} finally {proxy.closeAllConnections(); await new Promise(r => proxy.close(r)); await transport.close();}
writeFileSync(join(output, "identity.json"), JSON.stringify({kernelSha256: owner.kernelSha256, image: owner.image, packageDir, source: import.meta.url, cases: cases.length, skips: 0, hostAcceptance: false}, null, 2) + "\n");
console.log(JSON.stringify({passed: cases.length, skipped: 0}));
