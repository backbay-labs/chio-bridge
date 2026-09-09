import test from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, readFileSync, readdirSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { createGateway, gatewayToolResult, type GatewayConfig } from "../dist/gateway.js";

function fixture() {
  const directory=mkdtempSync(join(tmpdir(),"chio-gateway-"));
  const config: GatewayConfig={execution:{endpoint:"http://127.0.0.1:1/mcp",bearerToken:"test",trustedSigners:["aa".repeat(32)],subjectKey:"bb".repeat(32),capabilityId:"cap",serverId:"fs",sessionId:"kernel-session"},sessionId:"host-session",journalDir:directory,tools:[{name:"write_file",inputSchema:{type:"object"}}]};
  return {directory,config,cleanup:()=>rmSync(directory,{recursive:true,force:true})};
}

test("before dispatch the durable pending fence exists; unknown result fences all later effects across restart",async()=>{
  const f=fixture(); let effects=0;
  const executor={async execute(request:any){
    const records=readdirSync(f.directory).filter(n=>n.endsWith(".json"));
    assert.equal(records.length,1);
    assert.equal(JSON.parse(readFileSync(join(f.directory,records[0]!),"utf8")).state,"pending");
    effects++;return {state:"unknown" as const,evidence:"unverified" as const,requestId:request.requestId};
  }};
  const first=createGateway(f.config,executor);
  assert.equal((await first.call(1,"write_file",{path:"one"})).state,"unknown");
  assert.equal((await first.call(2,"write_file",{path:"two"})).state,"not_dispatched");first.close();
  const second=createGateway(f.config,executor);
  assert.equal((await second.call(1,"write_file",{path:"one"})).state,"unknown");
  assert.equal((await second.call(3,"write_file",{path:"three"})).state,"not_dispatched");
  assert.equal(effects,1);second.close();f.cleanup();
});

test("completed duplicate returns original result without redispatch; changed request conflicts",async()=>{
  const f=fixture();let effects=0;
  const executor={async execute(request:any){effects++;return {state:"completed" as const,evidence:"verified" as const,requestId:request.requestId,result:{written:true}};}};
  const first=createGateway(f.config,executor);const original=await first.call("id","write_file",{path:"one"});first.close();
  const second=createGateway(f.config,executor);
  assert.deepEqual(await second.call("id","write_file",{path:"one"}),original);
  assert.equal((await second.call("id","write_file",{path:"changed"})).state,"not_dispatched");
  assert.equal(effects,1);second.close();f.cleanup();
});

test("unlisted tools, cancellation before admission and concurrent gateway owners cannot dispatch",async()=>{
  const f=fixture();let effects=0;
  const executor={async execute(request:any){effects++;return {state:"not_dispatched" as const,evidence:"unverified" as const,requestId:request.requestId};}};
  const gateway=createGateway(f.config,executor);
  assert.throws(()=>createGateway(f.config,executor),/EEXIST/);
  assert.equal((await gateway.call(1,"bash",{})).state,"not_dispatched");
  assert.equal((await gateway.call(2,"write_file",{},AbortSignal.abort())).state,"not_dispatched");
  assert.equal(effects,0);gateway.close();f.cleanup();
});

test("post-delivery denial remains fenced rather than being treated as no effect",async()=>{
  const f=fixture();let effects=0;
  const executor={async execute(request:any){effects++;return {state:"denied" as const,evidence:"verified" as const,requestId:request.requestId};}};
  const gateway=createGateway(f.config,executor);
  assert.equal((await gateway.call(1,"write_file",{})).state,"denied");
  assert.equal((await gateway.call(2,"write_file",{})).state,"not_dispatched");
  assert.equal(effects,1);gateway.close();f.cleanup();
});

test("journal authority cannot change on restart",async()=>{
  const f=fixture();
  const first=createGateway(f.config);first.close();
  assert.throws(()=>createGateway({...f.config,execution:{...f.config.execution,subjectKey:"cc".repeat(32)}}),/different authority/);
  f.cleanup();
});

test("stdio cancellation received with a queued call prevents contact with the kernel", async () => {
  const { createServer } = await import("node:http");
  const { spawn } = await import("node:child_process");
  const { writeFileSync } = await import("node:fs");
  const f = fixture();
  let requests = 0;
  const server = createServer((_request, response) => { requests++; response.writeHead(500); response.end(); });
  await new Promise<void>(resolve => server.listen(0, "127.0.0.1", resolve));
  const address = server.address(); assert.ok(address && typeof address === "object");
  f.config.execution.endpoint = `http://127.0.0.1:${address.port}`;
  f.config.journalDir = join(f.directory, "journal");
  const configPath = join(f.directory, "config.json");
  writeFileSync(configPath, JSON.stringify(f.config), { mode: 0o600 });
  try {
    const child = spawn(process.execPath, [new URL("../dist/gateway.js", import.meta.url).pathname, configPath], { stdio: ["pipe", "pipe", "pipe"] });
    let output = ""; let errors = "";
    child.stdout.on("data", chunk => { output += chunk; });
    child.stderr.on("data", chunk => { errors += chunk; });
    const exited = new Promise<number | null>((resolve, reject) => { child.on("error", reject); child.on("exit", resolve); });
    child.stdin.end([
      { jsonrpc: "2.0", id: 0, method: "initialize" },
      { jsonrpc: "2.0", method: "notifications/initialized" },
      { jsonrpc: "2.0", id: 1, method: "tools/call", params: { name: "write_file", arguments: { path: "/must-not-exist" } } },
      { jsonrpc: "2.0", method: "notifications/cancelled", params: { requestId: 1 } },
    ].map(message => JSON.stringify(message)).join("\n") + "\n");
    assert.equal(await exited, 0, errors);
    const call = output.trim().split("\n").map(line => JSON.parse(line)).find(message => message.id === 1);
    const outcome = JSON.parse(call.result.content[0].text);
    assert.equal(outcome.state, "not_dispatched");
    assert.equal(outcome.reason, "cancelled before admission");
    assert.equal(requests, 0);
  } finally { await new Promise<void>(resolve => server.close(() => resolve())); f.cleanup(); }
});

test("completed kernel invocation preserves an upstream MCP tool error", () => {
  const outcome = {
    state: "completed" as const, evidence: "verified" as const, requestId: "read-missing-file",
    result: { isError: true, content: [{ type: "text", text: "file does not exist" }] },
  };
  const rendered = gatewayToolResult(outcome);
  assert.equal(rendered.isError, true);
  assert.deepEqual(JSON.parse(rendered.content[0]!.text), outcome);
  assert.equal(gatewayToolResult({ ...outcome, result: { isError: false, content: [] } }).isError, false);
});
