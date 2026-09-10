import { test } from "node:test";
import assert from "node:assert/strict";
import { generateKeyPairSync } from "node:crypto";
import { canonicalizeJson, sha256Hex, signUtf8MessageEd25519 } from "@chio-protocol/sdk/invariants";
import { createMcpExecutionClient, verifyBoundReceipt, verifyCompletedOutcome, verifyReceivedOutcome } from "../dist/index.js";

const { privateKey, publicKey } = generateKeyPairSync("ed25519");
const signer = publicKey.export({type:"spki",format:"der"}).subarray(-32).toString("hex");
const seed = privateKey.export({type:"pkcs8",format:"der"}).subarray(-32).toString("hex");
const args = { path: "allowed.txt" };
const output = { text: "useful output" };
const request = {tool: "read_file", arguments: args, requestId: "host-session:call-1"};
const config = { endpoint:"http://127.0.0.1:1234/mcp", bearerToken:"isolated-token", trustedSigners:[signer], subjectKey:"ab".repeat(32), capabilityId:"cap-1", serverId:"workspace", sessionId:"edge-session" };
const expected = {...config, tool: request.tool, parameters:args, requestId:request.requestId};
function receipt(overrides = {}) {
  const body = {
    timestamp: 1_783_000_000, capability_id: config.capabilityId, tool_server: config.serverId, tool_name:request.tool,
    action: {parameters:args, parameter_hash:sha256Hex(canonicalizeJson(args))}, decision:{verdict:"allow"},
    receipt_kind:"mediated_decision", boundary_class:"prevent", trust_level:"mediated", tool_origin:"caller_executed", redaction_mode:"none",
    content_hash:sha256Hex(canonicalizeJson(output)), policy_hash:"cd".repeat(32), kernel_key:signer,
    metadata:{receipt_context:{request_id:request.requestId},attribution:{subject_key:config.subjectKey},admission_operation:{schema:"chio.admission-receipt.v1",request_id:request.requestId,projected_state:"completed",projected_dispatch_state:"terminal",tool_outcome_id:"ef".repeat(32)}},
    ...overrides,
  };
  const id = sha256Hex(canonicalizeJson(body));
  return {...body, id, signature:signUtf8MessageEd25519(canonicalizeJson({id,body}),seed).signature_hex};
}
function transport(options: {feature?: boolean; tamper?: (value:any)=>any; lost?:boolean; contextTamper?: (value:any)=>any}={}) {
  let effects = 0; let acknowledgements = 0;
  const fetchImpl: typeof fetch = async (_input, init) => {
    if (init?.method === "DELETE") return new Response(null,{status:204});
    const body = JSON.parse(String(init?.body));
    if (body.method === "initialize") return new Response(JSON.stringify({jsonrpc:"2.0",id:body.id,result:{protocolVersion:"2025-11-25",capabilities:{experimental: options.feature === false ? {} : {"io.chio/execution-evidence":{version:"1"}}}}}),{headers:{"mcp-session-id":"edge-session","content-type":"application/json"}});
    if (body.method === "notifications/initialized") return new Response(null,{status:202});
    if (body.method === "chio/execution-context") {
      const now = Math.floor(Date.now() / 1000);
      let context: any = {schema:"chio.mcp.execution-context.v1",evidenceVersion:options.feature === false ? "0" : "1",deliveryAcknowledgementVersion:"1",subjectKey:config.subjectKey,capabilityIds:[config.capabilityId],serverId:config.serverId,
        sessionCredential: {schema:"chio.mcp.session-credential.v1",sessionId:config.sessionId,subjectKey:config.subjectKey,capabilityIds:[config.capabilityId],serverId:config.serverId,endpointPath:"/mcp",allowedTools:[request.tool],issuedAt:now,expiresAt:now+300}};
      if (options.contextTamper) context = options.contextTamper(context);
      return new Response(JSON.stringify({jsonrpc:"2.0",id:body.id,result:context}),{headers:{"content-type":"application/json"}});
    }
    if (body.method === "chio/acknowledge") {
      acknowledgements++;
      return new Response(JSON.stringify({jsonrpc:"2.0",id:body.id,result:{schema:"chio.mcp.delivery-ack.v1",requestId:body.params.requestId,receiptId:body.params.receiptId,acknowledged:true}}),{headers:{"content-type":"application/json"}});
    }
    assert.equal(body.method,"tools/call");
    assert.equal(body.params._meta.chioRequestId,request.requestId);
    effects++;
    if(options.lost) throw new Error("response lost after observed effect");
    let result = {_meta:{chioEvidence:{schema:"chio.mcp.execution-evidence.v1",requestId:request.requestId,receipt:receipt(),output,outputKind:"value",terminalState:"completed"}},content:[{type:"text",text:"untrusted rendering"}]};
    (result._meta as any).chioDelivery = {schema:"chio.mcp.delivery-ack.v1",requestId:request.requestId,requestHash:sha256Hex(canonicalizeJson({method:"tools/call",params:body.params})),receiptId:result._meta.chioEvidence.receipt.id,resultHash:result._meta.chioEvidence.receipt.content_hash,acknowledgement:"a".repeat(43)};
    if(options.tamper) result=options.tamper(result);
    return new Response(JSON.stringify({jsonrpc:"2.0",id:body.id,result}),{headers:{"content-type":"application/json"}});
  };
  return {fetchImpl,effects:()=>effects,acknowledgements:()=>acknowledgements};
}

test("strict verification binds trusted signer, principal, capability, tool, arguments, and request ID",()=>{
  const valid=receipt();
  assert.equal(verifyBoundReceipt(valid,expected),true);
  for(const mismatch of [{trustedSigners:["00".repeat(32)]},{subjectKey:"ef".repeat(32)},{capabilityId:"other"},{serverId:"other"},{tool:"write_file"},{parameters:{path:"forbidden"}},{requestId:"different"}]) {
    assert.equal(verifyBoundReceipt(valid,{...expected,...mismatch}),false);
  }
  assert.equal(verifyBoundReceipt(null,expected),false);
  assert.equal(verifyBoundReceipt({...valid,signature:"00".repeat(64)},expected),false);
});

test("kernel without evidence feature cannot receive any effecting request",async()=>{
  const wire=transport({feature:false});
  const client=createMcpExecutionClient({...config,fetchImpl:wire.fetchImpl});
  assert.equal((await client.execute(request)).state,"not_dispatched");
  assert.equal(wire.effects(),0);
});

test("qualified response returns only verified raw result and coalesces concurrent identical IDs",async()=>{
  const wire=transport();
  const client=createMcpExecutionClient({...config,fetchImpl:wire.fetchImpl});
  const [a,b]=await Promise.all([client.execute(request),client.execute(request)]);
  assert.equal(a.state,"completed"); assert.equal(a.evidence,"verified"); assert.deepEqual(a.result,output); assert.deepEqual(a,b); assert.equal(wire.effects(),1);
  assert.equal((await client.execute({...request,arguments:{path:"changed"}})).state,"not_dispatched"); assert.equal(wire.effects(),1);
});

for(const [name,tamper] of [
  ["missing receipt",(value:any)=>{delete value._meta.chioEvidence.receipt;return value;}],
  ["substituted result",(value:any)=>{value._meta.chioEvidence.output={text:"forged"};return value;}],
  ["substituted request",(value:any)=>{value._meta.chioEvidence.requestId="other";return value;}],
  ["unsupported stream",(value:any)=>{value._meta.chioEvidence.outputKind="stream";return value;}],
  ["preflight only",(value:any)=>{value._meta.chioEvidence.outputKind="none";return value;}],
] as const) test(`${name} preserves uncertain outcome after dispatch`,async()=>{
  const wire=transport({tamper});
  const client=createMcpExecutionClient({...config,fetchImpl:wire.fetchImpl});
  assert.equal((await client.execute(request)).state,"unknown");
  assert.equal((await client.execute(request)).state,"unknown");
  assert.equal(wire.effects(),1);
});

test("lost response after observed effect stays unknown and is never retried",async()=>{
  const wire=transport({lost:true});
  const client=createMcpExecutionClient({...config,fetchImpl:wire.fetchImpl});
  assert.equal((await client.execute(request)).state,"unknown");
  await client.execute(request); assert.equal(wire.effects(),1);
});

test("cancellation before dispatch produces no request",async()=>{
  const wire=transport();
  const client=createMcpExecutionClient({...config,fetchImpl:wire.fetchImpl});
  const signal=AbortSignal.abort();
  assert.equal((await client.execute(request,{signal})).state,"not_dispatched"); assert.equal(wire.effects(),0);
});

test("wrong operator-pinned caller, capability or resource owner is rejected before effects",async()=>{
  for (const wrong of [{subjectKey:"cc".repeat(32)},{capabilityId:"wrong-capability"},{serverId:"wrong-resource-owner"}]) {
    const wire=transport();
    const client=createMcpExecutionClient({...config,...wrong,fetchImpl:wire.fetchImpl});
    assert.equal((await client.execute(request)).state,"not_dispatched");
    assert.equal(wire.effects(),0);
  }
});

test("unsigned terminal diagnostics cannot promote a preflight receipt to completion",async()=>{
  const wire=transport({tamper:value=>{
    value._meta.chioEvidence.receipt=receipt({metadata:{receipt_context:{request_id:request.requestId},attribution:{subject_key:config.subjectKey}}});
    return value;
  }});
  const client=createMcpExecutionClient({...config,fetchImpl:wire.fetchImpl});
  assert.equal((await client.execute(request)).state,"unknown");
});

test("durable retry denial cannot erase an original unknown external outcome", async () => {
  const wire = transport({ tamper: value => {
    value._meta.chioEvidence.receipt = receipt({
      decision: { verdict: "deny", guard: "kernel", reason: "durable admission failed: request replay is retained in state OutcomeUnknownAfterDispatch" },
      metadata: { receipt_context: { request_id: request.requestId }, attribution: { subject_key: config.subjectKey } },
    });
    value._meta.chioEvidence.output = null;
    value._meta.chioEvidence.outputKind = "none";
    return value;
  } });
  const client = createMcpExecutionClient({ ...config, fetchImpl: wire.fetchImpl });
  const outcome = await client.execute(request);
  assert.equal(outcome.state, "unknown");
  assert.equal(outcome.evidence, "verified");
  assert.equal(outcome.receipt?.decision.verdict, "deny");
  assert.equal((await client.execute(request)).state, "unknown");
  assert.equal(wire.effects(), 1);
});


test("trusted launcher authenticates delegated scope before exposing a bearer to the host", async () => {
  const wire = transport(); const client = createMcpExecutionClient({...config,fetchImpl:wire.fetchImpl});
  assert.equal((await client.validateSession({allowedTools:[request.tool]})).ok,true);
  assert.equal((await client.validateSession({allowedTools:[request.tool,"write_file"]})).ok,false);
  assert.equal(wire.effects(),0);
});

for (const [name, mutate] of [
  ["bootstrap bearer without delegated context", (context:any) => { delete context.sessionCredential; return context; }],
  ["foreign retained session", (context:any) => { context.sessionCredential.sessionId="other"; return context; }],
  ["expired delegated credential", (context:any) => { context.sessionCredential.expiresAt=1; return context; }],
  ["different allowed tool", (context:any) => { context.sessionCredential.allowedTools=["write_file"]; return context; }],
] as const) test(`${name} cannot dispatch a protected call`, async () => {
  const wire=transport({contextTamper:mutate}); const client=createMcpExecutionClient({...config,fetchImpl:wire.fetchImpl});
  assert.equal((await client.execute(request)).state,"not_dispatched"); assert.equal(wire.effects(),0);
});

test("missing retained session cannot cause automatic initialization", () => {
  assert.throws(()=>createMcpExecutionClient({...config,sessionId:undefined}),/retained session/);
});


test("completed result requires explicit durable-owner acknowledgement and cached proof revalidation",async()=>{
  const wire=transport();const client=createMcpExecutionClient({...config,fetchImpl:wire.fetchImpl});
  const outcome=await client.execute(request);assert.equal(outcome.state,"completed");assert.equal(wire.acknowledgements(),0);
  assert.equal(verifyCompletedOutcome(outcome,config,request),true);
  assert.equal(verifyCompletedOutcome(outcome,config,{...request,arguments:{path:"substituted"}}),false);
  assert.equal((await client.acknowledge({...outcome,result:{forged:true}})).acknowledged,false);assert.equal(wire.acknowledgements(),0);
  assert.equal((await client.acknowledge(outcome)).acknowledged,true);assert.equal(wire.acknowledgements(),1);assert.equal(wire.effects(),1);
});

test("kernel without delivery acknowledgement negotiation cannot receive effects",async()=>{
  const wire=transport({contextTamper:value=>{delete value.deliveryAcknowledgementVersion;return value;}});
  assert.equal((await createMcpExecutionClient({...config,fetchImpl:wire.fetchImpl}).execute(request)).state,"not_dispatched");assert.equal(wire.effects(),0);
});

test("missing post-dispatch delivery binding retains unknown and cannot acknowledge",async()=>{
  const wire=transport({tamper:value=>{delete value._meta.chioDelivery;return value;}});const client=createMcpExecutionClient({...config,fetchImpl:wire.fetchImpl});
  const outcome=await client.execute(request);assert.equal(outcome.state,"unknown");assert.equal((await client.acknowledge(outcome)).acknowledged,false);assert.equal(wire.acknowledgements(),0);
});

test("host-received output bytes cannot be substituted under an authentic decision receipt",async()=>{
  const wire=transport(); const client=createMcpExecutionClient({...config,fetchImpl:wire.fetchImpl});
  const outcome=await client.execute(request);
  assert.equal(verifyReceivedOutcome(outcome,expected),true);
  for(const changed of [
    {...outcome,result:{text:"forged host result"}},
    {...outcome,requestId:"stale-operation"},
    {...outcome,evidence:"unverified" as const},
    {...outcome,delivery:{...outcome.delivery!,resultHash:"00".repeat(32)}},
    {...outcome,delivery:{...outcome.delivery!,receiptId:"different"}},
  ]) assert.equal(verifyReceivedOutcome(changed,expected),false);
  assert.equal(verifyReceivedOutcome(outcome,{...expected,requestId:"next-operation"}),false);
  assert.equal(verifyReceivedOutcome(outcome,{...expected,trustedSigners:["00".repeat(32)]}),false);
  assert.equal(wire.acknowledgements(),0);
});
