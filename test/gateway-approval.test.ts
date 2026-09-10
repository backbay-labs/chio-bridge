import test from "node:test";
import assert from "node:assert/strict";
import { generateKeyPairSync } from "node:crypto";
import { mkdtempSync, mkdirSync, readFileSync, readdirSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { canonicalizeJson, sha256Hex, signUtf8MessageEd25519 } from "@chio-protocol/sdk/invariants";
import { createGateway, gatewayApprovalPath, operationKey, type GatewayConfig, type GatewayProposal } from "../dist/gateway.js";
import { signedCompletion } from "./helpers/completed.ts";
const keys=generateKeyPairSync("ed25519");const signer=keys.publicKey.export({type:"spki",format:"der"}).subarray(-32).toString("hex");const seed=keys.privateKey.export({type:"pkcs8",format:"der"}).subarray(-32).toString("hex");
function fixture(){const directory=mkdtempSync(join(tmpdir(),"chio-approval-"));const config:GatewayConfig={execution:{endpoint:"http://127.0.0.1:1",bearerToken:"delegated",subjectKey:"ab".repeat(32),trustedSigners:[signer],capabilityId:"cap-one",serverId:"fs",sessionId:"kernel-session"},sessionId:"host-session",journalDir:directory,tools:[{name:"write_file",inputSchema:{type:"object"}}],approval:{requiredTools:["write_file"],purpose:"Review exact file content",ttlSeconds:300}};return{directory,config,cleanup:()=>rmSync(directory,{recursive:true,force:true})};}
function artifact(f:ReturnType<typeof fixture>,proposal:GatewayProposal,decision="approved",mutate?:(value:any)=>void){
 const intent={id:"approval-id",server_id:"fs",tool_name:proposal.tool_name,purpose:proposal.purpose,context:{mcpSessionId:proposal.session_id,capabilityId:proposal.capability_id},body:{kind:"bound_tool_invocation",value:{capability_id:proposal.capability_id,parameters_hash:"0x"+sha256Hex(canonicalizeJson(proposal.arguments))}}};
 const now=Math.floor(Date.now()/1000);const body={id:"token-id",approver:signer,subject:f.config.execution.subjectKey,governed_intent_hash:sha256Hex(canonicalizeJson(intent)),request_id:proposal.request_id,issued_at:now,expires_at:now+300,decision};
 const token={...body,signature:signUtf8MessageEd25519(canonicalizeJson(body),seed).signature_hex};
 const value={toolCallParams:{name:proposal.tool_name,arguments:proposal.arguments,_meta:{chioRequestId:proposal.request_id,chioGovernedIntent:intent,chioApprovalToken:token}}};mutate?.(value);
 const path=gatewayApprovalPath(f.config,proposal.request_id);mkdirSync(dirname(path),{recursive:true,mode:0o700});writeFileSync(path,JSON.stringify(value),{mode:0o600});
}
test("proposal performs no dispatch, explicit approved resume retains exact identity and saves completion before acknowledgement",async()=>{
 const f=fixture();let effects=0;let acknowledgements=0;let dispatched:any;
 const executor={async execute(request:any){effects++;dispatched=request;return signedCompletion(f.config.execution,request,seed);},async acknowledge(outcome:any){const record=JSON.parse(readFileSync(join(f.directory,operationKey(outcome.requestId)+".json"),"utf8"));assert.equal(record.state,"completed");assert.equal(record.outcome.result.written,true);acknowledgements++;return{acknowledged:true as const,requestId:outcome.requestId,receiptId:"fixture"};}};
 const gateway=createGateway(f.config,executor);try{
  const initial=await gateway.call(1,"write_file",{path:"allowed.txt",content:"reviewed"});assert.equal(initial.state,"awaiting_approval");assert.equal(effects,0);assert.equal(acknowledgements,0);assert.ok("proposal" in initial);
  assert.equal((await gateway.call(2,"write_file",{path:"different.txt"})).state,"not_dispatched");
  artifact(f,initial.proposal);
  assert.equal((await gateway.call(1,"write_file",initial.proposal.arguments)).state,"awaiting_approval");assert.equal(effects,0);
  const resume={requestId:initial.requestId,tool:"write_file",arguments:initial.proposal.arguments};
  assert.equal((await gateway.call(3,"chio_resume",resume)).state,"completed");assert.equal(effects,1);assert.equal(acknowledgements,1);
  assert.equal(dispatched.requestId,initial.requestId);assert.equal(dispatched.approval.chioApprovalToken.request_id,initial.requestId);
  assert.equal((await gateway.call(4,"chio_resume",resume)).state,"completed");assert.equal(effects,1);
 }finally{gateway.close();f.cleanup();}
});
for(const [name,mutate] of [
 ["changed arguments",(v:any)=>{v.toolCallParams.arguments={path:"other"};}],
 ["forged signature",(v:any)=>{v.toolCallParams._meta.chioApprovalToken.signature="00".repeat(64);}],
 ["expired approval",(v:any)=>{v.toolCallParams._meta.chioApprovalToken.expires_at=1;}],
] as const)test(`${name} leaves the proposal undispatched and fenced`,async()=>{
 const f=fixture();let effects=0;const gateway=createGateway(f.config,{async execute(request:any){effects++;return{state:"unknown",evidence:"unverified",requestId:request.requestId};}});try{
 const initial=await gateway.call(1,"write_file",{path:"allowed"});assert.ok("proposal"in initial);artifact(f,initial.proposal,"approved",mutate);
 assert.equal((await gateway.call(2,"chio_resume",{requestId:initial.requestId,tool:"write_file",arguments:initial.proposal.arguments})).state,"awaiting_approval");assert.equal(effects,0);
 }finally{gateway.close();f.cleanup();}
});
test("signed operator denial prevents dispatch and retains the terminal proposal identity",async()=>{
 const f=fixture();let effects=0;const gateway=createGateway(f.config,{async execute(request:any){effects++;return{state:"unknown",evidence:"unverified",requestId:request.requestId};}});try{
 const initial=await gateway.call(1,"write_file",{path:"denied"});assert.ok("proposal"in initial);artifact(f,initial.proposal,"denied");
 assert.equal((await gateway.call(2,"chio_resume",{requestId:initial.requestId,tool:"write_file",arguments:initial.proposal.arguments})).state,"not_dispatched");assert.equal(effects,0);
 assert.equal((await gateway.call(3,"write_file",{path:"fresh"})).state,"awaiting_approval");assert.equal(effects,0);
 }finally{gateway.close();f.cleanup();}
});
test("proposal survives restart and unknown approved execution never redispatches",async()=>{
 const f=fixture();let effects=0;const executor={async execute(request:any){effects++;return{state:"unknown" as const,evidence:"unverified" as const,requestId:request.requestId};}};
 const first=createGateway(f.config,executor);const initial=await first.call(1,"write_file",{path:"maybe-written"});assert.ok("proposal"in initial);first.close();artifact(f,initial.proposal);
 const second=createGateway(f.config,executor);const resume={requestId:initial.requestId,tool:"write_file",arguments:initial.proposal.arguments};assert.equal((await second.call(9,"chio_resume",resume)).state,"unknown");second.close();
 const third=createGateway(f.config,executor);try{assert.equal((await third.call(10,"chio_resume",resume)).state,"unknown");assert.equal((await third.call(11,"write_file",{path:"other"})).state,"not_dispatched");assert.equal(effects,1);}finally{third.close();f.cleanup();}
});
