import test from "node:test";
import assert from "node:assert/strict";
import {generateKeyPairSync} from "node:crypto";
import {mkdtempSync,readFileSync,readdirSync,rmSync} from "node:fs";
import {tmpdir} from "node:os";
import {join} from "node:path";
import {canonicalizeJson,sha256Hex,signUtf8MessageEd25519} from "@chio-protocol/sdk/invariants";
import {createGateway,type GatewayConfig} from "../dist/gateway.js";
import {importOwnerOutcome} from "../dist/owner-recovery.js";
import {signedCompletion} from "./helpers/completed.ts";

async function fixture(){
 const keys=generateKeyPairSync("ed25519"),signer=keys.publicKey.export({type:"spki",format:"der"}).subarray(-32).toString("hex"),seed=keys.privateKey.export({type:"pkcs8",format:"der"}).subarray(-32).toString("hex");
 const directory=mkdtempSync(join(tmpdir(),"chio-owner-recovery-"));
 const config:GatewayConfig={execution:{endpoint:"http://127.0.0.1:1",bearerToken:"test",subjectKey:"ab".repeat(32),trustedSigners:[signer],capabilityId:"cap",serverId:"fs",sessionId:"kernel"},sessionId:"host",journalDir:directory,tools:[{name:"write_file",inputSchema:{type:"object"}}]};
 let request:any;const gateway=createGateway(config,{async execute(input){request=input;return{state:"unknown",evidence:"unverified",requestId:input.requestId,reason:"lost result"};}},{requireHostAcknowledgement:true});
 await gateway.call(1,"write_file",{path:"one",content:"original"});gateway.close();
 const outcome=signedCompletion(config.execution,request,seed);
 const record={schema:"chio.mcp.session-credential-call.v1",sessionId:config.execution.sessionId,subjectKey:config.execution.subjectKey,capabilityIds:[config.execution.capabilityId],serverId:config.execution.serverId,requestId:request.requestId,requestHash:outcome.delivery!.requestHash,toolName:request.tool,parameterHash:sha256Hex(canonicalizeJson(request.arguments)),startedAt:1,state:"completed_unacknowledged",response:{jsonrpc:"2.0",id:1,result:{_meta:{chioEvidence:{schema:"chio.mcp.execution-evidence.v1",requestId:request.requestId,receipt:outcome.receipt,output:outcome.result,outputKind:"value",terminalState:"completed"},chioDelivery:outcome.delivery}}},deliveryAck:outcome.delivery};
 const sign=(value:any)=>({schema:"chio.gateway.owner-outcome.v1",record:value,signature:signUtf8MessageEd25519(canonicalizeJson(value),seed).signature_hex});
 const path=join(directory,readdirSync(directory).find(name=>name.endsWith(".json"))!);
 return{directory,config,record,sign,path,outcome,cleanup:()=>rmSync(directory,{recursive:true,force:true})};
}

test("signed owner import preserves uncertainty history and stays fenced until explicit acknowledgement",async()=>{
 const f=await fixture();try{
  const imported=importOwnerOutcome(f.config,f.sign(f.record));assert.equal(imported.protectedDispatch,false);assert.equal(imported.acknowledgedByImport,false);
  const stored=JSON.parse(readFileSync(f.path,"utf8"));assert.equal(stored.state,"completed");assert.equal(stored.acknowledged,false);assert.equal(stored.hostDeliveryConfirmed,false);assert.equal(stored.operatorReconciliation.previousOutcome.state,"unknown");
  assert.equal(importOwnerOutcome(f.config,f.sign(f.record)).alreadyRetained,true);
  let calls=0;const gateway=createGateway(f.config,{async execute(request){calls++;return{state:"unknown",evidence:"unverified",requestId:request.requestId};}},{requireHostAcknowledgement:true});
  try{assert.equal((await gateway.call(2,"write_file",{path:"two"})).state,"not_dispatched");assert.equal(calls,0);}finally{gateway.close();}
 }finally{f.cleanup();}
});

for(const mutation of ["signature","session","principal","scope","pending","output","proof","request","ambiguous-response"]){
 test(`owner import rejects ${mutation} mismatch without changing the original journal`,async()=>{
  const f=await fixture();try{
   const before=readFileSync(f.path,"utf8"),record:any=structuredClone(f.record);
   if(mutation==="session")record.sessionId="different";
   if(mutation==="principal")record.subjectKey="ef".repeat(32);
   if(mutation==="scope")record.capabilityIds.push("other");
   if(mutation==="pending")record.state="pending";
   if(mutation==="output")record.response.result._meta.chioEvidence.output={forged:true};
   if(mutation==="proof")record.deliveryAck={...record.deliveryAck,acknowledgement:"b".repeat(43)};
   if(mutation==="request")record.requestHash="0".repeat(64);
   if(mutation==="ambiguous-response")record.response.error={code:-32603,message:"ambiguous terminal state"};
   const artifact=f.sign(record);if(mutation==="signature")artifact.signature="0".repeat(128);
   assert.throws(()=>importOwnerOutcome(f.config,artifact));assert.equal(readFileSync(f.path,"utf8"),before);
  }finally{f.cleanup();}
 });
}

test("owner import cannot run while a gateway owns the journal",async()=>{
 const f=await fixture();try{
  const gateway=createGateway(f.config);const before=readFileSync(f.path,"utf8");
  try{assert.throws(()=>importOwnerOutcome(f.config,f.sign(f.record)),/EEXIST/);assert.equal(readFileSync(f.path,"utf8"),before);assert(readdirSync(f.directory).includes("gateway.lock"));assert(!readdirSync(f.directory).includes("recovery.lock"));}finally{gateway.close();}
 }finally{f.cleanup();}
});
