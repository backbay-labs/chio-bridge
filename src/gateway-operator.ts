#!/usr/bin/env node
import { closeSync, fsyncSync, lstatSync, mkdirSync, openSync, readFileSync, readdirSync, realpathSync, unlinkSync, writeFileSync } from "node:fs";
import { hostname } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { gatewayApprovalPath, gatewayBinding, operationKey, privatePath, readGatewayConfig, type GatewayConfig, type StoredOperation } from "./gateway.js";
import { verifyApprovalToolCall } from "./approval.js";

function syncDirectory(path: string) { const fd=openSync(path,"r");try{fsyncSync(fd);}finally{closeSync(fd);} }
function privateJson(path: string): any { privatePath(path,false);if(lstatSync(path).size>1024*1024)throw new Error("oversized private file");return JSON.parse(readFileSync(path,"utf8")); }
function ownerState(owner: any): "alive"|"dead"|"unverifiable" {
  if (!owner || owner.hostname!==hostname() || !Number.isSafeInteger(owner.pid) || owner.pid<1) return "unverifiable";
  try {process.kill(owner.pid,0);return "alive";} catch(error) {return (error as NodeJS.ErrnoException).code==="ESRCH" ? "dead" : "unverifiable";}
}
function checkBinding(config:GatewayConfig) {
  privatePath(config.journalDir,true);
  const binding=join(config.journalDir,"authority.binding");privatePath(binding,false);
  if(readFileSync(binding,"utf8")!==gatewayBinding(config))throw new Error("journal authority does not match operator configuration");
}
export function gatewayStatus(config: GatewayConfig) {
  checkBinding(config);
  const names=readdirSync(config.journalDir);const lockPath=join(config.journalDir,"gateway.lock");
  const owner=names.includes("gateway.lock")?privateJson(lockPath):undefined;
  const operations=names.filter(name=>name.endsWith(".json")).map(name=>{
    const record=privateJson(join(config.journalDir,name)) as StoredOperation;
    if(!record.requestId||!["pending","awaiting_approval","not_dispatched","unknown","denied","completed"].includes(record.state))throw new Error("corrupt operation journal");
    return {requestId:record.requestId,state:record.state,acknowledged:record.acknowledged===true};
  });
  return {schema:"chio.gateway.status.v1",sessionId:config.sessionId,lock:owner?{...owner,state:ownerState(owner)}:{state:"missing"},operations,
    fenced:operations.some(record=>record.state!=="not_dispatched"&&!(record.state==="completed"&&record.acknowledged))};
}
export function recoverGatewayLock(config:GatewayConfig) {
  checkBinding(config);
  const recoveryPath=join(config.journalDir,"recovery.lock");const recovery=openSync(recoveryPath,"wx",0o600);
  try {
    writeFileSync(recovery,JSON.stringify({pid:process.pid,hostname:hostname()}));fsyncSync(recovery);syncDirectory(config.journalDir);
    const lockPath=join(config.journalDir,"gateway.lock");const before=lstatSync(lockPath);const raw=readFileSync(lockPath,"utf8");const owner=privateJson(lockPath);
    if(owner.sessionId!==config.sessionId||ownerState(owner)!=="dead")throw new Error("gateway owner is alive or cannot be proved dead on this machine");
    const status=gatewayStatus(config); // Validate and retain every operation, including pending and unknown.
    const after=lstatSync(lockPath);
    if(before.dev!==after.dev||before.ino!==after.ino||raw!==readFileSync(lockPath,"utf8"))throw new Error("gateway lock changed during recovery");
    unlinkSync(lockPath);syncDirectory(config.journalDir);
    return {...status,lock:{state:"recovered-dead-owner"},recovered:true,journalsRetained:true};
  } finally {closeSync(recovery);unlinkSync(recoveryPath);syncDirectory(config.journalDir);}
}
function proposal(config:GatewayConfig,requestId:string) {
  checkBinding(config);
  const record=privateJson(join(config.journalDir,operationKey(requestId)+".json")) as StoredOperation;
  if(record.requestId!==requestId||record.state!=="awaiting_approval"||!record.proposal)throw new Error("only an undispatched retained proposal can be decided");
  if(record.proposal.session_id!==config.execution.sessionId||record.proposal.capability_id!==config.execution.capabilityId)throw new Error("proposal authority changed");
  return record.proposal;
}
async function main() {
  const [action,configPath,...args]=process.argv.slice(2);
  if(!configPath||resolve(configPath)!==configPath)throw new Error("usage: chio-gateway-operator status|recover-lock|approval-submit|approval-decide CONFIG [arguments]");
  const config=readGatewayConfig(configPath);
  if(action==="status"&&args.length===0){process.stdout.write(JSON.stringify(gatewayStatus(config))+"\n");return;}
  if(action==="recover-lock"&&args.length===0){process.stdout.write(JSON.stringify(recoverGatewayLock(config))+"\n");return;}
  const [requestId,operatorPath,artifactOrId,decision]=args;
  if(!requestId||!operatorPath||!artifactOrId||!['approval-submit','approval-decide'].includes(action??""))throw new Error("approval-submit CONFIG REQUEST_ID OPERATOR_FILE NEW_OUTPUT; approval-decide CONFIG REQUEST_ID OPERATOR_FILE APPROVAL_ID approved|denied");
  const proposed=proposal(config,requestId);const operator=privateJson(operatorPath);
  if(typeof operator.adminToken!=="string"||!operator.adminToken||operator.adminToken===config.execution.bearerToken)throw new Error("distinct operator-only admin credential required");
  const endpoint=new URL(config.execution.endpoint);
  if(endpoint.pathname!=="/"||endpoint.username||endpoint.password||endpoint.search||endpoint.hash||(endpoint.protocol!=="https:"&&!(endpoint.protocol==="http:"&&["127.0.0.1","localhost","[::1]"].includes(endpoint.hostname))))throw new Error("invalid operator endpoint");
  let route="/admin/approvals";let body:unknown=proposed;let output=artifactOrId;
  if(action==="approval-decide"){
    if(!["approved","denied"].includes(decision??""))throw new Error("explicit approval decision required");
    route+="/"+encodeURIComponent(artifactOrId)+"/decision";body={decision};
    output=gatewayApprovalPath(config,requestId);mkdirSync(dirname(output),{recursive:true,mode:0o700});privatePath(dirname(output),true);
  }else if(decision!==undefined)throw new Error("unexpected submit argument");
  // Reserve the output before changing operator state. Never overwrite an earlier artifact.
  const descriptor=openSync(output,"wx",0o600);let saved=false;
  try {
    const response=await fetch(new URL(route,endpoint),{method:"POST",headers:{Authorization:`Bearer ${operator.adminToken}`,"Content-Type":"application/json"},body:JSON.stringify(body),redirect:"error",signal:AbortSignal.timeout(30000)});
    if(!response.ok)throw new Error("operator endpoint rejected the request");
    const value=await response.json() as any;
    if(value.dispatchPerformedByThisEndpoint!==false||value.record?.request_id!==requestId||value.record?.session_id!==config.execution.sessionId||value.record?.capability_id!==config.execution.capabilityId)throw new Error("operator record does not bind the retained proposal");
    if(action==="approval-decide"&&!verifyApprovalToolCall(value.toolCallParams,{...config.execution,sessionId:config.execution.sessionId,tool:proposed.tool_name,arguments:proposed.arguments,requestId}))throw new Error("operator decision lacks a trusted exact-action signature");
    writeFileSync(descriptor,JSON.stringify(value,null,2)+"\n");fsyncSync(descriptor);syncDirectory(dirname(output));saved=true;
    process.stdout.write(JSON.stringify({output,status:value.status,approvalId:value.record.id,protectedDispatch:false})+"\n");
  } finally {closeSync(descriptor);if(!saved){unlinkSync(output);syncDirectory(dirname(output));}}
}
if(process.argv[1]&&realpathSync(process.argv[1])===realpathSync(fileURLToPath(import.meta.url))) main().catch(error=>{process.stderr.write(`Gateway operator action failed: ${error instanceof Error?error.message:"invalid request"}. No protected tool was dispatched.\n`);process.exitCode=1;});
