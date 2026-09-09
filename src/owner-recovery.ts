import { closeSync, fsyncSync, openSync, readFileSync, renameSync, unlinkSync, writeFileSync } from "node:fs";
import { hostname } from "node:os";
import { join } from "node:path";
import { canonicalizeJson, sha256Hex, verifyChioSignature } from "@chio-protocol/sdk/invariants";
import { gatewayBinding, operationKey, privatePath, type GatewayConfig, type StoredOperation } from "./gateway.js";
import { verifyCompletedOutcome, type ExecutionOutcome } from "./execution.js";

function syncDirectory(path: string) {const fd=openSync(path,"r");try{fsyncSync(fd);}finally{closeSync(fd);}}

/** Operator-only reconciliation. No network, tool invocation or acknowledgement. */
export function importOwnerOutcome(config: GatewayConfig, artifact: any) {
  privatePath(config.journalDir,true);
  const bindingPath=join(config.journalDir,"authority.binding");privatePath(bindingPath,false);
  if(readFileSync(bindingPath,"utf8")!==gatewayBinding(config))throw new Error("journal authority does not match operator configuration");
  const recoveryPath=join(config.journalDir,"recovery.lock");
  const recovery=openSync(recoveryPath,"wx",0o600);
  const lockPath=join(config.journalDir,"gateway.lock");let lock:number|undefined;
  try {
    const owner=JSON.stringify({pid:process.pid,hostname:hostname(),sessionId:config.sessionId});
    writeFileSync(recovery,owner);fsyncSync(recovery);
    // Both locks close the race with a gateway that checked recovery.lock just
    // before this operator started. An existing owner must be stopped first.
    lock=openSync(lockPath,"wx",0o600);writeFileSync(lock,owner);fsyncSync(lock);syncDirectory(config.journalDir);
    const signed=artifact?.record;
    if(artifact?.schema!=="chio.gateway.owner-outcome.v1" || signed?.schema!=="chio.mcp.session-credential-call.v1"
      || typeof artifact.signature!=="string" || !config.execution.trustedSigners.some(key=>{
        try{return verifyChioSignature(canonicalizeJson(signed),artifact.signature,key);}catch{return false;}
      }))throw new Error("owner record lacks a trusted valid signature");
    if(signed.sessionId!==config.execution.sessionId || signed.subjectKey!==config.execution.subjectKey
      || canonicalizeJson(signed.capabilityIds)!==canonicalizeJson([config.execution.capabilityId]) || signed.serverId!==config.execution.serverId
      || !["completed_unacknowledged","acknowledged"].includes(signed.state)
      || typeof signed.requestId!=="string" || !signed.requestId)throw new Error("owner record is not a completed result for this authority");
    const path=join(config.journalDir,operationKey(signed.requestId)+".json");privatePath(path,false);
    const record=JSON.parse(readFileSync(path,"utf8")) as StoredOperation;
    if(record.requestId!==signed.requestId || !record.request || record.request.requestId!==record.requestId
      || record.digest!==operationKey(canonicalizeJson({name:record.request.tool,args:record.request.arguments})))throw new Error("retained original request is missing or changed");
    const result=signed.response?.result,envelope=result?._meta?.chioEvidence;
    const outcome:ExecutionOutcome={state:"completed",evidence:"verified",requestId:signed.requestId,receipt:envelope?.receipt,result:envelope?.output,delivery:result?._meta?.chioDelivery};
    if(signed.response?.jsonrpc!=="2.0" || Object.hasOwn(signed.response,"error")
      || envelope?.schema!=="chio.mcp.execution-evidence.v1" || envelope.requestId!==signed.requestId || envelope.terminalState!=="completed" || envelope.outputKind!=="value"
      || signed.toolName!==record.request.tool || signed.parameterHash!==sha256Hex(canonicalizeJson(record.request.arguments))
      || !verifyCompletedOutcome(outcome,config.execution,record.request)
      || signed.requestHash!==outcome.delivery?.requestHash || canonicalizeJson(signed.deliveryAck)!==canonicalizeJson(outcome.delivery))throw new Error("owner result does not bind the original request and signed output");
    if(record.state==="completed"){
      if(canonicalizeJson(record.outcome)!==canonicalizeJson(outcome))throw new Error("owner result conflicts with the retained completion");
      return {requestId:record.requestId,imported:false,alreadyRetained:true,protectedDispatch:false,acknowledgedByImport:false};
    }
    if(!["pending","unknown"].includes(record.state))throw new Error("only an uncertain original operation can be reconciled");
    const reconciled={...record,state:"completed",outcome,acknowledged:false,hostDeliveryRequired:true,hostDeliveryConfirmed:false,
      operatorReconciliation:{previousState:record.state,previousOutcome:record.outcome??null,ownerRecordSha256:sha256Hex(canonicalizeJson(signed)),ownerSignature:artifact.signature}};
    const temporary=path+`.operator-${process.pid}.tmp`;const fd=openSync(temporary,"wx",0o600);
    try{writeFileSync(fd,JSON.stringify(reconciled));fsyncSync(fd);}finally{closeSync(fd);}
    renameSync(temporary,path);syncDirectory(config.journalDir);
    return {requestId:record.requestId,imported:true,alreadyRetained:false,protectedDispatch:false,acknowledgedByImport:false};
  } finally {
    if(lock!==undefined){closeSync(lock);unlinkSync(lockPath);}
    closeSync(recovery);unlinkSync(recoveryPath);syncDirectory(config.journalDir);
  }
}
