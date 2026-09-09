import { canonicalizeJson, sha256Hex, signUtf8MessageEd25519 } from "@chio-protocol/sdk/invariants";
import type { ExecutionOutcome, ExecutionRequest, McpExecutionOptions } from "../../dist/execution.js";

export function signedCompletion(config: McpExecutionOptions, request: ExecutionRequest, seed: string, result: unknown = {written:true}): ExecutionOutcome {
  const body = {
    timestamp: Math.floor(Date.now()/1000), capability_id:config.capabilityId, tool_server:config.serverId, tool_name:request.tool,
    action:{parameters:request.arguments,parameter_hash:sha256Hex(canonicalizeJson(request.arguments))},decision:{verdict:"allow"},
    receipt_kind:"mediated_decision",boundary_class:"prevent",trust_level:"mediated",tool_origin:"caller_executed",redaction_mode:"none",
    content_hash:sha256Hex(canonicalizeJson(result)),policy_hash:"cd".repeat(32),kernel_key:config.trustedSigners[0],
    metadata:{receipt_context:{request_id:request.requestId},attribution:{subject_key:config.subjectKey},
      admission_operation:{schema:"chio.admission-receipt.v1",request_id:request.requestId,projected_state:"completed",projected_dispatch_state:"terminal",tool_outcome_id:"ef".repeat(32)}},
  };
  const id=sha256Hex(canonicalizeJson(body));
  const receipt={...body,id,signature:signUtf8MessageEd25519(canonicalizeJson({id,body}),seed).signature_hex} as any;
  const params={name:request.tool,arguments:request.arguments,_meta:{chioRequestId:request.requestId,...request.approval}};
  return {state:"completed",evidence:"verified",requestId:request.requestId,result,receipt,
    delivery:{schema:"chio.mcp.delivery-ack.v1",requestId:request.requestId,requestHash:sha256Hex(canonicalizeJson({method:"tools/call",params})),receiptId:id,resultHash:body.content_hash,acknowledgement:"a".repeat(43)}};
}
