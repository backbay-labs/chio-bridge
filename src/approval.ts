import { canonicalizeJson, sha256Hex, verifyUtf8MessageEd25519 } from "@chio-protocol/sdk/invariants";

export interface ApprovalBinding {
  requestId: string; sessionId: string; capabilityId: string; subjectKey: string;
  serverId: string; tool: string; arguments: Record<string, unknown>; trustedSigners: string[];
}
export interface ApprovedToolCall {
  name: string; arguments: Record<string, unknown>;
  _meta: { chioRequestId: string; chioGovernedIntent: unknown; chioApprovalToken: unknown };
}
/** Authorization only. Neither an approval nor a denial attests a resource outcome. */
export function verifyApprovalToolCall(input: unknown, expected: ApprovalBinding): { decision: "approved" | "denied"; params: ApprovedToolCall } | undefined {
  try {
    const params = input as any; const intent = params?._meta?.chioGovernedIntent; const token = params?._meta?.chioApprovalToken;
    const now = Math.floor(Date.now() / 1000);
    if (params?.name !== expected.tool || canonicalizeJson(params.arguments) !== canonicalizeJson(expected.arguments)
      || params?._meta?.chioRequestId !== expected.requestId || intent?.server_id !== expected.serverId || intent.tool_name !== expected.tool
      || intent?.body?.kind !== "bound_tool_invocation" || intent.body.value?.capability_id !== expected.capabilityId
      || intent.body.value.parameters_hash !== "0x" + sha256Hex(canonicalizeJson(expected.arguments))
      || intent.context?.mcpSessionId !== expected.sessionId || intent.context?.capabilityId !== expected.capabilityId
      || !token || !["approved", "denied"].includes(token.decision) || token.subject !== expected.subjectKey || token.request_id !== expected.requestId
      || typeof token.approver !== "string" || !expected.trustedSigners.some(key => key.toLowerCase() === token.approver.toLowerCase())
      || token.governed_intent_hash !== sha256Hex(canonicalizeJson(intent)) || typeof token.id !== "string" || !token.id
      || !Number.isSafeInteger(token.issued_at) || !Number.isSafeInteger(token.expires_at) || token.issued_at > now + 5
      || token.expires_at <= now || token.expires_at <= token.issued_at || token.expires_at - token.issued_at > 3600
      || token.algorithm !== undefined || token.threshold_proposal_hash !== undefined) return undefined;
    const body = { id: token.id, approver: token.approver, subject: token.subject, governed_intent_hash: token.governed_intent_hash,
      request_id: token.request_id, issued_at: token.issued_at, expires_at: token.expires_at, decision: token.decision };
    if (!verifyUtf8MessageEd25519(canonicalizeJson(body), token.approver, token.signature)) return undefined;
    return { decision: token.decision, params: JSON.parse(canonicalizeJson(params)) as ApprovedToolCall };
  } catch { return undefined; }
}
