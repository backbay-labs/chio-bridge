import { ChioSession } from "@chio-protocol/sdk";
import {
  canonicalizeJson, sha256Hex, verifyReceiptWithTrustedSigners,
  type ChioReceipt,
} from "@chio-protocol/sdk/invariants";
import { ChioBridgeError } from "./errors.js";
import { verifyApprovalToolCall } from "./approval.js";

export interface McpExecutionOptions {
  endpoint: string;
  bearerToken: string;
  trustedSigners: string[];
  subjectKey: string;
  capabilityId: string;
  serverId: string;
  /** Operator-established session. Never silently replace an expired or lost session. */
  sessionId?: string;
  timeoutMs?: number;
  fetchImpl?: typeof fetch;
}
export interface DelegatedSessionBinding {
  schema: "chio.mcp.session-credential.v1";
  sessionId: string;
  subjectKey: string;
  capabilityIds: string[];
  serverId: string;
  endpointPath: "/mcp";
  allowedTools: string[];
  issuedAt: number;
  expiresAt: number;
}
export type SessionValidation = { ok: true; sessionCredential: DelegatedSessionBinding } | { ok: false; reason: string };
function validateContext(authority: any, config: McpExecutionOptions, requiredTools?: string[]): SessionValidation {
  const denied = (): SessionValidation => ({ ok: false, reason: "authenticated session credential does not match the retained caller, capability, resource owner, tool scope or lifetime" });
  const binding = authority?.sessionCredential;
  const now = Math.floor(Date.now() / 1000);
  if (authority?.schema !== "chio.mcp.execution-context.v1" || authority.evidenceVersion !== "1" || authority.deliveryAcknowledgementVersion !== "1"
    || authority.subjectKey !== config.subjectKey || authority.serverId !== config.serverId
    || !Array.isArray(authority.capabilityIds) || authority.capabilityIds.length !== 1 || authority.capabilityIds[0] !== config.capabilityId
    || binding?.schema !== "chio.mcp.session-credential.v1" || binding.sessionId !== config.sessionId
    || binding.subjectKey !== config.subjectKey || binding.serverId !== config.serverId || binding.endpointPath !== "/mcp"
    || !Array.isArray(binding.capabilityIds) || binding.capabilityIds.length !== 1 || binding.capabilityIds[0] !== config.capabilityId
    || !Array.isArray(binding.allowedTools) || !binding.allowedTools.length
    || binding.allowedTools.some((name: unknown) => typeof name !== "string" || !/^[a-zA-Z0-9_.-]{1,128}$/.test(name))
    || new Set(binding.allowedTools).size !== binding.allowedTools.length
    || !Number.isSafeInteger(binding.issuedAt) || binding.issuedAt > now + 5 || !Number.isSafeInteger(binding.expiresAt)
    || binding.expiresAt <= now || binding.expiresAt <= binding.issuedAt || binding.expiresAt - binding.issuedAt > 3600) return denied();
  if (requiredTools && (requiredTools.length !== binding.allowedTools.length
    || [...requiredTools].sort().some((name, index) => name !== [...binding.allowedTools].sort()[index]))) return denied();
  return { ok: true, sessionCredential: JSON.parse(JSON.stringify(binding)) as DelegatedSessionBinding };
}
export interface ExecutionRequest {
  tool: string;
  arguments: Record<string, unknown>;
  /** Persist this identity before dispatch. Never generate a fresh ID to retry an unknown effect. */
  requestId: string;
  approval?: { chioGovernedIntent: unknown; chioApprovalToken: unknown };
}
export interface ExecutionOutcome {
  state: "not_dispatched" | "unknown" | "denied" | "completed";
  evidence: "unverified" | "verified";
  requestId: string;
  result?: unknown;
  receipt?: ChioReceipt;
  reason?: string;
  delivery?: DeliveryAcknowledgement;
}
export interface DeliveryAcknowledgement {
  schema: "chio.mcp.delivery-ack.v1";
  requestId: string; requestHash: string; receiptId: string; resultHash: string; acknowledgement: string;
}
export type AcknowledgementResult = { acknowledged: true; requestId: string; receiptId: string } | { acknowledged: false; reason: string };
export interface ReceiptBinding {
  trustedSigners: string[];
  subjectKey: string;
  capabilityId: string;
  serverId: string;
  tool: string;
  parameters: unknown;
  requestId: string;
}

/** Verify the signer, modern receipt semantics and the exact intended request.
 * This validates a decision. A separate output hash check is required for a claimed result.
 */
export function verifyBoundReceipt(input: unknown, expected: ReceiptBinding): input is ChioReceipt {
  try {
    if (!input || typeof input !== "object" || !expected.trustedSigners.length) return false;
    const receipt = input as ChioReceipt;
    const verification = verifyReceiptWithTrustedSigners(receipt, expected.trustedSigners);
    const metadata = receipt.metadata as {
      receipt_context?: { request_id?: unknown };
      attribution?: { subject_key?: unknown };
    } | undefined;
    return verification.ok
      && receipt.receipt_kind === "mediated_decision"
      && receipt.boundary_class === "prevent"
      && receipt.trust_level === "mediated"
      && receipt.capability_id === expected.capabilityId
      && receipt.tool_server === expected.serverId
      && receipt.tool_name === expected.tool
      && metadata?.receipt_context?.request_id === expected.requestId
      && metadata?.attribution?.subject_key === expected.subjectKey
      && canonicalizeJson(receipt.action.parameters) === canonicalizeJson(expected.parameters);
  } catch {
    return false;
  }
}

/** Verify bytes received by a host against the signed terminal result.
 * The trusted gateway separately matches the exact delivery proof, including
 * private approval metadata, before acknowledging it at the resource owner.
 */
export function verifyReceivedOutcome(outcome: ExecutionOutcome, expected: ReceiptBinding): boolean {
  try {
    const receipt = outcome.receipt; const delivery = outcome.delivery;
    if (outcome.state !== "completed" || outcome.evidence !== "verified" || !receipt || !delivery || outcome.requestId !== expected.requestId
      || !verifyBoundReceipt(receipt, expected)) return false;
    const admission: any = (receipt.metadata as any)?.admission_operation;
    return receipt.decision?.verdict === "allow" && admission?.schema === "chio.admission-receipt.v1"
      && admission.request_id === expected.requestId && admission.projected_state === "completed"
      && admission.projected_dispatch_state === "terminal" && typeof admission.tool_outcome_id === "string"
      && outcome.result !== undefined && receipt.content_hash === sha256Hex(canonicalizeJson(outcome.result))
      && delivery.schema === "chio.mcp.delivery-ack.v1" && delivery.requestId === expected.requestId && delivery.receiptId === receipt.id
      && delivery.resultHash === receipt.content_hash && /^[a-f0-9]{64}$/.test(delivery.requestHash)
      && typeof delivery.acknowledgement === "string" && /^[A-Za-z0-9_-]{43}$/.test(delivery.acknowledgement);
  } catch { return false; }
}

/** Revalidate a cached result against the caller's original request before trusting it. */
export function verifyCompletedOutcome(outcome: ExecutionOutcome, config: McpExecutionOptions, request: ExecutionRequest): boolean {
  try {
    const params = {name:request.tool,arguments:request.arguments,_meta:{chioRequestId:request.requestId,...request.approval}};
    return verifyReceivedOutcome(outcome, {...config,tool:request.tool,parameters:request.arguments,requestId:request.requestId})
      && outcome.delivery!.requestHash === sha256Hex(canonicalizeJson({method:"tools/call",params}));
  } catch { return false; }
}

/** Executes only through the kernel-owned MCP edge. No local effect callback exists.
 * The owner must persist pending operations and fence uncertain outcomes across restarts.
 * The in-memory map prevents concurrent/repeated dispatch within this client instance.
 */
export function createMcpExecutionClient(options: McpExecutionOptions) {
  const endpoint = new URL(options.endpoint);
  if (endpoint.protocol !== "https:" && !(endpoint.protocol === "http:" && ["127.0.0.1", "localhost", "[::1]"].includes(endpoint.hostname))) {
    throw new ChioBridgeError("invalid_arg", "MCP endpoint requires HTTPS or loopback HTTP");
  }
  if (endpoint.username || endpoint.password || endpoint.hash || endpoint.search) {
    throw new ChioBridgeError("invalid_arg", "MCP endpoint must not contain credentials, query or fragment");
  }
  if (!options.sessionId || !options.bearerToken || !options.capabilityId || !options.serverId || !/^[a-f0-9]{64}$/i.test(options.subjectKey)
    || !options.trustedSigners.length || options.trustedSigners.some(key => !/^[a-f0-9]{64}$/i.test(key))) {
    throw new ChioBridgeError("invalid_arg", "execution requires a retained session, delegated bearer, capability, server, subject and pinned signer keys");
  }
  const timeoutMs = options.timeoutMs ?? 30_000;
  if (!Number.isSafeInteger(timeoutMs) || timeoutMs <= 0) throw new ChioBridgeError("invalid_arg", "invalid execution timeout");
  // Snapshot trusted operator configuration so caller mutation cannot replace authority.
  const config = { ...options, trustedSigners: [...options.trustedSigners] };
  const operations = new Map<string, { digest: string; outcome: Promise<ExecutionOutcome> }>();
  return {
    /** Run in the trusted launcher before making credentials readable to an agent. */
    async validateSession(control: { allowedTools?: string[]; signal?: AbortSignal } = {}): Promise<SessionValidation> {
      const deadline = AbortSignal.timeout(timeoutMs);
      const signal = control.signal ? AbortSignal.any([deadline, control.signal]) : deadline;
      const fetchImpl: typeof fetch = (input, init) => (config.fetchImpl ?? fetch)(input, { ...init, signal, redirect: "error" });
      try {
        const session = new ChioSession({ baseUrl: config.endpoint, authToken: config.bearerToken, sessionId: config.sessionId!, protocolVersion: "2025-11-25", fetchImpl });
        const response = await session.requestResult("chio/execution-context");
        return validateContext("result" in response ? response.result : undefined, config, control.allowedTools);
      } catch { return { ok: false, reason: "delegated session validation failed before dispatch" }; }
    },
    /** The durable owner must save the verified outcome before invoking this method. */
    async acknowledge(outcome: ExecutionOutcome): Promise<AcknowledgementResult> {
      const delivery = outcome?.delivery;
      const receipt = outcome?.receipt;
      try {
      if (outcome.state !== "completed" || outcome.evidence !== "verified" || !delivery || !receipt
        || delivery.schema !== "chio.mcp.delivery-ack.v1" || delivery.requestId !== outcome.requestId || delivery.receiptId !== receipt.id
        || delivery.resultHash !== receipt.content_hash || delivery.resultHash !== sha256Hex(canonicalizeJson(outcome.result))
        || !verifyBoundReceipt(receipt, {...config,tool:receipt.tool_name,parameters:receipt.action.parameters,requestId:outcome.requestId})) {
        return { acknowledged: false, reason: "only an exact verified completed result can be acknowledged" };
      }
      } catch { return {acknowledged:false,reason:"malformed durable outcome cannot be acknowledged"}; }
      const signal = AbortSignal.timeout(timeoutMs);
      const fetchImpl: typeof fetch = (input, init) => (config.fetchImpl ?? fetch)(input, {...init,signal,redirect:"error"});
      try {
        const session = new ChioSession({baseUrl:config.endpoint,authToken:config.bearerToken,sessionId:config.sessionId!,protocolVersion:"2025-11-25",fetchImpl});
        const response = await session.requestResult("chio/acknowledge", delivery!);
        const result: any = "result" in response ? response.result : undefined;
        if (result?.schema !== delivery!.schema || result.requestId !== delivery!.requestId || result.receiptId !== delivery!.receiptId || result.acknowledged !== true) throw new Error("invalid acknowledgement response");
        return {acknowledged:true,requestId:delivery!.requestId,receiptId:delivery!.receiptId};
      } catch { return {acknowledged:false,reason:"acknowledgement not confirmed; retain durable result and retry only acknowledgement"}; }
    },
    execute(request: ExecutionRequest, control: { signal?: AbortSignal } = {}): Promise<ExecutionOutcome> {
      if (!request.requestId || request.requestId.length > 2048 || !request.tool || !request.arguments || typeof request.arguments !== "object" || Array.isArray(request.arguments)) {
        return Promise.resolve({ state: "not_dispatched", evidence: "unverified", requestId: request.requestId, reason: "invalid execution request" });
      }
      let snapshot: ExecutionRequest;
      let digest: string;
      try {
        snapshot = JSON.parse(canonicalizeJson(request)) as ExecutionRequest;
        digest = sha256Hex(canonicalizeJson({ tool: snapshot.tool, arguments: snapshot.arguments, ...(snapshot.approval ? {approval:snapshot.approval} : {}) }));
      } catch {
        return Promise.resolve({ state: "not_dispatched", evidence: "unverified", requestId: request.requestId, reason: "request is not canonical JSON" });
      }
      const prior = operations.get(snapshot.requestId);
      if (prior) {
        if (prior.digest !== digest) return Promise.resolve({ state: "not_dispatched", evidence: "unverified", requestId: snapshot.requestId, reason: "request ID reused with different arguments" });
        return prior.outcome;
      }
      const outcome = dispatch(snapshot, control.signal);
      operations.set(snapshot.requestId, { digest, outcome });
      return outcome;
    },
  };

  async function dispatch(request: ExecutionRequest, signal?: AbortSignal): Promise<ExecutionOutcome> {
    let sent = false;
    const failure = (reason: string): ExecutionOutcome => ({
      state: sent ? "unknown" : "not_dispatched", evidence: "unverified", requestId: request.requestId, reason,
    });
    if (signal?.aborted) return failure("cancelled before admission");
    const deadline = AbortSignal.timeout(timeoutMs);
    const combined = signal ? AbortSignal.any([signal, deadline]) : deadline;
    const fetchImpl: typeof fetch = (input, init) => (config.fetchImpl ?? fetch)(input, { ...init, signal: combined, redirect: "error" });
    let session;
    try {
      session = new ChioSession({
        baseUrl: config.endpoint, authToken: config.bearerToken, sessionId: config.sessionId!,
        protocolVersion: "2025-11-25", fetchImpl,
      });
      const context = await session.requestResult("chio/execution-context");
      const authority = validateContext("result" in context ? context.result : undefined, config);
      if (!authority.ok) return failure(authority.reason);
      if (!authority.sessionCredential.allowedTools.includes(request.tool)) return failure("tool is outside the authenticated session credential scope");
      const params = { name: request.tool, arguments: request.arguments, _meta: { chioRequestId: request.requestId, ...request.approval } };
      if (request.approval && verifyApprovalToolCall(params,{...config,sessionId:config.sessionId!,tool:request.tool,arguments:request.arguments,requestId:request.requestId})?.decision !== "approved") return failure("approval does not authorize the exact retained action");
      if (combined.aborted) return failure("cancelled before dispatch");
      sent = true;
      const response = await session.requestResult<unknown>("tools/call", params);
      if (!("result" in response)) return failure("kernel RPC error after dispatch; reconcile the resource before retry");
      const result = response.result as { _meta?: { chioEvidence?: unknown } } | null;
      const envelope = result?._meta?.chioEvidence as {
        schema?: unknown; requestId?: unknown; receipt?: unknown; output?: unknown; terminalState?: unknown; outputKind?: unknown;
      } | undefined;
      if (envelope?.schema !== "chio.mcp.execution-evidence.v1" || envelope.requestId !== request.requestId) return failure("missing or substituted execution evidence");
      if (!verifyBoundReceipt(envelope.receipt, { ...config, tool: request.tool, parameters: request.arguments, requestId: request.requestId })) return failure("execution receipt failed trusted request verification");
      const receipt = envelope.receipt;
      // Denial is a verified decision, not proof that no pre-denial effect occurred.
      if (receipt.decision?.verdict === "deny") {
        // The current edge signs durable replay failures without an admission projection.
        // Such a denial can follow an already committed external effect. Conservatively
        // retain uncertainty for all durable-admission errors, including unknown states.
        if (receipt.decision.guard === "kernel" && receipt.decision.reason?.startsWith("durable admission failed:")) {
          return { state: "unknown", evidence: "verified", requestId: request.requestId, receipt,
            reason: "durable admission rejected this attempt; the original operation requires reconciliation" };
        }
        return { state: "denied", evidence: "verified", requestId: request.requestId, receipt, reason: receipt.decision.reason };
      }
      const admission = (receipt.metadata as { admission_operation?: { schema?: unknown; request_id?: unknown; projected_state?: unknown; projected_dispatch_state?: unknown; tool_outcome_id?: unknown } } | undefined)?.admission_operation;
      if (receipt.decision?.verdict !== "allow" || admission?.schema !== "chio.admission-receipt.v1"
        || admission.request_id !== request.requestId || admission.projected_state !== "completed"
        || admission.projected_dispatch_state !== "terminal" || typeof admission.tool_outcome_id !== "string"
        || envelope.terminalState !== "completed"
        || envelope.outputKind !== "value" || envelope.output === undefined || receipt.content_hash !== sha256Hex(canonicalizeJson(envelope.output))) {
        return { state: "unknown", evidence: "verified", requestId: request.requestId, receipt, reason: "no verified completed result; preserve the operation fence" };
      }
      const delivery = (result as any)?._meta?.chioDelivery as DeliveryAcknowledgement | undefined;
      if (!delivery || delivery.schema !== "chio.mcp.delivery-ack.v1" || delivery.requestId !== request.requestId
        || delivery.receiptId !== receipt.id || delivery.resultHash !== receipt.content_hash
        || delivery.requestHash !== sha256Hex(canonicalizeJson({method:"tools/call",params}))
        || typeof delivery.acknowledgement !== "string" || !/^[A-Za-z0-9_-]{43}$/.test(delivery.acknowledgement)) {
        return {state:"unknown",evidence:"verified",requestId:request.requestId,receipt,reason:"verified result lacks exact retained delivery acknowledgement; preserve operation fence"};
      }
      return { state: "completed", evidence: "verified", requestId: request.requestId, receipt, result: envelope.output, delivery };
    } catch {
      return failure(sent ? "execution outcome unknown; no automatic retry" : "kernel unavailable or malformed handshake before dispatch");
    }
  }
}
