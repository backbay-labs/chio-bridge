import { ChioClient, ChioSession } from "@chio-protocol/sdk";
import {
  canonicalizeJson, sha256Hex, verifyReceiptWithTrustedSigners,
  type ChioReceipt,
} from "@chio-protocol/sdk/invariants";
import { ChioBridgeError } from "./errors.js";

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
export interface ExecutionRequest {
  tool: string;
  arguments: Record<string, unknown>;
  /** Persist this identity before dispatch. Never generate a fresh ID to retry an unknown effect. */
  requestId: string;
}
export interface ExecutionOutcome {
  state: "not_dispatched" | "unknown" | "denied" | "completed";
  evidence: "unverified" | "verified";
  requestId: string;
  result?: unknown;
  receipt?: ChioReceipt;
  reason?: string;
}
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
  if (!options.bearerToken || !options.capabilityId || !options.serverId || !/^[a-f0-9]{64}$/i.test(options.subjectKey)
    || !options.trustedSigners.length || options.trustedSigners.some(key => !/^[a-f0-9]{64}$/i.test(key))) {
    throw new ChioBridgeError("invalid_arg", "execution requires bearer, capability, server, subject and pinned signer keys");
  }
  const timeoutMs = options.timeoutMs ?? 30_000;
  if (!Number.isSafeInteger(timeoutMs) || timeoutMs <= 0) throw new ChioBridgeError("invalid_arg", "invalid execution timeout");
  // Snapshot trusted operator configuration so caller mutation cannot replace authority.
  const config = { ...options, trustedSigners: [...options.trustedSigners] };
  const operations = new Map<string, { digest: string; outcome: Promise<ExecutionOutcome> }>();
  return {
    execute(request: ExecutionRequest, control: { signal?: AbortSignal } = {}): Promise<ExecutionOutcome> {
      if (!request.requestId || request.requestId.length > 2048 || !request.tool || !request.arguments || typeof request.arguments !== "object" || Array.isArray(request.arguments)) {
        return Promise.resolve({ state: "not_dispatched", evidence: "unverified", requestId: request.requestId, reason: "invalid execution request" });
      }
      let snapshot: ExecutionRequest;
      let digest: string;
      try {
        snapshot = JSON.parse(canonicalizeJson(request)) as ExecutionRequest;
        digest = sha256Hex(canonicalizeJson({ tool: snapshot.tool, arguments: snapshot.arguments }));
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
      session = config.sessionId ? new ChioSession({
        baseUrl: config.endpoint, authToken: config.bearerToken, sessionId: config.sessionId,
        protocolVersion: "2025-11-25", fetchImpl,
      }) : await ChioClient.withStaticBearer(config.endpoint, config.bearerToken, fetchImpl).initialize({
        protocolVersion: "2025-11-25", clientInfo: { name: "@chio/bridge", version: "0.3.0" },
      });
      const handshake = session.handshake?.initializeResponse.messages.find(message => "result" in message) as { result?: { capabilities?: { experimental?: Record<string, unknown> } } } | undefined;
      const feature = handshake?.result?.capabilities?.experimental?.["io.chio/execution-evidence"] as { version?: unknown } | undefined;
      if (!config.sessionId && feature?.version !== "1") return failure("kernel does not advertise execution-evidence v1; upgrade required before dispatch");
      const context = await session.requestResult<{ schema?: unknown; evidenceVersion?: unknown; subjectKey?: unknown; capabilityIds?: unknown }>("chio/execution-context");
      const authority = ("result" in context ? context.result : undefined) as { schema?: unknown; evidenceVersion?: unknown; subjectKey?: unknown; capabilityIds?: unknown } | undefined;
      if (authority?.schema !== "chio.mcp.execution-context.v1"
        || authority.evidenceVersion !== "1" || authority.subjectKey !== config.subjectKey
        || !Array.isArray(authority.capabilityIds) || !authority.capabilityIds.includes(config.capabilityId)) {
        return failure("kernel session authority does not match operator-pinned caller and capability");
      }
      if (combined.aborted) return failure("cancelled before dispatch");
      sent = true;
      const response = await session.requestResult<unknown>("tools/call", {
        name: request.tool, arguments: request.arguments, _meta: { chioRequestId: request.requestId },
      });
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
      return { state: "completed", evidence: "verified", requestId: request.requestId, receipt, result: envelope.output };
    } catch {
      return failure(sent ? "execution outcome unknown; no automatic retry" : "kernel unavailable or malformed handshake before dispatch");
    } finally {
      try { if (!config.sessionId) await session?.close(); } catch { /* Closing a session cannot authorize a retry. */ }
    }
  }
}
