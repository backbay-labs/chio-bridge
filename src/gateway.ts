#!/usr/bin/env node
import { createHash } from "node:crypto";
import { constants, closeSync, fsyncSync, lstatSync, mkdirSync, openSync, readFileSync, readdirSync, realpathSync, renameSync, unlinkSync, writeFileSync } from "node:fs";
import { hostname } from "node:os";
import { resolve, join } from "node:path";
import { createInterface } from "node:readline";
import { fileURLToPath } from "node:url";
import { canonicalizeJson } from "@chio-protocol/sdk/invariants";
import { verifyApprovalToolCall } from "./approval.js";
import { createMcpExecutionClient, verifyCompletedOutcome, type ExecutionOutcome, type McpExecutionOptions, type AcknowledgementResult, type ExecutionRequest } from "./execution.js";

interface Tool { name: string; description?: string; inputSchema: Record<string, unknown> }
export interface GatewayConfig {
  execution: McpExecutionOptions & { sessionId: string };
  sessionId: string;
  journalDir: string;
  tools: Tool[];
  approval?: { requiredTools: string[]; purpose: string; ttlSeconds: number };
}
export interface GatewayProposal {
  session_id: string; capability_id: string; request_id: string; tool_name: string;
  arguments: Record<string, unknown>; purpose: string; ttl_seconds: number;
}
export type GatewayOutcome = ExecutionOutcome | { state: "awaiting_approval"; evidence: "unverified"; requestId: string; proposal: GatewayProposal; reason: string };
export interface StoredOperation {
  requestId: string; digest: string; state: "pending" | GatewayOutcome["state"];
  outcome?: GatewayOutcome; proposal?: GatewayProposal; acknowledged?: boolean;
  request?: ExecutionRequest;
  hostDeliveryConfirmed?: boolean;
  hostDeliveryRequired?: boolean;
}
export function operationKey(requestId: string) { return createHash("sha256").update(requestId).digest("hex"); }
export function gatewayApprovalPath(config: GatewayConfig, requestId: string) { return join(resolve(config.journalDir), "approvals", `${operationKey(requestId)}.json`); }
export function gatewayBinding(config: GatewayConfig) {
  return canonicalizeJson({sessionId:config.sessionId,kernelSessionId:config.execution.sessionId,endpoint:config.execution.endpoint,
    subjectKey:config.execution.subjectKey,capabilityId:config.execution.capabilityId,serverId:config.execution.serverId,
    trustedSigners:config.execution.trustedSigners,tools:config.tools,...(config.approval ? {approval:config.approval} : {})});
}
function syncDirectory(path: string) {
  const fd = openSync(path, constants.O_RDONLY);
  try { fsyncSync(fd); } finally { closeSync(fd); }
}
export function privatePath(path: string, directory: boolean) {
  const stat = lstatSync(path);
  if (stat.isSymbolicLink() || (directory ? !stat.isDirectory() : !stat.isFile()) || (stat.mode & 0o077) !== 0) {
    throw new Error("operator config and journal must be private regular paths");
  }
}
export function readGatewayConfig(path: string): GatewayConfig {
  privatePath(path, false);
  if (lstatSync(path).size > 1024 * 1024) throw new Error("gateway config exceeds size limit");
  const config = JSON.parse(readFileSync(path, "utf8")) as GatewayConfig;
  if (!config?.execution?.sessionId || !config.sessionId || !config.journalDir || !Array.isArray(config.tools) || !config.tools.length) {
    throw new Error("gateway requires an operator-established kernel session, journal and explicit tools");
  }
  if (config.execution.fetchImpl !== undefined) throw new Error("config cannot provide executable transport");
  const names = new Set<string>();
  for (const tool of config.tools) {
    if (!tool || typeof tool.name !== "string" || !/^[a-zA-Z0-9_.-]{1,128}$/.test(tool.name) || names.has(tool.name)
      || !tool.inputSchema || typeof tool.inputSchema !== "object" || Array.isArray(tool.inputSchema)) throw new Error("invalid or duplicate operator tool");
    names.add(tool.name);
  }
  if (config.approval && (!Array.isArray(config.approval.requiredTools) || !config.approval.requiredTools.length
    || config.approval.requiredTools.some(name => !names.has(name)) || !config.approval.purpose
    || !Number.isSafeInteger(config.approval.ttlSeconds) || config.approval.ttlSeconds < 1 || config.approval.ttlSeconds > 3600)) throw new Error("invalid approval configuration");
  if (names.has("chio_resume")) throw new Error("chio_resume is reserved for explicit gateway resumption");
  return config;
}
/** The journal is a conservative dispatch interlock, not a second resource ledger.
 * It never resolves an unknown outcome or replays it under a fresh identity.
 */
export function createGateway(config: GatewayConfig, executor: { execute(request: ExecutionRequest, control?: {signal?:AbortSignal}): Promise<ExecutionOutcome>; acknowledge?(outcome: ExecutionOutcome): Promise<AcknowledgementResult> } = createMcpExecutionClient(config.execution), delivery: { requireHostAcknowledgement?: boolean } = {}) {
  const snapshot: GatewayConfig = JSON.parse(JSON.stringify(config));
  const directory = resolve(snapshot.journalDir);
  mkdirSync(directory, { recursive: true, mode: 0o700 }); privatePath(directory, true);
  if (readdirSync(directory).includes("recovery.lock")) throw new Error("operator recovery is active");
  const lockPath = join(directory, "gateway.lock");
  const lock = openSync(lockPath, constants.O_CREAT | constants.O_EXCL | constants.O_WRONLY, 0o600);
  writeFileSync(lock, JSON.stringify({ pid: process.pid, hostname: hostname(), sessionId: snapshot.sessionId }));
  fsyncSync(lock); closeSync(lock); syncDirectory(directory);
  const binding = gatewayBinding(snapshot); const bindingPath = join(directory, "authority.binding");
  if (readdirSync(directory).includes("authority.binding")) {
    privatePath(bindingPath, false);
    if (readFileSync(bindingPath, "utf8") !== binding) throw new Error("journal belongs to a different authority or configuration");
  } else {
    if (readdirSync(directory).some(name => name.endsWith(".json"))) throw new Error("operation journal is missing its authority binding");
    const fd = openSync(bindingPath, constants.O_CREAT | constants.O_EXCL | constants.O_WRONLY, 0o600);
    try { writeFileSync(fd, binding); fsyncSync(fd); } finally { closeSync(fd); } syncDirectory(directory);
  }
  const records = new Map<string, StoredOperation>();
  for (const filename of readdirSync(directory).filter(name => name.endsWith(".json"))) {
    const path = join(directory, filename); privatePath(path, false);
    const record = JSON.parse(readFileSync(path, "utf8")) as StoredOperation;
    if (!record.requestId || !record.digest || !["awaiting_approval", "pending", "not_dispatched", "unknown", "denied", "completed"].includes(record.state)) throw new Error("invalid operation journal");
    if (record.state !== "pending" && (!record.outcome || record.outcome.state !== record.state || record.outcome.requestId !== record.requestId)) throw new Error("inconsistent operation journal result");
    if (record.state === "awaiting_approval" && (!record.proposal || record.proposal.request_id !== record.requestId)) throw new Error("missing approval proposal");
    if (record.state === "completed" && (!record.request || !record.outcome
      || record.requestId !== record.request.requestId
      || record.digest !== operationKey(canonicalizeJson({name:record.request.tool,args:record.request.arguments}))
      || !verifyCompletedOutcome(record.outcome as ExecutionOutcome,snapshot.execution,record.request))) {
      throw new Error("cached completion does not bind a trusted original request and result");
    }
    if (records.has(record.requestId)) throw new Error("duplicate operation journal identity");
    records.set(record.requestId, record);
  }
  let closed = false; let busy = false;
  const tools = new Map(snapshot.tools.map(tool => [tool.name, tool]));
  const fenced = () => [...records.values()].some(record => record.state !== "not_dispatched" && !(record.state === "completed" && record.acknowledged === true && (!delivery.requireHostAcknowledgement || record.hostDeliveryConfirmed === true)));
  function persist(record: StoredOperation) {
    const key = operationKey(record.requestId); const path = join(directory, `${key}.json`); const temp = join(directory, `${key}.${process.pid}.tmp`);
    const fd = openSync(temp, constants.O_CREAT | constants.O_EXCL | constants.O_WRONLY, 0o600);
    try { writeFileSync(fd, JSON.stringify(record)); fsyncSync(fd); } finally { closeSync(fd); }
    renameSync(temp, path); syncDirectory(directory); records.set(record.requestId, record);
  }
  async function confirmDelivery(record: StoredOperation): Promise<GatewayOutcome> {
    const outcome = record.outcome!;
    if (outcome.state === "completed" && !record.acknowledged && executor.acknowledge && (!delivery.requireHostAcknowledgement || record.hostDeliveryConfirmed === true)) {
      const acknowledgement = await executor.acknowledge(outcome);
      if (acknowledgement.acknowledged) persist({...record,acknowledged:true});
    }
    return outcome;
  }
  async function dispatch(record: StoredOperation, request: ExecutionRequest, signal?: AbortSignal): Promise<GatewayOutcome> {
    busy = true;
    try {
      persist({...record,state:"pending",outcome:undefined,request});
      let outcome = await executor.execute(request, signal ? {signal} : {});
      if (outcome.state === "completed" && !verifyCompletedOutcome(outcome,snapshot.execution,request)) {
        outcome = {state:"unknown",evidence:"unverified",requestId:request.requestId,reason:"completed result failed durable request verification"};
      }
      const completed = {...record,state:outcome.state,outcome,acknowledged:false,hostDeliveryRequired:delivery.requireHostAcknowledgement===true,request};
      persist(completed); // The verified result is durable before the acknowledgement.
      return await confirmDelivery(completed);
    } catch { return {state:"unknown",evidence:"unverified",requestId:record.requestId,reason:"dispatch or persistence interrupted; no automatic retry"}; }
    finally { busy = false; }
  }
  const resumeTool: Tool = {name:"chio_resume",description:"Explicitly resume one exact operator-approved proposal, retaining its original request identity. Never retries an unknown effect.",inputSchema:{type:"object",properties:{requestId:{type:"string"},tool:{type:"string"},arguments:{type:"object"}},required:["requestId","tool","arguments"],additionalProperties:false}};
  return {
    /** Trusted launcher observed this exact result in native host history. */
    async acknowledgeReceivedOutcome(input: unknown): Promise<AcknowledgementResult> {
      try {
        const outcome = input as ExecutionOutcome;
        const record = records.get(outcome?.requestId);
        if (!record?.request || !verifyCompletedOutcome(outcome,snapshot.execution,record.request)) throw new Error("host result differs from retained request or signed output");
        return await this.acknowledgeDelivery(outcome.delivery);
      } catch { return {acknowledged:false,reason:"host-received result is not the exact verified terminal outcome"}; }
    },
    /** Proof of receiving the exact retained result. This never dispatches a tool. */
    async acknowledgeDelivery(proof: unknown): Promise<AcknowledgementResult> {
      try {
        const requestId = (proof as {requestId?: unknown})?.requestId;
        if (closed || typeof requestId !== "string") throw new Error("invalid delivery proof");
        const record = records.get(requestId);
        if (!record || record.state !== "completed" || !record.request || record.outcome?.state !== "completed"
          || !verifyCompletedOutcome(record.outcome,snapshot.execution,record.request)
          || canonicalizeJson(proof) !== canonicalizeJson(record.outcome.delivery)) throw new Error("delivery proof does not match retained outcome");
        const confirmed = {...record,hostDeliveryConfirmed:true};
        persist(confirmed); // Receiving host proof is durable before kernel acknowledgement.
        await confirmDelivery(confirmed);
        if (!records.get(requestId)?.acknowledged) throw new Error("kernel acknowledgement not confirmed");
        return {acknowledged:true,requestId,receiptId:record.outcome.receipt!.id};
      } catch { return {acknowledged:false,reason:"host delivery proof or kernel acknowledgement is unresolved; preserve the operation"}; }
    },
    listTools: () => snapshot.approval ? [...snapshot.tools,resumeTool] : snapshot.tools,
    async call(id: string | number, name: string, args: Record<string, unknown>, signal?: AbortSignal): Promise<GatewayOutcome> {
      const requestId = name === "chio_resume" ? String(args.requestId ?? "") : `${snapshot.sessionId}:${createHash("sha256").update(canonicalizeJson({ id })).digest("hex")}`;
      const refused = (reason: string): ExecutionOutcome => ({state:"not_dispatched",evidence:"unverified",requestId,reason});
      if (closed || busy) return refused("gateway closed or another operation in flight");
      const resuming = name === "chio_resume";
      if (resuming && !snapshot.approval) return refused("explicit approval resumption is not configured");
      const tool = resuming ? String(args.tool ?? "") : name;
      const parameters = resuming ? args.arguments as Record<string, unknown> : args;
      if (!tools.has(tool) || !parameters || typeof parameters !== "object" || Array.isArray(parameters)) return refused("tool or arguments are outside the operator allowlist");
      let digest: string; try { digest = operationKey(canonicalizeJson({name:tool,args:parameters})); } catch { return refused("invalid canonical arguments"); }
      const prior = records.get(requestId);
      if (prior) {
        if (prior.digest !== digest) return refused("operation identity conflicts with retained request");
        if (prior.state !== "awaiting_approval") return prior.outcome ? confirmDelivery(prior) : {state:"unknown",evidence:"unverified",requestId,reason:"interrupted dispatch requires resource reconciliation"};
        if (!resuming) return prior.outcome!;
        if (signal?.aborted) return refused("cancelled before approval resumption");
        let approved;
        try {
          const path = gatewayApprovalPath(snapshot, requestId); privatePath(path,false);
          if (lstatSync(path).size > 1024*1024) throw new Error("oversized artifact");
          const artifact = JSON.parse(readFileSync(path,"utf8"));
          approved = verifyApprovalToolCall(artifact.toolCallParams,{...snapshot.execution,sessionId:snapshot.execution.sessionId,tool,arguments:parameters,requestId});
        } catch { /* No artifact can authorize this proposal. */ }
        if (!approved) return {...prior.outcome!,reason:"approval missing, expired, substituted or untrusted; proposal remains undispatched"};
        if (approved.decision === "denied") { const outcome = refused("operator denied the proposal before dispatch"); persist({...prior,state:"not_dispatched",outcome}); return outcome; }
        return dispatch(prior,{tool,arguments:parameters,requestId,approval:{chioGovernedIntent:approved.params._meta.chioGovernedIntent,chioApprovalToken:approved.params._meta.chioApprovalToken}},signal);
      }
      if (resuming) return refused("no retained proposal matches this request");
      if (fenced()) return refused("an unresolved operation fences this gateway; operator reconciliation required");
      if (signal?.aborted) return refused("cancelled before admission");
      if (snapshot.approval?.requiredTools.includes(tool)) {
        const proposal: GatewayProposal = {session_id:snapshot.execution.sessionId,capability_id:snapshot.execution.capabilityId,request_id:requestId,tool_name:tool,arguments:JSON.parse(canonicalizeJson(parameters)),purpose:snapshot.approval.purpose,ttl_seconds:snapshot.approval.ttlSeconds};
        const outcome: GatewayOutcome = {state:"awaiting_approval",evidence:"unverified",requestId,proposal,reason:"proposal retained without dispatch; operator decision and explicit chio_resume are required"};
        persist({requestId,digest,state:"awaiting_approval",proposal,outcome}); return outcome;
      }
      return dispatch({requestId,digest,state:"pending"},{tool,arguments:parameters,requestId},signal);
    },
    close() { if (!closed) {closed=true;unlinkSync(lockPath);syncDirectory(directory);} },
  };
}

/** A completed invocation can still return a tool-level error. Preserve both states. */
export function gatewayToolResult(outcome: GatewayOutcome) {
  const toolError = "result" in outcome && outcome.result !== null && typeof outcome.result === "object"
    && (outcome.result as { isError?: unknown }).isError === true;
  return {
    isError: outcome.state !== "completed" || toolError,
    content: [{ type: "text", text: JSON.stringify(outcome) }],
  };
}

async function main() {
  if (process.argv.length !== 3) throw new Error("usage: chio-mcp-gateway /absolute/operator-config.json");
  const configPath = process.argv[2]!;
  if (resolve(configPath) !== configPath) throw new Error("config path must be absolute");
  const gateway = createGateway(readGatewayConfig(configPath));
  const reader = createInterface({ input: process.stdin, crlfDelay: Infinity });
  const active = new Map<string, AbortController>();
  let initialized = false;
  let queued = Promise.resolve();
  const send = (value: unknown) => process.stdout.write(JSON.stringify(value) + "\n");
  reader.on("line", line => {
    if (Buffer.byteLength(line) > 1024 * 1024) { send({ jsonrpc: "2.0", id: null, error: { code: -32600, message: "request exceeds size limit" } }); return; }
    let message: any;
    try { message = JSON.parse(line); } catch { send({ jsonrpc: "2.0", id: null, error: { code: -32700, message: "invalid JSON" } }); return; }
    if (message?.method === "notifications/cancelled") { active.get(JSON.stringify(message.params?.requestId))?.abort(); return; }
    if (message?.method === "notifications/initialized") { initialized = true; return; }
    if (message?.id === undefined) return;
    // Register queued calls immediately so cancellation before queue dispatch is retained.
    const key = JSON.stringify(message.id);
    const controller = message.method === "tools/call" ? new AbortController() : undefined;
    if (controller) {
      if (active.has(key)) { send({ jsonrpc: "2.0", id: message.id, error: { code: -32600, message: "request ID is already in flight" } }); return; }
      active.set(key, controller);
    }
    queued = queued.then(async () => {
      const error = (code: number, text: string) => send({ jsonrpc: "2.0", id: message.id, error: { code, message: text } });
      const result = (value: unknown) => send({ jsonrpc: "2.0", id: message.id, result: value });
      if (message.jsonrpc !== "2.0" || !["string", "number"].includes(typeof message.id)) { error(-32600, "invalid request"); return; }
      if (message.method === "initialize") { result({ protocolVersion: "2025-11-25", capabilities: { tools: {} }, serverInfo: { name: "chio-mcp-gateway", version: "0.3.0" } }); return; }
      if (message.method === "ping") { result({}); return; }
      if (!initialized) { error(-32600, "session not initialized"); return; }
      if (message.method === "tools/list") { result({ tools: gateway.listTools() }); return; }
      if (message.method !== "tools/call") { error(-32601, "unsupported method"); return; }
      const args = message.params?.arguments;
      if (!args || typeof args !== "object" || Array.isArray(args)) { error(-32602, "tool arguments must be an object"); return; }
      const outcome = await gateway.call(message.id, message.params.name, args, controller?.signal);
      result(gatewayToolResult(outcome));
    }).catch(() => { send({ jsonrpc: "2.0", id: message.id, error: { code: -32603, message: "gateway failed; no automatic retry" } }); })
      .finally(() => { if (controller) active.delete(key); });
  });
  await new Promise<void>(done => reader.on("close", done));
  await queued;
  gateway.close();
}
// Node resolves the module location physically unless preserve-symlinks-main is set.
// Canonicalize both sides so npm bin links and symlinked install parents also start.
function isGatewayEntrypoint(): boolean {
  const entry = process.argv[1];
  // In stdin/eval mode argv[1] is absent, '-' or a user argument, not a script.
  // Even an eval argument naming this file must not start the gateway on import.
  const evaluatesCode = process.execArgv.some(arg => /^--(?:eval|print)(?:=|$)|^-[ep]/.test(arg));
  if (!entry || entry === "-" || evaluatesCode) return false;
  let canonicalEntry: string;
  try { canonicalEntry = realpathSync(entry); }
  catch (error) {
    const code = (error as NodeJS.ErrnoException).code;
    if (code === "ENOENT" || code === "ENOTDIR") return false;
    throw error;
  }
  return canonicalEntry === realpathSync(fileURLToPath(import.meta.url));
}
if (isGatewayEntrypoint()) {
  main().catch(() => { process.stderr.write("Chio gateway startup or persistence failed; protected tools unavailable.\n"); process.exitCode = 1; });
}
