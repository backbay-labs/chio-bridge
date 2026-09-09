#!/usr/bin/env node
import { createHash } from "node:crypto";
import { constants, closeSync, fsyncSync, lstatSync, mkdirSync, openSync, readFileSync, readdirSync, realpathSync, renameSync, unlinkSync, writeFileSync } from "node:fs";
import { resolve, join } from "node:path";
import { createInterface } from "node:readline";
import { fileURLToPath } from "node:url";
import { canonicalizeJson } from "@chio-protocol/sdk/invariants";
import { createMcpExecutionClient, type ExecutionOutcome, type McpExecutionOptions } from "./execution.js";

interface Tool { name: string; description?: string; inputSchema: Record<string, unknown> }
export interface GatewayConfig {
  execution: McpExecutionOptions & { sessionId: string };
  sessionId: string;
  journalDir: string;
  tools: Tool[];
}
interface StoredOperation {
  requestId: string;
  digest: string;
  state: "pending" | ExecutionOutcome["state"];
  outcome?: ExecutionOutcome;
}
function syncDirectory(path: string) {
  const fd = openSync(path, constants.O_RDONLY);
  try { fsyncSync(fd); } finally { closeSync(fd); }
}
function privatePath(path: string, directory: boolean) {
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
  return config;
}
/** The journal is a conservative dispatch interlock, not a second resource ledger.
 * It never resolves an unknown outcome or replays it under a fresh identity.
 */
export function createGateway(config: GatewayConfig, executor = createMcpExecutionClient(config.execution)) {
  const snapshot: GatewayConfig = JSON.parse(JSON.stringify(config));
  const directory = resolve(snapshot.journalDir);
  mkdirSync(directory, { recursive: true, mode: 0o700 });
  privatePath(directory, true);
  const lockPath = join(directory, "gateway.lock");
  const lock = openSync(lockPath, constants.O_CREAT | constants.O_EXCL | constants.O_WRONLY, 0o600);
  writeFileSync(lock, JSON.stringify({ pid: process.pid, sessionId: snapshot.sessionId }));
  fsyncSync(lock); closeSync(lock); syncDirectory(directory);
  const binding = canonicalizeJson({ sessionId: snapshot.sessionId, kernelSessionId: snapshot.execution.sessionId,
    endpoint: snapshot.execution.endpoint, subjectKey: snapshot.execution.subjectKey,
    capabilityId: snapshot.execution.capabilityId, serverId: snapshot.execution.serverId,
    trustedSigners: snapshot.execution.trustedSigners, tools: snapshot.tools });
  const bindingPath = join(directory, "authority.binding");
  if (readdirSync(directory).includes("authority.binding")) {
    privatePath(bindingPath, false);
    if (readFileSync(bindingPath, "utf8") !== binding) throw new Error("journal belongs to a different authority or configuration");
  } else {
    if (readdirSync(directory).some(name => name.endsWith(".json"))) throw new Error("operation journal is missing its authority binding");
    const fd = openSync(bindingPath, constants.O_CREAT | constants.O_EXCL | constants.O_WRONLY, 0o600);
    try { writeFileSync(fd, binding); fsyncSync(fd); } finally { closeSync(fd); }
    syncDirectory(directory);
  }
  const records = new Map<string, StoredOperation>();
  let fenced = false;
  try {
    for (const filename of readdirSync(directory).filter(name => name.endsWith(".json"))) {
      const path = join(directory, filename); privatePath(path, false);
      const record = JSON.parse(readFileSync(path, "utf8")) as StoredOperation;
      if (!record.requestId || !record.digest || !["pending", "not_dispatched", "unknown", "denied", "completed"].includes(record.state)) throw new Error("invalid operation journal");
      if (record.state !== "pending" && (!record.outcome || record.outcome.state !== record.state || record.outcome.requestId !== record.requestId)) throw new Error("inconsistent operation journal result");
      if (records.has(record.requestId)) throw new Error("duplicate operation journal identity");
      records.set(record.requestId, record);
      if (!["not_dispatched", "completed"].includes(record.state)) fenced = true;
    }
  } catch (error) {
    // Preserve the lock on corrupt or incomplete recovery state for operator review.
    throw error;
  }
  let closed = false;
  let busy = false;
  const tools = new Map(snapshot.tools.map(tool => [tool.name, tool]));
  function persist(record: StoredOperation) {
    const key = createHash("sha256").update(record.requestId).digest("hex");
    const path = join(directory, `${key}.json`);
    const temp = join(directory, `${key}.${process.pid}.tmp`);
    const fd = openSync(temp, constants.O_CREAT | constants.O_EXCL | constants.O_WRONLY, 0o600);
    try { writeFileSync(fd, JSON.stringify(record)); fsyncSync(fd); } finally { closeSync(fd); }
    renameSync(temp, path); syncDirectory(directory); records.set(record.requestId, record);
  }
  return {
    listTools: () => snapshot.tools,
    async call(id: string | number, name: string, args: Record<string, unknown>, signal?: AbortSignal): Promise<ExecutionOutcome> {
      const requestId = `${snapshot.sessionId}:${createHash("sha256").update(canonicalizeJson({ id })).digest("hex")}`;
      const refused = (reason: string): ExecutionOutcome => ({ state: "not_dispatched", evidence: "unverified", requestId, reason });
      if (closed || busy) return refused("gateway closed or another operation in flight");
      if (!tools.has(name)) return refused("tool is outside the operator allowlist");
      let digest: string;
      try { digest = createHash("sha256").update(canonicalizeJson({ name, args })).digest("hex"); }
      catch { return refused("invalid canonical arguments"); }
      const prior = records.get(requestId);
      if (prior) {
        if (prior.digest !== digest) return refused("operation identity conflicts with retained request");
        return prior.outcome ?? { state: "unknown", evidence: "unverified", requestId, reason: "interrupted dispatch requires resource reconciliation" };
      }
      if (fenced) return refused("an unresolved operation fences this gateway; operator reconciliation required");
      if (signal?.aborted) return refused("cancelled before admission");
      busy = true;
      try {
        persist({ requestId, digest, state: "pending" });
        fenced = true;
        const outcome = await executor.execute({ tool: name, arguments: args, requestId }, signal ? { signal } : {});
        persist({ requestId, digest, state: outcome.state, outcome });
        fenced = !["not_dispatched", "completed"].includes(outcome.state);
        return outcome;
      } catch {
        fenced = true;
        return { state: "unknown", evidence: "unverified", requestId, reason: "dispatch or evidence persistence interrupted; no automatic retry" };
      } finally { busy = false; }
    },
    close() { if (!closed) { closed = true; unlinkSync(lockPath); syncDirectory(directory); } },
  };
}

/** A completed invocation can still return a tool-level error. Preserve both states. */
export function gatewayToolResult(outcome: ExecutionOutcome) {
  const toolError = outcome.result !== null && typeof outcome.result === "object"
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
if (process.argv[1] && realpathSync(process.argv[1]) === realpathSync(fileURLToPath(import.meta.url))) {
  main().catch(() => { process.stderr.write("Chio gateway startup or persistence failed; protected tools unavailable.\n"); process.exitCode = 1; });
}
