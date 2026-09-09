#!/usr/bin/env node
import { closeSync, fsyncSync, openSync, readFileSync, writeFileSync, lstatSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { ChioClient, ChioSession } from "@chio-protocol/sdk";

function sameNames(actual: unknown, expected: string[]): boolean {
  return Array.isArray(actual) && actual.length === expected.length
    && actual.every(value => typeof value === "string")
    && [...actual].sort().every((value, index) => value === [...expected].sort()[index]);
}

async function main() {
  const [requestPath, outputPath] = process.argv.slice(2);
  if (!requestPath || !outputPath || process.argv.length !== 4 || resolve(outputPath) !== outputPath) throw new Error("usage: chio-prepare-gateway operator-request.json /absolute/new-gateway-config.json");
  const stat = lstatSync(requestPath);
  if (!stat.isFile() || stat.isSymbolicLink() || (stat.mode & 0o077) !== 0 || stat.size > 1024 * 1024) throw new Error("operator request must be a private regular file");
  const input = JSON.parse(readFileSync(requestPath, "utf8"));
  const { endpoint: requestedEndpoint, bearerToken, adminToken, credentialTtlSeconds, trustedSigners, serverId, journalDir, sessionId, allowedTools } = input;
  const url = new URL(requestedEndpoint);
  if (url.protocol !== "https:" && !(url.protocol === "http:" && ["127.0.0.1", "localhost", "[::1]"].includes(url.hostname))) throw new Error("authenticated endpoint requires HTTPS or loopback HTTP");
  if (url.username || url.password || url.search || url.hash || url.pathname !== "/") throw new Error("endpoint must be a bare origin without credentials, query, fragment or MCP path");
  const endpoint = url.origin;
  if (typeof bearerToken !== "string" || !bearerToken || typeof adminToken !== "string" || !adminToken || adminToken === bearerToken
    || !Number.isSafeInteger(credentialTtlSeconds) || credentialTtlSeconds < 1 || credentialTtlSeconds > 3600
    || typeof serverId !== "string" || !serverId || typeof journalDir !== "string" || resolve(journalDir) !== journalDir || typeof sessionId !== "string" || !sessionId
    || !Array.isArray(allowedTools) || !allowedTools.length || new Set(allowedTools).size !== allowedTools.length
    || allowedTools.some(name => typeof name !== "string" || !/^[a-zA-Z0-9_.-]{1,128}$/.test(name))
    || !Array.isArray(trustedSigners) || !trustedSigners.length || trustedSigners.some(key => typeof key !== "string" || !/^[a-f0-9]{64}$/i.test(key))) {
    throw new Error("distinct operator and admin credentials, bounded credential TTL, explicit authority, signer, journal and tool allowlist required");
  }
  const fetchImpl: typeof fetch = (url, init) => fetch(url, { ...init, signal: AbortSignal.timeout(30_000), redirect: "error" });
  const session = await ChioClient.withStaticBearer(endpoint, bearerToken, fetchImpl).initialize({ clientInfo: { name: "chio-prepare-gateway", version: "0.3.0" } });
  let retained = false;
  try {
    const contextResponse = await session.requestResult("chio/execution-context");
    const context: any = "result" in contextResponse ? contextResponse.result : null;
    if (context?.schema !== "chio.mcp.execution-context.v1" || context.evidenceVersion !== "1" || context.serverId !== serverId
      || typeof context.subjectKey !== "string" || !/^[a-f0-9]{64}$/i.test(context.subjectKey)
      || !Array.isArray(context.capabilityIds) || context.capabilityIds.length !== 1 || typeof context.capabilityIds[0] !== "string" || !context.capabilityIds[0]) {
      throw new Error("kernel requires supported evidence, matching server and exactly one pinned session capability");
    }
    const listing = await session.listTools() as { tools?: any[]; nextCursor?: unknown };
    if (!Array.isArray(listing?.tools) || listing.nextCursor) throw new Error("tool inventory is missing or paginated; prepare an explicitly bounded server");
    const tools = allowedTools.map((name: string) => {
      const tool = listing.tools!.find(tool => tool.name === name);
      if (!tool?.inputSchema) throw new Error("operator tool not found in kernel inventory");
      return { name, description: tool.description, inputSchema: tool.inputSchema };
    });
    const issuedAfter = Math.floor(Date.now() / 1000);
    const exchange = await fetchImpl(new URL(`/admin/sessions/${encodeURIComponent(session.sessionId)}/credential`, endpoint), {
      method: "POST", headers: { Authorization: `Bearer ${adminToken}`, "Content-Type": "application/json" },
      body: JSON.stringify({ ttlSeconds: credentialTtlSeconds, allowedTools }),
    });
    if (!exchange.ok) throw new Error("kernel requires session-credential exchange support");
    const text = await exchange.text();
    if (text.length > 1024 * 1024) throw new Error("credential response exceeds limit");
    const credential = JSON.parse(text);
    const now = Math.floor(Date.now() / 1000);
    if (credential?.schema !== "chio.mcp.session-credential.v1" || credential.sessionId !== session.sessionId
      || credential.subjectKey !== context.subjectKey || !sameNames(credential.capabilityIds, context.capabilityIds)
      || credential.serverId !== serverId || credential.endpointPath !== "/mcp" || !sameNames(credential.allowedTools, allowedTools)
      || typeof credential.bearerToken !== "string" || !credential.bearerToken || [bearerToken, adminToken].includes(credential.bearerToken)
      || !Number.isSafeInteger(credential.issuedAt) || credential.issuedAt < issuedAfter - 5 || credential.issuedAt > now + 5
      || !Number.isSafeInteger(credential.expiresAt) || credential.expiresAt <= now || credential.expiresAt > credential.issuedAt + credentialTtlSeconds) {
      throw new Error("credential does not match the pinned session, scope and bounded lifetime");
    }
    // The exchange is authenticated transport, not a client-verified signed response.
    // Reopen only the existing session with the delegated bearer; never initialize.
    const delegated = new ChioSession({ baseUrl: endpoint, authToken: credential.bearerToken, sessionId: session.sessionId, protocolVersion: "2025-11-25", fetchImpl });
    const delegatedResponse = await delegated.requestResult("chio/execution-context");
    const delegatedContext: any = "result" in delegatedResponse ? delegatedResponse.result : null;
    const binding = delegatedContext?.sessionCredential;
    if (delegatedContext?.schema !== context.schema || delegatedContext.evidenceVersion !== "1"
      || delegatedContext.subjectKey !== context.subjectKey || delegatedContext.serverId !== serverId || !sameNames(delegatedContext.capabilityIds, context.capabilityIds)
      || binding?.schema !== credential.schema || binding.sessionId !== credential.sessionId || binding.subjectKey !== credential.subjectKey
      || binding.serverId !== serverId || binding.endpointPath !== "/mcp" || !sameNames(binding.capabilityIds, credential.capabilityIds)
      || !sameNames(binding.allowedTools, allowedTools) || binding.issuedAt !== credential.issuedAt || binding.expiresAt !== credential.expiresAt) {
      throw new Error("delegated credential context does not confirm the issued scope");
    }
    const sessionCredential = { schema: credential.schema, sessionId: credential.sessionId, subjectKey: credential.subjectKey,
      capabilityIds: credential.capabilityIds, serverId, endpointPath: credential.endpointPath,
      allowedTools: credential.allowedTools, issuedAt: credential.issuedAt, expiresAt: credential.expiresAt };
    const config = { execution: { endpoint, bearerToken: credential.bearerToken, trustedSigners, serverId, subjectKey: context.subjectKey, capabilityId: context.capabilityIds[0], sessionId: session.sessionId }, sessionId, journalDir, tools, sessionCredential };
    const fd = openSync(outputPath, "wx", 0o600);
    try { writeFileSync(fd, JSON.stringify(config, null, 2) + "\n"); fsyncSync(fd); } finally { closeSync(fd); }
    const dir = openSync(dirname(outputPath), "r"); try { fsyncSync(dir); } finally { closeSync(dir); }
    retained = true;
    process.stdout.write("Prepared retained kernel session and private config with a scoped session credential; no tool was executed.\n");
  } finally { if (!retained) await session.close(); }
}
main().catch(() => { process.stderr.write("Gateway preparation failed; config must not be used and no protected tool was dispatched.\n"); process.exitCode = 1; });
