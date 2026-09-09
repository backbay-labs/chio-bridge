#!/usr/bin/env node
import { closeSync, fsyncSync, openSync, readFileSync, writeFileSync, lstatSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { ChioClient } from "@chio-protocol/sdk";

async function main() {
  const [requestPath, outputPath] = process.argv.slice(2);
  if (!requestPath || !outputPath || process.argv.length !== 4 || resolve(outputPath) !== outputPath) throw new Error("usage: chio-prepare-gateway operator-request.json /absolute/new-gateway-config.json");
  const stat = lstatSync(requestPath);
  if (!stat.isFile() || stat.isSymbolicLink() || (stat.mode & 0o077) !== 0 || stat.size > 1024 * 1024) throw new Error("operator request must be a private regular file");
  const input = JSON.parse(readFileSync(requestPath, "utf8"));
  const { endpoint, bearerToken, trustedSigners, serverId, journalDir, sessionId, allowedTools } = input;
  const url = new URL(endpoint);
  if (url.protocol !== "https:" && !(url.protocol === "http:" && ["127.0.0.1", "localhost", "[::1]"].includes(url.hostname))) throw new Error("authenticated endpoint requires HTTPS or loopback HTTP");
  if (!bearerToken || !serverId || !journalDir || !sessionId || !Array.isArray(allowedTools) || !allowedTools.length || !Array.isArray(trustedSigners) || !trustedSigners.length || trustedSigners.some(key => !/^[a-f0-9]{64}$/i.test(key))) throw new Error("explicit authority, signer, journal and tool allowlist required");
  const fetchImpl: typeof fetch = (url, init) => fetch(url, { ...init, signal: AbortSignal.timeout(30_000), redirect: "error" });
  const session = await ChioClient.withStaticBearer(endpoint, bearerToken, fetchImpl).initialize({ clientInfo: { name: "chio-prepare-gateway", version: "0.3.0" } });
  let retained = false;
  try {
    const contextResponse = await session.requestResult("chio/execution-context");
    const context: any = "result" in contextResponse ? contextResponse.result : null;
    if (context?.schema !== "chio.mcp.execution-context.v1" || context.evidenceVersion !== "1" || !/^[a-f0-9]{64}$/i.test(context.subjectKey) || !Array.isArray(context.capabilityIds) || context.capabilityIds.length !== 1) throw new Error("kernel requires supported evidence and exactly one pinned session capability");
    const listing = await session.listTools() as { tools?: any[]; nextCursor?: unknown };
    if (!Array.isArray(listing?.tools) || listing.nextCursor) throw new Error("tool inventory is missing or paginated; prepare an explicitly bounded server");
    const tools = allowedTools.map((name: string) => {
      const tool = listing.tools!.find(tool => tool.name === name);
      if (!tool?.inputSchema || !/^[a-zA-Z0-9_.-]{1,128}$/.test(name)) throw new Error("operator tool not found in kernel inventory");
      return { name, description: tool.description, inputSchema: tool.inputSchema };
    });
    const config = { execution: { endpoint, bearerToken, trustedSigners, serverId, subjectKey: context.subjectKey, capabilityId: context.capabilityIds[0], sessionId: session.sessionId }, sessionId, journalDir, tools };
    const fd = openSync(outputPath, "wx", 0o600);
    try { writeFileSync(fd, JSON.stringify(config, null, 2) + "\n"); fsyncSync(fd); } finally { closeSync(fd); }
    const dir = openSync(dirname(outputPath), "r"); try { fsyncSync(dir); } finally { closeSync(dir); }
    retained = true;
    process.stdout.write("Prepared retained kernel session and private gateway config; no tool was executed.\n");
  } finally { if (!retained) await session.close(); }
}
main().catch(() => { process.stderr.write("Gateway preparation failed; config must not be used and no protected tool was dispatched.\n"); process.exitCode = 1; });
