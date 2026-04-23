import { spawn, type ChildProcess } from "node:child_process";
import { createHash, randomBytes } from "node:crypto";
import type { ChioCli } from "./client/cli.js";
import type { DaemonClient } from "./client/daemon.js";
import { ChioBridgeError, NotInitializedError } from "./errors.js";
import { DEFAULT_MCP_EDGE_URL, type McpServerInfo, type WrappedMcp } from "./types.js";

interface AdminSessionsResponse {
  sessions?: Array<{
    id?: string;
    server_id?: string;
    tools?: string[];
    status?: string;
    transport?: string;
  }>;
}

export async function discoverMcpServers(
  daemon: DaemonClient | undefined,
): Promise<McpServerInfo[]> {
  if (!daemon) {
    throw new NotInitializedError(
      "discoverMcpServers() requires daemon mode (hits /admin/sessions on the MCP edge)",
    );
  }
  const url = `${daemon.mcpEdgeUrl}/admin/sessions`;
  let response: Response;
  try {
    response = await daemon.fetchImpl(url, {
      method: "GET",
      headers: { Authorization: `Bearer ${daemon.token}` },
    });
  } catch (cause) {
    throw new ChioBridgeError(
      "mcp_admin_unreachable",
      `MCP edge admin endpoint unreachable at ${url}: ${(cause as Error).message}`,
      cause,
    );
  }
  if (!response.ok) {
    throw new ChioBridgeError(
      "mcp_admin_failed",
      `MCP edge /admin/sessions returned HTTP ${response.status}`,
    );
  }
  const data = (await response.json()) as AdminSessionsResponse;
  const sessions = data.sessions ?? [];
  return sessions.map((s) => {
    const info: McpServerInfo = {
      id: s.server_id ?? s.id ?? "",
    };
    if (s.tools) info.tools = s.tools;
    if (s.status) info.status = s.status;
    if (s.transport === "http" || s.transport === "stdio") info.transport = s.transport;
    return info;
  });
}

export interface WrapMcpOptions {
  /**
   * Forwarded to `chio mcp serve-http --listen`. Defaults to
   * `127.0.0.1:0` (kernel auto-assigns a port). The resolved address
   * is recovered from the real readiness banner the edge emits on
   * stderr (`remote MCP edge listening on http://127.0.0.1:PORT/mcp`).
   */
  listen?: string;
  /**
   * Forwarded to `chio mcp serve-http --policy`. Required by the real
   * CLI usage signature. If both this field and the bridge's
   * fromDaemon/fromCli-time default policy are missing, `wrapMcp`
   * throws before spawning the subprocess.
   */
  policy?: string;
  /**
   * Forwarded to `chio mcp serve-http --auth-token`. When omitted,
   * the bridge mints a fresh 32-byte random hex token so remote
   * sessions can still authenticate. The returned token mirrors
   * whichever value was used.
   */
  authToken?: string;
  /**
   * Forwarded to `chio mcp serve-http --server-id`. When omitted, the
   * bridge derives a deterministic id from `sha256(cmd[0]).slice(0, 16)`
   * so repeat wraps of the same binary produce the same id — callers
   * then use `serverId` in downstream `check({ serverId })` calls for
   * receipt attribution.
   */
  serverId?: string;
  /**
   * Extra argv appended to the wrap invocation before `-- <cmd...>`.
   * Callers only need this for flags the bridge hasn't first-classed
   * yet (e.g. `--server-name`, `--receipt-db`).
   */
  extraArgs?: string[];
  env?: NodeJS.ProcessEnv;
  readinessTimeoutMs?: number;
}

export async function wrapMcp(
  cli: ChioCli,
  cmd: string[],
  options: WrapMcpOptions = {},
): Promise<WrappedMcp> {
  if (cmd.length === 0) {
    throw new ChioBridgeError("invalid_arg", "wrapMcp requires at least one command arg");
  }
  const policy = options.policy;
  if (!policy) {
    throw new ChioBridgeError(
      "invalid_arg",
      "wrapMcp requires options.policy (chio mcp serve-http --policy is required)",
    );
  }
  const listen = options.listen ?? "127.0.0.1:0";
  const authToken = options.authToken ?? randomBytes(32).toString("hex");
  const serverId = options.serverId ?? deriveServerId(cmd[0]!);

  const args = [
    "mcp",
    "serve-http",
    "--listen",
    listen,
    "--policy",
    policy,
    "--server-id",
    serverId,
    "--auth-token",
    authToken,
  ];
  if (options.extraArgs) args.push(...options.extraArgs);
  args.push("--", ...cmd);

  const child: ChildProcess = spawn(cli.binary, args, {
    stdio: ["ignore", "pipe", "pipe"],
    env: options.env ?? process.env,
  });

  const timeoutMs = options.readinessTimeoutMs ?? 10_000;
  let url: string;
  let resolvedListen: string;
  try {
    const ready = await waitForReady(child, timeoutMs);
    url = ready.url;
    resolvedListen = ready.listen;
  } catch (err) {
    // Ensure we don't leak a child if readiness never fires.
    if (child.exitCode === null) child.kill("SIGKILL");
    throw err;
  }

  const stop = async (): Promise<void> => {
    if (child.exitCode !== null) return;
    child.kill("SIGTERM");
    await new Promise<void>((resolve) => {
      const timer = setTimeout(() => {
        child.kill("SIGKILL");
        resolve();
      }, 2000);
      child.once("exit", () => {
        clearTimeout(timer);
        resolve();
      });
    });
  };

  return { url, authToken, serverId, policy, listen: resolvedListen, stop };
}

/**
 * Deterministic server-id derived from the wrapped binary's first
 * argv token. Keeps idempotent re-wraps of the same server stable
 * across restarts so receipts stay correlated.
 */
export function deriveServerId(cmdHead: string): string {
  const h = createHash("sha256").update(cmdHead).digest("hex").slice(0, 16);
  return `chio-wrap-${h}`;
}

/**
 * Parses the real readiness banner emitted by
 * `arc/crates/chio-cli/src/remote_mcp/http_service.rs:246`:
 *
 *   remote MCP edge listening on http://127.0.0.1:PORT/mcp
 *
 * We accept the legacy `bound to <addr>` alias for forward-compat,
 * then extract the `host:port` substring so callers can both read
 * the full MCP endpoint URL and recover the resolved listen address.
 */
async function waitForReady(
  child: ChildProcess,
  timeoutMs: number,
): Promise<{ url: string; listen: string }> {
  return new Promise<{ url: string; listen: string }>((resolve, reject) => {
    let buffer = "";
    let settled = false;
    const timer = setTimeout(() => {
      if (settled) return;
      settled = true;
      detach();
      reject(
        new ChioBridgeError(
          "mcp_wrap_timeout",
          `chio mcp serve-http did not signal readiness within ${timeoutMs}ms: ${buffer.slice(-400)}`,
        ),
      );
    }, timeoutMs);

    const onData = (chunk: Buffer | string) => {
      buffer += typeof chunk === "string" ? chunk : chunk.toString("utf8");
      // Strict: match the real banner emitted by the chio edge.
      //   "remote MCP edge listening on http://<host>:<port><path>"
      const exact = buffer.match(
        /remote MCP edge listening on (https?:\/\/([^\s/]+)(?:\/\S*)?)/i,
      );
      if (exact && !settled) {
        settled = true;
        clearTimeout(timer);
        detach();
        resolve({ url: exact[1]!, listen: exact[2]! });
        return;
      }
      // Forward-compat aliases: some future chio versions may drop the
      // "remote MCP edge" prefix. Accept the bare shape too.
      const loose =
        buffer.match(/listening on (https?:\/\/([^\s/]+)(?:\/\S*)?)/i) ??
        buffer.match(/bound to (?:http:\/\/)?([^\s]+)/i);
      if (loose && !settled) {
        settled = true;
        clearTimeout(timer);
        detach();
        if (loose.length >= 3 && loose[1]!.startsWith("http")) {
          resolve({ url: loose[1]!, listen: loose[2]! });
        } else {
          const hostport = loose[1]!.replace(/^https?:\/\//, "").replace(/\/.*$/, "");
          resolve({
            url: loose[1]!.startsWith("http") ? loose[1]! : `http://${loose[1]!}`,
            listen: hostport,
          });
        }
      }
    };

    // After readiness fires we no longer need to buffer the wrapped
    // edge's stderr/stdout, but we MUST keep draining both streams or
    // the OS pipe buffer (~64KB) fills and the chio subprocess's writes
    // block, which surfaces as ECONNRESET / "edge looks hung" downstream.
    // We therefore detach the banner-match listener, then attach a
    // no-op drain so the streams stay flowing.
    const drain = () => {};
    const detach = () => {
      child.stdout?.off("data", onData);
      child.stderr?.off("data", onData);
      child.stdout?.on("data", drain);
      child.stderr?.on("data", drain);
    };

    child.stdout?.on("data", onData);
    child.stderr?.on("data", onData);

    child.once("exit", (code) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      detach();
      reject(
        new ChioBridgeError(
          "mcp_wrap_exit",
          `chio mcp serve-http exited before readiness (code ${code}): ${buffer.slice(-400)}`,
        ),
      );
    });
  });
}

export { DEFAULT_MCP_EDGE_URL };
