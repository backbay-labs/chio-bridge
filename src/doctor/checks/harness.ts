import { existsSync, readFileSync } from "node:fs";
import { resolve } from "node:path";
import type { CheckResult, CheckSection, RunContext } from "../types.js";
import { findOnPath, run } from "../util.js";

const DEFAULT_HARNESS_DIR =
  "/Users/connor/Medica/backbay/standalone/chio-test-harness";
const TRUST_URL = "http://127.0.0.1:8940";
const MCP_URL = "http://127.0.0.1:8931";

export interface HarnessState {
  dir?: string;
  startedByDoctor: boolean;
  token?: string;
}

/**
 * Runs checks 8-12. Tracks whether we started the harness ourselves so
 * the top-level runner can tear it down at the end.
 */
export async function runHarnessChecks(
  ctx: RunContext,
): Promise<{ section: CheckSection; state: HarnessState }> {
  const results: CheckResult[] = [];
  const state: HarnessState = { startedByDoctor: false };

  // 8. Harness directory discoverable
  const envDir = process.env.CHIO_HARNESS_DIR;
  const fallback = envDir ?? DEFAULT_HARNESS_DIR;
  const start = resolve(fallback, "bin/start.sh");
  if (!existsSync(start)) {
    results.push({
      id: "harness.dir",
      label: "harness dir",
      status: "warn",
      message: `not found at ${fallback}`,
      remediation: "git clone chio-test-harness, or export CHIO_HARNESS_DIR",
    });
    results.push({
      id: "harness.daemon",
      label: "daemon",
      status: "skip",
      message: "harness dir missing",
    });
    // Endpoint and CLI-check are only meaningful with a running daemon.
    results.push({
      id: "daemon.trust-health",
      label: "trust /health",
      status: "skip",
      message: "harness not available",
    });
    results.push({
      id: "daemon.mcp-initialize",
      label: "mcp initialize",
      status: "skip",
      message: "harness not available",
    });
    results.push({
      id: "daemon.chio-check",
      label: "chio check",
      status: "skip",
      message: "harness not available",
    });
    return { section: { title: "Harness", results }, state };
  }

  state.dir = fallback;
  results.push({
    id: "harness.dir",
    label: "harness dir",
    status: "ok",
    message: fallback,
    details: { path: fallback },
  });

  // 9. Harness starts + serves — expensive; --full only
  if (!ctx.opts.full) {
    results.push({
      id: "harness.daemon",
      label: "daemon",
      status: "skip",
      message: "not running (use --full to start + probe)",
      fullOnly: true,
    });
    results.push({
      id: "daemon.trust-health",
      label: "trust /health",
      status: "skip",
      message: "harness not started (use --full)",
      fullOnly: true,
    });
    results.push({
      id: "daemon.mcp-initialize",
      label: "mcp initialize",
      status: "skip",
      message: "harness not started (use --full)",
      fullOnly: true,
    });
    results.push({
      id: "daemon.chio-check",
      label: "chio check",
      status: "skip",
      message: "harness not started (use --full)",
      fullOnly: true,
    });
    return { section: { title: "Harness", results }, state };
  }

  const startRes = await run("bash", [start], {
    timeoutMs: 45_000,
    cwd: fallback,
  });
  if (startRes.spawnError || startRes.exitCode !== 0) {
    results.push({
      id: "harness.daemon",
      label: "daemon",
      status: "warn",
      message: `bin/start.sh failed (exit ${startRes.exitCode})`,
      remediation: "check ports 8940/8931; tail harness/var/*.log",
      details: { stderr: startRes.stderr.slice(-400) },
    });
    results.push({
      id: "daemon.trust-health",
      label: "trust /health",
      status: "skip",
      message: "harness did not start",
    });
    results.push({
      id: "daemon.mcp-initialize",
      label: "mcp initialize",
      status: "skip",
      message: "harness did not start",
    });
    results.push({
      id: "daemon.chio-check",
      label: "chio check",
      status: "skip",
      message: "harness did not start",
    });
    return { section: { title: "Harness", results }, state };
  }
  state.startedByDoctor = !startRes.stderr.includes("already running");
  results.push({
    id: "harness.daemon",
    label: "daemon",
    status: "ok",
    message: state.startedByDoctor ? "started" : "already running",
    details: { trust: TRUST_URL, mcp: MCP_URL },
  });

  // Resolve token for authenticated probes.
  const tokenPath = resolve(fallback, "var/trust.token");
  try {
    state.token = readFileSync(tokenPath, "utf8").trim();
  } catch {
    // Fall through; probes will degrade.
  }

  // 10. Trust plane /health
  const healthRes = await probeHealth(state.token);
  if (healthRes.ok) {
    results.push({
      id: "daemon.trust-health",
      label: "trust /health",
      status: "ok",
      message: `HTTP 200 at ${TRUST_URL}/health`,
    });
  } else {
    results.push({
      id: "daemon.trust-health",
      label: "trust /health",
      status: "fail",
      message: healthRes.message,
      remediation: "check trust plane logs at harness/var/trust.log",
    });
  }

  // 11. MCP initialize handshake
  const initRes = await probeMcpInitialize(state.token);
  if (initRes.ok) {
    results.push({
      id: "daemon.mcp-initialize",
      label: "mcp initialize",
      status: "ok",
      message: "handshake accepted",
    });
  } else {
    results.push({
      id: "daemon.mcp-initialize",
      label: "mcp initialize",
      status: "fail",
      message: initRes.message,
      remediation: "check MCP edge logs at harness/var/mcp.log",
    });
  }

  // 12. `chio check` smoke via CLI
  const chioBin = findOnPath("chio", ctx.pathEnv)
    ?? findOnPath("arc", ctx.pathEnv)
    ?? (existsSync("/Users/connor/Medica/backbay/standalone/arc/target/release/arc")
      ? "/Users/connor/Medica/backbay/standalone/arc/target/release/arc"
      : undefined);
  const policy = resolve(fallback, "policy/canonical.yaml");
  if (!chioBin) {
    results.push({
      id: "daemon.chio-check",
      label: "chio check",
      status: "skip",
      message: "no chio/arc binary on PATH",
    });
  } else {
    const checkRes = await run(
      chioBin,
      [
        "check",
        "--policy", policy,
        "--tool", "echo",
        "--params", '{"msg":"hi"}',
        "--format", "json",
      ],
      { timeoutMs: 15_000 },
    );
    const text = checkRes.stdout.trim();
    let parsed: { decision?: string } | undefined;
    try { parsed = JSON.parse(text.split("\n").pop() ?? text); } catch {
      // Non-JSON output: fall through to fail branch below.
    }
    if (checkRes.exitCode === 0 && parsed?.decision === "allow") {
      results.push({
        id: "daemon.chio-check",
        label: "chio check",
        status: "ok",
        message: "echo → allow",
      });
    } else {
      results.push({
        id: "daemon.chio-check",
        label: "chio check",
        status: "warn",
        message: parsed?.decision
          ? `echo → ${parsed.decision}`
          : `exit ${checkRes.exitCode}`,
        remediation:
          "ensure the canonical policy allows `echo`; check chio version vs policy schema",
        details: { stderr: checkRes.stderr.slice(-300) },
      });
    }
  }

  return { section: { title: "Harness", results }, state };
}

async function probeHealth(token: string | undefined): Promise<
  { ok: true } | { ok: false; message: string }
> {
  try {
    const headers: Record<string, string> = {};
    if (token) headers.Authorization = `Bearer ${token}`;
    const res = await fetch(`${TRUST_URL}/health`, { headers });
    if (res.status === 200) return { ok: true };
    return { ok: false, message: `HTTP ${res.status} from ${TRUST_URL}/health` };
  } catch (err) {
    return { ok: false, message: `fetch failed: ${(err as Error).message}` };
  }
}

async function probeMcpInitialize(token: string | undefined): Promise<
  { ok: true } | { ok: false; message: string }
> {
  try {
    const headers: Record<string, string> = {
      "Content-Type": "application/json",
      Accept: "application/json, text/event-stream",
    };
    if (token) headers.Authorization = `Bearer ${token}`;
    const body = JSON.stringify({
      jsonrpc: "2.0",
      id: 1,
      method: "initialize",
      params: {
        protocolVersion: "2024-11-05",
        capabilities: {},
        clientInfo: { name: "chio-doctor", version: "0.0.0" },
      },
    });
    const res = await fetch(`${MCP_URL}/mcp`, { method: "POST", headers, body });
    if (res.status >= 200 && res.status < 500) return { ok: true };
    return { ok: false, message: `HTTP ${res.status} from ${MCP_URL}/mcp` };
  } catch (err) {
    return { ok: false, message: `fetch failed: ${(err as Error).message}` };
  }
}

/** Tear down the harness if we started it ourselves. */
export async function tearDownHarness(state: HarnessState): Promise<void> {
  if (!state.startedByDoctor || !state.dir) return;
  const stop = resolve(state.dir, "bin/stop.sh");
  if (!existsSync(stop)) return;
  await run("bash", [stop], { timeoutMs: 20_000, cwd: state.dir });
}
