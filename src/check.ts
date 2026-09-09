import type { ChioReceipt } from "@chio-protocol/sdk/invariants";
import type { ChioCli } from "./client/cli.js";
import type { DaemonClient } from "./client/daemon.js";
import { ChioBridgeError } from "./errors.js";
import { DEFAULT_TRUST_URL, type CheckOptions, type ToolCall, type Verdict, type VerdictDecision } from "./types.js";

interface ChioCheckJsonOutput {
  decision?: unknown;
  verdict?: unknown;
  reason?: string;
  guard?: string;
  receipt?: ChioReceipt;
}

/** Policy evaluation only. This method never executes the requested tool. */
export async function checkCall(
  daemon: DaemonClient | undefined,
  cli: ChioCli | undefined,
  call: ToolCall,
  options: CheckOptions = {},
): Promise<Verdict> {
  if (!cli || !call.policyPath) {
    throw new ChioBridgeError("missing_policy", "check() requires a CLI and policyPath; MCP tools/call executes effects and cannot be used as a precheck");
  }
  const timeoutMs = options.timeoutMs ?? 10_000;
  if (!Number.isSafeInteger(timeoutMs) || timeoutMs <= 0) {
    throw new ChioBridgeError("invalid_arg", "timeoutMs must be a positive safe integer");
  }
  if (options.costUsd !== undefined && (!Number.isFinite(options.costUsd) || options.costUsd < 0)) {
    return { decision: "deny", reason: "invalid costUsd", guard: "budget" };
  }
  if ((options.costUsd ?? 0) > 0) {
    const budget = await mediateBudget(daemon, options, timeoutMs);
    if (budget.decision !== "allow") return budget;
  }
  const args: string[] = [];
  const receiptDb = process.env.CHIO_RECEIPT_DB;
  if (receiptDb) args.push("--receipt-db", receiptDb);
  args.push("check", "--policy", call.policyPath, "--tool", call.tool, "--params", JSON.stringify(call.params ?? {}));
  if (call.serverId) args.push("--server", call.serverId);
  const out = await cli.runJson<ChioCheckJsonOutput>(args, { timeoutMs });
  if (!out || typeof out !== "object" || Array.isArray(out)) {
    return { decision: "deny", reason: "chio check returned malformed output" };
  }
  return normalizeVerdict(out);
}

async function mediateBudget(daemon: DaemonClient | undefined, options: CheckOptions, timeoutMs: number): Promise<Verdict> {
  const deny = (reason: string): Verdict => ({ decision: "deny", guard: "budget", reason });
  const capabilityId = options.capabilityId;
  const token = options.trustToken ?? daemon?.token ?? process.env.CHIO_SERVICE_TOKEN ?? process.env.CHIO_TOKEN;
  if (!capabilityId || !token) return deny("budget authorization requires capabilityId and trust token");
  // Round upwards: sub-cent positive charges must not escape admission.
  const exposureUnits = Math.ceil(options.costUsd! * 100);
  if (!Number.isSafeInteger(exposureUnits)) return deny("costUsd exceeds supported precision");
  const trustUrl = (options.trustUrl ?? daemon?.trustUrl ?? process.env.CHIO_TRUST_URL ?? DEFAULT_TRUST_URL).replace(/\/$/, "");
  const url = `${trustUrl}/v1/budgets/authorize-exposure`;
  try {
    const response = await (daemon?.fetchImpl ?? fetch)(url, {
      method: "POST",
      headers: { Authorization: `Bearer ${token}`, "Content-Type": "application/json" },
      body: JSON.stringify({ capabilityId, grantIndex: 0, exposureUnits }),
      signal: AbortSignal.timeout(timeoutMs),
      redirect: "error",
    });
    if (!response.ok) return deny(`budget authorization failed: HTTP ${response.status}`);
    const parsed: unknown = await response.json();
    if (!parsed || typeof parsed !== "object" || typeof (parsed as {allowed?: unknown}).allowed !== "boolean") {
      return deny("budget authorization returned malformed response");
    }
    if (!(parsed as {allowed: boolean}).allowed) {
      return { decision: "cancelled", guard: "velocity", reason: "trust plane denied spend authorization" };
    }
    return { decision: "allow" };
  } catch {
    // The admission outcome may be unknown. Do not retry the charge or dispatch.
    return deny("budget authorization unavailable or outcome unknown; no automatic retry");
  }
}

function normalizeVerdict(out: ChioCheckJsonOutput): Verdict {
  const raw = out.decision ?? out.verdict;
  let decision: VerdictDecision;
  let reason: string | undefined = out.reason;
  let guard: string | undefined = out.guard;

  if (typeof raw === "string") {
    const lower = raw.toLowerCase();
    if (lower === "allow" || lower === "deny" || lower === "cancelled") {
      decision = lower;
    } else {
      decision = "deny";
      reason ??= `unknown chio check decision "${raw}"`;
    }
  } else if (raw && typeof raw === "object") {
    const obj = raw as Record<string, unknown>;
    const explicitTag = (obj.type ?? obj.kind ?? obj.verdict) as string | undefined;
    const tag = explicitTag ?? (Object.keys(obj)[0] as string | undefined);
    const lowered = tag?.toLowerCase();
    if (lowered === "allow") decision = "allow";
    else if (lowered === "cancelled") decision = "cancelled";
    else decision = "deny";
    if (typeof obj.reason === "string") reason ??= obj.reason;
    if (typeof obj.guard === "string") guard ??= obj.guard;
    if (tag && !explicitTag) {
      const inner = obj[tag];
      if (inner && typeof inner === "object") {
        const innerObj = inner as Record<string, unknown>;
        if (typeof innerObj.reason === "string") reason ??= innerObj.reason;
        if (typeof innerObj.guard === "string") guard ??= innerObj.guard;
      }
    }
  } else {
    decision = "deny";
    reason ??= "chio check did not return a decision";
  }

  const verdict: Verdict = { decision };
  if (reason) verdict.reason = reason;
  if (guard) verdict.guard = guard;
  if (out.receipt) verdict.receipt = out.receipt;
  return verdict;
}
