import { generateKeyPairSync, randomBytes } from "node:crypto";
import type { ChioReceipt } from "@chio-protocol/sdk/invariants";
import {
  canonicalizeJsonString,
  sha256Hex,
  signUtf8MessageEd25519,
} from "@chio-protocol/sdk/invariants";
import type { ChioCli } from "./client/cli.js";
import type { DaemonClient } from "./client/daemon.js";
import { ChioBridgeError, NotInitializedError } from "./errors.js";
import {
  DEFAULT_TRUST_URL,
  type CheckOptions,
  type ToolCall,
  type Verdict,
  type VerdictDecision,
} from "./types.js";

interface ChioCheckJsonOutput {
  decision?: unknown;
  verdict?: unknown;
  reason?: string;
  guard?: string;
  receipt?: ChioReceipt;
}

export async function checkCall(
  daemon: DaemonClient | undefined,
  cli: ChioCli | undefined,
  call: ToolCall,
  options: CheckOptions = {},
): Promise<Verdict> {
  // Wave D Bug 2: when a capability id is bonded, gate the downstream
  // verdict on a trust-plane budget-authorize-exposure call so a single
  // bonded session enforces a cumulative budget across all checks.
  // Evaluated BEFORE the underlying CLI/daemon verdict so an over-budget
  // call short-circuits with `cancelled/velocity` and never touches the
  // tool. When the mediation call itself fails (network/404), fall
  // through to the CLI/daemon verdict rather than fail-closed — the
  // task spec requires the CLI path to "fail-closed with a clear
  // reason" only when NO capability is bonded.
  let mediationVerdict: Verdict | undefined;
  if (
    typeof options.capabilityId === "string" &&
    options.capabilityId.length > 0 &&
    typeof options.costUsd === "number" &&
    options.costUsd > 0
  ) {
    if (process.env.CHIO_BRIDGE_DEBUG) {
      process.stderr.write(
        `[chio-bridge] mediate: capabilityId=${options.capabilityId} costUsd=${options.costUsd}\n`,
      );
    }
    mediationVerdict = await mediateBudget(
      options.capabilityId,
      options.costUsd,
      options,
    );
    if (process.env.CHIO_BRIDGE_DEBUG) {
      process.stderr.write(
        `[chio-bridge] mediate result: ${JSON.stringify(mediationVerdict)}\n`,
      );
    }
    if (mediationVerdict && mediationVerdict.decision !== "allow") {
      return mediationVerdict;
    }
  }

  if (cli && call.policyPath) {
    const out = await checkViaCli(cli, call, options);
    return mergeMediationReason(out, mediationVerdict);
  }
  if (daemon) {
    const out = await checkViaDaemon(daemon, call);
    return mergeMediationReason(out, mediationVerdict);
  }
  if (cli) {
    throw new ChioBridgeError(
      "missing_policy",
      "CLI-mode check() requires a policyPath (chio check --policy is required)",
    );
  }
  throw new NotInitializedError("check() requires daemon or CLI client");
}

function mergeMediationReason(v: Verdict, mediation?: Verdict): Verdict {
  // The mediation pass either returned `allow` (and we're here), or was
  // skipped entirely. Nothing to merge; return the downstream verdict.
  if (!mediation) return v;
  if (v.decision !== "allow") return v;
  return v;
}

async function checkViaCli(
  cli: ChioCli,
  call: ToolCall,
  _options: CheckOptions,
): Promise<Verdict> {
  // When CHIO_RECEIPT_DB (or CHIO_HARNESS_DIR) is set, forward --receipt-db
  // to chio so every check() call persists a receipt to that DB. Required
  // for plugin smoke tests that assert via `chio receipt list`.
  const args: string[] = [];
  const receiptDb =
    process.env.CHIO_RECEIPT_DB ??
    (process.env.CHIO_HARNESS_DIR
      ? `${process.env.CHIO_HARNESS_DIR}/var/receipts.sqlite`
      : undefined);
  if (receiptDb) args.push("--receipt-db", receiptDb);
  args.push(
    "check",
    "--policy",
    call.policyPath!,
    "--tool",
    call.tool,
    "--params",
    JSON.stringify(call.params ?? {}),
  );
  if (call.serverId) args.push("--server", call.serverId);

  const out = await cli.runJson<ChioCheckJsonOutput>(args);
  return normalizeVerdict(out);
}

async function checkViaDaemon(daemon: DaemonClient, call: ToolCall): Promise<Verdict> {
  const client = daemon.mcpClient();
  let session;
  try {
    session = await client.initialize();
  } catch (cause) {
    throw new ChioBridgeError(
      "mcp_handshake_failed",
      `MCP handshake against ${daemon.mcpEdgeUrl} failed: ${(cause as Error).message}`,
      cause,
    );
  }
  try {
    const params = (call.params ?? {}) as Record<string, unknown>;
    const callResult = await session.callTool(call.tool, params);
    const result = callResult as unknown as {
      isError?: boolean;
      content?: unknown;
      structuredContent?: unknown;
      _meta?: { receipt?: ChioReceipt; [k: string]: unknown };
    };
    const receipt = result._meta?.receipt;
    const decision: VerdictDecision = result.isError ? "deny" : "allow";
    const verdict: Verdict = { decision };
    if (receipt) verdict.receipt = receipt;
    if (result.isError && typeof result.content === "string") {
      verdict.reason = result.content;
    }
    return verdict;
  } finally {
    try {
      await session.close();
    } catch {
      // ignore
    }
  }
}

/**
 * Wave D Bug 2: thread a bonded capability id through
 * `POST /v1/budgets/authorize-exposure` on the trust plane. Uses the
 * existing `TryChargeCostRequest` wire shape documented at
 * `arc/crates/chio-cli/src/trust_control/service_types.rs:2109-2123`
 * with camelCase field names:
 *   { capabilityId, grantIndex, exposureUnits, maxTotalExposureUnits }
 *
 * The trust plane atomically accumulates per-`(capabilityId, grantIndex)`
 * spend and returns `allowed: false` once the accumulated total would
 * exceed `maxTotalExposureUnits`. We map `allowed=false` to a
 * `cancelled/velocity` verdict. When the endpoint is unreachable (no
 * trust token or HTTP error), we skip mediation and let the downstream
 * verdict stand — the bond contract is what ensures a bonded session
 * has a real capability id to thread through.
 *
 * The max_total_exposure_units (budget cap) is NOT sent on every
 * authorize-exposure call; the trust plane resolves the cap from the
 * capability's per-grant `max_total_cost` at issuance time. We still
 * pass `maxTotalExposureUnits` when the caller supplied an explicit
 * ceiling via `CHIO_CAPABILITY_BUDGET_USD` env so the mediation call
 * can enforce a client-asserted cap against older trust-plane builds
 * that did not retain budget caps at issuance.
 */
async function mediateBudget(
  capabilityId: string,
  costUsd: number,
  options: CheckOptions,
): Promise<Verdict | undefined> {
  const token =
    options.trustToken ??
    process.env.CHIO_SERVICE_TOKEN ??
    process.env.CHIO_TOKEN;
  const trustUrl = (options.trustUrl ?? process.env.CHIO_TRUST_URL ?? DEFAULT_TRUST_URL).replace(/\/$/, "");
  if (!token) return undefined;

  const exposureUnits = Math.max(0, Math.floor(costUsd * 100));
  if (exposureUnits === 0) return undefined;

  const envCapUsd = Number.parseFloat(process.env.CHIO_CAPABILITY_BUDGET_USD ?? "");
  const maxTotalExposureUnits = Number.isFinite(envCapUsd) && envCapUsd > 0
    ? Math.floor(envCapUsd * 100)
    : undefined;

  const body: Record<string, unknown> = {
    capabilityId,
    grantIndex: 0,
    exposureUnits,
  };
  if (maxTotalExposureUnits !== undefined) {
    body.maxTotalExposureUnits = maxTotalExposureUnits;
  }
  const url = `${trustUrl}/v1/budgets/authorize-exposure`;
  let response: Response;
  try {
    response = await fetch(url, {
      method: "POST",
      headers: {
        Authorization: `Bearer ${token}`,
        "Content-Type": "application/json",
      },
      body: JSON.stringify(body),
    });
  } catch {
    return undefined;
  }
  if (!response.ok) {
    // 4xx: fall through, let underlying verdict stand. The trust plane
    // may not know this capability yet (mock/test paths).
    return undefined;
  }
  const raw = await response.text();
  let parsed: { allowed?: boolean; totalCostExposed?: number; total_cost_exposed?: number } = {};
  try {
    parsed = JSON.parse(raw);
  } catch {
    return undefined;
  }
  if (parsed.allowed === false) {
    const totalExposed =
      parsed.totalCostExposed ?? parsed.total_cost_exposed ?? undefined;
    const reason = maxTotalExposureUnits !== undefined
      ? `velocity guard: $${(exposureUnits / 100).toFixed(2)} would exceed capability budget cap of $${(maxTotalExposureUnits / 100).toFixed(2)}` +
        (typeof totalExposed === "number"
          ? ` (exposed so far: $${(totalExposed / 100).toFixed(2)})`
          : "")
      : `velocity guard: trust plane denied spend authorization for capability ${capabilityId}`;
    const verdict: Verdict = {
      decision: "cancelled",
      guard: "velocity",
      reason,
    };
    // Persist a signed cancel receipt through `POST /v1/receipts/tools`
    // so evidence bundles contain proof of the velocity-guard cancel.
    // Best-effort: if submission fails we still return the verdict.
    const receipt = await submitVelocityCancelReceipt(
      trustUrl,
      token,
      capabilityId,
      exposureUnits,
      maxTotalExposureUnits,
      reason,
    );
    if (receipt) verdict.receipt = receipt;
    return verdict;
  }
  return { decision: "allow" };
}

/**
 * Build, sign, and submit a `decision.verdict: "cancelled"` receipt to
 * the trust plane's tool-receipts endpoint so downstream evidence
 * bundles contain proof of the velocity-guard cancel. The bridge
 * mints a fresh ed25519 keypair per cancel (the receipt's
 * `kernel_key` is that public hex); auditors can verify the
 * signature over the canonical receipt body but the key is NOT
 * anchored in the trust plane's issuer set. This is deliberate — the
 * receipt records a bridge-side mediation decision, not a kernel-side
 * guard denial, and mirrors the existing "synthesised cancel"
 * pattern used by the hedge-fund demo's step-7 scope probes.
 */
async function submitVelocityCancelReceipt(
  trustUrl: string,
  token: string,
  capabilityId: string,
  exposureUnits: number,
  maxTotalExposureUnits: number | undefined,
  reason: string,
): Promise<ChioReceipt | undefined> {
  try {
    const { publicKey, privateKey } = generateKeyPairSync("ed25519");
    const privDer = privateKey.export({ type: "pkcs8", format: "der" });
    const pubDer = publicKey.export({ type: "spki", format: "der" });
    const seedHex = Buffer.from(privDer).subarray(-32).toString("hex");
    const kernelKeyHex = Buffer.from(pubDer).subarray(-32).toString("hex");

    const params = {
      capability_id: capabilityId,
      exposure_cents: exposureUnits,
      max_total_cents: maxTotalExposureUnits ?? null,
    };
    const parameterCanonical = canonicalizeJsonString(JSON.stringify(params));
    const parameterHash = sha256Hex(parameterCanonical);
    const idSeed = randomBytes(8).toString("hex");
    const contentHash = sha256Hex(
      canonicalizeJsonString(
        JSON.stringify("chio-bridge:velocity-cancel:no-content"),
      ),
    );
    const policyHash = sha256Hex("chio-bridge-mediation");

    const body = {
      id: `rcpt-velocity-${Date.now().toString(16)}-${idSeed}`,
      timestamp: Math.floor(Date.now() / 1000),
      capability_id: capabilityId,
      tool_server: "chio-bridge",
      tool_name: "velocity_guard",
      action: {
        parameters: params,
        parameter_hash: parameterHash,
      },
      // Decision is tagged-enum: {verdict: "cancelled", reason} for Cancelled.
      // Mirrors `Decision::Cancelled { reason }` in chio-core-types/receipt.rs:677.
      // `guard` is NOT a field on the Cancelled variant; the guard name is
      // surfaced through the `evidence[].guard_name` channel instead.
      decision: {
        verdict: "cancelled" as const,
        reason,
      },
      content_hash: contentHash,
      policy_hash: policyHash,
      evidence: [
        {
          guard_name: "velocity",
          verdict: false,
          details: reason,
        },
      ],
      metadata: {
        source: "chio-bridge.mediate",
        attribution: {
          delegation_depth: 0,
          grant_index: 0,
          issuer_key: kernelKeyHex,
          subject_key: kernelKeyHex,
        },
      },
      kernel_key: kernelKeyHex,
    };
    const bodyCanonical = canonicalizeJsonString(JSON.stringify(body));
    const sig = signUtf8MessageEd25519(bodyCanonical, seedHex);
    const receipt: ChioReceipt = {
      ...body,
      signature: sig.signature_hex,
    } as ChioReceipt;

    const res = await fetch(`${trustUrl}/v1/receipts/tools`, {
      method: "POST",
      headers: {
        Authorization: `Bearer ${token}`,
        "Content-Type": "application/json",
      },
      body: JSON.stringify(receipt),
    });
    if (!res.ok && process.env.CHIO_BRIDGE_DEBUG) {
      const raw = await res.text().catch(() => "");
      process.stderr.write(
        `[chio-bridge] cancel-receipt submit failed: HTTP ${res.status}: ${raw.slice(0, 200)}\n`,
      );
    }
    return receipt;
  } catch {
    return undefined;
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
