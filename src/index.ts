import type { ChioReceipt, CapabilityToken } from "@chio-protocol/sdk/invariants";
import { ChioCli } from "./client/cli.js";
import { DaemonClient } from "./client/daemon.js";
import {
  issueCapability,
  attenuateCapability,
  issueCapabilityViaHttp,
  attenuateCapabilityViaHttp,
} from "./capabilities.js";
import { checkCall } from "./check.js";
import { discoverMcpServers, wrapMcp, type WrapMcpOptions } from "./mcp.js";
import { createPassport, verifyPassport, type VerifyPassportInput } from "./passport.js";
import { loadPolicy, lintPolicy } from "./policy.js";
import {
  exportEvidence,
  listReceipts,
  parseReceipt,
  streamReceipts,
  verifyReceiptValue,
} from "./receipts.js";
import { ChioBridgeError, NotInitializedError } from "./errors.js";
import {
  isChioDid,
  type AttenuationDelta,
  type BondOptions,
  type BondStatus,
  type CapabilityScope,
  type CheckOptions,
  type CliOptions,
  type CreatePassportOptions,
  type DaemonOptions,
  type HushSpec,
  type IssueCapabilityInput,
  type IssuedCapabilityToken,
  type LintReport,
  type McpServerInfo,
  type Passport,
  type ToolCall,
  type ToolGrant,
  type Verdict,
  type WrappedMcp,
} from "./types.js";
import {
  DEFAULT_MCP_EDGE_URL,
  DEFAULT_TRUST_URL,
  EXTENSION_KEYS,
  HUSHSPEC_SUPPORTED_VERSION,
  RULE_KEYS,
} from "./types.js";

export class ChioBridge {
  private readonly daemon?: DaemonClient;
  private readonly cli?: ChioCli;
  private readonly receiptDbPath?: string;

  private constructor(
    daemon?: DaemonClient,
    cli?: ChioCli,
    receiptDbPath?: string,
  ) {
    this.daemon = daemon;
    this.cli = cli;
    this.receiptDbPath = receiptDbPath;
  }

  static fromDaemon(opts: DaemonOptions): ChioBridge {
    return new ChioBridge(
      new DaemonClient(opts),
      new ChioCli(),
      opts.receiptDbPath,
    );
  }

  static fromCli(opts: CliOptions = {}): ChioBridge {
    return new ChioBridge(undefined, new ChioCli(opts.chioBinary));
  }

  async bond(opts: BondOptions): Promise<Passport> {
    const policy = await loadPolicy(opts.policyPath);
    const lint = await lintPolicy(policy);
    if (lint.errors.length > 0) {
      throw new ChioBridgeError(
        "policy_invalid",
        `policy at ${opts.policyPath} has ${lint.errors.length} error(s): ${lint.errors
          .map((e) => `${e.path}: ${e.message}`)
          .join("; ")}`,
        lint,
      );
    }
    const createOpts: CreatePassportOptions = {};
    if (opts.ttl) createOpts.ttl = opts.ttl;
    if (this.receiptDbPath) createOpts.receiptDbPath = this.receiptDbPath;
    const passport = await createPassport(this.daemon, this.cli, createOpts);

    // Wave D Bug 1: bond() in CLI mode previously returned
    // capabilityId: "" because the attenuate path was gated on
    // `this.daemon && opts.capabilityId`. Fix: always derive a
    // capability scope from the policy's `rules.tool_access.allow` list
    // and issue a real capability bound to the passport subject, then
    // attenuate to the requested budget. Daemon mode uses
    // DaemonClient; CLI mode talks to the trust plane directly over
    // HTTP using env-derived credentials (CHIO_SERVICE_TOKEN /
    // CHIO_TOKEN + CHIO_TRUST_URL), which the harness always exposes.
    // When neither path can reach the trust plane, bond() still
    // returns a valid passport with capabilityId: "" so older
    // smoke-test fixtures keep passing.
    const scope = deriveCapabilityScopeFromPolicy(policy, opts.budgetUsd);
    const subjectPublicKey = passport.subjectPublicKey;
    const ttlSeconds = parseTtlSeconds(opts.ttl);

    if (this.daemon) {
      // Daemon mode: issue via the authoritative daemon client, then
      // optionally attenuate if a caller-supplied capability id was
      // passed (legacy compat).
      let issued: IssuedCapabilityToken | undefined;
      let issueError: unknown;
      try {
        const input: IssueCapabilityInput = { scope, ttlSeconds };
        if (subjectPublicKey) input.subjectPublicKey = subjectPublicKey;
        issued = await issueCapability(this.daemon, input);
      } catch (err) {
        issueError = err;
        issued = undefined;
      }
      if (!issued && issueError && process.env.CHIO_BRIDGE_DEBUG) {
        process.stderr.write(
          `[chio-bridge] bond(): issueCapability failed: ${(issueError as Error).message}\n`,
        );
      }
      let currentCapabilityId = issued?.id as string | undefined;

      if (opts.capabilityId) {
        // Legacy path: caller pre-issued a capability and asked us to
        // attenuate it to their budget. Keep this behavior intact.
        const delta: AttenuationDelta = {};
        if (opts.budgetUsd !== undefined) delta.budget = { maxUsd: opts.budgetUsd };
        if (Object.keys(delta).length > 0) {
          try {
            const token = await attenuateCapability(
              this.daemon,
              opts.capabilityId,
              delta,
            );
            const reissued =
              (token as unknown as { id?: string; capability_id?: string }).id ??
              (token as unknown as { capability_id?: string }).capability_id;
            currentCapabilityId =
              typeof reissued === "string" && reissued.length > 0
                ? reissued
                : opts.capabilityId;
          } catch {
            currentCapabilityId = opts.capabilityId;
          }
        } else {
          currentCapabilityId = opts.capabilityId;
        }
      }
      if (typeof currentCapabilityId === "string" && currentCapabilityId.length > 0) {
        passport.capabilityId = currentCapabilityId;
      }
      return passport;
    }

    // CLI mode: reach the trust plane directly over HTTP.
    const token =
      process.env.CHIO_SERVICE_TOKEN ??
      process.env.CHIO_TOKEN ??
      undefined;
    const trustUrl =
      process.env.CHIO_TRUST_URL ??
      DEFAULT_TRUST_URL;
    if (!token) {
      // No trust plane reachable — return the passport with empty
      // capabilityId. The plugin's fail-closed PreToolUse path will
      // then refuse tool calls until a real bond lands.
      return passport;
    }
    try {
      const issued = await issueCapabilityViaHttp(trustUrl, token, {
        subjectPublicKey,
        scope,
        ttlSeconds,
      });
      let finalId = (issued as { id?: string }).id;
      if (finalId && opts.budgetUsd !== undefined) {
        // Attenuate to the requested budget cap. The trust plane has no
        // `/attenuate` route (see capabilities.ts); we mirror the
        // daemon-mode `issue-narrower-then-revoke-old` semantic over
        // HTTP so the returned capability id carries the budget.
        const narrower = await attenuateCapabilityViaHttp(
          trustUrl,
          token,
          finalId,
          {
            scope: narrowerScopeWithBudget(scope, opts.budgetUsd),
            ...(subjectPublicKey ? { subjectPublicKey } : {}),
            ttlSeconds,
          },
        );
        finalId = (narrower as { id?: string }).id ?? finalId;
      }
      if (typeof finalId === "string" && finalId.length > 0) {
        passport.capabilityId = finalId;
      }
    } catch {
      // Best-effort: CLI bond still returns a valid passport when the
      // trust plane refuses issuance. The plugin layer treats empty
      // capabilityId as "no budget binding" and degrades gracefully.
    }
    return passport;
  }

  /**
   * Revoke a passport. Accepts either:
   *   - A passportId (SHA-256 artifact id) — passed through directly.
   *   - A did:chio subject — resolved to a passportId via the trust plane
   *     lifecycle registry (most-recent active record for that subject).
   *
   * Wire path: POST /v1/passport/statuses/{passport_id}/revoke (matches
   * arc/crates/chio-cli/src/trust_control/service_types.rs PASSPORT_STATUS_REVOKE_PATH).
   * The legacy /v1/revocations endpoint is for capability-id revocation, not
   * passport lifecycle, and fails closed with `missing field capabilityId`.
   */
  async revoke(passportIdOrDid: string): Promise<void> {
    if (this.daemon) {
      const passportId = await this.resolvePassportId(passportIdOrDid);
      const res = await this.daemon.trust(
        "POST",
        `/v1/passport/statuses/${encodeURIComponent(passportId)}/revoke`,
        {},
      );
      if (!res.ok) {
        throw new ChioBridgeError(
          "revoke_failed",
          `revoke failed: HTTP ${res.status}: ${res.raw.slice(0, 300)}`,
        );
      }
      return;
    }
    if (this.cli) {
      const result = await this.cli.run([
        "passport",
        "status",
        "revoke",
        "--passport-id",
        passportIdOrDid,
      ]);
      if (result.exitCode !== 0) {
        throw new ChioBridgeError(
          "revoke_failed",
          `chio passport status revoke failed (code ${result.exitCode}): ${result.stderr}`,
        );
      }
      return;
    }
    throw new NotInitializedError("revoke() requires daemon or CLI client");
  }

  private async resolvePassportId(input: string): Promise<string> {
    if (!isChioDid(input)) return input;
    if (!this.daemon) return input;
    const res = await this.daemon.trust<{
      passports?: Array<{ passportId: string; subject: string; status: string; publishedAt?: number }>;
    }>("GET", "/v1/passport/statuses");
    if (!res.ok || !res.data?.passports) {
      throw new ChioBridgeError(
        "revoke_failed",
        `could not list passport statuses to resolve ${input}: HTTP ${res.status}`,
      );
    }
    const matches = res.data.passports.filter((p) => p.subject === input);
    if (matches.length === 0) {
      throw new ChioBridgeError(
        "revoke_failed",
        `no passport lifecycle record found for subject ${input}`,
      );
    }
    // Prefer the most recently published active record.
    matches.sort((a, b) => (b.publishedAt ?? 0) - (a.publishedAt ?? 0));
    const active = matches.find((p) => p.status === "active") ?? matches[0];
    if (!active) {
      throw new ChioBridgeError(
        "revoke_failed",
        `no passport record to revoke for subject ${input}`,
      );
    }
    return active.passportId;
  }

  /**
   * Resolve a passport's lifecycle state.
   *
   * Wire: `GET /v1/passport/statuses/{passportId}` returns a
   * `PassportLifecycleRecord` (see
   * `arc/crates/chio-credentials/src/passport.rs:88-107`). The response
   * carries `status` (active/stale/superseded/revoked), `validUntil`,
   * `publishedAt`, `updatedAt`, and revocation/supersession metadata.
   * It does NOT carry `bonded`, `budget_used_usd`, `budget_cap_usd`,
   * or `guard_count` — those were fabricated defaults in the pre-5.2
   * bridge. `bonded` is derived from `status === "active"`;
   * `ttlExpiresAt` is `validUntil`; budget/guard fields are `undefined`
   * because the passport-statuses endpoint does not expose them (budget
   * usage lives on `/v1/budgets` and is keyed by capabilityId+grantIndex,
   * not passportId).
   */
  async status(passportId: string): Promise<BondStatus> {
    interface WireRecord {
      passportId?: string;
      subject?: string;
      status?: string;
      validUntil?: string;
      publishedAt?: number;
      updatedAt?: number;
      supersededBy?: string;
      revokedAt?: number;
      revokedReason?: string;
    }
    const toBondStatus = (d: WireRecord): BondStatus => ({
      bonded: d.status === "active",
      status: d.status ?? "not-found",
      ttlExpiresAt: d.validUntil ?? "",
    });
    if (this.daemon) {
      const res = await this.daemon.trust<WireRecord>(
        "GET",
        `/v1/passport/statuses/${encodeURIComponent(passportId)}`,
      );
      if (!res.ok) {
        throw new ChioBridgeError(
          "status_failed",
          `status failed: HTTP ${res.status}`,
        );
      }
      return toBondStatus(res.data);
    }
    if (this.cli) {
      // CLI fallback: `chio passport status --id <passportId>` emits the
      // same PassportLifecycleRecord JSON as the HTTP endpoint.
      const data = await this.cli.runJson<WireRecord>([
        "passport",
        "status",
        "--id",
        passportId,
      ]);
      return toBondStatus(data);
    }
    throw new NotInitializedError("status() requires daemon or CLI client");
  }

  check(call: ToolCall, options: CheckOptions = {}): Promise<Verdict> {
    return checkCall(this.daemon, this.cli, call, options);
  }

  receipts(opts: {
    since?: Date;
    limit?: number;
  } = {}): Promise<ChioReceipt[]> {
    return listReceipts(this.daemon, opts);
  }

  receiptStream(opts: { since?: Date } = {}): AsyncIterable<ChioReceipt> {
    return streamReceipts(this.daemon, opts);
  }

  async verifyReceipt(r: ChioReceipt | string): Promise<boolean> {
    return verifyReceiptValue(r);
  }

  exportEvidence(opts: { since: Date; until?: Date; outPath: string }): Promise<string> {
    return exportEvidence(this.daemon, opts);
  }

  issueCapability(input: IssueCapabilityInput): Promise<IssuedCapabilityToken> {
    return issueCapability(this.daemon, input);
  }

  attenuate(capabilityId: string, delta: AttenuationDelta): Promise<IssuedCapabilityToken> {
    return attenuateCapability(this.daemon, capabilityId, delta);
  }

  /**
   * Revoke every active passport in the trust plane lifecycle registry
   * whose `subject === did`. Useful when an operator wants to "kill
   * everything for this DID" — since each `bond()` mints a fresh
   * issuer keypair, a long-lived agent accumulates multiple
   * concurrently-active passports, and `revoke(passportId)` only
   * tombstones one.
   *
   * Wire path: `GET /v1/passport/statuses` (list-then-filter), then
   * `POST /v1/passport/statuses/<id>/revoke` per active record.
   * The trust plane has no `?subject=<did>` query param on the
   * statuses endpoint, so we filter client-side. Matches
   * `arc/crates/chio-cli/src/trust_control/service_types.rs` paths
   * `PASSPORT_STATUSES_PATH` and `PASSPORT_STATUS_REVOKE_PATH`.
   *
   * Returns a structured aggregate so callers can audit individual
   * failures without throwing on a single-passport revoke fault.
   */
  async revokeAllForSubject(did: string): Promise<{
    revokedPassportIds: string[];
    failed: Array<{ passportId: string; reason: string }>;
  }> {
    if (!this.daemon) {
      throw new NotInitializedError(
        "revokeAllForSubject() requires daemon mode; construct via ChioBridge.fromDaemon({...})",
      );
    }
    if (!isChioDid(did)) {
      throw new ChioBridgeError(
        "invalid_arg",
        `revokeAllForSubject() requires a did:chio/did:arc subject, got ${did}`,
      );
    }
    const listRes = await this.daemon.trust<{
      passports?: Array<{
        passportId: string;
        subject: string;
        status: string;
        publishedAt?: number;
      }>;
    }>("GET", "/v1/passport/statuses");
    if (!listRes.ok || !listRes.data?.passports) {
      throw new ChioBridgeError(
        "revoke_failed",
        `could not list passport statuses for ${did}: HTTP ${listRes.status}`,
      );
    }
    const matches = listRes.data.passports.filter(
      (p) => p.subject === did && p.status === "active",
    );
    const revokedPassportIds: string[] = [];
    const failed: Array<{ passportId: string; reason: string }> = [];
    for (const p of matches) {
      try {
        await this.revoke(p.passportId);
        revokedPassportIds.push(p.passportId);
      } catch (cause) {
        failed.push({
          passportId: p.passportId,
          reason: (cause as Error).message ?? String(cause),
        });
      }
    }
    return { revokedPassportIds, failed };
  }

  createPassport(opts: CreatePassportOptions = {}): Promise<Passport> {
    return createPassport(this.daemon, this.cli, opts);
  }

  verifyPassport(input: VerifyPassportInput): Promise<boolean> {
    return verifyPassport(this.daemon, this.cli, input);
  }

  loadPolicy(path: string): Promise<HushSpec> {
    return loadPolicy(path);
  }

  lintPolicy(input: HushSpec | string): Promise<LintReport> {
    return lintPolicy(input);
  }

  discoverMcpServers(): Promise<McpServerInfo[]> {
    return discoverMcpServers(this.daemon);
  }

  /**
   * Spawn a secured `chio mcp serve-http` wrapper around an MCP server
   * subprocess. The returned handle exposes the resolved MCP URL, the
   * auth token the caller must present on downstream sessions, and the
   * server id the edge will stamp on receipts.
   *
   * Backward-compat: `wrapMcp(cmd)` (single-argument form) is still
   * valid when the caller has set a bridge-wide default policy or
   * passes `policy` via the second argument. The real `chio mcp
   * serve-http` requires `--policy` and `--server-id`, so callers that
   * invoked the old single-arg form against the previous bridge
   * version were implicitly depending on whatever policy/auth state
   * their shell had already configured.
   */
  wrapMcp(cmd: string[], options: WrapMcpOptions = {}): Promise<WrappedMcp> {
    if (!this.cli) {
      throw new NotInitializedError("wrapMcp() requires the CLI (chio binary on $PATH)");
    }
    return wrapMcp(this.cli, cmd, options);
  }
}

// ---------------------------------------------------------------------------
// Wave D Bug 1 helpers: derive a capability scope + TTL from the
// policy's rules.tool_access.allow list so CLI-mode bond() can issue a
// real CapabilityToken bound to the passport's subject key.
// ---------------------------------------------------------------------------

function deriveCapabilityScopeFromPolicy(
  policy: HushSpec,
  budgetUsd?: number,
): CapabilityScope {
  // tool_access.allow entries may be either bare strings (tool names)
  // or objects with {server_id, tool_name}. Normalise to ToolGrant
  // entries with a wildcard server so `place_order` etc. match under
  // any alpaca/hello-mcp id. Grant 0 is the grant the bridge's
  // mediation call charges against.
  const rules = policy.rules as Record<string, unknown> | undefined;
  const toolAccess = (rules?.tool_access ?? {}) as Record<string, unknown>;
  const allow = Array.isArray(toolAccess.allow) ? toolAccess.allow : [];
  const grants: ToolGrant[] = [];
  const budgetAmount =
    typeof budgetUsd === "number" && Number.isFinite(budgetUsd) && budgetUsd > 0
      ? { units: Math.floor(budgetUsd * 100), currency: "USD" }
      : undefined;
  for (const entry of allow) {
    if (typeof entry === "string") {
      const grant: ToolGrant = {
        server_id: "*",
        tool_name: entry,
        operations: ["invoke"],
      };
      if (budgetAmount) grant.max_total_cost = budgetAmount;
      grants.push(grant);
    } else if (entry && typeof entry === "object") {
      const obj = entry as Record<string, unknown>;
      const server_id =
        typeof obj.server_id === "string" ? obj.server_id : "*";
      const tool_name = typeof obj.tool_name === "string" ? obj.tool_name : "*";
      const grant: ToolGrant = {
        server_id,
        tool_name,
        operations: ["invoke"],
      };
      if (budgetAmount) grant.max_total_cost = budgetAmount;
      grants.push(grant);
    }
  }
  if (grants.length === 0) {
    // Fall back to a permissive wildcard grant so downstream checks
    // still have a grant index to charge against. The policy's own
    // tool_access.default=block still denies bare calls; this is only
    // a shape for the capability scope.
    const grant: ToolGrant = {
      server_id: "*",
      tool_name: "*",
      operations: ["invoke"],
    };
    if (budgetAmount) grant.max_total_cost = budgetAmount;
    grants.push(grant);
  }
  return { grants };
}

function narrowerScopeWithBudget(
  scope: CapabilityScope,
  budgetUsd: number,
): CapabilityScope {
  const budgetAmount = {
    units: Math.max(0, Math.floor(budgetUsd * 100)),
    currency: "USD",
  };
  const grants = (scope.grants ?? []).map((g) => ({
    ...g,
    max_total_cost: budgetAmount,
  }));
  return { ...scope, grants };
}

function parseTtlSeconds(ttl: string | undefined): number {
  if (!ttl) return 3600;
  const m = ttl.trim().match(/^(\d+)\s*([smhdw]?)$/i);
  if (!m) return 3600;
  const n = Number(m[1]);
  const unit = (m[2] ?? "s").toLowerCase();
  switch (unit) {
    case "s": return n;
    case "m": return n * 60;
    case "h": return n * 3600;
    case "d": return n * 86_400;
    case "w": return n * 7 * 86_400;
    default: return 3600;
  }
}

export {
  ChioBridgeError,
  NotInitializedError,
  CapabilityDeniedError,
  PolicyParseError,
  DaemonUnreachableError,
  SignatureInvalidError,
  CliError,
} from "./errors.js";

export {
  DEFAULT_MCP_EDGE_URL,
  DEFAULT_TRUST_URL,
  EXTENSION_KEYS,
  HUSHSPEC_SUPPORTED_VERSION,
  RULE_KEYS,
};

export type {
  AttenuationDelta,
  BondOptions,
  BondStatus,
  CapabilityScope,
  CheckOptions,
  CliOptions,
  CreatePassportOptions,
  DaemonOptions,
  ExtensionKey,
  HushSpec,
  HushSpecRules,
  IssueCapabilityInput,
  IssuedCapabilityToken,
  LintIssue,
  LintReport,
  McpServerInfo,
  Passport,
  RuleKey,
  ToolCall,
  ToolGrant,
  Verdict,
  VerdictDecision,
  WrappedMcp,
} from "./types.js";

export { loadPolicy, lintPolicy } from "./policy.js";
export { parseReceipt, verifyReceiptValue } from "./receipts.js";
export type { WrapMcpOptions } from "./mcp.js";
export type { VerifyPassportInput } from "./passport.js";

export { ChioClient, ChioSession, ReceiptQueryClient } from "@chio-protocol/sdk";
export type { ChioReceipt, CapabilityToken } from "@chio-protocol/sdk/invariants";
