import type { ChioReceipt, CapabilityToken } from "@chio-protocol/sdk/invariants";

export const DEFAULT_MCP_EDGE_URL = "http://127.0.0.1:8931";
export const DEFAULT_TRUST_URL = "http://127.0.0.1:8940";
export const HUSHSPEC_SUPPORTED_VERSION = "0.1.0";

/**
 * DID schemes emitted by the runtime. Wave 5.0: chio-did prefers
 * `did:chio:` but the pre-rename `arc` build still emits `did:arc:`,
 * and during the regression window (see Wave 5.0 report §5) we may
 * be running against either binary. Accept both; emit whichever the
 * runtime produced.
 */
export const DID_PREFIXES = ["did:chio:", "did:arc:"] as const;
export type DidPrefix = (typeof DID_PREFIXES)[number];

/** Returns true if `s` starts with any accepted DID scheme. */
export function isChioDid(s: string | undefined): boolean {
  if (!s) return false;
  return DID_PREFIXES.some((p) => s.startsWith(p));
}

/** Extracts the hex suffix from any accepted DID scheme, else undefined. */
export function didSuffix(s: string | undefined): string | undefined {
  if (!s) return undefined;
  for (const p of DID_PREFIXES) {
    if (s.startsWith(p)) return s.slice(p.length);
  }
  return undefined;
}

export const RULE_KEYS = [
  "forbidden_paths",
  "path_allowlist",
  "egress",
  "secret_patterns",
  "patch_integrity",
  "shell_commands",
  "tool_access",
  "computer_use",
  "remote_desktop_channels",
  "input_injection",
  // Wave 1.6: first-class rule variants in arc-policy
  // (see arc/crates/arc-policy/src/models.rs#Rules, ~L143).
  "velocity",
  "human_in_loop",
] as const;

export type RuleKey = (typeof RULE_KEYS)[number];

/**
 * First-class `Extensions` blocks accepted by arc-policy.
 * Keep in sync with arc/crates/arc-policy/src/models.rs#Extensions (~L391).
 */
export const EXTENSION_KEYS = [
  "posture",
  "origins",
  "detection",
  "reputation",
  "runtime_assurance",
  // Wave 1.6: chio passthrough extensions. arc kernel does not
  // interpret this block; chio-bridge enforces it downstream.
  "chio",
] as const;

export type ExtensionKey = (typeof EXTENSION_KEYS)[number];

export interface HushSpecRules {
  forbidden_paths?: unknown;
  path_allowlist?: unknown;
  egress?: unknown;
  secret_patterns?: unknown;
  patch_integrity?: unknown;
  shell_commands?: unknown;
  tool_access?: unknown;
  computer_use?: unknown;
  remote_desktop_channels?: unknown;
  input_injection?: unknown;
  velocity?: unknown;
  human_in_loop?: unknown;
}

export interface HushSpec {
  hushspec: string;
  name?: string;
  description?: string;
  extends?: string;
  merge_strategy?: "replace" | "merge" | "deep_merge";
  rules?: HushSpecRules;
  extensions?: Record<string, unknown>;
  metadata?: Record<string, unknown>;
}

export interface CapabilityScope {
  grants?: ToolGrant[];
  resource_grants?: unknown[];
  prompt_grants?: unknown[];
}

export interface MonetaryAmount {
  /** Amount in the currency's smallest unit (e.g. cents for USD). */
  units: number;
  /** ISO 4217 currency code (e.g. "USD"). */
  currency: string;
}

export interface ToolGrant {
  server_id: string;
  tool_name: string;
  operations?: string[];
  constraints?: Record<string, unknown>;
  max_invocations?: number;
  /** Mirrors `ToolGrant.max_cost_per_invocation` in arc-core-types
   *  (see `chio-core-types/src/capability.rs:1749`). Accepts either
   *  the full `MonetaryAmount {units, currency}` struct (what the
   *  trust plane expects on the wire) or a bare number interpreted
   *  as minor units (USD cents). Bare-number callers are upgraded to
   *  the struct shape at serialization time. */
  max_cost_per_invocation?: MonetaryAmount | number;
  /** Same shape as above; mirrors `ToolGrant.max_total_cost`. */
  max_total_cost?: MonetaryAmount | number;
  dpop_required?: boolean;
}

export interface BondOptions {
  policyPath: string;
  /** Explicit subject with existing attested receipts. Never inferred from the receipt store. */
  subjectPublicKey?: string;
  ttl?: string;
  budgetUsd?: number;
  capabilityId?: string;
  delegatable?: boolean;
}

export interface Passport {
  /** Subject DID (did:chio:<hex>) from the signed AgentPassport. */
  did: string;
  /** Optional capability id attenuated during bond(). Empty string when the
   *  bond did not attenuate a capability. */
  capabilityId: string;
  /** RFC 3339 UTC timestamp. Mirrors AgentPassport.validUntil. */
  expiresAt: string;
  /** Primary issuer DID when the passport has a single issuer; the first
   *  issuer otherwise. Empty string when no issuer could be resolved. */
  issuer: string;
  /** SHA256 artifact id from arc-credentials::passport_artifact_id.
   *  Surfaced so downstream smoke tests can resolve or revoke the
   *  lifecycle record without re-deriving the hash. */
  passportId?: string;
  /** Full list of issuers when the passport is multi-issuer. */
  issuers?: string[];
  /** Lifecycle status from the trust plane (active | stale | superseded |
   *  revoked | not-found). Present when the passport was published. */
  status?: string;
  /** RFC 3339 UTC timestamp of publication, if published. */
  publishedAt?: string;
  /** Hex-encoded subject ed25519 public key. Identical to the bytes in
   *  did — kept as a convenience for signers that need the raw key. */
  subjectPublicKey?: string;
}

/**
 * Status of a bonded passport, mapped from the trust plane
 * `PassportLifecycleRecord` returned by
 * `GET /v1/passport/statuses/{passportId}`.
 *
 * Wire shape (see `arc/crates/chio-credentials/src/passport.rs:88-107`):
 *   { passportId, subject, issuers[], issuerCount, publishedAt, updatedAt,
 *     status: "active"|"stale"|"superseded"|"revoked"|"not-found",
 *     supersededBy?, revokedAt?, revokedReason?, distribution, validUntil }
 *
 * Budget/guard fields are NOT on this endpoint. Budget usage is keyed by
 * `capabilityId + grantIndex` on `GET /v1/budgets?capabilityId=<id>`
 * (see `BudgetUsageView` in
 * `arc/crates/chio-cli/src/trust_control/service_types.rs:1651`), not by
 * passport. Budget caps live on the per-grant `max_total_cost` inside the
 * capability scope — not on the trust plane response. `guardCount` has no
 * wire representation at all; it was a historical placeholder. We therefore
 * surface these three as OPTIONAL (`undefined` when the bridge can't prove
 * a value) rather than fabricate zeros.
 */
export interface BondStatus {
  /** True iff `status === "active"` on the wire. */
  bonded: boolean;
  /** Raw lifecycle state from the trust plane: "active" | "stale" |
   *  "superseded" | "revoked" | "not-found". Surfaces supersession/
   *  revocation without forcing callers to re-hit the registry. */
  status: string;
  /** RFC3339 UTC timestamp of passport expiry (mirrors
   *  `PassportLifecycleRecord.validUntil`). Empty string only when the
   *  trust plane omitted it (legacy builds). */
  ttlExpiresAt: string;
  /**
   * Cumulative realized-spend on the capability attenuated during bond,
   * in USD cents scaled to USD. Only populated when the caller supplied a
   * `capabilityId` to correlate against `/v1/budgets`. `undefined` when
   * the bridge can't resolve a budget record (no capability id bound, or
   * trust plane has no budget row yet).
   */
  budgetUsedUsd?: number;
  /**
   * Budget cap (USD) from the per-grant `max_total_cost` on the
   * capability. `undefined` when no capability context is available to
   * the `status()` call — the passport-statuses endpoint never surfaces
   * budget caps.
   */
  budgetCapUsd?: number;
  /**
   * Count of policy guards active for this bond. `undefined` — there is
   * NO wire field for this on the trust plane. Historical placeholder
   * retained in the typed surface for call-site compat; downstream code
   * that needs guard detail should lint the policy directly.
   */
  guardCount?: number;
}

export interface ToolCall {
  tool: string;
  params: unknown;
  serverId?: string;
  policyPath?: string;
}

/** Options for side-effect-free CLI policy evaluation and optional budget admission.
 * A check is not execution evidence and does not enforce a resource boundary.
 * A failed/ambiguous budget admission denies; it is never retried automatically.
 */
export interface CheckOptions {
  /** Admission-only by default. Full evaluates an explicit local output fixture, not the real tool. */
  mode?: "preflight" | "full";
  /** JSON file required in full mode; forbidden in preflight mode. */
  outputFixturePath?: string;
  /** Operator-owned durable admission database, required by policies with durable admission. */
  sessionDbPath?: string;
  /** Optional receipt persistence for this local evaluation; not evidence of real tool execution. */
  receiptDbPath?: string;
  /** Deadline for CLI evaluation and budget HTTP admission. Default 10000 ms. */
  timeoutMs?: number;
  /** Capability id to thread through the mediation endpoint. When
   *  present, a non-zero costUsd triggers a budget-authorize-exposure
   *  POST against the trust plane. */
  capabilityId?: string;
  /** Declared cost of this invocation in USD. Converted to cents
   *  (minor units) on the wire. Use 0 (or omit) for tools that do not
   *  attribute spend. */
  costUsd?: number;
  /** Override the trust URL used for mediation. Defaults to
   *  `CHIO_TRUST_URL` / `DEFAULT_TRUST_URL`. */
  trustUrl?: string;
  /** Override the bearer token used for mediation. Defaults to
   *  `CHIO_SERVICE_TOKEN` / `CHIO_TOKEN`. */
  trustToken?: string;
}

export type VerdictDecision = "allow" | "deny" | "cancelled";

export interface Verdict {
  decision: VerdictDecision;
  reason?: string;
  guard?: string;
  receipt?: ChioReceipt;
}

export interface LintIssue {
  path: string;
  message: string;
  severity: "error" | "warning";
  suggestion?: string;
}

export interface LintReport {
  errors: LintIssue[];
  warnings: LintIssue[];
}

export interface IssueCapabilityInput {
  /**
   *  Subject DID (did:chio:<hex>). When `subjectPublicKey` is omitted
   *  and `subject` is a did:chio, the bridge derives the public key
   *  from the DID suffix.
   */
  subject?: string;
  /**
   *  Hex-encoded subject ed25519 public key. The trust plane requires
   *  this on every `POST /v1/capabilities/issue` request — see
   *  `IssueCapabilityRequest::subject_public_key` in
   *  `arc/crates/chio-cli/src/trust_control/service_types.rs:691`.
   *
   *  When omitted, the bridge generates a fresh ed25519 keypair via
   *  `node:crypto`. The freshly-generated public + private hex keys
   *  are returned on the response object as
   *  `subjectPublicKey` / `subjectPrivateKeyHex` so the caller can
   *  retain the signing key in memory.
   */
  subjectPublicKey?: string;
  scope: CapabilityScope;
  /**
   *  ISO-8601 duration string (e.g. "1h"). Forwarded to the trust
   *  plane as `ttlSeconds: number` after parsing. When neither `ttl`
   *  nor `ttlSeconds` is supplied, defaults to 3600 (one hour).
   */
  ttl?: string;
  /**
   *  Explicit TTL in seconds. Mirrors the trust plane's
   *  `IssueCapabilityRequest.ttlSeconds`. Wins over `ttl` when both
   *  are set.
   */
  ttlSeconds?: number;
  delegatable?: boolean;
  /**
   *  Optional runtime attestation evidence forwarded as
   *  `runtimeAttestation` on the wire (camelCase). Schema mirrors
   *  `RuntimeAttestationEvidence` in arc-cli; passed through
   *  verbatim by the bridge.
   */
  runtimeAttestation?: unknown;
}

/**
 * Extension of `CapabilityToken` returned by `bridge.issueCapability()`.
 * When the caller did not supply a `subjectPublicKey`, the bridge
 * generates a fresh ed25519 keypair and surfaces both halves here so
 * the caller can sign downstream presentations.
 */
export interface IssuedCapabilityToken extends CapabilityToken {
  /** Hex-encoded subject ed25519 public key used on the wire. */
  subjectPublicKey?: string;
  /**
   *  Hex-encoded raw 32-byte ed25519 seed for the freshly-generated
   *  subject key. Present ONLY when the bridge generated the keypair
   *  (i.e. `IssueCapabilityInput.subjectPublicKey` was omitted).
   *  Never logged; never persisted by the bridge.
   */
  subjectPrivateKeyHex?: string;
}

export interface AttenuationDelta {
  scope?: Partial<CapabilityScope>;
  budget?: { maxUsd?: number; maxCalls?: number };
  /**
   *  Hex-encoded subject ed25519 public key for the narrower
   *  capability that will be issued during attenuation. The trust
   *  plane has no `/attenuate` endpoint on this build; the bridge
   *  implements attenuation as `issue-narrower-then-revoke-old`,
   *  so the new capability needs a subject key.
   *
   *  When omitted, the bridge generates a fresh ed25519 keypair and
   *  surfaces both halves on the returned `IssuedCapabilityToken`.
   *  Document this in your call site so signers know to retain the
   *  returned `subjectPrivateKeyHex`.
   */
  subjectPublicKey?: string;
  /**
   *  Optional new TTL in seconds for the narrower capability.
   *  Defaults to 3600 (one hour).
   */
  ttlSeconds?: number;
}

export interface CreatePassportOptions {
  /** Explicit subject Ed25519 public key (64 hex characters) with existing attested receipts. */
  subjectPublicKey?: string;
  /** Optional subject DID assertion. Must match subjectPublicKey when provided. */
  subject?: string;
  scope?: CapabilityScope;
  /** Reserved. The real `arc passport create` takes validity in days, not
   *  a duration string; `ttl` is accepted for call-site ergonomics but
   *  ignored by the current bridge. */
  ttl?: string;
  /**
   *  Absolute path to the SQLite receipt DB the arc CLI should read when
   *  building the attested reputation credential. Required for the CLI
   *  fallback path. Falls back to the `CHIO_RECEIPT_DB` env var.
   */
  receiptDbPath?: string;
  /**
   *  Validity period in days. Forwarded to `arc passport create
   *  --validity-days`. Defaults to 30.
   */
  validityDays?: number;
}

export interface McpServerInfo {
  id: string;
  url?: string;
  transport?: "stdio" | "http";
  tools?: string[];
  status?: string;
}

export interface DaemonOptions {
  mcpEdgeUrl?: string;
  trustUrl?: string;
  token: string;
  fetchImpl?: typeof fetch;
  /**
   *  Absolute path to the shared SQLite receipt DB arc CLI should read
   *  when building attested reputation credentials in the passport
   *  create flow. When omitted, the bridge falls back to the
   *  `CHIO_RECEIPT_DB` env var at the call site (see `createPassport`).
   */
  receiptDbPath?: string;
}

export interface CliOptions {
  chioBinary?: string;
}

export interface WrappedMcp {
  /**
   * Full MCP endpoint URL (includes /mcp path) emitted by
   * `arc mcp serve-http` on the readiness banner.
   */
  url: string;
  /**
   * Bearer token required by remote MCP sessions. When the caller
   * passes `options.authToken`, this mirrors that value. When omitted,
   * the bridge synthesises a random token and returns it here so the
   * caller can authenticate downstream `check()` requests without
   * re-deriving it.
   */
  authToken: string;
  /**
   * Server ID used by the edge when emitting receipts. Either the
   * caller-supplied `options.serverId` or a deterministic hash of
   * `cmd[0]` so repeat wraps of the same server are idempotent.
   */
  serverId: string;
  /** Policy path forwarded to `arc mcp serve-http --policy`. */
  policy: string;
  /** Resolved listen address (host:port) returned by the edge banner. */
  listen: string;
  stop: () => Promise<void>;
}

export type { ChioReceipt, CapabilityToken };
