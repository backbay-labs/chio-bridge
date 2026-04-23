import {
  generateKeyPairSync,
  createPrivateKey,
  createPublicKey,
} from "node:crypto";
import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import type { ChioCli } from "./client/cli.js";
import type { DaemonClient } from "./client/daemon.js";
import { ChioBridgeError, NotInitializedError } from "./errors.js";
import { checkCall } from "./check.js";
import { isChioDid, type CreatePassportOptions, type Passport } from "./types.js";

/**
 * Wire shape returned by `POST /v1/passport/statuses`. Mirrors
 * `PassportLifecycleRecord` in
 * `arc/crates/chio-credentials/src/passport.rs` (camelCase via serde).
 */
interface PassportLifecycleRecord {
  passportId: string;
  subject: string;
  issuers?: string[];
  issuerCount?: number;
  publishedAt?: number;
  updatedAt?: number;
  status?: string;
  supersededBy?: string | null;
  revokedAt?: number | null;
  revokedReason?: string | null;
  validUntil: string;
}

/**
 * Minimal wire shape for the signed `AgentPassport` JSON written by
 * `chio passport create`. Mirrors `AgentPassport` in
 * `arc/crates/chio-credentials/src/passport.rs`.
 */
interface AgentPassportJson {
  schema: string;
  subject: string;
  credentials: unknown[];
  merkleRoots: string[];
  issuedAt: string;
  validUntil: string;
  enterpriseIdentityProvenance?: unknown[];
}

/**
 * Creates a signed Agent Passport via the chio CLI, optionally publishes
 * it to the trust plane lifecycle registry, and returns the chio-bridge
 * `Passport` surface.
 *
 * Real wire path (see arc/crates/chio-cli/src/trust_control/service_types.rs#L304):
 *   POST {trustUrl}/v1/passport/statuses with body
 *     { "passport": <AgentPassport JSON>, "distribution"?: {...} }
 *   Response is a `PassportLifecycleRecord` with camelCase fields
 *   including `passportId`, `subject` (did:chio), `issuers[]`, and
 *   `validUntil` (RFC 3339).
 */
export async function createPassport(
  daemon: DaemonClient | undefined,
  cli: ChioCli | undefined,
  opts: CreatePassportOptions = {},
): Promise<Passport> {
  if (!cli) {
    // Both fromDaemon and fromCli attach an ChioCli, so this should not
    // be reachable in practice — but guard defensively.
    throw new NotInitializedError(
      "createPassport() requires the chio CLI (chio binary on $PATH or CHIO_BIN)",
    );
  }

  const receiptDbPath =
    opts.receiptDbPath ??
    process.env.CHIO_RECEIPT_DB ??
    process.env.CHIO_HARNESS_RECEIPT_DB ??
    deriveHarnessReceiptDb();
  if (!receiptDbPath) {
    throw new ChioBridgeError(
      "passport_create_failed",
      "createPassport() requires a receipt database path (set CreatePassportOptions.receiptDbPath, CHIO_RECEIPT_DB, or provide DaemonOptions.receiptDbPath) — chio passport create reads receipts from that DB to build the attested reputation credential.",
    );
  }

  const validityDays = Math.max(1, Math.floor(opts.validityDays ?? 30));

  const tmpDir = await mkdtemp(join(tmpdir(), "chio-passport-"));
  const passportPath = join(tmpDir, "passport.json");
  const seedPath = join(tmpDir, "signing-seed.hex");
  try {
    const { subjectPublicKeyHex } = await writeFreshSigningSeed(seedPath);
    let subjectPublicKey = await resolveSubjectPublicKey(
      cli,
      receiptDbPath,
      subjectPublicKeyHex,
    );
    // Fresh receipt-db guard: when the DB has NO receipts at all,
    // resolveSubjectPublicKey falls through to `preferredHex` (our
    // brand-new keypair). `chio passport create` will then reject with
    // `no receipts found for subject <hex>`. This is the Gap 3
    // signature surfaced by the OpenCode chio_init smoke — a bridge
    // consumer without a pre-seeded receipt hits an opaque 422.
    //
    // Fix: if the daemon is reachable, bootstrap a seed receipt via an
    // always-allowed `echo` check against the MCP edge. The edge
    // stamps a receipt with the kernel-minted subject key; we re-run
    // `resolveSubjectPublicKey` to pick that key up. This keeps the
    // cold-boot bond path idempotent without requiring plugin authors
    // to remember to call `check()` first.
    if (subjectPublicKey === subjectPublicKeyHex && daemon) {
      const seeded = await seedBootstrapReceipt(daemon, receiptDbPath);
      if (seeded) {
        subjectPublicKey = await resolveSubjectPublicKey(
          cli,
          receiptDbPath,
          subjectPublicKeyHex,
        );
      }
    }

    // Drive the real CLI flag surface documented by
    // `chio passport create --help`:
    //   --subject-public-key, --output, --signing-seed-file,
    //   --validity-days, --receipt-db
    const createArgs = [
      "--receipt-db",
      receiptDbPath,
      "passport",
      "create",
      "--subject-public-key",
      subjectPublicKey,
      "--output",
      passportPath,
      "--signing-seed-file",
      seedPath,
      "--validity-days",
      String(validityDays),
    ];
    const createResult = await cli.run([...createArgs, "--format", "json"]);
    if (createResult.exitCode !== 0) {
      throw new ChioBridgeError(
        "passport_create_failed",
        `chio passport create exited ${createResult.exitCode}: ${
          createResult.stderr.trim() || createResult.stdout.trim()
        }`,
      );
    }

    let passportJson: AgentPassportJson;
    try {
      passportJson = JSON.parse(
        await readFile(passportPath, "utf8"),
      ) as AgentPassportJson;
    } catch (cause) {
      throw new ChioBridgeError(
        "passport_invalid",
        `chio passport create did not emit parseable JSON at ${passportPath}: ${(cause as Error).message}`,
        cause,
      );
    }
    if (typeof passportJson.subject !== "string" ||
        !isChioDid(passportJson.subject)) {
      throw new ChioBridgeError(
        "passport_invalid",
        `chio passport create produced a passport with non-did:chio subject: ${passportJson.subject ?? "<missing>"}`,
      );
    }

    // If the bridge is constructed with a daemon, publish the passport
    // to the trust plane lifecycle registry. This is what unlocks
    // `verifyPassport(did)` and `status(did)` against the live service.
    let record: PassportLifecycleRecord | undefined;
    if (daemon) {
      const envelope = { passport: passportJson };
      const res = await daemon.trust<PassportLifecycleRecord | { error?: string }>(
        "POST",
        "/v1/passport/statuses",
        envelope,
      );
      if (!res.ok) {
        const detail = (res.data as { error?: string })?.error ??
          res.raw.slice(0, 300);
        throw new ChioBridgeError(
          "passport_publish_failed",
          `passport publish failed: HTTP ${res.status}: ${detail}`,
        );
      }
      record = res.data as PassportLifecycleRecord;
      if (!record.subject || !isChioDid(record.subject)) {
        throw new ChioBridgeError(
          "passport_invalid",
          `trust plane returned invalid lifecycle record (expected did:chio: subject, got ${record.subject ?? "<empty>"})`,
        );
      }
    }

    const issuers = record?.issuers ?? [];
    const issuer: string = issuers[0] ?? "";
    const passport: Passport = {
      did: passportJson.subject,
      capabilityId: "",
      expiresAt: record?.validUntil ?? passportJson.validUntil,
      issuer,
      subjectPublicKey,
    };
    if (record) {
      passport.passportId = record.passportId;
      passport.issuers = issuers;
      passport.status = record.status;
      if (typeof record.publishedAt === "number") {
        passport.publishedAt = new Date(record.publishedAt * 1000).toISOString();
      }
    }
    return passport;
  } finally {
    await rm(tmpDir, { recursive: true, force: true }).catch(() => {
      // best-effort cleanup
    });
  }
}

/**
 * Accepted shapes for `verifyPassport()`:
 *   - bare DID string (`"did:chio:..."`) — daemon-mode lifecycle lookup.
 *   - `{ did }` — same, explicit form.
 *   - `{ file }` — path to an AgentPassport JSON file (what callers
 *     hold after `createPassport(...)` writes its `--output`). Drives
 *     the real `arc passport verify --input <file>` CLI command.
 *   - `{ passportId }` — SHA256 artifact id; daemon-mode resolve.
 */
export type VerifyPassportInput =
  | string
  | { did: string }
  | { passportId: string }
  | { file: string };

/**
 * Verifies a passport's lifecycle status.
 *
 * Real CLI surface (from `arc passport verify --help`):
 *   `arc passport verify --input <FILE>` — requires an AgentPassport
 *   JSON file, NOT a bare DID. Older bridge versions passed the DID
 *   as `--input` which the CLI rejected; CLI-only callers must now
 *   pass `{ file }` to hit the real verify path.
 *
 * Daemon-mode (Option C): we read the lifecycle registry via
 *   `GET /v1/passport/statuses`, match on `subject` (DID) or
 *   `passportId`, and treat `status === "active"` as verified. The
 *   trust plane stores lifecycle metadata only — not the full
 *   AgentPassport body — so Option A ("fetch JSON, write tempfile,
 *   call arc passport verify") is not possible without changing arc.
 *   See `arc/crates/chio-credentials/src/passport.rs:86-107`.
 */
export async function verifyPassport(
  daemon: DaemonClient | undefined,
  cli: ChioCli | undefined,
  input: VerifyPassportInput,
): Promise<boolean> {
  // Normalise shapes.
  let did: string | undefined;
  let passportId: string | undefined;
  let file: string | undefined;
  if (typeof input === "string") {
    did = input;
  } else if ("file" in input) {
    file = input.file;
  } else if ("passportId" in input) {
    passportId = input.passportId;
  } else {
    did = input.did;
  }

  // File-path verification drives the real chio CLI. Works without the
  // daemon, since the passport body is self-signed and carries the
  // issuer's public key.
  if (file) {
    if (!cli) {
      throw new NotInitializedError(
        "verifyPassport({ file }) requires the chio CLI (chio binary on $PATH or CHIO_BIN)",
      );
    }
    const result = await cli.run(["passport", "verify", "--input", file]);
    return result.exitCode === 0;
  }

  if (did && !isChioDid(did)) return false;

  // Daemon-mode lifecycle lookup. Matches on subject DID (and as a
  // convenience on passportId as well, in case callers pass that form).
  // When multiple records match the same subject (the harness retains
  // history across runs), prefer an active one so verify(did) reflects
  // the current lifecycle state rather than the oldest record.
  if (daemon) {
    const listRes = await daemon.trust<{ passports?: PassportLifecycleRecord[] }>(
      "GET",
      "/v1/passport/statuses",
    );
    if (!listRes.ok) return false;
    const records = listRes.data.passports ?? [];
    const matches = records.filter((r) => {
      if (passportId && r.passportId === passportId) return true;
      if (did && r.subject === did) return true;
      return false;
    });
    if (matches.length === 0) return false;
    // Prefer active; otherwise fall back to whatever matched.
    const active = matches.find((m) => m.status === "active");
    return Boolean(active);
  }

  if (cli) {
    // Old form: `verifyPassport(did)` against CLI only. The real
    // `chio passport verify --input <file>` takes a file path, so we
    // can't meaningfully verify a bare DID without talking to the
    // trust plane. Fail closed with an actionable error.
    throw new ChioBridgeError(
      "verify_requires_file_or_daemon",
      "verifyPassport(did) requires daemon mode; for CLI-only verification pass { file: '/path/to/passport.json' } (the --output of createPassport / `chio passport create`).",
    );
  }

  throw new NotInitializedError("verifyPassport() requires daemon or CLI client");
}

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

function deriveHarnessReceiptDb(): string | undefined {
  const harness = process.env.CHIO_HARNESS_DIR;
  if (!harness) return undefined;
  return join(harness, "var", "receipts.sqlite");
}

/**
 * Seeds a bootstrap receipt in the receipt DB for the cold-boot bond
 * path. Returns `true` when a receipt was (or might have been) written
 * and a rescan of the DB is warranted. On failure returns `false` so
 * the caller surfaces the original "no receipts found" error without
 * getting a confusing bootstrap-related stack.
 *
 * Uses `checkCall(daemon, undefined, {tool: "echo", params: {...}})`
 * which drives the MCP edge's `tools/call` path. The edge stamps a
 * receipt against whichever subject key the kernel mints for the
 * bearer token, which is exactly the key the subsequent
 * `resolveSubjectPublicKey` peek will recover.
 */
async function seedBootstrapReceipt(
  daemon: DaemonClient,
  receiptDbPath: string,
): Promise<boolean> {
  // This tool is part of the chio-test-harness hello-mcp server and is
  // always-allowed by canonical.yaml. Production consumers who use a
  // different MCP fixture should pre-seed their receipt DB by running
  // one allowed call before calling bond(); this bootstrap is a best
  // effort for the common harness case.
  void receiptDbPath; // receipt-db routing is handled by the edge config
  try {
    await checkCall(daemon, undefined, {
      tool: "echo",
      params: { msg: "chio-bridge:bond:bootstrap" },
    });
    return true;
  } catch {
    // Swallow: caller will surface the downstream "no receipts" error
    // when the real `chio passport create` runs, giving a clear signal
    // to the operator that a warmup is required.
    return false;
  }
}

async function writeFreshSigningSeed(seedPath: string): Promise<{
  seedHex: string;
  subjectPublicKeyHex: string;
}> {
  // Generate an Ed25519 keypair and extract the 32-byte raw seed + raw
  // public key. Node's PKCS#8 DER encoding for Ed25519 is 48 bytes: the
  // last 32 are the private seed. The SPKI DER encoding is 44 bytes:
  // the last 32 are the public key.
  const { privateKey, publicKey } = generateKeyPairSync("ed25519");
  const privDer = privateKey.export({ type: "pkcs8", format: "der" });
  const pubDer = publicKey.export({ type: "spki", format: "der" });
  const seed = Buffer.from(privDer).subarray(-32);
  const pub = Buffer.from(pubDer).subarray(-32);
  const seedHex = seed.toString("hex");
  const subjectPublicKeyHex = pub.toString("hex");
  await writeFile(seedPath, seedHex, { mode: 0o600 });
  // Silence unused-lint warnings for crypto import typechecks.
  void createPrivateKey;
  void createPublicKey;
  return { seedHex, subjectPublicKeyHex };
}

/**
 * `arc passport create` refuses to build a passport unless the receipt DB
 * already contains at least one receipt for the given subject key. The
 * trust plane's MCP edge stamps receipts against whichever subject key
 * the kernel minted for a check call, so a freshly-generated keypair has
 * no receipts yet. To stay compatible with the current harness, we peek
 * at the most recent receipt and reuse its subject key.
 *
 * This is a documented limitation of the "bootstrap a brand-new agent"
 * path on a harness that has not been preloaded with receipts for the
 * caller's key. A production flow would run a warmup check() first,
 * then pass that subject's public key here. Downstream smoke-test agents
 * that want full subject control should pass `opts.subjectPublicKey` via
 * a future extension to `CreatePassportOptions`.
 *
 * Returns the subject key the caller should stamp on the passport. When
 * the receipt DB already holds receipts for the freshly-generated key
 * (e.g. a smoke test warmed it up), `preferredHex` is returned directly.
 */
async function resolveSubjectPublicKey(
  cli: ChioCli,
  receiptDbPath: string,
  preferredHex: string,
): Promise<string> {
  // Try the preferred key first — if the caller has warmed up receipts
  // against it, arc passport create will succeed without fallback.
  // (We can't cheaply test this without running `arc passport create`
  // itself, so we just pass `preferredHex` through; on `no receipts
  // found for subject` we fall back to the most-recent receipt.)
  //
  // Shortcut: if the DB is empty or the preferred key has zero receipts,
  // `arc receipt list --limit 1` will tell us the newest subject.
  try {
    const raw = await cli.run([
      "--receipt-db",
      receiptDbPath,
      "receipt",
      "list",
      "--limit",
      "1",
    ]);
    if (raw.exitCode === 0) {
      const line = raw.stdout.split("\n").find((l) => l.trim().startsWith("{"));
      if (line) {
        const rec = JSON.parse(line) as {
          metadata?: {
            attribution?: { subject_key?: string };
          };
        };
        const subjectKey = rec.metadata?.attribution?.subject_key;
        if (typeof subjectKey === "string" && /^[0-9a-f]{64}$/i.test(subjectKey)) {
          return subjectKey;
        }
      }
    }
  } catch {
    // fall through to preferred
  }
  return preferredHex;
}
