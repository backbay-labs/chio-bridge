import { generateKeyPairSync } from "node:crypto";
import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import type { ChioCli } from "./client/cli.js";
import type { DaemonClient } from "./client/daemon.js";
import { ChioBridgeError, NotInitializedError } from "./errors.js";
import { didSuffix, isChioDid, type CreatePassportOptions, type Passport } from "./types.js";

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

  if (typeof opts.subjectPublicKey !== "string" || !/^[a-f0-9]{64}$/i.test(opts.subjectPublicKey)) {
    throw new ChioBridgeError("passport_subject_required", "createPassport() requires an explicit 64-hex subjectPublicKey with existing attested receipts; it never infers identity from another receipt");
  }
  const subjectPublicKey = opts.subjectPublicKey.toLowerCase();
  if (opts.subject !== undefined && didSuffix(opts.subject)?.toLowerCase() !== subjectPublicKey) {
    throw new ChioBridgeError("passport_invalid", "subject DID does not match the explicit subjectPublicKey");
  }
  const validityDays = opts.validityDays ?? 30;
  if (!Number.isSafeInteger(validityDays) || validityDays < 1) {
    throw new ChioBridgeError("invalid_arg", "validityDays must be a positive safe integer");
  }

  const tmpDir = await mkdtemp(join(tmpdir(), "chio-passport-"));
  const passportPath = join(tmpDir, "passport.json");
  const seedPath = join(tmpDir, "signing-seed.hex");
  try {
    await writeFreshSigningSeed(seedPath);
    // Passport creation does not execute a fixture tool to manufacture evidence.
    // A fresh database must be populated by explicit, verified operator work.
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
    // The passport body is written to --output; no stdout format flag is needed.
    const createResult = await cli.run(createArgs);
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
        !isChioDid(passportJson.subject) ||
        didSuffix(passportJson.subject)?.toLowerCase() !== subjectPublicKey) {
      throw new ChioBridgeError(
        "passport_invalid",
        "chio passport create produced a subject that does not match the explicit subjectPublicKey",
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
      if (record.subject !== passportJson.subject) {
        throw new ChioBridgeError(
          "passport_invalid",
          "trust plane lifecycle subject does not match the signed passport subject",
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

async function writeFreshSigningSeed(seedPath: string): Promise<void> {
  // The temporary key signs the issuer credential, never selects the subject.
  const { privateKey } = generateKeyPairSync("ed25519");
  const privDer = privateKey.export({ type: "pkcs8", format: "der" });
  const seedHex = Buffer.from(privDer).subarray(-32).toString("hex");
  await writeFile(seedPath, seedHex, { mode: 0o600 });
}
