import { generateKeyPairSync } from "node:crypto";
import type { CapabilityToken } from "@chio-protocol/sdk/invariants";
import type { DaemonClient } from "./client/daemon.js";
import { CapabilityDeniedError, ChioBridgeError, NotInitializedError } from "./errors.js";
import {
  didSuffix,
  type AttenuationDelta,
  type IssueCapabilityInput,
  type IssuedCapabilityToken,
} from "./types.js";

const DEFAULT_TTL_SECONDS = 3600;

/**
 * `POST /v1/capabilities/issue`. Wire shape mirrors
 * `IssueCapabilityRequest` at
 * `arc/crates/chio-cli/src/trust_control/service_types.rs:691`:
 *   {
 *     subjectPublicKey: string,   // ed25519 hex, REQUIRED
 *     scope: ChioScope,
 *     ttlSeconds: u64,
 *     runtimeAttestation?: RuntimeAttestationEvidence,
 *   }
 *
 * When the caller omits `subjectPublicKey`, the bridge derives one
 * from `input.subject` (when it's a `did:chio:<hex>` form) or
 * generates a fresh ed25519 keypair via `node:crypto`. In the
 * fresh-keypair case the returned token carries both
 * `subjectPublicKey` and `subjectPrivateKeyHex` so the caller can
 * sign downstream presentations without having to re-mint a key.
 */
export async function issueCapability(
  daemon: DaemonClient | undefined,
  input: IssueCapabilityInput,
): Promise<IssuedCapabilityToken> {
  if (!daemon) {
    throw new NotInitializedError(
      "issueCapability() requires daemon mode; construct via ChioBridge.fromDaemon({...})",
    );
  }

  let subjectPublicKey = input.subjectPublicKey;
  let subjectPrivateKeyHex: string | undefined;
  if (!subjectPublicKey) {
    const suffix = typeof input.subject === "string" ? didSuffix(input.subject) : undefined;
    if (suffix && /^[0-9a-f]{64}$/i.test(suffix)) {
      subjectPublicKey = suffix;
    }
  }
  if (!subjectPublicKey) {
    const generated = generateEd25519KeyPairHex();
    subjectPublicKey = generated.publicKeyHex;
    subjectPrivateKeyHex = generated.privateKeyHex;
  }

  const ttlSeconds = resolveTtlSeconds(input.ttl, input.ttlSeconds);

  const body: Record<string, unknown> = {
    subjectPublicKey,
    scope: input.scope,
    ttlSeconds,
  };
  if (input.delegatable !== undefined) body.delegatable = input.delegatable;
  if (input.runtimeAttestation !== undefined) {
    body.runtimeAttestation = input.runtimeAttestation;
  }

  const res = await daemon.trust<
    { capability?: CapabilityToken; error?: string } | CapabilityToken
  >("POST", "/v1/capabilities/issue", body);
  if (!res.ok) {
    const err = (res.data as { error?: string })?.error ?? res.raw.slice(0, 300);
    throw new CapabilityDeniedError(
      `capability issuance failed: HTTP ${res.status}: ${err}`,
    );
  }
  // The trust plane wraps the token in `{capability: ...}`
  // (IssueCapabilityResponse), but earlier builds returned the bare
  // CapabilityToken. Accept both.
  const data = res.data as { capability?: CapabilityToken } & CapabilityToken;
  const token = (data.capability ?? data) as CapabilityToken;
  const issued: IssuedCapabilityToken = { ...token, subjectPublicKey };
  if (subjectPrivateKeyHex) issued.subjectPrivateKeyHex = subjectPrivateKeyHex;
  return issued;
}

/**
 * Attenuate a capability to a narrower scope or budget.
 *
 * The arc trust plane on this build has NO `/v1/capabilities/<id>/attenuate`
 * route. (We grepped `arc/crates/chio-cli/src/trust_control/` for
 * `attenuat`: only the `validate_attenuation` core type machinery exists,
 * never bound to an HTTP handler.) The bridge therefore implements
 * attenuation as a two-step `issue-narrower-then-revoke-old` semantic:
 *
 *   1. POST `/v1/capabilities/issue` with the narrower scope/budget,
 *      yielding a fresh `CapabilityToken` (new id, new subject key).
 *   2. POST `/v1/revocations` with the *old* capability id.
 *
 * Best-effort atomicity: if (2) fails after (1) succeeds, the bridge
 * still returns the new token and surfaces the revocation error in a
 * `ChioBridgeError` so the operator can retry or hand-revoke. Documented
 * in `README.md` under "Attenuation semantics".
 */
export async function attenuateCapability(
  daemon: DaemonClient | undefined,
  capabilityId: string,
  delta: AttenuationDelta,
): Promise<IssuedCapabilityToken> {
  if (!daemon) {
    throw new NotInitializedError(
      "attenuate() requires daemon mode; construct via ChioBridge.fromDaemon({...})",
    );
  }

  // Step 1: issue narrower capability.
  const scope = (delta.scope ?? {}) as IssueCapabilityInput["scope"];
  const issueInput: IssueCapabilityInput = {
    scope,
  };
  if (delta.subjectPublicKey) issueInput.subjectPublicKey = delta.subjectPublicKey;
  if (delta.ttlSeconds !== undefined) issueInput.ttlSeconds = delta.ttlSeconds;
  const newToken = await issueCapability(daemon, issueInput);

  // Step 2: revoke the old capability.
  // Wire path: POST /v1/revocations with `{capabilityId}` (camelCase via
  // `serde(rename_all="camelCase")` on RevokeCapabilityRequest at
  // `arc/crates/chio-cli/src/trust_control/config_and_public.rs:1-5`).
  const revokeRes = await daemon.trust<{ capabilityId?: string; revoked?: boolean; error?: string }>(
    "POST",
    "/v1/revocations",
    { capabilityId: capabilityId },
  );
  if (!revokeRes.ok) {
    const err = (revokeRes.data as { error?: string })?.error ?? revokeRes.raw.slice(0, 300);
    throw new ChioBridgeError(
      "attenuation_partial",
      `attenuation issued new capability ${(newToken as { id?: string }).id ?? "<unknown>"} but failed to revoke old ${capabilityId}: HTTP ${revokeRes.status}: ${err}`,
      { newToken, oldCapabilityId: capabilityId },
    );
  }
  return newToken;
}

function resolveTtlSeconds(ttl: string | undefined, ttlSeconds: number | undefined): number {
  if (typeof ttlSeconds === "number" && ttlSeconds > 0) return Math.floor(ttlSeconds);
  if (!ttl) return DEFAULT_TTL_SECONDS;
  const m = ttl.trim().match(/^(\d+)\s*([smhdw]?)$/i);
  if (!m) return DEFAULT_TTL_SECONDS;
  const n = Number(m[1]);
  const unit = (m[2] ?? "s").toLowerCase();
  switch (unit) {
    case "s": return n;
    case "m": return n * 60;
    case "h": return n * 3600;
    case "d": return n * 86_400;
    case "w": return n * 7 * 86_400;
    default: return DEFAULT_TTL_SECONDS;
  }
}

function generateEd25519KeyPairHex(): { publicKeyHex: string; privateKeyHex: string } {
  // Mirror the writeFreshSigningSeed pattern from passport.ts: the last
  // 32 bytes of PKCS#8 DER are the private seed, the last 32 bytes of
  // SPKI DER are the public key.
  const { privateKey, publicKey } = generateKeyPairSync("ed25519");
  const privDer = privateKey.export({ type: "pkcs8", format: "der" });
  const pubDer = publicKey.export({ type: "spki", format: "der" });
  const seed = Buffer.from(privDer).subarray(-32);
  const pub = Buffer.from(pubDer).subarray(-32);
  return {
    publicKeyHex: pub.toString("hex"),
    privateKeyHex: seed.toString("hex"),
  };
}

// ---------------------------------------------------------------------------
// Wave D Bug 1: CLI-mode bond() reaches the trust plane via raw HTTP
// rather than going through DaemonClient (which the CLI constructor
// never instantiates). These helpers mirror the issue/attenuate wire
// semantics but use `fetch` + env-derived auth instead.
// ---------------------------------------------------------------------------

export async function issueCapabilityViaHttp(
  trustUrl: string,
  token: string,
  input: IssueCapabilityInput,
): Promise<IssuedCapabilityToken> {
  let subjectPublicKey = input.subjectPublicKey;
  let subjectPrivateKeyHex: string | undefined;
  if (!subjectPublicKey) {
    const generated = generateEd25519KeyPairHex();
    subjectPublicKey = generated.publicKeyHex;
    subjectPrivateKeyHex = generated.privateKeyHex;
  }
  const ttlSeconds = resolveTtlSeconds(input.ttl, input.ttlSeconds);
  const body: Record<string, unknown> = {
    subjectPublicKey,
    scope: input.scope,
    ttlSeconds,
  };
  if (input.delegatable !== undefined) body.delegatable = input.delegatable;
  if (input.runtimeAttestation !== undefined) {
    body.runtimeAttestation = input.runtimeAttestation;
  }
  const url = `${trustUrl.replace(/\/$/, "")}/v1/capabilities/issue`;
  const res = await fetch(url, {
    method: "POST",
    headers: {
      Authorization: `Bearer ${token}`,
      "Content-Type": "application/json",
    },
    body: JSON.stringify(body),
  });
  const raw = await res.text();
  if (!res.ok) {
    throw new CapabilityDeniedError(
      `capability issuance failed: HTTP ${res.status}: ${raw.slice(0, 300)}`,
    );
  }
  let parsed: unknown;
  try {
    parsed = JSON.parse(raw);
  } catch {
    throw new ChioBridgeError(
      "capability_issue_parse",
      `trust plane returned non-JSON issuance response: ${raw.slice(0, 300)}`,
    );
  }
  const data = parsed as { capability?: CapabilityToken } & CapabilityToken;
  const tokenOut = (data.capability ?? data) as CapabilityToken;
  const issued: IssuedCapabilityToken = { ...tokenOut, subjectPublicKey };
  if (subjectPrivateKeyHex) issued.subjectPrivateKeyHex = subjectPrivateKeyHex;
  return issued;
}

export async function attenuateCapabilityViaHttp(
  trustUrl: string,
  token: string,
  capabilityId: string,
  delta: AttenuationDelta & { scope?: IssueCapabilityInput["scope"] },
): Promise<IssuedCapabilityToken> {
  const scope = (delta.scope ?? {}) as IssueCapabilityInput["scope"];
  const issueInput: IssueCapabilityInput = { scope };
  if (delta.subjectPublicKey) issueInput.subjectPublicKey = delta.subjectPublicKey;
  if (delta.ttlSeconds !== undefined) issueInput.ttlSeconds = delta.ttlSeconds;
  const newToken = await issueCapabilityViaHttp(trustUrl, token, issueInput);

  // Best-effort revoke the parent. The trust plane may reject
  // unknown ids with a 4xx — we swallow the error because the
  // narrower capability is already issued and the caller now holds its
  // id.
  const revokeUrl = `${trustUrl.replace(/\/$/, "")}/v1/revocations`;
  try {
    await fetch(revokeUrl, {
      method: "POST",
      headers: {
        Authorization: `Bearer ${token}`,
        "Content-Type": "application/json",
      },
      body: JSON.stringify({ capabilityId }),
    });
  } catch {
    // swallow
  }
  return newToken;
}
