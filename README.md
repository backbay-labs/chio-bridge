# @chio/bridge

Shared integration library that chio plugins import to talk to the [chio protocol](https://github.com/bb-connor/chio) runtime. Wraps `@chio-protocol/sdk` (MCP edge + trust plane) and the local `chio` CLI.

This is **plugin-author infrastructure**, not an end-user tool.

## Install

```bash
npm install @chio/bridge
# peer: @chio-protocol/sdk ^1.0.0 (bundled as dep here)
```

Node >= 22 (ESM only).

## Two transport modes

```ts
import { ChioBridge } from "@chio/bridge";

// Daemon mode — hits chio's MCP edge (8931) and trust plane (8940)
const bridge = ChioBridge.fromDaemon({
  mcpEdgeUrl: "http://127.0.0.1:8931",  // default
  trustUrl:   "http://127.0.0.1:8940",  // default
  token: process.env.CHIO_SERVICE_TOKEN!,
});

// CLI mode — shells out to the local `chio` binary. No daemon required.
const bridge = ChioBridge.fromCli({ chioBinary: "chio" });
```

## Breaking changes (Wave 5.0)

Arc upstream renamed every runtime identifier to `chio`. Downstream consumers must update in lockstep:

| Before (Wave 4.x) | After (Wave 5.0) |
|-------------------|------------------|
| `CHIO_ARC_BIN` env var | `CHIO_BIN` |
| `chioBinary` was `arcBinary` on `CliOptions` | `chioBinary` |
| `ArcClient`, `ArcSession`, `ArcReceipt` re-exports | `ChioClient`, `ChioSession`, `ChioReceipt` |
| `ArcCli` class (rarely used directly) | `ChioCli` |
| `@arc-protocol/sdk` dep | `@chio-protocol/sdk` |
| `did:arc:<hex>` subject DIDs | `did:chio:<hex>` |
| default binary fallback `"arc"` on PATH | `"chio"` on PATH |

The HushSpec `hushspec:` schema identity is unchanged (that's the policy schema version, not an arc identifier).

### Binary discovery (Wave 5.0.1)

The bridge **prefers `chio` over `arc`**. `ChioCli` resolves the runtime binary in this order:

1. Explicit `chioBinary` option (highest precedence).
2. `CHIO_BIN` env var (set by `chio-test-harness/bin/env.sh`).
3. If a legacy `CHIO_ARC_BIN` / `ARC_BIN` path is set and a sibling `chio` binary exists in the same directory (common for `cargo build --release --bin chio` landing alongside the old `arc` artifact), the bridge switches to that sibling automatically.
4. `chio` on `$PATH`.
5. Legacy `CHIO_ARC_BIN` / `ARC_BIN` — fallback for pre-rename deployments where `chio` has not been built yet.
6. Plain `arc` on `$PATH` (final fallback).

Set `CHIO_BIN` explicitly in CI to pin the binary. Legacy `CHIO_ARC_BIN` is honored only when `CHIO_BIN` is not set.

## Core surface

- `bond(opts)` — load policy, validate, issue passport.
- `check(call)` — mediate a tool call. Returns a `Verdict`; verdict may include a signed `ChioReceipt`.
- `receipts(opts)` / `receiptStream(opts)` — query / long-poll the trust plane.
- `verifyReceipt(r)` — real ed25519 verification via `@chio-protocol/sdk/invariants`.
- `issueCapability(input)` / `attenuate(id, delta)` — trust plane REST. See "Attenuation semantics" below for the issue-then-revoke fallback.
- `revokeAllForSubject(did)` — kill every active passport in the lifecycle registry whose subject matches `did`. Returns `{ revokedPassportIds, failed }`.
- `createPassport(opts)` / `verifyPassport(did)` — `did:chio:*` via trust plane or CLI.
- `loadPolicy(path)` / `lintPolicy(policyOrPath)` — real HushSpec schema validation.
- `discoverMcpServers()` / `wrapMcp(cmd, options)` — MCP mesh. `wrapMcp`
  forwards `--policy`, `--server-id`, `--auth-token`, and `--listen` to
  the real `chio mcp serve-http` flag surface and returns the resolved
  URL + auth token + server id. `policy` is required (matching chio's
  own Usage signature). `serverId` defaults to a deterministic
  `chio-wrap-<sha256(cmd[0])[0..16]>` so idempotent re-wraps of the
  same binary produce the same id.
- `verifyPassport(input)` — `input` may be a bare DID string (daemon
  mode: trust-plane lifecycle lookup), `{ did }` / `{ passportId }`
  for explicit forms, or `{ file: "/path/to/passport.json" }` for
  CLI-only verification via `chio passport verify --input <file>`. The
  old single-arg `verifyPassport(did)` form continues to work against
  daemon mode; CLI-only callers must switch to the `{ file }` form
  because `chio passport verify --input` expects a path, not a DID.

## Policy notes

HushSpec `0.1.0` is the only supported version. The rule set is **closed**:

```
forbidden_paths | path_allowlist | egress | secret_patterns | patch_integrity
shell_commands | tool_access | computer_use | remote_desktop_channels | input_injection
```

`velocity` and `human_in_loop` are **not** first-class rule keys. Put them under
`extensions.chio.*` — the linter suggests this path.

## Constants

```ts
import { DEFAULT_MCP_EDGE_URL, DEFAULT_TRUST_URL, HUSHSPEC_SUPPORTED_VERSION } from "@chio/bridge";
```

## Attenuation semantics

The chio trust plane on this build has **no** `/v1/capabilities/<id>/attenuate` endpoint. (We grepped `arc/crates/chio-cli/src/trust_control/` for `attenuat`: only the `validate_attenuation` core type machinery exists, never bound to an HTTP handler.) `bridge.attenuate(capabilityId, delta)` therefore implements attenuation as **issue-narrower-then-revoke-old**:

1. `POST /v1/capabilities/issue` with the narrower scope/budget, yielding a fresh `IssuedCapabilityToken` (new id, new subject key).
2. `POST /v1/revocations` with the *old* capability id.

Best-effort atomicity: if step 2 fails after step 1 succeeds, the bridge throws `ChioBridgeError("attenuation_partial", ...)` carrying the new token in `cause` so the operator can retry or hand-revoke.

`AttenuationDelta.subjectPublicKey` lets callers reuse an existing key on the narrower capability; when omitted, the bridge generates a fresh ed25519 keypair via `node:crypto` and surfaces both halves on the returned `IssuedCapabilityToken` (`subjectPublicKey`, `subjectPrivateKeyHex`).

## Capability issuance

`bridge.issueCapability({ subject?, subjectPublicKey?, scope, ttl?, ttlSeconds?, runtimeAttestation? })` mirrors the trust plane DTO `IssueCapabilityRequest { subjectPublicKey, scope, ttlSeconds }` (camelCase, see `arc/crates/chio-cli/src/trust_control/service_types.rs:691`). Resolution order for `subjectPublicKey`:

1. Explicit `subjectPublicKey` argument (preferred).
2. Hex suffix of `subject` when it matches `did:chio:<64-hex>`.
3. A fresh ed25519 keypair generated via `node:crypto` — both `subjectPublicKey` and `subjectPrivateKeyHex` are returned on the `IssuedCapabilityToken` so the caller can sign downstream presentations.

## Re-exports

`ChioClient`, `ChioSession`, `ReceiptQueryClient` and types `ChioReceipt`, `CapabilityToken` are re-exported for plugin convenience — one import surface.

## CI

[![ci](https://github.com/owner/chio-bridge/actions/workflows/ci.yml/badge.svg)](https://github.com/owner/chio-bridge/actions/workflows/ci.yml)

Workflow: [`.github/workflows/ci.yml`](.github/workflows/ci.yml). Runs lint/typecheck (non-blocking in Wave 5.1), unit tests, and a chio-backed smoke pass. Swap `owner/...` once the GitHub org is live.
