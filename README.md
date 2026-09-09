# @chio/bridge

Version 0.3.0 is an integration qualification candidate. See [ACCEPTANCE.md](ACCEPTANCE.md) for the current execution contract, limits, and operator procedures. No host is accepted by installing this package.

Shared integration library that chio plugins import to talk to the [chio protocol](https://github.com/bb-connor/chio) runtime. Wraps `@chio-protocol/sdk` (MCP edge + trust plane) and the local `chio` CLI.

This is **plugin-author infrastructure**, not an end-user tool.

## Install

```bash
npm install ./chio-bridge-0.3.0.tgz
# Qualification candidate; exact SDK and runtime dependencies are bundled.
```

Node >= 22 (ESM only). Source builds use `npm ci`; create the distributable with
`npm run pack:release -- /absolute/output-directory`. The stage bundles the exact
SDK and production dependencies without changing the source manifest. See
[the packaging procedure](ACCEPTANCE.md#reproducible-candidate-packaging).

MCP client endpoints use an origin such as `http://127.0.0.1:8931`, without
`/mcp`; the SDK adds the MCP path.

## Two transport modes

```ts
import { ChioBridge } from "@chio/bridge";

// Daemon mode - hits chio's MCP edge (8931) and trust plane (8940)
const bridge = ChioBridge.fromDaemon({
  mcpEdgeUrl: "http://127.0.0.1:8931",  // default
  trustUrl:   "http://127.0.0.1:8940",  // default
  token: process.env.CHIO_SERVICE_TOKEN!,
});

// CLI mode - shells out to the local `chio` binary. No daemon required.
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
5. Legacy `CHIO_ARC_BIN` / `ARC_BIN` - fallback for pre-rename deployments where `chio` has not been built yet.
6. Plain `arc` on `$PATH` (final fallback).

Set `CHIO_BIN` explicitly in CI to pin the binary. Legacy `CHIO_ARC_BIN` is honored only when `CHIO_BIN` is not set.

## Core surface

- `bond(opts)` - load policy, validate, issue passport.
- `check(call)` evaluates a CLI policy without executing a tool. A returned receipt is not proof of host enforcement.
- `receipts(opts)` / `receiptStream(opts)` - query / long-poll the trust plane.
- `verifyReceipt(r)` - real ed25519 verification via `@chio-protocol/sdk/invariants`.
- `issueCapability(input)` calls the trust plane. `attenuate(id, delta)` is disabled until a parent-bound authority endpoint is qualified.
- `revokeAllForSubject(did)` - kill every active passport in the lifecycle registry whose subject matches `did`. Returns `{ revokedPassportIds, failed }`.
- `createPassport(opts)` / `verifyPassport(did)` - `did:chio:*` via trust plane or CLI.
- `loadPolicy(path)` / `lintPolicy(policyOrPath)` - real HushSpec schema validation.
- `discoverMcpServers()` / `wrapMcp(cmd, options)` - MCP mesh. `wrapMcp`
  forwards `--policy`, `--server-id`, `--auth-token`, and `--listen` to
  the real `chio mcp serve-http` flag surface and returns the resolved
  URL + auth token + server id. `policy` is required (matching chio's
  own Usage signature). `serverId` defaults to a deterministic
  `chio-wrap-<sha256(cmd[0])[0..16]>` so idempotent re-wraps of the
  same binary produce the same id.
- `verifyPassport(input)` - `input` may be a bare DID string (daemon
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
velocity | human_in_loop
```

`velocity` and `human_in_loop` are supported rule keys in the candidate linter.
Legacy policies can also carry these settings under `extensions.chio.*`.

## Constants

```ts
import { DEFAULT_MCP_EDGE_URL, DEFAULT_TRUST_URL, HUSHSPEC_SUPPORTED_VERSION } from "@chio/bridge";
```

## Attenuation semantics

Attenuation is disabled with `unsupported_authority_operation`. Administrative
reissuance followed by revocation does not establish narrowing, atomicity, or
aggregate budget lineage. There is no permissive fallback.

## Capability issuance

`bridge.issueCapability({ subject?, subjectPublicKey?, scope, ttl?, ttlSeconds?, runtimeAttestation? })` mirrors the trust plane DTO `IssueCapabilityRequest { subjectPublicKey, scope, ttlSeconds }` (camelCase, see `arc/crates/chio-cli/src/trust_control/service_types.rs:691`). Resolution order for `subjectPublicKey`:

1. Explicit `subjectPublicKey` argument (preferred).
2. Hex suffix of `subject` when it matches `did:chio:<64-hex>`.
3. A fresh ed25519 keypair generated via `node:crypto` - both `subjectPublicKey` and `subjectPrivateKeyHex` are returned on the `IssuedCapabilityToken` so the caller can sign downstream presentations.

## Re-exports

`ChioClient`, `ChioSession`, `ReceiptQueryClient` and types `ChioReceipt`, `CapabilityToken` are re-exported for plugin convenience - one import surface.

## CI

[![ci](https://github.com/owner/chio-bridge/actions/workflows/ci.yml/badge.svg)](https://github.com/owner/chio-bridge/actions/workflows/ci.yml)

Workflow: [`.github/workflows/ci.yml`](.github/workflows/ci.yml). Runs lint/typecheck (non-blocking in Wave 5.1), unit tests, and a chio-backed smoke pass. Swap `owner/...` once the GitHub org is live.

### Recover a completed owner result absent from the bridge cache

An uncertain journal entry cannot be retried automatically. For the qualified
local owner, the separately shipped `export-owner-outcome.py` reads one exact
session/request row from the owner's SQLite database in read-only mode. It does
not invoke a tool, acknowledge delivery, or establish trust in the exported bytes.
Keep its new output private. Stop the host first and recover a dead gateway lock
using `recover-lock` if necessary; an active gateway blocks import.

```sh
chio-gateway-operator owner-result-import /absolute/original/gateway.json /absolute/private/owner-result.json
chio-gateway-operator delivery-export /absolute/original/gateway.json ORIGINAL_REQUEST_ID /absolute/private/received-result.json
```

Import verifies the owner's signature, original caller/session/capability,
resource, complete request, trusted receipt, result and acknowledgement proof.
It preserves the earlier uncertain outcome and marks the recovered completion
unacknowledged. It never dispatches or releases the fence. Read and verify the
exported result and independent resource observation before explicitly running:

```sh
chio-gateway-operator delivery-acknowledge /absolute/original/gateway.json /absolute/private/received-result.json
```

A missing, pending, unsigned, mismatched or ambiguous owner result remains
unresolved. Import cannot extend or replace revoked/expired authority. A failed
acknowledgement leaves the fence in place. This operator procedure is separate
from host runtime delivery and uses the same existing kernel wire contract.
