# COMMITS.md — chio-bridge

Shared integration library (`@<NPM_SCOPE>/bridge`, currently `@chio/bridge`
in source). Load-bearing: every plugin imports it, and the live-harness
live tests (15) + unit tests (53) both exercise it. Target first ship tag:
`v0.2.1`.

Commit plan turns the working tree into 7 logical slices.

---

## 1. chore: scaffold package and workspace

**Body.** Initial scaffold — `package.json`, `tsconfig.json`,
`LICENSE`, `.gitignore`. Establishes Node `>=22`, ESM-only, TypeScript
`~5.7`, and the `@<NPM_SCOPE>/bridge` identity. Declares
`@chio-protocol/sdk` as the peer to the chio runtime. From Wave 1's
bootstrap.

**Files.**

- `package.json`, `package-lock.json`, `bun.lock`
- `tsconfig.json`
- `LICENSE`
- `.gitignore`

---

## 2. feat: implement bridge against real chio host schema

**Body.** The real bridge surface against a live chio daemon or CLI:
`bond`, `check`, `receipts`, `receiptStream`, `verifyReceipt`,
`issueCapability`, `attenuate` (issue-narrower-then-revoke fallback),
`revokeAllForSubject`, `createPassport`, `verifyPassport`, `loadPolicy`,
`lintPolicy`, `discoverMcpServers`, `wrapMcp`. Dual transport:
`fromDaemon({trustUrl, mcpEdgeUrl, token})` hits the trust plane on 8940
and the MCP edge on 8931; `fromCli({chioBinary})` shells out. From
Wave 1's rewrite against the host schema — replaces all stubs with
real HTTP + CLI wiring.

**Files.**

- `src/index.ts`, `src/capabilities.ts`, `src/check.ts`, `src/errors.ts`,
  `src/mcp.ts`, `src/passport.ts`, `src/policy.ts`, `src/receipts.ts`,
  `src/types.ts`
- `src/client/cli.ts`, `src/client/daemon.ts`
- `src/doctor/*` — `chio-doctor` bin (installed env checks, trust
  plane reachability, policy parse, receipts.db health).

---

## 3. test: cover bridge surface with unit and live integration tests

**Body.** 53 unit tests plus 15 live-daemon integration tests driven
through `chio-test-harness`. Unit tests pin the error taxonomy,
attenuation fallback semantics, verifyReceipt ed25519 path, and
parsing invariants. Live tests cover end-to-end
`bond → check → receipts → verifyReceipt` round-trips and
`extensions.chio.*` passthrough behaviour. From Waves 1, 4 (W4 gaps
regression), and 5.0 (chio-rename regressions).

**Files.**

- `test/*.test.ts` — `bond_bootstrap`, `cli`, `daemon`, `doctor`,
  `mcp_wrap`, `policy`, `verify_passport`, `verify`, `wave4_gaps`.
- `test/fixtures/`
- `test/live/` — live-harness integration suite.

---

## 4. feat: prefer chio binary over legacy arc via CHIO_BIN resolution

**Body.** Arc upstream renamed every runtime identifier to `chio` in
Wave 5.0. The bridge updates its binary discovery ladder to prefer
`chio`: (1) explicit `chioBinary`, (2) `CHIO_BIN` env, (3) sibling
`chio` adjacent to a legacy `CHIO_ARC_BIN`, (4) `chio` on `PATH`,
(5) `CHIO_ARC_BIN`/`ARC_BIN`, (6) `arc` on `PATH`. Also re-exports
`ChioClient`, `ChioSession`, `ChioReceipt` (replacing `Arc*`); flips
`did:arc:` → `did:chio:` default; switches the dependency to
`@chio-protocol/sdk`. Wave 5.0 + Wave 5.0.1.

**Files.**

- `src/client/cli.ts` — binary resolution ladder.
- `src/index.ts` — re-export renames.
- `src/passport.ts` — `did:chio:` first, `did:arc:` accepted on ingest.
- `package.json` — `@chio-protocol/sdk` dep + version bump to `0.2.1`.
- `README.md` — "Breaking changes (Wave 5.0)" + "Binary discovery
  (Wave 5.0.1)" sections.

---

## 5. ci: run unit and live tests under chio-test-harness

**Body.** GitHub Actions workflow that checks out `chio-bridge`, arc
(for `setup-chio`), and `chio-test-harness`, boots the harness, and
runs `bun run test` + `bun run test:live`. Uses the composite
`setup-chio@v0.1.0` from `<GH_ORG>/chio-ci-actions`; typecheck is
non-blocking per Wave 5.1. Wave 5.1.

**Files.**

- `.github/workflows/ci.yml`

---

## 6. ci: add SLSA L3 and Sigstore-signed release workflow

**Body.** Tag-triggered release flow publishing
`@<NPM_SCOPE>/bridge` with native npm provenance
(`npm publish --provenance`). SLSA L3 attestation is emitted by the
`slsa-github-generator/generator_generic_slsa3.yml` reusable workflow
at job level (required by SLSA to satisfy L3 isolation). Shipped
via the `publish-chio` composite in `chio-ci-actions`. Wave 5.5.

**Files.**

- `.github/workflows/release.yml`
- `scripts/verify-release.sh` — post-tag integrity check
  (attestation + npm provenance + tarball sha256 match).

---

## 7. docs: verification notes and README polish

**Body.** `README.md` rewrite — documents the public surface, dual
transport modes, binary discovery, attenuation semantics, capability
issuance, and HushSpec 0.1.0 constraints. `VERIFY.md` captures the
live-harness reference run (all 68 tests green against the Wave 5.0.1
chio binary). Wave 5.1 + 5.2 polish pass.

**Files.**

- `README.md`
- `VERIFY.md`
