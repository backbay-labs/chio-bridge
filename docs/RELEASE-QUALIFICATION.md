# Release qualification

This lane builds `@chio/bridge` from one immutable source commit. A passing workflow
qualifies its source checks and installable package. It does not establish
real-host I01-I08 acceptance, a compatible public kernel, or six-host completion.

## Current boundary

- Package version: `0.3.0`. Existing local candidate tarball hashes do
  not identify newly rebuilt archives, including metadata-only rebuilds.
- Public repository identity: `backbay-labs/chio-bridge`.
- Workflow: `.github/workflows/release.yml`.
- Registry package: `@chio/bridge`; GitHub environment: `npm`.
- Release tags: `v<package.json version>`, reachable from `main`.
- Manual `workflow_dispatch` always builds, tests, packs, performs a clean
  consumer install, and generates provenance. It never publishes to npm or
  creates a GitHub Release. There is no manual publish switch.
- Source CI, real-host acceptance, kernel qualification, and any repository
  rulesets remain separate gates. Do not treat package checks as replacements.

The release build uses Node 22.19.0, npm 11.8.0, `npm ci --ignore-scripts`, mandatory build and
unit checks, and `npm run pack:release`. TypeScript packages also require a
successful typecheck. It builds from this checkout and its checked-in vendored
archives; no private sibling checkouts or placeholder actions are used. The
staged tarball embeds the Chio dependencies and removes lifecycle scripts.

## Local qualification

Use a clean isolated checkout and a new artifact directory. Never overwrite a
frozen acceptance bundle. From `.`:

```sh
npm ci --ignore-scripts --no-audit --no-fund
npm run typecheck
npm run build
npm test
npm run pack:release -- /absolute/new-candidate-directory
```

Install the resulting tarball from a fresh consumer directory and empty npm
cache, with scripts disabled:

```sh
npm install --offline --ignore-scripts --no-audit --no-fund \
  --cache /absolute/new-empty-cache /absolute/new-candidate-directory/package.tgz
npm publish /absolute/new-candidate-directory/package.tgz --dry-run --ignore-scripts --access public
```

The filename `package.tgz` above is a placeholder for the emitted tarball. The
workflow checks the emitted checksum, installed package name, absence of local
`file:`/`link:`/`workspace:` dependencies, and installed entrypoint syntax.
The cold consumer install is offline and therefore fails if an unpublished or omitted dependency is needed.

## Hosted qualification and publication

1. Commit source, package metadata, and evidence in their owning repository.
   Preserve the exact kernel, plugin, bridge, SDK, policy, and host identities.
2. Observe required repository checks on the candidate. Run this workflow
   manually at that exact ref and retain `qualified-package` plus
   `package.intoto.jsonl`. A skipped real-host case remains unresolved.
3. Complete all applicable I01-I08 acceptance and the compatible kernel's
   release/security gates before approving production delivery. The original
   unsigned kernel 0.1.0 is not evidence for the new candidate.
4. Configure the `npm` environment before tagging and preserve existing
   repository protection rules. Verify exact commit, kernel compatibility and
   acceptance records under the applicable release procedures. This workflow
   does not require adding human reviewers or changing protection rules.
5. An npm maintainer must register this package's Trusted Publisher with GitHub
   owner `backbay-labs`, repository `chio-bridge`, workflow filename `release.yml`,
   and environment `npm`. Permit direct `npm publish` for this workflow. Do not
   configure a stored `NPM_TOKEN` fallback or print authentication files.
6. Only after those gates, create a new annotated version tag from reviewed
   `main`. A tag push can publish. The workflow rejects tag/version mismatch,
   a source commit outside `main`, and a mismatched `repository.url`.
7. The publication job downloads the built bytes, verifies SLSA provenance and
   checksums, signs the checksum index, verifies its exact GitHub workflow
   identity, then publishes that same tarball with npm OIDC provenance. A
   prerelease version uses npm's `next` dist-tag. Stable versions use `latest`.
8. Verify the public tarball and GitHub Release assets independently, install
   from the documented public path in a new profile, and repeat the supported
   useful-work and prevention/recovery smoke cases against the qualified kernel.

Ordinary actions use full commit pins. The SLSA generator is the documented
exception: upstream requires the exact release tag `v2.1.0` for standard
`slsa-verifier` compatibility. Before using it, the build checks that the tag
resolves to `f7dd8c54c2067bafc12ca7a55595d5ee9b75204a`. The generator runs as a
separate reusable workflow and must pass before publication. No SLSA level or
reproducibility claim is established by the presence of this YAML alone.

## Verify and recover

The GitHub Release contains the tarball, `release-identity.json`, `SHA256SUMS`,
its `.sig` and `.pem`, and `package.intoto.jsonl`. Pin the intended repository,
tag, source commit, and expected checksums before trusting the package:

```sh
sha256sum --check SHA256SUMS
cosign verify-blob --certificate SHA256SUMS.pem --signature SHA256SUMS.sig \
  --certificate-identity 'https://github.com/backbay-labs/chio-bridge/.github/workflows/release.yml@refs/tags/v0.3.0' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com SHA256SUMS
slsa-verifier verify-artifact package.tgz \
  --provenance-path package.intoto.jsonl \
  --source-uri github.com/backbay-labs/chio-bridge --source-tag 'v0.3.0'
```

A timeout or failure after npm publication can leave a published version without
all GitHub assets. Inspect registry `dist.integrity`, retained
`publication-evidence`, and release assets before retrying anything. Compare the
published bytes with the qualified digest; never repack and overwrite a version
or replace conflicting release assets. If the package already exists with the
expected bytes, recover only missing GitHub assets after review. If a defective
package escaped, deprecate it and release a new version. Preserve evidence of the
failed attempt. Roll users back only to a compatible previously qualified
kernel/plugin set; do not silently select the old CLI by its ambiguous version.

## Unresolved external setup

The 2026-09-09 audit observed GitHub ADMIN access for existing Chio integration
repositories. That does not establish npm ownership or Trusted Publisher trust.
No production environment protections or npm Trusted Publisher configuration
were changed while preparing this workflow. Hosted execution, publication,
registry verification, and final host acceptance remain unperformed by this
workflow change.

References: [npm Trusted Publishing](https://docs.npmjs.com/trusted-publishers/),
[GitHub secure action use](https://docs.github.com/en/actions/reference/security/secure-use),
[SLSA generator contract](https://github.com/slsa-framework/slsa-github-generator/blob/v2.1.0/internal/builders/generic/README.md).

## Verification of this workflow change

Local execution used Node 22.19.0 and npm 11.8.0 in an isolated checkout. The
workflow's locked dependency install with scripts disabled, build/type checks,
and 131 unit tests passed with zero failed or skipped tests. Staged packing,
a new consumer directory with an empty cache, entrypoint checks, and
`npm publish --dry-run` passed. `actionlint` passed. The source identity check
accepted the intended identity and rejected a different package, repository,
tag, and invalid version. These are local package and workflow checks; hosted
OIDC signing, SLSA verification, npm publication, and real-host acceptance are
not claimed by these results.

## Source CI

`.github/workflows/ci.yml` uses pinned actions, this checkout's locked and
vendored dependencies, mandatory source checks, and the same staged packaging
and clean-consumer commands exercised locally. Existing workflow/job check names
are retained. No typecheck failure is downgraded to a warning, no real-host test
is reported successful because credentials are absent, and no legacy normal-home
smoke cleanup is executed. CI does not publish.

The `test` job also retains `npm run test:live` as a mandatory legacy live API
regression. It checks out public `backbay-labs/chio` at kernel source
`d8c5f53705173e614a853bad6c0a85acfdf1212b` and public
`backbay-labs/chio-test-harness` at
`05945ccf4f652a22801c9ab35cabf99456ef76c9`. It builds the selected CLI with Cargo's
lockfile and the kernel's pinned Rust toolchain. The harness uses a new HOME and
XDG directories; delete denial targets a newly created disposable sentinel and
checks its contents independently. It never targets a host configuration file.
The live suite includes legacy compatibility assertions and is not a replacement
for required-host I01-I08 cases. If this source commit has not reached the public
mirror, checkout fails; no old public binary is substituted. The owning kernel
repository's required CI and release qualification remain additional gates.

### Enforced promotion prerequisites

A tag build fails before publication unless the `npm` environment exists and the latest `ci.yml` push run on
`main` for the exact tag commit is completed successfully. The publication job
checks both conditions again when the configured environment permits the job. Missing API access,
missing environment configuration, pending, skipped, cancelled or failed CI is a
release failure. Configure the environment before creating a release tag; a
workflow reference alone can otherwise create an environment implicitly. Existing
protection rules remain enforced by GitHub; this workflow does not require adding
reviewers or changing them.

These checks enforce this repository's source/package CI and configured environment boundary.
They do not establish kernel security or any host acceptance gate. Release
qualification must separately verify the selected kernel's exact-source CI and Release
Qualification, immutable artifact identity, and all applicable I01-I08 evidence.
The workflow does not publish on manual dispatch. No environment or repository
setting was changed by this local workflow repair.

## Live API compatibility qualification

On 2026-09-09 the repaired live suite passed 16 of 16 cases, with zero skips,
against kernel source `d8c5f53705173e614a853bad6c0a85acfdf1212b`, binary SHA-256
`33dd1dea21a4ca5ecddeab4f30f6b06b0b90c513f0987aef552b0633d9da1e25`,
Node 22.19.0, npm 11.8.0, and harness commit
`05945ccf4f652a22801c9ab35cabf99456ef76c9`. The workspace and HOME were disposable.
The harness trust process owns durable admission; the MCP process is a remote
participant with an independent persisted identity.

The suite explicitly executes echo, verifies trusted request-bound receipt and
claimed output bytes, queries real receipts, creates passports for the explicit
caller, exercises lifecycle revocation, and starts a wrapped real MCP edge.
A forbidden delete targets a new disposable sentinel and an independent file
read confirms the original bytes remain. That capability prefilter response has
no signed execution envelope, so the negative observation is not an I06 claim.

Legacy behavior removed from the assertions is not supported delivery:

- `check()` is policy evaluation. Full evaluation needs an explicit output
  fixture and receipt/session stores. Each independent CLI fixture evaluation
  gets separate state because its fixed request identity must not be reused for
  different parameters. No tool is dispatched by a check.
- A fresh passport store cannot manufacture evidence by implicitly calling echo.
  The caller's exact public key is required; arbitrary latest-subject inference
  is disabled.
- Administrative issue-then-revoke is not attenuation. Unsupported attenuation
  remains disabled and its rejection is exercised.
- Unbound budget prechecks are rejected by the durable authority. Five zero-cost
  checks do not establish budget accounting. Actual bound execution budgets
  require their separate kernel/host cases.
- Proof-required export rejects uncheckpointed receipts and produces no file.
  Explicit raw export discloses uncheckpointed coverage and remains unverified
  until independent signer, request and result verification.

Earlier runs exposed split-database startup rejection, stale effectful precheck
assumptions, unsupported CLI flag placement, implicit receipt-read scope, missing
checkpoint coverage, and retained-request conflicts. Their failures are retained
in the qualification record; none was accepted as a successful effect. This API
suite is additional CI coverage, not real-host I01-I08 acceptance or public release.
