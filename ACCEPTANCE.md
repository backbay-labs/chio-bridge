# Shared bridge integration candidate

Version 0.3.0 is unaccepted for the six-host program. Component and fixture
checks are not real-host acceptance. The candidate bundles the exact current
SDK tarball under vendor, so installation does not require private siblings.
No registry publication or supported production release is claimed.

## Contract changes

- check() evaluates CLI policy only and never calls an effecting MCP tool.
- Budget admission errors, timeouts, malformed responses and missing authority
  deny. No zero-cost fallback or fabricated kernel receipt is emitted.
- Administrative issue-then-revoke attenuation is disabled because it cannot
  prove narrowing or preserve an aggregate parent budget.
- createMcpExecutionClient executes through the kernel MCP edge only. It checks
  the operator-pinned session caller and capability before dispatch, verifies
  the trusted receipt, exact request and raw output, and requires signed durable
  admission completion metadata before returning completed.
- Gateway responses preserve a completed invocation whose underlying MCP tool
  returned `isError: true` as a tool error; invocation and tool-result states stay distinct.
- Missing or invalid post-dispatch evidence produces unknown. A verified deny
  is only a decision and can follow an effect; callers must not infer prevention.

## Operator procedure

1. Install the checksum-verified bridge tarball, Node >=22, and the matching
   kernel candidate. Keep the kernel and protected resource outside the host's
   writable/configuration boundary. Use different agent and admin credentials.
2. Start the kernel MCP edge with durable_admission_mode: all and persistent
   authority, budget, receipt, revocation and session stores. Expose a constrained
   resource server. Hosts must have no direct resource mount or Docker socket.
3. Write a private (0600) operator request JSON with endpoint, bearerToken,
   trustedSigners (operator-selected kernel public keys), serverId, journalDir,
   sessionId (logical host session), and allowedTools (explicit tool names).
   The endpoint is the origin, for example `http://127.0.0.1:8931`, without
   `/mcp` (the SDK appends that path). Use HTTPS or literal loopback HTTP. The kernel policy must issue
   one capability containing the selected grants.
4. Run `chio-prepare-gateway request.json /absolute/gateway-config.json`.
   It initializes the kernel session, reads its assigned authority and tool
   inventory, and writes a private configuration. It executes no tool. Retain
   this kernel session; creating a fresh one can change authority and budgets.
5. Configure the restricted host's sole MCP server as
   `chio-mcp-gateway /absolute/gateway-config.json`. Disable native, custom,
   background, delegation, resource/prompt and user-discovered tool routes in
   that host mode. The gateway exposes only the operator-selected tool list.
6. Keep config and the 0700 journal in the trusted process boundary. The journal
   records pending before dispatch, fsyncs results, and returns retained outcomes
   for identical IDs. It refuses changed identity/arguments/configuration.

## Recovery, upgrade and removal

An unknown or denied operation fences later dispatch, including after restart.
Do not erase its journal, invent another operation/session ID, or automatically
retry. The operator must inspect the independently owned resource and kernel
admission record. Preserve the original evidence and resolve the outcome before
starting a separately authorized session. A stale gateway.lock after a process
crash likewise requires confirming the old process is dead and reconciling all
pending records before removing only that lock. No automatic reaper is provided.

Graceful gateway EOF closes its local lock but retains the kernel session and
journal. During upgrade stop host admission, finish/reconcile in-flight work,
retain configuration and journals, verify new artifact identities, then restart.
Incompatible authority/configuration is refused. For removal stop the host and
gateway, revoke/close the kernel session using the trusted operator control path,
then remove the host MCP entry and package. Preserve audit records per operator
retention policy. Do not delete another agent's normal profile or citizen state.

## Remaining qualification

Real kernel/host useful work, I01-I08 for every host, authentication failure
cutpoints, budget/approval semantics, streaming (unsupported by this value-only
client), actual restart/upgrade/removal and publication remain unresolved until
recorded separately. The client interlock does not replace kernel/resource
transaction ownership. A denied output can follow delivery, so denial remains
conservatively fenced until resource reconciliation.

## Reproducible candidate packaging

The source manifest references the checksum-named SDK tarball committed under
`vendor/`; it does not require an adjacent SDK checkout or a published candidate.
The SDK candidate is `0.1.1-rc.1`, SHA-256
`ea8639364db147ed0a9d590f58d532f93c84200a47c3245b1facdaf8f776eb90`.

Run `npm ci`, `npm run typecheck`, `npm test`, then
`npm run pack:release -- /absolute/output-directory`. The packaging command
builds first, copies npm-selected release files and the complete installed
production dependency tree into a temporary directory, pins dependency versions
in that directory, bundles them, and writes an artifact plus `.sha256` sidecar.
The source manifest and lockfile remain unchanged. Direct `npm pack` is refused
to prevent delivery of an artifact that requires an unpublished dependency.

For a plugin using this tarball, keep its source dependency as a vendored file,
set `install-strategy=nested`, and omit source `bundleDependencies`. npm can
otherwise try to resolve the bundled candidate SDK from the public registry.
Add bundling only in a separate release stage after dependency installation.
Qualification must install the resulting tarball in an independent directory
with an empty npm cache and `--offline --ignore-scripts`, then import and exercise
its runtime. Package installation is a delivery check, not host acceptance.

Local component validation on 2026-09-09: Node 25.5.0, npm 11.8.0, Darwin arm64;
TypeScript typecheck and 79 component tests passed with zero skips. This includes
queued cancellation before kernel contact, retained unknown outcomes after a
signed replay denial, and completed invocations returning MCP tool errors.
These results do not close any host's I01-I08 record.
