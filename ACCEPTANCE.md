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
- Execution requires authenticated scoped session context and delivery
  acknowledgement version 1. The client never initializes another session.
  `execute()` returns a verified completion with its exact delivery binding;
  it does not acknowledge automatically. Durable owners save that outcome before
  calling `acknowledge()`. The gateway follows this order and revalidates cached
  signed results against the retained request on restart.

## Operator procedure

1. Install the checksum-verified bridge tarball, Node >=22, and the matching
   kernel candidate. Keep the kernel and protected resource outside the host's
   writable/configuration boundary. Use different agent and admin credentials.
2. Start the kernel MCP edge with durable_admission_mode: all and persistent
   authority, budget, receipt, revocation and session stores. Expose a constrained
   resource server. Hosts must have no direct resource mount or Docker socket.
3. Write a private (0600) operator request JSON with endpoint, bearerToken,
   adminToken (distinct from bearerToken), credentialTtlSeconds (integer 1..3600),
   trustedSigners (operator-selected kernel public keys), serverId, journalDir,
   sessionId (logical host session), and allowedTools (explicit tool names).
   The endpoint is the origin, for example `http://127.0.0.1:8931`, without
   `/mcp` (the SDK appends that path). Use HTTPS or literal loopback HTTP. The kernel policy must issue
   one capability containing the selected grants.
4. Run `chio-prepare-gateway request.json /absolute/gateway-config.json`.
   It initializes the kernel session, reads its assigned authority and tool
   inventory, and exchanges the operator-only admin credential at
   `POST /admin/sessions/{sessionId}/credential` for a session bearer restricted
   by the kernel to that session, capability, server, selected tools and lifetime.
   It checks the returned binding and confirms the delegated execution context
   before writing a private configuration. Only the delegated bearer is stored;
   the original bootstrap and admin credentials stay in the operator request,
   outside the host's readable process boundary. The response is authenticated
   transport, not a client-verified signature. Public scope and expiry metadata
   are retained as `sessionCredential` for operator inspection. An absent or
   incompatible credential endpoint fails preparation; there is no static-bearer
   fallback. Preparation executes no tool. Retain this kernel session; creating
   a fresh one can change authority and budgets.
5. In a confined host launcher, call `startGatewayHttp(config)` in the trusted
   launcher process and configure the host's sole MCP server with its returned
   `url` and `Authorization: Bearer <token>`. Close the transport when the host
   exits. Keep the retained gateway config and journal outside the guest sandbox;
   allow guest network access only to this transport and its separately bounded
   model relay. The guest must not have direct kernel egress. The transport dies
   with the launcher, so detached descendants cannot retain its resource route.
   `chio-mcp-gateway /absolute/gateway-config.json` remains a stdio interface for
   separately qualified process boundaries. Disable native, custom,
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
pending records before removing only that lock. Use
`chio-gateway-operator status /absolute/gateway-config.json` to inspect local
state, then `chio-gateway-operator recover-lock /absolute/gateway-config.json`.
Recovery checks same-machine ownership, proves the recorded PID is dead, detects
concurrent recovery or lock replacement, and retains all operation journals.
It never resolves an unknown resource outcome. No automatic reaper is provided.

Graceful gateway EOF closes its local lock but retains the kernel session and
journal. During upgrade stop host admission, finish/reconcile in-flight work,
retain configuration and journals, verify new artifact identities, then restart.
Incompatible authority/configuration is refused. For removal stop the host and
gateway, revoke/close the kernel session using the trusted operator control path,
then remove the host MCP entry and package. Preserve audit records per operator
retention policy. Do not delete another agent's normal profile or citizen state.

The delegated credential expires no later than the requested TTL and the
underlying capability expiry. There is no automatic credential renewal or
session recreation. Stop admission before expiry and have the trusted operator
reconcile outstanding work before issuing a new bounded credential. A delegated
bearer cannot initialize another session or use administration, resources,
prompts, unsolicited GET events, or tools outside its recorded allowlist.
Keep the gateway and its journal in a process boundary the host cannot mutate;
credential restrictions alone do not make a host-owned journal trustworthy.

## Explicit approval proposals

Set `approval` in the operator-owned gateway config, for example
`{"requiredTools":["write_file"],"purpose":"Review exact content","ttlSeconds":300}`.
The kernel policy must independently require confirmation for those operations.
An ordinary call returns `awaiting_approval` and retains its exact proposal
without contacting kernel `tools/call`. The host cannot execute different work
through that gateway while the proposal remains unresolved.

The operator uses the returned request ID with these commands:

```sh
chio-gateway-operator approval-submit /absolute/gateway-config.json REQUEST_ID /absolute/operator.json /absolute/new-submission.json
chio-gateway-operator approval-decide /absolute/gateway-config.json REQUEST_ID /absolute/operator.json APPROVAL_ID approved
```

Use `denied` for rejection. The operator file supplies only an `adminToken` and
must remain outside every guest profile. The decision command writes a signed
exact-action artifact into the retained gateway's approvals directory; it never
dispatches the action. The host explicitly calls the virtual `chio_resume` tool
with the returned request ID, original tool and exact arguments. The gateway
verifies the operator signature, session, capability, request, parameters and
expiry before submitting that original request through normal kernel admission.
Unknown dispatched outcomes are never converted into proposals or retried by
this mechanism. Approval tokens cannot prove a resource effect completed.

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
TypeScript typecheck and 115 component tests passed with zero skips. This includes
16 spawned-CLI preparation cases with independent HTTP request observations,
queued cancellation before kernel contact, retained unknown outcomes after a
signed replay denial, and completed invocations returning MCP tool errors.
These results do not close any host's I01-I08 record.

The acknowledgement/HTTP source passed two additional real-kernel scenarios:
six ordinary-work checks and seven approval checks, with zero skips. The
independent filesystem observer recorded allowed write/read calls, no forbidden
read dispatch, one explicitly approved write, no dispatch for pending/rejected
proposals, no redispatch on completed resume, and no new effect after transport
closure. The kernel binary SHA256 was
`0e683f6f7cc8f21816b10641e3c18fba2dd1445fbcd28752cd3260d8ac5edb5a`;
the audited resource image was
`sha256:188cb84d5d0bb4063d4ce5a3b9c3832445a5acda5604911cda80a9136d1850a0`.
Source evidence is under `evidence/20260909/ack-http/`. These runs used source
build output; the newly packed consumer and all real hosts require separate
artifact runs. The exact reusable driver is `test/live/required-gateway.mjs`.

The packaged CLI is also exercised through an explicit symlinked installation
parent using `node scripts/verify-packed-cli.mjs /absolute/bridge.tgz`. Direct
module startup and the normal npm bin link respond to initialize and tools/list
without contacting a kernel. `--preserve-symlinks-main` is supported for the
direct module path; combining it with the npm `.bin` symlink is unsupported
because Node resolves package imports from `.bin`, and exits before dispatch.
