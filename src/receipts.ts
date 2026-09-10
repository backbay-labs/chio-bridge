import { writeFile } from "node:fs/promises";
import { verifyReceipt, verifyReceiptJson, parseReceiptJson } from "@chio-protocol/sdk/invariants";
import type { ChioReceipt } from "@chio-protocol/sdk/invariants";
import type { DaemonClient } from "./client/daemon.js";
import { ChioBridgeError, NotInitializedError } from "./errors.js";

export interface ReceiptListOptions {
  since?: Date;
  until?: Date;
  limit?: number;
  capabilityId?: string;
  toolServer?: string;
  toolName?: string;
}

export interface ReceiptStreamOptions {
  since?: Date;
  pollIntervalMs?: number;
  signal?: AbortSignal;
}

export async function listReceipts(
  daemon: DaemonClient | undefined,
  opts: ReceiptListOptions = {},
): Promise<ChioReceipt[]> {
  if (!daemon) {
    throw new NotInitializedError(
      "receipts() requires daemon mode; construct via ChioBridge.fromDaemon({...})",
    );
  }
  const client = daemon.receiptQueryClient();
  const params: Record<string, unknown> = {};
  if (opts.since) params.since = Math.floor(opts.since.getTime() / 1000);
  if (opts.until) params.until = Math.floor(opts.until.getTime() / 1000);
  if (opts.limit !== undefined) params.limit = opts.limit;
  if (opts.capabilityId) params.capabilityId = opts.capabilityId;
  if (opts.toolServer) params.toolServer = opts.toolServer;
  if (opts.toolName) params.toolName = opts.toolName;
  const res = await client.query(params);
  return res.receipts;
}

export async function* streamReceipts(
  daemon: DaemonClient | undefined,
  opts: ReceiptStreamOptions = {},
): AsyncIterable<ChioReceipt> {
  if (!daemon) {
    throw new NotInitializedError(
      "receiptStream() requires daemon mode; construct via ChioBridge.fromDaemon({...})",
    );
  }
  const client = daemon.receiptQueryClient();
  const poll = opts.pollIntervalMs ?? 2000;
  let since = opts.since ? Math.floor(opts.since.getTime() / 1000) : Math.floor(Date.now() / 1000);
  const seen = new Set<string>();
  while (!opts.signal?.aborted) {
    const res = await client.query({ since });
    for (const r of res.receipts) {
      if (seen.has(r.id)) continue;
      seen.add(r.id);
      if (typeof r.timestamp === "number" && r.timestamp >= since) {
        since = r.timestamp;
      }
      yield r;
    }
    await sleep(poll, opts.signal);
  }
}

export function verifyReceiptValue(input: ChioReceipt | string): boolean {
  const v = typeof input === "string" ? verifyReceiptJson(input) : verifyReceipt(input);
  return v.signature_valid && v.parameter_hash_valid;
}

export function parseReceipt(text: string): ChioReceipt {
  return parseReceiptJson(text);
}

/** A requested scope, not authority: the service must authenticate and authorize it. */
export type ReceiptReadBoundary = { kind: "admin_all" } | { kind: "tenant_scoped"; tenant: string };

export interface ExportEvidenceOptions {
  since: Date;
  until?: Date;
  outPath: string;
  /** Explicit operator selection. Never infer administrative access from an omitted tenant. */
  readBoundary: ReceiptReadBoundary;
  /** Ask the kernel to reject evidence without required checkpoint coverage. Default false. */
  requireProofs?: boolean;
}

export async function exportEvidence(
  daemon: DaemonClient | undefined,
  opts: ExportEvidenceOptions,
): Promise<string> {
  if (!daemon) {
    throw new NotInitializedError(
      "exportEvidence() requires daemon mode; construct via ChioBridge.fromDaemon({...})",
    );
  }
  const supplied = opts.readBoundary;
  if (!supplied || typeof supplied !== "object" ||
      (supplied.kind !== "admin_all" && supplied.kind !== "tenant_scoped")) {
    throw new ChioBridgeError("evidence_read_boundary_required", "exportEvidence() requires an explicit readBoundary authorized by the trust service");
  }
  if (supplied.kind === "tenant_scoped" && (typeof supplied.tenant !== "string" || !supplied.tenant.trim())) {
    throw new ChioBridgeError("invalid_arg", "tenant-scoped evidence export requires a nonempty tenant");
  }
  const boundaryKeys = supplied.kind === "admin_all" ? ["kind"] : ["kind", "tenant"];
  if (Object.keys(supplied).some(key => !boundaryKeys.includes(key))) {
    throw new ChioBridgeError("invalid_arg", "evidence readBoundary contains unsupported fields");
  }
  const readBoundary: ReceiptReadBoundary = supplied.kind === "admin_all"
    ? { kind: "admin_all" } : { kind: "tenant_scoped", tenant: supplied.tenant };
  const since = opts.since instanceof Date ? Math.floor(opts.since.getTime() / 1000) : NaN;
  const until = opts.until instanceof Date ? Math.floor(opts.until.getTime() / 1000) : undefined;
  if (!Number.isSafeInteger(since) || since < 0 ||
      (opts.until !== undefined && (until === undefined || !Number.isSafeInteger(until) || until < since)) ||
      (opts.requireProofs !== undefined && typeof opts.requireProofs !== "boolean")) {
    throw new ChioBridgeError("invalid_arg", "evidence export requires a valid ordered time window and boolean requireProofs");
  }
  const query: Record<string, unknown> = { since, readBoundary };
  if (until !== undefined) query.until = until;
  if (readBoundary.kind === "tenant_scoped") query.tenant = readBoundary.tenant;
  // RemoteEvidenceExportRequest nests filters under query. Top-level filters
  // are ignored by the selected kernel and cannot establish a receipt boundary.
  const body = { query, requireProofs: opts.requireProofs ?? false };

  const res = await daemon.trust<unknown>("POST", "/v1/evidence/export", body);
  if (!res.ok) {
    throw new Error(
      `evidence export failed: HTTP ${res.status}: ${res.raw.slice(0, 300)}`,
    );
  }
  const result = res.data as { bundle?: { query?: Record<string, unknown>; toolReceipts?: unknown[];
    childReceipts?: unknown[]; checkpoints?: unknown[]; capabilityLineage?: unknown[];
    inclusionProofs?: unknown[]; uncheckpointedReceipts?: unknown[] } } | null;
  const bundle = result?.bundle;
  const returnedQuery = bundle?.query;
  const returnedBoundary = returnedQuery?.readBoundary as ReceiptReadBoundary | undefined;
  if (!bundle || !returnedQuery || returnedQuery.since !== since || returnedQuery.until !== until ||
      returnedBoundary?.kind !== readBoundary.kind ||
      (readBoundary.kind === "tenant_scoped" &&
        (returnedBoundary?.kind !== "tenant_scoped" || returnedBoundary.tenant !== readBoundary.tenant || returnedQuery.tenant !== readBoundary.tenant)) ||
      (readBoundary.kind === "admin_all" && returnedQuery.tenant !== undefined) ||
      ![bundle.toolReceipts, bundle.childReceipts, bundle.checkpoints, bundle.capabilityLineage,
        bundle.inclusionProofs, bundle.uncheckpointedReceipts].every(Array.isArray)) {
    throw new ChioBridgeError("evidence_invalid", "evidence export response is malformed or differs from the requested receipt boundary/time window");
  }
  // Preserve the service response for independent cryptographic verification.
  // Exporting it does not assert trusted-signer or claimed-result verification.
  await writeFile(opts.outPath, JSON.stringify(res.data, null, 2), { encoding: "utf8", mode: 0o600, flag: "wx" });
  return opts.outPath;
}

function sleep(ms: number, signal?: AbortSignal): Promise<void> {
  return new Promise((resolve) => {
    const timer = setTimeout(resolve, ms);
    if (signal) {
      const handler = () => {
        clearTimeout(timer);
        resolve();
      };
      if (signal.aborted) handler();
      else signal.addEventListener("abort", handler, { once: true });
    }
  });
}
