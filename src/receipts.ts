import { writeFile } from "node:fs/promises";
import { verifyReceipt, verifyReceiptJson, parseReceiptJson } from "@chio-protocol/sdk/invariants";
import type { ChioReceipt } from "@chio-protocol/sdk/invariants";
import type { DaemonClient } from "./client/daemon.js";
import { NotInitializedError } from "./errors.js";

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

export interface ExportEvidenceOptions {
  since: Date;
  until?: Date;
  outPath: string;
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
  const since = Math.floor(opts.since.getTime() / 1000);
  const until = opts.until ? Math.floor(opts.until.getTime() / 1000) : undefined;
  const body: Record<string, unknown> = { since };
  if (until !== undefined) body.until = until;

  const res = await daemon.trust<unknown>("POST", "/v1/evidence/export", body);
  if (!res.ok) {
    throw new Error(
      `evidence export failed: HTTP ${res.status}: ${res.raw.slice(0, 300)}`,
    );
  }
  await writeFile(opts.outPath, JSON.stringify(res.data, null, 2), "utf8");
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
