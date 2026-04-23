import { ChioClient, ReceiptQueryClient } from "@chio-protocol/sdk";
import { DaemonUnreachableError } from "../errors.js";
import { DEFAULT_MCP_EDGE_URL, DEFAULT_TRUST_URL, type DaemonOptions } from "../types.js";

export interface TrustHttpResponse<T> {
  ok: boolean;
  status: number;
  data: T;
  raw: string;
}

export class DaemonClient {
  readonly mcpEdgeUrl: string;
  readonly trustUrl: string;
  readonly token: string;
  readonly fetchImpl: typeof fetch;

  constructor(options: DaemonOptions) {
    this.mcpEdgeUrl = (options.mcpEdgeUrl ?? DEFAULT_MCP_EDGE_URL).replace(/\/$/, "");
    this.trustUrl = (options.trustUrl ?? DEFAULT_TRUST_URL).replace(/\/$/, "");
    this.token = options.token;
    this.fetchImpl = options.fetchImpl ?? globalThis.fetch;
  }

  mcpClient(): ChioClient {
    return ChioClient.withStaticBearer(this.mcpEdgeUrl, this.token, this.fetchImpl);
  }

  receiptQueryClient(): ReceiptQueryClient {
    return new ReceiptQueryClient(this.trustUrl, this.token, this.fetchImpl);
  }

  async trust<T = unknown>(
    method: string,
    path: string,
    body?: unknown,
    headers: Record<string, string> = {},
  ): Promise<TrustHttpResponse<T>> {
    const url = `${this.trustUrl}${path.startsWith("/") ? path : `/${path}`}`;
    const init: RequestInit = {
      method,
      headers: {
        Authorization: `Bearer ${this.token}`,
        ...(body !== undefined ? { "Content-Type": "application/json" } : {}),
        ...headers,
      },
    };
    if (body !== undefined) init.body = JSON.stringify(body);

    let response: Response;
    try {
      response = await this.fetchImpl(url, init);
    } catch (cause) {
      throw new DaemonUnreachableError(
        `trust plane unreachable at ${url}: ${(cause as Error).message}`,
        this.trustUrl,
        cause,
      );
    }

    const raw = await response.text();
    let data: T;
    try {
      data = raw.length === 0 ? (undefined as T) : (JSON.parse(raw) as T);
    } catch {
      data = raw as unknown as T;
    }
    return { ok: response.ok, status: response.status, data, raw };
  }
}
