// Thin JSON-RPC 2.0 client for the Aithos platform reads endpoint.
//
// All read primitives (§10.5) are anonymous, so we just POST with the
// ambient fetch. Errors come back in the `error` field; we surface them as
// thrown `AithosRpcError` so React routes can branch on `.code` (§10.9).

const DEFAULT_ENDPOINT =
  "https://api.aithos.be";

export interface JsonRpcErrorShape {
  readonly code: number;
  readonly message: string;
  readonly data?: Record<string, unknown>;
}

export class AithosRpcError extends Error {
  readonly code: number;
  readonly data: Record<string, unknown> | undefined;

  constructor(err: JsonRpcErrorShape) {
    super(err.message);
    this.name = "AithosRpcError";
    this.code = err.code;
    this.data = err.data;
  }
}

export interface RpcOptions {
  readonly baseUrl?: string;
  readonly signal?: AbortSignal;
}

export async function readRpc<T>(
  method: string,
  params: unknown,
  opts?: RpcOptions,
): Promise<T> {
  const base = opts?.baseUrl ?? DEFAULT_ENDPOINT;
  const res = await fetch(`${base}/mcp/primitives/read`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({
      jsonrpc: "2.0",
      id: method,
      method,
      params,
    }),
    signal: opts?.signal,
  });
  if (!res.ok) {
    throw new Error(`HTTP ${res.status} ${res.statusText}`);
  }
  const body = (await res.json()) as {
    result?: T;
    error?: JsonRpcErrorShape;
  };
  if (body.error) throw new AithosRpcError(body.error);
  if (body.result === undefined) {
    throw new Error(`empty result from ${method}`);
  }
  return body.result;
}
