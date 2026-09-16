// SPDX-License-Identifier: AGPL-3.0-only
export const helloPath = "/api/arcforges.hello.v1.HelloService/SayHello";
export const healthPath = "/api/healthz";
export const maxBodyBytes = 4096;

export interface CloudBindings {
  SOURCE_REVISION: string;
  CLOUD_CONTAINER: {
    getByName(name: string): { fetch(request: Request): Promise<Response> };
  };
  HELLO_RATE_LIMITER: { limit(options: { key: string }): Promise<{ success: boolean }> };
}

const deadlineError = new Error("RPC deadline exceeded.");
const canceledError = new Error("Request canceled.");
const bodyTimeoutError = new Error("Request body timed out.");
const bodySizeError = new Error("Body size limit exceeded.");

function reject(status: number, message: string): Response {
  return new Response(message, {
    status,
    headers: { "content-type": "text/plain; charset=utf-8", "cache-control": "no-store" },
  });
}

// Binary clients read the terminal gRPC status even when HTTP status is 200.
function rpcError(code: number, message: string): Response {
  const trailer = new TextEncoder().encode(
    `grpc-status: ${code}\r\ngrpc-message: ${encodeURIComponent(message)}\r\n`,
  );
  const frame = new Uint8Array(5 + trailer.length);
  frame[0] = 0x80;
  new DataView(frame.buffer).setUint32(1, trailer.length);
  frame.set(trailer, 5);
  return new Response(frame, {
    headers: { "content-type": "application/grpc-web+proto", "cache-control": "no-store" },
  });
}

function timeoutMs(value: string | null): number | null {
  if (value === null) return 10000;
  const match = /^(\d{1,8})([HMSmun])$/.exec(value);
  if (!match) return null;
  const units: Record<string, number> = {
    H: 3600000,
    M: 60000,
    S: 1000,
    m: 1,
    u: 0.001,
    n: 0.000001,
  };
  return Math.min(10000, Number(match[1]) * (units[match[2] ?? ""] ?? 0));
}

// Enforce the budget even if a binding does not observe Request.signal.
async function bounded<T>(operation: Promise<T>, signal: AbortSignal): Promise<T> {
  if (signal.aborted) {
    void operation.catch(() => {});
    throw signal.reason;
  }
  let aborted: (() => void) | undefined;
  const interrupted = new Promise<never>((_resolve, rejectPromise) => {
    aborted = () => rejectPromise(signal.reason);
    signal.addEventListener("abort", aborted, { once: true });
  });
  try {
    return await Promise.race([operation, interrupted]);
  } finally {
    if (aborted) signal.removeEventListener("abort", aborted);
  }
}

async function readBytes(
  stream: ReadableStream<Uint8Array> | null,
  limit: number,
  signal: AbortSignal,
): Promise<Uint8Array<ArrayBuffer>> {
  signal.throwIfAborted();
  if (!stream) return new Uint8Array();
  const reader = stream.getReader();
  const chunks: Uint8Array[] = [];
  let length = 0;
  try {
    while (true) {
      const { done, value } = await bounded(reader.read(), signal);
      if (done) break;
      length += value.byteLength;
      if (length > limit) throw bodySizeError;
      chunks.push(value);
    }
  } catch (error) {
    // Cancellation itself must not hold up an expired request.
    void reader.cancel().catch(() => {});
    throw error;
  } finally {
    reader.releaseLock();
  }
  const result = new Uint8Array(length);
  let offset = 0;
  for (const chunk of chunks) {
    result.set(chunk, offset);
    offset += chunk.length;
  }
  return result;
}

async function handleRequest(request: Request, env: CloudBindings): Promise<Response> {
  const started = performance.now();
  const url = new URL(request.url);
  const health = url.pathname === healthPath;
  if (!health && url.pathname !== helloPath) return reject(404, "Unknown API method.");
  if (url.search) return reject(400, "Query parameters are not supported.");
  if (request.method !== (health ? "GET" : "POST")) return reject(405, "Method not allowed.");
  const mediaType = request.headers.get("content-type")?.split(";")[0]?.trim().toLowerCase();
  if (
    !health &&
    !["application/grpc-web", "application/grpc-web+proto"].includes(mediaType ?? "")
  ) {
    return reject(415, "Use binary gRPC-Web.");
  }
  if (
    !health &&
    (request.headers.has("content-encoding") ||
      ![null, "identity"].includes(request.headers.get("grpc-encoding")))
  )
    return reject(415, "Compressed requests are not supported.");

  const budget = health ? 15000 : timeoutMs(request.headers.get("grpc-timeout"));
  if (budget === null) return rpcError(3, "Invalid grpc-timeout.");
  if (budget < 1) return rpcError(4, "RPC deadline exceeded.");
  const controller = new AbortController();
  const cancel = () => controller.abort(canceledError);
  request.signal.addEventListener("abort", cancel, { once: true });
  if (request.signal.aborted) cancel();
  const timer = setTimeout(
    () => controller.abort(deadlineError),
    Math.max(0, budget - (performance.now() - started)),
  );
  const signal = controller.signal;
  try {
    signal.throwIfAborted();
    // Cloudflare supplies this header. The limit is not authentication or a billing quota.
    const { success } = await bounded(
      env.HELLO_RATE_LIMITER.limit({
        key: request.headers.get("cf-connecting-ip") ?? "local",
      }),
      signal,
    );
    if (!success) return reject(429, "Hello rate limit exceeded.");
    if (Number(request.headers.get("content-length") ?? "0") > maxBodyBytes) {
      return reject(413, "Request body exceeds 4096 bytes.");
    }

    let body: Uint8Array<ArrayBuffer> | undefined;
    if (!health) {
      const bodyTimer = setTimeout(() => controller.abort(bodyTimeoutError), 5000);
      try {
        body = await readBytes(request.body, maxBodyBytes, signal);
      } catch (error) {
        if (error === bodySizeError) return reject(413, "Request body exceeds 4096 bytes.");
        throw error;
      } finally {
        clearTimeout(bodyTimer);
      }
      if (body[0] === 1) return reject(415, "Compressed requests are not supported.");
    }
    const remaining = Math.floor(budget - (performance.now() - started));
    if (remaining <= 0) throw deadlineError;
    const headers = new Headers();
    if (!health) {
      headers.set("content-type", "application/grpc-web+proto");
      headers.set("x-grpc-web", "1");
      headers.set("grpc-timeout", `${remaining}m`);
    }
    // Strip exactly the owned /api prefix; never forward cookies, auth or arbitrary metadata.
    const target = new URL(url.pathname.slice(4), "http://container");
    const operation = env.CLOUD_CONTAINER.getByName("hello").fetch(
      new Request(target, { method: request.method, headers, body, signal }),
    );
    // A late response from an uncooperative binding must not leave a body open.
    void operation.then(
      (response) => {
        if (signal.aborted) void response.body?.cancel().catch(() => {});
      },
      () => {},
    );
    const response = await bounded(operation, signal);
    if (response.status >= 500) {
      void response.body?.cancel().catch(() => {});
      return reject(503, "Cloud container is temporarily unavailable.");
    }
    // Hello is unary and small. Include response/trailer delivery in the same budget.
    const payload = await readBytes(response.body, 8192, signal);
    const resultHeaders = new Headers(response.headers);
    resultHeaders.set("cache-control", "no-store");
    resultHeaders.set("x-content-type-options", "nosniff");
    resultHeaders.set("x-arcforges-worker-revision", env.SOURCE_REVISION);
    return new Response(payload, { status: response.status, headers: resultHeaders });
  } catch (error) {
    if (error === deadlineError)
      return health ? reject(504, deadlineError.message) : rpcError(4, deadlineError.message);
    if (error === canceledError)
      return health ? reject(499, canceledError.message) : rpcError(1, canceledError.message);
    if (error === bodyTimeoutError)
      return reject(408, "Request body could not be read within five seconds.");
    // No restart loop or RPC replay. Readiness polling is separate from application calls.
    return reject(503, "Cloud container is temporarily unavailable.");
  } finally {
    clearTimeout(timer);
    request.signal.removeEventListener("abort", cancel);
  }
}

export async function routeRequest(
  request: Request,
  env: CloudBindings,
  context?: { waitUntil(promise: Promise<unknown>): void },
): Promise<Response> {
  try {
    return await handleRequest(request, env);
  } finally {
    if (request.body && !request.bodyUsed) {
      // Early rejection can leave an HTTP connection with unread upload bytes. Wrangler's
      // source-mode middleware hides this; the immutable no_bundle artifact has no middleware.
      // Dispose a small upload in the background without extending the RPC deadline or
      // accepting an unlimited body. A stalled/large upload is canceled instead.
      const controller = new AbortController();
      const timer = setTimeout(() => controller.abort(bodyTimeoutError), 1000);
      const cleanup = readBytes(request.body, maxBodyBytes + 1, controller.signal)
        .then(() => {})
        .catch(() => {})
        .finally(() => clearTimeout(timer));
      context?.waitUntil(cleanup);
    }
  }
}
