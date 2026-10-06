// SPDX-License-Identifier: AGPL-3.0-only
// The only vendor-aware transport policy. This endpoint is private Container outbound interception,
// never a public Worker route. Business admission and mutation fencing remain Commerce responsibilities.
export interface CommerceEgressEnvironment {
  COMMERCE_EGRESS?: string;
}
export const requestByteLimit = 32 * 1024;
export const responseByteLimit = 16 * 1024 * 1024;
// A reply is buffered for exact bounds before forwarding. Keep at most two such replies live
// per Worker isolate, including downstream body consumption; never accumulate unbounded queues.
export const maxConcurrentTransports = 2;
let activeTransports = 0;
const durationLimitMs = 30_000;
const productionHost = "api.paddle.com";
const sandboxHost = "sandbox-api.paddle.com";
const reference = (value: string, prefix: string) =>
  new RegExp(`^${prefix}_[a-z0-9]{26}$`, "u").test(value);

export function commerceTransportEnvironment(
  env: CommerceEgressEnvironment,
): Record<string, string> {
  if (env.COMMERCE_EGRESS === undefined || env.COMMERCE_EGRESS === "disabled") return {};
  if (env.COMMERCE_EGRESS !== "production" && env.COMMERCE_EGRESS !== "sandbox")
    throw new Error("Invalid commerce egress configuration");
  return { ARCFORGES_COMMERCE_EGRESS: "enabled" };
}

function admittedQuery(url: URL, resource: string, individual: boolean): boolean {
  const seen = new Set<string>();
  for (const [key, value] of url.searchParams) {
    if (seen.has(key)) return false;
    seen.add(key);
    if (individual) {
      if (key !== "include" || value !== (resource === "prices" ? "product" : "address"))
        return false;
    } else if (key === "per_page") {
      if (!/^([1-9]|[1-9][0-9]|1[0-9]{2}|200)$/u.test(value)) return false;
      if (resource !== "events" && Number(value) > 30) return false;
    } else if (key === "after") {
      const prefix = (
        { transactions: "txn", subscriptions: "sub", adjustments: "adj", events: "evt" } as Record<
          string,
          string
        >
      )[resource];
      if (!prefix || !reference(value, prefix)) return false;
    } else if (key === "include") {
      if (resource !== "transactions" || value !== "address") return false;
    } else if (key === "id") {
      if (resource !== "adjustments" || !reference(value, "adj")) return false;
    } else if (key === "order_by") {
      if (resource !== "events" || value !== "id[ASC]") return false;
    } else if (key === "updated_at[GTE]" || key === "updated_at[LTE]") {
      if (
        resource !== "transactions" ||
        !/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d{1,6})?Z$/u.test(value)
      )
        return false;
    } else return false;
  }
  return true;
}

function admittedPath(request: Request, url: URL): boolean {
  if (url.pathname.includes("%") || url.pathname.includes("\\") || url.pathname.length > 256)
    return false;
  const segments = url.pathname.split("/");
  if (segments[0] !== "" || segments.some((segment, index) => index > 0 && segment === ""))
    return false;
  const resource = segments[1] ?? "";
  const id = segments[2] ?? "";
  if (request.method === "GET") {
    if (
      segments.length === 2 &&
      ["transactions", "subscriptions", "adjustments", "events"].includes(resource)
    )
      return admittedQuery(url, resource, false);
    const prefix = (
      { prices: "pri", transactions: "txn", subscriptions: "sub" } as Record<string, string>
    )[resource];
    return (
      segments.length === 3 &&
      !!prefix &&
      reference(id, prefix) &&
      admittedQuery(url, resource, true) &&
      (resource !== "subscriptions" || url.search === "")
    );
  }
  if (url.search !== "") return false;
  if (request.method === "POST")
    return (
      (segments.length === 2 && ["transactions", "adjustments"].includes(resource)) ||
      (segments.length === 4 &&
        resource === "subscriptions" &&
        reference(id, "sub") &&
        segments[3] === "cancel") ||
      (segments.length === 4 &&
        resource === "customers" &&
        reference(id, "ctm") &&
        segments[3] === "portal-sessions")
    );
  return (
    request.method === "PATCH" &&
    segments.length === 3 &&
    resource === "subscriptions" &&
    reference(id, "sub")
  );
}

function failure(status: number): Response {
  return new Response("Commerce transport unavailable", {
    status,
    headers: {
      "content-type": "text/plain; charset=utf-8",
      "cache-control": "no-store",
      ...(status === 429 ? { "retry-after": "1" } : {}),
    },
  });
}

async function boundedBytes(
  body: ReadableStream<Uint8Array> | null,
  declared: string | null,
  maximum: number,
  signal: AbortSignal,
  checkLifetime: () => void,
): Promise<Uint8Array> {
  checkLifetime();
  if (
    declared !== null &&
    (declared.length > 20 ||
      !/^(0|[1-9][0-9]*)$/u.test(declared) ||
      BigInt(declared) > BigInt(maximum))
  )
    throw new Error("Body bound");
  if (!body) {
    if (declared !== null && declared !== "0") throw new Error("Body length");
    return new Uint8Array();
  }
  const reader = body.getReader();
  let buffer = new Uint8Array(Math.min(maximum, 64 * 1024));
  let bytes = 0;
  const abort = () => {
    void reader.cancel().catch(() => undefined);
  };
  signal.addEventListener("abort", abort, { once: true });
  try {
    checkLifetime();
    for (;;) {
      const part = await reader.read();
      checkLifetime();
      if (part.done) break;
      const length = bytes + part.value.byteLength;
      if (length > maximum) throw new Error("Body bound");
      if (length > buffer.length) {
        const grown = new Uint8Array(Math.min(maximum, Math.max(length, buffer.length * 2)));
        grown.set(buffer.subarray(0, bytes));
        buffer = grown;
      }
      buffer.set(part.value, bytes);
      bytes = length;
    }
    if (declared !== null && BigInt(declared) !== BigInt(bytes)) throw new Error("Body length");
    // Fragment count and provider-owned backing buffers cannot inflate retained memory.
    return buffer.slice(0, bytes);
  } catch (error) {
    void reader.cancel().catch(() => undefined);
    throw error;
  } finally {
    signal.removeEventListener("abort", abort);
    reader.releaseLock();
  }
}

export async function handleCommerceEgress(
  request: Request,
  env: CommerceEgressEnvironment,
  fetcher: typeof fetch = fetch,
  durationMs = durationLimitMs,
): Promise<Response> {
  if (env.COMMERCE_EGRESS !== "production" && env.COMMERCE_EGRESS !== "sandbox")
    return failure(503);
  if (!Number.isSafeInteger(durationMs) || durationMs < 1 || durationMs > durationLimitMs)
    throw new Error("Invalid commerce transport deadline");
  const url = new URL(request.url);
  const host = env.COMMERCE_EGRESS === "production" ? productionHost : sandboxHost;
  if (
    url.protocol !== "https:" ||
    url.hostname !== host ||
    (url.port !== "" && url.port !== "443") ||
    url.username !== "" ||
    url.password !== "" ||
    url.hash !== "" ||
    request.url.length > 2048 ||
    !admittedPath(request, url)
  )
    return failure(403);
  const authorization = request.headers.get("authorization");
  if (
    !authorization ||
    !/^Bearer [!-~]{16,512}$/u.test(authorization) ||
    request.headers.get("paddle-version") !== "1" ||
    request.headers.has("content-encoding")
  )
    return failure(403);
  const mutating = request.method !== "GET";
  if (mutating && request.headers.get("content-type")?.toLowerCase() !== "application/json")
    return failure(403);
  if (activeTransports >= maxConcurrentTransports) return failure(429);
  activeTransports++;
  const controller = new AbortController();
  const abort = () => controller.abort();
  const deadline = Date.now() + durationMs;
  const checkLifetime = () => {
    // Resolved stream reads can keep the microtask queue busy; elapsed checks also enforce
    // the deadline when the timer task cannot run between empty or very small fragments.
    if (Date.now() >= deadline) abort();
    controller.signal.throwIfAborted();
  };
  request.signal.addEventListener("abort", abort, { once: true });
  if (request.signal.aborted) controller.abort();
  const timer = setTimeout(abort, durationMs);
  let dispatched = false;
  let transferred = false;
  let finished = false;
  let upstream: Response | undefined;
  let reply: Uint8Array | undefined;
  let streamAbort: (() => void) | undefined;
  const finish = () => {
    if (finished) return;
    finished = true;
    reply = undefined;
    activeTransports--;
    clearTimeout(timer);
    request.signal.removeEventListener("abort", abort);
    if (streamAbort) controller.signal.removeEventListener("abort", streamAbort);
  };
  try {
    const bytes = await boundedBytes(
      request.body,
      request.headers.get("content-length"),
      requestByteLimit,
      controller.signal,
      checkLifetime,
    );
    if (mutating !== bytes.byteLength > 0) return failure(403);
    controller.signal.throwIfAborted();
    const headers = new Headers({
      authorization,
      "paddle-version": "1",
      accept: "application/json",
    });
    if (mutating) headers.set("content-type", "application/json");
    // Always build a fresh request from the validated fixed destination and closed headers.
    // Redirects never forward the bearer credential. No mutation or read is retried here.
    dispatched = true;
    const response = await fetcher(
      new Request(url, {
        method: request.method,
        headers,
        body: mutating ? (bytes as BodyInit) : undefined,
        redirect: "manual",
        signal: controller.signal,
      }),
    );
    upstream = response;
    if ((response.status >= 300 && response.status < 400) || response.redirected) {
      void response.body?.cancel().catch(() => undefined);
      return failure(502);
    }
    reply = await boundedBytes(
      response.body,
      response.headers.get("content-length"),
      responseByteLimit,
      controller.signal,
      checkLifetime,
    );
    const resultHeaders = new Headers({ "cache-control": "no-store" });
    const type = response.headers.get("content-type");
    if (type?.toLowerCase().startsWith("application/json"))
      resultHeaders.set("content-type", "application/json");
    const retry = response.headers.get("retry-after");
    if (retry !== null && /^(0|[1-9][0-9]{0,3})$/u.test(retry))
      resultHeaders.set("retry-after", retry);
    if ([204, 205, 304].includes(response.status) || reply.length === 0)
      return new Response(null, { status: response.status, headers: resultHeaders });
    controller.signal.throwIfAborted();
    let offset = 0;
    const body = new ReadableStream<Uint8Array>(
      {
        start(output) {
          streamAbort = () => {
            output.error(new Error("Commerce transport canceled"));
            finish();
          };
          controller.signal.addEventListener("abort", streamAbort, { once: true });
        },
        pull(output) {
          if (!reply) return;
          const end = Math.min(reply.length, offset + 64 * 1024);
          // A consumer-held chunk must not retain the complete bounded upstream allocation.
          output.enqueue(reply.slice(offset, end));
          offset = end;
          if (offset === reply.length) {
            output.close();
            finish();
          }
        },
        cancel() {
          controller.abort();
          finish();
        },
      },
      { highWaterMark: 0 },
    );
    const result = new Response(body, { status: response.status, headers: resultHeaders });
    transferred = true;
    return result;
  } catch {
    const wasAborted = controller.signal.aborted;
    controller.abort();
    void upstream?.body?.cancel().catch(() => undefined);
    // Any failure after dispatch must remain ambiguous to COM01, especially for a mutation.
    if (dispatched) return failure(wasAborted ? 504 : 502);
    return failure(wasAborted ? 408 : 413);
  } finally {
    if (!transferred) finish();
  }
}

export const commerceOutboundHosts = {
  [productionHost]: (request: Request, env: CommerceEgressEnvironment) =>
    handleCommerceEgress(request, env),
  [sandboxHost]: (request: Request, env: CommerceEgressEnvironment) =>
    handleCommerceEgress(request, env),
};
