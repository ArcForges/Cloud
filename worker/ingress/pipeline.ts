// SPDX-License-Identifier: AGPL-3.0-only
// The public /api pipeline of the Worker: exact-method routing from the deny-by-default table,
// binary gRPC-Web admission, the deadline and cancellation budget, edge credential checks and the
// hand-off to the Container over the private binding. The Container port is never exposed: this
// function is the only caller of the Container binding for public requests, and it forwards only
// headers it builds itself. Unary replies are bounded and buffered; a server stream is passed through
// frame by frame (see frames.ts) and never buffered.
import {
  newCorrelationId,
  readRequestCorrelation,
  singleMessage,
  traceparentFor,
} from "./correlation.ts";
import { edgeCredentials } from "./edge-caller.ts";
import {
  bodySizeError,
  bodyTimeoutError,
  canceledError,
  coldStartError,
  deadlineError,
  grpcStatus,
} from "./errors.ts";
import { guardResponse } from "./frames.ts";
import { bounded, readBytes, reject, rpcError } from "./io.ts";
import {
  type ApiRoute,
  coldStartBudgetMs,
  findRoute,
  healthPath,
  streamLifetimeMs,
} from "./routes.ts";

export interface IngressEnv {
  SOURCE_REVISION: string;
  BUILD_IDENTITY?: string;
  FOUNDATION_PROOF?: string;
  ALLOWED_ORIGIN?: string;
  CLOUD_CONTAINER: {
    getByName(name: string): { fetch(request: Request): Promise<Response> };
  };
  HELLO_RATE_LIMITER: { limit(options: { key: string }): Promise<{ success: boolean }> };
}

const healthRoute: ApiRoute = {
  path: healthPath.slice(4),
  kind: "unary",
  auth: "anonymous",
  maxRequestBytes: 0,
  maxFrameBytes: 0,
  maxUnaryResponseBytes: 8192,
  maxDurationMs: 15_000,
  instance: "hello",
  requestMeta: false,
};

/** The stable message key of the registered refusal for a request that cannot be admitted as stated. */
export const invalidRequestKey = "validation.invalid_request";

function timeoutMs(value: string | null, cap: number): number | null {
  if (value === null) return cap;
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
  return Math.min(cap, Number(match[1]) * (units[match[2] ?? ""] ?? 0));
}

function isGrpcWeb(contentType: string | null): boolean {
  const mediaType = contentType?.split(";")[0]?.trim().toLowerCase();
  return mediaType === "application/grpc-web" || mediaType === "application/grpc-web+proto";
}

function responseContentType(upstream: string | null): string {
  return isGrpcWeb(upstream) ? (upstream as string) : "application/grpc-web+proto";
}

export async function handleApiRequest(request: Request, env: IngressEnv): Promise<Response> {
  const started = performance.now();
  const url = new URL(request.url);
  const health = url.pathname === healthPath;
  const route = health ? healthRoute : findRoute(env, url.pathname);
  if (!route) return reject(404, "Unknown API method.");
  if (url.search) return reject(400, "Query parameters are not supported.");
  if (request.method !== (health ? "GET" : "POST")) return reject(405, "Method not allowed.");
  if (!health && !isGrpcWeb(request.headers.get("content-type"))) {
    return reject(415, "Use binary gRPC-Web.");
  }
  if (
    !health &&
    (request.headers.has("content-encoding") ||
      ![null, "identity"].includes(request.headers.get("grpc-encoding")))
  )
    return reject(415, "Compressed requests are not supported.");

  const streaming = route.kind === "serverStream";
  const cap = streaming ? Math.min(route.maxDurationMs, streamLifetimeMs) : route.maxDurationMs;
  const budget = timeoutMs(health ? null : request.headers.get("grpc-timeout"), cap);
  if (budget === null) return rpcError(grpcStatus.invalidArgument, "Invalid grpc-timeout.");
  if (budget < 1) return rpcError(grpcStatus.deadlineExceeded, "RPC deadline exceeded.");

  const controller = new AbortController();
  const cancel = () => controller.abort(canceledError);
  request.signal.addEventListener("abort", cancel, { once: true });
  if (request.signal.aborted) cancel();
  const deadlineTimer = setTimeout(
    () => controller.abort(deadlineError),
    Math.max(0, budget - (performance.now() - started)),
  );
  let coldTimer: ReturnType<typeof setTimeout> | undefined;
  const signal = controller.signal;
  let handedOver = false;
  const cleanup = () => {
    clearTimeout(deadlineTimer);
    if (coldTimer !== undefined) clearTimeout(coldTimer);
    request.signal.removeEventListener("abort", cancel);
  };
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

    // Only what the Worker builds reaches the Container: never arbitrary client metadata, and a
    // credential only for a session method after the edge checks.
    const headers = new Headers();
    if (route.auth === "session") {
      const credentials = edgeCredentials(request, env.ALLOWED_ORIGIN);
      if (!credentials.ok) return rpcError(credentials.code, credentials.message);
      for (const [name, value] of Object.entries(credentials.headers)) headers.set(name, value);
    }
    if (Number(request.headers.get("content-length") ?? "0") > route.maxRequestBytes && !health) {
      return reject(413, `Request body exceeds ${route.maxRequestBytes} bytes.`);
    }

    let body: Uint8Array<ArrayBuffer> | undefined;
    if (!health) {
      const bodyTimer = setTimeout(() => controller.abort(bodyTimeoutError), 5000);
      try {
        body = await readBytes(request.body, route.maxRequestBytes, signal);
      } catch (error) {
        if (error === bodySizeError)
          return reject(413, `Request body exceeds ${route.maxRequestBytes} bytes.`);
        throw error;
      } finally {
        clearTimeout(bodyTimer);
      }
      if (body[0] === 1) return reject(415, "Compressed requests are not supported.");
    }
    // One correlation identity per call (CR-01, CR-03): a client's value is validated, an absent one is created here.
    // A malformed value is refused before the Container is woken and before any authorization decision, and no value
    // the client sent is ever copied into a header: the traceparent below is built from the validated identity.
    let correlationId: string | undefined;
    if (!health && route.requestMeta) {
      const message = singleMessage(body as Uint8Array);
      const stated = message ? readRequestCorrelation(message) : ({ kind: "unreadable" } as const);
      if (stated.kind === "malformed")
        return rpcError(grpcStatus.invalidArgument, invalidRequestKey);
      if (stated.kind === "valid") correlationId = stated.id;
    }
    if (!health) headers.set("traceparent", traceparentFor(correlationId ?? newCorrelationId()));
    const remaining = Math.floor(budget - (performance.now() - started));
    if (remaining <= 0) throw deadlineError;
    if (!health) {
      headers.set("content-type", "application/grpc-web+proto");
      headers.set("x-grpc-web", "1");
      headers.set("grpc-timeout", `${remaining}m`);
    }
    // Strip exactly the owned /api prefix.
    const target = new URL(route.path, "http://container");
    if (streaming) {
      // The cold start is bounded on its own: a stream's long lifetime must not make an unavailable
      // Container wait that long.
      coldTimer = setTimeout(() => controller.abort(coldStartError), coldStartBudgetMs);
    }
    const operation = env.CLOUD_CONTAINER.getByName(route.instance).fetch(
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
    if (coldTimer !== undefined) clearTimeout(coldTimer);
    if (response.status !== 200) {
      void response.body?.cancel().catch(() => {});
      return reject(503, "Cloud container is temporarily unavailable.");
    }
    const resultHeaders = new Headers({
      "content-type": health
        ? (response.headers.get("content-type") ?? "application/json")
        : responseContentType(response.headers.get("content-type")),
      "cache-control": "no-store",
      "x-content-type-options": "nosniff",
      "x-arcforges-worker-revision": env.SOURCE_REVISION,
      "x-arcforges-worker-build": env.BUILD_IDENTITY ?? "{}",
    });
    for (const name of ["grpc-status", "grpc-message"]) {
      const value = response.headers.get(name);
      if (value !== null && !health) resultHeaders.set(name, value);
    }
    if (health) {
      // The health route is a small plain reply.
      const payload = await readBytes(response.body, route.maxUnaryResponseBytes, signal);
      return new Response(payload, { status: 200, headers: resultHeaders });
    }
    if (!response.body) {
      // A bodyless reply is a trailers-only status carried in the headers; without one it is no answer.
      if (!resultHeaders.has("grpc-status"))
        return reject(503, "Cloud container is temporarily unavailable.");
      return new Response(null, { status: 200, headers: resultHeaders });
    }
    const guarded = guardResponse(response.body, {
      signal,
      maxFrameBytes: Math.max(route.maxFrameBytes, 1),
      maxResponseBytes: streaming ? undefined : route.maxUnaryResponseBytes,
      maxDataFrames: streaming ? undefined : 1,
      statusInHeaders: resultHeaders.has("grpc-status"),
      onAbort: streaming ? "trailer" : "error",
      onFinish: cleanup,
      onClientCancel: (reason) => controller.abort(reason ?? canceledError),
    });
    if (streaming) {
      handedOver = true;
      return new Response(guarded, { status: 200, headers: resultHeaders });
    }
    // A unary reply is bounded by its route and the deadline, and is fully read before any byte is
    // returned, so a failure still maps to an accurate status and no partial message leaks.
    const payload = await readBytes(guarded, route.maxUnaryResponseBytes, signal);
    return new Response(payload, { status: 200, headers: resultHeaders });
  } catch (error) {
    if (error === deadlineError)
      return health
        ? reject(504, deadlineError.message)
        : rpcError(grpcStatus.deadlineExceeded, deadlineError.message);
    if (error === canceledError)
      return health
        ? reject(499, canceledError.message)
        : rpcError(grpcStatus.canceled, canceledError.message);
    if (error === bodyTimeoutError)
      return reject(408, "Request body could not be read within five seconds.");
    // No restart loop or RPC replay. Readiness polling is separate from application calls.
    return reject(503, "Cloud container is temporarily unavailable.");
  } finally {
    if (!handedOver) cleanup();
  }
}
