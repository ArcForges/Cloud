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

function reject(status: number, message: string): Response {
  return new Response(message, {
    status,
    headers: { "content-type": "text/plain; charset=utf-8", "cache-control": "no-store" },
  });
}

// Read with a bound even when content-length is missing or deliberately incorrect.
async function readBody(request: Request): Promise<Uint8Array<ArrayBuffer> | null> {
  if (!request.body) return new Uint8Array();
  const reader = request.body.getReader();
  const chunks: Uint8Array[] = [];
  let length = 0;
  let timedOut = false;
  const timer = setTimeout(() => {
    timedOut = true;
    void reader.cancel();
  }, 5000);
  try {
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      length += value.byteLength;
      if (length > maxBodyBytes) {
        await reader.cancel();
        return null;
      }
      chunks.push(value);
    }
  } finally {
    clearTimeout(timer);
    reader.releaseLock();
  }
  if (timedOut) throw new Error("Request body timed out.");
  const result = new Uint8Array(length);
  let offset = 0;
  for (const chunk of chunks) {
    result.set(chunk, offset);
    offset += chunk.byteLength;
  }
  return result;
}

export async function routeRequest(request: Request, env: CloudBindings): Promise<Response> {
  const url = new URL(request.url);
  const health = url.pathname === healthPath;
  if (!health && url.pathname !== helloPath) return reject(404, "Unknown API method.");
  if (url.search) return reject(400, "Query parameters are not supported.");
  if (request.method !== (health ? "GET" : "POST")) return reject(405, "Method not allowed.");
  if (
    !health &&
    request.headers.get("content-type")?.split(";")[0]?.trim() !== "application/grpc-web+proto"
  ) {
    return reject(415, "Use binary gRPC-Web.");
  }
  if (!health && request.headers.has("content-encoding"))
    return reject(415, "Compressed requests are not supported.");

  // Cloudflare supplies this header at the edge. This is an abuse limit, not authentication.
  const { success } = await env.HELLO_RATE_LIMITER.limit({
    key: request.headers.get("cf-connecting-ip") ?? "local",
  });
  if (!success) return reject(429, "Hello rate limit exceeded.");

  if (Number(request.headers.get("content-length") ?? "0") > maxBodyBytes) {
    return reject(413, "Request body exceeds 4096 bytes.");
  }
  let body: Uint8Array<ArrayBuffer> | undefined | null;
  try {
    body = health ? undefined : await readBody(request);
  } catch {
    return reject(408, "Request body could not be read within five seconds.");
  }
  if (body === null) return reject(413, "Request body exceeds 4096 bytes.");

  const headers = new Headers();
  if (!health) {
    headers.set("content-type", "application/grpc-web+proto");
    headers.set("x-grpc-web", "1");
    // Limit work even when a custom client omits its deadline.
    headers.set("grpc-timeout", "10S");
  }
  // Strip exactly the owned /api prefix. Do not forward cookies, auth or arbitrary headers.
  const target = new URL(url.pathname.slice(4), "http://container");
  try {
    const response = await env.CLOUD_CONTAINER.getByName("hello").fetch(
      new Request(target, {
        method: request.method,
        headers,
        body,
        signal: AbortSignal.any([request.signal, AbortSignal.timeout(15000)]),
      }),
    );
    const resultHeaders = new Headers(response.headers);
    resultHeaders.set("cache-control", "no-store");
    resultHeaders.set("x-content-type-options", "nosniff");
    resultHeaders.set("x-arcforges-worker-revision", env.SOURCE_REVISION);
    return new Response(response.body, {
      status: response.status,
      statusText: response.statusText,
      headers: resultHeaders,
    });
  } catch {
    // No restart loop or replay. Deployment smoke retries readiness, not application writes.
    return reject(503, "Cloud container is temporarily unavailable.");
  }
}
