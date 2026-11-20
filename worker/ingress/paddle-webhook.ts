// SPDX-License-Identifier: AGPL-3.0-only
import { newCorrelationId, traceparentFor } from "./correlation.ts";
import { edgeClientKey } from "./edge-limit.ts";
import { bodySizeError, canceledError, deadlineError } from "./errors.ts";
import { bounded, readBytes, reject } from "./io.ts";
import { hasRequestType, type PageEnv } from "./pages.ts";
import { enabledSurfaces } from "./routes.ts";
import { containerUnavailable } from "../readiness/container.ts";
import {
  clientIpHeader,
  edgeRateLimitPeriodSeconds,
  type WebhookRoute,
} from "../tables/center-tables.generated.ts";

export interface WebhookEnv extends PageEnv {
  ARCFORGES_CENTER_MODE?: string;
}

const receiptStatuses = [200, 400, 404, 405, 413, 415, 503];

export async function handlePaddleWebhook(
  request: Request,
  env: WebhookEnv,
  route: WebhookRoute,
): Promise<Response> {
  if (
    env.ARCFORGES_CENTER_MODE !== route.centerMode ||
    !enabledSurfaces(env.FLAGSHIP_SURFACES).has(route.surface)
  )
    return reject(404, "Unknown API method.");
  if (request.method !== route.method) return reject(405, "Method not allowed.");
  if (request.url.includes("?")) return reject(404, "Unknown API method.");

  const headers = request.headers;
  if (
    headers.has("content-encoding") ||
    !hasRequestType(headers.get("content-type"), route.contentType)
  )
    return reject(415, "An unencoded JSON request is required.");
  if (Number(headers.get("content-length") ?? "0") > route.maxRequestBytes)
    return reject(413, "Request body too large.");
  const signature = headers.get(route.signatureHeader);
  if (!signature || signature.length > route.maxSignatureBytes || signature.includes(","))
    return reject(400, "A provider signature is required.");
  const client = headers.get("cf-connecting-ip");
  if (!client) return reject(404, "Unknown API method.");

  const controller = new AbortController();
  const cancel = () => controller.abort(canceledError);
  request.signal.addEventListener("abort", cancel, { once: true });
  if (request.signal.aborted) cancel();
  const deadline = setTimeout(() => controller.abort(deadlineError), route.maxDurationMs);
  const signal = controller.signal;
  try {
    signal.throwIfAborted();
    const limiter = env.IDENTITY_RATE_LIMITER;
    if (!limiter) return containerUnavailable(false);
    const limit = await bounded(
      limiter.limit({ key: `${route.path}:${edgeClientKey(client)}` }),
      signal,
    );
    if (!limit.success) {
      const refused = reject(429, "Rate limit exceeded.");
      refused.headers.set("retry-after", String(edgeRateLimitPeriodSeconds));
      return refused;
    }
    const body = await readBytes(request.body, route.maxRequestBytes, signal);
    if (body.byteLength === 0) return reject(400, "A webhook payload is required.");

    // Keep the signed bytes verbatim. Forward only the generated ingress assertion and the provider signature.
    const operation = env.CLOUD_CONTAINER.getByName(route.instance).fetch(
      new Request(new URL(route.path, "http://container"), {
        method: route.method,
        headers: {
          "content-type": route.contentType,
          [route.signatureHeader]: signature,
          [clientIpHeader]: client,
          traceparent: traceparentFor(newCorrelationId()),
        },
        body,
        redirect: "manual",
        signal,
      }),
    );
    // The provider needs only the durable receipt's status. Drop the reply's body even after a timeout.
    void operation.then(
      (reply) => void reply.body?.cancel().catch(() => {}),
      () => {},
    );
    const reply = await bounded(operation, signal);
    if (!receiptStatuses.includes(reply.status)) return containerUnavailable(false);
    return new Response(null, {
      status: reply.status,
      headers: { "cache-control": "no-store" },
    });
  } catch (error) {
    if (error === bodySizeError) return reject(413, "Request body too large.");
    if (error === canceledError) return reject(499, canceledError.message);
    if (error === deadlineError) return reject(504, deadlineError.message);
    return containerUnavailable(false);
  } finally {
    clearTimeout(deadline);
    request.signal.removeEventListener("abort", cancel);
  }
}
