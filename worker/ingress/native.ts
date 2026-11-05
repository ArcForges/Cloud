// SPDX-License-Identifier: AGPL-3.0-only
// The Worker's native JSON handler (AF-CTR-04 part M, MB-3): the mobile app's two routes of the Contracts document MobileNativeAuth
// (mobile.begin and mobile.token), forwarded to the Container only for an exact path of the generated native table, while the mobile
// surface is enabled. It holds no business rule and is deny by default in both directions:
//   - Request side: only POST; any query string, an Authorization header, any Cookie header (the app sends none, and a browser's
//     cookie gains nothing here), a Content-Type other than exactly application/json (so a cross-site browser request needs a CORS
//     preflight, which nothing answers), an encoding and a body over the route's bound are refused here, before the edge limit counts
//     the call and before the Container wakes. No Origin or CSRF token is required, and neither is forwarded: only the client's
//     address, its coarse origin from request.cf, a W3C traceparent the Worker builds and the body reach the Container.
//   - Response side: the page handler's rules (completeResponse): the generated statuses and security headers, a JSON reply within
//     the route's bound, no Set-Cookie and no Location (a redirect is never followed: redirect "manual").
import { newCorrelationId, traceparentFor } from "./correlation.ts";
import { edgeClientKey } from "./edge-limit.ts";
import { bodySizeError, bodyTimeoutError, canceledError, deadlineError } from "./errors.ts";
import { bounded, readBytes, reject } from "./io.ts";
import { completeResponse, type PageEnv } from "./pages.ts";
import { containerUnavailable } from "../readiness/container.ts";
import {
  clientAsnHeader,
  clientCountryHeader,
  clientIpHeader,
  edgeRateLimitPeriodSeconds,
  type NativeRoute,
  nativeRoutes,
  type PageRoute,
  pageDurationMs,
  pageInstance,
} from "../tables/center-tables.generated.ts";
import { bodyReadMilliseconds } from "../tables/cloud-tables.generated.ts";
import { enabledSurfaces } from "./routes.ts";

/** The native JSON routes by exact /api path. */
export const nativeTable: ReadonlyMap<string, NativeRoute> = new Map(
  nativeRoutes.map((route) => [`/api${route.path}`, route]),
);

/** The page handler's view of a native route: no cookie in or out, no redirect, its request and reply bounds. */
export function asPageRoute(route: NativeRoute): PageRoute {
  return {
    surface: route.surface,
    method: route.method,
    path: route.path,
    kind: "json",
    requestType: route.requestType,
    responseTypes: route.responseTypes,
    maxRequestBytes: route.maxRequestBytes,
    maxResponseBytes: route.maxResponseBytes,
    cookie: false,
    setCookie: "none",
    redirects: false,
  };
}

/** The coarse origin of a request as header values (pipeline.requestOrigin computes it from request.cf). */
export interface NativeOrigin {
  country?: string;
  asn?: string;
}

/** Answers one request for a native JSON path; the caller has found the path in the native table. */
export async function handleNativeRequest(
  request: Request,
  env: PageEnv,
  route: NativeRoute,
  origin: NativeOrigin,
): Promise<Response> {
  // A disabled surface is a path the Worker does not know (the same reply), before anything about the request is read.
  if (!enabledSurfaces(env.FLAGSHIP_SURFACES).has(route.surface))
    return reject(404, "Unknown API method.");
  if (request.method !== route.method) return reject(405, "Method not allowed.");
  if (request.url.includes("?")) return reject(400, "Query parameters are not supported.");
  if (request.headers.has("authorization")) return reject(400, "Authorization is not accepted.");
  if (request.headers.has("cookie")) return reject(400, "Cookies are not accepted.");
  if (request.headers.has("content-encoding") || request.headers.has("content-range"))
    return reject(415, "Encoded requests are not supported.");
  if (request.headers.get("content-type") !== route.requestType)
    return reject(415, "Unsupported media type.");
  const length = Number(request.headers.get("content-length") ?? "0");
  if (length > route.maxRequestBytes) return reject(413, "The request is too large.");

  const started = performance.now();
  const controller = new AbortController();
  const cancel = () => controller.abort(canceledError);
  request.signal.addEventListener("abort", cancel, { once: true });
  if (request.signal.aborted) cancel();
  const deadline = setTimeout(() => controller.abort(deadlineError), pageDurationMs);
  const signal = controller.signal;
  try {
    signal.throwIfAborted();
    // The edge limit of the surfaces counts the native calls too, by the client's network; over it, or without the binding, the
    // handler answers 429 and the Container never sees the call.
    const client = request.headers.get("cf-connecting-ip");
    const limiter = env.IDENTITY_RATE_LIMITER;
    const underLimit = limiter
      ? (await bounded(limiter.limit({ key: edgeClientKey(client) }), signal)).success
      : false;
    if (!underLimit) {
      const refused = reject(429, "Rate limit exceeded.");
      refused.headers.set("retry-after", String(edgeRateLimitPeriodSeconds));
      return refused;
    }
    const headers = new Headers();
    if (client !== null) headers.set(clientIpHeader, client);
    if (origin.country !== undefined) headers.set(clientCountryHeader, origin.country);
    if (origin.asn !== undefined) headers.set(clientAsnHeader, origin.asn);
    headers.set("traceparent", traceparentFor(newCorrelationId()));
    headers.set("content-type", route.requestType);

    let body: Uint8Array<ArrayBuffer>;
    const bodyTimer = setTimeout(() => controller.abort(bodyTimeoutError), bodyReadMilliseconds);
    try {
      body = await readBytes(request.body, route.maxRequestBytes, signal);
    } catch (error) {
      if (error === bodySizeError) return reject(413, "The request is too large.");
      throw error;
    } finally {
      clearTimeout(bodyTimer);
    }
    if (performance.now() - started >= pageDurationMs) throw deadlineError;
    const target = new URL(route.path, "http://container");
    // redirect "manual": the center never redirects a native call, and one that did is refused as a reply with a Location.
    const operation = env.CLOUD_CONTAINER.getByName(pageInstance).fetch(
      new Request(target, {
        method: "POST",
        headers,
        body: body.byteLength ? body : undefined,
        signal,
        redirect: "manual",
      }),
    );
    // A late response from an uncooperative binding must not leave a body open.
    void operation.then(
      (reply) => {
        if (signal.aborted) void reply.body?.cancel().catch(() => {});
      },
      () => {},
    );
    const reply = await bounded(operation, signal);
    return await completeResponse(reply, asPageRoute(route), signal);
  } catch (error) {
    if (error === deadlineError) return reject(504, deadlineError.message);
    if (error === canceledError) return reject(499, canceledError.message);
    if (error === bodyTimeoutError)
      return reject(408, "Request body could not be read within five seconds.");
    return containerUnavailable(false);
  } finally {
    clearTimeout(deadline);
    request.signal.removeEventListener("abort", cancel);
  }
}
