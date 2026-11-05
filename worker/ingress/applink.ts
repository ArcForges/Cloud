// SPDX-License-Identifier: AGPL-3.0-only
// The Worker's apex handler (AF-CTR-04 part M, MB-8, M-13, M-15): the two exact paths at the root of the host that the mobile app's
// verified App Link needs, /.well-known/assetlinks.json (the Digital Asset Links statement list Android's verifier, Google's fetcher
// and Credential Manager read) and /app/callback (the fixed page a browser shows when the App Link did not open the app). They are
// forwarded to the same center path only while the mobile surface is enabled; every other path of the host keeps its answer (404 from
// this Worker; production's zone route covers /api/* only, so these rows are unreachable there until AF-PROD-01 adds its routes). It
// holds no business rule: the center renders both replies.
//   - Request side: only GET; a query string, an Authorization header or a body is refused here. No cookie is forwarded (a browser
//     sends the host's session cookie with a navigation; neither route reads one), and nothing else of the request but the client's
//     address and a W3C traceparent the Worker builds reaches the Container.
//   - Response side: the page handler's rules (completeResponse): the generated statuses and security headers, the route's media
//     type and bound, no Set-Cookie and no Location (redirect "manual": Android's verifier and Google's fetcher follow no redirect).
import { newCorrelationId, traceparentFor } from "./correlation.ts";
import { edgeClientKey } from "./edge-limit.ts";
import { canceledError, deadlineError } from "./errors.ts";
import { bounded, reject } from "./io.ts";
import { completeResponse, type PageEnv } from "./pages.ts";
import { containerUnavailable } from "../readiness/container.ts";
import {
  type ApexRoute,
  apexRoutes,
  clientIpHeader,
  edgeRateLimitPeriodSeconds,
  type PageRoute,
  pageDurationMs,
  pageInstance,
} from "../tables/center-tables.generated.ts";
import { enabledSurfaces } from "./routes.ts";

/** The apex routes by exact path at the root of the host (no /api prefix). */
export const apexTable: ReadonlyMap<string, ApexRoute> = new Map(
  apexRoutes.map((route) => [route.path, route]),
);

/** The page handler's view of an apex route: no body, no cookie in or out, no redirect, its reply bound. */
export function apexAsPageRoute(route: ApexRoute): PageRoute {
  return {
    surface: route.surface,
    method: route.method,
    path: route.path,
    kind: "html",
    requestType: "",
    responseTypes: route.responseTypes,
    maxRequestBytes: 0,
    maxResponseBytes: route.maxResponseBytes,
    cookie: false,
    setCookie: "none",
    redirects: false,
  };
}

/** Answers one request for an apex path; the caller has found the path in the apex table. */
export async function handleApexRequest(
  request: Request,
  env: PageEnv,
  route: ApexRoute,
): Promise<Response> {
  if (!enabledSurfaces(env.FLAGSHIP_SURFACES).has(route.surface))
    return reject(404, "Unknown API method.");
  if (request.method !== route.method) return reject(405, "Method not allowed.");
  if (request.url.includes("?")) return reject(400, "Query parameters are not supported.");
  if (request.headers.has("authorization")) return reject(400, "Authorization is not accepted.");
  const length = Number(request.headers.get("content-length") ?? "0");
  if (length > 0 || request.headers.has("transfer-encoding"))
    return reject(400, "A GET has no body.");

  const controller = new AbortController();
  const cancel = () => controller.abort(canceledError);
  request.signal.addEventListener("abort", cancel, { once: true });
  if (request.signal.aborted) cancel();
  const deadline = setTimeout(() => controller.abort(deadlineError), pageDurationMs);
  const signal = controller.signal;
  try {
    signal.throwIfAborted();
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
    headers.set("traceparent", traceparentFor(newCorrelationId()));
    const target = new URL(route.path, "http://container");
    const operation = env.CLOUD_CONTAINER.getByName(pageInstance).fetch(
      new Request(target, { method: "GET", headers, signal, redirect: "manual" }),
    );
    void operation.then(
      (reply) => {
        if (signal.aborted) void reply.body?.cancel().catch(() => {});
      },
      () => {},
    );
    const reply = await bounded(operation, signal);
    return await completeResponse(reply, apexAsPageRoute(route), signal);
  } catch (error) {
    if (error === deadlineError) return reject(504, deadlineError.message);
    if (error === canceledError) return reject(499, canceledError.message);
    return containerUnavailable(false);
  } finally {
    clearTimeout(deadline);
    request.signal.removeEventListener("abort", cancel);
  }
}
