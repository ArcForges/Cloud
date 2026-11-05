// SPDX-License-Identifier: AGPL-3.0-only
// The Worker's upgrade handler (AF-CTR-05 E1a; Plan CTR5-HUB-02, PN-2, PN-3, PN-4): the node channel's WebSocket upgrade route
// GET /api/fleet/v1/node, passed through to the Container only for an exact path of the generated upgrade table, while the relay surface
// is enabled. It holds no business rule; the center admits the channel (the credential, the operation row, the node) and is the only
// authority. Deny by default in both directions:
//   - Request side: only GET as an upgrade (Upgrade websocket, Connection upgrade, Sec-WebSocket-Version 13, one Sec-WebSocket-Key, the
//     route's one subprotocol), no query string, no body, and an Authorization of the native bearer's shape; anything else is refused
//     here, before the edge limit counts the call and before the Container wakes. A Cookie is never forwarded (PN-4: the channel is
//     admitted on a node credential only), nor is any other client header: the Container sees the upgrade headers, the bearer, the
//     client's address and coarse origin from Cloudflare, and a W3C traceparent the Worker builds.
//   - Response side: the Container's 101 is returned unchanged, the Response object itself with its WebSocket (PN-2; the Durable
//     Object proxies the socket and stays awake while it is open). Any other reply is the center's refusal before the upgrade: kept
//     only with one of the statuses the center answers and only its JSON body and the headers that carry its reason
//     (ArcForges-Refusal, Retry-After; PN-3); anything else is the Worker's own 503. The Worker's own 503, 504 and 499 carry the fixed
//     reason RESOURCE/overloaded in the refusal header too.
import { newCorrelationId, traceparentFor } from "./correlation.ts";
import { edgeClientKey } from "./edge-limit.ts";
import { canceledError, deadlineError } from "./errors.ts";
import { bounded, readBytes, reject } from "./io.ts";
import type { NativeOrigin } from "./native.ts";
import { containerUnavailable } from "../readiness/container.ts";
import {
  clientAsnHeader,
  clientCountryHeader,
  clientIpHeader,
  edgeRateLimitPeriodSeconds,
  upgradeRefusalBytes,
  upgradeRefusalHeader,
  upgradeRefusalStatuses,
  upgradeRefusalValuePattern,
  type UpgradeRoute,
  upgradeRoutes,
} from "../tables/center-tables.generated.ts";
import { bearerCredentialPattern } from "../tables/cloud-tables.generated.ts";
import { enabledSurfaces } from "./routes.ts";
import type { PageEnv } from "./pages.ts";

/** The upgrade routes by exact /api path. */
export const upgradeTable: ReadonlyMap<string, UpgradeRoute> = new Map(
  upgradeRoutes.map((route) => [`/api${route.path}`, route]),
);

/** The headers a refusal before the upgrade may keep. */
const refusalHeaders = [upgradeRefusalHeader, "retry-after"];

/** The reason the Worker's own unavailability carries (its 503, its deadline's 504, a cancel's 499): retry after a short time. */
const overloadedReason = "RESOURCE/overloaded";

/** A refusal of the Worker itself, with its closed reason in the refusal header (PN-3). */
function refuse(status: number, reason: string, message: string): Response {
  const refused = reject(status, message);
  refused.headers.set(upgradeRefusalHeader, reason);
  return refused;
}

/** The Worker's own 503, with its reason in the refusal header too (review B N-5: a client sees only the status and the headers). */
function unavailable(): Response {
  const refused = containerUnavailable(false);
  refused.headers.set(upgradeRefusalHeader, overloadedReason);
  return refused;
}

/** Whether a comma-separated header lists a token, ignoring case. */
function hasToken(value: string | null, token: string): boolean {
  if (value === null) return false;
  return value.split(",").some((item) => item.trim().toLowerCase() === token);
}

/** Answers one request for an upgrade path; the caller has found the path in the upgrade table. */
export async function handleUpgradeRequest(
  request: Request,
  env: PageEnv,
  route: UpgradeRoute,
  origin: NativeOrigin,
): Promise<Response> {
  // A disabled surface is answered here, before anything about the request is read and before any Container wakes.
  if (!enabledSurfaces(env.FLAGSHIP_SURFACES).has(route.surface))
    return refuse(404, "STATE/not_activated", "Unknown API method.");
  if (request.method !== route.method)
    return refuse(405, "VALIDATION/invalid_argument", "Method not allowed.");
  const headers = request.headers;
  if (request.url.includes("?"))
    return refuse(400, "VALIDATION/invalid_argument", "Query parameters are not supported.");
  if (
    request.body !== null ||
    headers.has("transfer-encoding") ||
    Number(headers.get("content-length") ?? "0") !== 0
  )
    return refuse(400, "VALIDATION/invalid_argument", "An upgrade has no body.");
  const key = headers.get("sec-websocket-key");
  if (
    !hasToken(headers.get("upgrade"), "websocket") ||
    !hasToken(headers.get("connection"), "upgrade") ||
    headers.get("sec-websocket-version") !== "13" ||
    key === null ||
    !/^[A-Za-z0-9+/]{22}==$/u.test(key)
  )
    return refuse(400, "VALIDATION/invalid_argument", "A WebSocket upgrade is required.");
  if (headers.get("sec-websocket-protocol") !== route.subprotocol)
    return refuse(400, "VALIDATION/invalid_argument", "The subprotocol is not admitted.");
  const authorization = headers.get("authorization");
  if (authorization === null || !bearerCredentialPattern.test(authorization))
    return refuse(401, "AUTHENTICATION/unauthenticated", "A node credential is required.");

  const controller = new AbortController();
  const cancel = () => controller.abort(canceledError);
  request.signal.addEventListener("abort", cancel, { once: true });
  if (request.signal.aborted) cancel();
  const deadline = setTimeout(() => controller.abort(deadlineError), route.maxDurationMs);
  const signal = controller.signal;
  try {
    signal.throwIfAborted();
    // The surfaces' edge limit counts the upgrades too, by the client's network; over it, or without the binding, the Container
    // never sees the call.
    const client = headers.get("cf-connecting-ip");
    const limiter = env.IDENTITY_RATE_LIMITER;
    const underLimit = limiter
      ? (await bounded(limiter.limit({ key: edgeClientKey(client) }), signal)).success
      : false;
    if (!underLimit) {
      const refused = refuse(429, "RESOURCE/rate_limited", "Rate limit exceeded.");
      refused.headers.set("retry-after", String(edgeRateLimitPeriodSeconds));
      return refused;
    }
    // Only what the Worker builds reaches the Container: the upgrade headers, the bearer, the client's address and origin.
    const forwarded = new Headers({
      upgrade: "websocket",
      connection: "Upgrade",
      "sec-websocket-version": "13",
      "sec-websocket-key": key,
      "sec-websocket-protocol": route.subprotocol,
      authorization,
      traceparent: traceparentFor(newCorrelationId()),
    });
    if (client !== null) forwarded.set(clientIpHeader, client);
    if (origin.country !== undefined) forwarded.set(clientCountryHeader, origin.country);
    if (origin.asn !== undefined) forwarded.set(clientAsnHeader, origin.asn);
    const target = new URL(route.path, "http://container");
    // redirect "manual": the center never redirects an upgrade, and one that did is refused below as a reply that is not a refusal.
    const operation = env.CLOUD_CONTAINER.getByName(route.instance).fetch(
      new Request(target, { method: "GET", headers: forwarded, signal, redirect: "manual" }),
    );
    // A late response from an uncooperative binding must not leave a body open.
    void operation.then(
      (reply) => {
        if (signal.aborted && reply.status !== 101) void reply.body?.cancel().catch(() => {});
      },
      () => {},
    );
    const reply = await bounded(operation, signal);
    // PN-2: the 101 is the Durable Object's own Response with its WebSocket; it is returned as it is, never rebuilt.
    if (reply.status === 101) return reply;
    return await refusalOf(reply, signal);
  } catch (error) {
    if (error === deadlineError) return refuse(504, overloadedReason, deadlineError.message);
    if (error === canceledError) return refuse(499, overloadedReason, canceledError.message);
    return unavailable();
  } finally {
    clearTimeout(deadline);
    request.signal.removeEventListener("abort", cancel);
  }
}

/** The center's refusal before the upgrade, kept to its status, its JSON body within the bound and its reason headers. */
async function refusalOf(reply: Response, signal: AbortSignal): Promise<Response> {
  const type = reply.headers.get("content-type");
  if (!upgradeRefusalStatuses.includes(reply.status) || type !== "application/json") {
    void reply.body?.cancel().catch(() => {});
    return unavailable();
  }
  let body: Uint8Array<ArrayBuffer>;
  try {
    body = await readBytes(reply.body, upgradeRefusalBytes, signal);
  } catch {
    return unavailable();
  }
  const headers = new Headers({
    "content-type": "application/json",
    "cache-control": "no-store",
    "x-content-type-options": "nosniff",
  });
  for (const name of refusalHeaders) {
    const value = reply.headers.get(name);
    if (value !== null && upgradeRefusalValuePattern.test(value)) headers.set(name, value);
  }
  return new Response(body, { status: reply.status, headers });
}
