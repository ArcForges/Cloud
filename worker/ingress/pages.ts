// SPDX-License-Identifier: AGPL-3.0-only
// The Worker's page handler (AF-CTR-03 A2, PLT-1): the center's account pages and its WebBrowserSession routes, forwarded to the
// Container only for an exact method and path of the generated page table, while the surface of the route (pages, or operations) is enabled. It is deny by default
// in both directions and holds no business rule:
//   - Request side: any query string, an Authorization header, a body on a GET, an Origin that is not exactly ALLOWED_ORIGIN on a
//     POST, a media type or an encoding the route does not take, a body over the route's bound, and a session cookie that is not
//     exactly one `__Host-af_session` of 43 base64url characters are refused here, before the edge limit counts the call and before
//     the Container wakes. Only a rebuilt cookie (the session cookie, for a route that reads it), the Origin, the CSRF token, the
//     client's address, a W3C traceparent the Worker builds and a bounded User-Agent reach the Container.
//   - Response side: a status outside the generated list becomes the Worker's 503; a reply must carry every generated security
//     header with its exact value (so an HTML reply without the content security policy is a 503, decision 4.8); its media type must
//     be one the route allows; its body is bounded; a Set-Cookie is copied only where the route allows it and only in the exact form
//     of the session cookie (or its removal); a Location is copied only on a 303 of a route that redirects, below the pages' prefix,
//     without a query. No other header of the Container reaches the client.
import { newCorrelationId, traceparentFor } from "./correlation.ts";
import { edgeClientKey } from "./edge-limit.ts";
import { bodySizeError, bodyTimeoutError, canceledError, deadlineError } from "./errors.ts";
import { bounded, readBytes, reject } from "./io.ts";
import { classifyStartFailureResponse, containerUnavailable } from "../readiness/container.ts";
import {
  clientIpHeader,
  edgeRateLimitPeriodSeconds,
  type PageRoute,
  pageCookieMaxAgeDigits,
  pageCookieName,
  pageDurationMs,
  pageInstance,
  pageLocationPrefix,
  pageReturnFragment,
  pageReturnPathBytes,
  pageRoutes,
  pageSecurityHeaders,
  pageStatuses,
  pageUserAgentBytes,
} from "../tables/center-tables.generated.ts";
import { bodyReadMilliseconds, sessionTokenPattern } from "../tables/cloud-tables.generated.ts";
import { csrfHeader } from "./edge-caller.ts";
import { enabledSurfaces } from "./routes.ts";

export interface PageEnv {
  SOURCE_REVISION: string;
  ALLOWED_ORIGIN?: string;
  FLAGSHIP_SURFACES?: string;
  CLOUD_CONTAINER: {
    getByName(name: string): { fetch(request: Request): Promise<Response> };
  };
  IDENTITY_RATE_LIMITER?: { limit(options: { key: string }): Promise<{ success: boolean }> };
}

/** The page routes by exact /api path, each path with its methods. */
export const pageTable: ReadonlyMap<string, readonly PageRoute[]> = (() => {
  const table = new Map<string, PageRoute[]>();
  for (const route of pageRoutes) {
    const path = `/api${route.path}`;
    const methods = table.get(path) ?? [];
    // The surface check answers for a whole path, so the methods of one path belong to one surface (fail closed).
    if (methods.some((other) => other.surface !== route.surface))
      throw new TypeError("The methods of one page path belong to one surface.");
    table.set(path, [...methods, route]);
  }
  return table;
})();

/**
 * The session cookie value (a 32-byte handle) and the CSRF token (an HMAC-SHA-256 or a SHA-256) are both 43 unpadded base64url
 * characters: the generated session-token shape, which the gRPC-Web edge guard uses for the same two values.
 */
const sessionHandle = sessionTokenPattern;
const csrfToken = sessionTokenPattern;

/** The text of an anchored pattern without its anchors: the shape a larger pattern embeds (fail closed if it is not anchored). */
function unanchored(pattern: RegExp): string {
  const { source } = pattern;
  if (!source.startsWith("^") || !source.endsWith("$"))
    throw new TypeError("An anchored pattern is expected.");
  return source.slice(1, -1);
}

/**
 * The Set-Cookie of a new session: the cookie of a session handle (the generated shape, not a copy of it), a Max-Age of a positive
 * number of at most the generated count of digits, and the fixed attributes the center writes.
 */
const sessionSetCookie = new RegExp(
  `^${escapeRegExp(pageCookieName)}=${unanchored(sessionTokenPattern)}; Path=/; Max-Age=[1-9][0-9]{0,${pageCookieMaxAgeDigits - 1}}; Secure; HttpOnly; SameSite=Strict$`,
  "u",
);
const clearSetCookie = `${pageCookieName}=; Path=/; Max-Age=0; Secure; HttpOnly; SameSite=Strict`;

function escapeRegExp(text: string): string {
  return text.replace(/[.*+?^${}()|[\]\\]/gu, "\\$&");
}

/**
 * A redirect's Location: a path below the pages' prefix made of lower-case words joined by hyphens and slashes, without a query,
 * and at most the sign-in page's return fragment (a percent-encoded path).
 */
const redirectLocation = new RegExp(
  `^${escapeRegExp(pageLocationPrefix)}[a-z0-9]+(?:-[a-z0-9]+)*(?:/[a-z0-9]+(?:-[a-z0-9]+)*)*(?:${escapeRegExp(pageReturnFragment)}[A-Za-z0-9%._~-]{1,${pageReturnPathBytes}})?$`,
  "u",
);

/** The lower-case media type of a Content-Type value without its parameters, and its parameters without white space. */
function mediaType(value: string | null): { type: string; parameters: string } {
  if (value === null) return { type: "", parameters: "" };
  const separator = value.indexOf(";");
  const type = (separator < 0 ? value : value.slice(0, separator)).trim().toLowerCase();
  const parameters = separator < 0 ? "" : value.slice(separator + 1).replaceAll(/\s+/gu, "");
  return { type, parameters: parameters.toLowerCase() };
}

/** Whether a request's Content-Type is the route's media type, with at most the UTF-8 charset. */
export function hasRequestType(value: string | null, expected: string): boolean {
  const { type, parameters } = mediaType(value);
  return type === expected && (parameters === "" || parameters === "charset=utf-8");
}

/**
 * The one session cookie of a Cookie header: its value, null when there is none, or "invalid" when it is repeated or malformed.
 * Every other cookie of the header is ignored (and never forwarded).
 */
export function sessionCookieOf(header: string | null): string | null | "invalid" {
  if (header === null) return null;
  let found: string | null = null;
  for (const pair of header.split(";")) {
    const text = pair.trim();
    const separator = text.indexOf("=");
    if (separator <= 0 || text.slice(0, separator) !== pageCookieName) continue;
    if (found !== null) return "invalid";
    found = text.slice(separator + 1);
  }
  if (found === null) return null;
  return sessionHandle.test(found) ? found : "invalid";
}

/** Whether a Set-Cookie value is exactly the session cookie of a new session (a route that signs in) or its removal (a sign-out). */
export function isAllowedSetCookie(value: string, allowed: PageRoute["setCookie"]): boolean {
  if (allowed === "session") return sessionSetCookie.test(value);
  if (allowed === "clear") return value === clearSetCookie;
  return false;
}

/** Whether a Location is a redirect the pages may answer. */
export function isPageLocation(value: string): boolean {
  return redirectLocation.test(value);
}

/** The User-Agent the Container may see: printable ASCII of at most the generated bound, else none. */
export function boundedUserAgent(value: string | null): string | null {
  if (value === null || value.length === 0 || value.length > pageUserAgentBytes) return null;
  return /^[\x20-\x7e]+$/u.test(value) ? value : null;
}

function unavailable(): Response {
  return containerUnavailable(false);
}

/**
 * Answers one request for a page path. The caller has found the path in the page table; `candidates` are its routes (one per
 * method).
 */
export async function handlePageRequest(
  request: Request,
  env: PageEnv,
  candidates: readonly PageRoute[],
): Promise<Response> {
  const route = candidates.find((row) => row.method === request.method);
  // A disabled surface is a path the Worker does not know (the same reply), before anything about the request is read. A path's
  // methods belong to one surface (the generated table is built that way), so the first candidate names it.
  const surface = candidates[0]?.surface;
  if (surface === undefined || !enabledSurfaces(env.FLAGSHIP_SURFACES).has(surface))
    return reject(404, "Unknown API method.");
  if (!route) return reject(405, "Method not allowed.");
  if (request.url.includes("?")) return reject(400, "Query parameters are not supported.");
  if (request.headers.has("authorization")) return reject(400, "Authorization is not accepted.");
  const length = Number(request.headers.get("content-length") ?? "0");
  if (request.method === "GET") {
    if (length > 0 || request.headers.has("transfer-encoding"))
      return reject(400, "A GET has no body.");
  } else {
    // Every POST states the exact Origin; an Origin the Worker was not configured with is never accepted.
    const allowed = env.ALLOWED_ORIGIN;
    if (allowed === undefined || allowed === "" || request.headers.get("origin") !== allowed)
      return reject(403, "The Origin is not allowed.");
    if (request.headers.has("content-encoding") || request.headers.has("content-range"))
      return reject(415, "Encoded requests are not supported.");
    if (
      route.requestType !== "" &&
      !hasRequestType(request.headers.get("content-type"), route.requestType)
    )
      return reject(415, "Unsupported media type.");
    if (length > route.maxRequestBytes) return reject(413, "The request is too large.");
  }
  const cookie = route.cookie ? sessionCookieOf(request.headers.get("cookie")) : null;
  if (cookie === "invalid") return reject(400, "The session cookie is not valid.");

  const started = performance.now();
  const controller = new AbortController();
  const cancel = () => controller.abort(canceledError);
  request.signal.addEventListener("abort", cancel, { once: true });
  if (request.signal.aborted) cancel();
  const deadline = setTimeout(() => controller.abort(deadlineError), pageDurationMs);
  const signal = controller.signal;
  try {
    signal.throwIfAborted();
    // The edge limit of the surfaces counts the page calls too, by the client's network; over it, or without the binding, the page
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
    headers.set("traceparent", traceparentFor(newCorrelationId()));
    if (cookie !== null) headers.set("cookie", `${pageCookieName}=${cookie}`);
    const agent = boundedUserAgent(request.headers.get("user-agent"));
    if (request.method === "POST") {
      headers.set("origin", request.headers.get("origin") as string);
      if (route.requestType !== "") headers.set("content-type", route.requestType);
      const token = request.headers.get(csrfHeader);
      if (token !== null && csrfToken.test(token)) headers.set(csrfHeader, token);
      if (agent !== null) headers.set("user-agent", agent);
    }

    let body: Uint8Array<ArrayBuffer> | undefined;
    if (request.method === "POST") {
      const bodyTimer = setTimeout(() => controller.abort(bodyTimeoutError), bodyReadMilliseconds);
      try {
        body = await readBytes(request.body, route.maxRequestBytes, signal);
      } catch (error) {
        if (error === bodySizeError) return reject(413, "The request is too large.");
        throw error;
      } finally {
        clearTimeout(bodyTimer);
      }
    }
    if (performance.now() - started >= pageDurationMs) throw deadlineError;
    const target = new URL(route.path, "http://container");
    const operation = env.CLOUD_CONTAINER.getByName(pageInstance).fetch(
      // redirect "manual": the platform's fetch follows a redirect unless told not to, and the center's 303 (a page without a session
      // to the sign-in page) would become the 404 of a path it does not serve. The handler must see the 303 itself; it admits its
      // Location, and the browser follows it.
      new Request(target, {
        method: request.method,
        headers,
        body: body?.byteLength ? body : undefined,
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
    return await completeResponse(reply, route, signal);
  } catch (error) {
    if (error === deadlineError) return reject(504, deadlineError.message);
    if (error === canceledError) return reject(499, canceledError.message);
    if (error === bodyTimeoutError)
      return reject(408, "Request body could not be read within five seconds.");
    return unavailable();
  } finally {
    clearTimeout(deadline);
    request.signal.removeEventListener("abort", cancel);
  }
}

/**
 * The reply the client gets for a Container reply, or the Worker's 503 when the reply breaks a rule of its route. Only the generated
 * security headers, the media type, an allowed Set-Cookie and an allowed Location are copied.
 */
export async function completeResponse(
  reply: Response,
  route: PageRoute,
  signal: AbortSignal,
): Promise<Response> {
  const discard = () => void reply.body?.cancel().catch(() => {});
  // A Container the platform could not start never saw the request: its plain-text reply is classified, not forwarded.
  const startFailure = await classifyStartFailureResponse(reply);
  if (startFailure !== null) {
    discard();
    return containerUnavailable(true);
  }
  if (!pageStatuses.includes(reply.status)) {
    discard();
    return unavailable();
  }
  for (const [name, value] of Object.entries(pageSecurityHeaders)) {
    if (reply.headers.get(name) !== value) {
      discard();
      return unavailable();
    }
  }
  const headers = new Headers(pageSecurityHeaders);
  const cookies = reply.headers.getSetCookie();
  if (cookies.length > 0) {
    // At most one cookie, only where the route allows one, only on a reply that answers the request, only in the exact form.
    const [cookie] = cookies;
    const answered = reply.status === 200 || (reply.status === 303 && route.redirects);
    if (
      cookies.length !== 1 ||
      cookie === undefined ||
      !answered ||
      !isAllowedSetCookie(cookie, route.setCookie)
    ) {
      discard();
      return unavailable();
    }
    headers.append("set-cookie", cookie);
  }
  if (reply.status === 303) {
    const location = reply.headers.get("location");
    if (!route.redirects || location === null || !isPageLocation(location)) {
      discard();
      return unavailable();
    }
    headers.set("location", location);
    // A redirect has no body.
    discard();
    return new Response(null, { status: 303, headers });
  }
  if (reply.headers.has("location")) {
    discard();
    return unavailable();
  }
  let payload: Uint8Array<ArrayBuffer>;
  try {
    payload = await readBytes(reply.body, route.maxResponseBytes, signal);
  } catch (error) {
    if (error === bodySizeError) return unavailable();
    throw error;
  }
  if (payload.byteLength > 0) {
    const contentType = reply.headers.get("content-type");
    if (contentType === null || !route.responseTypes.includes(contentType)) return unavailable();
    headers.set("content-type", contentType);
  }
  return new Response(payload.byteLength > 0 ? payload : null, { status: reply.status, headers });
}
