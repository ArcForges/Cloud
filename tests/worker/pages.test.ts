// SPDX-License-Identifier: AGPL-3.0-only
// The Worker's page handler (AF-CTR-03 A2, PLT-1; SEC-16): exact paths and methods from the generated table, requests refused before
// the edge limit and the Container when they break the browser protocol, a rebuilt request to the Container, and replies held to the
// generated rules: the security headers byte for byte, a status from the list, a media type of the route, a Set-Cookie only in the
// exact form of the session cookie, a Location only on a 303 below the pages' prefix. Every refusal of the response side is the
// Worker's own 503.
import assert from "node:assert/strict";
import test from "node:test";
import {
  boundedUserAgent,
  isAllowedSetCookie,
  isPageLocation,
  pageTable,
  sessionCookieOf,
} from "../../worker/ingress/pages.ts";
import { routeRequest, type CloudBindings } from "../../worker/router.ts";
import {
  pageCookieMaxAgeDigits,
  pageCookieName,
  pageLocationPrefix,
  pageReturnFragment,
  pageReturnPathBytes,
  pageRoutes,
  pageSecurityHeaders,
  pageStatuses,
  type PageRoute,
} from "../../worker/tables/center-tables.generated.ts";
import { sessionTokenPattern } from "../../worker/tables/cloud-tables.generated.ts";
import { platformFetch } from "./support/platform-fetch.ts";

const origin = "https://proof.example.test";
const handle = "A".repeat(43);
const token = "B".repeat(43);
const exactHeaders: Record<string, string> = {
  "content-security-policy":
    "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self'; connect-src 'self'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'; require-trusted-types-for 'script'; trusted-types 'none'",
  "x-frame-options": "DENY",
  "referrer-policy": "same-origin",
  "cross-origin-opener-policy": "same-origin",
  "permissions-policy": "publickey-credentials-get=(self), publickey-credentials-create=(self)",
  "cache-control": "no-store, no-transform",
  "x-content-type-options": "nosniff",
};
const sessionCookie = `${pageCookieName}=${handle}; Path=/; Max-Age=43200; Secure; HttpOnly; SameSite=Strict`;
const clearedCookie = `${pageCookieName}=; Path=/; Max-Age=0; Secure; HttpOnly; SameSite=Strict`;

function route(method: string, path: string): PageRoute {
  const found = pageRoutes.find((row) => row.method === method && row.path === path);
  assert(found, `${method} ${path} is a page route`);
  return found;
}

const signInPage = route("GET", "/account/sign-in");
const sessionsPage = route("GET", "/account/sessions");
const script = route("GET", "/account/account.js");
const bootstrap = route("GET", "/session/v1/web/bootstrap");
const begin = route("POST", "/session/v1/web/authentication/begin");
const complete = route("POST", "/session/v1/web/authentication/complete");
const stepUp = route("POST", "/session/v1/web/step-up/begin");
const logout = route("POST", "/session/v1/web/logout");
const revoke = route("POST", "/account/sessions/revoke");

interface Seen {
  request: Request;
  body: Uint8Array;
}

function bindings(
  reply: (request: Request) => Response | Promise<Response>,
  overrides: Partial<CloudBindings> = {},
): { env: CloudBindings; seen: Seen[]; keys: string[] } {
  const seen: Seen[] = [];
  const keys: string[] = [];
  const env: CloudBindings = {
    SOURCE_REVISION: "candidate",
    ALLOWED_ORIGIN: origin,
    FLAGSHIP_SURFACES: "identity,pages,operations",
    CLOUD_CONTAINER: {
      getByName() {
        return {
          async fetch(request: Request) {
            seen.push({ request, body: new Uint8Array(await request.clone().arrayBuffer()) });
            // The platform follows a redirect unless the request says redirect "manual" (see support/platform-fetch.ts).
            return platformFetch(reply)(request);
          },
        };
      },
    },
    HELLO_RATE_LIMITER: {
      limit: async () => {
        throw new Error("the Hello limiter does not count page calls");
      },
    },
    IDENTITY_RATE_LIMITER: {
      limit: async ({ key }) => {
        keys.push(key);
        return { success: true };
      },
    },
    ...overrides,
  };
  return { env, seen, keys };
}

/** A reply of the center as a route would give it, with every generated security header. */
function centerReply(
  status: number,
  options: { type?: string; body?: string; headers?: Record<string, string>; skip?: string[] } = {},
): Response {
  const headers = new Headers();
  for (const [name, value] of Object.entries(pageSecurityHeaders)) {
    if (!options.skip?.includes(name)) headers.set(name, value);
  }
  if (options.type) headers.set("content-type", options.type);
  for (const [name, value] of Object.entries(options.headers ?? {})) {
    if (name === "set-cookie") headers.append(name, value);
    else headers.set(name, value);
  }
  return new Response(options.body ?? null, { status, headers });
}

function jsonOk(body = "{}"): Response {
  return centerReply(200, { type: "application/json", body });
}

function call(
  row: PageRoute,
  options: {
    headers?: Record<string, string>;
    body?: BodyInit | null;
    suffix?: string;
    sendOrigin?: boolean;
  } = {},
): Request {
  const headers = new Headers(options.headers);
  if (row.method === "POST") {
    if (options.sendOrigin !== false && !headers.has("origin")) headers.set("origin", origin);
    if (row.requestType !== "" && !headers.has("content-type"))
      headers.set("content-type", row.requestType);
  }
  const body =
    options.body !== undefined
      ? options.body
      : row.method === "POST" && row.requestType !== ""
        ? row.requestType === "application/json"
          ? "{}"
          : "csrf=x"
        : null;
  // The Workers runtime states the length of a body it received; a Request built here has to say so itself.
  if (typeof body === "string" && !headers.has("content-length"))
    headers.set("content-length", String(new TextEncoder().encode(body).length));
  return new Request(`https://proof.example.test/api${row.path}${options.suffix ?? ""}`, {
    method: row.method,
    headers,
    body,
  });
}

async function replyOf(row: PageRoute, centerAnswer: Response): Promise<Response> {
  const { env } = bindings(() => centerAnswer);
  return routeRequest(call(row, { headers: { "cf-connecting-ip": "203.0.113.7" } }), env);
}

test("the Container request says redirect manual, so the center's 303 reaches the browser instead of the page it leads to (H-1)", async () => {
  // Every route, every method: the Request the Container stub receives is told not to follow a redirect.
  for (const row of pageRoutes) {
    const { env, seen } = bindings(() => jsonOk());
    await (
      await routeRequest(call(row, { headers: { "cf-connecting-ip": "203.0.113.7" } }), env)
    ).arrayBuffer();
    assert.equal(seen.length, 1, `${row.method} ${row.path} reached the Container`);
    assert.equal(seen[0]?.request.redirect, "manual", `${row.method} ${row.path}`);
  }
  // The hosted finding: a page without a session is the center's 303 to the sign-in page. A stand-in that, like the platform, follows
  // a redirect it was not forbidden to follow turns it into a 404 of a path the center does not serve, which the handler refuses.
  for (const row of pageRoutes.filter((item) => item.redirects)) {
    const location = "/api/account/sign-in#return=%2Fapi%2Faccount%2Fpasskeys";
    const reply = await replyOf(row, centerReply(303, { headers: { location } }));
    assert.equal(reply.status, 303, row.path);
    assert.equal(reply.headers.get("location"), location, row.path);
    assert.equal(reply.headers.get("cache-control"), exactHeaders["cache-control"], row.path);
  }
  // The stand-in follows when the option is missing: this is what made every protected page answer 503 on proof.
  const platform = platformFetch(() =>
    centerReply(303, { headers: { location: "/api/account/sign-in" } }),
  );
  assert.equal((await platform(new Request("http://container/api/account/passkeys"))).status, 404);
  assert.equal(
    (await platform(new Request("http://container/api/account/passkeys", { redirect: "manual" })))
      .status,
    303,
  );
});

test("the generated page table is what the pages' contract names", () => {
  assert.deepEqual(Object.fromEntries(Object.entries(pageSecurityHeaders)), exactHeaders);
  assert.deepEqual([...pageStatuses], [200, 303, 400, 403, 404, 413, 415, 429]);
  assert.equal(pageCookieName, "__Host-af_session");
  assert.equal(pageLocationPrefix, "/api/account/");
  const keys = new Set<string>();
  for (const row of pageRoutes) {
    // The pages surface lives under the account and WebBrowserSession prefixes, the operations surface under its own.
    assert(
      row.surface === "operations"
        ? row.path.startsWith("/operations/")
        : row.path.startsWith("/account/") || row.path.startsWith("/session/v1/web/"),
      row.path,
    );
    assert(!/[?#%\\ ]|\/\/|\.\.|\/$/u.test(row.path), `canonical: ${row.path}`);
    assert(row.method === "GET" || row.method === "POST");
    assert.equal(keys.has(`${row.method} ${row.path}`), false);
    keys.add(`${row.method} ${row.path}`);
    assert(row.responseTypes.length > 0 && row.maxResponseBytes > 0);
    assert.equal(
      row.requestType === "" && row.maxRequestBytes === 0,
      row.method === "GET" || row.path.endsWith("/logout"),
    );
    assert(!row.redirects || row.kind === "html");
    assert(row.setCookie === "none" || row.cookie, `${row.path} sets a cookie it never receives`);
    assert.equal(pageTable.get(`/api${row.path}`)?.includes(row), true);
  }
  // Only the two sign-in steps set a session; only the sign-out and the revocations of the caller's own ends it.
  assert.deepEqual(
    pageRoutes.filter((row) => row.setCookie === "session").map((row) => row.path),
    ["/session/v1/web/authentication/complete", "/session/v1/web/enrollment/complete"],
  );
  assert.deepEqual(
    pageRoutes.filter((row) => row.setCookie === "clear").map((row) => row.path),
    ["/session/v1/web/logout", "/account/sessions/revoke", "/account/devices/revoke"],
  );
});

test("a disabled surface is the reply of a path the Worker does not know, before anything else", async () => {
  for (const flag of [undefined, "", "identity", "pages ", "Pages", "pages,pages"]) {
    const { env, seen, keys } = bindings(() => jsonOk(), { FLAGSHIP_SURFACES: flag });
    for (const row of pageRoutes) {
      const reply = await routeRequest(
        call(row, {
          headers: { authorization: "Bearer x", "cf-connecting-ip": "203.0.113.7" },
          suffix: "?q=1",
        }),
        env,
      );
      const unknown = await routeRequest(
        new Request("https://proof.example.test/api/account/not-a-page"),
        env,
      );
      assert.equal(reply.status, 404);
      assert.equal(await reply.text(), await unknown.text());
    }
    assert.equal(seen.length, 0);
    assert.equal(keys.length, 0);
  }
  const { env } = bindings(
    () => centerReply(200, { type: "text/html; charset=utf-8", body: "x" }),
    { FLAGSHIP_SURFACES: "pages" },
  );
  assert.equal((await routeRequest(call(signInPage), env)).status, 200);
});

test("a route belongs to its own surface: the operations page is not the pages' and is forwarded only while it is enabled", async () => {
  const operations = pageRoutes.filter((row) => row.surface === "operations");
  assert.deepEqual(
    operations.map((row) => `${row.method} ${row.path}`),
    ["GET /operations/grant", "POST /operations/grant/review", "POST /operations/grant/confirm"],
  );
  assert(operations.length < pageRoutes.length);
  // Every other route is of the pages surface, and the methods of one path share a surface.
  for (const row of pageRoutes.filter((item) => item.surface !== "operations"))
    assert.equal(row.surface, "pages", row.path);
  assert.equal(pageTable.get("/api/operations/grant")?.length, 1);
  for (const flag of ["identity,pages", "pages", "identity", "operations,x"]) {
    const { env, seen, keys } = bindings(() => jsonOk(), { FLAGSHIP_SURFACES: flag });
    for (const row of operations) {
      const reply = await routeRequest(
        call(row, { headers: { "cf-connecting-ip": "203.0.113.7" } }),
        env,
      );
      const unknown = await routeRequest(
        new Request("https://proof.example.test/api/account/not-a-page"),
        env,
      );
      assert.equal(reply.status, 404, `${flag} ${row.path}`);
      const unknownText = await unknown.text();
      assert.equal(await reply.text(), unknownText);
      // A method the route lacks is not told apart either: a disabled surface is answered 404 before the method is looked at, never
      // 405 (a path the Worker knows).
      const lacking = await routeRequest(
        new Request(`https://proof.example.test/api${row.path}`, { method: "DELETE" }),
        env,
      );
      assert.equal(lacking.status, 404, `${flag} DELETE ${row.path}`);
      assert.equal(await lacking.text(), unknownText, `${flag} DELETE ${row.path}`);
    }
    assert.equal(seen.length, 0, flag);
    assert.equal(keys.length, 0, flag);
  }
  // The pages surface alone does not open the operations page, and the operations surface alone does not open the pages.
  const { env: pagesOnly, seen: pagesSeen } = bindings(
    () => centerReply(200, { type: "text/html; charset=utf-8", body: "x" }),
    { FLAGSHIP_SURFACES: "identity,pages" },
  );
  assert.equal((await routeRequest(call(signInPage), pagesOnly)).status, 200);
  assert.equal(pagesSeen.length, 1);
  const { env: both } = bindings(
    () => centerReply(200, { type: "text/html; charset=utf-8", body: "x" }),
    { FLAGSHIP_SURFACES: "identity,pages,operations" },
  );
  const grant = route("GET", "/operations/grant");
  assert.equal((await routeRequest(call(grant), both)).status, 200);
});

test("the request side refuses what breaks the browser protocol before the limit and the Container", async () => {
  const { env, seen, keys } = bindings(() => jsonOk());
  const refuse = async (request: Request, status: number, what: string) => {
    const reply = await routeRequest(request, env);
    assert.equal(reply.status, status, what);
    assert.equal(reply.headers.get("cache-control"), "no-store", what);
    await reply.arrayBuffer();
  };
  for (const row of pageRoutes) {
    for (const suffix of ["?x=1", "?", "?a=b&a=c"])
      await refuse(call(row, { suffix }), 400, `${row.path}${suffix}`);
    await refuse(
      call(row, { headers: { authorization: "Bearer afa1.x" } }),
      400,
      `${row.path} with Authorization`,
    );
    const other = row.method === "GET" ? "POST" : "GET";
    await refuse(
      new Request(`https://proof.example.test/api${row.path}`, {
        method: other,
        headers: { origin },
      }),
      405,
      `${row.path} by ${other}`,
    );
    await refuse(
      new Request(`https://proof.example.test/api${row.path}`, { method: "DELETE" }),
      405,
      `${row.path} by DELETE`,
    );
    await refuse(
      new Request(`https://proof.example.test/api${row.path}`, { method: "HEAD" }),
      row.method === "GET" ? 405 : 405,
      `${row.path} by HEAD`,
    );
    if (row.method === "GET") {
      await refuse(
        new Request(`https://proof.example.test/api${row.path}`, {
          headers: { "transfer-encoding": "chunked" },
        }),
        400,
        `${row.path} with a body`,
      );
      if (row.cookie)
        await refuse(
          call(row, { headers: { cookie: `${pageCookieName}=short` } }),
          400,
          `${row.path} with a bad cookie`,
        );
      continue;
    }
    for (const bad of [
      undefined,
      "https://evil.example",
      "null",
      `${origin}/`,
      "http://proof.example.test",
      `${origin}, ${origin}`,
    ])
      await refuse(
        call(row, bad === undefined ? { sendOrigin: false } : { headers: { origin: bad } }),
        403,
        `${row.path} with Origin ${String(bad)}`,
      );
    if (row.requestType !== "") {
      for (const type of [
        "text/plain",
        "application/octet-stream",
        "application/json; charset=latin1",
        "multipart/form-data; boundary=x",
      ])
        await refuse(
          call(row, { headers: { "content-type": type } }),
          415,
          `${row.path} as ${type}`,
        );
      await refuse(
        call(row, {
          headers: {
            "content-type":
              row.requestType === "application/json"
                ? "application/x-www-form-urlencoded"
                : "application/json",
          },
        }),
        415,
        `${row.path} as the other type`,
      );
      await refuse(
        call(row, { headers: { "content-encoding": "gzip" } }),
        415,
        `${row.path} encoded`,
      );
      await refuse(
        call(row, { body: "x".repeat(row.maxRequestBytes + 1) }),
        413,
        `${row.path} over its bound`,
      );
      // Streamed without a declared length.
      const stream = new ReadableStream<Uint8Array>({
        start(controller) {
          controller.enqueue(new Uint8Array(row.maxRequestBytes + 1));
          controller.close();
        },
      });
      const streamed = new Request(`https://proof.example.test/api${row.path}`, {
        method: "POST",
        headers: { origin, "content-type": row.requestType },
        body: stream,
        duplex: "half",
      } as RequestInit);
      await refuse(streamed, 413, `${row.path} streamed over its bound`);
    }
  }
  await refuse(call(logout, { body: "{}" }), 413, "a sign-out with a body");
  await refuse(
    call(logout, {
      headers: { cookie: `${pageCookieName}=${handle}; ${pageCookieName}=${handle}` },
    }),
    400,
    "a repeated cookie",
  );
  await refuse(
    call(logout, { headers: { cookie: `${pageCookieName}=${"A".repeat(42)}` } }),
    400,
    "a short cookie",
  );
  await refuse(
    call(logout, { headers: { cookie: `${pageCookieName}=${"A".repeat(44)}` } }),
    400,
    "a long cookie",
  );
  await refuse(
    call(logout, { headers: { cookie: `${pageCookieName}=${"A".repeat(42)}=` } }),
    400,
    "a padded cookie",
  );
  const withoutOrigin = bindings(() => jsonOk(), { ALLOWED_ORIGIN: undefined });
  assert.equal((await routeRequest(call(begin), withoutOrigin.env)).status, 403);
  // A Worker configured with an empty origin accepts no request, not even one that states an empty Origin.
  const emptyOrigin = bindings(() => jsonOk(), { ALLOWED_ORIGIN: "" });
  assert.equal(
    (await routeRequest(call(begin, { headers: { origin: "" } }), emptyOrigin.env)).status,
    403,
  );
  assert.equal(emptyOrigin.seen.length, 0);
  assert.equal(seen.length, 0, "the Container is never called");
  // Only a body that has no declared length is read after the edge limit counted the call, and refused at its bound.
  assert.equal(
    keys.length,
    pageRoutes.filter((row) => row.method === "POST" && row.requestType !== "").length,
    "no limit counts a request refused from its headers",
  );
});

test("the edge limit counts page calls by the client's network and refuses with 429", async () => {
  const { env, seen, keys } = bindings(() => jsonOk());
  await routeRequest(call(signInPage, { headers: { "cf-connecting-ip": "2001:db8:a:b::1" } }), env);
  await routeRequest(call(begin, { headers: { "cf-connecting-ip": "203.0.113.7" } }), env);
  assert.deepEqual(keys, ["2001:db8:a:b::/64", "203.0.113.7"]);
  assert.equal(seen.length, 2);
  for (const limiter of [{ limit: async () => ({ success: false }) }, undefined]) {
    const limited = bindings(() => jsonOk(), { IDENTITY_RATE_LIMITER: limiter });
    const reply = await routeRequest(
      call(signInPage, { headers: { "cf-connecting-ip": "203.0.113.7" } }),
      limited.env,
    );
    assert.equal(reply.status, 429);
    assert.equal(reply.headers.get("retry-after"), "60");
    assert.equal(limited.seen.length, 0);
  }
});

test("only what the Worker builds reaches the Container", async () => {
  const { env, seen } = bindings(() => jsonOk());
  const reply = await routeRequest(
    call(stepUp, {
      headers: {
        "cf-connecting-ip": "203.0.113.7",
        "x-arcforges-client-ip": "198.51.100.1",
        cookie: `other=1; ${pageCookieName}=${handle}; analytics=2`,
        "x-af-csrf": token,
        "user-agent": "Mozilla/5.0 (X11; Linux x86_64) Firefox/130.0",
        referer: "https://elsewhere.example/",
        "x-forwarded-for": "198.51.100.2",
        traceparent: "00-11111111111111111111111111111111-2222222222222222-01",
        accept: "application/json",
      },
      body: '{"a":1}',
    }),
    env,
  );
  assert.equal(reply.status, 200);
  const forwarded = seen[0]?.request;
  assert(forwarded);
  assert.equal(forwarded.method, "POST");
  assert.equal(new URL(forwarded.url).pathname, stepUp.path);
  assert.equal(new URL(forwarded.url).search, "");
  assert.deepEqual(
    [...forwarded.headers.keys()].sort(),
    [
      "content-type",
      "cookie",
      "origin",
      "traceparent",
      "user-agent",
      "x-af-csrf",
      "x-arcforges-client-ip",
    ].sort(),
  );
  assert.equal(forwarded.headers.get("x-arcforges-client-ip"), "203.0.113.7");
  assert.equal(forwarded.headers.get("cookie"), `${pageCookieName}=${handle}`);
  assert.equal(forwarded.headers.get("origin"), origin);
  assert.equal(forwarded.headers.get("content-type"), "application/json");
  assert.equal(forwarded.headers.get("x-af-csrf"), token);
  assert.match(forwarded.headers.get("traceparent") ?? "", /^00-[0-9a-f]{32}-[0-9a-f]{16}-01$/u);
  assert.notEqual(
    forwarded.headers.get("traceparent"),
    "00-11111111111111111111111111111111-2222222222222222-01",
  );
  assert.equal(new TextDecoder().decode(seen[0]?.body), '{"a":1}');
  // A token that is not 43 base64url characters and a hostile User-Agent are not forwarded.
  for (const [csrf, agent] of [
    ["short", "x".repeat(300)],
    [`${token}=`, "bad\u0001agent"],
  ] as const) {
    const rebuilt = bindings(() => jsonOk());
    await routeRequest(
      call(stepUp, {
        headers: { "x-af-csrf": csrf, "user-agent": agent, "cf-connecting-ip": "203.0.113.7" },
      }),
      rebuilt.env,
    );
    assert.equal(rebuilt.seen[0]?.request.headers.get("x-af-csrf"), null);
    assert.equal(rebuilt.seen[0]?.request.headers.get("user-agent"), null);
  }
  // A page that never reads the session does not receive the cookie; a GET carries no Origin, token or body.
  const assets = bindings(() =>
    centerReply(200, { type: "text/javascript; charset=utf-8", body: "export {};" }),
  );
  await routeRequest(
    call(script, {
      headers: { cookie: `${pageCookieName}=${handle}`, "cf-connecting-ip": "203.0.113.7" },
    }),
    assets.env,
  );
  assert.equal(assets.seen[0]?.request.headers.get("cookie"), null);
  assert.equal(assets.seen[0]?.request.method, "GET");
  assert.equal(assets.seen[0]?.request.headers.get("origin"), null);
  // Without Cloudflare's header no address is forwarded.
  const anonymous = bindings(() => jsonOk());
  await routeRequest(
    call(begin, { headers: { "x-arcforges-client-ip": "198.51.100.1" } }),
    anonymous.env,
  );
  assert.equal(anonymous.seen[0]?.request.headers.get("x-arcforges-client-ip"), null);
  assert.equal(boundedUserAgent("Mozilla/5.0"), "Mozilla/5.0");
  assert.equal(boundedUserAgent(null), null);
  assert.equal(boundedUserAgent(""), null);
  assert.equal(sessionCookieOf(null), null);
  assert.equal(sessionCookieOf("a=b"), null);
  assert.equal(sessionCookieOf(`${pageCookieName}=${handle}`), handle);
});

test("a reply that keeps every rule is copied with exactly the generated headers", async () => {
  const html = centerReply(200, {
    type: "text/html; charset=utf-8",
    body: "<!doctype html><title>x</title>",
  });
  const reply = await replyOf(signInPage, html);
  assert.equal(reply.status, 200);
  assert.equal(await reply.text(), "<!doctype html><title>x</title>");
  assert.equal(reply.headers.get("content-type"), "text/html; charset=utf-8");
  for (const [name, value] of Object.entries(exactHeaders))
    assert.equal(reply.headers.get(name), value, name);
  assert.deepEqual(
    [...reply.headers.keys()].sort(),
    [...Object.keys(exactHeaders), "content-type"].sort(),
  );
  // A refusal of a JSON route and of an HTML route keeps its status and its route's media type.
  for (const status of [400, 403, 404, 413, 415, 429]) {
    const refused = await replyOf(
      begin,
      centerReply(status, { type: "application/json", body: '{"error":{}}' }),
    );
    assert.equal(refused.status, status);
    assert.equal(refused.headers.get("content-type"), "application/json");
  }
  const bare = await replyOf(script, centerReply(404));
  assert.equal(bare.status, 404);
  assert.equal(bare.headers.has("content-type"), false);
  assert.equal((await bare.arrayBuffer()).byteLength, 0);
});

test("a page reply that says no-store without no-transform is the Worker's 503: the edge would inject its beacon (H-2)", async () => {
  // Cloudflare's Web Analytics adds a third-party script to HTML that nothing forbids it to transform. The center forbids it on every
  // reply, and the Worker lets no reply through that does not say so, whatever its kind.
  assert.match(pageSecurityHeaders["cache-control"] ?? "", /(?:^|, )no-transform(?:,|$)/u);
  for (const row of pageRoutes) {
    const type = row.responseTypes[0] ?? "text/html; charset=utf-8";
    const old = await replyOf(
      row,
      centerReply(row.redirects ? 303 : 200, {
        type: row.redirects ? undefined : type,
        body: row.redirects ? undefined : "x",
        headers: {
          "cache-control": "no-store",
          ...(row.redirects ? { location: "/api/account/sign-in" } : {}),
        },
      }),
    );
    // The reply the browser gets is the Worker's: it carries the generated value, so the edge sees no-transform on what it forwards.
    const good = await replyOf(
      row,
      centerReply(row.redirects ? 303 : 200, {
        type: row.redirects ? undefined : type,
        body: row.redirects ? undefined : "x",
        headers: row.redirects ? { location: "/api/account/sign-in" } : {},
      }),
    );
    assert.equal(good.status, row.redirects ? 303 : 200, `${row.method} ${row.path}`);
    assert.equal(
      good.headers.get("cache-control"),
      "no-store, no-transform",
      `${row.method} ${row.path}`,
    );
    assert.equal(old.status, 503, `${row.method} ${row.path} with the old value`);
    assert.equal(
      old.headers.get("cache-control"),
      "no-store",
      "the Worker's own refusal is plain text",
    );
    assert.match(old.headers.get("content-type") ?? "", /^text\/plain/u);
  }
});

test("a reply that lacks a security header or differs from it is the Worker's 503", async () => {
  for (const name of Object.keys(pageSecurityHeaders)) {
    const missing = await replyOf(
      signInPage,
      centerReply(200, { type: "text/html; charset=utf-8", body: "x", skip: [name] }),
    );
    assert.equal(missing.status, 503, `${name} missing`);
    const wrong = await replyOf(
      signInPage,
      centerReply(200, {
        type: "text/html; charset=utf-8",
        body: "x",
        headers: { [name]: `${pageSecurityHeaders[name]}x` },
      }),
    );
    assert.equal(wrong.status, 503, `${name} differs`);
    assert.equal(wrong.headers.has("content-security-policy"), false);
    const folded = await replyOf(
      signInPage,
      centerReply(200, {
        type: "text/html; charset=utf-8",
        body: "x",
        headers: { [name]: `${pageSecurityHeaders[name]}, ${pageSecurityHeaders[name]}` },
      }),
    );
    assert.equal(folded.status, 503, `${name} repeated`);
  }
  // The policy is the one the plan names, with Trusted Types refused for every sink.
  assert.match(
    pageSecurityHeaders["content-security-policy"] ?? "",
    /require-trusted-types-for 'script'; trusted-types 'none'$/u,
  );
});

test("a status outside the generated list, a foreign media type and an oversized body are the Worker's 503", async () => {
  for (const status of [201, 204, 301, 302, 304, 307, 401, 405, 409, 410, 500, 502, 503, 504]) {
    const bodyless = status === 204 || status === 304;
    const reply = await replyOf(
      begin,
      centerReply(status, bodyless ? {} : { type: "application/json", body: "{}" }),
    );
    assert.equal(reply.status, 503, String(status));
    assert.equal(reply.headers.has("content-security-policy"), false);
  }
  for (const type of [
    "text/html; charset=utf-8",
    "text/plain",
    "application/json; charset=utf-8",
    "application/octet-stream",
    "text/javascript; charset=utf-8",
  ]) {
    assert.equal(
      (await replyOf(begin, centerReply(200, { type, body: "{}" }))).status,
      type === "application/json" ? 200 : 503,
      type,
    );
  }
  assert.equal(
    (await replyOf(signInPage, centerReply(200, { type: "application/json", body: "{}" }))).status,
    503,
  );
  assert.equal(
    (await replyOf(script, centerReply(200, { type: "text/html; charset=utf-8", body: "x" })))
      .status,
    503,
  );
  assert.equal(
    (await replyOf(begin, centerReply(200, { body: "{}" }))).status,
    503,
    "a body without a media type",
  );
  const big = "x".repeat(begin.maxResponseBytes + 1);
  assert.equal(
    (await replyOf(begin, centerReply(200, { type: "application/json", body: big }))).status,
    503,
  );
  const ok = "x".repeat(begin.maxResponseBytes);
  assert.equal(
    (await replyOf(begin, centerReply(200, { type: "application/json", body: ok }))).status,
    200,
  );
});

test("a Container that could not start is a retryable 503 and the center's own 429 is kept", async () => {
  const failed = await replyOf(
    signInPage,
    new Response("Failed to start container: boom", {
      status: 500,
      headers: { "content-type": "text/plain; charset=utf-8" },
    }),
  );
  assert.equal(failed.status, 503);
  assert(failed.headers.get("retry-after"));
  const limited = await replyOf(
    begin,
    centerReply(429, { type: "application/json", body: '{"error":{"code":"rate_limited"}}' }),
  );
  assert.equal(limited.status, 429);
});

test("a Set-Cookie is copied only in the exact form of the session cookie and only where the route allows it", async () => {
  // The sign-in step sets the session; the cookie is copied byte for byte.
  const signedIn = await replyOf(
    complete,
    centerReply(200, {
      type: "application/json",
      body: "{}",
      headers: { "set-cookie": sessionCookie },
    }),
  );
  assert.equal(signedIn.status, 200);
  assert.deepEqual(signedIn.headers.getSetCookie(), [sessionCookie]);
  // The sign-out removes it, on a 200 and, for a revocation of the caller's own session, on a 303.
  const out = await replyOf(
    logout,
    centerReply(200, {
      type: "application/json",
      body: "{}",
      headers: { "set-cookie": clearedCookie },
    }),
  );
  assert.deepEqual(out.headers.getSetCookie(), [clearedCookie]);
  const redirected = await replyOf(
    revoke,
    centerReply(303, {
      headers: { "set-cookie": clearedCookie, location: "/api/account/sign-in" },
    }),
  );
  assert.equal(redirected.status, 303);
  assert.deepEqual(redirected.headers.getSetCookie(), [clearedCookie]);
  assert.equal(redirected.headers.get("location"), "/api/account/sign-in");
  const ok = (value: string, row = complete) =>
    replyOf(
      row,
      centerReply(200, { type: "application/json", body: "{}", headers: { "set-cookie": value } }),
    );
  for (const value of [
    `${sessionCookie}; Domain=proof.example.test`,
    `${sessionCookie}; Partitioned`,
    sessionCookie.replace("SameSite=Strict", "SameSite=Lax"),
    sessionCookie.replace("; Secure", ""),
    sessionCookie.replace("; HttpOnly", ""),
    sessionCookie.replace("Path=/", "Path=/api"),
    sessionCookie.replace("__Host-", "__Secure-"),
    sessionCookie.replace(handle, "A".repeat(42)),
    sessionCookie.replace(handle, "A".repeat(44)),
    sessionCookie.replace("Max-Age=43200", "Max-Age=0"),
    sessionCookie.replace("Max-Age=43200", "Max-Age=-1"),
    sessionCookie.replace("Max-Age=43200", "Max-Age=99999999"),
    sessionCookie.replace("Max-Age=43200", "Expires=Fri, 31 Dec 2027 23:59:59 GMT"),
    `${sessionCookie};`,
    `other=1; Path=/`,
    clearedCookie,
    "",
  ])
    assert.equal((await ok(value)).status, 503, value);
  // The removal is exact too, and a session cookie is never accepted on the sign-out (nor its removal on a sign-in step).
  for (const value of [
    clearedCookie.replace("Max-Age=0", "Max-Age=1"),
    clearedCookie.replace("Secure; ", ""),
    `${clearedCookie}; Domain=x`,
    sessionCookie,
  ])
    assert.equal((await ok(value, logout)).status, 503, value);
  assert.equal((await ok(clearedCookie, complete)).status, 503);
  // Two cookies, and a cookie on a route that sets none, on a refusal, or on a page.
  const two = new Response("{}", {
    status: 200,
    headers: new Headers(
      Object.entries(pageSecurityHeaders).concat([["content-type", "application/json"]]),
    ),
  });
  two.headers.append("set-cookie", sessionCookie);
  two.headers.append("set-cookie", sessionCookie);
  assert.equal((await replyOf(complete, two)).status, 503);
  assert.equal((await ok(sessionCookie, begin)).status, 503);
  assert.equal((await ok(sessionCookie, bootstrap)).status, 503);
  assert.equal(
    (
      await replyOf(
        signInPage,
        centerReply(200, {
          type: "text/html; charset=utf-8",
          body: "x",
          headers: { "set-cookie": sessionCookie },
        }),
      )
    ).status,
    503,
  );
  assert.equal(
    (
      await replyOf(
        complete,
        centerReply(403, {
          type: "application/json",
          body: "{}",
          headers: { "set-cookie": sessionCookie },
        }),
      )
    ).status,
    503,
  );
  assert.equal(
    (
      await replyOf(
        complete,
        centerReply(303, {
          headers: { "set-cookie": sessionCookie, location: "/api/account/passkeys" },
        }),
      )
    ).status,
    503,
  );
  assert.equal(isAllowedSetCookie(sessionCookie, "none"), false);
});

test("the shapes a cookie and a Location are held to follow the generated values (worker-2)", () => {
  // The handle: the generated session-token shape, whatever its length (the pattern's own quantifier decides).
  const shape = sessionTokenPattern.source.slice(1, -1);
  const length = Number(/\{(\d+)\}$/u.exec(shape)?.[1]);
  assert(Number.isInteger(length) && length > 0, "the session token shape has a fixed length");
  const cookieOf = (handleText: string, maxAge: string) =>
    `${pageCookieName}=${handleText}; Path=/; Max-Age=${maxAge}; Secure; HttpOnly; SameSite=Strict`;
  assert.equal(isAllowedSetCookie(cookieOf("A".repeat(length), "1"), "session"), true);
  assert.equal(isAllowedSetCookie(cookieOf("A".repeat(length - 1), "1"), "session"), false);
  assert.equal(isAllowedSetCookie(cookieOf("A".repeat(length + 1), "1"), "session"), false);
  assert.equal(isAllowedSetCookie(cookieOf(`${"A".repeat(length - 1)}=`, "1"), "session"), false);
  // Max-Age: a positive number of at most the generated digits, without a leading zero.
  assert.equal(
    isAllowedSetCookie(cookieOf(handle, "9".repeat(pageCookieMaxAgeDigits)), "session"),
    true,
  );
  assert.equal(
    isAllowedSetCookie(cookieOf(handle, "9".repeat(pageCookieMaxAgeDigits + 1)), "session"),
    false,
  );
  for (const bad of ["", "0", "01", "-1", "1.5", "1e3", " 1"])
    assert.equal(isAllowedSetCookie(cookieOf(handle, bad), "session"), false, bad);
  // The return path in the sign-in redirect's fragment: one to the generated count of characters.
  const location = (path: string) => `${pageLocationPrefix}sign-in${pageReturnFragment}${path}`;
  assert.equal(isPageLocation(location("a")), true);
  assert.equal(isPageLocation(location("a".repeat(pageReturnPathBytes))), true);
  assert.equal(isPageLocation(location("a".repeat(pageReturnPathBytes + 1))), false);
  assert.equal(isPageLocation(location("")), false);
});

test("a Location is copied only on a 303 of a route that redirects, below the pages' prefix", async () => {
  const redirect = (location: string | null, row = sessionsPage, body: string | null = null) =>
    replyOf(
      row,
      centerReply(303, { headers: location === null ? {} : { location }, body: body ?? undefined }),
    );
  for (const good of [
    "/api/account/passkeys",
    "/api/account/sign-in",
    "/api/account/sign-in#return=%2Fapi%2Faccount%2Fsessions",
    "/api/account/devices",
  ]) {
    const reply = await redirect(good);
    assert.equal(reply.status, 303, good);
    assert.equal(reply.headers.get("location"), good);
    assert.equal((await reply.arrayBuffer()).byteLength, 0);
    assert.equal(isPageLocation(good), true);
    // A body the Container puts on a redirect never reaches the client.
    const withBody = await redirect(good, sessionsPage, "<p>not for the client</p>");
    assert.equal(withBody.status, 303, good);
    assert.equal(withBody.body, null, `${good}: a redirect has no body`);
    assert.equal((await withBody.arrayBuffer()).byteLength, 0);
  }
  for (const bad of [
    "https://proof.example.test/api/account/passkeys",
    "//evil.example/api/account/passkeys",
    "/api/account/passkeys?x=1",
    "/api/account",
    "/api/accounts/passkeys",
    "/api/account/../session",
    "/api/account//passkeys",
    "/api/account/Passkeys",
    "/api/account/passkeys/",
    "/api/account/passkeys#other",
    "/api/account/sign-in#return=",
    `/api/account/sign-in#return=${"a".repeat(513)}`,
    "/api/account/pass\\keys",
    "/api/account/pass keys",
    "/account/passkeys",
    "javascript:alert(1)",
    "",
  ]) {
    assert.equal((await redirect(bad)).status, 503, JSON.stringify(bad));
    assert.equal(isPageLocation(bad), false, JSON.stringify(bad));
  }
  assert.equal((await redirect(null)).status, 503, "a 303 without a Location");
  assert.equal(
    (await redirect("/api/account/passkeys", signInPage)).status,
    503,
    "the sign-in page does not redirect",
  );
  assert.equal(
    (await redirect("/api/account/passkeys", begin)).status,
    503,
    "a JSON route does not redirect",
  );
  assert.equal(
    (await redirect("/api/account/passkeys", script)).status,
    503,
    "an asset does not redirect",
  );
  // A Location on any other status is refused.
  const other = await replyOf(
    sessionsPage,
    centerReply(200, {
      type: "text/html; charset=utf-8",
      body: "x",
      headers: { location: "/api/account/passkeys" },
    }),
  );
  assert.equal(other.status, 503);
});

test("no other header of the Container reaches the client", async () => {
  const reply = await replyOf(
    signInPage,
    centerReply(200, {
      type: "text/html; charset=utf-8",
      body: "x",
      headers: {
        server: "center",
        "x-powered-by": "Go",
        "access-control-allow-origin": "*",
        "content-language": "en",
        link: "</x>; rel=preload",
        refresh: "0; url=/",
        vary: "cookie",
      },
    }),
  );
  assert.equal(reply.status, 200);
  for (const name of [
    "server",
    "x-powered-by",
    "access-control-allow-origin",
    "content-language",
    "link",
    "refresh",
    "vary",
  ])
    assert.equal(reply.headers.has(name), false, name);
});
