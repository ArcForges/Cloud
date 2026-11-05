// SPDX-License-Identifier: AGPL-3.0-only
// The Worker's mobile rows (AF-CTR-04 part M, MB-3, MB-8, M-13, M-15): the two native JSON routes of the mobile app (POST, exactly
// application/json, no cookie in or out, no Origin or CSRF requirement, no CORS) and the two exact apex paths at the root of the host
// (GET, no cookie forwarded, no redirect), forwarded only while the mobile surface is enabled and otherwise answered 404 by the
// Worker; replies held to the page handler's rules. Production's route list and its plain paths are unchanged.
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import path from "node:path";
import test from "node:test";
import { apexTable } from "../../worker/ingress/applink.ts";
import { nativeTable } from "../../worker/ingress/native.ts";
import { routeRequest, type CloudBindings } from "../../worker/router.ts";
import {
  apexRoutes,
  clientAsnHeader,
  clientCountryHeader,
  clientIpHeader,
  nativeRoutes,
  pageRoutes,
  pageSecurityHeaders,
  productionRoutes,
} from "../../worker/tables/center-tables.generated.ts";
import { platformFetch } from "./support/platform-fetch.ts";

const origin = "https://proof.example.test";
const statement = "[]";

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
    FLAGSHIP_SURFACES: "identity,pages,mobile",
    CLOUD_CONTAINER: {
      getByName() {
        return {
          async fetch(request: Request) {
            seen.push({ request, body: new Uint8Array(await request.clone().arrayBuffer()) });
            return platformFetch(reply)(request);
          },
        };
      },
    },
    HELLO_RATE_LIMITER: {
      limit: async () => {
        throw new Error("the Hello limiter does not count mobile calls");
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

function centerReply(
  status: number,
  options: { type?: string; body?: string; headers?: Record<string, string> } = {},
): Response {
  const headers = new Headers(pageSecurityHeaders);
  if (options.type) headers.set("content-type", options.type);
  for (const [name, value] of Object.entries(options.headers ?? {})) headers.set(name, value);
  return new Response(options.body ?? null, { status, headers });
}

const begin = "/api/session/v1/mobile/begin";
const token = "/api/session/v1/mobile/token";
const json = { "content-type": "application/json" };
const body = '{"clientId":"arcforges.android"}';

test("the generated mobile rows are exactly the contract's native routes and the two apex paths", () => {
  assert.deepEqual(
    nativeRoutes.map((row) => `${row.method} ${row.path} ${row.surface} ${row.requestType}`),
    [
      "POST /session/v1/mobile/begin mobile application/json",
      "POST /session/v1/mobile/token mobile application/json",
    ],
  );
  assert.deepEqual(
    nativeRoutes.map((row) => [row.maxRequestBytes, row.maxResponseBytes]),
    [
      [4096, 4096],
      [4096, 65536],
    ],
  );
  assert.deepEqual(
    apexRoutes.map(
      (row) => `${row.method} ${row.path} ${row.surface} ${row.responseTypes.join(",")}`,
    ),
    [
      "GET /.well-known/assetlinks.json mobile application/json",
      "GET /app/callback mobile text/html; charset=utf-8",
    ],
  );
  assert.deepEqual([...nativeTable.keys()], [begin, token]);
  assert.deepEqual([...apexTable.keys()], ["/.well-known/assetlinks.json", "/app/callback"]);
  // No native or apex path is a page row, and only the page rows live under the mobile page prefix.
  for (const row of pageRoutes) {
    assert(!row.path.startsWith("/session/v1/mobile/") && !row.path.startsWith("/app/"), row.path);
    if (row.surface === "mobile") assert(row.path.startsWith("/mobile/authorize"), row.path);
  }
});

test("a native request is forwarded with only the client's address, origin, traceparent, content type and body", async () => {
  const { env, seen, keys } = bindings(() =>
    centerReply(200, { type: "application/json", body: '{"flowId":"x"}' }),
  );
  const request = new Request(`https://proof.example.test${begin}`, {
    method: "POST",
    headers: {
      ...json,
      origin,
      "x-af-csrf": "B".repeat(43),
      "cf-connecting-ip": "203.0.113.9",
      "user-agent": "okhttp/5",
      [clientIpHeader]: "198.51.100.1",
      [clientCountryHeader]: "XX",
    },
    body,
  });
  Object.defineProperty(request, "cf", { value: { country: "DE", asn: 3320 } });
  const reply = await routeRequest(request, env);
  assert.equal(reply.status, 200);
  assert.equal(await reply.text(), '{"flowId":"x"}');
  assert.equal(reply.headers.get("cache-control"), "no-store, no-transform");
  assert.equal(reply.headers.get("access-control-allow-origin"), null);
  assert.equal(seen.length, 1);
  const [first] = seen;
  assert(first);
  const forwarded = first.request;
  assert.equal(new URL(forwarded.url).pathname, "/session/v1/mobile/begin");
  assert.equal(forwarded.redirect, "manual");
  assert.deepEqual(
    [...forwarded.headers.keys()].sort(),
    ["content-type", clientAsnHeader, clientCountryHeader, clientIpHeader, "traceparent"].sort(),
  );
  assert.equal(forwarded.headers.get(clientIpHeader), "203.0.113.9");
  assert.equal(forwarded.headers.get(clientCountryHeader), "DE");
  assert.equal(new TextDecoder().decode(first.body), body);
  assert.equal(keys.length, 1);
});

test("a native request with a cookie, another media type, a query, Authorization or another method is refused before the Container", async () => {
  const { env, seen, keys } = bindings(() => centerReply(200, { type: "application/json" }));
  const send = (init: RequestInit & { path?: string }) =>
    routeRequest(new Request(`https://proof.example.test${init.path ?? begin}`, init), env);
  const refusals: [RequestInit & { path?: string }, number][] = [
    [
      { method: "POST", headers: { ...json, cookie: `__Host-af_session=${"A".repeat(43)}` }, body },
      400,
    ],
    [{ method: "POST", headers: { ...json, cookie: "other=1" }, body }, 400],
    [{ method: "POST", headers: { "content-type": "text/plain" }, body }, 415],
    [{ method: "POST", headers: { "content-type": "application/json; charset=utf-8" }, body }, 415],
    [
      { method: "POST", headers: { "content-type": "application/x-www-form-urlencoded" }, body },
      415,
    ],
    [{ method: "POST", body }, 415],
    [{ method: "POST", headers: { ...json, authorization: "Bearer x" }, body }, 400],
    [{ method: "POST", headers: json, body, path: `${token}?x=1` }, 400],
    [{ method: "GET", path: token }, 405],
    [{ method: "OPTIONS", headers: { origin, "access-control-request-method": "POST" } }, 405],
    [{ method: "POST", headers: { ...json, "content-encoding": "gzip" }, body }, 415],
    [
      { method: "POST", headers: { ...json, "content-length": "4097" }, body: "x".repeat(4097) },
      413,
    ],
  ];
  for (const [init, status] of refusals) {
    const reply = await send(init);
    assert.equal(reply.status, status, `${init.method} ${JSON.stringify(init.headers)}`);
  }
  assert.equal(seen.length, 0);
  assert.equal(keys.length, 0);
});

test("a native reply that sets a cookie, redirects or is not JSON is the Worker's 503", async () => {
  for (const reply of [
    centerReply(200, { type: "application/json", body: "{}", headers: { "set-cookie": "a=b" } }),
    centerReply(303, { headers: { location: "/api/account/sign-in" } }),
    centerReply(200, { type: "text/html; charset=utf-8", body: "<p>" }),
    new Response("{}", { status: 200, headers: json }),
  ]) {
    const { env } = bindings(() => reply);
    const answered = await routeRequest(
      new Request(`https://proof.example.test${begin}`, { method: "POST", headers: json, body }),
      env,
    );
    assert.equal(answered.status, 503);
  }
});

test("the apex rows forward a bare GET to the same center path and carry no cookie", async () => {
  const { env, seen } = bindings((request) =>
    new URL(request.url).pathname === "/.well-known/assetlinks.json"
      ? centerReply(200, { type: "application/json", body: statement })
      : centerReply(200, { type: "text/html; charset=utf-8", body: "<!doctype html>" }),
  );
  const links = await routeRequest(
    new Request("https://proof.example.test/.well-known/assetlinks.json", {
      headers: { cookie: `__Host-af_session=${"A".repeat(43)}`, "cf-connecting-ip": "203.0.113.9" },
    }),
    env,
  );
  assert.equal(links.status, 200);
  assert.equal(await links.text(), statement);
  assert.equal(links.headers.get("content-type"), "application/json");
  assert.equal(links.headers.get("x-content-type-options"), "nosniff");
  const page = await routeRequest(new Request("https://proof.example.test/app/callback"), env);
  assert.equal(page.status, 200);
  assert.equal(
    page.headers.get("content-security-policy"),
    pageSecurityHeaders["content-security-policy"],
  );
  assert.deepEqual(
    seen.map((item) => new URL(item.request.url).pathname),
    ["/.well-known/assetlinks.json", "/app/callback"],
  );
  for (const item of seen) {
    assert.equal(item.request.method, "GET");
    assert.equal(item.request.redirect, "manual");
    assert.equal(item.request.headers.get("cookie"), null);
  }
  for (const [init, status] of [
    [{ method: "POST", body: "x" }, 405],
    [{ headers: { authorization: "Bearer x" } }, 400],
  ] as const) {
    const reply = await routeRequest(
      new Request("https://proof.example.test/app/callback", init),
      env,
    );
    assert.equal(reply.status, status);
  }
  const query = await routeRequest(
    new Request("https://proof.example.test/app/callback?code=x"),
    env,
  );
  assert.equal(query.status, 400);
  // An apex reply that redirects (Android's verifier follows none) or sets a cookie is the Worker's 503.
  for (const reply of [
    centerReply(302, { headers: { location: "https://elsewhere.example/" } }),
    centerReply(200, { type: "application/json", body: "[]", headers: { "set-cookie": "a=b" } }),
  ]) {
    const { env: other } = bindings(() => reply);
    const answered = await routeRequest(
      new Request("https://proof.example.test/.well-known/assetlinks.json"),
      other,
    );
    assert.equal(answered.status, 503);
  }
  // Only the exact apex paths are rows: any other path of the host stays the Worker's 404.
  for (const other of [
    "/app",
    "/app/node/1",
    "/app/callback/x",
    "/.well-known/other",
    "/api/app/callback",
  ]) {
    const reply = await routeRequest(new Request(`https://proof.example.test${other}`), env);
    assert.equal(reply.status, 404, other);
  }
});

test("a disabled mobile surface answers 404 on every mobile row and wakes no Container", async () => {
  for (const surfaces of [undefined, "", "identity,pages", "identity,pages,fleet"]) {
    const { env, seen, keys } = bindings(() => centerReply(200), { FLAGSHIP_SURFACES: surfaces });
    for (const [url, init] of [
      [`https://proof.example.test${begin}`, { method: "POST", headers: json, body }],
      [`https://proof.example.test${token}`, { method: "POST", headers: json, body }],
      ["https://proof.example.test/.well-known/assetlinks.json", {}],
      ["https://proof.example.test/app/callback", {}],
      ["https://proof.example.test/api/mobile/authorize", {}],
      [
        "https://proof.example.test/api/mobile/authorize/review",
        { method: "POST", headers: { origin } },
      ],
    ] as const) {
      const reply = await routeRequest(new Request(url, init), env);
      assert.equal(reply.status, 404, `${surfaces} ${url}`);
    }
    assert.equal(seen.length, 0);
    assert.equal(keys.length, 0);
  }
});

test("over the edge limit a mobile row is 429 and the Container never sees it", async () => {
  const { env, seen } = bindings(() => centerReply(200), {
    IDENTITY_RATE_LIMITER: { limit: async () => ({ success: false }) },
  });
  for (const request of [
    new Request(`https://proof.example.test${begin}`, { method: "POST", headers: json, body }),
    new Request("https://proof.example.test/.well-known/assetlinks.json"),
  ]) {
    const reply = await routeRequest(request, env);
    assert.equal(reply.status, 429);
    assert.equal(reply.headers.get("retry-after"), "60");
  }
  assert.equal(seen.length, 0);
});

test("production stays dark: one Worker route under /api, the Hello method only, and no mobile surface or Android app", () => {
  const root = path.resolve(import.meta.dirname, "../..");
  const wrangler = JSON.parse(readFileSync(path.join(root, "wrangler.json"), "utf8")) as {
    routes: unknown;
    vars: Record<string, string>;
    env: { proof: { vars: Record<string, string>; routes: unknown } };
  };
  assert.deepEqual(wrangler.routes, [
    { pattern: "arcforges.com/api/*", zone_name: "arcforges.com" },
  ]);
  assert.equal(wrangler.vars.FLAGSHIP_SURFACES, "");
  assert.equal(wrangler.vars.ARCFORGES_CENTER_ANDROID_APP, undefined);
  assert.equal(wrangler.vars.ARCFORGES_CENTER_MOBILE_DEBUG_REDIRECT, undefined);
  assert.equal(wrangler.env.proof.vars.ARCFORGES_CENTER_MOBILE_DEBUG_REDIRECT, undefined);
  assert.deepEqual(wrangler.env.proof.routes, [
    { pattern: "proof.arcforges.com", custom_domain: true },
  ]);
  assert.deepEqual(
    productionRoutes.map((row) => row.path),
    ["/arcforges.hello.v1.HelloService/SayHello"],
  );
});
