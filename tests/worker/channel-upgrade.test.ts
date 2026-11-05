// SPDX-License-Identifier: AGPL-3.0-only
// The Worker's node channel route (AF-CTR-05 E1a, E1-23; Plan CTR5-HUB-02, PN-2, PN-3, PN-4): GET /api/fleet/v1/node passed through to
// the Container only as a WebSocket upgrade with the route's subprotocol and a native bearer, only while the relay surface is enabled,
// counted by the surfaces' edge limit, never with a cookie or another client header; the Container's 101 returned as the very Response
// object (with its WebSocket), and any other reply kept only as the center's refusal with its reason header. A disabled surface and every
// malformed request are answered by the Worker without waking the Container.
import assert from "node:assert/strict";
import test from "node:test";
import { routeRequest, type CloudBindings } from "../../worker/router.ts";
import { handleUpgradeRequest, upgradeTable } from "../../worker/ingress/upgrade.ts";
import {
  clientIpHeader,
  surfaceNames,
  upgradeRefusalBytes,
  upgradeRefusalHeader,
  upgradeRefusalStatuses,
  upgradeRoutes,
} from "../../worker/tables/center-tables.generated.ts";

const path = "/api/fleet/v1/node";
const token = `Bearer afn_${"a".repeat(40)}`;
const key = "dGhlIHNhbXBsZSBub25jZQ==";

interface Seen {
  request: Request;
  instance: string;
}

function bindings(
  reply: (request: Request) => Response | Promise<Response>,
  overrides: Partial<CloudBindings> = {},
): { env: CloudBindings; seen: Seen[]; keys: string[] } {
  const seen: Seen[] = [];
  const keys: string[] = [];
  const env: CloudBindings = {
    SOURCE_REVISION: "candidate",
    FLAGSHIP_SURFACES: "identity,pages,fleet,relay",
    CLOUD_CONTAINER: {
      getByName(instance: string) {
        return {
          async fetch(request: Request) {
            seen.push({ request, instance });
            return reply(request);
          },
        };
      },
    },
    HELLO_RATE_LIMITER: {
      limit: async () => {
        throw new Error("the Hello limiter does not count upgrades");
      },
    },
    IDENTITY_RATE_LIMITER: {
      limit: async ({ key: limited }) => {
        keys.push(limited);
        return { success: true };
      },
    },
    ...overrides,
  };
  return { env, seen, keys };
}

function upgradeHeaders(extra: Record<string, string> = {}): Record<string, string> {
  return {
    upgrade: "websocket",
    connection: "Upgrade",
    "sec-websocket-version": "13",
    "sec-websocket-key": key,
    "sec-websocket-protocol": "arcforges.relay.v1",
    authorization: token,
    "cf-connecting-ip": "203.0.113.9",
    ...extra,
  };
}

/** A 101 as the Durable Object returns it: Node's Response cannot carry 101, so a stand-in with a webSocket. */
function switching(): Response {
  return {
    status: 101,
    headers: new Headers({ upgrade: "websocket" }),
    webSocket: { accept() {} },
    body: null,
  } as unknown as Response;
}

test("the generated route is the relay surface's one upgrade route, served by the one center instance", () => {
  assert.deepEqual(
    upgradeRoutes.map((route) => [
      route.surface,
      route.method,
      route.path,
      route.subprotocol,
      route.instance,
    ]),
    [["relay", "GET", "/fleet/v1/node", "arcforges.relay.v1", "hello"]],
  );
  assert(surfaceNames.includes("relay"));
  assert.equal(upgradeTable.size, 1);
  assert(upgradeTable.has(path));
  // The frame bound leaves ample headroom under the platform's WebSocket message limit (32 MiB, Durable Objects).
  assert((upgradeRoutes[0]?.maxFrameBytes ?? Infinity) <= 1 << 20);
  assert.equal(upgradeRefusalHeader, "arcforges-refusal");
});

test("the Container's 101 is returned unchanged: the same Response object, with its WebSocket (PN-2)", async () => {
  const reply = switching();
  const { env, seen, keys } = bindings(() => reply);
  const response = await routeRequest(
    new Request(`https://api.example.test${path}`, { headers: upgradeHeaders() }),
    env,
  );
  assert.equal(response, reply, "the Worker rewrapped the 101");
  assert.equal(seen.length, 1);
  const seenFirst = seen[0];
  assert(seenFirst !== undefined);
  assert.equal(seenFirst.instance, "hello");
  assert.deepEqual(keys, ["203.0.113.9"]);
  const forwarded = seenFirst.request;
  assert.equal(forwarded.method, "GET");
  assert.equal(new URL(forwarded.url).pathname, "/fleet/v1/node");
  assert.equal(forwarded.redirect, "manual");
  assert.equal(forwarded.headers.get("authorization"), token);
  assert.equal(forwarded.headers.get("sec-websocket-protocol"), "arcforges.relay.v1");
  assert.equal(forwarded.headers.get("sec-websocket-key"), key);
  assert.equal(forwarded.headers.get(clientIpHeader), "203.0.113.9");
  assert.match(forwarded.headers.get("traceparent") ?? "", /^00-[0-9a-f]{32}-[0-9a-f]{16}-01$/u);
});

test("a cookie, an Origin and any other client header never reach the Container (PN-4)", async () => {
  const { env, seen } = bindings(() => switching());
  await routeRequest(
    new Request(`https://api.example.test${path}`, {
      headers: upgradeHeaders({
        cookie: "__Host-af_session=abc",
        origin: "https://evil.example.test",
        "x-forwarded-for": "198.51.100.1",
        "sec-websocket-extensions": "permessage-deflate",
        [clientIpHeader]: "198.51.100.2",
      }),
    }),
    env,
  );
  const first = seen[0];
  assert(first !== undefined, "the Container saw the upgrade");
  const names = [...first.request.headers.keys()].sort();
  assert.deepEqual(
    names,
    [
      "authorization",
      "connection",
      "sec-websocket-key",
      "sec-websocket-protocol",
      "sec-websocket-version",
      "traceparent",
      "upgrade",
      clientIpHeader,
    ].sort(),
  );
  assert.equal(first.request.headers.get(clientIpHeader), "203.0.113.9");
});

test("a disabled surface is the Worker's 404 with its reason, and wakes no Container", async () => {
  for (const surfaces of [undefined, "", "identity,pages,fleet", "identity,relay,relay"]) {
    const { env, seen, keys } = bindings(() => switching(), { FLAGSHIP_SURFACES: surfaces });
    const response = await routeRequest(
      new Request(`https://api.example.test${path}`, { headers: upgradeHeaders() }),
      env,
    );
    assert.equal(response.status, 404, String(surfaces));
    assert.equal(response.headers.get(upgradeRefusalHeader), "STATE/not_activated");
    assert.equal(seen.length, 0);
    assert.equal(keys.length, 0);
  }
});

test("a request that is not exactly the route's upgrade is refused before the edge limit and the Container", async () => {
  const cases: [string, RequestInit & { url?: string }, number, string][] = [
    [
      "a POST",
      { method: "POST", headers: upgradeHeaders(), body: "x" },
      405,
      "VALIDATION/invalid_argument",
    ],
    [
      "a query string",
      { url: `${path}?token=x`, headers: upgradeHeaders() },
      400,
      "VALIDATION/invalid_argument",
    ],
    [
      "no Upgrade",
      { headers: upgradeHeaders({ upgrade: "h2c" }) },
      400,
      "VALIDATION/invalid_argument",
    ],
    [
      "no Connection upgrade",
      { headers: upgradeHeaders({ connection: "keep-alive" }) },
      400,
      "VALIDATION/invalid_argument",
    ],
    [
      "another version",
      { headers: upgradeHeaders({ "sec-websocket-version": "8" }) },
      400,
      "VALIDATION/invalid_argument",
    ],
    [
      "a malformed key",
      { headers: upgradeHeaders({ "sec-websocket-key": "short" }) },
      400,
      "VALIDATION/invalid_argument",
    ],
    [
      "another subprotocol",
      { headers: upgradeHeaders({ "sec-websocket-protocol": "chat" }) },
      400,
      "VALIDATION/invalid_argument",
    ],
    [
      "two subprotocols",
      { headers: upgradeHeaders({ "sec-websocket-protocol": "arcforges.relay.v1, chat" }) },
      400,
      "VALIDATION/invalid_argument",
    ],
    [
      "no credential",
      { headers: upgradeHeaders({ authorization: "" }) },
      401,
      "AUTHENTICATION/unauthenticated",
    ],
    [
      "a cookie only",
      {
        headers: {
          ...upgradeHeaders({ cookie: "__Host-af_session=abc" }),
          authorization: "Basic eA==",
        },
      },
      401,
      "AUTHENTICATION/unauthenticated",
    ],
    [
      "a short bearer",
      { headers: upgradeHeaders({ authorization: "Bearer abc" }) },
      401,
      "AUTHENTICATION/unauthenticated",
    ],
  ];
  for (const [name, init, status, reason] of cases) {
    const { env, seen, keys } = bindings(() => switching());
    const headers = new Headers(init.headers);
    if (headers.get("authorization") === "") headers.delete("authorization");
    const response = await routeRequest(
      new Request(`https://api.example.test${init.url ?? path}`, { ...init, headers }),
      env,
    );
    assert.equal(response.status, status, name);
    assert.equal(response.headers.get(upgradeRefusalHeader), reason, name);
    assert.equal(seen.length, 0, name);
    assert.equal(keys.length, 0, name);
  }
});

test("the edge limit counts upgrades by the client's network; over it the Container never sees the call", async () => {
  for (const limiter of [undefined, { limit: async () => ({ success: false }) }]) {
    const { env, seen } = bindings(() => switching(), { IDENTITY_RATE_LIMITER: limiter });
    const response = await routeRequest(
      new Request(`https://api.example.test${path}`, { headers: upgradeHeaders() }),
      env,
    );
    assert.equal(response.status, 429);
    assert.equal(response.headers.get(upgradeRefusalHeader), "RESOURCE/rate_limited");
    assert(Number(response.headers.get("retry-after")) > 0);
    assert.equal(seen.length, 0);
  }
});

test("the center's refusal before the upgrade keeps its status, its JSON body and its reason headers, and nothing else (PN-3)", async () => {
  for (const status of upgradeRefusalStatuses) {
    const body = JSON.stringify({ error: { category: "authentication", code: "token_expired" } });
    const { env } = bindings(
      () =>
        new Response(body, {
          status,
          headers: {
            "content-type": "application/json",
            "arcforges-refusal": "AUTHENTICATION/token_expired",
            "retry-after": "7",
            "set-cookie": "a=b",
            "x-internal": "secret",
          },
        }),
    );
    const response = await routeRequest(
      new Request(`https://api.example.test${path}`, { headers: upgradeHeaders() }),
      env,
    );
    assert.equal(response.status, status);
    assert.equal(response.headers.get(upgradeRefusalHeader), "AUTHENTICATION/token_expired");
    assert.equal(response.headers.get("retry-after"), "7");
    assert.equal(response.headers.get("set-cookie"), null);
    assert.equal(response.headers.get("x-internal"), null);
    assert.equal(await response.text(), body);
  }
  // A status the center never answers before an upgrade, another media type and an oversized body are the Worker's own 503.
  for (const reply of [
    () =>
      new Response("{}", {
        status: 302,
        headers: { "content-type": "application/json", location: "/x" },
      }),
    () => new Response("{}", { status: 200, headers: { "content-type": "application/json" } }),
    () => new Response("<html>", { status: 403, headers: { "content-type": "text/html" } }),
    () =>
      new Response("x".repeat(upgradeRefusalBytes + 1), {
        status: 403,
        headers: { "content-type": "application/json" },
      }),
  ]) {
    const { env } = bindings(reply);
    const response = await routeRequest(
      new Request(`https://api.example.test${path}`, { headers: upgradeHeaders() }),
      env,
    );
    assert.equal(response.status, 503);
    // The Worker's own 503 names its fixed reason (review B N-5), never the center's header it dropped.
    assert.equal(response.headers.get(upgradeRefusalHeader), "RESOURCE/overloaded");
  }
});

test("a Container that fails is the Worker's 503", async () => {
  const { env } = bindings(() => {
    throw new Error("no container");
  });
  const response = await routeRequest(
    new Request(`https://api.example.test${path}`, { headers: upgradeHeaders() }),
    env,
  );
  assert.equal(response.status, 503);
  assert.equal(response.headers.get(upgradeRefusalHeader), "RESOURCE/overloaded");
});

test("the Worker's own deadline and cancel answers carry their reason too", async () => {
  // review B N-5: a client such as .NET's ClientWebSocket sees only the status and the headers of a reply that is not 101.
  const route = upgradeRoutes[0];
  assert(route);
  const { env } = bindings(() => new Promise<Response>(() => {}));
  const deadline = await handleUpgradeRequest(
    new Request(`https://api.example.test${path}`, { headers: upgradeHeaders() }),
    env,
    { ...route, maxDurationMs: 20 },
    {},
  );
  assert.equal(deadline.status, 504);
  assert.equal(deadline.headers.get(upgradeRefusalHeader), "RESOURCE/overloaded");
  const gone = new AbortController();
  gone.abort();
  const canceled = await handleUpgradeRequest(
    new Request(`https://api.example.test${path}`, {
      headers: upgradeHeaders(),
      signal: gone.signal,
    }),
    env,
    route,
    {},
  );
  assert.equal(canceled.status, 499);
  assert.equal(canceled.headers.get(upgradeRefusalHeader), "RESOURCE/overloaded");
});
