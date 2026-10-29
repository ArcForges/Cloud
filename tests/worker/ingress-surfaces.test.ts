// SPDX-License-Identifier: AGPL-3.0-only
// The surface switch of the Worker (AF-CTR-03, DC-04, PLT-11, PLT-12): a method of a disabled surface is answered with the
// generated domain refusal STATE/not_activated without waking the Container; an enabled one passes its own edge rate limit (over it,
// the generated RESOURCE/rate_limited reply with its retry instant, F17), carries the client's address from Cloudflare's header only,
// and is forwarded like a production method. Both edge limits key an IPv6 client by its generated network (F7). FLAGSHIP_SURFACES is
// exact: anything but known names, comma-separated, enables nothing.
import assert from "node:assert/strict";
import test from "node:test";
import { edgeClientKey, rateLimitedReplyAt } from "../../worker/ingress/edge-limit.ts";
import { trailerFrame } from "../../worker/ingress/io.ts";
import {
  centerSurfaces,
  clientIpHeader,
  enabledSurfaces,
  notActivatedReplies,
  rateLimitedReply,
  surfaceTable,
} from "../../worker/ingress/routes.ts";
import { routeRequest, type CloudBindings } from "../../worker/router.ts";
import {
  edgeIpv6PrefixBits,
  edgeRateLimitPeriodSeconds,
  productionRoutes,
  rateLimitedReplyInstantOffsets,
  surfaceNames,
  surfaceRoutes,
} from "../../worker/tables/center-tables.generated.ts";

const grpcWeb = "application/grpc-web+proto";
const anonymous = surfaceRoutes.find((route) => route.auth === "anonymous");
const session = surfaceRoutes.find((route) => route.auth === "session");
assert(anonymous && session, "the identity surface has anonymous and session methods");

function frame(payload: number[]): Uint8Array<ArrayBuffer> {
  const bytes = new Uint8Array(5 + payload.length);
  new DataView(bytes.buffer).setUint32(1, payload.length);
  bytes.set(payload, 5);
  return bytes;
}

const okReply = new Uint8Array([...frame([1, 2]), ...trailerFrame(0)]);

function bindings(overrides: Partial<CloudBindings> = {}): {
  env: CloudBindings;
  seen: Request[];
  keys: string[];
} {
  const seen: Request[] = [];
  const keys: string[] = [];
  const env: CloudBindings = {
    SOURCE_REVISION: "candidate",
    CLOUD_CONTAINER: {
      getByName() {
        return {
          async fetch(request: Request) {
            seen.push(request);
            return new Response(okReply, { headers: { "content-type": grpcWeb } });
          },
        };
      },
    },
    HELLO_RATE_LIMITER: {
      limit: async () => {
        throw new Error("the Hello limiter does not count surface calls");
      },
    },
    IDENTITY_RATE_LIMITER: {
      limit: async ({ key }) => {
        keys.push(key);
        return { success: true };
      },
    },
    FLAGSHIP_SURFACES: "identity",
    ...overrides,
  };
  return { env, seen, keys };
}

function call(path: string, headers: Record<string, string> = {}): Request {
  return new Request(`https://proof.example.test/api${path}`, {
    method: "POST",
    headers: { "content-type": grpcWeb, ...headers },
    body: frame([10, 0]),
  });
}

function decode(base64: string): Uint8Array {
  return Uint8Array.from(atob(base64), (character) => character.charCodeAt(0));
}

/**
 * The template with the five given bytes at each instant offset. The center's own test (TestTheRateLimitedTemplateTakesTheWorkersInstant)
 * decodes such a body as its rate_limited refusal at that instant; here the expected bytes are fixed vectors.
 */
function withInstant(bytes: readonly number[]): Uint8Array {
  const body = decode(rateLimitedReply);
  for (const offset of rateLimitedReplyInstantOffsets) body.set(bytes, offset);
  return body;
}

test("FLAGSHIP_SURFACES enables exact generated names only", () => {
  assert.deepEqual([...enabledSurfaces("identity")], ["identity"]);
  for (const value of [
    undefined,
    "",
    "Identity",
    "identity,",
    ",identity",
    " identity",
    "identity ",
    "identity,identity",
    "none",
    "identity,operations",
  ]) {
    assert.equal(enabledSurfaces(value).size, 0, String(value));
    // The center is started with "none" for every such value, as its health then states.
    assert.equal(centerSurfaces(value), "none", String(value));
  }
  assert.equal(centerSurfaces("identity"), "identity");
  assert.deepEqual([...surfaceNames], ["identity"]);
  assert.equal(surfaceTable.size, surfaceRoutes.length);
  for (const route of surfaceRoutes) {
    assert.equal(route.instance, "hello");
    assert.equal(route.requestMeta, true);
    assert.equal(surfaceTable.get(`/api${route.path}`), route);
  }
});

test("a disabled surface is answered with the generated not_activated reply and wakes nothing", async () => {
  for (const flag of [undefined, "", "Identity", "identity "]) {
    const { env, seen, keys } = bindings({ FLAGSHIP_SURFACES: flag });
    for (const route of surfaceRoutes) {
      const response = await routeRequest(
        call(route.path, { authorization: "Bearer afa1.not-checked-at-all" }),
        env,
      );
      assert.equal(response.status, 200);
      assert.equal(response.headers.get("content-type"), grpcWeb);
      assert.deepEqual(
        new Uint8Array(await response.arrayBuffer()),
        decode(notActivatedReplies.identity),
      );
    }
    assert.equal(seen.length, 0, "the Container is never called");
    assert.equal(keys.length, 0, "no rate limit is consulted");
  }
});

test("an enabled surface forwards with its own rate limit and the client address from Cloudflare only", async () => {
  const { env, seen, keys } = bindings();
  const response = await routeRequest(
    call(anonymous.path, { "cf-connecting-ip": "203.0.113.7", [clientIpHeader]: "198.51.100.1" }),
    env,
  );
  assert.equal(response.status, 200);
  assert.deepEqual(new Uint8Array(await response.arrayBuffer()), okReply);
  assert.equal(seen.length, 1);
  assert.equal(new URL(seen[0]?.url ?? "").pathname, anonymous.path);
  assert.equal(
    seen[0]?.headers.get(clientIpHeader),
    "203.0.113.7",
    "the client's own header is never forwarded",
  );
  assert.deepEqual(keys, ["203.0.113.7"]);
  // Without Cloudflare's header no address is forwarded (the hosted center then refuses the call).
  await routeRequest(call(anonymous.path, { [clientIpHeader]: "198.51.100.1" }), env);
  assert.equal(seen[1]?.headers.get(clientIpHeader), null);
  // A session method still needs a credential at the edge.
  const unauthenticated = await routeRequest(call(session.path), env);
  assert.equal(new Uint8Array(await unauthenticated.arrayBuffer())[0], 0x80);
  assert.equal(seen.length, 2);
  await routeRequest(
    call(session.path, {
      authorization: "Bearer afa1.AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
    }),
    env,
  );
  assert.equal(
    seen[2]?.headers.get("authorization"),
    "Bearer afa1.AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
  );
});

test("over the edge limit, or without the limiter, a surface call gets the generated rate_limited reply", async () => {
  for (const limiter of [{ limit: async () => ({ success: false }) }, undefined]) {
    const { env, seen } = bindings({ IDENTITY_RATE_LIMITER: limiter });
    const before = Date.now();
    const response = await routeRequest(
      call(anonymous.path, { "cf-connecting-ip": "203.0.113.7" }),
      env,
    );
    const after = Date.now();
    assert.equal(response.status, 200);
    const body = new Uint8Array(await response.arrayBuffer());
    assert.equal(seen.length, 0);
    // The reply is the template with the retry instant of the refusal's time.
    assert(
      [before, after].some((at) => Buffer.from(rateLimitedReplyAt(at)).equals(Buffer.from(body))),
      "the reply is the template at the refusal's time",
    );
  }
});

test("the rate_limited reply's instants are the time rounded up to the second plus the edge period", () => {
  assert.equal(edgeRateLimitPeriodSeconds, 60);
  // The zigzag (sint64) seconds as five varint bytes: 2026-10-29T12:00:00.001Z rounds up to 1793275201, plus 60; and both ends of
  // the five-byte range (2^27 and 2^34 - 1 seconds).
  for (const [at, bytes] of [
    [Date.UTC(2026, 9, 29, 12, 0, 0, 1), [250, 213, 153, 174, 13]],
    [2 ** 27 * 1000 - 60000, [128, 128, 128, 128, 1]],
    [(2 ** 34 - 61) * 1000, [254, 255, 255, 255, 127]],
  ] as const)
    assert.deepEqual(rateLimitedReplyAt(at), withInstant(bytes), String(at));
});

test("an edge client key is the address, an IPv6 client's generated network", () => {
  assert.equal(edgeIpv6PrefixBits, 64);
  const network = "2001:db8:1:2::/64";
  for (const [address, key] of [
    ["203.0.113.7", "203.0.113.7"],
    ["::ffff:203.0.113.7", "203.0.113.7"],
    ["::ffff:cb00:7107", "203.0.113.7"],
    ["2001:db8:1:2:3:4:5:6", network],
    ["2001:db8:1:2:ffff:ffff:ffff:ffff", network],
    ["2001:DB8:1:2::1", network],
    ["2001:0db8:0001:0002::", network],
    ["2001:db8:1:3::1", "2001:db8:1:3::/64"],
    ["::1", "::/64"],
    ["not an address", "not an address"],
    ["fe80::1%eth0", "fe80::1%eth0"],
    ["1::2::3", "1::2::3"],
  ] as const)
    assert.equal(edgeClientKey(address), key, address);
  assert.equal(edgeClientKey(null), "local");
});

test("both edge limits key two addresses of one IPv6 network alike", async () => {
  const hello = productionRoutes[0]?.path ?? "";
  const helloKeys: string[] = [];
  const { env, keys } = bindings({
    HELLO_RATE_LIMITER: {
      limit: async ({ key }) => {
        helloKeys.push(key);
        return { success: true };
      },
    },
  });
  for (const address of ["2001:db8:a:b::1", "2001:db8:a:b:9::2", "2001:db8:a:c::1"]) {
    await routeRequest(call(anonymous.path, { "cf-connecting-ip": address }), env);
    await routeRequest(call(hello, { "cf-connecting-ip": address }), env);
  }
  assert.deepEqual(keys, ["2001:db8:a:b::/64", "2001:db8:a:b::/64", "2001:db8:a:c::/64"]);
  assert.deepEqual(helloKeys, keys);
});

test("a surface method keeps the transport rules of every method", async () => {
  const { env, seen } = bindings();
  const get = await routeRequest(
    new Request(`https://proof.example.test/api${anonymous.path}`),
    env,
  );
  assert.equal(get.status, 405);
  const query = await routeRequest(
    new Request(`https://proof.example.test/api${anonymous.path}?x=1`, {
      method: "POST",
      headers: { "content-type": grpcWeb },
    }),
    env,
  );
  assert.equal(query.status, 400);
  const json = await routeRequest(
    new Request(`https://proof.example.test/api${anonymous.path}`, {
      method: "POST",
      headers: { "content-type": "application/json" },
    }),
    env,
  );
  assert.equal(json.status, 415);
  const large = await routeRequest(
    new Request(`https://proof.example.test/api${anonymous.path}`, {
      method: "POST",
      headers: {
        "content-type": grpcWeb,
        "content-length": String(anonymous.maxRequestBytes + 1),
        "cf-connecting-ip": "203.0.113.7",
      },
      body: new Uint8Array(anonymous.maxRequestBytes + 1),
    }),
    env,
  );
  assert.equal(large.status, 413);
  assert.equal(seen.length, 0);
});
