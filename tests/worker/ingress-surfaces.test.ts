// SPDX-License-Identifier: AGPL-3.0-only
// The surface switch of the Worker (AF-CTR-03, DC-04, PLT-11, PLT-12): a method of a disabled surface is answered with the
// generated domain refusal STATE/not_activated without waking the Container; an enabled one passes its own edge rate limit (over it,
// the generated RESOURCE/rate_limited reply), carries the client's address from Cloudflare's header only, and is forwarded like a
// production method. FLAGSHIP_SURFACES is exact: anything but known names, comma-separated, enables nothing.
import assert from "node:assert/strict";
import test from "node:test";
import { trailerFrame } from "../../worker/ingress/io.ts";
import {
  clientIpHeader,
  enabledSurfaces,
  notActivatedReplies,
  rateLimitedReply,
  surfaceTable,
} from "../../worker/ingress/routes.ts";
import { routeRequest, type CloudBindings } from "../../worker/router.ts";
import { surfaceNames, surfaceRoutes } from "../../worker/tables/center-tables.generated.ts";

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
  ])
    assert.equal(enabledSurfaces(value).size, 0, String(value));
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
    const response = await routeRequest(
      call(anonymous.path, { "cf-connecting-ip": "203.0.113.7" }),
      env,
    );
    assert.equal(response.status, 200);
    assert.deepEqual(new Uint8Array(await response.arrayBuffer()), decode(rateLimitedReply));
    assert.equal(seen.length, 0);
  }
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
