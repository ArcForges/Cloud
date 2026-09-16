// SPDX-License-Identifier: AGPL-3.0-only
import assert from "node:assert/strict";
import test from "node:test";
import {
  healthPath,
  helloPath,
  maxBodyBytes,
  routeRequest,
  type CloudBindings,
} from "../../worker/router.ts";

function fixture(allowed = true) {
  const received: Request[] = [];
  const names: string[] = [];
  const env: CloudBindings = {
    SOURCE_REVISION: "candidate",
    CLOUD_CONTAINER: {
      getByName(name) {
        names.push(name);
        return {
          async fetch(request) {
            received.push(request);
            return new Response(new Uint8Array([0, 0, 0, 0, 0]), {
              headers: { "content-type": "application/grpc-web+proto" },
            });
          },
        };
      },
    },
    HELLO_RATE_LIMITER: {
      async limit() {
        return { success: allowed };
      },
    },
  };
  return { env, received, names };
}

test("preserves binary payload and uses one fixed container, stripping only /api", async () => {
  const { env, received, names } = fixture();
  const payload = new Uint8Array([0, 0, 0, 0, 2, 10, 0]);
  const response = await routeRequest(
    new Request(`https://arcforges.com${helloPath}`, {
      method: "POST",
      headers: {
        "content-type": "application/grpc-web+proto",
        cookie: "private",
        authorization: "private",
      },
      body: payload,
    }),
    env,
  );
  assert.equal(response.status, 200);
  assert.equal(response.headers.get("x-arcforges-worker-revision"), "candidate");
  assert.deepEqual(names, ["hello"]);
  const forwarded = received[0];
  assert.ok(forwarded);
  assert.equal(new URL(forwarded.url).pathname, helloPath.slice(4));
  assert.equal(forwarded.headers.get("cookie"), null);
  assert.equal(forwarded.headers.get("authorization"), null);
  assert.match(forwarded.headers.get("grpc-timeout") ?? "", /^\d+m$/);
  assert.ok(Number.parseInt(forwarded.headers.get("grpc-timeout") ?? "", 10) <= 10000);
  assert.deepEqual(new Uint8Array(await forwarded.arrayBuffer()), payload);
  assert.deepEqual(new Uint8Array(await response.arrayBuffer()), new Uint8Array([0, 0, 0, 0, 0]));
});

test("unknown paths, verbs and content types never wake a container", async () => {
  const { env, received } = fixture();
  for (const [path, method, contentType, expected] of [
    ["/api/admin", "POST", "application/grpc-web+proto", 404],
    [helloPath.slice(4), "POST", "application/grpc-web+proto", 404],
    [`/api${helloPath}`, "POST", "application/grpc-web+proto", 404],
    [helloPath, "GET", "application/grpc-web+proto", 405],
    [healthPath, "POST", "application/grpc-web+proto", 405],
    [helloPath, "POST", "application/json", 415],
    [helloPath, "POST", "application/grpc", 415],
    [helloPath, "POST", "application/grpc-web-text+proto", 415],
    [helloPath, "POST", "application/grpc-web+json", 415],
    [`${helloPath}?admin=1`, "POST", "application/grpc-web+proto", 400],
  ] as const) {
    const result = await routeRequest(
      new Request(`https://arcforges.com${path}`, {
        method,
        headers: { "content-type": contentType },
      }),
      env,
    );
    assert.equal(result.status, expected);
  }
  assert.equal(received.length, 0);
});

test("limits actual body bytes without trusting content-length", async () => {
  const { env, received } = fixture();
  const result = await routeRequest(
    new Request(`https://arcforges.com${helloPath}`, {
      method: "POST",
      headers: { "content-type": "application/grpc-web+proto" },
      body: new Uint8Array(maxBodyBytes + 1),
    }),
    env,
  );
  assert.equal(result.status, 413);
  assert.equal(received.length, 0);
});

test("rate limit blocks the request before starting a container", async () => {
  const { env, received } = fixture(false);
  const result = await routeRequest(new Request(`https://arcforges.com${healthPath}`), env);
  assert.equal(result.status, 429);
  assert.equal(received.length, 0);
});

test("unavailable container returns 503 without retrying the call", async () => {
  const { env } = fixture();
  let attempts = 0;
  env.CLOUD_CONTAINER.getByName = () => ({
    fetch: async () => {
      attempts++;
      throw new Error("not provisioned yet");
    },
  });
  const result = await routeRequest(new Request(`https://arcforges.com${healthPath}`), env);
  assert.equal(result.status, 503);
  assert.equal(attempts, 1);
});

test("container startup error responses do not expose internal diagnostics", async () => {
  const { env } = fixture();
  env.CLOUD_CONTAINER.getByName = () => ({
    fetch: async () => new Response("Internal deployment details", { status: 500 }),
  });
  const response = await routeRequest(new Request(`https://arcforges.com${healthPath}`), env);
  assert.equal(response.status, 503);
  assert.equal(await response.text(), "Cloud container is temporarily unavailable.");
});
