// SPDX-License-Identifier: AGPL-3.0-only
import assert from "node:assert/strict";
import test from "node:test";
import {
  commerceOutboundHosts,
  commerceTransportEnvironment,
  handleCommerceEgress as actualHandleCommerceEgress,
  requestByteLimit,
  responseByteLimit,
  maxConcurrentTransports,
} from "../../worker/commerce-provider/egress.ts";

const suffix = "01grnn4zta5a1mf02jjze7y2ys";
const credential = "component-transport-secret-only";
const environment = { COMMERCE_EGRESS: "production" };
const price = `/prices/pri_${suffix}?include=product`;
// Consume every returned production stream before the next assertion; its aggregate memory permit
// remains held until EOF/cancel. Dedicated lifecycle cases below exercise unconsumed streams directly.
async function handleCommerceEgress(...args: Parameters<typeof actualHandleCommerceEgress>) {
  const response = await actualHandleCommerceEgress(...args);
  const bytes = await response.arrayBuffer();
  return new Response(bytes, { status: response.status, headers: response.headers });
}
function request(
  path = price,
  method = "GET",
  body?: BodyInit,
  headers: Record<string, string> = {},
  signal?: AbortSignal,
) {
  return new Request(path.startsWith("http") ? path : `https://api.paddle.com${path}`, {
    method,
    body,
    headers: {
      authorization: `Bearer ${credential}`,
      "paddle-version": "1",
      ...(body ? { "content-type": "application/json" } : {}),
      ...headers,
    },
    signal,
    duplex: "half",
  } as RequestInit);
}
function transport(reply: () => Response = () => Response.json({ data: "component" })) {
  const calls: Request[] = [];
  const fetcher: typeof fetch = async (input) => {
    assert(input instanceof Request);
    calls.push(input);
    return reply();
  };
  return { calls, fetcher };
}

test("real request construction forwards exact admitted hosts, purpose paths and closed headers", async () => {
  const { calls, fetcher } = transport();
  const paths: [string, string, string?][] = [
    [price, "GET"],
    [`/transactions/txn_${suffix}?include=address`, "GET"],
    [
      "/transactions?per_page=30&include=address&updated_at[GTE]=2026-10-01T00:00:00Z&updated_at[LTE]=2026-11-01T00:00:00Z",
      "GET",
    ],
    [`/subscriptions/sub_${suffix}`, "GET"],
    ["/subscriptions?per_page=30", "GET"],
    [`/adjustments?per_page=1&id=adj_${suffix}`, "GET"],
    ["/adjustments?per_page=30", "GET"],
    ["/events?per_page=200&order_by=id[ASC]", "GET"],
    ["/transactions", "POST", "{}"],
    ["/adjustments", "POST", "{}"],
    [`/subscriptions/sub_${suffix}/cancel`, "POST", "{}"],
    [`/subscriptions/sub_${suffix}`, "PATCH", "{}"],
    [`/customers/ctm_${suffix}/portal-sessions`, "POST", "{}"],
  ];
  for (const [path, method, body] of paths)
    assert.equal(
      (
        await handleCommerceEgress(
          request(path, method, body, {
            cookie: "never=forward",
            "x-target-host": "private.internal",
            "x-secret": credential,
          }),
          environment,
          fetcher,
        )
      ).status,
      200,
    );
  for (const call of calls) {
    assert.equal(new URL(call.url).hostname, "api.paddle.com");
    assert.equal(call.headers.get("authorization"), `Bearer ${credential}`);
    assert.equal(call.headers.get("paddle-version"), "1");
    assert.equal(call.headers.get("cookie"), null);
    assert.equal(call.headers.get("x-target-host"), null);
    assert.equal(call.headers.get("x-secret"), null);
    assert.equal(call.redirect, "manual");
  }
});

test("configuration is explicit, environment-specific, and secret-free", async () => {
  assert.deepEqual(commerceTransportEnvironment({}), {});
  assert.deepEqual(commerceTransportEnvironment({ COMMERCE_EGRESS: "disabled" }), {});
  assert.deepEqual(commerceTransportEnvironment(environment), {
    ARCFORGES_COMMERCE_EGRESS: "enabled",
  });
  assert.throws(() => commerceTransportEnvironment({ COMMERCE_EGRESS: "typo" }));
  assert.deepEqual(Object.keys(commerceOutboundHosts).sort(), [
    "api.paddle.com",
    "sandbox-api.paddle.com",
  ]);
  const { calls, fetcher } = transport();
  assert.equal((await handleCommerceEgress(request(), {}, fetcher)).status, 503);
  assert.equal(
    (await handleCommerceEgress(request(), { COMMERCE_EGRESS: "sandbox" }, fetcher)).status,
    403,
  );
  assert.equal(
    (
      await handleCommerceEgress(
        request(`https://sandbox-api.paddle.com${price}`),
        { COMMERCE_EGRESS: "sandbox" },
        fetcher,
      )
    ).status,
    200,
  );
  assert.equal(calls.length, 1);
});

test("scheme, exact hostname, port, credentials, method, path, query and authentication failures never dispatch", async () => {
  const { calls, fetcher } = transport();
  assert.throws(() => request(`https://user:pass@api.paddle.com${price}`), /credentials/u);
  for (const url of [
    `http://api.paddle.com${price}`,
    `https://api.paddle.com:8443${price}`,
    `https://api.paddle.com.evil.test${price}`,
    `https://127.0.0.1${price}`,
    `https://[::1]${price}`,
    `https://private.internal${price}`,
    `https://sandbox-api.paddle.com${price}`,
    `https://api.paddle.com${price}#fragment`,
    "/products",
    "/transactions/invalid",
    `/subscriptions/sub_${suffix}/`,
    `/subscriptions/sub_${suffix}/pause`,
    `${price}&arbitrary=1`,
    `${price}&include=product`,
    `/events?per_page=201`,
    `/events?order_by=id[DESC]`,
    `/subscriptions?after=txn_${suffix}`,
    `/subscriptions?include=product`,
    `/prices/pri_${suffix}?include=other`,
  ])
    assert.equal((await handleCommerceEgress(request(url), environment, fetcher)).status, 403, url);
  for (const method of ["DELETE", "PUT", "OPTIONS", "HEAD"])
    assert.equal(
      (await handleCommerceEgress(request(price, method), environment, fetcher)).status,
      403,
    );
  const invalidHeaders: Record<string, string>[] = [
    { authorization: "" },
    { authorization: "Basic invalid" },
    { "paddle-version": "2" },
    { "content-encoding": "gzip" },
  ];
  for (const headers of invalidHeaders)
    assert.equal(
      (await handleCommerceEgress(request(price, "GET", undefined, headers), environment, fetcher))
        .status,
      403,
    );
  assert.equal(
    (
      await handleCommerceEgress(
        request("/transactions", "POST", "{}", { "content-type": "text/plain" }),
        environment,
        fetcher,
      )
    ).status,
    403,
  );
  assert.equal(calls.length, 0);
});

test("declared, actual and malformed request bounds fail before dispatch", async () => {
  const { calls, fetcher } = transport();
  for (const length of [
    String(requestByteLimit + 1),
    "999999999999999999999999999999999",
    "-1",
    "1.5",
    "0002",
    "3",
  ])
    assert.equal(
      (
        await handleCommerceEgress(
          request("/transactions", "POST", "{}", { "content-length": length }),
          environment,
          fetcher,
        )
      ).status,
      413,
    );
  assert.equal(
    (
      await handleCommerceEgress(
        request("/transactions", "POST", "x".repeat(requestByteLimit + 1)),
        environment,
        fetcher,
      )
    ).status,
    413,
  );
  assert.equal(
    (await handleCommerceEgress(request("/transactions", "POST"), environment, fetcher)).status,
    403,
  );
  assert.equal(calls.length, 0);
});

test("responses preserve usable provider statuses but strip cookies, redirects and sensitive errors", async () => {
  for (const status of [200, 400, 401, 403, 404, 409, 429, 500]) {
    const { calls, fetcher } = transport(
      () =>
        new Response("{}", {
          status,
          headers: {
            "content-type": "application/json",
            "set-cookie": "bearer=private",
            "x-private": credential,
            "retry-after": "2",
          },
        }),
    );
    const result = await handleCommerceEgress(request(), environment, fetcher);
    assert.equal(result.status, status);
    assert.equal(result.headers.get("retry-after"), "2");
    assert.equal(result.headers.get("set-cookie"), null);
    assert.equal(result.headers.get("x-private"), null);
    assert.equal(calls.length, 1, "the transport never retries a call");
  }
  for (const status of [301, 302, 303, 307, 308]) {
    const { calls, fetcher } = transport(() =>
      Response.redirect(`https://evil.test/${credential}`, status),
    );
    const result = await handleCommerceEgress(
      request("/transactions", "POST", "{}"),
      environment,
      fetcher,
    );
    assert.equal(result.status, 502);
    assert.equal(calls.length, 1);
    assert(!String(await result.text()).includes(credential));
    assert.equal(result.headers.get("location"), null);
  }
});

test("declared and streamed response overflow or mismatch remains ambiguous after dispatch", async () => {
  const replies = [
    () => new Response("{}", { headers: { "content-length": String(responseByteLimit + 1) } }),
    () => new Response("{}", { headers: { "content-length": "3" } }),
    () => new Response(new Uint8Array(responseByteLimit + 1)),
    () => new Response(null, { headers: { "content-length": "1" } }),
  ];
  for (const reply of replies) {
    const { calls, fetcher } = transport(reply);
    assert.equal(
      (await handleCommerceEgress(request("/adjustments", "POST", "{}"), environment, fetcher))
        .status,
      502,
    );
    assert.equal(calls.length, 1);
  }
});

test("real request signals cancel before and after dispatch, without retries or credential diagnostics", async () => {
  const before = new AbortController();
  before.abort();
  const unused = transport();
  assert.equal(
    (
      await handleCommerceEgress(
        request(price, "GET", undefined, {}, before.signal),
        environment,
        unused.fetcher,
      )
    ).status,
    408,
  );
  assert.equal(unused.calls.length, 0);
  const after = new AbortController();
  let dispatched = 0;
  const fetcher: typeof fetch = async (input) => {
    assert(input instanceof Request);
    dispatched++;
    after.abort();
    assert.equal(input.signal.aborted, true);
    throw new Error(credential);
  };
  const result = await handleCommerceEgress(
    request("/adjustments", "POST", "{}", {}, after.signal),
    environment,
    fetcher,
  );
  assert.equal(result.status, 504);
  assert.equal(dispatched, 1);
  assert(!String(await result.text()).includes(credential));
});

test("transport deadlines include stalled response bodies and concurrent calls have independent lifetimes", async () => {
  const stalled = transport(
    () => new Response(new ReadableStream<Uint8Array>({ start() {}, cancel() {} })),
  );
  assert.equal(
    (await handleCommerceEgress(request(), environment, stalled.fetcher, 10)).status,
    504,
  );
  let calls = 0;
  const fetcher: typeof fetch = async () => {
    calls++;
    return Response.json({ data: "ok" });
  };
  const results = await Promise.all(
    Array.from({ length: 16 }, () => handleCommerceEgress(request(), environment, fetcher)),
  );
  assert.equal(results.filter((result) => result.status === 200).length, maxConcurrentTransports);
  assert.equal(
    results.filter((result) => result.status === 429).length,
    16 - maxConcurrentTransports,
  );
  assert.equal(calls, maxConcurrentTransports);
  assert.equal(
    (await handleCommerceEgress(request(), environment, fetcher)).status,
    200,
    "consumed replies release permits",
  );
});

test("downstream body cancellation and deadline release aggregate memory permits without affecting other calls", async () => {
  const { calls, fetcher } = transport(() => new Response(new Uint8Array(128 * 1024)));
  const first = await actualHandleCommerceEgress(request(), environment, fetcher);
  const second = await actualHandleCommerceEgress(request(), environment, fetcher);
  const busy = await actualHandleCommerceEgress(request(), environment, fetcher);
  assert.equal(busy.status, 429);
  assert.equal(busy.headers.get("retry-after"), "1");
  assert.equal(calls.length, 2, "backpressure never dispatches a third call");
  await first.body?.cancel();
  assert.equal((await second.arrayBuffer()).byteLength, 128 * 1024);
  const expiring = await actualHandleCommerceEgress(request(), environment, fetcher, 10);
  await new Promise((resolve) => setTimeout(resolve, 20));
  await assert.rejects(expiring.arrayBuffer(), /canceled/u);
  assert.equal((await handleCommerceEgress(request(), environment, fetcher)).status, 200);
});
