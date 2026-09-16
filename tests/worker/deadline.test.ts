// SPDX-License-Identifier: AGPL-3.0-only
import assert from "node:assert/strict";
import test from "node:test";
import { helloPath, routeRequest, type CloudBindings } from "../../worker/router.ts";

const payload = new Uint8Array([0, 0, 0, 0, 3, 10, 1, 65]);
function request(headers: Record<string, string> = {}, extra: RequestInit = {}) {
  return new Request(`https://arcforges.com${helloPath}`, {
    method: "POST",
    body: payload,
    headers: { "content-type": "application/grpc-web+proto", ...headers },
    ...extra,
  });
}
function fixture(fetch: (request: Request) => Promise<Response>): CloudBindings {
  return {
    SOURCE_REVISION: "test",
    CLOUD_CONTAINER: { getByName: () => ({ fetch }) },
    HELLO_RATE_LIMITER: { limit: async () => ({ success: true }) },
  };
}
async function status(response: Response, expected: number) {
  assert.equal(response.status, 200);
  assert.equal(response.headers.get("content-type"), "application/grpc-web+proto");
  const bytes = new Uint8Array(await response.arrayBuffer());
  assert.equal(bytes[0], 128);
  assert.equal(new DataView(bytes.buffer).getUint32(1), bytes.length - 5);
  assert.match(
    new TextDecoder().decode(bytes.slice(5)),
    new RegExp(`^grpc-status: ${expected}\\r\\n`),
  );
}

test("accepts protobuf's default media type, case and parameters", async () => {
  let calls = 0;
  const env = fixture(async (forwarded) => {
    calls++;
    assert.equal(forwarded.headers.get("content-type"), "application/grpc-web+proto");
    assert.deepEqual(new Uint8Array(await forwarded.arrayBuffer()), payload);
    return new Response(payload);
  });
  for (const type of ["application/grpc-web", "Application/GRPC-Web+Proto; charset=utf-8"]) {
    assert.equal((await routeRequest(request({ "content-type": type }), env)).status, 200);
  }
  assert.equal(calls, 2);
});

test("malformed and expired budgets never wake a container", async () => {
  const env = fixture(async () => {
    assert.fail("Container must not be called");
  });
  for (const value of ["invalid", "1s", "-1S", "100000000m", "1.5S", "1S,2S"]) {
    await status(await routeRequest(request({ "grpc-timeout": value }), env), 3);
  }
  for (const value of ["0m", "0S", "1n", "1u"]) {
    await status(await routeRequest(request({ "grpc-timeout": value }), env), 4);
  }
});

test("early rejection drains the upload through the request lifetime", async () => {
  const env = fixture(async () => {
    assert.fail("Rejected requests must not wake a container");
  });
  const pending: Promise<unknown>[] = [];
  const incoming = request({ "grpc-timeout": "invalid" });
  await status(await routeRequest(incoming, env, { waitUntil: (work) => pending.push(work) }), 3);
  assert.equal(pending.length, 1);
  await Promise.all(pending);
  assert.equal(incoming.bodyUsed, true);
  assert.equal((await incoming.body?.getReader().read())?.done, true);
});

test(
  "rejected upload cleanup is bounded without delaying the deadline response",
  { timeout: 2500 },
  async () => {
    const env = fixture(async () => {
      assert.fail("Rejected requests must not wake a container");
    });
    for (const oversized of [false, true]) {
      let canceled = false;
      const stream = new ReadableStream<Uint8Array>({
        start(controller) {
          if (oversized) controller.enqueue(new Uint8Array(4098));
        },
        cancel() {
          canceled = true;
          // A sender ignoring cancellation cannot extend cleanup either.
          return new Promise<void>(() => {});
        },
      });
      const pending: Promise<unknown>[] = [];
      const incoming = request({ "grpc-timeout": "0m" }, {
        body: stream,
        duplex: "half",
      } as RequestInit);
      await status(
        await routeRequest(incoming, env, { waitUntil: (work) => pending.push(work) }),
        4,
      );
      if (!oversized) assert.equal(canceled, false, "Response must precede upload timeout");
      await Promise.all(pending);
      assert.equal(canceled, true);
    }
  },
);

test("caps long budgets and deducts request-body time from a shorter one", async () => {
  const forwarded: number[] = [];
  const env = fixture(async (incoming) => {
    forwarded.push(Number.parseInt(incoming.headers.get("grpc-timeout") ?? "", 10));
    return new Response(payload);
  });
  for (const value of ["1H", "1M", "60S", "10000000u", "99999999n"]) {
    assert.equal((await routeRequest(request({ "grpc-timeout": value }), env)).status, 200);
    const maximum = value === "99999999n" ? 100 : 10000;
    const remaining = forwarded.at(-1) ?? 0;
    assert.ok(remaining > 0 && remaining <= maximum);
  }
  const stream = new ReadableStream<Uint8Array>({
    start(controller) {
      setTimeout(() => {
        controller.enqueue(payload);
        controller.close();
      }, 30);
    },
  });
  const slow = request({ "grpc-timeout": "1000m" }, {
    body: stream,
    duplex: "half",
  } as RequestInit);
  assert.equal((await routeRequest(slow, env)).status, 200);
  const remaining = forwarded.at(-1) ?? 0;
  assert.ok(remaining > 0 && remaining < 990);
});

test(
  "deadline closes a stalled upload without waking the container",
  { timeout: 2000 },
  async () => {
    let canceled = false;
    const stream = new ReadableStream<Uint8Array>({
      cancel() {
        canceled = true;
      },
    });
    const env = fixture(async () => {
      assert.fail("Incomplete request must not be forwarded");
    });
    await status(
      await routeRequest(
        request({ "grpc-timeout": "30m" }, {
          body: stream,
          duplex: "half",
        } as RequestInit),
        env,
      ),
      4,
    );
    assert.equal(canceled, true);
  },
);

test(
  "deadline bounds a binding that ignores cancellation, without retry",
  { timeout: 2000 },
  async () => {
    let calls = 0;
    let received: Request | undefined;
    const env = fixture(async (incoming) => {
      calls++;
      received = incoming;
      return new Promise<Response>(() => {});
    });
    await status(await routeRequest(request({ "grpc-timeout": "30m" }), env), 4);
    assert.equal(calls, 1);
    assert.equal(received?.signal.aborted, true);
  },
);

test(
  "deadline also cancels a stalled response body after HTTP headers",
  { timeout: 2000 },
  async () => {
    let canceled = false;
    const env = fixture(
      async () =>
        new Response(
          new ReadableStream({
            cancel() {
              canceled = true;
            },
          }),
        ),
    );
    await status(await routeRequest(request({ "grpc-timeout": "30m" }), env), 4);
    assert.equal(canceled, true);
  },
);

test("client cancellation is CANCELED and cancels upstream", async () => {
  const controller = new AbortController();
  const env = fixture(async () => {
    controller.abort();
    return new Promise<Response>(() => {});
  });
  await status(await routeRequest(request({}, { signal: controller.signal }), env), 1);
});

test("upstream trailers and application errors remain byte-for-byte intact", async () => {
  const trailers = new TextEncoder().encode("grpc-status: 3\r\ngrpc-message: bad%20name\r\n");
  const frame = new Uint8Array(5 + trailers.length);
  frame[0] = 128;
  new DataView(frame.buffer).setUint32(1, trailers.length);
  frame.set(trailers, 5);
  const env = fixture(
    async () => new Response(frame, { headers: { "content-type": "application/grpc-web" } }),
  );
  const result = await routeRequest(request(), env);
  assert.equal(result.status, 200);
  assert.deepEqual(new Uint8Array(await result.arrayBuffer()), frame);
});

test("compressed requests never reach the container", async () => {
  const env = fixture(async () => {
    assert.fail("Compressed requests are unsupported");
  });
  const encodings: Record<string, string>[] = [
    { "content-encoding": "gzip" },
    { "grpc-encoding": "gzip" },
  ];
  for (const headers of encodings) {
    assert.equal((await routeRequest(request(headers), env)).status, 415);
  }
  assert.equal(
    (await routeRequest(request({}, { body: new Uint8Array([1, 0, 0, 0, 0]) }), env)).status,
    415,
  );
});
