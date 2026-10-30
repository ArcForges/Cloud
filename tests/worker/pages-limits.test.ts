// SPDX-License-Identifier: AGPL-3.0-only
// The time and cancellation rules of the Worker's page handler (worker-4; PLT-1): a request body that stalls is 408 at the body read
// budget, a Container that does not answer is 504 at the page budget with its request signal aborted, a client that goes away is 499
// and cancels the Container call, a body read that ends past the page budget is 504 before the Container is called, and an asset GET
// counts in the same edge limiter as every other page call. The timers are node:test mock timers, as the RPC pipeline's tests use.
import assert from "node:assert/strict";
import test, { mock } from "node:test";
import { routeRequest, type CloudBindings } from "../../worker/router.ts";
import { pageDurationMs, pageRoutes } from "../../worker/tables/center-tables.generated.ts";
import { bodyReadMilliseconds } from "../../worker/tables/cloud-tables.generated.ts";

const origin = "https://proof.example.test";
const client = "203.0.113.7";

function row(method: string, path: string) {
  const found = pageRoutes.find(
    (candidate) => candidate.method === method && candidate.path === path,
  );
  assert(found, `${method} ${path} is a page route`);
  return found;
}

const begin = row("POST", "/session/v1/web/authentication/begin");
const script = row("GET", "/account/account.js");

interface Rig {
  env: CloudBindings;
  seen: Request[];
  keys: string[];
}

/** Bindings whose Container answers as the given function does and whose identity limiter answers as the given function does. */
function rig(
  answer: (request: Request) => Promise<Response>,
  limiter: () => Promise<{ success: boolean }> = async () => ({ success: true }),
): Rig {
  const seen: Request[] = [];
  const keys: string[] = [];
  const env: CloudBindings = {
    SOURCE_REVISION: "candidate",
    ALLOWED_ORIGIN: origin,
    FLAGSHIP_SURFACES: "identity,pages",
    CLOUD_CONTAINER: {
      getByName() {
        return {
          async fetch(request: Request) {
            seen.push(request);
            return answer(request);
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
        return limiter();
      },
    },
  };
  return { env, seen, keys };
}

async function turns(count = 20): Promise<void> {
  for (let index = 0; index < count; index += 1)
    await new Promise<void>((resolve) => setImmediate(resolve));
}

/** A promise's value once it has settled, or "pending" after the event loop has turned over. */
async function peek<T>(promise: Promise<T>): Promise<T | "pending"> {
  let settled: { value: T } | undefined;
  void promise.then((value) => {
    settled = { value };
  });
  await turns();
  return settled ? settled.value : "pending";
}

/** A POST whose body never produces a byte. */
function stalledPost(): Request {
  return new Request(`${origin}/api${begin.path}`, {
    method: "POST",
    headers: { origin, "content-type": begin.requestType, "cf-connecting-ip": client },
    body: new ReadableStream<Uint8Array>({ start() {} }),
    duplex: "half",
  } as RequestInit);
}

function getScript(options: RequestInit = {}): Request {
  return new Request(`${origin}/api${script.path}`, {
    method: "GET",
    headers: { "cf-connecting-ip": client },
    ...options,
  });
}

test("a stalled POST body is 408 at the body read budget and never reaches the Container", async () => {
  mock.timers.enable({ apis: ["setTimeout"] });
  try {
    const { env, seen } = rig(async () => new Response("{}"));
    const reply = routeRequest(stalledPost(), env);
    await turns();
    assert.equal(await peek(reply), "pending", "still reading at the start");
    mock.timers.tick(bodyReadMilliseconds - 1);
    assert.equal(await peek(reply), "pending", "still reading just before the budget");
    mock.timers.tick(2);
    const answered = await peek(reply);
    assert.notEqual(answered, "pending", "the body read budget ends the call");
    assert.equal((answered as Response).status, 408);
    assert.equal(seen.length, 0, "the Container is never called");
  } finally {
    mock.timers.reset();
  }
});

test("a Container that never answers is 504 at the page budget and its request signal is aborted", async () => {
  mock.timers.enable({ apis: ["setTimeout"] });
  try {
    const { env, seen } = rig(() => new Promise<Response>(() => {}));
    const reply = routeRequest(getScript(), env);
    await turns();
    assert.equal(await peek(reply), "pending");
    mock.timers.tick(pageDurationMs - 1);
    assert.equal(await peek(reply), "pending", "just before the budget");
    assert.equal(seen[0]?.signal.aborted, false);
    mock.timers.tick(2);
    const answered = await peek(reply);
    assert.notEqual(answered, "pending", "the page budget ends the call");
    assert.equal((answered as Response).status, 504);
    assert.equal(seen[0]?.signal.aborted, true, "the signal handed to the Container is aborted");
  } finally {
    mock.timers.reset();
  }
});

test("a client that goes away is 499 and cancels the Container call", async () => {
  mock.timers.enable({ apis: ["setTimeout"] });
  try {
    const goer = new AbortController();
    const { env, seen } = rig(() => new Promise<Response>(() => {}));
    const reply = routeRequest(getScript({ signal: goer.signal }), env);
    await turns();
    assert.equal(await peek(reply), "pending");
    goer.abort();
    const answered = await peek(reply);
    assert.notEqual(answered, "pending", "the client's cancellation ends the call");
    assert.equal((answered as Response).status, 499);
    assert.equal(seen[0]?.signal.aborted, true);
  } finally {
    mock.timers.reset();
  }
});

test("a request that is already canceled is 499 and reaches neither the limiter nor the Container", async () => {
  const goer = new AbortController();
  goer.abort();
  const { env, seen, keys } = rig(async () => new Response("{}"));
  const reply = await routeRequest(getScript({ signal: goer.signal }), env);
  assert.equal(reply.status, 499);
  assert.equal(seen.length, 0);
  assert.equal(keys.length, 0);
});

test("a body read that ends after the page budget is 504 and the Container is not called", async () => {
  let reads = 0;
  const clock = mock.method(performance, "now", () => {
    reads += 1;
    // The first two reads are the pipeline's start and the handler's start; every later one is past the page budget.
    return reads <= 2 ? 1000 : 1000 + pageDurationMs + 1;
  });
  try {
    const { env, seen } = rig(async () => new Response("{}"));
    const reply = await routeRequest(
      new Request(`${origin}/api${begin.path}`, {
        method: "POST",
        headers: {
          origin,
          "content-type": begin.requestType,
          "content-length": "2",
          "cf-connecting-ip": client,
        },
        body: "{}",
      }),
      env,
    );
    assert.equal(reply.status, 504);
    assert.equal(seen.length, 0, "the Container is never called after the budget has passed");
  } finally {
    clock.mock.restore();
  }
});

test("an asset GET is counted by the identity limiter by the client's network and refused with 429 over it", async () => {
  const served = rig(
    async () =>
      new Response("export {};", {
        status: 200,
        headers: { "content-type": "text/javascript; charset=utf-8" },
      }),
  );
  // The reply lacks the security headers, so the handler answers 503; what is observed here is the limiter and the call.
  await routeRequest(getScript(), served.env);
  assert.deepEqual(served.keys, [client], "the asset GET was counted");
  assert.equal(served.seen.length, 1);
  const limited = rig(
    async () => new Response("x"),
    async () => ({ success: false }),
  );
  const refused = await routeRequest(getScript(), limited.env);
  assert.equal(refused.status, 429);
  assert.deepEqual(limited.keys, [client]);
  assert.equal(limited.seen.length, 0, "an asset GET over the limit never wakes the Container");
});
