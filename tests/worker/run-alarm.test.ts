// SPDX-License-Identifier: AGPL-3.0-only
// Pins the DO alarm wake adapter of HAR.40: it holds only a wake handle, it wakes the C# endpoint with one signed request, it retries on a
// bounded schedule and it fails closed without a W2C key. The Durable Object base class exists only inside workerd, so the same minimal
// stand-in as container-classes.test.ts lets the real module load under Node.
import assert from "node:assert/strict";
import { register } from "node:module";
import test, { mock } from "node:test";

const stub = [
  "export class DurableObject { constructor(ctx, env) { this.ctx = ctx; this.env = env; } }",
  "export class WorkerEntrypoint { constructor(ctx, env) { this.ctx = ctx; this.env = env; } }",
  "export const env = {};",
].join("\n");
const hooks = `
export async function resolve(specifier, context, next) {
  if (specifier === "cloudflare:workers")
    return { url: "data:text/javascript,${encodeURIComponent(stub)}", shortCircuit: true };
  try {
    return await next(specifier, context);
  } catch (error) {
    // The package is authored for bundlers and imports its own files without an extension (the alarm base derives from Container).
    if (specifier.startsWith(".") && !/[.][cm]?[jt]s$/u.test(specifier))
      return next(specifier + ".js", context);
    throw error;
  }
}`;
register(`data:text/javascript,${encodeURIComponent(hooks)}`);

interface Handle {
  readonly workspaceId: string;
  readonly runId: string;
  readonly wakeAtMs: number;
  readonly attempts: number;
}

interface CoreModule {
  readonly maxWakeAttempts: number;
  readonly leaseTermSeconds: number;
  readonly wakeBackoffSeconds: readonly number[];
  parseSchedule(body: unknown, nowMs: number): { ok: true; handle: Handle } | { ok: false };
  wakeBody(handle: Handle, workerVersion: string): Uint8Array;
  wakeBodySha256Hex(body: Uint8Array): Promise<string>;
  afterFailure(
    handle: Handle,
    nowMs: number,
  ): { kind: "retry"; handle: Handle; atMs: number } | { kind: "drop" };
  readHandle(value: unknown): Handle | null;
}

interface FakeStorage {
  readonly map: Map<string, unknown>;
  readonly writes: unknown[][];
  readonly alarmAt: number | null;
  get(key: string): Promise<unknown>;
  put(key: string, value: unknown): Promise<void>;
  delete(key: string): Promise<void>;
  setAlarm(ms: number): Promise<void>;
  deleteAlarm(): Promise<void>;
  consumeAlarm(): void;
}

interface Adapter {
  schedule(input: unknown): Promise<{ scheduled: boolean }>;
  cancel(): Promise<void>;
  alarm(): Promise<void>;
}

interface FakeContainer {
  readonly names: string[];
  readonly requests: { request: Request; body: Uint8Array }[];
  getByName(name: string): { fetch(request: Request): Promise<Response> };
}

// The Durable Object module is imported through a variable so the Node-side project does not type-check the workerd-only module.
const corePath = "../../worker/harness/run-alarm-core.ts";
const alarmPath = "../../worker/harness/run-alarm.ts";
const signingPath = "../../worker/private/signing.ts";
const core = (await import(corePath)) as CoreModule;
const alarmModule = (await import(alarmPath)) as unknown as {
  HarnessRunAlarm: new (ctx: { storage: FakeStorage }, env: object) => Adapter;
};
const signing = (await import(signingPath)) as {
  sign(
    parts: {
      method: string;
      pathAndQuery: string;
      bodySha256Hex: string;
      requestId: string;
      time: string;
      nonce: string;
    },
    key: { id: string; secret: Uint8Array },
  ): Promise<Record<string, string>>;
};

const workspaceId = "00000000-0000-4000-8000-0000000000b1";
const runId = "00000000-0000-4000-8000-0000000000d1";
const now = 1_800_000_000_000;
const secret = Buffer.alloc(32, 7).toString("base64url");
const workerVersion = "wv-test-1";
const w2cEnv = {
  HMAC_W2C_KEY_ID: "w2c-test",
  HMAC_W2C_SECRET: secret,
  CF_VERSION_METADATA: { id: workerVersion },
};
const schedule = { runId, workspaceId, wakeAtMs: now + 5_000 };

/** Storage and alarm of one Durable Object instance, with every write recorded so a test can prove what the adapter wrote. */
function storage(): FakeStorage {
  const map = new Map<string, unknown>();
  const writes: unknown[][] = [];
  let alarmAt: number | null = null;
  return {
    map,
    writes,
    get alarmAt() {
      return alarmAt;
    },
    get: async (key: string) => map.get(key),
    put: async (key: string, value: unknown) => {
      writes.push(["put", key]);
      map.set(key, value);
    },
    delete: async (key: string) => {
      writes.push(["delete", key]);
      map.delete(key);
    },
    setAlarm: async (ms: number) => {
      writes.push(["setAlarm", ms]);
      alarmAt = ms;
    },
    deleteAlarm: async () => {
      writes.push(["deleteAlarm"]);
      alarmAt = null;
    },
    /** The platform consumes the alarm when it fires, before the handler runs. */
    consumeAlarm: () => {
      alarmAt = null;
    },
  };
}

/** A container namespace whose stub answers with the given status (or throws) and records every request it receives. */
function container(status: number | "throw"): FakeContainer {
  const names: string[] = [];
  const requests: { request: Request; body: Uint8Array }[] = [];
  return {
    names,
    requests,
    getByName(name: string) {
      names.push(name);
      return {
        fetch: async (request: Request) => {
          requests.push({ request, body: new Uint8Array(await request.arrayBuffer()) });
          if (status === "throw") throw new Error("connection reset");
          return new Response("{}", { status });
        },
      };
    },
  };
}

function adapterFor(env: object, store: FakeStorage): Adapter {
  return new alarmModule.HarnessRunAlarm({ storage: store }, env);
}

/** One firing of the alarm: the platform consumes it, then the handler runs. */
async function fire(adapter: Adapter, store: FakeStorage): Promise<void> {
  store.consumeAlarm();
  await adapter.alarm();
}

function handleOf(store: FakeStorage): Handle {
  const handle = core.readHandle(store.map.get("wake"));
  assert.ok(handle, "a handle is stored");
  return handle;
}

test("a schedule is accepted only in its closed shape, with canonical identifiers and a bounded time", () => {
  assert.equal(core.parseSchedule(schedule, now).ok, true);
  assert.equal(core.parseSchedule({ ...schedule, extra: 1 }, now).ok, false);
  assert.equal(core.parseSchedule({ ...schedule, runId: runId.toUpperCase() }, now).ok, false);
  assert.equal(core.parseSchedule({ ...schedule, workspaceId: "not-a-uuid" }, now).ok, false);
  assert.equal(core.parseSchedule({ ...schedule, wakeAtMs: now - 1 }, now).ok, false);
  assert.equal(core.parseSchedule({ ...schedule, wakeAtMs: now + 1.5 }, now).ok, false);
  assert.equal(
    core.parseSchedule({ ...schedule, wakeAtMs: now + 366 * 24 * 60 * 60 * 1000 }, now).ok,
    false,
  );
  assert.equal(core.parseSchedule(null, now).ok, false);
  assert.equal(core.parseSchedule([schedule], now).ok, false);
});

test("the wake body carries identifiers and a time, and nothing that could be run state", () => {
  const body = JSON.parse(
    new TextDecoder().decode(
      core.wakeBody({ workspaceId, runId, wakeAtMs: now, attempts: 0 }, workerVersion),
    ),
  );
  assert.deepEqual(Object.keys(body).sort(), [
    "kind",
    "runId",
    "v",
    "wakeAtMs",
    "workerVersion",
    "workspaceId",
  ]);
  assert.equal(body.kind, "harness.wake");
  assert.equal(body.v, 1);
  assert.equal(
    body.workerVersion,
    workerVersion,
    "the Worker version identifier is carried as its own field",
  );
});

test("a wake body is never built without a bounded Worker version identifier", () => {
  const handle = { workspaceId, runId, wakeAtMs: now, attempts: 0 };
  assert.throws(() => core.wakeBody(handle, ""), /Worker version/u);
  assert.throws(() => core.wakeBody(handle, "bad version with spaces"), /Worker version/u);
  assert.throws(() => core.wakeBody(handle, "v".repeat(129)), /Worker version/u);
});

test("without the Worker version identifier no wake is sent and the handle is kept for a retry", async () => {
  const store = storage();
  const containerStub = container(200);
  const adapter = adapterFor(
    { HMAC_W2C_KEY_ID: "w2c-test", HMAC_W2C_SECRET: secret, CLOUD_CONTAINER: containerStub },
    store,
  );
  await adapter.schedule({ ...schedule, wakeAtMs: Date.now() + 60_000 });
  await fire(adapter, store);
  assert.equal(containerStub.requests.length, 0, "nothing is sent without the version");
  assert.equal(handleOf(store).attempts, 1, "the failed wake is retried, not dropped silently");
});

test("a failed wake is retried on the doubling 1 to 32 second backoff and then dropped", () => {
  let handle: Handle = { workspaceId, runId, wakeAtMs: now, attempts: 0 };
  const delays: (number | "drop")[] = [];
  for (let failure = 0; failure < core.maxWakeAttempts; failure += 1) {
    const plan = core.afterFailure(handle, now);
    if (plan.kind === "drop") {
      delays.push("drop");
      break;
    }
    delays.push(plan.atMs - now);
    handle = plan.handle;
  }
  assert.deepEqual(delays, [1000, 2000, 4000, 8000, 16000, 32000, "drop"]);
});

test("the wake retry horizon covers the full 60 second lease term, so a wake refused by a live lease is not dropped early", () => {
  // The lease of a crashed holder expires no later than one term after the refusal, and the first delivery was refused by that lease.
  // The last retry must therefore land at least one full term after the first refused delivery.
  assert.equal(core.leaseTermSeconds, 60);
  const horizonMs = core.wakeBackoffSeconds.reduce((sum, seconds) => sum + seconds * 1000, 0);
  assert.ok(
    horizonMs >= core.leaseTermSeconds * 1000,
    `horizon ${horizonMs} ms covers the lease term`,
  );

  // Each failure happens at the time of the previous retry, so the backoff steps accumulate into the horizon.
  let handle: Handle = { workspaceId, runId, wakeAtMs: now, attempts: 0 };
  let failedAtMs = now;
  for (;;) {
    const plan = core.afterFailure(handle, failedAtMs);
    if (plan.kind === "drop") break;
    failedAtMs = plan.atMs;
    handle = plan.handle;
  }
  assert.ok(
    failedAtMs - now >= core.leaseTermSeconds * 1000,
    "the last retry is after the lease term",
  );
});

test("a wake refused by a live lease keeps being retried for the whole lease term before it is dropped", async () => {
  // The clock is driven by the test: each delivery happens at the alarm time the previous failure scheduled, as the platform fires it.
  const start = now + 1_000_000_000_000;
  let clockMs = start;
  const dateNow = mock.method(Date, "now", () => clockMs);
  try {
    const store = storage();
    const containerStub = container(503);
    const adapter = adapterFor({ ...w2cEnv, CLOUD_CONTAINER: containerStub }, store);
    await adapter.schedule({ ...schedule, wakeAtMs: start + 60_000 });

    const deliveriesMs: number[] = [];
    for (let delivery = 0; delivery < core.maxWakeAttempts; delivery += 1) {
      deliveriesMs.push(clockMs);
      await fire(adapter, store);
      if (store.alarmAt !== null) clockMs = store.alarmAt;
    }

    // One first delivery and one per backoff step: every delivery was made, and the wake is dropped only after the last one.
    assert.equal(containerStub.requests.length, core.maxWakeAttempts);
    assert.equal(store.map.has("wake"), false, "the wake is dropped only after its last delivery");
    assert.equal(store.alarmAt, null);
    // The last delivery lands at least one full lease term after the first refused delivery.
    const lastDeliveryMs = deliveriesMs.at(-1) ?? start;
    assert.ok(
      lastDeliveryMs - start >= core.leaseTermSeconds * 1000,
      `the last delivery is ${lastDeliveryMs - start} ms after the first, past the lease term`,
    );
  } finally {
    dateNow.mock.restore();
  }
});

test("a stored handle is read back only in its exact shape and with an attempt count below the bound", () => {
  const handle = { workspaceId, runId, wakeAtMs: now, attempts: 1 };
  assert.deepEqual(core.readHandle(handle), handle);
  assert.equal(core.readHandle({ ...handle, attempts: core.maxWakeAttempts }), null);
  assert.equal(core.readHandle({ ...handle, attempts: -1 }), null);
  assert.equal(core.readHandle({ ...handle, runId: "x" }), null);
  assert.equal(core.readHandle(undefined), null);
});

test("scheduling stores only the wake handle and sets one alarm", async () => {
  const store = storage();
  const adapter = adapterFor(w2cEnv, store);
  assert.deepEqual(await adapter.schedule({ ...schedule, wakeAtMs: Date.now() + 60_000 }), {
    scheduled: true,
  });
  assert.deepEqual([...store.map.keys()], ["wake"]);
  assert.deepEqual(
    store.writes.map((write) => write[0]),
    ["put", "setAlarm"],
  );
});

test("an invalid schedule writes nothing", async () => {
  const store = storage();
  assert.deepEqual(await adapterFor(w2cEnv, store).schedule({ ...schedule, runId: "bad" }), {
    scheduled: false,
  });
  assert.equal(store.writes.length, 0);
});

test("an alarm sends one signed wake to the C# endpoint on the harness container and then drops the handle", async () => {
  const store = storage();
  const containerStub = container(200);
  const adapter = adapterFor({ ...w2cEnv, CLOUD_CONTAINER: containerStub }, store);
  await adapter.schedule({ ...schedule, wakeAtMs: Date.now() + 60_000 });
  await fire(adapter, store);

  assert.deepEqual(containerStub.names, ["harness"]);
  assert.equal(containerStub.requests.length, 1);
  const first = containerStub.requests[0];
  assert.ok(first, "one request was sent");
  const { request, body } = first;
  assert.equal(request.method, "POST");
  assert.equal(new URL(request.url).pathname, "/internal/harness/v1/wake");
  assert.equal(request.headers.get("content-type"), "application/json");
  assert.equal(JSON.parse(new TextDecoder().decode(body)).runId, runId);

  // The signature is the W2C signature of exactly this path, body and time, so it verifies with the configured key.
  const expected = await signing.sign(
    {
      method: "POST",
      pathAndQuery: "/internal/harness/v1/wake",
      bodySha256Hex: await core.wakeBodySha256Hex(body),
      requestId: request.headers.get("x-af-request-id") ?? "",
      time: request.headers.get("x-af-time") ?? "",
      nonce: request.headers.get("x-af-nonce") ?? "",
    },
    { id: "w2c-test", secret: Buffer.alloc(32, 7) },
  );
  assert.equal(request.headers.get("x-af-signature"), expected["x-af-signature"]);
  assert.equal(request.headers.get("x-af-key-id"), "w2c-test");

  assert.equal(store.map.has("wake"), false);
  assert.equal(store.alarmAt, null);
});

test("a refused wake is retried on the backoff schedule and dropped after the last attempt", async () => {
  const store = storage();
  const containerStub = container(503);
  const adapter = adapterFor({ ...w2cEnv, CLOUD_CONTAINER: containerStub }, store);
  await adapter.schedule({ ...schedule, wakeAtMs: Date.now() + 60_000 });

  for (let attempt = 1; attempt < core.maxWakeAttempts; attempt += 1) {
    await fire(adapter, store);
    assert.equal(handleOf(store).attempts, attempt);
    assert.ok((store.alarmAt ?? 0) > Date.now() + 500, "the retry is scheduled after a backoff");
  }
  await fire(adapter, store);
  assert.equal(containerStub.requests.length, core.maxWakeAttempts);
  assert.equal(store.map.has("wake"), false);
  assert.equal(store.alarmAt, null);
});

test("a transport failure is a failed wake, not a thrown error", async () => {
  const store = storage();
  const adapter = adapterFor({ ...w2cEnv, CLOUD_CONTAINER: container("throw") }, store);
  await adapter.schedule({ ...schedule, wakeAtMs: Date.now() + 60_000 });
  await fire(adapter, store);
  assert.equal(handleOf(store).attempts, 1);
});

test("without a W2C key no wake is sent and the handle is retried, never dropped silently", async () => {
  const store = storage();
  const containerStub = container(200);
  const adapter = adapterFor({ CLOUD_CONTAINER: containerStub }, store);
  await adapter.schedule({ ...schedule, wakeAtMs: Date.now() + 60_000 });
  await fire(adapter, store);
  assert.equal(containerStub.requests.length, 0);
  assert.equal(handleOf(store).attempts, 1);
});

test("an alarm with no readable handle clears itself and sends nothing", async () => {
  const store = storage();
  const containerStub = container(200);
  await fire(adapterFor({ ...w2cEnv, CLOUD_CONTAINER: containerStub }, store), store);
  assert.equal(containerStub.requests.length, 0);
  assert.equal(store.map.size, 0);
});

test("cancel removes the handle and its alarm", async () => {
  const store = storage();
  const adapter = adapterFor(w2cEnv, store);
  await adapter.schedule({ ...schedule, wakeAtMs: Date.now() + 60_000 });
  await adapter.cancel();
  assert.equal(store.map.size, 0);
  assert.equal(store.alarmAt, null);
});
