// SPDX-License-Identifier: AGPL-3.0-only
// Pins the DO alarm wake adapter of HAR.40: it holds only a wake handle, it wakes the C# endpoint with one signed request, it retries on a
// bounded schedule and it fails closed without a W2C key. The Durable Object base class exists only inside workerd, so the same minimal
// stand-in as container-classes.test.ts lets the real module load under Node.
import assert from "node:assert/strict";
import { register } from "node:module";
import test from "node:test";

const stub = [
  "export class DurableObject { constructor(ctx, env) { this.ctx = ctx; this.env = env; } }",
  "export class WorkerEntrypoint { constructor(ctx, env) { this.ctx = ctx; this.env = env; } }",
  "export const env = {};",
].join("\n");
const hooks = `
export async function resolve(specifier, context, next) {
  if (specifier === "cloudflare:workers")
    return { url: "data:text/javascript,${encodeURIComponent(stub)}", shortCircuit: true };
  return next(specifier, context);
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
  parseSchedule(body: unknown, nowMs: number): { ok: true; handle: Handle } | { ok: false };
  wakeBody(handle: Handle): Uint8Array;
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
const w2cEnv = { HMAC_W2C_KEY_ID: "w2c-test", HMAC_W2C_SECRET: secret };
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
    new TextDecoder().decode(core.wakeBody({ workspaceId, runId, wakeAtMs: now, attempts: 0 })),
  );
  assert.deepEqual(Object.keys(body).sort(), ["kind", "runId", "v", "wakeAtMs", "workspaceId"]);
  assert.equal(body.kind, "harness.wake");
  assert.equal(body.v, 1);
});

test("a failed wake is retried on the 1, 2 and 4 second backoff and then dropped", () => {
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
  assert.deepEqual(delays, [1000, 2000, 4000, "drop"]);
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
