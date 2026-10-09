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

// harness.internal outbound (merged from the former harness-internal suite; the handler lives in run-alarm-core.ts).
{
  interface AlarmStub {
    schedule(input: unknown): Promise<{ scheduled: boolean }>;
    cancel(): Promise<void>;
  }
  interface AlarmNamespace {
    getByName(name: string): AlarmStub;
  }
  interface HandlerEnv {
    HARNESS_RUN_ALARM?: AlarmNamespace;
  }
  interface HandlerModule {
    handleHarnessInternal(request: Request, env: HandlerEnv, nowMs?: number): Promise<Response>;
    harnessInternalOutbound(request: Request, env: unknown): Promise<Response>;
  }
  interface CoreModule {
    readonly wakePath: string;
    runKey(workspaceId: string, runId: string): string;
  }
  interface FakeStorage {
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
  interface SigningModule {
    parseSecret(text: string | undefined): Uint8Array | null;
    verify(
      request: { method: string; pathAndQuery: string; bodySha256Hex: string; headers: Headers },
      keys: readonly { id: string; secret: Uint8Array }[],
      nowSeconds: number,
    ): Promise<{ ok: boolean }>;
  }
  interface EncodingModule {
    sha256Hex(bytes: Uint8Array): Promise<string>;
  }

  // The modules are imported through variables so the Node-side project does not type-check the workerd-only code.
  const corePath = "../../worker/harness/run-alarm-core.ts";
  const alarmPath = "../../worker/harness/run-alarm.ts";
  const signingPath = "../../worker/private/signing.ts";
  const encodingPath = "../../worker/private/encoding.ts";
  const handler = (await import(corePath)) as unknown as HandlerModule;
  const core = (await import(corePath)) as unknown as CoreModule;
  const alarmModule = (await import(alarmPath)) as unknown as {
    HarnessRunAlarm: new (ctx: { storage: FakeStorage }, env: object) => Adapter;
  };
  const signing = (await import(signingPath)) as unknown as SigningModule;
  const encoding = (await import(encodingPath)) as unknown as EncodingModule;

  const url = (path: string, host = "harness.internal") => `http://${host}${path}`;
  const workspaceId = "00000000-0000-4000-8000-0000000000b1";
  const runId = "00000000-0000-4000-8000-0000000000d1";
  const nowMs = 1_800_000_000_000;
  const schedule = { runId, workspaceId, wakeAtMs: nowMs + 5_000 };
  const cancel = { runId, workspaceId };
  const json = { "content-type": "application/json" };
  const secretText = Buffer.alloc(32, 7).toString("base64url");
  const workerVersion = "wv-test-1";

  /** One run's alarm stub that records what the handler asked of it and answers from a script. */
  function namespace(
    options: { scheduled?: boolean | "throw"; cancelThrows?: boolean; bound?: boolean } = {},
  ) {
    const names: string[] = [];
    const scheduled: unknown[] = [];
    let cancels = 0;
    const ns: AlarmNamespace = {
      getByName(name: string) {
        names.push(name);
        return {
          async schedule(input: unknown) {
            scheduled.push(input);
            if (options.scheduled === "throw") throw new Error("stub unavailable");
            return { scheduled: options.scheduled ?? true };
          },
          async cancel() {
            cancels += 1;
            if (options.cancelThrows) throw new Error("stub unavailable");
          },
        };
      },
    };
    return {
      env: (options.bound === false ? {} : { HARNESS_RUN_ALARM: ns }) as HandlerEnv,
      names,
      scheduled,
      get cancels() {
        return cancels;
      },
    };
  }

  function post(
    target: string,
    body: unknown,
    headers: Record<string, string> = json,
    method = "POST",
  ): Request {
    const payload = typeof body === "string" ? body : JSON.stringify(body);
    return new Request(target, { method, headers, body: method === "GET" ? undefined : payload });
  }

  test("a closed schedule reaches the run's alarm under its run key and the reply is 200 scheduled", async () => {
    const ns = namespace();
    const reply = await handler.handleHarnessInternal(
      post(url("/v1/schedule"), schedule),
      ns.env,
      nowMs,
    );

    assert.equal(reply.status, 200);
    assert.deepEqual(await reply.json(), { scheduled: true });
    assert.deepEqual(ns.names, [core.runKey(workspaceId, runId)]);
    assert.deepEqual(ns.scheduled, [schedule]);
  });

  test("a charset of utf-8 on the JSON content type is admitted, and no other parameter is", async () => {
    const ok = namespace();
    const admitted = await handler.handleHarnessInternal(
      post(url("/v1/schedule"), schedule, { "content-type": "application/json; charset=utf-8" }),
      ok.env,
      nowMs,
    );
    assert.equal(admitted.status, 200);

    const other = namespace();
    const refused = await handler.handleHarnessInternal(
      post(url("/v1/schedule"), schedule, { "content-type": "application/json; charset=latin1" }),
      other.env,
      nowMs,
    );
    assert.equal(refused.status, 415);
    assert.equal(other.names.length, 0);
  });

  test("a closed cancel reaches the run's alarm under its run key and the reply is 200 cancelled", async () => {
    const ns = namespace();
    const reply = await handler.handleHarnessInternal(
      post(url("/v1/cancel"), cancel),
      ns.env,
      nowMs,
    );

    assert.equal(reply.status, 200);
    assert.deepEqual(await reply.json(), { cancelled: true });
    assert.deepEqual(ns.names, [core.runKey(workspaceId, runId)]);
    assert.equal(ns.cancels, 1);
    assert.equal(ns.scheduled.length, 0);
  });

  test("the outbound registration serves the same handler for the harness host", async () => {
    const ns = namespace();
    const reply = await handler.harnessInternalOutbound(post(url("/v1/cancel"), cancel), ns.env);
    assert.equal(reply.status, 200);
    assert.equal(ns.cancels, 1);
  });

  /** Every refusal below must leave the alarm untouched: the handler answers the status and never addresses a run. */
  const refusals: { name: string; request: () => Request; status: number }[] = [
    { name: "a GET", request: () => post(url("/v1/schedule"), schedule, json, "GET"), status: 405 },
    { name: "a PUT", request: () => post(url("/v1/cancel"), cancel, json, "PUT"), status: 405 },
    {
      name: "another host",
      request: () => post(url("/v1/schedule", "storage.internal"), schedule),
      status: 404,
    },
    {
      name: "an ai host",
      request: () => post(url("/v1/schedule", "ai.internal"), schedule),
      status: 404,
    },
    { name: "another path", request: () => post(url("/v1/run"), schedule), status: 404 },
    { name: "a wake path", request: () => post(url(core.wakePath), schedule), status: 404 },
    { name: "a query string", request: () => post(url("/v1/schedule?x=1"), schedule), status: 400 },
    {
      name: "text content",
      request: () => post(url("/v1/schedule"), schedule, { "content-type": "text/plain" }),
      status: 415,
    },
    {
      name: "no content type",
      request: () => post(url("/v1/schedule"), schedule, {}),
      status: 415,
    },
    { name: "invalid JSON", request: () => post(url("/v1/schedule"), "{not json"), status: 400 },
    {
      name: "invalid UTF-8",
      request: () =>
        new Request(url("/v1/schedule"), {
          method: "POST",
          headers: json,
          body: new Uint8Array([0x7b, 0xff, 0x7d]),
        }),
      status: 400,
    },
    {
      name: "an oversized body",
      request: () => post(url("/v1/schedule"), { ...schedule, pad: "x".repeat(2048) }),
      status: 413,
    },
    { name: "an array", request: () => post(url("/v1/schedule"), [schedule]), status: 400 },
    {
      name: "an extra key",
      request: () => post(url("/v1/schedule"), { ...schedule, extra: 1 }),
      status: 400,
    },
    {
      name: "a missing key",
      request: () => post(url("/v1/schedule"), { runId, workspaceId }),
      status: 400,
    },
    {
      name: "an uppercase run identifier",
      request: () => post(url("/v1/schedule"), { ...schedule, runId: runId.toUpperCase() }),
      status: 400,
    },
    {
      name: "a malformed workspace identifier",
      request: () => post(url("/v1/schedule"), { ...schedule, workspaceId: "not-a-uuid" }),
      status: 400,
    },
    {
      name: "a fractional time",
      request: () => post(url("/v1/schedule"), { ...schedule, wakeAtMs: nowMs + 0.5 }),
      status: 400,
    },
    {
      name: "a time in the past",
      request: () => post(url("/v1/schedule"), { ...schedule, wakeAtMs: nowMs - 1 }),
      status: 400,
    },
    {
      name: "a time past the 365-day ceiling",
      request: () =>
        post(url("/v1/schedule"), { ...schedule, wakeAtMs: nowMs + 366 * 24 * 60 * 60 * 1000 }),
      status: 400,
    },
    {
      name: "a schedule body on the cancel route",
      request: () => post(url("/v1/cancel"), schedule),
      status: 400,
    },
    {
      name: "a cancel body on the schedule route",
      request: () => post(url("/v1/schedule"), cancel),
      status: 400,
    },
    {
      name: "a cancel with an extra key",
      request: () => post(url("/v1/cancel"), { ...cancel, wakeAtMs: nowMs }),
      status: 400,
    },
  ];

  for (const refusal of refusals) {
    test(`${refusal.name} is refused with ${refusal.status} before any run's alarm is addressed`, async () => {
      const ns = namespace();
      const reply = await handler.handleHarnessInternal(refusal.request(), ns.env, nowMs);
      assert.equal(reply.status, refusal.status);
      assert.equal(ns.names.length, 0, "no run alarm is addressed");
      assert.equal(ns.scheduled.length, 0);
      assert.equal(ns.cancels, 0);
    });
  }

  test("without the alarm binding a valid schedule or cancel is 503 and nothing is addressed", async () => {
    const ns = namespace({ bound: false });
    assert.equal(
      (await handler.handleHarnessInternal(post(url("/v1/schedule"), schedule), ns.env, nowMs))
        .status,
      503,
    );
    assert.equal(
      (await handler.handleHarnessInternal(post(url("/v1/cancel"), cancel), ns.env, nowMs)).status,
      503,
    );
  });

  test("a schedule the alarm refuses is 422 and a stub failure is 502, both without a success reply", async () => {
    const refused = namespace({ scheduled: false });
    assert.equal(
      (await handler.handleHarnessInternal(post(url("/v1/schedule"), schedule), refused.env, nowMs))
        .status,
      422,
    );

    const failed = namespace({ scheduled: "throw" });
    assert.equal(
      (await handler.handleHarnessInternal(post(url("/v1/schedule"), schedule), failed.env, nowMs))
        .status,
      502,
    );

    const cancelFailed = namespace({ cancelThrows: true });
    assert.equal(
      (
        await handler.handleHarnessInternal(
          post(url("/v1/cancel"), cancel),
          cancelFailed.env,
          nowMs,
        )
      ).status,
      502,
    );
  });

  test("the schedule shape is checked against the clock the handler is given, so a stale schedule never reaches the alarm", async () => {
    const ns = namespace();
    const later = await handler.handleHarnessInternal(
      post(url("/v1/schedule"), schedule),
      ns.env,
      nowMs + 10_000,
    );
    assert.equal(later.status, 400);
    assert.equal(ns.names.length, 0);
  });

  test("the offline loop: schedule through the handler, the alarm fires, and one signed wake reaches the container stub", async () => {
    const alarms = new Map<string, Adapter & { store: FakeStorage }>();
    const containerRequests: { request: Request; body: Uint8Array }[] = [];
    const containerStub = {
      getByName(name: string) {
        assert.equal(name, "harness");
        return {
          fetch: async (request: Request) => {
            containerRequests.push({ request, body: new Uint8Array(await request.arrayBuffer()) });
            return new Response("{}", { status: 200 });
          },
        };
      },
    };
    const alarmEnv = {
      HMAC_W2C_KEY_ID: "w2c-test",
      HMAC_W2C_SECRET: secretText,
      CLOUD_CONTAINER: containerStub,
      CF_VERSION_METADATA: { id: workerVersion },
    };

    // Each run key addresses one Durable Object instance of the real alarm class, with its own storage.
    const runAlarm: AlarmNamespace = {
      getByName(name: string) {
        let instance = alarms.get(name);
        if (instance === undefined) {
          const map = new Map<string, unknown>();
          let alarmAt: number | null = null;
          const store: FakeStorage = {
            get alarmAt() {
              return alarmAt;
            },
            get: async (key: string) => map.get(key),
            put: async (key: string, value: unknown) => {
              map.set(key, value);
            },
            delete: async (key: string) => {
              map.delete(key);
            },
            setAlarm: async (ms: number) => {
              alarmAt = ms;
            },
            deleteAlarm: async () => {
              alarmAt = null;
            },
            consumeAlarm: () => {
              alarmAt = null;
            },
          } as FakeStorage;
          instance = Object.assign(new alarmModule.HarnessRunAlarm({ storage: store }, alarmEnv), {
            store,
          }) as Adapter & { store: FakeStorage };
          alarms.set(name, instance);
        }
        return instance;
      },
    };

    // 1. The C# executor arms the wake: the closed schedule reaches the run's alarm.
    const armed = await handler.handleHarnessInternal(post(url("/v1/schedule"), schedule), {
      HARNESS_RUN_ALARM: runAlarm,
    });
    assert.equal(armed.status, 200);
    const key = core.runKey(workspaceId, runId);
    const alarm = alarms.get(key);
    assert.ok(alarm, "the run's alarm exists under its run key");
    assert.equal(alarm.store.alarmAt, schedule.wakeAtMs);

    // 2. The alarm fires: the platform consumes it and the handler delivers one signed wake to the container.
    alarm.store.consumeAlarm();
    await alarm.alarm();
    assert.equal(containerRequests.length, 1);
    const first = containerRequests[0];
    assert.ok(first, "the signed wake reached the container");
    const { request, body } = first;
    assert.equal(request.method, "POST");
    assert.equal(new URL(request.url).pathname, core.wakePath);

    // 3. The wake body is the one the C# wake endpoint accepts: the closed key set, the kind, the version and the run.
    const parsed = JSON.parse(new TextDecoder().decode(body)) as Record<string, unknown>;
    assert.deepEqual(Object.keys(parsed).sort(), [
      "kind",
      "runId",
      "v",
      "wakeAtMs",
      "workerVersion",
      "workspaceId",
    ]);
    assert.equal(parsed.kind, "harness.wake");
    assert.equal(parsed.v, 1);
    assert.equal(parsed.runId, runId);
    assert.equal(parsed.workspaceId, workspaceId);
    assert.equal(parsed.wakeAtMs, schedule.wakeAtMs);
    assert.equal(parsed.workerVersion, workerVersion);

    // 4. The request is signed over its exact path and body, with the W2C key.
    const key2 = { id: "w2c-test", secret: signing.parseSecret(secretText) ?? new Uint8Array() };
    const verified = await signing.verify(
      {
        method: request.method,
        pathAndQuery: core.wakePath,
        bodySha256Hex: await encoding.sha256Hex(body),
        headers: request.headers,
      },
      [key2],
      Math.floor(Date.now() / 1000),
    );
    assert.equal(verified.ok, true, "the wake is signed with the W2C key");

    // 5. Once taken, the handle is dropped: a later alarm for the same run sends nothing more.
    alarm.store.consumeAlarm();
    await alarm.alarm();
    assert.equal(containerRequests.length, 1);
  });

  test("the offline loop: a cancelled schedule never fires and sends no wake", async () => {
    const alarms = new Map<string, Adapter & { store: FakeStorage }>();
    let deliveries = 0;
    const containerStub = {
      getByName: () => ({
        fetch: async () => {
          deliveries += 1;
          return new Response("{}", { status: 200 });
        },
      }),
    };
    const alarmEnv = {
      HMAC_W2C_KEY_ID: "w2c-test",
      HMAC_W2C_SECRET: secretText,
      CLOUD_CONTAINER: containerStub,
      CF_VERSION_METADATA: { id: workerVersion },
    };
    const runAlarm: AlarmNamespace = {
      getByName(name: string) {
        let instance = alarms.get(name);
        if (instance === undefined) {
          const map = new Map<string, unknown>();
          let alarmAt: number | null = null;
          const store = {
            get alarmAt() {
              return alarmAt;
            },
            get: async (key: string) => map.get(key),
            put: async (key: string, value: unknown) => {
              map.set(key, value);
            },
            delete: async (key: string) => {
              map.delete(key);
            },
            setAlarm: async (ms: number) => {
              alarmAt = ms;
            },
            deleteAlarm: async () => {
              alarmAt = null;
            },
            consumeAlarm: () => {
              alarmAt = null;
            },
          } as FakeStorage;
          instance = Object.assign(new alarmModule.HarnessRunAlarm({ storage: store }, alarmEnv), {
            store,
          });
          alarms.set(name, instance);
        }
        return instance;
      },
    };

    await handler.handleHarnessInternal(
      post(url("/v1/schedule"), schedule),
      { HARNESS_RUN_ALARM: runAlarm },
      nowMs,
    );
    const alarm = alarms.get(core.runKey(workspaceId, runId));
    assert.ok(alarm, "the run alarm exists");
    const cancelled = await handler.handleHarnessInternal(
      post(url("/v1/cancel"), cancel),
      { HARNESS_RUN_ALARM: runAlarm },
      nowMs,
    );
    assert.equal(cancelled.status, 200);
    assert.equal(alarm.store.alarmAt, null, "the cancel removes the alarm");

    alarm.store.consumeAlarm();
    await alarm.alarm();
    assert.equal(deliveries, 0, "a cancelled wake sends nothing");
  });
}
