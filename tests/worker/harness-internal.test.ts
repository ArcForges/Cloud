// SPDX-License-Identifier: AGPL-3.0-only
// Pins the harness.internal outbound handler of HAR.40 alarm arming: it admits only the closed schedule and cancel shapes on the two routes of
// one virtual host, refuses every other method, path, host, query, content type, size and body before any run's alarm is addressed, and
// reports a missing binding as 503. The end-to-end test runs the whole offline loop: schedule through the handler, the alarm firing, and the
// signed wake POST to the container stub, whose body is the one the C# HarnessWakeEndpoint parses.
import assert from "node:assert/strict";
import { register } from "node:module";
import test from "node:test";

// `cloudflare:workers` only exists inside workerd; a minimal stand-in lets the Durable Object module load under Node.
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
    // The package is authored for bundlers and imports its own files without an extension.
    if (specifier.startsWith(".") && !/[.][cm]?[jt]s$/u.test(specifier))
      return next(specifier + ".js", context);
    throw error;
  }
}`;
register(`data:text/javascript,${encodeURIComponent(hooks)}`);

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
const handlerPath = "../../worker/harness/internal/outbound.ts";
const corePath = "../../worker/harness/run-alarm-core.ts";
const alarmPath = "../../worker/harness/run-alarm.ts";
const signingPath = "../../worker/private/signing.ts";
const encodingPath = "../../worker/private/encoding.ts";
const handler = (await import(handlerPath)) as unknown as HandlerModule;
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
  const reply = await handler.handleHarnessInternal(post(url("/v1/cancel"), cancel), ns.env, nowMs);

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
  { name: "no content type", request: () => post(url("/v1/schedule"), schedule, {}), status: 415 },
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
    (await handler.handleHarnessInternal(post(url("/v1/cancel"), cancel), cancelFailed.env, nowMs))
      .status,
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
