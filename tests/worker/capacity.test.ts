// SPDX-License-Identifier: AGPL-3.0-only
import {
  callCapacity,
  callCapacityRecovery,
  capacityWakePath,
  capacityRecoveryPath,
} from "../../worker/capacity/container-client.ts";
import { handleCapacitySchedule, schedulePath } from "../../worker/capacity/handler.ts";
import { sha256Hex } from "../../worker/private/encoding.ts";
import { sign } from "../../worker/private/signing.ts";
import {
  CapacityRecoveryCoordinator,
  recoverCapacity,
  type RecoveryState,
} from "../../worker/capacity/recovery.ts";
import assert from "node:assert/strict";
import test from "node:test";
import {
  CapacityPacer,
  freshWake,
  validWake,
  type CapacityPacerState,
  type CapacityPacerStorage,
  type CapacityReply,
} from "../../worker/capacity/pacer.ts";

const uuid = (n: number) => `10000000-0000-0000-0000-${String(n).padStart(12, "0")}`;
const owner = { realmId: uuid(1), workspaceId: uuid(2), kind: "upload", ownerId: uuid(3) };
class Storage implements CapacityPacerStorage {
  state: CapacityPacerState | undefined;
  alarmAt: number | null = null;
  private tail: Promise<unknown> = Promise.resolve();
  async get() {
    return this.state ? structuredClone(this.state) : undefined;
  }
  async put(value: CapacityPacerState) {
    this.state = structuredClone(value);
  }
  async delete() {
    this.state = undefined;
  }
  async alarm(value: number | null) {
    this.alarmAt = value;
  }
  async exclusive<T>(action: () => Promise<T>): Promise<T> {
    const task = this.tail.then(action);
    this.tail = task.catch(() => {});
    return task;
  }
}
function harness(call: (wake: ReturnType<typeof freshWake>) => Promise<CapacityReply>) {
  const storage = new Storage();
  let now = 1000;
  let n = 10;
  const id = () => uuid(n++);
  const wake = freshWake(owner, uuid(4), id);
  const pacer = new CapacityPacer(storage, call, () => now, id);
  return {
    storage,
    wake,
    pacer,
    setNow(value: number) {
      now = value;
    },
    now: () => now,
    id,
  };
}
test("durable schedule deduplicates exact job and cannot replace immutable in-flight identities", async () => {
  const h = harness(async () => ({ status: "Complete" }));
  assert.equal(await h.pacer.schedule(h.wake, 2000), "scheduled");
  const alternate = freshWake(owner, h.wake.jobId, h.id);
  assert.equal(await h.pacer.schedule(alternate, 3000), "duplicate");
  assert.equal(h.storage.state?.wake.wakeId, h.wake.wakeId);
  assert.equal(h.storage.alarmAt, 2000);
  assert.equal(await h.pacer.schedule({ ...alternate, jobId: uuid(90) }, 1000), "conflict");
  assert.equal(await h.pacer.schedule(alternate, 1500), "duplicate");
  assert.equal(h.storage.alarmAt, 1500);
});
test("early alarm does no host work; completion clears durable state and alarm", async () => {
  let calls = 0;
  const h = harness(async () => {
    calls++;
    return { status: "Complete" };
  });
  await h.pacer.schedule(h.wake, 2000);
  await h.pacer.run();
  assert.equal(calls, 0);
  h.setNow(2000);
  await h.pacer.run();
  assert.equal(calls, 1);
  assert.equal(h.storage.state, undefined);
  assert.equal(h.storage.alarmAt, null);
});
test("ambiguous dispatch keeps identical command IDs across persisted restart with bounded backoff", async () => {
  const calls: string[] = [];
  const h = harness(async (wake) => {
    calls.push(JSON.stringify(wake));
    throw new Error("transport disconnected after dispatch");
  });
  await h.pacer.schedule(h.wake, h.now());
  await h.pacer.run();
  assert.equal(h.storage.state?.failures, 1);
  assert.equal(h.storage.alarmAt, 2000);
  h.setNow(2000);
  const restarted = new CapacityPacer(
    h.storage,
    async (wake) => {
      calls.push(JSON.stringify(wake));
      return { status: "UnknownOutcome" };
    },
    h.now,
    h.id,
  );
  await restarted.run();
  assert.equal(calls[0], calls[1]);
  assert.equal(h.storage.alarmAt, 4000);
});
test("continuation uses new immutable IDs and rounds microseconds up without numeric truncation", async () => {
  const h = harness(async () => ({ status: "Reschedule", availableAtMicros: "2000001" }));
  await h.pacer.schedule(h.wake, h.now());
  await h.pacer.run();
  assert.equal(h.storage.alarmAt, 2001);
  assert.equal(h.storage.state?.failures, 0);
  assert.notEqual(h.storage.state?.wake.wakeId, h.wake.wakeId);
  assert.notEqual(h.storage.state?.wake.claimCommandId, h.wake.claimCommandId);
  assert.equal(h.storage.state?.wake.jobId, h.wake.jobId);
});
test("invalid continuation time never becomes immediate fresh work", async () => {
  const h = harness(async () => ({ status: "Busy", availableAtMicros: "9223372036854775807" }));
  await h.pacer.schedule(h.wake, h.now());
  await h.pacer.run();
  // Valid int64 microseconds beyond exact JS scheduling precision are refused, never rounded down.
  assert.equal(h.storage.alarmAt, 2000);
  assert.equal(h.storage.state?.wake.wakeId, h.wake.wakeId);
  const bad = harness(async () => ({ status: "Reschedule", availableAtMicros: "1e9" }));
  await bad.pacer.schedule(bad.wake, bad.now());
  await bad.pacer.run();
  assert.equal(bad.storage.state?.wake.wakeId, bad.wake.wakeId);
  assert.equal(bad.storage.state?.failures, 1);
});
test("twenty transport failures pause with persisted evidence rather than claim completion", async () => {
  const h = harness(async () => ({ status: "Unavailable" }));
  await h.pacer.schedule(h.wake, h.now());
  for (let i = 0; i < 20; i++) {
    await h.pacer.run();
    assert.ok(h.storage.state);
    h.setNow(h.storage.state.dueAt);
  }
  assert.equal(h.storage.state?.paused, true);
  assert.equal(h.storage.state?.failures, 20);
  assert.equal(h.storage.state?.wake.wakeId, h.wake.wakeId);
  assert.equal(h.storage.alarmAt, null);
});
test("refused owner remains paused and explicit reschedule resumes; another job cannot commandeer it", async () => {
  const h = harness(async () => ({ status: "Refused" }));
  await h.pacer.schedule(h.wake, h.now());
  await h.pacer.run();
  assert.equal(h.storage.state?.paused, true);
  assert.equal(await h.pacer.schedule({ ...h.wake, jobId: uuid(50) }, h.now()), "conflict");
  assert.equal(await h.pacer.schedule(freshWake(owner, h.wake.jobId, h.id), h.now()), "scheduled");
  assert.equal(h.storage.state?.paused, false);
});
test("concurrent alarm deliveries dispatch once and recover alarm exists before network wait", async () => {
  let release: (reply: CapacityReply) => void = () => {};
  let calls = 0;
  const pending = new Promise<CapacityReply>((resolve) => {
    release = resolve;
  });
  const h = harness(async () => {
    calls++;
    return pending;
  });
  await h.pacer.schedule(h.wake, h.now());
  const first = h.pacer.run();
  for (let i = 0; i < 5; i++) await Promise.resolve();
  await h.pacer.run();
  assert.equal(calls, 1);
  assert.equal(h.storage.alarmAt, 61000);
  release({ status: "Complete" });
  await first;
});
test("wake validation refuses unknown fields, nil/alias identities and another holder", () => {
  const h = harness(async () => ({ status: "Complete" }));
  assert.equal(validWake(h.wake), true);
  assert.equal(validWake({ ...h.wake, scope: "caller-unverified" }), false);
  assert.equal(validWake({ ...h.wake, checkpointCommandId: h.wake.claimCommandId }), false);
  assert.equal(validWake({ ...h.wake, holder: "other" }), false);
  assert.equal(
    validWake({ ...h.wake, owner: { ...owner, realmId: "00000000-0000-0000-0000-000000000000" } }),
    false,
  );
});

{
  const uuid = (n: number) => `20000000-0000-0000-0000-${String(n).padStart(12, "0")}`;
  const secret = new Uint8Array(32).fill(7);
  const encoded = Buffer.from(secret).toString("base64url");
  const owner = { realmId: uuid(1), workspaceId: uuid(2), kind: "upload", ownerId: uuid(3) };
  let n = 10;
  const wake = freshWake(owner, uuid(4), () => uuid(n++));
  const json = (value: unknown) =>
    new Response(JSON.stringify(value), { headers: { "content-type": "application/json" } });
  const env = {
    HMAC_W2C_KEY_ID: "w2c",
    HMAC_W2C_SECRET: encoded,
    CAPACITY_CONTAINER_NAME: "capacity",
  };
  test("actual wake transport signs exact private path/bytes/request ID and preserves string lease times", async () => {
    let calls = 0;
    const reply = await callCapacity(
      {
        ...env,
        CLOUD_CONTAINER: {
          getByName: (name) => {
            assert.equal(name, "capacity");
            return {
              async fetch(request) {
                calls++;
                assert.equal(new URL(request.url).pathname, capacityWakePath);
                assert.equal(request.headers.get("x-af-request-id"), wake.wakeId);
                assert.deepEqual(await request.json(), wake);
                return json({
                  status: "Busy",
                  availableAtMicros: "1791316000000001",
                  fence: "9223372036854775807",
                });
              },
            };
          },
        },
      },
      wake,
    );
    assert.equal(calls, 1);
    assert.equal(reply.availableAtMicros, "1791316000000001");
  });
  test("missing key/target and malformed wake cause zero dispatch", async () => {
    let calls = 0;
    const target = {
      getByName: () => ({
        async fetch() {
          calls++;
          return json({ status: "Complete" });
        },
      }),
    };
    await assert.rejects(
      callCapacity({ ...env, HMAC_W2C_SECRET: undefined, CLOUD_CONTAINER: target }, wake),
    );
    await assert.rejects(
      callCapacity({ ...env, CAPACITY_CONTAINER_NAME: "../public", CLOUD_CONTAINER: target }, wake),
    );
    await assert.rejects(
      callCapacity({ ...env, CLOUD_CONTAINER: target }, { ...wake, holder: "foreign" }),
    );
    assert.equal(calls, 0);
  });
  test("non-success, unknown field, numeric time and oversized replies do not become completion", async () => {
    for (const response of [
      new Response(null, { status: 503 }),
      json({ status: "Complete", arbitrary: true }),
      json({ status: "Busy", availableAtMicros: 2000 }),
      new Response("x".repeat(4097), { headers: { "content-type": "application/json" } }),
    ]) {
      let calls = 0;
      await assert.rejects(
        callCapacity(
          {
            ...env,
            CLOUD_CONTAINER: {
              getByName: () => ({
                async fetch() {
                  calls++;
                  return response;
                },
              }),
            },
          },
          wake,
        ),
      );
      assert.equal(calls, 1);
    }
  });
  test("elapsed receive deadline refuses endless empty fragments even if timer tasks are starved", async () => {
    let now = 1000;
    let cancelled = false;
    let pulls = 0;
    const stream = new ReadableStream<Uint8Array>({
      pull(controller) {
        pulls++;
        now += 5000;
        controller.enqueue(new Uint8Array());
      },
      cancel() {
        cancelled = true;
      },
    });
    await assert.rejects(
      callCapacity(
        {
          ...env,
          CLOUD_CONTAINER: {
            getByName: () => ({
              async fetch() {
                return new Response(stream, { headers: { "content-type": "application/json" } });
              },
            }),
          },
        },
        wake,
        () => now,
      ),
    );
    assert.equal(cancelled, true);
    assert.ok(pulls < 10);
  });
  test("exact signed scheduling reaches realm/job durable object with integer ceiling; duplicate is accepted", async () => {
    const body = new TextEncoder().encode(JSON.stringify({ wake, dueAtMicros: "2000001" }));
    const headers = await sign(
      {
        method: "POST",
        pathAndQuery: schedulePath,
        bodySha256Hex: await sha256Hex(body),
        requestId: wake.wakeId,
        time: "1000",
        nonce: "AAAAAAAAAAAAAAAAAAAAAA",
      },
      { id: "c2w", secret },
    );
    let calls = 0;
    const reply = await handleCapacitySchedule(
      new Request(`http://capacity.internal${schedulePath}`, {
        method: "POST",
        headers: { ...headers, "content-type": "application/json" },
        body,
      }),
      {
        HMAC_C2W_KEY_ID: "c2w",
        HMAC_C2W_SECRET: encoded,
        CAPACITY_PACER: {
          getByName(name) {
            assert.equal(name, `${owner.realmId}:${wake.jobId}`);
            return {
              async schedule(actual, due) {
                calls++;
                assert.deepEqual(actual, wake);
                assert.equal(due, 2001);
                return "duplicate";
              },
            };
          },
        },
      },
      () => 1_000_000,
    );
    assert.equal(reply.status, 200);
    assert.equal(calls, 1);
    assert.deepEqual(await reply.json(), { status: "duplicate" });
  });
  test("schedule refuses public/alternate paths, unsigned/expired identity and absent bindings before durable work", async () => {
    let calls = 0;
    const configured = {
      HMAC_C2W_KEY_ID: "c2w",
      HMAC_C2W_SECRET: encoded,
      CAPACITY_PACER: {
        getByName() {
          calls++;
          return {
            async schedule() {
              return "scheduled" as const;
            },
          };
        },
      },
    };
    const body = JSON.stringify({ wake, dueAtMicros: "2000001" });
    assert.equal(
      (
        await handleCapacitySchedule(
          new Request(`https://arcforges.com${schedulePath}`, { method: "POST" }),
          configured,
        )
      ).status,
      404,
    );
    assert.equal(
      (
        await handleCapacitySchedule(
          new Request(`http://capacity.internal${schedulePath}?q=1`, { method: "POST" }),
          configured,
        )
      ).status,
      404,
    );
    assert.equal(
      (
        await handleCapacitySchedule(
          new Request(`http://capacity.internal${schedulePath}`, {
            method: "POST",
            headers: { "content-type": "application/json" },
            body,
          }),
          configured,
        )
      ).status,
      401,
    );
    assert.equal(
      (
        await handleCapacitySchedule(
          new Request(`http://capacity.internal${schedulePath}`, { method: "POST" }),
          {},
        )
      ).status,
      503,
    );
    assert.equal(calls, 0);
  });
}

function recoveryFixture(now: () => number) {
  let state: RecoveryState | undefined;
  const coordinator = new CapacityRecoveryCoordinator(
    {
      get: async () => structuredClone(state),
      put: async (value) => {
        state = structuredClone(value);
      },
      exclusive: async (action) => action(),
    },
    now,
  );
  return { coordinator, state: () => state };
}
test("recovery keyset persists across restart and stale concurrent holder cannot advance it", async () => {
  let clock = 1000;
  const f = recoveryFixture(() => clock);
  const holder = uuid(301),
    other = uuid(302),
    cursor = { dueAtMicros: "9223372036854775807", jobId: uuid(303) };
  assert.deepEqual(await f.coordinator.begin(holder), { cursor: null });
  assert.equal(await f.coordinator.begin(other), null);
  assert.equal(await f.coordinator.advance(other, cursor, true), false);
  assert.equal(await f.coordinator.advance(holder, cursor, false), true);
  clock += 30_001;
  assert.deepEqual(await f.coordinator.begin(other), { cursor });
  assert.equal(await f.coordinator.advance(holder, null, true), false);
  assert.equal(await f.coordinator.advance(other, null, true), true);
  assert.equal(f.state()?.cursor, null);
});
test("recovery refuses invalid or overflow cursor rather than numerically truncating it", async () => {
  const f = recoveryFixture(() => 1000);
  await f.coordinator.begin(uuid(301));
  await assert.rejects(
    f.coordinator.advance(
      uuid(301),
      { dueAtMicros: "9223372036854775808", jobId: uuid(303) },
      true,
    ),
  );
  await assert.rejects(
    f.coordinator.advance(uuid(301), { dueAtMicros: "001", jobId: uuid(303) }, true),
  );
  assert.equal(f.state()?.cursor, null);
});
test("actual signed recovery transport binds only the closed path and strict keyset contract", async () => {
  let calls = 0;
  const requestId = uuid(310),
    cursor = { dueAtMicros: "1791316000000001", jobId: uuid(311) };
  const reply = await callCapacityRecovery(
    {
      HMAC_W2C_KEY_ID: "w2c",
      HMAC_W2C_SECRET: Buffer.alloc(32, 1).toString("base64url"),
      CAPACITY_CONTAINER_NAME: "capacity",
      CLOUD_CONTAINER: {
        getByName: () => ({
          fetch: async (request: Request) => {
            calls++;
            assert.equal(new URL(request.url).pathname, capacityRecoveryPath);
            assert.equal(request.headers.get("x-af-request-id"), requestId);
            assert.deepEqual(await request.json(), {
              requestId,
              afterDueAtMicros: cursor.dueAtMicros,
              afterJobId: cursor.jobId,
            });
            return new Response(
              JSON.stringify({ status: "Succeeded", nextDueAtMicros: null, nextJobId: null }),
              { headers: { "content-type": "application/json" } },
            );
          },
        }),
      },
    },
    requestId,
    cursor,
    20000,
  );
  assert.equal(reply.status, "Succeeded");
  assert.equal(calls, 1);
});
test("cron advances at most ten actual recovery pages and leaves keyset for the next minute", async () => {
  const f = recoveryFixture(() => 1000);
  let sequence = 320,
    calls = 0;
  const env = {
    CAPACITY_ENABLED: "enabled",
    CAPACITY_CONTAINER_NAME: "capacity",
    HMAC_W2C_KEY_ID: "w2c",
    HMAC_W2C_SECRET: Buffer.alloc(32, 1).toString("base64url"),
    CAPACITY_PACER: {
      getByName: () => ({
        recoveryBegin: (holder: string) => f.coordinator.begin(holder),
        recoveryAdvance: (
          holder: string,
          cursor: { dueAtMicros: string; jobId: string } | null,
          complete: boolean,
        ) => f.coordinator.advance(holder, cursor, complete),
      }),
    },
    CLOUD_CONTAINER: {
      getByName: () => ({
        fetch: async (request: Request) => {
          const input = (await request.json()) as { afterDueAtMicros: string | null };
          assert.equal(input.afterDueAtMicros, calls === 0 ? null : String(calls));
          calls++;
          return new Response(
            JSON.stringify({
              status: "Succeeded",
              nextDueAtMicros: String(calls),
              nextJobId: uuid(350 + calls),
            }),
            { headers: { "content-type": "application/json" } },
          );
        },
      }),
    },
  };
  await recoverCapacity(
    env,
    () => 1000,
    () => uuid(sequence++),
  );
  assert.equal(calls, 10);
  assert.equal(f.state()?.cursor?.dueAtMicros, "10");
  assert.equal(f.state()?.holder, null);
});
test("unknown recovery retains current cursor and disabled production performs no scan", async () => {
  const f = recoveryFixture(() => 1000);
  let calls = 0;
  const env = {
    CAPACITY_ENABLED: "enabled",
    CAPACITY_CONTAINER_NAME: "capacity",
    HMAC_W2C_KEY_ID: "w2c",
    HMAC_W2C_SECRET: Buffer.alloc(32, 1).toString("base64url"),
    CAPACITY_PACER: {
      getByName: () => ({
        recoveryBegin: (holder: string) => f.coordinator.begin(holder),
        recoveryAdvance: (
          holder: string,
          cursor: { dueAtMicros: string; jobId: string } | null,
          complete: boolean,
        ) => f.coordinator.advance(holder, cursor, complete),
      }),
    },
    CLOUD_CONTAINER: {
      getByName: () => ({
        fetch: async () => {
          calls++;
          return new Response(
            JSON.stringify({ status: "UnknownOutcome", nextDueAtMicros: null, nextJobId: null }),
            { headers: { "content-type": "application/json" } },
          );
        },
      }),
    },
  };
  await recoverCapacity({ ...env, CAPACITY_ENABLED: undefined });
  assert.equal(calls, 0);
  await recoverCapacity(
    env,
    () => 1000,
    () => uuid(390),
  );
  assert.equal(calls, 1);
  assert.equal(f.state()?.cursor, null);
  assert.equal(f.state()?.holder, null);
});
test("schedule body has bounded copied storage and refuses starvation or caller cancellation before durable work", async () => {
  let clock = Date.now(),
    cancelled = false,
    calls = 0;
  const body = new ReadableStream<Uint8Array>({
    pull(controller) {
      clock += 2000;
      controller.enqueue(new Uint8Array());
    },
    cancel() {
      cancelled = true;
    },
  });
  const env = {
    HMAC_C2W_KEY_ID: "c2w",
    HMAC_C2W_SECRET: Buffer.alloc(32, 1).toString("base64url"),
    CAPACITY_PACER: {
      getByName: () => ({
        schedule: async () => {
          calls++;
          return "scheduled" as const;
        },
      }),
    },
  };
  const response = await handleCapacitySchedule(
    new Request(`http://capacity.internal${schedulePath}`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body,
      duplex: "half",
    } as RequestInit),
    env,
    () => clock,
  );
  assert.equal(response.status, 503);
  assert.equal(cancelled, true);
  assert.equal(calls, 0);
  const abort = new AbortController();
  abort.abort();
  const cancelledRequest = new Request(`http://capacity.internal${schedulePath}`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: "{}",
    signal: abort.signal,
  });
  assert.equal((await handleCapacitySchedule(cancelledRequest, env)).status, 503);
  assert.equal(calls, 0);
});
