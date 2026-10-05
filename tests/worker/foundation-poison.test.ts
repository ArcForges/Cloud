// SPDX-License-Identifier: AGPL-3.0-only
// The proof-only queue loss/retry probe: the real operator routes, the real queue entry and the real
// consumers, run against a simulated platform that applies the queue's retry rule (a message that keeps
// asking for a retry is delivered once and retried max_retries times, then moved to the dead-letter queue).
// Only the Durable Object wrapper (a one-line delegate to the pure state functions) is not importable here.
import assert from "node:assert/strict";
import test from "node:test";
import { queueEntry } from "../../worker/foundation/entry.ts";
import {
  emptyObservation,
  maxRecordedAttempts,
  parsePoison,
  poisonName,
  poisonRetryDelaySeconds,
  processDeadLetter,
  processPoison,
  withAttempt,
  withDeadLetter,
} from "../../worker/foundation/poison.ts";
import { handleProof } from "../../worker/foundation/proof-routes.ts";
import type { MessageLike } from "../../worker/foundation/queue.ts";
import type {
  CoordinatorLike,
  FoundationEnv,
  PoisonMessage,
  PoisonObservation,
  WakeMessage,
} from "../../worker/foundation/types.ts";
import { base64UrlEncode } from "../../worker/private/encoding.ts";
import { createFakeR2 } from "./support/fake-r2.ts";

const token = "t".repeat(40);
const maxRetries = 6;

function fakeCoordinators(options: { failWrites?: boolean } = {}) {
  const states = new Map<string, PoisonObservation>();
  let clock = 1_000;
  const tick = () => {
    clock += 10;
    return clock;
  };
  const names: string[] = [];
  const coordinator = (name: string): CoordinatorLike => ({
    admit: () => Promise.reject(new Error("not used")),
    complete: () => Promise.reject(new Error("not used")),
    release: () => Promise.reject(new Error("not used")),
    recordPoisonAttempt(attempt) {
      if (options.failWrites) return Promise.reject(new Error("storage down"));
      states.set(name, withAttempt(states.get(name) ?? emptyObservation(), attempt, tick()));
      return Promise.resolve();
    },
    recordDeadLetter(attempt) {
      if (options.failWrites) return Promise.reject(new Error("storage down"));
      states.set(name, withDeadLetter(states.get(name) ?? emptyObservation(), attempt, tick()));
      return Promise.resolve();
    },
    readPoison: () => Promise.resolve(states.get(name) ?? emptyObservation()),
  });
  return {
    states,
    names,
    namespace: {
      getByName(name: string) {
        names.push(name);
        return coordinator(name);
      },
    },
  };
}

function environment(overrides: Partial<FoundationEnv> = {}) {
  const coordinators = fakeCoordinators();
  const queued: (WakeMessage | PoisonMessage)[] = [];
  const env: FoundationEnv = {
    FOUNDATION_PROOF: "enabled",
    DB: undefined as never,
    RECOVERY_GENERATION: "0",
    PROOF_OPERATOR_TOKEN: token,
    HMAC_W2C_KEY_ID: "w2c-1",
    HMAC_W2C_SECRET: base64UrlEncode(new Uint8Array(32).fill(2)),
    OBJECTS: createFakeR2(),
    WAKE_QUEUE: {
      send(message) {
        queued.push(message);
        return Promise.resolve();
      },
    },
    JOB_COORDINATOR: coordinators.namespace,
    CLOUD_CONTAINER: { getByName: () => ({ fetch: () => Promise.reject(new Error("no host")) }) },
    ...overrides,
  };
  return { env, queued, coordinators };
}

const operator = (operation: string, body: unknown, authorization = `Bearer ${token}`) =>
  new Request(`https://proof.example/proof/v1/${operation}`, {
    method: "POST",
    headers: { authorization, "content-type": "application/json" },
    body: JSON.stringify(body),
  });

interface Delivery {
  queue: string;
  attempt: number;
  retried: number[];
  acked: boolean;
}
/** The platform's rule: deliver, and while the consumer retries, redeliver up to maxRetries more times, then dead-letter. */
async function runPlatform(env: FoundationEnv, message: PoisonMessage, retries = maxRetries) {
  const deliveries: Delivery[] = [];
  const deliver = async (queue: string, attempt: number) => {
    const record: Delivery = { queue, attempt, retried: [], acked: false };
    deliveries.push(record);
    const like: MessageLike = {
      body: message,
      attempts: attempt,
      ack: () => {
        record.acked = true;
      },
      retry: (options) => {
        record.retried.push(options?.delaySeconds ?? 0);
      },
    };
    await queueEntry({ queue, messages: [like] }, env as never);
    return record;
  };
  for (let attempt = 1; attempt <= retries + 1; attempt++) {
    const record = await deliver("arcforges-proof-wake", attempt);
    if (record.acked) return deliveries;
  }
  await deliver("arcforges-proof-wake-dlq", 1);
  return deliveries;
}

test("a poison message is retried until the retry limit, then delivered to the dead-letter queue and observed", async () => {
  const { env, queued, coordinators } = environment();
  const issued = await handleProof(operator("queue/poison", {}), env);
  assert.equal(issued.status, 200);
  const { probeId } = (await issued.json()) as { probeId: string };
  assert.match(probeId, /^[0-9a-f-]{36}$/u);
  assert.equal(queued.length, 1);
  assert.deepEqual(queued[0], { v: 1, kind: "proof.poison", probeId });

  const before = await handleProof(operator("queue/observation", { probeId }), env);
  assert.deepEqual(await before.json(), { attempts: [], deadLetter: null });

  const deliveries = await runPlatform(env, queued[0] as PoisonMessage);
  // One delivery plus max_retries retries on the wake queue, each asking for a short retry, then one dead letter.
  const wake = deliveries.filter((d) => d.queue === "arcforges-proof-wake");
  assert.equal(wake.length, maxRetries + 1);
  assert(
    wake.every(
      (d) => !d.acked && d.retried.length === 1 && d.retried[0] === poisonRetryDelaySeconds,
    ),
  );
  const dead = deliveries.filter((d) => d.queue.endsWith("-dlq"));
  assert.equal(dead.length, 1);
  assert(dead[0]?.acked && dead[0].retried.length === 0);

  const observed = (await (
    await handleProof(operator("queue/observation", { probeId }), env)
  ).json()) as PoisonObservation;
  assert.deepEqual(
    observed.attempts.map((a) => a.attempt),
    [1, 2, 3, 4, 5, 6, 7],
  );
  assert(observed.deadLetter, "the dead-letter delivery is recorded");
  const last = observed.attempts.at(-1);
  assert(last && observed.deadLetter.atMs > last.atMs, "the dead letter follows the last attempt");
  // Every record lives under the probe's own Durable Object name; nothing else is touched.
  assert.deepEqual([...new Set(coordinators.names)], [poisonName(probeId)]);
});

test("the probe routes are operator-gated, strict and proof-only", async () => {
  const { env, queued } = environment();
  assert.equal((await handleProof(operator("queue/poison", {}, "Bearer nope"), env)).status, 401);
  assert.equal(queued.length, 0);
  for (const body of [{}, { probeId: "x" }, { probeId: 7 }])
    assert.equal((await handleProof(operator("queue/observation", body), env)).status, 400);
  const get = new Request("https://proof.example/proof/v1/queue/poison", {
    method: "GET",
    headers: { authorization: `Bearer ${token}` },
  });
  assert.equal((await handleProof(get, env)).status, 405);
  // Without FOUNDATION_PROOF (production) the surface answers 404 and a queue message is deferred, never processed.
  const production = environment({ FOUNDATION_PROOF: undefined });
  assert.equal((await handleProof(operator("queue/poison", {}), production.env)).status, 404);
  const retried: (number | undefined)[] = [];
  await queueEntry(
    {
      queue: "arcforges-proof-wake",
      messages: [
        {
          body: { v: 1, kind: "proof.poison", probeId: "00000000-0000-4000-8000-000000000001" },
          attempts: 1,
          ack: () => assert.fail("must not ack"),
          retry: (o) => retried.push(o?.delaySeconds),
        },
      ],
    },
    production.env as never,
  );
  assert.deepEqual(retried, [60]);
  assert.equal(production.coordinators.names.length, 0);
});

test("the consumers never ack a poison message early, ignore anything else on the dead-letter queue and tolerate storage faults", async () => {
  const probeId = "00000000-0000-4000-8000-0000000000aa";
  const poison: PoisonMessage = { v: 1, kind: "proof.poison", probeId };
  const make = (body: unknown, attempts = 1) => {
    const result = { acked: 0, retried: [] as (number | undefined)[] };
    const message: MessageLike = {
      body,
      attempts,
      ack: () => {
        result.acked++;
      },
      retry: (o) => {
        result.retried.push(o?.delaySeconds);
      },
    };
    return { result, message };
  };
  const healthy = fakeCoordinators();
  const faulty = fakeCoordinators({ failWrites: true });
  // The wake consumer retries even when the observation cannot be written.
  const a = make(poison, 3);
  assert.equal(await processPoison(a.message, { coordinators: faulty.namespace }), "retry");
  assert.deepEqual(a.result, { acked: 0, retried: [poisonRetryDelaySeconds] });
  // Malformed poison is dropped, not retried forever.
  const b = make({ v: 1, kind: "proof.poison", probeId: "x" });
  assert.equal(await processPoison(b.message, { coordinators: healthy.namespace }), "dropped");
  assert.deepEqual(b.result, { acked: 1, retried: [] });
  // The dead-letter consumer records poison, retries when it cannot, and drops other messages without a record.
  const c = make(poison, 1);
  assert.equal(await processDeadLetter(c.message, { coordinators: faulty.namespace }), "retry");
  assert.deepEqual(c.result, { acked: 0, retried: [poisonRetryDelaySeconds] });
  const d = make(poison, 1);
  assert.equal(await processDeadLetter(d.message, { coordinators: healthy.namespace }), "recorded");
  assert.equal(d.result.acked, 1);
  const e = make({ v: 1, kind: "job.wake" });
  assert.equal(await processDeadLetter(e.message, { coordinators: healthy.namespace }), "dropped");
  assert.equal(e.result.acked, 1);
  assert.equal(healthy.names.length, 1, "only the poison dead letter touched a Durable Object");
});

test("the observation is bounded, keeps the first dead letter and parses poison strictly", () => {
  let state = emptyObservation();
  for (let attempt = 1; attempt <= maxRecordedAttempts + 5; attempt++)
    state = withAttempt(state, attempt, attempt);
  assert.equal(state.attempts.length, maxRecordedAttempts);
  assert.equal(state.attempts[0]?.attempt, 6);
  const first = withDeadLetter(state, 1, 100);
  assert.equal(withDeadLetter(first, 2, 200), first, "a repeated dead letter changes nothing");
  assert.deepEqual(first.deadLetter, { attempt: 1, atMs: 100 });
  const id = "00000000-0000-4000-8000-0000000000bb";
  assert.deepEqual(parsePoison({ v: 1, kind: "proof.poison", probeId: id }), {
    v: 1,
    kind: "proof.poison",
    probeId: id,
  });
  for (const bad of [
    null,
    [],
    {},
    { v: 2, kind: "proof.poison", probeId: id },
    { v: 1, kind: "job.wake", probeId: id },
    { v: 1, kind: "proof.poison", probeId: "x" },
    { v: 1, kind: "proof.poison", probeId: id, extra: 1 },
  ])
    assert.equal(parsePoison(bad), null);
});
