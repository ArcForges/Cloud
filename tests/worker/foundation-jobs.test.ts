// SPDX-License-Identifier: AGPL-3.0-only
// Durable Object coordination state and the Queue consumer: duplicate delivery, single flight,
// retry/backoff and continuation without ever becoming a business authority.
import assert from "node:assert/strict";
import test from "node:test";
import {
  admitEvent,
  completeEvent,
  emptyState,
  inflightLeaseMs,
  maxSeenEvents,
  releaseEvent,
} from "../../worker/foundation/coordination.ts";
import {
  backoffSeconds,
  parseSliceReply,
  parseWake,
  processWake,
  type ConsumerDeps,
  type MessageLike,
} from "../../worker/foundation/queue.ts";
import type { AdmitResult, CoordinatorLike, WakeMessage } from "../../worker/foundation/types.ts";

const event = (n: number) => `00000000-0000-4000-8000-${String(n).padStart(12, "0")}`;

test("an event is admitted once, is busy while in flight and duplicate once completed", () => {
  let state = emptyState();
  const first = admitEvent(state, event(1), 1_000);
  assert.deepEqual(first.result, { admit: true });
  state = first.state;
  assert.deepEqual(admitEvent(state, event(2), 1_001).result, { admit: false, reason: "busy" });
  assert.deepEqual(admitEvent(state, event(1), 1_001).result, { admit: false, reason: "busy" });
  state = completeEvent(state, event(1));
  assert.deepEqual(admitEvent(state, event(1), 1_002).result, {
    admit: false,
    reason: "duplicate",
  });
  assert.deepEqual(admitEvent(state, event(2), 1_002).result, { admit: true });
});

test("an in-flight slice that never completes is freed by its lease, and a released event can run again", () => {
  const admitted = admitEvent(emptyState(), event(1), 1_000).state;
  assert.deepEqual(admitEvent(admitted, event(2), 1_000 + inflightLeaseMs - 1).result, {
    admit: false,
    reason: "busy",
  });
  assert.deepEqual(admitEvent(admitted, event(2), 1_000 + inflightLeaseMs).result, { admit: true });
  const released = releaseEvent(admitted, event(1));
  assert.deepEqual(admitEvent(released, event(1), 1_001).result, { admit: true });
});

test("completion and release only affect the event that is in flight", () => {
  const admitted = admitEvent(emptyState(), event(1), 1).state;
  assert.equal(completeEvent(admitted, event(2)), admitted);
  assert.equal(releaseEvent(admitted, event(2)), admitted);
  assert.deepEqual(completeEvent(emptyState(), event(1)), emptyState());
});

test("the remembered events are bounded", () => {
  let state = emptyState();
  for (let index = 0; index < maxSeenEvents + 10; index++) {
    state = admitEvent(state, event(index), index * 100_000).state;
    state = completeEvent(state, event(index));
  }
  assert.equal(state.seen.length, maxSeenEvents);
  assert.equal(state.seen[0], event(10));
  // An event older than the window is no longer recognized: D1's inbox is what still stops its effect.
  assert.deepEqual(admitEvent(state, event(0), 1e12).result, { admit: true });
});

const wake = (n = 1): WakeMessage => ({
  v: 1,
  kind: "job.wake",
  jobId: event(900),
  scope: "proof/run-1",
  eventId: event(n),
});

test("wake messages are a closed shape carrying identifiers only", () => {
  assert.deepEqual(parseWake(wake()), wake());
  for (const bad of [
    null,
    "x",
    [],
    { ...wake(), extra: 1 },
    { ...wake(), v: 2 },
    { ...wake(), kind: "other" },
    { ...wake(), jobId: "not-a-uuid" },
    { ...wake(), eventId: event(1).replace(/^0/u, "A") },
    { ...wake(), scope: "other/run" },
    { ...wake(), scope: "proof/" },
    { ...wake(), scope: `proof/${"x".repeat(201)}` },
    { v: 1, kind: "job.wake", jobId: event(900), scope: "proof/run-1" },
  ])
    assert.equal(parseWake(bad), null, JSON.stringify(bad));
});

test("slice replies are parsed strictly", () => {
  const body = (value: unknown) => new TextEncoder().encode(JSON.stringify(value));
  assert.deepEqual(parseSliceReply(body({ state: "running", jobComplete: false, cursor: "3" })), {
    state: "running",
    jobComplete: false,
  });
  for (const bad of [
    { state: "running" },
    { state: "bogus", jobComplete: true },
    { state: "complete", jobComplete: "yes" },
  ])
    assert.equal(parseSliceReply(body(bad)), null);
  assert.equal(parseSliceReply(new TextEncoder().encode("not json")), null);
});

test("retry backoff grows and is capped", () => {
  assert.deepEqual([0, 1, 2, 3, 6, 7, 20].map(backoffSeconds), [1, 2, 4, 8, 60, 60, 60]);
});

interface Harness {
  deps: ConsumerDeps;
  messages: { acked: number; retried: (number | undefined)[] };
  sent: WakeMessage[];
  calls: { admit: string[]; complete: string[]; release: string[]; slice: WakeMessage[] };
  message: MessageLike;
}
function harness(options: {
  admit?: AdmitResult | "throw";
  slice?: { status: number; body: unknown } | "throw";
  sendFails?: boolean;
  body?: unknown;
  attempts?: number;
}): Harness {
  const calls: Harness["calls"] = { admit: [], complete: [], release: [], slice: [] };
  const messages: Harness["messages"] = { acked: 0, retried: [] };
  const sent: WakeMessage[] = [];
  const coordinator: CoordinatorLike = {
    admit(id) {
      calls.admit.push(id);
      if (options.admit === "throw") return Promise.reject(new Error("unreachable"));
      return Promise.resolve(options.admit ?? { admit: true });
    },
    complete(id) {
      calls.complete.push(id);
      return Promise.resolve();
    },
    release(id) {
      calls.release.push(id);
      return Promise.resolve();
    },
    recordPoisonAttempt: () => Promise.reject(new Error("not a poison probe")),
    recordDeadLetter: () => Promise.reject(new Error("not a poison probe")),
    readPoison: () => Promise.reject(new Error("not a poison probe")),
  };
  let counter = 100;
  const deps: ConsumerDeps = {
    coordinators: { getByName: () => coordinator },
    queue: {
      send(message) {
        if (options.sendFails) return Promise.reject(new Error("queue down"));
        sent.push(message as WakeMessage);
        return Promise.resolve();
      },
    },
    newEventId: () => event(counter++),
    callSlice(message) {
      calls.slice.push(message);
      if (options.slice === "throw") return Promise.reject(new Error("container down"));
      const reply = options.slice ?? {
        status: 200,
        body: { state: "running", jobComplete: false },
      };
      return Promise.resolve({
        status: reply.status,
        body: new TextEncoder().encode(JSON.stringify(reply.body)),
      });
    },
  };
  const message: MessageLike = {
    body: options.body ?? wake(),
    attempts: options.attempts ?? 1,
    ack: () => {
      messages.acked++;
    },
    retry: (retry) => {
      messages.retried.push(retry?.delaySeconds);
    },
  };
  return { deps, messages, sent, calls, message };
}

test("a running job enqueues a continuation with a new event id, then completes and acks the event", async () => {
  const h = harness({});
  assert.equal(await processWake(h.message, h.deps), "continued");
  assert.equal(h.messages.acked, 1);
  assert.deepEqual(h.messages.retried, []);
  assert.deepEqual(h.sent, [{ ...wake(), eventId: event(100) }]);
  assert.deepEqual(h.calls.complete, [event(1)]);
  assert.deepEqual(h.calls.release, []);
});

test("a finished job is acknowledged without a continuation", async () => {
  const h = harness({ slice: { status: 200, body: { state: "complete", jobComplete: true } } });
  assert.equal(await processWake(h.message, h.deps), "complete");
  assert.deepEqual(h.sent, []);
  assert.equal(h.messages.acked, 1);
});

test("a duplicate slice reply still continues an unfinished job", async () => {
  const h = harness({ slice: { status: 200, body: { state: "duplicate", jobComplete: false } } });
  assert.equal(await processWake(h.message, h.deps), "continued");
  assert.equal(h.sent.length, 1);
});

test("a duplicate delivery is acknowledged without touching the Container", async () => {
  const h = harness({ admit: { admit: false, reason: "duplicate" } });
  assert.equal(await processWake(h.message, h.deps), "duplicate");
  assert.deepEqual(h.calls.slice, []);
  assert.equal(h.messages.acked, 1);
});

test("a busy job is retried later and never acknowledged", async () => {
  const h = harness({ admit: { admit: false, reason: "busy" } });
  assert.equal(await processWake(h.message, h.deps), "busy");
  assert.deepEqual(h.messages.retried, [5]);
  assert.equal(h.messages.acked, 0);
  assert.deepEqual(h.calls.slice, []);
});

test("a malformed message is dropped as poison and never reaches the coordinator", async () => {
  const h = harness({ body: { v: 1 } });
  assert.equal(await processWake(h.message, h.deps), "dropped");
  assert.equal(h.messages.acked, 1);
  assert.deepEqual(h.calls.admit, []);
});

test("Container failure, a bad status or an unparsable reply releases the event and retries with backoff", async () => {
  for (const slice of [
    "throw" as const,
    { status: 503, body: {} },
    { status: 200, body: { nonsense: true } },
  ]) {
    const h = harness({ slice, attempts: 3 });
    assert.equal(await processWake(h.message, h.deps), "retry");
    assert.deepEqual(h.calls.release, [event(1)]);
    assert.deepEqual(h.calls.complete, []);
    assert.deepEqual(h.messages.retried, [8]);
    assert.equal(h.messages.acked, 0);
  }
});

test("a busy or stale holder reply releases the event and retries shortly without a continuation", async () => {
  for (const [state, delay] of [
    ["busy", 10],
    ["stale", 1],
  ] as const) {
    const h = harness({ slice: { status: 200, body: { state, jobComplete: false } } });
    assert.equal(await processWake(h.message, h.deps), "busy");
    assert.deepEqual(h.messages.retried, [delay]);
    assert.deepEqual(h.calls.release, [event(1)]);
    assert.deepEqual(h.sent, []);
  }
});

test("when the continuation cannot be queued the message is retried so the hint is not lost", async () => {
  const h = harness({ sendFails: true });
  assert.equal(await processWake(h.message, h.deps), "retry");
  assert.deepEqual(h.calls.release, [event(1)]);
  assert.equal(h.messages.acked, 0);
});

test("an unreachable coordinator is a retry, not a lost message", async () => {
  const h = harness({ admit: "throw", attempts: 1 });
  assert.equal(await processWake(h.message, h.deps), "retry");
  assert.deepEqual(h.messages.retried, [2]);
  assert.deepEqual(h.calls.slice, []);
});
