// SPDX-License-Identifier: AGPL-3.0-only
// CLOUD.69: correlation acceptance and propagation on the Worker side. The real router and pipeline run against a
// faked Container binding: a valid client identity is joined to one traceparent, an absent one is created, a
// malformed one is refused before anything wakes, nothing a client sends becomes a header, and the identity never
// takes part in an admission decision. The job wake and the private job-slice call carry the identity and a cause.
import assert from "node:assert/strict";
import test from "node:test";
import {
  isCorrelationId,
  newCorrelationId,
  newSpanId,
  readRequestCorrelation,
  singleMessage,
  traceparentFor,
} from "../../worker/ingress/correlation.ts";
import { jobSliceBody } from "../../worker/foundation/container-client.ts";
import { queueEntry } from "../../worker/foundation/entry.ts";
import { trailerFrame } from "../../worker/ingress/io.ts";
import type { MessageLike } from "../../worker/foundation/queue.ts";
import type { CoordinatorLike, FoundationEnv, WakeMessage } from "../../worker/foundation/types.ts";
import { base64UrlEncode } from "../../worker/private/encoding.ts";
import { routeRequest, type CloudBindings } from "../../worker/router.ts";
import { createFakeR2 } from "./support/fake-r2.ts";
import { parseTraceparent } from "./support/traceparent.ts";

const origin = "https://proof.example.test";
const whoami = "/api/arcforges.proof.v1.PipelineProbe/Whoami";
const stream = "/api/arcforges.proof.v1.PipelineProbe/Stream";
const hello = "/api/arcforges.hello.v1.HelloService/SayHello";
const handle = "A".repeat(43);
const csrf = "B".repeat(43);
const grpcWeb = "application/grpc-web+proto";
const nil = "00000000-0000-0000-0000-000000000000";
const mine = "4bf92f35-77b3-4da6-a3ce-929d0e0e4736";

// ---- protobuf builders: the tests state the wire bytes themselves ----

const bytes = (...parts: (number[] | Uint8Array)[]): Uint8Array =>
  Uint8Array.from(parts.flatMap((part) => [...part]));
const varint = (value: number): number[] => {
  const out: number[] = [];
  let rest = value;
  while (rest >= 0x80) {
    out.push((rest % 0x80) | 0x80);
    rest = Math.floor(rest / 0x80);
  }
  out.push(rest);
  return out;
};
const tag = (field: number, wire: number): number[] => varint(field * 8 + wire);
const lengthDelimited = (field: number, body: Uint8Array | number[]): Uint8Array =>
  bytes(tag(field, 2), varint(body.length), body);
const uuidBytes = (uuid: string): number[] =>
  [...uuid.replaceAll("-", "").matchAll(/../gu)].map((pair) => Number.parseInt(pair[0], 16));
const idMessage = (value: Uint8Array | number[]): Uint8Array => lengthDelimited(1, value);
const correlationField = (uuid: string): Uint8Array =>
  lengthDelimited(3, idMessage(uuidBytes(uuid)));
const workspaceField = (uuid: string): Uint8Array => lengthDelimited(4, idMessage(uuidBytes(uuid)));
const envelope = (...metaFields: Uint8Array[]): Uint8Array =>
  lengthDelimited(1, bytes(...metaFields));
const framed = (message: Uint8Array): Uint8Array<ArrayBuffer> => {
  const out = new Uint8Array(5 + message.length);
  new DataView(out.buffer).setUint32(1, message.length);
  out.set(message, 5);
  return out;
};
const concat = (...parts: Uint8Array[]): Uint8Array<ArrayBuffer> =>
  Uint8Array.from(parts.flatMap((part) => [...part]));
const okReply = concat(framed(bytes([1, 2])), trailerFrame(0));

const malformedKinds: Record<string, Uint8Array> = {
  repeated: bytes(correlationField(mine), correlationField(newCorrelationId())),
  fifteenBytes: lengthDelimited(3, idMessage(uuidBytes(mine).slice(0, 15))),
  seventeenBytes: lengthDelimited(3, idMessage([...uuidBytes(mine), 1])),
  allZero: lengthDelimited(3, idMessage(new Array<number>(16).fill(0))),
  emptyId: lengthDelimited(3, []),
  noValue: lengthDelimited(3, bytes(tag(2, 0), [1])),
  varintWire: bytes(tag(3, 0), [1]),
  repeatedValue: lengthDelimited(
    3,
    bytes(idMessage(uuidBytes(mine)), idMessage(uuidBytes(newCorrelationId()))),
  ),
  uuidText: lengthDelimited(3, idMessage([...new TextEncoder().encode(mine)])),
};

// ---- the identity helpers ----

test("only a canonical lowercase nonzero UUID is a correlation identity", () => {
  assert.equal(isCorrelationId(mine), true);
  assert.equal(isCorrelationId(newCorrelationId()), true);
  for (const bad of [
    mine.toUpperCase(),
    nil,
    `{${mine}}`,
    mine.replaceAll("-", ""),
    `${mine} `,
    `${mine}\r\nx-injected: 1`,
    "",
    null,
    undefined,
    7,
    {},
  ])
    assert.equal(isCorrelationId(bad), false, String(bad));
});

test("a traceparent is built from the identity and parsed back strictly", () => {
  const span = "00f067aa0ba902b7";
  const traceparent = traceparentFor(mine, span);
  assert.equal(traceparent, `00-4bf92f3577b34da6a3ce929d0e0e4736-${span}-01`);
  assert.deepEqual(parseTraceparent(traceparent), { correlationId: mine, parentSpanId: span });
  assert.match(traceparentFor(mine), /^00-4bf92f3577b34da6a3ce929d0e0e4736-[0-9a-f]{16}-01$/u);
  assert.throws(() => traceparentFor("not-an-id"));
  assert.throws(() => traceparentFor(nil));
  for (const bad of [
    null,
    "",
    `00-${"0".repeat(32)}-${span}-01`,
    `00-4bf92f3577b34da6a3ce929d0e0e4736-${"0".repeat(16)}-01`,
    `01-4bf92f3577b34da6a3ce929d0e0e4736-${span}-01`,
    `00-4BF92F3577B34DA6A3CE929D0E0E4736-${span}-01`,
    `00-4bf92f3577b34da6a3ce929d0e0e4736-${span}-01 `,
    `00-4bf92f3577b34da6a3ce929d0e0e4736-${span}`,
  ])
    assert.equal(parseTraceparent(bad), null, String(bad));
  const spans = new Set(Array.from({ length: 300 }, () => newSpanId()));
  assert.equal(spans.size, 300);
  for (const value of spans) assert.match(value, /^(?!0{16}$)[0-9a-f]{16}$/u);
});

test("the request correlation is read strictly from RequestMeta without a per-method type", () => {
  const withWorkspace = (...rest: Uint8Array[]) =>
    envelope(workspaceField(newCorrelationId()), ...rest);
  assert.deepEqual(readRequestCorrelation(withWorkspace(correlationField(mine))), {
    kind: "valid",
    id: mine,
  });
  // Other fields of the meta and of the message are skipped, whatever their wire type.
  assert.deepEqual(
    readRequestCorrelation(
      bytes(
        envelope(
          bytes(tag(5, 1), new Array<number>(8).fill(1)),
          correlationField(mine),
          bytes(tag(7, 0), varint(300)),
          bytes(tag(9, 5), [1, 2, 3, 4]),
        ),
        bytes(tag(10, 0), [1]),
        lengthDelimited(11, [1, 2]),
      ),
    ),
    { kind: "valid", id: mine },
  );
  assert.deepEqual(readRequestCorrelation(new Uint8Array()), { kind: "absent" });
  assert.deepEqual(readRequestCorrelation(withWorkspace()), { kind: "absent" });
  assert.deepEqual(readRequestCorrelation(envelope()), { kind: "absent" });
  for (const [name, field] of Object.entries(malformedKinds))
    assert.deepEqual(readRequestCorrelation(withWorkspace(field)), { kind: "malformed" }, name);
  // A message that is not protobuf at all, or a repeated meta, is unreadable; the host refuses it on its own.
  for (const unreadable of [
    bytes([0xff]),
    bytes(tag(1, 2), varint(50), [1]),
    bytes(tag(1, 3)),
    bytes(envelope(), envelope()),
    bytes(tag(1, 0), [1]),
  ])
    assert.deepEqual(readRequestCorrelation(unreadable), { kind: "unreadable" });
  // A wrong correlation is a refusal even when a later field of the meta is cut off.
  assert.deepEqual(
    readRequestCorrelation(lengthDelimited(1, bytes(malformedKinds.allZero ?? [], [0x0a, 0x7f]))),
    { kind: "malformed" },
  );
});

test("a request body is one uncompressed message of exactly its declared length", () => {
  assert.deepEqual(singleMessage(framed(bytes([1, 2, 3]))), bytes([1, 2, 3]));
  assert.deepEqual(singleMessage(framed(new Uint8Array())), new Uint8Array());
  for (const bad of [
    new Uint8Array(),
    bytes([0, 0, 0, 0]),
    bytes([1, 0, 0, 0, 1, 7]),
    bytes([0, 0, 0, 0, 2, 7]),
    bytes([0, 0, 0, 0, 1, 7, 7]),
    bytes([0x80, 0, 0, 0, 0]),
  ])
    assert.equal(singleMessage(bad), null);
});

// ---- the Worker pipeline ----

interface Seen {
  requests: Request[];
}
function bindings(overrides: Partial<CloudBindings> = {}): { env: CloudBindings; seen: Seen } {
  const seen: Seen = { requests: [] };
  const env: CloudBindings = {
    SOURCE_REVISION: "candidate",
    BUILD_IDENTITY: '{"buildId":"fixture.1"}',
    FOUNDATION_PROOF: "enabled",
    ALLOWED_ORIGIN: origin,
    CLOUD_CONTAINER: {
      getByName() {
        return {
          async fetch(request) {
            seen.requests.push(request);
            return new Response(okReply);
          },
        };
      },
    },
    HELLO_RATE_LIMITER: { limit: async () => ({ success: true }) },
    ...overrides,
  };
  return { env, seen };
}
const cookieHeaders = { cookie: `__Host-af_session=${handle}`, origin, "x-af-csrf": csrf };
const call = (path: string, message: Uint8Array, headers: Record<string, string> = {}) =>
  new Request(`https://proof.example.test${path}`, {
    method: "POST",
    headers: { "content-type": grpcWeb, ...headers },
    body: framed(message),
  });

async function trailerStatus(response: Response): Promise<{ code: number; message: string }> {
  assert.equal(response.status, 200);
  const frame = new Uint8Array(await response.arrayBuffer());
  assert.equal(frame[0], 0x80);
  const text = new TextDecoder().decode(frame.subarray(5));
  return {
    code: Number(/^grpc-status: (\d+)/u.exec(text)?.[1]),
    message: decodeURIComponent(/grpc-message: ([^\r]*)/u.exec(text)?.[1] ?? ""),
  };
}

test("a valid client identity becomes the trace id of the one traceparent the Container receives", async () => {
  for (const path of [whoami, stream]) {
    const { env, seen } = bindings();
    const response = await routeRequest(
      call(
        path,
        envelope(workspaceField(newCorrelationId()), correlationField(mine)),
        cookieHeaders,
      ),
      env,
    );
    assert.equal(response.status, 200);
    const forwarded = seen.requests[0];
    assert.ok(forwarded);
    const traceparent = parseTraceparent(forwarded.headers.get("traceparent"));
    assert.equal(traceparent?.correlationId, mine);
    assert.match(traceparent?.parentSpanId ?? "", /^[0-9a-f]{16}$/u);
    // No new header reaches the client, and the identity is not reflected anywhere in the reply.
    assert.equal(response.headers.get("traceparent"), null);
    assert.equal(
      [...response.headers.values()].some((value) => value.includes(mine)),
      false,
    );
  }
});

test("an absent identity is created at the edge, one per call, and the body is forwarded unchanged", async () => {
  const { env, seen } = bindings();
  const message = envelope(workspaceField(newCorrelationId()));
  for (let index = 0; index < 4; index++)
    await routeRequest(call(whoami, message, cookieHeaders), env);
  const created = seen.requests.map(
    (request) => parseTraceparent(request.headers.get("traceparent"))?.correlationId,
  );
  assert.equal(created.length, 4);
  assert.equal(new Set(created).size, 4);
  for (const id of created) assert.equal(isCorrelationId(id), true);
  for (const request of seen.requests)
    assert.deepEqual(new Uint8Array(await request.arrayBuffer()), framed(message));
});

test("a malformed identity is refused as invalid_request before anything wakes or any credential decision", async () => {
  for (const [name, field] of Object.entries(malformedKinds)) {
    const { env, seen } = bindings();
    const response = await routeRequest(
      call(whoami, envelope(workspaceField(newCorrelationId()), field), cookieHeaders),
      env,
    );
    assert.deepEqual(
      await trailerStatus(response),
      {
        code: 3,
        message: "validation.invalid_request",
      },
      name,
    );
    assert.equal(seen.requests.length, 0, name);
  }
  // Admission failures that come first are unchanged by what the body states: no credential is still UNAUTHENTICATED.
  const { env, seen } = bindings();
  const bare = await routeRequest(
    call(whoami, envelope(malformedKinds.allZero ?? new Uint8Array())),
    env,
  );
  assert.deepEqual(await trailerStatus(bare), { code: 16, message: "auth.unauthenticated" });
  assert.equal(seen.requests.length, 0);
});

test("a message the Worker cannot read is passed on with a created identity and left to the host", async () => {
  const { env, seen } = bindings();
  await routeRequest(call(whoami, bytes([0xff, 0xff]), cookieHeaders), env);
  const traceparent = parseTraceparent(seen.requests[0]?.headers.get("traceparent") ?? null);
  assert.equal(isCorrelationId(traceparent?.correlationId), true);
  assert.equal(seen.requests.length, 1);
});

test("nothing a client sends becomes a trace header, and its own trace context is never believed", async () => {
  const { env, seen } = bindings();
  const hostile: Record<string, string> = {
    ...cookieHeaders,
    traceparent: `00-${"ab".repeat(16)}-${"cd".repeat(8)}-01`,
    tracestate: "evil=1",
    baggage: "k=v",
    "x-request-id": "attacker",
    "x-correlation-id": mine,
    "x-b3-traceid": "abc",
  };
  await routeRequest(call(whoami, envelope(workspaceField(newCorrelationId())), hostile), env);
  const forwarded = seen.requests[0];
  assert.ok(forwarded);
  const traceparent = parseTraceparent(forwarded.headers.get("traceparent"));
  assert.notEqual(traceparent?.correlationId, "abababab-abab-abab-abab-abababababab");
  assert.notEqual(traceparent?.parentSpanId, "cd".repeat(8));
  for (const name of ["tracestate", "baggage", "x-request-id", "x-correlation-id", "x-b3-traceid"])
    assert.equal(forwarded.headers.get(name), null, name);
  assert.equal(JSON.stringify([...forwarded.headers.values()]).includes("attacker"), false);
});

test("the Hello method is never read for a correlation, but its call is joined to a traceparent too", async () => {
  const { env, seen } = bindings();
  // Field 1 of a Hello request is the name: bytes that would be a malformed RequestMeta are just a name there.
  const name = new TextEncoder().encode("\u0003\u0005xy");
  const response = await routeRequest(call(hello, lengthDelimited(1, name)), env);
  assert.equal(response.status, 200);
  assert.equal(seen.requests.length, 1);
  assert.equal(
    isCorrelationId(
      parseTraceparent(seen.requests[0]?.headers.get("traceparent") ?? null)?.correlationId,
    ),
    true,
  );
  const health = bindings();
  await routeRequest(new Request("https://proof.example.test/api/healthz"), health.env);
  assert.equal(health.seen.requests[0]?.headers.get("traceparent"), null);
});

test("what the Worker admits or refuses never depends on the identity a client states", async () => {
  const base = envelope(workspaceField(newCorrelationId()));
  const stated = envelope(workspaceField(newCorrelationId()), correlationField(newCorrelationId()));
  const decisions = async (message: Uint8Array) => {
    const out: unknown[] = [];
    const cases: Record<string, string>[] = [
      cookieHeaders,
      {},
      { ...cookieHeaders, origin: "https://evil.example" },
      { ...cookieHeaders, "x-af-csrf": "short" },
      { cookie: `__Host-af_session=${handle}`, authorization: `Bearer ${"t".repeat(40)}` },
    ];
    for (const headers of cases) {
      const { env, seen } = bindings();
      const response = await routeRequest(call(whoami, message, headers), env);
      const forwarded = seen.requests[0];
      const credentialHeaders = forwarded
        ? Object.fromEntries(
            [...forwarded.headers.entries()].filter(([header]) => header !== "traceparent"),
          )
        : null;
      out.push({
        status: response.status,
        woke: seen.requests.length,
        credentialHeaders: credentialHeaders && { ...credentialHeaders, "grpc-timeout": "-" },
      });
    }
    return out;
  };
  assert.deepEqual(await decisions(stated), await decisions(base));
});

test("a body over the method bound is still refused as too large, whatever it states", async () => {
  const { env, seen } = bindings();
  const big = envelope(workspaceField(newCorrelationId()), correlationField(mine));
  const response = await routeRequest(
    new Request(`https://proof.example.test${whoami}`, {
      method: "POST",
      headers: { "content-type": grpcWeb, ...cookieHeaders },
      body: concat(framed(concat(big, new Uint8Array(5000)))),
    }),
    env,
  );
  assert.equal(response.status, 413);
  assert.equal(seen.requests.length, 0);
});

// ---- the queue wake and the private job-slice call ----

const eventId = (n: number) => `00000000-0000-4000-8000-${String(n).padStart(12, "0")}`;
const w2c = base64UrlEncode(new Uint8Array(32).fill(2));

function wakeHarness(options: { jobComplete: boolean }) {
  const slices: { path: string; body: Record<string, unknown>; headers: Headers }[] = [];
  const queued: WakeMessage[] = [];
  const coordinator: CoordinatorLike = {
    admit: () => Promise.resolve({ admit: true }),
    complete: () => Promise.resolve(),
    release: () => Promise.resolve(),
    recordPoisonAttempt: () => Promise.reject(new Error("unused")),
    recordDeadLetter: () => Promise.reject(new Error("unused")),
    readPoison: () => Promise.reject(new Error("unused")),
  };
  const env = {
    FOUNDATION_PROOF: "enabled",
    HMAC_W2C_KEY_ID: "w2c-1",
    HMAC_W2C_SECRET: w2c,
    OBJECTS: createFakeR2(),
    WAKE_QUEUE: {
      send(message: WakeMessage) {
        queued.push(message);
        return Promise.resolve();
      },
    },
    JOB_COORDINATOR: { getByName: () => coordinator },
    CLOUD_CONTAINER: {
      getByName: () => ({
        async fetch(request: Request) {
          slices.push({
            path: new URL(request.url).pathname,
            body: JSON.parse(await request.text()) as Record<string, unknown>,
            headers: request.headers,
          });
          return new Response(
            JSON.stringify({ state: "running", jobComplete: options.jobComplete }),
            {
              headers: { "content-type": "application/json" },
            },
          );
        },
      }),
    },
  } as unknown as FoundationEnv;
  const acked: number[] = [];
  const message = (body: unknown): MessageLike => ({
    body,
    attempts: 1,
    ack: () => acked.push(1),
    retry: () => assert.fail("must not retry"),
  });
  return { env, slices, queued, message, acked };
}

const wake = (overrides: Partial<WakeMessage> = {}): WakeMessage => ({
  v: 1,
  kind: "job.wake",
  jobId: eventId(900),
  scope: "proof/run-1",
  eventId: eventId(1),
  correlationId: mine,
  causationId: eventId(700),
  ...overrides,
});

test("the private job-slice call carries the wake's correlation and causation inside the signed body", async () => {
  const h = wakeHarness({ jobComplete: false });
  await queueEntry({ messages: [h.message(wake())] }, h.env as never);
  assert.equal(h.slices.length, 1);
  const slice = h.slices[0];
  assert.ok(slice);
  assert.equal(slice.path, "/internal/foundation/v1/job/slice");
  assert.deepEqual(slice.body, {
    scope: "proof/run-1",
    jobId: eventId(900),
    eventId: eventId(1),
    correlationId: mine,
    causationId: eventId(700),
    maxItems: 100,
    maxMilliseconds: 20_000,
  });
  // The body hash is what the signature covers, so the identity cannot be swapped in transit.
  assert.ok(slice.headers.get("x-af-signature"));
  assert.equal(h.acked.length, 1);
});

test("a continuation keeps the chain's identity and names the wake that just ran as its cause", async () => {
  const h = wakeHarness({ jobComplete: false });
  await queueEntry({ messages: [h.message(wake())] }, h.env as never);
  assert.equal(h.queued.length, 1);
  const next = h.queued[0];
  assert.ok(next);
  assert.equal(next.correlationId, mine);
  assert.equal(next.causationId, eventId(1));
  assert.notEqual(next.eventId, eventId(1));
  // Following it one step further keeps extending the same chain.
  const second = wakeHarness({ jobComplete: false });
  await queueEntry({ messages: [second.message(next)] }, second.env as never);
  assert.equal(second.slices[0]?.body.correlationId, mine);
  assert.equal(second.queued[0]?.causationId, next.eventId);
  assert.equal(second.queued[0]?.correlationId, mine);
});

test("a finished job queues nothing further and a wake with a bad identity is poison, never a slice", async () => {
  const done = wakeHarness({ jobComplete: true });
  await queueEntry({ messages: [done.message(wake())] }, done.env as never);
  assert.equal(done.queued.length, 0);
  const poison = wakeHarness({ jobComplete: false });
  for (const bad of [
    wake({ correlationId: "x" }),
    wake({ correlationId: nil }),
    wake({ causationId: mine.toUpperCase() }),
    { ...wake(), extra: "x" },
  ])
    await queueEntry({ messages: [poison.message(bad)] }, poison.env as never);
  assert.equal(poison.slices.length, 0);
  assert.equal(poison.acked.length, 4);
});

test("the job-slice body states exactly the correlation members and nothing from the wake that is free text", () => {
  const body = JSON.parse(
    new TextDecoder().decode(jobSliceBody(wake(), { maxItems: 5, maxMilliseconds: 7 })),
  ) as Record<string, unknown>;
  assert.deepEqual(Object.keys(body).sort(), [
    "causationId",
    "correlationId",
    "eventId",
    "jobId",
    "maxItems",
    "maxMilliseconds",
    "scope",
  ]);
});
