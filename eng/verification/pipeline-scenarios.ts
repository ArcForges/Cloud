// SPDX-License-Identifier: AGPL-3.0-only
// The CLOUD.01 ingress pipeline scenarios, written once and run against a target the operator names:
// the local cross-process harness (the real host process behind the real Worker modules in workerd)
// or the deployed `proof` environment (explicit local opt-in, never CI). They observe the public
// binary gRPC-Web path end to end: an authenticated unary call with the current owner resolved, the
// CSRF/Origin/credential refusals, a server stream that must arrive frame by frame with its custom
// trailer, the cancellation of a stream reaching the host, and a stream deadline ending with a status.
// The probe messages are hand-framed proof bytes; the probe exists only in the proof environment.
import assert from "node:assert/strict";
import { randomBytes, randomUUID } from "node:crypto";
import { type Evidence, operator, type Target } from "./foundation-scenarios.ts";

const sleep = (ms: number) => new Promise((resolve) => setTimeout(resolve, ms));
const whoamiPath = "/api/arcforges.proof.v1.PipelineProbe/Whoami";
const streamPath = "/api/arcforges.proof.v1.PipelineProbe/Stream";
const observationPath = "/api/arcforges.proof.v1.PipelineProbe/Observation";
const probeTrailer = "x-af-probe";

// ---- protobuf and gRPC-Web framing, by hand ----

function varint(value: number | bigint): number[] {
  let rest = BigInt(value);
  const bytes: number[] = [];
  while (rest >= 0x80n) {
    bytes.push(Number(rest & 0x7fn) | 0x80);
    rest >>= 7n;
  }
  bytes.push(Number(rest));
  return bytes;
}

function lengthDelimited(field: number, bytes: Uint8Array | number[]): number[] {
  return [...varint((field << 3) | 2), ...varint(bytes.length), ...bytes];
}

function uuidBytes(uuid: string): number[] {
  return [...Buffer.from(uuid.replaceAll("-", ""), "hex")];
}

/** RequestMeta at field 1 of the request: the workspace (field 4, an Id message) and an optional generation (field 7). */
export function envelope(workspaceId: string | null, generation?: number): number[] {
  const meta = [
    ...(workspaceId === null ? [] : lengthDelimited(4, lengthDelimited(1, uuidBytes(workspaceId)))),
    ...(generation === undefined ? [] : [...varint(7 << 3), ...varint(generation)]),
  ];
  return lengthDelimited(1, meta);
}

function frame(message: number[]): Uint8Array<ArrayBuffer> {
  const bytes = new Uint8Array(5 + message.length);
  new DataView(bytes.buffer).setUint32(1, message.length);
  bytes.set(message, 5);
  return bytes;
}

interface Frame {
  flag: number;
  payload: Uint8Array;
  atMs: number;
}

/** Reads whole frames from a response body as they arrive, timestamping each. */
async function* frames(body: ReadableStream<Uint8Array>, started: number): AsyncGenerator<Frame> {
  const reader = body.getReader();
  let buffer = new Uint8Array(0);
  const need = async (count: number): Promise<boolean> => {
    while (buffer.length < count) {
      const { done, value } = await reader.read();
      if (done) return false;
      const joined = new Uint8Array(buffer.length + value.length);
      joined.set(buffer);
      joined.set(value, buffer.length);
      buffer = joined;
    }
    return true;
  };
  for (;;) {
    if (!(await need(5))) {
      assert.equal(buffer.length, 0, "the response ended inside a frame header");
      return;
    }
    const length = new DataView(buffer.buffer, buffer.byteOffset).getUint32(1);
    assert(await need(5 + length), "the response ended inside a frame");
    yield {
      flag: buffer[0] as number,
      payload: buffer.slice(5, 5 + length),
      atMs: performance.now() - started,
    };
    buffer = buffer.slice(5 + length);
  }
}

function trailers(payload: Uint8Array): Record<string, string> {
  const result: Record<string, string> = {};
  for (const line of new TextDecoder().decode(payload).split("\r\n")) {
    const separator = line.indexOf(": ");
    if (separator > 0) result[line.slice(0, separator)] = line.slice(separator + 2);
  }
  return result;
}

function field(message: Uint8Array, wanted: number): Uint8Array | bigint | undefined {
  let position = 0;
  const read = (): bigint => {
    let value = 0n;
    for (let shift = 0n; ; shift += 7n) {
      const byte = message[position++] as number;
      value |= BigInt(byte & 0x7f) << shift;
      if ((byte & 0x80) === 0) return value;
    }
  };
  while (position < message.length) {
    const tag = Number(read());
    const number = tag >> 3;
    const wire = tag & 7;
    let value: Uint8Array | bigint;
    if (wire === 0) value = read();
    else if (wire === 2) {
      const length = Number(read());
      value = message.slice(position, position + length);
      position += length;
    } else throw new Error(`unexpected wire type ${wire}`);
    if (number === wanted) return value;
  }
  return undefined;
}

const text = (value: Uint8Array | bigint | undefined) =>
  new TextDecoder().decode(value as Uint8Array);

interface Session {
  cookie: string;
  csrf: string;
  workspace: string;
  sessionId: string;
  user: string;
}

async function issueSession(target: Target): Promise<Session> {
  const workspace = randomUUID();
  const user = randomUUID();
  const issued = await operator(target, "session/issue", {
    userId: user,
    deviceId: randomUUID(),
    workspaceIds: [workspace],
  });
  assert.equal(issued.status, 200, JSON.stringify(issued.json));
  return {
    cookie: `__Host-af_session=${String(issued.json.handle)}`,
    csrf: String(issued.json.csrfToken),
    workspace,
    sessionId: String(issued.json.sessionId),
    user,
  };
}

function authorized(target: Target, session: Session, extra: Record<string, string> = {}) {
  return {
    "content-type": "application/grpc-web+proto",
    cookie: session.cookie,
    origin: target.origin,
    "x-af-csrf": session.csrf,
    ...extra,
  };
}

interface Reply {
  status: number;
  headers: Headers;
  frames: Frame[];
}

async function unary(
  target: Target,
  path: string,
  headers: Record<string, string>,
  message: number[],
): Promise<Reply> {
  const started = performance.now();
  const response = await fetch(`${target.baseUrl}${path}`, {
    method: "POST",
    headers: { "content-type": "application/grpc-web+proto", ...headers },
    body: frame(message),
    redirect: "error",
    signal: AbortSignal.timeout(30_000),
  });
  const collected: Frame[] = [];
  if (response.status === 200 && response.body)
    for await (const item of frames(response.body, started)) collected.push(item);
  return { status: response.status, headers: response.headers, frames: collected };
}

/** The gRPC status of a reply, from its trailer frame or its headers. */
function grpcStatus(reply: Reply): number {
  const trailer = reply.frames.find((item) => item.flag === 0x80);
  const code = trailer
    ? trailers(trailer.payload)["grpc-status"]
    : (reply.headers.get("grpc-status") ?? undefined);
  assert.notEqual(code, undefined, `no gRPC status (HTTP ${reply.status})`);
  return Number(code);
}

// ---- the scenarios ----

export async function pipelineUnary(target: Target): Promise<Evidence> {
  const session = await issueSession(target);
  const reply = await unary(
    target,
    whoamiPath,
    authorized(target, session),
    envelope(session.workspace),
  );
  assert.equal(reply.status, 200);
  assert.equal(grpcStatus(reply), 0);
  const message = reply.frames.find((item) => item.flag === 0)?.payload;
  assert.ok(message, "a data frame");
  assert.equal(text(field(message, 1)), session.sessionId);
  assert.equal(text(field(message, 2)), session.user);
  assert.equal(
    text(field(message, 3)),
    session.workspace,
    "the current owner is the addressed workspace",
  );
  assert.equal(reply.headers.get("cache-control"), "no-store");
  assert.equal(reply.headers.get("set-cookie"), null);
  assert.ok(reply.headers.get("x-arcforges-worker-revision"));
  return {
    scenario: "pipeline-unary",
    ok: true,
    detail: {
      httpStatus: reply.status,
      grpcStatus: 0,
      dataFrames: reply.frames.filter((item) => item.flag === 0).length,
      workerRevision: reply.headers.get("x-arcforges-worker-revision"),
    },
  };
}

export async function pipelineRefusals(target: Target): Promise<Evidence> {
  const session = await issueSession(target);
  const good = authorized(target, session);
  const run = (headers: Record<string, string>, message = envelope(session.workspace)) =>
    unary(target, whoamiPath, headers, message);
  const withoutCredential = { "content-type": "application/grpc-web+proto" };
  const results: Record<string, number> = {};
  const expect = async (label: string, reply: Promise<Reply>, code: number): Promise<void> => {
    const outcome = await reply;
    assert.equal(outcome.status, 200, label);
    assert.equal(grpcStatus(outcome), code, label);
    assert.equal(
      outcome.frames.filter((item) => item.flag === 0).length,
      0,
      `${label}: no message accompanies a refusal`,
    );
    results[label] = code;
  };
  await expect("no credential", run(withoutCredential), 16);
  await expect("wrong origin", run({ ...good, origin: "https://evil.example" }), 7);
  const { origin: _omitted, ...noOrigin } = good;
  await expect("no origin", run(noOrigin), 7);
  await expect(
    "no csrf",
    run({ ...withoutCredential, cookie: session.cookie, origin: target.origin }),
    7,
  );
  await expect("wrong csrf", run({ ...good, "x-af-csrf": "x".repeat(43) }), 7);
  await expect("malformed cookie", run({ ...good, cookie: "__Host-af_session=short" }), 16);
  await expect(
    "unknown session",
    run({ ...good, cookie: `__Host-af_session=${randomBytes(32).toString("base64url")}` }),
    16,
  );
  await expect("foreign workspace", run(good, envelope(randomUUID())), 7);
  await expect("no workspace", run(good, envelope(null)), 3);
  await expect("stale generation", run(good, envelope(session.workspace, 7)), 9);
  await expect(
    "bearer without verifier",
    run({ ...withoutCredential, authorization: `Bearer ${"t".repeat(40)}` }),
    16,
  );
  // The valid control still works, then logout revokes the session and the very next call refuses.
  const control = await run(good);
  assert.equal(grpcStatus(control), 0, "the valid control request");
  const logout = await fetch(`${target.baseUrl}/session/v1/logout`, {
    method: "POST",
    headers: { cookie: session.cookie, origin: target.origin, "x-af-csrf": session.csrf },
    redirect: "error",
    signal: AbortSignal.timeout(30_000),
  });
  assert.equal(logout.status, 200);
  await expect("revoked session", run(good), 16);
  const unknownMethod = await fetch(`${target.baseUrl}/api/arcforges.proof.v1.PipelineProbe/Nope`, {
    method: "POST",
    headers: good,
    body: frame(envelope(session.workspace)),
    redirect: "error",
    signal: AbortSignal.timeout(30_000),
  });
  assert.equal(unknownMethod.status, 404);
  const internal = await fetch(`${target.baseUrl}/api/internal/storage/v1/execute-plan`, {
    method: "POST",
    headers: good,
    body: frame([]),
    redirect: "error",
    signal: AbortSignal.timeout(30_000),
  });
  assert.equal(internal.status, 404);
  return {
    scenario: "pipeline-refusals",
    ok: true,
    detail: { refusals: results, unknownMethodStatus: 404, internalPathStatus: 404 },
  };
}

function streamMessage(workspace: string, count: number, intervalMs: number): number[] {
  return [
    ...envelope(workspace),
    ...varint(10 << 3),
    ...varint(count),
    ...varint(11 << 3),
    ...varint(intervalMs),
  ];
}

export async function pipelineStream(target: Target): Promise<Evidence> {
  const session = await issueSession(target);
  const count = 5;
  const interval = 500;
  const started = performance.now();
  const response = await fetch(`${target.baseUrl}${streamPath}`, {
    method: "POST",
    headers: authorized(target, session),
    body: frame(streamMessage(session.workspace, count, interval)),
    redirect: "error",
    signal: AbortSignal.timeout(60_000),
  });
  assert.equal(response.status, 200);
  assert.ok(response.body);
  const arrivals: number[] = [];
  let trailer: Record<string, string> | undefined;
  let sequence = 0;
  for await (const item of frames(response.body, started)) {
    if (item.flag === 0) {
      assert.equal(
        field(item.payload, 1),
        BigInt(sequence),
        "frames arrive in order, none lost or repeated",
      );
      const payload = field(item.payload, 2) as Uint8Array;
      assert.equal(payload.length, 32);
      for (let i = 0; i < 32; i++) assert.equal(payload[i], (sequence * 31 + i) & 0xff);
      arrivals.push(item.atMs);
      sequence++;
    } else {
      trailer = trailers(item.payload);
    }
  }
  assert.equal(sequence, count);
  assert.ok(trailer, "the status trailer arrives");
  assert.equal(trailer["grpc-status"], "0");
  assert.equal(trailer[probeTrailer], "done", "the custom trailer survives the Worker");
  const first = arrivals[0] as number;
  const last = arrivals[count - 1] as number;
  // A buffering Worker would deliver everything at the end: the first frame would arrive after the
  // last one was produced and the arrivals would collapse into one burst.
  assert.ok(
    last - first >= (count - 1) * interval * 0.7,
    `frames arrived as a burst: ${Math.round(last - first)} ms apart over ${count - 1} intervals of ${interval} ms`,
  );
  return {
    scenario: "pipeline-stream",
    ok: true,
    detail: {
      frames: count,
      intervalMs: interval,
      arrivalsMs: arrivals.map((value) => Math.round(value)),
      spreadMs: Math.round(last - first),
      trailerStatus: trailer["grpc-status"],
      customTrailer: trailer[probeTrailer],
    },
  };
}

async function observation(target: Target, session: Session) {
  const reply = await unary(
    target,
    observationPath,
    authorized(target, session),
    envelope(session.workspace),
  );
  assert.equal(grpcStatus(reply), 0);
  const message = reply.frames.find((item) => item.flag === 0)?.payload as Uint8Array;
  const count = (wanted: number) => Number((field(message, wanted) as bigint | undefined) ?? 0n);
  return { started: count(1), completed: count(2), canceled: count(3), deadline: count(4) };
}

export async function pipelineStreamCancel(target: Target): Promise<Evidence> {
  const session = await issueSession(target);
  const before = await observation(target, session);
  const controller = new AbortController();
  const response = await fetch(`${target.baseUrl}${streamPath}`, {
    method: "POST",
    headers: authorized(target, session),
    body: frame(streamMessage(session.workspace, 50, 100)),
    redirect: "error",
    signal: controller.signal,
  });
  assert.equal(response.status, 200);
  const seen: number[] = [];
  const reader = frames(response.body as ReadableStream<Uint8Array>, performance.now());
  for (let i = 0; i < 2; i++) seen.push((await reader.next()).value?.atMs ?? -1);
  assert.ok(
    seen.every((value) => value >= 0),
    "two frames before the client goes away",
  );
  const closedAt = Date.now();
  controller.abort();
  let after = before;
  const deadline = Date.now() + 30_000;
  while (Date.now() < deadline) {
    await sleep(500);
    after = await observation(target, session);
    if (after.canceled > before.canceled) break;
  }
  assert.ok(
    after.canceled > before.canceled,
    `the host never saw the stream end (canceled ${before.canceled} -> ${after.canceled})`,
  );
  assert.equal(
    after.completed,
    before.completed,
    "the stream must not have run to completion after the client closed",
  );
  return {
    scenario: "pipeline-stream-cancel",
    ok: true,
    detail: {
      framesBeforeClose: 2,
      hostCanceledBefore: before.canceled,
      hostCanceledAfter: after.canceled,
      observedAfterMs: Date.now() - closedAt,
    },
  };
}

export async function pipelineStreamDeadline(target: Target): Promise<Evidence> {
  const session = await issueSession(target);
  const started = performance.now();
  const response = await fetch(`${target.baseUrl}${streamPath}`, {
    method: "POST",
    headers: authorized(target, session, { "grpc-timeout": "700m" }),
    body: frame(streamMessage(session.workspace, 30, 200)),
    redirect: "error",
    signal: AbortSignal.timeout(30_000),
  });
  assert.equal(response.status, 200);
  const items: Frame[] = [];
  for await (const item of frames(response.body as ReadableStream<Uint8Array>, started))
    items.push(item);
  const data = items.filter((item) => item.flag === 0).length;
  const end = items.at(-1);
  assert.ok(end && end.flag === 0x80, "the stream ends with a status trailer, never a silent end");
  assert.equal(trailers(end.payload)["grpc-status"], "4");
  assert.ok(data >= 1 && data < 30, `${data} data frames before the deadline`);
  return {
    scenario: "pipeline-stream-deadline",
    ok: true,
    detail: { dataFrames: data, trailerStatus: 4, totalMs: Math.round(end.atMs) },
  };
}
