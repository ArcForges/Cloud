// SPDX-License-Identifier: AGPL-3.0-only
import assert from "node:assert/strict";
import test from "node:test";
import { setFlagsFromString } from "node:v8";
import { runInNewContext } from "node:vm";
import { canceledError, deadlineError } from "../../worker/ingress/errors.ts";
import { guardResponse, type GuardOptions } from "../../worker/ingress/frames.ts";
import { trailerFrame } from "../../worker/ingress/io.ts";

function dataFrame(payload: number[]): Uint8Array<ArrayBuffer> {
  const frame = new Uint8Array(5 + payload.length);
  new DataView(frame.buffer).setUint32(1, payload.length);
  frame.set(payload, 5);
  return frame;
}

function concat(...parts: Uint8Array[]): Uint8Array<ArrayBuffer> {
  const result = new Uint8Array(parts.reduce((sum, part) => sum + part.length, 0));
  let offset = 0;
  for (const part of parts) {
    result.set(part, offset);
    offset += part.length;
  }
  return result;
}

function sourceOf(chunks: Uint8Array[]) {
  const state = { pulls: 0, canceled: false };
  let index = 0;
  const stream = new ReadableStream<Uint8Array>(
    {
      pull(controller) {
        state.pulls++;
        const chunk = chunks[index++];
        if (chunk) controller.enqueue(chunk);
        else controller.close();
      },
      cancel() {
        state.canceled = true;
      },
    },
    { highWaterMark: 0 },
  );
  return { stream, state };
}

function options(overrides: Partial<GuardOptions> = {}) {
  const events: string[] = [];
  const controller = new AbortController();
  const result: GuardOptions = {
    signal: controller.signal,
    maxFrameBytes: 1024,
    onAbort: "trailer",
    onFinish: (outcome) => events.push(`finish:${outcome}`),
    onClientCancel: () => events.push("client-cancel"),
    ...overrides,
  };
  return { options: result, controller, events };
}

async function collect(stream: ReadableStream<Uint8Array>): Promise<{
  bytes: Uint8Array;
  error?: unknown;
}> {
  const reader = stream.getReader();
  const parts: Uint8Array[] = [];
  try {
    for (;;) {
      const { done, value } = await reader.read();
      if (done) break;
      parts.push(value);
    }
  } catch (error) {
    return { bytes: concat(...parts), error };
  }
  return { bytes: concat(...parts) };
}

function trailerText(bytes: Uint8Array): string {
  assert.equal(bytes[0], 0x80);
  return new TextDecoder().decode(bytes.subarray(5));
}

const okTrailer = trailerFrame(0);
const wholeReply = concat(dataFrame([1, 2, 3]), dataFrame([4]), okTrailer);

test("a reply passes unchanged however the platform splits it into chunks", async () => {
  for (const size of [1, 2, 3, 4, 5, 6, 7, 11, wholeReply.length]) {
    const chunks: Uint8Array[] = [];
    for (let offset = 0; offset < wholeReply.length; offset += size)
      chunks.push(wholeReply.subarray(offset, offset + size));
    const { stream } = sourceOf(chunks);
    const { options: guard, events } = options();
    const { bytes, error } = await collect(guardResponse(stream, guard));
    assert.equal(error, undefined, `chunk size ${size}`);
    assert.deepEqual(bytes, wholeReply, `chunk size ${size}`);
    assert.deepEqual(events, ["finish:complete"]);
  }
});

test("a zero-length data frame and a zero-length trailer frame are whole frames", async () => {
  const reply = concat(dataFrame([]), new Uint8Array([0x80, 0, 0, 0, 0]));
  for (const size of [1, reply.length]) {
    const chunks: Uint8Array[] = [];
    for (let offset = 0; offset < reply.length; offset += size)
      chunks.push(reply.subarray(offset, offset + size));
    const { bytes, error } = await collect(
      guardResponse(sourceOf(chunks).stream, options().options),
    );
    assert.equal(error, undefined);
    assert.deepEqual(bytes, reply);
  }
});

test("an end of data without a status trailer becomes UNAVAILABLE, never a success", async () => {
  const { stream } = sourceOf([dataFrame([1, 2, 3])]);
  const { options: guard, events } = options();
  const { bytes, error } = await collect(guardResponse(stream, guard));
  assert.equal(error, undefined);
  const trailer = bytes.subarray(8);
  assert.match(trailerText(trailer), /^grpc-status: 14\r\n/u);
  assert.deepEqual(events, ["finish:trailer"]);
  const empty = await collect(guardResponse(sourceOf([]).stream, options().options));
  assert.match(trailerText(empty.bytes), /^grpc-status: 14\r\n/u);
});

test("an empty body with the status in the headers is a complete trailers-only reply", async () => {
  const { options: guard, events } = options({ statusInHeaders: true });
  const { bytes, error } = await collect(guardResponse(sourceOf([]).stream, guard));
  assert.equal(error, undefined);
  assert.equal(bytes.length, 0);
  assert.deepEqual(events, ["finish:complete"]);
});

test("an end inside a frame errors the stream instead of closing it", async () => {
  for (const cut of [1, 3, 5, 6, wholeReply.length - 1]) {
    const { options: guard, events } = options();
    const { error } = await collect(
      guardResponse(sourceOf([wholeReply.subarray(0, cut)]).stream, guard),
    );
    assert.ok(error instanceof Error, `cut ${cut}`);
    assert.deepEqual(events, ["finish:error"]);
  }
});

test("frame violations error the stream and release the source", async () => {
  const cases: [string, Uint8Array[], Partial<GuardOptions>][] = [
    ["unknown flag", [new Uint8Array([2, 0, 0, 0, 0])], {}],
    ["compressed flag", [dataFrame([1]).map((b, i) => (i === 0 ? 1 : b))], {}],
    ["oversized frame", [dataFrame(new Array(11).fill(1))], { maxFrameBytes: 10 }],
    ["huge declared length", [new Uint8Array([0, 0xff, 0xff, 0xff, 0xff])], {}],
    ["data after the trailer, same chunk", [concat(okTrailer, dataFrame([1]))], {}],
    ["data after the trailer, later chunk", [okTrailer, dataFrame([1])], {}],
    [
      "a second data frame of a unary reply",
      [concat(dataFrame([1]), dataFrame([2]))],
      { maxDataFrames: 1 },
    ],
    ["a reply over its total bound", [dataFrame(new Array(50).fill(1))], { maxResponseBytes: 40 }],
  ];
  for (const [name, chunks, overrides] of cases) {
    const { stream, state } = sourceOf(chunks);
    const { options: guard, events } = options(overrides);
    const { error, bytes } = await collect(guardResponse(stream, guard));
    assert.ok(error instanceof Error, name);
    assert.equal(state.canceled, true, name);
    assert.deepEqual(events, ["finish:error"], name);
    // The violating chunk itself is never delivered; only the valid chunk before it may have been.
    assert.equal(bytes.length, name.includes("later chunk") ? okTrailer.length : 0, name);
  }
});

test("a deadline or cancellation on a frame boundary ends with an explicit status trailer", async () => {
  for (const [reason, status] of [
    [deadlineError, 4],
    [canceledError, 1],
  ] as const) {
    const frame = dataFrame([9, 9]);
    const hold = new ReadableStream<Uint8Array>({
      start(controller) {
        controller.enqueue(frame);
      },
    });
    const { options: guard, controller, events } = options();
    const guarded = guardResponse(hold, guard).getReader();
    assert.deepEqual((await guarded.read()).value, frame);
    const pending = guarded.read();
    controller.abort(reason);
    const tail = await pending;
    assert.ok(tail.value, "a trailer is delivered");
    assert.match(trailerText(tail.value), new RegExp(`^grpc-status: ${status}\\r\\n`, "u"));
    assert.equal((await guarded.read()).done, true);
    assert.deepEqual(events, ["finish:trailer"]);
  }
});

test("an abort inside a frame, or with onAbort error, errors the stream", async () => {
  const half = dataFrame([1, 2, 3]).subarray(0, 7);
  const cases: [string, Uint8Array, Partial<GuardOptions>][] = [
    ["inside a frame", half, {}],
    ["buffered unary", dataFrame([1]), { onAbort: "error" }],
  ];
  for (const [name, first, overrides] of cases) {
    const hold = new ReadableStream<Uint8Array>({
      start(controller) {
        controller.enqueue(first);
      },
    });
    const { options: guard, controller, events } = options(overrides);
    const reader = guardResponse(hold, guard).getReader();
    await reader.read();
    const pending = reader.read();
    controller.abort(deadlineError);
    await assert.rejects(pending, () => true, name);
    assert.deepEqual(events, ["finish:error"], name);
  }
});

test("an abort after the trailer frame still completes cleanly", async () => {
  const hold = new ReadableStream<Uint8Array>({
    start(controller) {
      controller.enqueue(okTrailer);
    },
  });
  const { options: guard, controller, events } = options();
  const reader = guardResponse(hold, guard).getReader();
  assert.deepEqual((await reader.read()).value, okTrailer);
  const pending = reader.read();
  controller.abort(deadlineError);
  assert.equal((await pending).done, true);
  assert.deepEqual(events, ["finish:complete"]);
});

test("the consumer going away cancels the source and reports a client cancel", async () => {
  const { stream, state } = sourceOf([dataFrame([1]), dataFrame([2]), okTrailer]);
  const { options: guard, events } = options();
  const reader = guardResponse(stream, guard).getReader();
  await reader.read();
  await reader.cancel(canceledError);
  assert.equal(state.canceled, true);
  assert.deepEqual(events, ["client-cancel", "finish:canceled"]);
});

test("the guard reads from the source only as fast as the consumer reads", async () => {
  const { stream, state } = sourceOf([
    dataFrame([1]),
    dataFrame([2]),
    dataFrame([3]),
    dataFrame([4]),
    okTrailer,
  ]);
  const reader = guardResponse(stream, options().options).getReader();
  await reader.read();
  await new Promise((resolve) => setTimeout(resolve, 20));
  assert.ok(state.pulls <= 2, `source pulled ${state.pulls} times for one read`);
  await reader.cancel();
});

test("the status trailer carries the message as an escaped key", () => {
  assert.equal(
    new TextDecoder().decode(trailerFrame(14, "dependency unavailable").subarray(5)),
    "grpc-status: 14\r\ngrpc-message: dependency%20unavailable\r\n",
  );
});

function chattySource(count: number) {
  const frame = dataFrame([1, 2, 3, 4]);
  let sent = 0;
  return new ReadableStream<Uint8Array>(
    {
      pull(controller) {
        if (sent < count) {
          sent++;
          controller.enqueue(frame);
        } else {
          controller.enqueue(okTrailer);
          controller.close();
        }
      },
    },
    { highWaterMark: 0 },
  );
}

test("one abort listener serves the whole stream however many frames it carries", async () => {
  const controller = new AbortController();
  const signal = controller.signal;
  let added = 0;
  let removed = 0;
  const add = signal.addEventListener.bind(signal);
  const remove = signal.removeEventListener.bind(signal);
  signal.addEventListener = ((...args: Parameters<typeof add>) => {
    added++;
    return add(...args);
  }) as typeof signal.addEventListener;
  signal.removeEventListener = ((...args: Parameters<typeof remove>) => {
    removed++;
    return remove(...args);
  }) as typeof signal.removeEventListener;
  const { options: guard } = options({ signal });
  const reader = guardResponse(chattySource(5000), guard).getReader();
  for (;;) if ((await reader.read()).done) break;
  assert.equal(added, 1, "a listener per read would grow with the stream");
  assert.equal(removed, 1, "the listener is released when the stream ends");
});

test("reading many frames retains no memory per read", async () => {
  // A stream may live five minutes and carry thousands of small frames a second in a 128 MB isolate.
  setFlagsFromString("--expose-gc");
  const collect = runInNewContext("gc") as () => void;
  const reads = 200_000;
  const settle = () => {
    collect();
    collect();
    return process.memoryUsage().heapUsed;
  };
  const reader = guardResponse(chattySource(reads), options().options).getReader();
  for (let i = 0; i < 1000; i++) await reader.read();
  const before = settle();
  for (let i = 0; i < reads - 2000; i++) await reader.read();
  const after = settle();
  await reader.cancel();
  const grown = after - before;
  // About 312 bytes per read were retained by a long-lived race promise: tens of MB over this many reads.
  assert.ok(
    grown < 8 * 1024 * 1024,
    `heap grew by ${Math.round(grown / 1024)} KiB over ${reads} reads`,
  );
});
