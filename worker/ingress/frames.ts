// SPDX-License-Identifier: AGPL-3.0-only
// The frame guard: a pass-through of a gRPC-Web response body that never holds more than the chunk in
// flight and never lets a truncated stream look like a success. It follows frame boundaries (a flag byte,
// a big-endian length, the payload) without copying, enforces the frame and response bounds and turns
// the three ways a stream can end without a status into an explicit gRPC status:
//   - the source ends on a frame boundary without a trailer frame: UNAVAILABLE trailer;
//   - the deadline or a cancellation fires on a frame boundary: DEADLINE_EXCEEDED or CANCELED trailer;
//   - anything else (a malformed or oversized frame, a source error, an abort inside a frame) errors the
//     stream, which a client observes as a failed transfer, never as end of data.
import { grpcFrameHeaderBytes } from "../tables/cloud-tables.generated.ts";
import { canceledError, deadlineError, grpcStatus } from "./errors.ts";
import { trailerFrame } from "./io.ts";

export interface GuardOptions {
  /** Aborted by the deadline, by the client going away or by the guard itself. */
  readonly signal: AbortSignal;
  readonly maxFrameBytes: number;
  /** Total response bytes, or unbounded for a server stream. */
  readonly maxResponseBytes?: number;
  /** At most this many data frames (a unary response has exactly one at most). */
  readonly maxDataFrames?: number;
  /** An HTTP response that carries grpc-status in its headers (trailers-only) may have an empty body. */
  readonly statusInHeaders?: boolean;
  /** On abort at a frame boundary: end with a status trailer (a stream) or error the stream (a buffered unary). */
  readonly onAbort: "trailer" | "error";
  /** Called once when the stream has ended, however it ended. */
  readonly onFinish: (outcome: "complete" | "trailer" | "error" | "canceled") => void;
  /** The upstream is released through this; it must cancel the Container request. */
  readonly onClientCancel: (reason: unknown) => void;
}

const dataFlag = 0x00;
const trailerFlag = 0x80;

class FrameViolation extends Error {}

/** The gRPC status an abort reason maps to. */
export function statusForAbort(reason: unknown): { code: number; message: string } {
  if (reason === deadlineError)
    return { code: grpcStatus.deadlineExceeded, message: "dependency.timeout" };
  if (reason === canceledError) return { code: grpcStatus.canceled, message: "execution.canceled" };
  return { code: grpcStatus.unavailable, message: "dependency.unavailable" };
}

export function guardResponse(
  source: ReadableStream<Uint8Array>,
  options: GuardOptions,
): ReadableStream<Uint8Array> {
  const reader = source.getReader();
  const header = new Uint8Array(grpcFrameHeaderBytes);
  let headerBytes = 0;
  let payloadLeft = 0;
  let inTrailer = false;
  let sawTrailer = false;
  let dataFrames = 0;
  let total = 0;
  let finished = false;

  const atBoundary = () => headerBytes === 0 && payloadLeft === 0;

  // One abort listener for the life of the stream. A pending read is interrupted through `interrupt`, which each
  // read installs and clears itself: nothing accumulates on a long-lived promise however many frames are read.
  let interrupt: ((reason: unknown) => void) | null = null;
  const onAbort = () => interrupt?.(options.signal.reason);
  if (!options.signal.aborted) options.signal.addEventListener("abort", onAbort, { once: true });

  function readOrAbort(): Promise<ReadableStreamReadResult<Uint8Array>> {
    if (options.signal.aborted) return Promise.reject(options.signal.reason);
    return new Promise((resolve, reject) => {
      interrupt = reject;
      reader.read().then(
        (result) => {
          interrupt = null;
          resolve(result);
        },
        (error) => {
          interrupt = null;
          reject(error);
        },
      );
    });
  }

  const finish = (outcome: "complete" | "trailer" | "error" | "canceled") => {
    if (finished) return;
    finished = true;
    options.signal.removeEventListener("abort", onAbort);
    options.onFinish(outcome);
  };

  // The frame that just ended; a trailer frame must be the last bytes of the response.
  function frameEnded(rest: number): void {
    headerBytes = 0;
    if (!inTrailer) return;
    sawTrailer = true;
    if (rest > 0) throw new FrameViolation("data after the trailer frame");
  }

  // Advances the frame state over one chunk; throws on any violation.
  function observe(chunk: Uint8Array): void {
    if (sawTrailer) throw new FrameViolation("data after the trailer frame");
    total += chunk.byteLength;
    if (options.maxResponseBytes !== undefined && total > options.maxResponseBytes)
      throw new FrameViolation("response too large");
    let position = 0;
    while (position < chunk.length) {
      if (payloadLeft === 0) {
        // Collecting the five header bytes of the next frame.
        const take = Math.min(5 - headerBytes, chunk.length - position);
        header.set(chunk.subarray(position, position + take), headerBytes);
        headerBytes += take;
        position += take;
        if (headerBytes < 5) continue;
        const flag = header[0];
        const length = new DataView(header.buffer).getUint32(1);
        if (flag !== dataFlag && flag !== trailerFlag)
          throw new FrameViolation("unknown frame flag");
        if (length > options.maxFrameBytes) throw new FrameViolation("frame too large");
        inTrailer = flag === trailerFlag;
        if (!inTrailer && ++dataFrames > (options.maxDataFrames ?? Number.POSITIVE_INFINITY))
          throw new FrameViolation("too many data frames");
        payloadLeft = length;
        if (length === 0) frameEnded(chunk.length - position);
        continue;
      }
      const take = Math.min(payloadLeft, chunk.length - position);
      payloadLeft -= take;
      position += take;
      if (payloadLeft === 0) frameEnded(chunk.length - position);
    }
  }

  return new ReadableStream<Uint8Array>(
    {
      async pull(controller) {
        let result: ReadableStreamReadResult<Uint8Array>;
        try {
          result = await readOrAbort();
        } catch (error) {
          void reader.cancel(error).catch(() => {});
          if (options.signal.aborted && error === options.signal.reason) {
            if (options.onAbort === "trailer" && atBoundary() && !sawTrailer) {
              const status = statusForAbort(error);
              controller.enqueue(trailerFrame(status.code, status.message));
              controller.close();
              finish("trailer");
              return;
            }
            if (sawTrailer && atBoundary()) {
              controller.close();
              finish("complete");
              return;
            }
          }
          controller.error(error);
          finish("error");
          return;
        }
        if (result.done) {
          if (!atBoundary()) {
            controller.error(new FrameViolation("response ended inside a frame"));
            finish("error");
          } else if (sawTrailer || options.statusInHeaders === true) {
            controller.close();
            finish("complete");
          } else {
            // An end of data without a status is a failure, never a success.
            controller.enqueue(trailerFrame(grpcStatus.unavailable, "dependency.unavailable"));
            controller.close();
            finish("trailer");
          }
          return;
        }
        try {
          observe(result.value);
        } catch (error) {
          void reader.cancel(error).catch(() => {});
          controller.error(error);
          finish("error");
          return;
        }
        controller.enqueue(result.value);
      },
      cancel(reason) {
        // The client went away (or the platform dropped the response): stop the Container work now.
        void reader.cancel(reason).catch(() => {});
        options.onClientCancel(reason);
        finish("canceled");
      },
    },
    { highWaterMark: 0 },
  );
}
