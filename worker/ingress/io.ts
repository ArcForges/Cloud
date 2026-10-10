// SPDX-License-Identifier: AGPL-3.0-only
import { grpcFrameHeaderBytes } from "../tables/cloud-tables.generated.ts";
import { bodySizeError } from "./errors.ts";

// Enforce the budget even if a binding does not observe Request.signal.
export async function bounded<T>(operation: Promise<T>, signal: AbortSignal): Promise<T> {
  if (signal.aborted) {
    void operation.catch(() => {});
    throw signal.reason;
  }
  let aborted: (() => void) | undefined;
  const interrupted = new Promise<never>((_resolve, rejectPromise) => {
    aborted = () => rejectPromise(signal.reason);
    signal.addEventListener("abort", aborted, { once: true });
  });
  try {
    return await Promise.race([operation, interrupted]);
  } finally {
    if (aborted) signal.removeEventListener("abort", aborted);
  }
}

export async function readBytes(
  stream: ReadableStream<Uint8Array> | null,
  limit: number,
  signal: AbortSignal,
): Promise<Uint8Array<ArrayBuffer>> {
  signal.throwIfAborted();
  if (!stream) return new Uint8Array();
  const reader = stream.getReader();
  const chunks: Uint8Array[] = [];
  let length = 0;
  try {
    while (true) {
      const { done, value } = await bounded(reader.read(), signal);
      if (done) break;
      length += value.byteLength;
      if (length > limit) throw bodySizeError;
      chunks.push(value);
    }
  } catch (error) {
    // Cancellation itself must not hold up an expired request.
    void reader.cancel().catch(() => {});
    throw error;
  } finally {
    reader.releaseLock();
  }
  const result = new Uint8Array(length);
  let offset = 0;
  for (const chunk of chunks) {
    result.set(chunk, offset);
    offset += chunk.length;
  }
  return result;
}

/** A trailers-only gRPC-Web status response (HTTP 200): the form binary clients read the error from. */
export function rpcError(code: number, message: string): Response {
  const trailer = new TextEncoder().encode(
    `grpc-status: ${code}\r\ngrpc-message: ${encodeURIComponent(message)}\r\n`,
  );
  const frame = new Uint8Array(grpcFrameHeaderBytes + trailer.length);
  frame[0] = 0x80;
  new DataView(frame.buffer).setUint32(1, trailer.length);
  frame.set(trailer, grpcFrameHeaderBytes);
  return new Response(frame, {
    headers: { "content-type": "application/grpc-web+proto", "cache-control": "no-store" },
  });
}

/** A plain HTTP refusal for requests that are not valid gRPC-Web at all. */
export function reject(status: number, message: string): Response {
  return new Response(message, {
    status,
    headers: { "content-type": "text/plain; charset=utf-8", "cache-control": "no-store" },
  });
}

/** The trailer frame bytes for a status, as the host writes them. */
export function trailerFrame(code: number, message?: string): Uint8Array<ArrayBuffer> {
  const text =
    `grpc-status: ${code}\r\n` +
    (message === undefined ? "" : `grpc-message: ${encodeURIComponent(message)}\r\n`);
  const payload = new TextEncoder().encode(text);
  const frame = new Uint8Array(grpcFrameHeaderBytes + payload.length);
  frame[0] = 0x80;
  new DataView(frame.buffer).setUint32(1, payload.length);
  frame.set(payload, grpcFrameHeaderBytes);
  return frame;
}
