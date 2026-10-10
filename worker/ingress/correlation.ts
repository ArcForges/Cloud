// SPDX-License-Identifier: AGPL-3.0-only
// The Worker side of the correlation seam (CLOUD.69; Design CR-01, CR-03, CR-06, HP-06). One correlation identity per call: a client's
// RequestMeta.correlationId is accepted only when it matches the identity guard (a canonical, nonzero, lowercase UUID; wire registry 04:
// Id is exactly 16 nonzero bytes), an absent one is created here, and a malformed one is refused by the caller of this module. The
// identity never takes part in authorization.
//
// The guards (the identifier shape, the field numbers that carry it and the traceparent form) are declared in C# and generated into
// worker/tables/cloud-tables.generated.ts (CLOUD.84 S34(3)). This module applies them and forwards; it decides nothing of its own.
//
// The identity reaches the host as the trace id of one W3C traceparent the Worker builds itself (a UUID is exactly 128 bits), so the
// Worker, the host and a wake message are joined by the identifier alone and no new header, field or contract meaning exists. Nothing a
// client sends is ever copied into a header: every value here is produced from 16 validated bytes or from the platform's random source.
import {
  correlationGuard,
  grpcFrameHeaderBytes,
  spanIdByteLength,
} from "../tables/cloud-tables.generated.ts";

const uuidPattern = new RegExp(correlationGuard.uuidPattern, "u");
const nilUuid = correlationGuard.nilUuid;
const requestMetaField = correlationGuard.requestMetaField;
const correlationIdField = correlationGuard.correlationIdField;
const idValueField = correlationGuard.idValueField;
const idByteLength = correlationGuard.idByteLength;

/** A canonical lowercase UUID that is not the nil UUID: the only accepted spelling of a correlation or causation id. */
export function isCorrelationId(value: unknown): value is string {
  return typeof value === "string" && uuidPattern.test(value) && value !== nilUuid;
}

/** A fresh correlation identity (a random version 4 UUID, never nil). */
export function newCorrelationId(): string {
  return crypto.randomUUID();
}

/** Sixteen lowercase hex characters, never all zero: the span id of one hop. */
export function newSpanId(): string {
  const bytes = new Uint8Array(spanIdByteLength);
  do crypto.getRandomValues(bytes);
  while (bytes.every((byte) => byte === 0));
  return Array.from(bytes, (byte) => byte.toString(16).padStart(2, "0")).join("");
}

/** The W3C traceparent of a call: the correlation id is the trace id, the Worker's span is the parent of the host's. */
export function traceparentFor(correlationId: string, spanId: string = newSpanId()): string {
  if (!isCorrelationId(correlationId)) throw new TypeError("Invalid correlation id.");
  return `${correlationGuard.traceparentVersion}-${correlationId.replaceAll("-", "")}-${spanId}-${correlationGuard.traceparentFlags}`;
}

export type RequestCorrelation =
  | { readonly kind: "valid"; readonly id: string }
  /** The envelope carries no correlation id (or no RequestMeta at all). */
  | { readonly kind: "absent" }
  /** The envelope carries a correlation id that is repeated, not 16 bytes, all zero or not an Id message. */
  | { readonly kind: "malformed" }
  /** The envelope itself cannot be read as protobuf; the host decides what that means for the method. */
  | { readonly kind: "unreadable" };

class Reader {
  position = 0;
  readonly data: Uint8Array;

  constructor(data: Uint8Array) {
    this.data = data;
  }

  get done(): boolean {
    return this.position >= this.data.length;
  }

  varint(): number | null {
    let value = 0;
    for (let index = 0; index < 10; index++) {
      const byte = this.data[this.position++];
      if (byte === undefined) return null;
      // Past 2^53 a length or tag is unusable anyway; the exact value of a skipped varint is irrelevant.
      value += (byte & 0x7f) * 2 ** (7 * index);
      if ((byte & 0x80) === 0) return index === 9 && byte > 1 ? null : value;
    }
    return null;
  }

  tag(): { field: number; wire: number } | null {
    const tag = this.varint();
    if (tag === null) return null;
    const field = Math.floor(tag / 8);
    return field === 0 || field > 2_147_483_647 ? null : { field, wire: tag % 8 };
  }

  lengthDelimited(): Uint8Array | null {
    const length = this.varint();
    if (length === null || length > this.data.length - this.position) return null;
    const slice = this.data.subarray(this.position, this.position + length);
    this.position += length;
    return slice;
  }

  skip(wire: number): boolean {
    switch (wire) {
      case 0:
        return this.varint() !== null;
      case 1:
        return this.advance(8);
      case 2:
        return this.lengthDelimited() !== null;
      case 5:
        return this.advance(4);
      default:
        return false;
    }
  }

  private advance(count: number): boolean {
    if (this.data.length - this.position < count) return false;
    this.position += count;
    return true;
  }
}

function formatId(bytes: Uint8Array): string {
  const hex = Array.from(bytes, (byte) => byte.toString(16).padStart(2, "0")).join("");
  return `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20)}`;
}

/** An Id message: exactly one field 1 of exactly 16 bytes, not all zero; anything else is null. */
function readId(message: Uint8Array): string | null {
  const reader = new Reader(message);
  let value: Uint8Array | null = null;
  while (!reader.done) {
    const tag = reader.tag();
    if (!tag) return null;
    if (tag.field === idValueField) {
      if (tag.wire !== 2 || value !== null) return null;
      value = reader.lengthDelimited();
      if (value === null) return null;
    } else if (!reader.skip(tag.wire)) {
      return null;
    }
  }
  if (value?.length !== idByteLength || value.every((byte) => byte === 0)) return null;
  return formatId(value);
}

/**
 * Reads RequestMeta.correlationId (RequestMeta is field 1 of every generated request message, correlationId is its
 * field 3) from one protobuf message without a per-method type. Strict like the host's reader: a repeated meta or
 * correlation field, a group, a truncated field or a wrong wire type is not read as a value.
 */
export function readRequestCorrelation(message: Uint8Array): RequestCorrelation {
  const outer = new Reader(message);
  let meta: Uint8Array | null = null;
  while (!outer.done) {
    const tag = outer.tag();
    if (!tag) return { kind: "unreadable" };
    if (tag.field === requestMetaField) {
      if (tag.wire !== 2 || meta !== null) return { kind: "unreadable" };
      meta = outer.lengthDelimited();
      if (meta === null) return { kind: "unreadable" };
    } else if (!outer.skip(tag.wire)) {
      return { kind: "unreadable" };
    }
  }
  if (meta === null) return { kind: "absent" };
  const inner = new Reader(meta);
  let found: string | null = null;
  let seen = false;
  let readable = true;
  let malformed = false;
  while (!inner.done) {
    const tag = inner.tag();
    if (!tag) {
      readable = false;
      break;
    }
    if (tag.field === correlationIdField) {
      if (tag.wire !== 2) {
        malformed = true;
        if (!inner.skip(tag.wire)) {
          readable = false;
          break;
        }
        continue;
      }
      const id = inner.lengthDelimited();
      if (id === null) {
        readable = false;
        break;
      }
      if (seen) malformed = true;
      seen = true;
      found = readId(id);
      if (found === null) malformed = true;
    } else if (!inner.skip(tag.wire)) {
      readable = false;
      break;
    }
  }
  // A correlation value that is itself wrong is a refusal even when the rest of the meta is unreadable: the identifier is
  // what the edge validates, and the host refuses the rest of the envelope on its own.
  if (malformed) return { kind: "malformed" };
  if (!readable) return { kind: "unreadable" };
  return found === null ? { kind: "absent" } : { kind: "valid", id: found };
}

/** The one message of a unary or server-streaming gRPC-Web request body, or null for any other framing. */
export function singleMessage(body: Uint8Array): Uint8Array | null {
  if (body.length < grpcFrameHeaderBytes || body[0] !== 0) return null;
  const length = new DataView(body.buffer, body.byteOffset, body.byteLength).getUint32(1);
  return length === body.length - grpcFrameHeaderBytes ? body.subarray(grpcFrameHeaderBytes) : null;
}
