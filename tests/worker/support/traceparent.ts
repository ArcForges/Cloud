// SPDX-License-Identifier: AGPL-3.0-only
// A strict reader of a W3C traceparent, for tests only (CLOUD.84 U4). The Worker builds traceparents from the generated identity guard
// and never parses one, so the parser lives here, where the tests check what the Worker forwarded.
const traceparentPattern = /^00-([0-9a-f]{32})-([0-9a-f]{16})-([0-9a-f]{2})$/u;

export interface Traceparent {
  readonly correlationId: string;
  readonly parentSpanId: string;
}

/** A strict W3C traceparent (version 00, nonzero trace and parent ids), or null. */
export function parseTraceparent(value: string | null): Traceparent | null {
  const match = value === null ? null : traceparentPattern.exec(value);
  if (!match) return null;
  const [, traceId = "", parentSpanId = ""] = match;
  if (/^0+$/u.test(traceId) || /^0+$/u.test(parentSpanId)) return null;
  const correlationId = `${traceId.slice(0, 8)}-${traceId.slice(8, 12)}-${traceId.slice(12, 16)}-${traceId.slice(16, 20)}-${traceId.slice(20)}`;
  return { correlationId, parentSpanId };
}
