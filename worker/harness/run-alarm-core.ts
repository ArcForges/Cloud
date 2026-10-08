// SPDX-License-Identifier: AGPL-3.0-only
// The pure part of the run alarm: the wake handle it may hold, the signed wake body and the bounded retry schedule. It runs in plain
// Node so it can be tested without workerd; the Durable Object class in run-alarm.ts only stores this handle and calls the C# endpoint.
import { sha256Hex } from "../private/encoding.ts";

export const wakePath = "/internal/harness/v1/wake";
export const harnessContainerName = "harness";

/** The wake handle: the only state the alarm holds. It names a run and a time; it never holds run state. */
export interface WakeHandle {
  readonly workspaceId: string;
  readonly runId: string;
  readonly wakeAtMs: number;
  readonly attempts: number;
}

/** Bounded retries of a failed wake, with the 1, 2 and 4 second backoff of contracts 05 section 2, then the wake is dropped. */
export const maxWakeAttempts = 4;

const canonicalUuid = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/u;
const maxAlarmMs = 365 * 24 * 60 * 60 * 1000;

/** Parses the schedule request. Anything outside the closed key set and its exact types is refused. */
export function parseSchedule(
  body: unknown,
  nowMs: number,
): { ok: true; handle: WakeHandle } | { ok: false } {
  if (typeof body !== "object" || body === null || Array.isArray(body)) return { ok: false };
  const record = body as Record<string, unknown>;
  const keys = Object.keys(record).sort().join(",");
  if (keys !== "runId,wakeAtMs,workspaceId") return { ok: false };
  const { runId, wakeAtMs, workspaceId } = record;
  if (typeof runId !== "string" || !canonicalUuid.test(runId)) return { ok: false };
  if (typeof workspaceId !== "string" || !canonicalUuid.test(workspaceId)) return { ok: false };
  if (typeof wakeAtMs !== "number" || !Number.isSafeInteger(wakeAtMs)) return { ok: false };
  // A wake is never scheduled further out than the 365-day ceiling of an alarm, nor before the present.
  if (wakeAtMs < nowMs || wakeAtMs - nowMs > maxAlarmMs) return { ok: false };
  return { ok: true, handle: { workspaceId, runId, wakeAtMs, attempts: 0 } };
}

/**
 * The Cloudflare Worker version identifier, as the Worker reports it (version metadata). It is a bounded token and is kept apart from the
 * Cloud build identity, which the C# side supplies itself (HAR.40 validation (g)).
 */
const workerVersionPattern = /^[A-Za-z0-9._:-]{1,128}$/u;
export function isWorkerVersion(value: unknown): value is string {
  return typeof value === "string" && workerVersionPattern.test(value);
}

/**
 * The signed body of one wake. It carries identifiers, a time and the Worker version identifier, and nothing else; the C# endpoint
 * decides everything else. The caller must supply a valid Worker version; the body is never built without one.
 */
export function wakeBody(handle: WakeHandle, workerVersion: string): Uint8Array {
  if (!isWorkerVersion(workerVersion))
    throw new Error("A wake needs a bounded Worker version identifier.");
  return new TextEncoder().encode(
    JSON.stringify({
      v: 1,
      kind: "harness.wake",
      workspaceId: handle.workspaceId,
      runId: handle.runId,
      wakeAtMs: handle.wakeAtMs,
      workerVersion,
    }),
  );
}

/** Hex SHA-256 of the wake body, carried in the signed request. */
export function wakeBodySha256Hex(body: Uint8Array): Promise<string> {
  return sha256Hex(body);
}

export type RetryPlan =
  | { readonly kind: "retry"; readonly handle: WakeHandle; readonly atMs: number }
  | { readonly kind: "drop" };

/** What follows a failed wake: retry after the next backoff step, or drop the wake (the C# side reconciles on its own schedule). */
export function afterFailure(handle: WakeHandle, nowMs: number): RetryPlan {
  const attempts = handle.attempts + 1;
  if (attempts >= maxWakeAttempts) return { kind: "drop" };
  const seconds = attempts === 1 ? 1 : attempts === 2 ? 2 : 4;
  return { kind: "retry", handle: { ...handle, attempts }, atMs: nowMs + seconds * 1000 };
}

/** Reads a stored handle back, refusing any stored value that does not have the exact shape it was written with. */
export function readHandle(value: unknown): WakeHandle | null {
  if (typeof value !== "object" || value === null) return null;
  const record = value as Record<string, unknown>;
  const { workspaceId, runId, wakeAtMs, attempts } = record;
  if (typeof workspaceId !== "string" || !canonicalUuid.test(workspaceId)) return null;
  if (typeof runId !== "string" || !canonicalUuid.test(runId)) return null;
  if (typeof wakeAtMs !== "number" || !Number.isSafeInteger(wakeAtMs)) return null;
  if (
    typeof attempts !== "number" ||
    !Number.isSafeInteger(attempts) ||
    attempts < 0 ||
    attempts >= maxWakeAttempts
  )
    return null;
  return { workspaceId, runId, wakeAtMs, attempts };
}
