// SPDX-License-Identifier: AGPL-3.0-only
// The pure part of the run alarm: the wake handle it may hold, the signed wake body and the bounded retry schedule. It runs in plain
// Node so it can be tested without workerd; the Durable Object class in run-alarm.ts only stores this handle and calls the C# endpoint.
import { sha256Hex } from "../private/encoding.ts";

export const wakePath = "/internal/harness/v1/wake";
export const harnessContainerName = "harness";

/**
 * The outbound virtual host of the C# alarm client (HAR.40 alarm arming). The proof container class alone registers it, with exactly one
 * schedule path and one cancel path. Nothing else is reachable through it.
 */
export const alarmHost = "harness.internal";
export const scheduleAlarmPath = "/v1/schedule";
export const cancelAlarmPath = "/v1/cancel";

/** The wake handle: the only state the alarm holds. It names a run and a time; it never holds run state. */
export interface WakeHandle {
  readonly workspaceId: string;
  readonly runId: string;
  readonly wakeAtMs: number;
  readonly attempts: number;
}

/** The C# lease term (LeasePolicy.TermMicros, 60 seconds). A wake refused by a live lease must keep retrying until that lease has expired. */
export const leaseTermSeconds = 60;

/**
 * The backoff between the failed deliveries of one wake, in seconds. The steps double from 1 second and their sum is 63 seconds, which is
 * more than the lease term: a holder that crashed while its lease was live leaves a lease that expires no later than one term after the
 * refusal that the first retry saw, so a retry lands after expiry and the wake claims the run instead of being dropped (HAR.40 (b)).
 */
export const wakeBackoffSeconds: readonly number[] = [1, 2, 4, 8, 16, 32];

/** Bounded deliveries of one wake: the first delivery and one more per backoff step; the wake is dropped after the last failure. */
export const maxWakeAttempts = wakeBackoffSeconds.length + 1;

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
  const seconds = wakeBackoffSeconds[attempts - 1];
  if (seconds === undefined) return { kind: "drop" };
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

/**
 * The run key that names one run's alarm: the workspace and the run identifiers, the same pair the wake carries. The Worker addresses the
 * Durable Object with it and never with a free-form name.
 */
export function runKey(workspaceId: string, runId: string): string {
  return `${workspaceId}/${runId}`;
}

/** A run named by its run key fields. */
export interface RunRef {
  readonly workspaceId: string;
  readonly runId: string;
}

/** Parses the cancel body: exactly the run key with canonical identifiers. Anything else, including a schedule time, is refused. */
export function parseRunRef(body: unknown): { ok: true; ref: RunRef } | { ok: false } {
  if (typeof body !== "object" || body === null || Array.isArray(body)) return { ok: false };
  const record = body as Record<string, unknown>;
  const keys = Object.keys(record).sort().join(",");
  if (keys !== "runId,workspaceId") return { ok: false };
  const { runId, workspaceId } = record;
  if (typeof runId !== "string" || !canonicalUuid.test(runId)) return { ok: false };
  if (typeof workspaceId !== "string" || !canonicalUuid.test(workspaceId)) return { ok: false };
  return { ok: true, ref: { workspaceId, runId } };
}

// The harness.internal outbound handler (HAR.40 alarm arming). It validates the closed schedule and cancel shapes of the two routes of one
// virtual host and calls the run's Durable Object, and nothing else. The proof Container class alone registers it (worker/index.ts).
/** The part of a run's alarm stub this handler calls; the Durable Object answers both. */
export interface HarnessAlarmStub {
  schedule(input: unknown): Promise<{ scheduled: boolean }>;
  cancel(): Promise<void>;
}

export interface HarnessAlarmNamespace {
  getByName(name: string): HarnessAlarmStub;
}

export interface HarnessInternalEnv {
  readonly HARNESS_RUN_ALARM?: HarnessAlarmNamespace;
}

/** The largest request body; the schedule body is far below it, and anything longer is refused before it is parsed. */
export const maxHarnessBodyBytes = 1024;

function refusal(status: number, code: string): Response {
  return new Response(JSON.stringify({ error: code }), {
    status,
    headers: { "content-type": "application/json" },
  });
}

function reply(status: number, body: Record<string, unknown>): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "content-type": "application/json" },
  });
}

/** application/json with no parameter other than charset=utf-8. */
function isJsonContentType(value: string | null): boolean {
  if (value === null) return false;
  const [mediaType = "", ...parameters] = value.split(";").map((part) => part.trim());
  if (mediaType.toLowerCase() !== "application/json") return false;
  return parameters.every((parameter) => /^charset=(?:"?utf-8"?)$/iu.test(parameter));
}

/** Reads the whole body up to the limit; null when it is longer (the rest is cancelled, never buffered). */
async function readBounded(
  body: ReadableStream<Uint8Array> | null,
  limit: number,
): Promise<Uint8Array | null> {
  if (body === null) return new Uint8Array(0);
  const reader = body.getReader();
  const chunks: Uint8Array[] = [];
  let total = 0;
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    total += value.byteLength;
    if (total > limit) {
      await reader.cancel().catch(() => undefined);
      return null;
    }
    chunks.push(value);
  }
  const bytes = new Uint8Array(total);
  let offset = 0;
  for (const chunk of chunks) {
    bytes.set(chunk, offset);
    offset += chunk.byteLength;
  }
  return bytes;
}

/**
 * Serves the two closed routes of harness.internal. Every refusal happens before the binding is read or any stub is addressed, so a
 * refused request never reaches a run's alarm. A missing binding is a 503; a stub that fails after the call is a 502.
 */
export async function handleHarnessInternal(
  request: Request,
  env: HarnessInternalEnv,
  nowMs: number = Date.now(),
): Promise<Response> {
  const url = new URL(request.url);
  if (url.hostname !== alarmHost) return refusal(404, "harness.not_found");
  const isSchedule = url.pathname === scheduleAlarmPath;
  if (!isSchedule && url.pathname !== cancelAlarmPath) return refusal(404, "harness.not_found");
  if (request.method !== "POST") return refusal(405, "harness.method_not_allowed");
  if (url.search !== "") return refusal(400, "harness.query_refused");
  if (!isJsonContentType(request.headers.get("content-type")))
    return refusal(415, "harness.content_type");

  const raw = await readBounded(request.body, maxHarnessBodyBytes);
  if (raw === null) return refusal(413, "harness.body_too_large");
  let body: unknown;
  try {
    body = JSON.parse(new TextDecoder("utf-8", { fatal: true, ignoreBOM: false }).decode(raw));
  } catch {
    return refusal(400, "harness.body_invalid");
  }

  if (isSchedule) {
    const admitted = parseSchedule(body, nowMs);
    if (!admitted.ok) return refusal(400, "harness.body_refused");
    const namespace = env.HARNESS_RUN_ALARM;
    if (namespace === undefined) return refusal(503, "harness.binding_missing");
    const stub = namespace.getByName(runKey(admitted.handle.workspaceId, admitted.handle.runId));
    try {
      const result = await stub.schedule(body);
      if (result.scheduled === true) return reply(200, { scheduled: true });
      return refusal(422, "harness.schedule_refused");
    } catch {
      return refusal(502, "harness.upstream_failed");
    }
  }

  const ref = parseRunRef(body);
  if (!ref.ok) return refusal(400, "harness.body_refused");
  const namespace = env.HARNESS_RUN_ALARM;
  if (namespace === undefined) return refusal(503, "harness.binding_missing");
  try {
    await namespace.getByName(runKey(ref.ref.workspaceId, ref.ref.runId)).cancel();
    return reply(200, { cancelled: true });
  } catch {
    return refusal(502, "harness.upstream_failed");
  }
}

/** The outbound registration of the proof class for harness.internal (worker/index.ts). */
export const harnessInternalOutbound = (request: Request, env: unknown): Promise<Response> =>
  handleHarnessInternal(request, env as HarnessInternalEnv);
