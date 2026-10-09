// SPDX-License-Identifier: AGPL-3.0-only
// The harness.internal outbound handler (HAR.40 alarm arming). The C# executor asks for one wake through a closed JSON request to this
// virtual host: a POST to the schedule path with {runId, wakeAtMs, workspaceId}, or a POST to the cancel path with the run key
// {runId, workspaceId}. This handler validates that closed shape and calls the run's Durable Object, and nothing else. It never decides
// whether a run advances (architecture 05): the Worker performs only the external invocation that the C# loop instructs.
// It is registered on the proof Container class only (worker/index.ts); the production class keeps ai.internal alone.
import {
  alarmHost,
  cancelAlarmPath,
  parseRunRef,
  parseSchedule,
  runKey,
  scheduleAlarmPath,
} from "../run-alarm-core.ts";

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
