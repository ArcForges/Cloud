// SPDX-License-Identifier: AGPL-3.0-only
// Queue consumer for job wake hints. A message carries only identifiers: D1 stays the business
// authority and a duplicate, late or lost delivery can never change business truth because the
// commit itself is guarded by lease, fence and inbox rows (contracts 05 and D1 profile section 5).
import { isCorrelationId } from "../ingress/correlation.ts";
import type { CoordinatorLike, CoordinatorNamespaceLike, QueueLike, WakeMessage } from "./types.ts";

export interface MessageLike {
  readonly body: unknown;
  readonly attempts: number;
  ack(): void;
  retry(options?: { delaySeconds?: number }): void;
}

export const maxSliceItems = 100;
export const maxSliceMilliseconds = 20_000;
const uuid = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/u;
const scopePattern = /^proof\/[A-Za-z0-9._/-]{1,200}$/u;

const legacyKeys = "eventId,jobId,kind,scope,v";
const correlatedKeys = "causationId,correlationId,eventId,jobId,kind,scope,v";

/**
 * Parses the closed key set of a job wake. A wake carries its correlation identity and its causation id (CLOUD.69); a
 * message queued by an earlier revision (the legacy key set, no correlation) is still accepted and takes its own event
 * id as correlation and causation, so a deploy never turns queued wakes into poison. Nothing else is accepted:
 * the keys are closed and every identifier is a canonical lowercase UUID, so no free text can reach a log or a header.
 */
export function parseWake(body: unknown): WakeMessage | null {
  if (typeof body !== "object" || body === null || Array.isArray(body)) return null;
  const record = body as Record<string, unknown>;
  const keys = Object.keys(record).sort().join(",");
  if (keys !== legacyKeys && keys !== correlatedKeys) return null;
  if (record.v !== 1 || record.kind !== "job.wake") return null;
  if (typeof record.jobId !== "string" || !uuid.test(record.jobId)) return null;
  if (typeof record.eventId !== "string" || !uuid.test(record.eventId)) return null;
  if (typeof record.scope !== "string" || !scopePattern.test(record.scope)) return null;
  let correlationId: string;
  let causationId: string;
  if (keys === correlatedKeys) {
    if (!isCorrelationId(record.correlationId) || !isCorrelationId(record.causationId)) return null;
    correlationId = record.correlationId;
    causationId = record.causationId;
  } else {
    // Deterministic, so every redelivery of the same legacy message carries the same identity.
    correlationId = record.eventId;
    causationId = record.eventId;
  }
  return {
    v: 1,
    kind: "job.wake",
    jobId: record.jobId,
    scope: record.scope,
    eventId: record.eventId,
    correlationId,
    causationId,
  };
}

export interface SliceReply {
  state: "running" | "complete" | "duplicate" | "busy" | "stale";
  jobComplete: boolean;
}
export function parseSliceReply(bytes: Uint8Array): SliceReply | null {
  try {
    const value = JSON.parse(new TextDecoder().decode(bytes)) as Record<string, unknown>;
    const states = ["running", "complete", "duplicate", "busy", "stale"];
    if (typeof value.state !== "string" || !states.includes(value.state)) return null;
    if (typeof value.jobComplete !== "boolean") return null;
    return { state: value.state as SliceReply["state"], jobComplete: value.jobComplete };
  } catch {
    return null;
  }
}

export interface ConsumerDeps {
  coordinators: CoordinatorNamespaceLike;
  queue: QueueLike;
  callSlice(wake: WakeMessage): Promise<{ status: number; body: Uint8Array }>;
  newEventId(): string;
}

export type Disposition = "dropped" | "duplicate" | "busy" | "continued" | "complete" | "retry";

/** Seconds of backoff for the nth delivery attempt, capped at one minute. */
export const backoffSeconds = (attempts: number) => Math.min(60, 2 ** Math.max(0, attempts));

export async function processWake(message: MessageLike, deps: ConsumerDeps): Promise<Disposition> {
  const wake = parseWake(message.body);
  if (!wake) {
    // A malformed message is poison: retrying cannot make it valid.
    message.ack();
    return "dropped";
  }
  const coordinator: CoordinatorLike = deps.coordinators.getByName(wake.jobId);
  let admitted: Awaited<ReturnType<CoordinatorLike["admit"]>>;
  try {
    admitted = await coordinator.admit(wake.eventId);
  } catch {
    message.retry({ delaySeconds: backoffSeconds(message.attempts) });
    return "retry";
  }
  if (!admitted.admit) {
    if (admitted.reason === "duplicate") {
      message.ack();
      return "duplicate";
    }
    message.retry({ delaySeconds: 5 });
    return "busy";
  }
  const fail = async (): Promise<Disposition> => {
    await coordinator.release(wake.eventId).catch(() => {});
    message.retry({ delaySeconds: backoffSeconds(message.attempts) });
    return "retry";
  };
  let reply: SliceReply | null;
  try {
    const response = await deps.callSlice(wake);
    reply = response.status === 200 ? parseSliceReply(response.body) : null;
  } catch {
    return fail();
  }
  if (!reply) return fail();
  if (reply.state === "busy" || reply.state === "stale") {
    // Another holder owns the lease or won a race: leave the effect to it and look again shortly.
    await coordinator.release(wake.eventId).catch(() => {});
    message.retry({ delaySeconds: reply.state === "busy" ? 10 : 1 });
    return "busy";
  }
  if (!reply.jobComplete) {
    try {
      // The continuation keeps the correlation of the chain and is caused by the wake event that just ran (CR-01, CR-02).
      await deps.queue.send({ ...wake, eventId: deps.newEventId(), causationId: wake.eventId });
    } catch {
      // The slice (or its duplicate) is committed, but the continuation is not queued: retry the
      // message so the continuation is attempted again. The duplicate reply is harmless.
      return fail();
    }
  }
  await coordinator.complete(wake.eventId).catch(() => {});
  message.ack();
  return reply.jobComplete ? "complete" : "continued";
}
