// SPDX-License-Identifier: AGPL-3.0-only
// The proof-only queue loss/retry probe. An operator-signed route enqueues a "poison" message that carries
// only a random probe id. The wake consumer records every delivery attempt and always asks for a retry, so
// the platform's own retry limit runs out and delivers the message to the dead-letter queue, where a second
// consumer records the delivery. Nothing here touches D1, the Container or any business state: the
// observation lives in a Durable Object addressed by the probe id and is read back by the operator.
import type { CoordinatorNamespaceLike, PoisonMessage, PoisonObservation } from "./types.ts";
import type { MessageLike } from "./queue.ts";

const uuid = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/u;
export const poisonRetryDelaySeconds = 1;
export const maxRecordedAttempts = 12;

export function poisonName(probeId: string): string {
  return `poison-${probeId}`;
}

export function parsePoison(body: unknown): PoisonMessage | null {
  if (typeof body !== "object" || body === null || Array.isArray(body)) return null;
  const record = body as Record<string, unknown>;
  if (Object.keys(record).sort().join(",") !== "kind,probeId,v") return null;
  if (record.v !== 1 || record.kind !== "proof.poison") return null;
  if (typeof record.probeId !== "string" || !uuid.test(record.probeId)) return null;
  return { v: 1, kind: "proof.poison", probeId: record.probeId };
}

export const emptyObservation = (): PoisonObservation => ({ attempts: [], deadLetter: null });

/** Appends one delivery attempt (bounded) to the observation. */
export function withAttempt(
  state: PoisonObservation,
  attempt: number,
  atMs: number,
): PoisonObservation {
  return {
    attempts: [...state.attempts, { attempt, atMs }].slice(-maxRecordedAttempts),
    deadLetter: state.deadLetter,
  };
}

/** Records the first dead-letter delivery; a repeated delivery changes nothing. */
export function withDeadLetter(
  state: PoisonObservation,
  attempt: number,
  atMs: number,
): PoisonObservation {
  return state.deadLetter ? state : { attempts: state.attempts, deadLetter: { attempt, atMs } };
}

export interface PoisonDeps {
  coordinators: CoordinatorNamespaceLike;
}

/** The wake-queue consumer's handling of a poison message: record the attempt and always retry. */
export async function processPoison(
  message: MessageLike,
  deps: PoisonDeps,
): Promise<"retry" | "dropped"> {
  const poison = parsePoison(message.body);
  if (!poison) {
    message.ack();
    return "dropped";
  }
  try {
    await deps.coordinators
      .getByName(poisonName(poison.probeId))
      .recordPoisonAttempt(message.attempts);
  } catch {
    // A failed observation write must not stop the retry cycle that is being observed.
  }
  message.retry({ delaySeconds: poisonRetryDelaySeconds });
  return "retry";
}

/** The dead-letter consumer: record the delivery of a poison message, drop everything else. */
export async function processDeadLetter(
  message: MessageLike,
  deps: PoisonDeps,
): Promise<"recorded" | "dropped" | "retry"> {
  const poison = parsePoison(message.body);
  if (!poison) {
    message.ack();
    return "dropped";
  }
  try {
    await deps.coordinators
      .getByName(poisonName(poison.probeId))
      .recordDeadLetter(message.attempts);
  } catch {
    message.retry({ delaySeconds: poisonRetryDelaySeconds });
    return "retry";
  }
  message.ack();
  return "recorded";
}
