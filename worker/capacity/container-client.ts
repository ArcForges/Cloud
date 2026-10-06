// SPDX-License-Identifier: AGPL-3.0-only
import { sha256Hex } from "../private/encoding.ts";
import { loadKeys, type PrivateKeyEnv } from "../private/hmac-settings.ts";
import { newNonce, sign } from "../private/signing.ts";
import type { ContainerNamespaceLike } from "../foundation/types.ts";
import { validWake, type CapacityReply, type CapacityWake } from "./pacer.ts";

export const capacityRecoveryPath = "/internal/capacity/v1/recover";
export const capacityWakePath = "/internal/capacity/v1/wake";
export interface CapacityClientEnv extends PrivateKeyEnv {
  CLOUD_CONTAINER: ContainerNamespaceLike;
  CAPACITY_CONTAINER_NAME?: string;
}

/** Actual private Worker-to-Container transport. A timeout has an unknown business outcome; the
 * pacer retains the same immutable IDs and the next dispatch must reconcile durable D1 receipts. */
export async function callCapacity(
  env: CapacityClientEnv,
  wake: CapacityWake,
  now: () => number = Date.now,
): Promise<CapacityReply> {
  if (!validWake(wake)) throw new Error("Invalid capacity wake");
  const parsed = await callPrivate(env, capacityWakePath, wake, wake.wakeId, now, 25_000);
  if (!parsed || typeof parsed !== "object") throw new Error("Invalid capacity reply");
  const reply = parsed as CapacityReply & { fence?: string | null };
  if (
    Object.keys(reply).some((key) => !["status", "availableAtMicros", "fence"].includes(key)) ||
    !["Complete", "Reschedule", "Busy", "Refused", "Unavailable", "UnknownOutcome"].includes(
      reply.status,
    ) ||
    (reply.availableAtMicros !== undefined &&
      reply.availableAtMicros !== null &&
      (typeof reply.availableAtMicros !== "string" ||
        !/^(0|[1-9][0-9]{0,18})$/u.test(reply.availableAtMicros))) ||
    (reply.fence !== undefined &&
      reply.fence !== null &&
      (typeof reply.fence !== "string" || !/^(0|[1-9][0-9]{0,18})$/u.test(reply.fence)))
  )
    throw new Error("Invalid capacity reply");
  return reply;
}

export interface CapacityRecoveryCursor {
  dueAtMicros: string;
  jobId: string;
}
export interface CapacityRecoveryReply {
  status:
    | "Succeeded"
    | "Denied"
    | "Invalid"
    | "Conflict"
    | "StaleGeneration"
    | "Unavailable"
    | "UnknownOutcome";
  nextDueAtMicros: string | null;
  nextJobId: string | null;
}
const nonNilUuid = (value: unknown): value is string =>
  typeof value === "string" &&
  /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/u.test(value) &&
  value !== "00000000-0000-0000-0000-000000000000";
export const validRecoveryCursor = (value: CapacityRecoveryCursor) =>
  /^(0|[1-9][0-9]{0,18})$/u.test(value.dueAtMicros) &&
  BigInt(value.dueAtMicros) <= 9223372036854775807n &&
  nonNilUuid(value.jobId);
export async function callCapacityRecovery(
  env: CapacityClientEnv,
  requestId: string,
  cursor: CapacityRecoveryCursor | null,
  budgetMs: number,
  now: () => number = Date.now,
): Promise<CapacityRecoveryReply> {
  if (
    !nonNilUuid(requestId) ||
    (cursor !== null && !validRecoveryCursor(cursor)) ||
    !Number.isSafeInteger(budgetMs) ||
    budgetMs < 1 ||
    budgetMs > 25_000
  )
    throw new Error("Invalid capacity recovery");
  const parsed = await callPrivate(
    env,
    capacityRecoveryPath,
    { requestId, afterDueAtMicros: cursor?.dueAtMicros ?? null, afterJobId: cursor?.jobId ?? null },
    requestId,
    now,
    budgetMs,
  );
  if (!parsed || typeof parsed !== "object") throw new Error("Invalid recovery reply");
  const reply = parsed as CapacityRecoveryReply;
  if (
    Object.keys(reply).sort().join(",") !== "nextDueAtMicros,nextJobId,status" ||
    ![
      "Succeeded",
      "Denied",
      "Invalid",
      "Conflict",
      "StaleGeneration",
      "Unavailable",
      "UnknownOutcome",
    ].includes(reply.status) ||
    (reply.nextDueAtMicros === null) !== (reply.nextJobId === null) ||
    (reply.nextDueAtMicros !== null &&
      !validRecoveryCursor({
        dueAtMicros: reply.nextDueAtMicros,
        jobId: reply.nextJobId as string,
      })) ||
    (reply.status !== "Succeeded" && reply.nextDueAtMicros !== null)
  )
    throw new Error("Invalid recovery reply");
  return reply;
}

async function callPrivate(
  env: CapacityClientEnv,
  path: typeof capacityWakePath | typeof capacityRecoveryPath,
  payload: unknown,
  requestId: string,
  now: () => number,
  budgetMs: number,
): Promise<unknown> {
  const keys = loadKeys(env, "W2C");
  if (
    !keys ||
    !env.CAPACITY_CONTAINER_NAME ||
    !/^[A-Za-z0-9._-]{1,64}$/u.test(env.CAPACITY_CONTAINER_NAME)
  )
    throw new Error("Capacity transport unavailable");
  const body = new TextEncoder().encode(JSON.stringify(payload));
  const headers = await sign(
    {
      method: "POST",
      pathAndQuery: path,
      bodySha256Hex: await sha256Hex(body),
      requestId,
      time: String(Math.floor(now() / 1000)),
      nonce: newNonce(),
    },
    keys.current,
  );
  const abort = new AbortController();
  const deadline = now() + budgetMs;
  let rejectTimeout: (reason: Error) => void = () => {};
  const timeout = new Promise<never>((_, reject) => {
    rejectTimeout = reject;
  });
  const timer = setTimeout(() => {
    abort.abort();
    rejectTimeout(new Error("Capacity dispatch deadline"));
  }, budgetMs);
  let response: Response | undefined;
  let finished = false;
  const checkDeadline = () => {
    if (abort.signal.aborted || now() >= deadline) throw new Error("Capacity dispatch deadline");
  };
  const dispatched = Promise.resolve().then(() =>
    env.CLOUD_CONTAINER.getByName(env.CAPACITY_CONTAINER_NAME as string).fetch(
      new Request(`http://container${path}`, {
        method: "POST",
        headers: { ...headers, "content-type": "application/json" },
        body: body as BodyInit,
        signal: abort.signal,
      }),
    ),
  );
  void dispatched.then(
    (late) => {
      if (finished) void late.body?.cancel().catch(() => {});
    },
    () => {},
  );
  try {
    response = await Promise.race([dispatched, timeout]);
    checkDeadline();
    if (
      response.status !== 200 ||
      response.redirected ||
      response.headers.has("content-encoding") ||
      response.headers.get("content-type")?.split(";")[0]?.trim().toLowerCase() !==
        "application/json"
    )
      throw new Error("Capacity dispatch refused");
    const bounded = new Uint8Array(4096);
    let length = 0;
    const reader = response.body?.getReader();
    if (reader) {
      try {
        for (;;) {
          checkDeadline();
          const part = await Promise.race([reader.read(), timeout]);
          checkDeadline();
          if (part.done) break;
          if (part.value.byteLength > bounded.byteLength - length)
            throw new Error("Capacity reply too large");
          bounded.set(part.value, length);
          length += part.value.byteLength;
        }
      } catch (error) {
        void reader.cancel().catch(() => {});
        throw error;
      } finally {
        reader.releaseLock();
      }
    }
    const bytes = bounded.subarray(0, length);
    checkDeadline();
    const parsed: unknown = JSON.parse(
      new TextDecoder("utf-8", { fatal: true, ignoreBOM: true }).decode(bytes),
    );
    return parsed;
  } finally {
    finished = true;
    clearTimeout(timer);
    abort.abort();
    if (response?.body && !response.body.locked) void response.body.cancel().catch(() => {});
  }
}
