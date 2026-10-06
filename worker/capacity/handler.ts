// SPDX-License-Identifier: AGPL-3.0-only
import { BodyTooLarge, refusal, jsonResponse } from "../private/bounded-body.ts";
import { sha256Hex } from "../private/encoding.ts";
import { loadKeys, verificationKeys, type PrivateKeyEnv } from "../private/hmac-settings.ts";
import { verify } from "../private/signing.ts";
import { validWake, type CapacityWake } from "./pacer.ts";

export const capacityHost = "capacity.internal";
export const schedulePath = "/internal/capacity/v1/schedule";
export interface CapacityPacerNamespace {
  getByName(name: string): {
    schedule(wake: CapacityWake, dueAt: number): Promise<"scheduled" | "duplicate" | "conflict">;
  };
}
export interface CapacityScheduleEnv extends PrivateKeyEnv {
  CAPACITY_PACER?: CapacityPacerNamespace;
}

/** Closed signed Container-to-Worker scheduling adapter. The key authenticates the infrastructure
 * hop; it grants no business authority. Public routes never call this virtual-host handler. */
export async function handleCapacitySchedule(
  request: Request,
  env: CapacityScheduleEnv,
  now: () => number = Date.now,
): Promise<Response> {
  const url = new URL(request.url);
  if (url.hostname !== capacityHost || url.pathname !== schedulePath || url.search)
    return refusal(404);
  if (request.method !== "POST") return refusal(405);
  const keys = loadKeys(env, "C2W");
  if (!keys || !env.CAPACITY_PACER) return refusal(503);
  if (
    request.headers.has("content-encoding") ||
    request.headers.get("content-type") !== "application/json"
  )
    return refusal(415);
  if (Number(request.headers.get("content-length")) > 4096) return refusal(413);
  let bytes: Uint8Array;
  try {
    bytes = await readScheduleBody(request, now);
  } catch (error) {
    if (error instanceof BodyTooLarge) return refusal(413);
    return refusal(503);
  }
  const verified = await verify(
    {
      method: "POST",
      pathAndQuery: schedulePath,
      bodySha256Hex: await sha256Hex(bytes),
      headers: request.headers,
    },
    verificationKeys(keys),
    Math.floor(now() / 1000),
  );
  if (!verified.ok) return refusal(401);
  let parsed: { wake: CapacityWake; dueAtMicros: string };
  try {
    const text = new TextDecoder("utf-8", { fatal: true, ignoreBOM: true }).decode(bytes);
    parsed = JSON.parse(text) as typeof parsed;
    // Own exact canonical request contract rejects duplicate members and alternate encodings.
    if (
      JSON.stringify(parsed) !== text ||
      !parsed ||
      typeof parsed !== "object" ||
      Object.keys(parsed).join(",") !== "wake,dueAtMicros" ||
      !validWake(parsed.wake) ||
      parsed.wake.wakeId !== verified.requestId ||
      typeof parsed.dueAtMicros !== "string" ||
      !/^(0|[1-9][0-9]{0,18})$/u.test(parsed.dueAtMicros)
    )
      return refusal(400);
  } catch {
    return refusal(400);
  }
  const millis = Number((BigInt(parsed.dueAtMicros) + 999n) / 1000n);
  if (!Number.isSafeInteger(millis) || millis < 0) return refusal(400);
  const result = await env.CAPACITY_PACER.getByName(
    `${parsed.wake.owner.realmId}:${parsed.wake.jobId}`,
  ).schedule(parsed.wake, millis);
  return result === "conflict" ? refusal(409) : jsonResponse(200, { status: result });
}

async function readScheduleBody(request: Request, now: () => number): Promise<Uint8Array> {
  const deadline = now() + 10_000;
  let rejectDeadline: (reason: Error) => void = () => {};
  const stopped = new Promise<never>((_, reject) => {
    rejectDeadline = reject;
  });
  const stop = () => rejectDeadline(new Error("Capacity scheduling deadline"));
  const timer = setTimeout(stop, 10_000);
  request.signal.addEventListener("abort", stop, { once: true });
  const check = () => {
    if (request.signal.aborted || now() >= deadline)
      throw new Error("Capacity scheduling deadline");
  };
  const reader = request.body?.getReader();
  const bytes = new Uint8Array(4096);
  let length = 0;
  try {
    check();
    if (reader)
      for (;;) {
        const part = await Promise.race([reader.read(), stopped]);
        check();
        if (part.done) break;
        if (part.value.byteLength > bytes.byteLength - length) throw new BodyTooLarge();
        bytes.set(part.value, length);
        length += part.value.byteLength;
      }
    check();
    return bytes.slice(0, length);
  } catch (error) {
    if (reader) void reader.cancel().catch(() => {});
    throw error;
  } finally {
    clearTimeout(timer);
    request.signal.removeEventListener("abort", stop);
    reader?.releaseLock();
  }
}
