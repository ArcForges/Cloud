// SPDX-License-Identifier: AGPL-3.0-only
// The private `storage.internal` ingress: exact host, path and method, signature before body, strict
// generated ExecutePlan request and reply. Public routes never reach it.
import {
  executePlanResponseJsonMaxBytes,
  serializeExecutePlanResponseJson,
  tryParseExecutePlanRequestJson,
  executePlanRequestJsonMaxBytes,
} from "@arcforges/ai-internal";
import { BodyTooLarge, readBounded, refusal } from "../private/bounded-body.ts";
import { sha256Hex } from "../private/encoding.ts";
import { loadKeys, verificationKeys, type PrivateKeyEnv } from "../private/keys.ts";
import { verify } from "../private/signing.ts";
import type { D1Like } from "./d1.ts";
import { executePlan, planKey } from "./execute-plan.ts";
import { manifestHash, plans } from "./plans.generated.ts";

export const storageHost = "storage.internal";
export const executePlanPath = "/internal/storage/v1/execute-plan";

export interface StorageEnv extends PrivateKeyEnv {
  DB: D1Like;
  /** Active recovery generation as canonical uint64 text. */
  RECOVERY_GENERATION: string;
}

const planIndex = new Map(plans.map((plan) => [planKey(plan.id, plan.version), plan]));
const nilUuid = "00000000-0000-0000-0000-000000000000";

function reply(body: Uint8Array): Response {
  return new Response(body as BodyInit, {
    status: 200,
    headers: { "content-type": "application/json", "cache-control": "no-store" },
  });
}

export async function handleExecutePlan(
  request: Request,
  env: StorageEnv,
  nowMs: () => number = Date.now,
): Promise<Response> {
  const url = new URL(request.url);
  if (url.hostname !== storageHost || url.pathname !== executePlanPath || url.search !== "")
    return refusal(404);
  if (request.method !== "POST") return refusal(405);
  const keys = loadKeys(env, "C2W");
  // Missing or malformed deployment secrets make the endpoint unavailable, never open.
  if (!keys) return refusal(503);
  if (
    (request.headers.get("content-type") ?? "").split(";")[0]?.trim().toLowerCase() !==
    "application/json"
  )
    return refusal(415);
  const declared = Number(request.headers.get("content-length") ?? "0");
  if (declared > executePlanRequestJsonMaxBytes) return refusal(413);
  let body: Uint8Array;
  try {
    body = await readBounded(request.body, executePlanRequestJsonMaxBytes);
  } catch (error) {
    if (error instanceof BodyTooLarge) return refusal(413);
    throw error;
  }
  const verification = await verify(
    {
      method: request.method,
      pathAndQuery: url.pathname + url.search,
      bodySha256Hex: await sha256Hex(body),
      headers: request.headers,
    },
    verificationKeys(keys),
    Math.floor(nowMs() / 1000),
  );
  if (!verification.ok) return refusal(401);

  const failure = (kind: "invalidPlan") =>
    reply(
      serializeExecutePlanResponseJson({
        requestId: verification.requestId,
        manifestHash,
        failure: kind,
      }),
    );
  const parsed = tryParseExecutePlanRequestJson(body);
  if (
    !parsed.ok ||
    parsed.value.requestId !== verification.requestId ||
    parsed.value.requestId === nilUuid
  )
    return failure("invalidPlan");
  const response = await executePlan(parsed.value, {
    db: env.DB,
    plans: planIndex,
    manifestHash,
    recoveryGeneration: env.RECOVERY_GENERATION,
    nowMs,
  });
  const bytes = serializeExecutePlanResponseJson(response);
  if (bytes.length > executePlanResponseJsonMaxBytes)
    return reply(
      serializeExecutePlanResponseJson({
        requestId: parsed.value.requestId,
        manifestHash,
        failure: "overloaded",
      }),
    );
  return reply(bytes);
}
