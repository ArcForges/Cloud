// SPDX-License-Identifier: AGPL-3.0-only
// Builders for typed named-plan calls used by the offline executor and plan vectors.
import type { D1Scalar, ExecutePlanRequest, ExecutePlanResponse } from "@arcforges/ai-internal";
import { base64UrlEncode } from "../../../worker/private/encoding.ts";
import type { D1Like } from "../../../worker/storage/d1.ts";
import { executePlan, planKey, type ExecuteDeps } from "../../../worker/storage/execute-plan.ts";
import { manifestHash, plans } from "../../../worker/storage/plans.generated.ts";

export const scope = "proof/test";
export const fixedNow = Date.UTC(2026, 9, 2, 12, 0, 0);
export const planIndex = new Map(plans.map((plan) => [planKey(plan.id, plan.version), plan]));

export const i64 = (value: string | bigint | number): D1Scalar => ({
  kind: "int64",
  value: String(value),
});
export const u64 = (value: string | bigint | number): D1Scalar => ({
  kind: "uint64",
  value: String(value),
});
export const dec = (value: string): D1Scalar => ({ kind: "decimal", value });
export const txt = (value: string): D1Scalar => ({ kind: "text", value });
export const bytes = (value: Uint8Array): D1Scalar => ({
  kind: "bytes",
  value: base64UrlEncode(value),
});
export const sc = (value = scope): D1Scalar => ({ kind: "text", value });
export const nul = (): D1Scalar => ({ kind: "null" });

let counter = 0;
export function uuid(): string {
  counter++;
  return `00000000-0000-4000-8000-${counter.toString(16).padStart(12, "0")}`;
}

export function deadline(offsetMs = 5_000, now = fixedNow): string {
  return new Date(now + offsetMs).toISOString().replace(/\.(\d{3})Z$/u, ".$10000Z");
}

export function planRequest(
  planId: string,
  args: D1Scalar[][],
  overrides: Partial<ExecutePlanRequest> = {},
): ExecutePlanRequest {
  return {
    planId,
    planVersion: 1,
    manifestHash,
    requestId: uuid(),
    recoveryGeneration: "0",
    ownerScope: scope,
    arguments: args,
    deadlineUtc: deadline(),
    ...overrides,
  };
}

export function depsFor(db: D1Like, overrides: Partial<ExecuteDeps> = {}): ExecuteDeps {
  return {
    db,
    plans: planIndex,
    manifestHash,
    recoveryGeneration: "0",
    nowMs: () => fixedNow,
    ...overrides,
  };
}

export type Outcome =
  { ok: true; rows: string[][]; changes: string } | { ok: false; failure: string };

/** Runs a plan and flattens scalar values to text for compact assertions ("null" for null). */
export async function run(
  db: D1Like,
  planId: string,
  args: D1Scalar[][],
  overrides: Partial<ExecutePlanRequest> = {},
  deps: Partial<ExecuteDeps> = {},
): Promise<Outcome> {
  const response: ExecutePlanResponse = await executePlan(
    planRequest(planId, args, overrides),
    depsFor(db, deps),
  );
  if ("failure" in response) return { ok: false, failure: response.failure };
  return {
    ok: true,
    rows: response.rows.map((row) =>
      row.map((value) => ("value" in value ? String(value.value) : "null")),
    ),
    changes: response.changes,
  };
}
