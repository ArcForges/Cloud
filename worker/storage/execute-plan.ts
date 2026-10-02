// SPDX-License-Identifier: AGPL-3.0-only
// Executes one reviewed named plan against D1 (Design D1 profile sections 3 and 4). The Worker runs
// fixed SQL and encodes exact results; every business decision stays in the C# host.
import type { D1Scalar, ExecutePlanRequest, ExecutePlanResponse } from "@arcforges/ai-internal";
import type { D1Like, D1PreparedStatement } from "./d1.ts";
import type { PlanDefinition } from "./plan-types.ts";
import { bindValue, encodeResult, PlanResultError } from "./scalars.ts";

export type PlanFailure =
  | "invalidPlan"
  | "staleGeneration"
  | "precondition"
  | "constraint"
  | "overloaded"
  | "unavailable"
  | "unknownOutcome";

/** The caller deadline is at most ten seconds ahead (Design D1 profile section 3). */
export const maxDeadlineAheadMs = 10_000;
/** Tolerance for clock difference between the Container and the Worker. */
export const deadlineClockToleranceMs = 2_000;
export const guardConstraintName = "af_guard_failed";

export interface ExecuteDeps {
  readonly db: D1Like;
  readonly plans: ReadonlyMap<string, PlanDefinition>;
  readonly manifestHash: string;
  /** The active recovery generation as canonical uint64 text. */
  readonly recoveryGeneration: string;
  readonly nowMs: () => number;
}

export function planKey(id: string, version: number): string {
  return `${id}@${version}`;
}

const deadlinePattern = /^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})(?:\.(\d{1,7}))?Z$/u;
export function parseDeadline(text: string): number | null {
  const match = deadlinePattern.exec(text);
  if (!match) return null;
  const [, year, month, day, hour, minute, second, fraction] = match;
  const milliseconds = Number((fraction ?? "").padEnd(3, "0").slice(0, 3));
  const value = Date.UTC(
    Number(year),
    Number(month) - 1,
    Number(day),
    Number(hour),
    Number(minute),
    Number(second),
    milliseconds,
  );
  const check = new Date(value);
  return Number.isNaN(value) ||
    check.getUTCMonth() !== Number(month) - 1 ||
    check.getUTCDate() !== Number(day) ||
    check.getUTCHours() !== Number(hour)
    ? null
    : value;
}

function failure(
  request: { requestId: string },
  deps: ExecuteDeps,
  kind: PlanFailure,
): ExecutePlanResponse {
  return { requestId: request.requestId, manifestHash: deps.manifestHash, failure: kind };
}

/** Maps a thrown D1 error to the contract failure. Only recognized messages are definite. */
export function classifyError(error: unknown, access: PlanDefinition["access"]): PlanFailure {
  const message = error instanceof Error ? error.message : String(error);
  if (message.includes(guardConstraintName)) return "precondition";
  if (
    /UNIQUE constraint failed|FOREIGN KEY constraint failed|CHECK constraint failed|NOT NULL constraint failed|cannot store (?:TEXT|REAL|INTEGER|BLOB)|datatype mismatch/iu.test(
      message,
    )
  )
    return "constraint";
  if (/overloaded|too many requests/iu.test(message)) return "overloaded";
  // An unrecognized error during a write may have happened after the commit point: never report it
  // as safe to retry. A failed read has no effect.
  return access === "write" ? "unknownOutcome" : "unavailable";
}

const timedOut = Symbol("deadline");
async function withDeadline<T>(
  promise: Promise<T>,
  milliseconds: number,
): Promise<T | typeof timedOut> {
  let timer: ReturnType<typeof setTimeout> | undefined;
  const deadline = new Promise<typeof timedOut>((resolve) => {
    timer = setTimeout(() => resolve(timedOut), Math.max(0, milliseconds));
  });
  try {
    return await Promise.race([promise, deadline]);
  } finally {
    if (timer !== undefined) clearTimeout(timer);
    // The abandoned operation may still settle; its outcome is reconciled by the caller.
    void promise.catch(() => {});
  }
}

function bindStatements(
  plan: PlanDefinition,
  request: ExecutePlanRequest,
  db: D1Like,
): D1PreparedStatement[] | null {
  if (request.arguments.length !== plan.statements.length) return null;
  const statements: D1PreparedStatement[] = [];
  for (const [index, statement] of plan.statements.entries()) {
    const supplied: readonly D1Scalar[] = request.arguments[index] ?? [];
    if (supplied.length !== statement.params.length) return null;
    const values: unknown[] = [];
    for (const [position, param] of statement.params.entries()) {
      const bound = bindValue(supplied[position] as D1Scalar, param, request.ownerScope);
      if (!bound.ok) return null;
      values.push(bound.value);
    }
    statements.push(db.prepare(statement.sql).bind(...values));
  }
  return statements;
}

export async function executePlan(
  request: ExecutePlanRequest,
  deps: ExecuteDeps,
): Promise<ExecutePlanResponse> {
  const plan = deps.plans.get(planKey(request.planId, request.planVersion));
  if (!plan || request.manifestHash !== deps.manifestHash)
    return failure(request, deps, "invalidPlan");
  if (request.recoveryGeneration !== deps.recoveryGeneration)
    return failure(request, deps, "staleGeneration");
  const deadline = parseDeadline(request.deadlineUtc);
  if (deadline === null) return failure(request, deps, "invalidPlan");
  const now = deps.nowMs();
  if (deadline - now > maxDeadlineAheadMs + deadlineClockToleranceMs)
    return failure(request, deps, "invalidPlan");
  // Nothing has been sent to D1 yet, so an expired deadline is a plain unavailable.
  if (deadline <= now) return failure(request, deps, "unavailable");
  let statements: D1PreparedStatement[] | null;
  try {
    statements = bindStatements(plan, request, deps.db);
  } catch {
    statements = null;
  }
  if (!statements) return failure(request, deps, "invalidPlan");
  const remaining = deadline - now;

  if (plan.access === "read") {
    const returns = plan.statements[0]?.returns;
    const statement = statements[0];
    if (!returns || !statement) return failure(request, deps, "invalidPlan");
    let outcome: unknown[][] | typeof timedOut;
    try {
      outcome = await withDeadline(statement.raw(), remaining);
    } catch (error) {
      return failure(request, deps, classifyError(error, "read"));
    }
    if (outcome === timedOut) return failure(request, deps, "unavailable");
    if (outcome.length > plan.maxRows) return failure(request, deps, "overloaded");
    try {
      const rows = outcome.map((row) => {
        if (row.length !== returns.length) throw new PlanResultError("Unexpected column count");
        return returns.map((param, column) => encodeResult(row[column], param));
      });
      return {
        requestId: request.requestId,
        manifestHash: deps.manifestHash,
        rows,
        changes: "0",
      };
    } catch (error) {
      if (error instanceof PlanResultError) return failure(request, deps, "unavailable");
      throw error;
    }
  }

  let results: Awaited<ReturnType<D1Like["batch"]>> | typeof timedOut;
  try {
    results = await withDeadline(deps.db.batch(statements), remaining);
  } catch (error) {
    return failure(request, deps, classifyError(error, "write"));
  }
  // A write that outlives its deadline may still commit: only a receipt lookup can tell.
  if (results === timedOut) return failure(request, deps, "unknownOutcome");
  const changes = results.reduce((sum, result) => sum + BigInt(result.meta?.changes ?? 0), 0n);
  return {
    requestId: request.requestId,
    manifestHash: deps.manifestHash,
    rows: [],
    changes: String(changes),
  };
}
