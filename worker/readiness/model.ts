// SPDX-License-Identifier: AGPL-3.0-only
// The readiness model (WP-21.07): the health of the ingress, the Container, D1, the Durable Object, R2
// and the Queue is reported separately, from a closed vocabulary, and the whole is ready only when every
// required component is. Nothing here carries content: a component is a state, a reason from the closed
// list below, the evidence level of the check and a duration. Reports and logs hold no request, no
// identifier of a person or an object, no secret and no error text.

export const readinessSchema = "cloud.readiness.v1";

export const componentIds = ["ingress", "container", "d1", "durableObject", "r2", "queue"] as const;
export type ComponentId = (typeof componentIds)[number];

/**
 * - `ready`: the check passed at its evidence level.
 * - `starting`: the dependency did not answer within the bounded wait and a start may be in progress.
 * - `unavailable`: the dependency failed or could not be provided; a retry may succeed.
 * - `misconfigured`: a declared binding, key, plan manifest or recovery generation is missing or wrong; a retry
 *   cannot succeed until the deployment is repaired.
 * - `unknown`: not determined because a dependency of this check (the Container) is not ready. Never counts as ready.
 * - `not_required`: the environment does not declare this component, so it takes no part in readiness.
 */
export const componentStates = [
  "ready",
  "starting",
  "unavailable",
  "misconfigured",
  "unknown",
  "not_required",
] as const;
export type ComponentState = (typeof componentStates)[number];

export const reasons = [
  "binding_missing",
  "key_missing",
  "key_mismatch",
  "host_route_missing",
  "host_reply_invalid",
  "host_error",
  "no_instance_available",
  "start_failed",
  "rate_limited",
  "no_answer_in_wait",
  "unreachable",
  "container_not_ready",
  "plan_hash_mismatch",
  "schema_mismatch",
  "recovery_generation_mismatch",
  "d1_unavailable",
] as const;
export type Reason = (typeof reasons)[number];

/**
 * How far the check went: `probed` means a bounded read through the real dependency answered; `bound` means only
 * that the declared binding is present with the expected shape (a Queue producer has no read-only probe, and a
 * send would enqueue work), so `ready` there does not prove delivery.
 */
export type Evidence = "probed" | "bound";

export interface ComponentReport {
  readonly state: ComponentState;
  readonly reason?: Reason;
  readonly evidence?: Evidence;
  /** The names of the declared bindings or secrets that are missing (a closed, declared set; never a value). */
  readonly missing?: readonly string[];
  /** Whole milliseconds the check took; absent when nothing was awaited. */
  readonly elapsedMs?: number;
}

export type ReadinessStatus = "ready" | "starting" | "unavailable" | "misconfigured";

export type Components = Readonly<Record<ComponentId, ComponentReport>>;

export interface ReadinessReport {
  readonly schema: typeof readinessSchema;
  readonly status: ReadinessStatus;
  /** True only when the status is `ready`. */
  readonly ready: boolean;
  readonly environment: "production" | "proof";
  readonly workerRevision: string;
  readonly components: Components;
  /** What the Container host reported about itself, present only when its reply was valid. */
  readonly host?: {
    readonly revision?: string;
    readonly manifestHash: string;
    readonly schemaVersion: string;
  };
}

/** Seconds a client is advised to wait before it tries again after a transient refusal (Design D1 profile, section 3). */
export const retryAfterSeconds = 2;

/**
 * The status of the whole. It fails closed: the order is misconfigured, unavailable, starting, ready, an `unknown`
 * component can never yield `ready`, and a component that is not required takes no part.
 */
export function summarize(components: Components): ReadinessStatus {
  const states = componentIds.map((id) => components[id].state);
  if (states.includes("misconfigured")) return "misconfigured";
  if (states.includes("unavailable")) return "unavailable";
  if (states.includes("starting")) return "starting";
  // An undetermined component only remains when its cause was not reported: it still never counts as ready.
  if (states.includes("unknown")) return "unavailable";
  return "ready";
}

/** Whether a client may usefully retry: only a transient status. A misconfigured deployment will not heal by itself. */
export function isTransient(status: ReadinessStatus): boolean {
  return status === "starting" || status === "unavailable";
}
