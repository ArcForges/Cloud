// SPDX-License-Identifier: AGPL-3.0-only
// The Worker's binding observations (WP-21.07, CLOUD.84 S39(1)). Which bindings each component declares, per environment, is the C#
// declaration in src/ArcForges.Cloud/Readiness, generated into worker/tables/cloud-tables.generated.ts. This file holds only the shape check
// of each named binding: the Worker can see its own bindings, and nothing else. A check reads no value out. An owning module task declares
// its binding in C#; the generated names then require a shape here too, so a missing shape fails the type check.
import { proofEnabled } from "../foundation/types.ts";
import { loadKeys, type PrivateKeyEnv } from "../private/hmac-settings.ts";
import {
  readinessBindings,
  type ComponentId,
  type ReadinessBindingName,
  type ReadinessEnvironment,
} from "../tables/cloud-tables.generated.ts";

/** The Worker's environment as readiness sees it: every member optional, nothing assumed. */
export interface ReadinessEnv extends PrivateKeyEnv {
  SOURCE_REVISION?: string;
  FOUNDATION_PROOF?: string;
  ALLOWED_ORIGIN?: string;
  REALM_ID?: string;
  CSRF_SECRET?: string;
  RECOVERY_GENERATION?: string;
  HELLO_RATE_LIMITER?: unknown;
  CLOUD_CONTAINER?: unknown;
  DB?: unknown;
  JOB_COORDINATOR?: unknown;
  OBJECTS?: unknown;
  WAKE_QUEUE?: unknown;
}

export function environmentOf(env: ReadinessEnv): ReadinessEnvironment {
  return proofEnabled(env) ? "proof" : "production";
}

const uint64Text = /^(0|[1-9][0-9]{0,19})$/u;
const maxUint64 = 2n ** 64n - 1n;

function text(value: unknown): boolean {
  return typeof value === "string" && value !== "";
}

function hasMethods(value: unknown, ...names: string[]): boolean {
  if (typeof value !== "object" && typeof value !== "function") return false;
  if (value === null) return false;
  const record = value as Record<string, unknown>;
  return names.every((name) => typeof record[name] === "function");
}

function recoveryGeneration(value: unknown): boolean {
  return typeof value === "string" && uint64Text.test(value) && BigInt(value) <= maxUint64;
}

/** Whether the environment declares the binding. The generated tuples are literal types, so the check widens them to strings. */
const declaredIn = (
  binding: { readonly environments: readonly string[] },
  environment: ReadinessEnvironment,
): boolean => binding.environments.includes(environment);

/** The shape each declared binding must have, keyed by its generated name. A missing key is a compile error. */
const shapes: Record<ReadinessBindingName, (env: ReadinessEnv) => boolean> = {
  SOURCE_REVISION: (env) => text(env.SOURCE_REVISION),
  HELLO_RATE_LIMITER: (env) => hasMethods(env.HELLO_RATE_LIMITER, "limit"),
  ALLOWED_ORIGIN: (env) => text(env.ALLOWED_ORIGIN),
  CLOUD_CONTAINER: (env) => hasMethods(env.CLOUD_CONTAINER, "getByName"),
  HMAC_W2C_KEY: (env) => loadKeys(env, "W2C") !== null,
  CSRF_SECRET: (env) => text(env.CSRF_SECRET),
  DB: (env) => hasMethods(env.DB, "prepare", "batch"),
  RECOVERY_GENERATION: (env) => recoveryGeneration(env.RECOVERY_GENERATION),
  HMAC_C2W_KEY: (env) => loadKeys(env, "C2W") !== null,
  JOB_COORDINATOR: (env) => hasMethods(env.JOB_COORDINATOR, "getByName"),
  OBJECTS: (env) => hasMethods(env.OBJECTS, "head", "get", "put", "delete"),
  REALM_ID: (env) => text(env.REALM_ID),
  WAKE_QUEUE: (env) => hasMethods(env.WAKE_QUEUE, "send"),
};

/** Every declared binding's shape, met or not, for the forwarded observations. Names only; never a value. */
export function bindingObservations(env: ReadinessEnv): Record<ReadinessBindingName, boolean> {
  return Object.fromEntries(
    readinessBindings.map((binding) => [binding.name, shapes[binding.name](env)]),
  ) as Record<ReadinessBindingName, boolean>;
}

/** The components the environment declares; the rest are `not_required`. */
export function requiredComponents(environment: ReadinessEnvironment): ReadonlySet<ComponentId> {
  return new Set(
    readinessBindings
      .filter((binding) => declaredIn(binding, environment))
      .map((binding) => binding.component),
  );
}

/** The declared bindings of one component, in the environment, whose shape is not met, in declaration order. */
export function missingBindings(env: ReadinessEnv, component: ComponentId): string[] {
  const environment = environmentOf(env);
  return readinessBindings
    .filter(
      (binding) =>
        binding.component === component &&
        declaredIn(binding, environment) &&
        !shapes[binding.name](env),
    )
    .map((binding) => binding.name);
}
