// SPDX-License-Identifier: AGPL-3.0-only
// The declared binding sets of the Worker, per environment and per component (WP-21.07, architecture 22:
// startup validates bindings and the key inventory). A required binding that is absent, or present with the
// wrong shape, makes its component `misconfigured`, so a partially configured Worker can never report ready.
// Each owning module task appends its own entries here in its own section (RES-cloud-deployment); only the
// names of bindings and secrets are ever reported, never a value.
import { proofEnabled } from "../foundation/types.ts";
import { loadKeys, type PrivateKeyEnv } from "../private/hmac-settings.ts";
import type { ComponentId } from "./model.ts";

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

export type Environment = "production" | "proof";

export function environmentOf(env: ReadinessEnv): Environment {
  return proofEnabled(env) ? "proof" : "production";
}

interface Declaration {
  readonly component: ComponentId;
  /** The name reported when this declaration is not met. */
  readonly name: string;
  /** Which environments declare it. */
  readonly in: readonly Environment[];
  readonly met: (env: ReadinessEnv) => boolean;
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

const both = ["production", "proof"] as const;
const proof = ["proof"] as const;

/**
 * Every declared binding. The production Worker binds only the Hello bindings; the isolated proof environment
 * adds the rest (wrangler.json env.proof). A later module appends its declarations under its own component.
 */
const declarations: readonly Declaration[] = [
  // ingress
  { component: "ingress", name: "SOURCE_REVISION", in: both, met: (e) => text(e.SOURCE_REVISION) },
  {
    component: "ingress",
    name: "HELLO_RATE_LIMITER",
    in: both,
    met: (e) => hasMethods(e.HELLO_RATE_LIMITER, "limit"),
  },
  { component: "ingress", name: "ALLOWED_ORIGIN", in: proof, met: (e) => text(e.ALLOWED_ORIGIN) },
  // container
  {
    component: "container",
    name: "CLOUD_CONTAINER",
    in: both,
    met: (e) => hasMethods(e.CLOUD_CONTAINER, "getByName"),
  },
  {
    component: "container",
    name: "HMAC_W2C_KEY",
    in: proof,
    met: (e) => loadKeys(e, "W2C") !== null,
  },
  { component: "container", name: "CSRF_SECRET", in: proof, met: (e) => text(e.CSRF_SECRET) },
  // d1
  { component: "d1", name: "DB", in: proof, met: (e) => hasMethods(e.DB, "prepare", "batch") },
  {
    component: "d1",
    name: "RECOVERY_GENERATION",
    in: proof,
    met: (e) => recoveryGeneration(e.RECOVERY_GENERATION),
  },
  { component: "d1", name: "HMAC_C2W_KEY", in: proof, met: (e) => loadKeys(e, "C2W") !== null },
  // durable object
  {
    component: "durableObject",
    name: "JOB_COORDINATOR",
    in: proof,
    met: (e) => hasMethods(e.JOB_COORDINATOR, "getByName"),
  },
  // r2
  {
    component: "r2",
    name: "OBJECTS",
    in: proof,
    met: (e) => hasMethods(e.OBJECTS, "head", "get", "put", "delete"),
  },
  { component: "r2", name: "REALM_ID", in: proof, met: (e) => text(e.REALM_ID) },
  // queue
  {
    component: "queue",
    name: "WAKE_QUEUE",
    in: proof,
    met: (e) => hasMethods(e.WAKE_QUEUE, "send"),
  },
];

/** The components the environment declares; the rest are `not_required`. Ingress and Container always are. */
export function requiredComponents(environment: Environment): ReadonlySet<ComponentId> {
  return new Set(declarations.filter((d) => d.in.includes(environment)).map((d) => d.component));
}

/** The declared bindings of one component that are missing or malformed, in declaration order. */
export function missingBindings(env: ReadinessEnv, component: ComponentId): string[] {
  const environment = environmentOf(env);
  return declarations
    .filter((d) => d.component === component && d.in.includes(environment) && !d.met(env))
    .map((d) => d.name);
}
