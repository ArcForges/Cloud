// SPDX-License-Identifier: AGPL-3.0-only
// Evaluates readiness (WP-21.07). Each component is checked separately and bounded, nothing is retried, no
// request is replayed and nothing is written: the Container is asked its own readiness through the signed
// private call, the Durable Object and R2 are read once, and the Queue and the bindings are checked for shape.
// A missing binding, a plan-manifest mismatch or a recovery-generation mismatch fails readiness instead of
// letting a partially configured deployment look successful.
import { postSigned, type ContainerClientEnv } from "../foundation/container-client.ts";
import type { CoordinatorNamespaceLike, R2Like } from "../foundation/types.ts";
import { manifestHash as workerManifestHash } from "../storage/plans.generated.ts";
import {
  environmentOf,
  missingBindings,
  requiredComponents,
  type ReadinessEnv,
} from "./bindings.ts";
import { classifyStartFailure } from "./container.ts";
import {
  readinessSchema,
  summarize,
  type ComponentId,
  type ComponentReport,
  type Components,
  type Reason,
  type ReadinessReport,
} from "./model.ts";

/**
 * The longest the readiness check waits for one component (Design D1 profile, section 3: the Worker's readiness wait
 * is at most eight seconds). launch-capacity.v1 (CLOUD.10) carries the same value as `readinessTimeoutMs`.
 */
export const readinessWaitMs = 8_000;
export const durableObjectProbeName = "readiness-probe";
export const r2ProbeKey = "readiness/absent-probe";

export interface HostReply {
  readonly status: number;
  readonly contentType: string | null;
  readonly body: Uint8Array;
}

export interface ReadinessDeps {
  /** One signed readiness call to the Container host; aborted at the wait bound. */
  callHost(env: ReadinessEnv, signal: AbortSignal): Promise<HostReply>;
  now(): number;
  waitMs: number;
  /** The plan-manifest hash of this Worker's generated plans. */
  manifestHash: string;
}

export const defaultDeps: ReadinessDeps = {
  async callHost(env, signal) {
    const reply = await postSigned(
      env as ContainerClientEnv,
      "readiness",
      new TextEncoder().encode("{}"),
      { requestId: crypto.randomUUID(), signal },
    );
    return reply;
  },
  now: () => performance.now(),
  waitMs: readinessWaitMs,
  manifestHash: workerManifestHash,
};

type Waited<T> = { ok: true; value: T } | { ok: false; why: "timeout" | "error" };

/** Runs one bounded check: it ends at the wait bound whether or not the dependency honors the abort signal. */
async function waited<T>(
  work: (signal: AbortSignal) => Promise<T>,
  waitMs: number,
): Promise<Waited<T>> {
  const controller = new AbortController();
  let timer: ReturnType<typeof setTimeout> | undefined;
  const expired = new Promise<Waited<T>>((resolve) => {
    timer = setTimeout(() => {
      controller.abort();
      resolve({ ok: false, why: "timeout" });
    }, waitMs);
  });
  // A dependency that throws before it returns a promise (a binding that is not what it claims to be) is an error too.
  const operation = (async () => work(controller.signal))().then(
    (value): Waited<T> => ({ ok: true, value }),
    (): Waited<T> => ({ ok: false, why: "error" }),
  );
  try {
    return await Promise.race([operation, expired]);
  } finally {
    if (timer !== undefined) clearTimeout(timer);
  }
}

const keyNames = new Set(["HMAC_W2C_KEY", "HMAC_C2W_KEY", "CSRF_SECRET"]);
function missingReason(names: readonly string[]): Reason {
  return names.every((name) => keyNames.has(name)) ? "key_missing" : "binding_missing";
}

const hex64 = /^[0-9a-f]{64}$/u;
type D1Report = Pick<ComponentReport, "state" | "reason">;
const hostReasons: ReadonlySet<string> = new Set([
  "d1_unavailable",
  "plan_hash_mismatch",
  "schema_mismatch",
  "recovery_generation_mismatch",
  "key_mismatch",
]);

interface HostBody {
  readonly ready: boolean;
  readonly manifestHash: string;
  readonly schemaVersion: string;
  readonly revision?: string;
  readonly d1: D1Report;
}

/** Strict reading of the host's readiness reply; anything outside the closed shape is invalid. */
export function parseHostBody(bytes: Uint8Array): HostBody | null {
  let value: unknown;
  try {
    value = JSON.parse(new TextDecoder("utf-8", { fatal: true, ignoreBOM: false }).decode(bytes));
  } catch {
    return null;
  }
  if (typeof value !== "object" || value === null || Array.isArray(value)) return null;
  const record = value as Record<string, unknown>;
  const { ready, manifestHash, schemaVersion, revision, components } = record;
  if (typeof ready !== "boolean") return null;
  if (typeof manifestHash !== "string" || !hex64.test(manifestHash)) return null;
  if (typeof schemaVersion !== "string" || schemaVersion.length > 8) return null;
  if (revision !== undefined && (typeof revision !== "string" || revision.length > 80)) return null;
  if (typeof components !== "object" || components === null || Array.isArray(components))
    return null;
  const d1 = (components as Record<string, unknown>).d1;
  if (typeof d1 !== "object" || d1 === null || Array.isArray(d1)) return null;
  const { state, reason } = d1 as Record<string, unknown>;
  if (state !== "ready" && state !== "unavailable" && state !== "misconfigured") return null;
  if (reason !== undefined && (typeof reason !== "string" || !hostReasons.has(reason))) return null;
  // The two statements must agree: a host cannot be ready with a failed D1, nor not ready with a healthy one.
  if (ready !== (state === "ready")) return null;
  return {
    ready,
    manifestHash,
    schemaVersion,
    ...(revision === undefined ? {} : { revision }),
    d1: { state, ...(reason === undefined ? {} : { reason: reason as Reason }) },
  };
}

interface HostAssessment {
  readonly container: ComponentReport;
  readonly d1: ComponentReport;
  readonly host?: ReadinessReport["host"];
}

/** Turns what came back from the Container host into the Container and D1 components. */
export function assessHostReply(reply: HostReply, expectedManifestHash: string): HostAssessment {
  const unknownD1: ComponentReport = { state: "unknown", reason: "container_not_ready" };
  const fail = (container: ComponentReport): HostAssessment => ({
    container,
    d1: unknownD1,
  });
  const prefix = new TextDecoder().decode(reply.body.subarray(0, 128));
  const startFailure = classifyStartFailure(reply.status, reply.contentType, prefix);
  if (startFailure) return fail({ state: "unavailable", reason: startFailure, evidence: "probed" });
  // The host answers an unsigned or wrongly signed call with an empty 401, whichever check failed.
  if (reply.status === 401)
    return fail({ state: "misconfigured", reason: "key_mismatch", evidence: "probed" });
  if (reply.status === 404)
    return fail({ state: "misconfigured", reason: "host_route_missing", evidence: "probed" });
  if (reply.status !== 200 && reply.status !== 503)
    return fail({ state: "unavailable", reason: "host_error", evidence: "probed" });
  const body = parseHostBody(reply.body);
  if (!body)
    return fail({
      state: "unavailable",
      reason: reply.status === 200 ? "host_reply_invalid" : "host_error",
      evidence: "probed",
    });

  // The host answered a signed call, so the Container is up and trusts this Worker's key. D1 is judged from its own
  // report, but the Worker is the authority on the plan manifest and the schema version it was built with.
  let d1: ComponentReport = { ...body.d1, evidence: "probed" };
  if (body.manifestHash !== expectedManifestHash)
    d1 = { state: "misconfigured", reason: "plan_hash_mismatch", evidence: "probed" };
  else if (body.schemaVersion !== "1" && d1.state === "ready")
    d1 = { state: "misconfigured", reason: "schema_mismatch", evidence: "probed" };
  return {
    container: { state: "ready", evidence: "probed" },
    d1,
    host: {
      manifestHash: body.manifestHash,
      schemaVersion: body.schemaVersion,
      ...(body.revision === undefined ? {} : { revision: body.revision }),
    },
  };
}

function elapsed(deps: ReadinessDeps, started: number): number {
  return Math.max(0, Math.round(deps.now() - started));
}

// The Container is asked through the foundation instance: the one that carries the signed private routes (the Hello
// instance is a separate Durable Object instance of the same class and serves only /api). This evaluation is therefore
// reachable only from the proof surface, which is the only place that holds the signing key.
async function probeContainer(
  env: ReadinessEnv,
  deps: ReadinessDeps,
): Promise<{ container: ComponentReport; d1: ComponentReport; host?: ReadinessReport["host"] }> {
  const started = deps.now();
  const outcome = await waited((signal) => deps.callHost(env, signal), deps.waitMs);
  const took = elapsed(deps, started);
  if (!outcome.ok) {
    const container: ComponentReport =
      outcome.why === "timeout"
        ? { state: "starting", reason: "no_answer_in_wait", evidence: "probed", elapsedMs: took }
        : { state: "unavailable", reason: "unreachable", evidence: "probed", elapsedMs: took };
    return { container, d1: { state: "unknown", reason: "container_not_ready" } };
  }
  const assessed = assessHostReply(outcome.value, deps.manifestHash);
  return {
    container: { ...assessed.container, elapsedMs: took },
    d1: assessed.d1,
    ...(assessed.host ? { host: assessed.host } : {}),
  };
}

async function probeDurableObject(
  env: ReadinessEnv,
  deps: ReadinessDeps,
): Promise<ComponentReport> {
  const started = deps.now();
  const namespace = env.JOB_COORDINATOR as CoordinatorNamespaceLike;
  // A read of an observation that nothing writes: it creates no state and carries no content.
  const outcome = await waited(
    () => namespace.getByName(durableObjectProbeName).readPoison(),
    deps.waitMs,
  );
  const took = elapsed(deps, started);
  if (outcome.ok) return { state: "ready", evidence: "probed", elapsedMs: took };
  return {
    state: "unavailable",
    reason: outcome.why === "timeout" ? "no_answer_in_wait" : "unreachable",
    evidence: "probed",
    elapsedMs: took,
  };
}

async function probeR2(env: ReadinessEnv, deps: ReadinessDeps): Promise<ComponentReport> {
  const started = deps.now();
  const bucket = env.OBJECTS as R2Like;
  // A head of a key that holds nothing: absent is the healthy answer, and no object is ever written.
  const outcome = await waited(() => bucket.head(r2ProbeKey), deps.waitMs);
  const took = elapsed(deps, started);
  if (outcome.ok) return { state: "ready", evidence: "probed", elapsedMs: took };
  return {
    state: "unavailable",
    reason: outcome.why === "timeout" ? "no_answer_in_wait" : "unreachable",
    evidence: "probed",
    elapsedMs: took,
  };
}

function misconfigured(names: readonly string[]): ComponentReport {
  return { state: "misconfigured", reason: missingReason(names), missing: names };
}

/** The readiness of the Worker's deployment: every declared component, separately, and the whole. */
export async function evaluateReadiness(
  env: ReadinessEnv,
  overrides: Partial<ReadinessDeps> = {},
): Promise<ReadinessReport> {
  const deps: ReadinessDeps = { ...defaultDeps, ...overrides };
  const environment = environmentOf(env);
  const required = requiredComponents(environment);
  const missing = (id: ComponentId) => missingBindings(env, id);
  const notRequired: ComponentReport = { state: "not_required" };

  const probes = {
    container: required.has("container") && missing("container").length === 0,
    durableObject: required.has("durableObject") && missing("durableObject").length === 0,
    r2: required.has("r2") && missing("r2").length === 0,
  };
  const [hostResult, durableObject, r2] = await Promise.all([
    probes.container ? probeContainer(env, deps) : Promise.resolve(null),
    probes.durableObject ? probeDurableObject(env, deps) : Promise.resolve(null),
    probes.r2 ? probeR2(env, deps) : Promise.resolve(null),
  ]);

  const containerMissing = missing("container");
  const d1Missing = missing("d1");
  const component = (id: ComponentId, probed: ComponentReport | null): ComponentReport => {
    if (!required.has(id)) return notRequired;
    const names = missing(id);
    if (names.length > 0) return misconfigured(names);
    return probed ?? { state: "unknown", reason: "container_not_ready" };
  };

  let container: ComponentReport;
  let d1: ComponentReport;
  if (!required.has("container")) {
    container = notRequired;
    d1 = notRequired;
  } else if (containerMissing.length > 0) {
    container = misconfigured(containerMissing);
    d1 = !required.has("d1")
      ? notRequired
      : d1Missing.length > 0
        ? misconfigured(d1Missing)
        : { state: "unknown", reason: "container_not_ready" };
  } else {
    container = hostResult?.container ?? { state: "unknown", reason: "container_not_ready" };
    d1 = !required.has("d1")
      ? notRequired
      : d1Missing.length > 0
        ? misconfigured(d1Missing)
        : (hostResult?.d1 ?? { state: "unknown", reason: "container_not_ready" });
  }

  const ingressMissing = missing("ingress");
  const components: Components = {
    ingress:
      ingressMissing.length > 0
        ? misconfigured(ingressMissing)
        : { state: "ready", evidence: "bound" },
    container,
    d1,
    durableObject: component("durableObject", durableObject),
    r2: component("r2", r2),
    // A Queue producer binding has no read-only probe (a send would enqueue work), so ready means bound.
    queue: component("queue", { state: "ready", evidence: "bound" }),
  };
  const status = summarize(components);
  return {
    schema: readinessSchema,
    status,
    ready: status === "ready",
    environment,
    workerRevision: typeof env.SOURCE_REVISION === "string" ? env.SOURCE_REVISION : "",
    components,
    ...(hostResult?.host ? { host: hostResult.host } : {}),
  };
}
