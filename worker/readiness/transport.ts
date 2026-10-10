// SPDX-License-Identifier: AGPL-3.0-only
// The Worker's half of readiness (WP-21.07, CLOUD.84 S39(1)). The Worker measures what it can see itself: whether each declared binding
// is met, and the outcome of one bounded Durable Object read and one bounded R2 head. It forwards those raw observations on the signed
// readiness call, and the Container host returns the whole report, judged in C#. When the Container cannot answer, the Worker keeps a
// transport-only report: the class of the reply it could not get, its own observations, and no readiness verdict beyond
// "container unreachable: <class>". Nothing is retried, replayed or written.
import { postSigned, type ContainerClientEnv } from "../foundation/container-client.ts";
import type { CoordinatorNamespaceLike, R2Like } from "../foundation/types.ts";
import { manifestHash as workerManifestHash } from "../storage/plans.generated.ts";
import {
  readinessKeyBindings,
  type readinessProbeOutcomes,
  readinessSchema,
  readinessWaitMs,
  type ComponentId,
  type ComponentState,
  type ReadinessBindingName,
  type ReadinessEnvironment,
  type ReadinessStatus,
} from "../tables/cloud-tables.generated.ts";
import {
  bindingObservations,
  environmentOf,
  missingBindings,
  requiredComponents,
  type ReadinessEnv,
} from "./bindings.ts";
import { classifiedPrefixBytes, classifyStartFailure } from "./container.ts";
import {
  parseHostReport,
  type ComponentReport,
  type Components,
  type ReadinessReport,
} from "./report.ts";

export const durableObjectProbeName = "readiness-probe";
export const r2ProbeKey = "readiness/absent-probe";

export type ProbeOutcome = (typeof readinessProbeOutcomes)[number];

/** One bounded probe: its outcome and the whole milliseconds it took. */
export interface ProbeObservation {
  readonly outcome: ProbeOutcome;
  readonly elapsedMs: number;
}

export interface HostReply {
  readonly status: number;
  readonly contentType: string | null;
  readonly body: Uint8Array;
}

/** The raw observations forwarded on the signed readiness call (S39(1)). The host reads no verdict out of the Worker's side. */
export interface ReadinessObservations {
  readonly environment: ReadinessEnvironment;
  readonly workerRevision: string;
  readonly manifestHash: string;
  readonly bindings: Record<ReadinessBindingName, boolean>;
  readonly durableObject: ProbeObservation | null;
  readonly r2: ProbeObservation | null;
}

export interface ReadinessDeps {
  /** One signed readiness call to the Container host with the observations; aborted at the wait bound. */
  callHost(env: ReadinessEnv, body: Uint8Array, signal: AbortSignal): Promise<HostReply>;
  now(): number;
  waitMs: number;
  /** The plan-manifest hash of this Worker's generated plans. */
  manifestHash: string;
}

export const defaultDeps: ReadinessDeps = {
  async callHost(env, body, signal) {
    return postSigned(env as ContainerClientEnv, "readiness", body, {
      requestId: crypto.randomUUID(),
      signal,
    });
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

function probeOutcome<T>(outcome: Waited<T>): ProbeOutcome {
  if (outcome.ok) return "ready";
  return outcome.why === "timeout" ? "no_answer_in_wait" : "unreachable";
}

function elapsed(deps: ReadinessDeps, started: number): number {
  return Math.max(0, Math.round(deps.now() - started));
}

/** One read of an observation that nothing writes, on a Durable Object with a fixed name: it creates no state and carries no content. */
export async function probeDurableObject(
  env: ReadinessEnv,
  deps: ReadinessDeps,
): Promise<ProbeObservation> {
  const started = deps.now();
  const namespace = env.JOB_COORDINATOR as CoordinatorNamespaceLike;
  const outcome = await waited(
    () => namespace.getByName(durableObjectProbeName).readPoison(),
    deps.waitMs,
  );
  return { outcome: probeOutcome(outcome), elapsedMs: elapsed(deps, started) };
}

/** A head of a key that holds nothing: absent is the healthy answer, and no object is ever written. */
export async function probeR2(env: ReadinessEnv, deps: ReadinessDeps): Promise<ProbeObservation> {
  const started = deps.now();
  const bucket = env.OBJECTS as R2Like;
  const outcome = await waited(() => bucket.head(r2ProbeKey), deps.waitMs);
  return { outcome: probeOutcome(outcome), elapsedMs: elapsed(deps, started) };
}

/** A transport class of the Container's reply: the component it puts the Container in. */
function transport(container: ComponentReport): HostAnswer {
  return { kind: "transport", container };
}

export type HostAnswer =
  | { readonly kind: "report"; readonly report: ReadinessReport }
  | { readonly kind: "transport"; readonly container: ComponentReport };

/**
 * Classifies what the Container answered. A plain-text start failure proves the request never reached the host (safe to retry). A 401 or
 * a 404 is a deployment fault. Any other status, or a body outside the closed report, is classified without a verdict of its own.
 */
export function classifyHostReply(reply: HostReply): HostAnswer {
  const prefix = new TextDecoder().decode(reply.body.subarray(0, classifiedPrefixBytes));
  const startFailure = classifyStartFailure(reply.status, reply.contentType, prefix);
  if (startFailure)
    return transport({ state: "unavailable", reason: startFailure, evidence: "probed" });
  // The host answers an unsigned or wrongly signed call with an empty 401, whichever check failed.
  if (reply.status === 401)
    return transport({ state: "misconfigured", reason: "key_mismatch", evidence: "probed" });
  if (reply.status === 404)
    return transport({ state: "misconfigured", reason: "host_route_missing", evidence: "probed" });
  if (reply.status !== 200 && reply.status !== 503)
    return transport({ state: "unavailable", reason: "host_error", evidence: "probed" });
  const report = parseHostReport(reply.body);
  if (!report)
    return transport({
      state: "unavailable",
      reason: reply.status === 200 ? "host_reply_invalid" : "host_error",
      evidence: "probed",
    });
  // A 200 is ready and a ready report is a 200: a reply where the two disagree is not believed.
  if ((reply.status === 200) !== report.ready)
    return transport({
      state: "unavailable",
      reason: reply.status === 200 ? "host_reply_invalid" : "host_error",
      evidence: "probed",
    });
  return { kind: "report", report };
}

const probeComponent = (probe: ProbeObservation): ComponentReport =>
  probe.outcome === "ready"
    ? { state: "ready", evidence: "probed", elapsedMs: probe.elapsedMs }
    : {
        state: "unavailable",
        reason: probe.outcome === "no_answer_in_wait" ? "no_answer_in_wait" : "unreachable",
        evidence: "probed",
        elapsedMs: probe.elapsedMs,
      };

const misconfigured = (names: readonly string[]): ComponentReport => ({
  state: "misconfigured",
  reason: names.every((name) => readinessKeyBindings.some((key) => key === name))
    ? "key_missing"
    : "binding_missing",
  missing: names,
});

/**
 * The report of a Container that could not answer. The components the Worker can see are reported from its own observations: a binding that
 * is not met is misconfigured with its names, and each probe is its outcome. D1 depends on the Container and is not judged (unknown). A
 * component the environment does not declare is not_required. The status is the fail-closed order of the whole.
 */
function transportReport(
  env: ReadinessEnv,
  workerRevision: string,
  container: ComponentReport,
  durableObject: ProbeObservation | null,
  r2: ProbeObservation | null,
): ReadinessReport {
  const environment = environmentOf(env);
  const required = requiredComponents(environment);
  const judge = (id: ComponentId, observed: ComponentReport): ComponentReport => {
    if (!required.has(id)) return { state: "not_required" };
    const names = missingBindings(env, id);
    return names.length > 0 ? misconfigured(names) : observed;
  };
  const unknown: ComponentReport = { state: "unknown", reason: "container_not_ready" };
  const components: Components = {
    ingress: judge("ingress", { state: "ready", evidence: "bound" }),
    container: required.has("container") ? container : { state: "not_required" },
    d1: judge("d1", unknown),
    durableObject: judge("durableObject", durableObject ? probeComponent(durableObject) : unknown),
    r2: judge("r2", r2 ? probeComponent(r2) : unknown),
    queue: judge("queue", { state: "ready", evidence: "bound" }),
  };
  const states: ComponentState[] = Object.values(components).map((component) => component.state);
  return {
    schema: readinessSchema,
    status: transportStatus(states),
    ready: false,
    environment,
    workerRevision,
    components,
  };
}

/** The fail-closed order of a transport-only report: misconfigured, unavailable, starting, then an undetermined component. */
function transportStatus(states: readonly ComponentState[]): ReadinessStatus {
  if (states.includes("misconfigured")) return "misconfigured";
  if (states.includes("unavailable")) return "unavailable";
  if (states.includes("starting")) return "starting";
  // The Container is never ready in a transport-only report, so an undetermined component is never ready either.
  return "unavailable";
}

/** The readiness of the Worker's deployment: every declared component, separately, and the whole. */
export async function evaluateReadiness(
  env: ReadinessEnv,
  overrides: Partial<ReadinessDeps> = {},
): Promise<ReadinessReport> {
  const deps: ReadinessDeps = { ...defaultDeps, ...overrides };
  const environment = environmentOf(env);
  const required = requiredComponents(environment);
  const probesDurable =
    required.has("durableObject") && missingBindings(env, "durableObject").length === 0;
  const probesR2 = required.has("r2") && missingBindings(env, "r2").length === 0;
  // The probes run first, each bounded, because their outcomes are part of what the host judges.
  const [durableObject, r2] = await Promise.all([
    probesDurable ? probeDurableObject(env, deps) : Promise.resolve(null),
    probesR2 ? probeR2(env, deps) : Promise.resolve(null),
  ]);
  const workerRevision = typeof env.SOURCE_REVISION === "string" ? env.SOURCE_REVISION : "";
  const containerMissing = missingBindings(env, "container");
  if (containerMissing.length > 0) {
    const container = misconfigured(containerMissing);
    return transportReport(env, workerRevision, container, durableObject, r2);
  }

  const observations: ReadinessObservations = {
    environment,
    workerRevision,
    manifestHash: deps.manifestHash,
    bindings: bindingObservations(env),
    durableObject,
    r2,
  };
  const body = new TextEncoder().encode(JSON.stringify(observations));
  const started = deps.now();
  const outcome = await waited((signal) => deps.callHost(env, body, signal), deps.waitMs);
  const took = elapsed(deps, started);
  if (!outcome.ok) {
    const container: ComponentReport =
      outcome.why === "timeout"
        ? { state: "starting", reason: "no_answer_in_wait", evidence: "probed", elapsedMs: took }
        : { state: "unavailable", reason: "unreachable", evidence: "probed", elapsedMs: took };
    return transportReport(env, workerRevision, container, durableObject, r2);
  }
  const answer = classifyHostReply(outcome.value);
  if (answer.kind === "transport") {
    return transportReport(
      env,
      workerRevision,
      { ...answer.container, elapsedMs: took },
      durableObject,
      r2,
    );
  }
  // The host's own report, with the Worker's measure of how long the Container took.
  const { report } = answer;
  return {
    ...report,
    components: {
      ...report.components,
      container: { ...report.components.container, elapsedMs: took },
    },
  };
}
