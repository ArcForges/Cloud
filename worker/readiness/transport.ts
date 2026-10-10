// SPDX-License-Identifier: AGPL-3.0-only
// The Worker's half of readiness (WP-21.07, CLOUD.84 S39(1)). The Worker measures what only it can see: whether each declared binding is met,
// and the outcome of one bounded Durable Object read and one bounded R2 head. It forwards those raw observations on the signed readiness
// call, and the Container host judges the whole report in C# (ReadinessEvaluator). When the Container cannot be called, or cannot answer, the
// Worker keeps a transport-only report: the Container's class and no readiness verdict beyond "container unreachable: <class>". Nothing is
// retried, replayed or written.
import { postSigned, type ContainerClientEnv } from "../foundation/container-client.ts";
import type { CoordinatorNamespaceLike, R2Like } from "../foundation/types.ts";
import { manifestHash as workerManifestHash } from "../storage/plans.generated.ts";
import {
  type readinessProbeOutcomes,
  readinessSchema,
  readinessTerms,
  readinessWaitMs,
  type ComponentId,
  type ComponentState,
  type ReadinessEnvironment,
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

/** The bindings the signed call needs. Without them the Worker has no call to make, so it forwards nothing (S39(1)). */
const callBindings: readonly string[] = ["CLOUD_CONTAINER", "HMAC_W2C_KEY"];

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
  readonly bindings: Record<string, boolean>;
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
  if (outcome.ok) return readinessTerms.ready;
  return outcome.why === "timeout" ? readinessTerms.no_answer_in_wait : readinessTerms.unreachable;
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

/** The Container's class on a transport-only report: the one verdict such a report carries (S39(1)). */
type TransportState = Extract<
  ComponentState,
  | typeof readinessTerms.starting
  | typeof readinessTerms.unavailable
  | typeof readinessTerms.misconfigured
>;

export interface TransportClass extends ComponentReport {
  readonly state: TransportState;
}

export type HostAnswer =
  | { readonly kind: "report"; readonly report: ReadinessReport }
  | { readonly kind: "transport"; readonly container: TransportClass };

function transport(container: TransportClass): HostAnswer {
  return { kind: "transport", container };
}

/**
 * Classifies what the Container answered. A plain-text start failure proves the request never reached the host (safe to retry). A 401 or
 * a 404 is a deployment fault. Any other status, or a body outside the closed report, is classified without a verdict of its own.
 */
export function classifyHostReply(reply: HostReply): HostAnswer {
  const prefix = new TextDecoder().decode(reply.body.subarray(0, classifiedPrefixBytes));
  const startFailure = classifyStartFailure(reply.status, reply.contentType, prefix);
  if (startFailure)
    return transport({
      state: readinessTerms.unavailable,
      reason: startFailure,
      evidence: readinessTerms.probed,
    });
  // The host answers an unsigned or wrongly signed call with an empty 401, whichever check failed.
  if (reply.status === 401)
    return transport({
      state: readinessTerms.misconfigured,
      reason: readinessTerms.key_mismatch,
      evidence: readinessTerms.probed,
    });
  if (reply.status === 404)
    return transport({
      state: readinessTerms.misconfigured,
      reason: readinessTerms.host_route_missing,
      evidence: readinessTerms.probed,
    });
  if (reply.status !== 200 && reply.status !== 503)
    return transport({
      state: readinessTerms.unavailable,
      reason: readinessTerms.host_error,
      evidence: readinessTerms.probed,
    });
  const report = parseHostReport(reply.body);
  if (!report)
    return transport({
      state: readinessTerms.unavailable,
      reason: reply.status === 200 ? readinessTerms.host_reply_invalid : readinessTerms.host_error,
      evidence: readinessTerms.probed,
    });
  // A 200 is ready and a ready report is a 200: a reply where the two disagree is not believed.
  if ((reply.status === 200) !== report.ready)
    return transport({
      state: readinessTerms.unavailable,
      reason: reply.status === 200 ? readinessTerms.host_reply_invalid : readinessTerms.host_error,
      evidence: readinessTerms.probed,
    });
  return { kind: "report", report };
}

/**
 * The report of a Container that was not called, or did not answer (S39(1)). Its one verdict is the Container's class. Nothing else is judged
 * here: the host that judges the other components did not answer, so each component the environment requires is undetermined, and one it
 * does not declare is not_required. The status is the Container's class, the only state of this report that is not ready.
 */
function transportReport(
  env: ReadinessEnv,
  workerRevision: string,
  container: TransportClass,
): ReadinessReport {
  const environment = environmentOf(env);
  const required = requiredComponents(environment);
  // The names of the bindings that are not met are the Worker's own observation, so they are reported without a verdict.
  const undetermined = (id: ComponentId): ComponentReport => {
    if (!required.has(id)) return { state: readinessTerms.not_required };
    const missing = missingBindings(env, id);
    return {
      state: readinessTerms.unknown,
      reason: readinessTerms.container_not_ready,
      ...(missing.length > 0 ? { missing } : {}),
    };
  };
  const components: Components = {
    ingress: undetermined(readinessTerms.ingress),
    container,
    d1: undetermined(readinessTerms.d1),
    durableObject: undetermined(readinessTerms.durableObject),
    r2: undetermined(readinessTerms.r2),
    queue: undetermined(readinessTerms.queue),
  };
  return {
    schema: readinessSchema,
    status: container.state,
    ready: false,
    environment,
    workerRevision,
    components,
  };
}

/** The readiness of the Worker's deployment: every declared component, separately, and the whole. */
export async function evaluateReadiness(
  env: ReadinessEnv,
  overrides: Partial<ReadinessDeps> = {},
): Promise<ReadinessReport> {
  const deps: ReadinessDeps = { ...defaultDeps, ...overrides };
  const environment = environmentOf(env);
  const required = requiredComponents(environment);
  const workerRevision = typeof env.SOURCE_REVISION === "string" ? env.SOURCE_REVISION : "";
  const unmetCallBindings = missingBindings(env, readinessTerms.container).filter((name) =>
    callBindings.includes(name),
  );
  if (unmetCallBindings.length > 0) {
    return transportReport(env, workerRevision, {
      state: readinessTerms.unavailable,
      reason: readinessTerms.unreachable,
      missing: unmetCallBindings,
    });
  }
  const probesDurable =
    required.has(readinessTerms.durableObject) &&
    missingBindings(env, readinessTerms.durableObject).length === 0;
  const probesR2 =
    required.has(readinessTerms.r2) && missingBindings(env, readinessTerms.r2).length === 0;
  // The probes run first, each bounded, because their outcomes are forwarded for the host to judge.
  const [durableObject, r2] = await Promise.all([
    probesDurable ? probeDurableObject(env, deps) : Promise.resolve(null),
    probesR2 ? probeR2(env, deps) : Promise.resolve(null),
  ]);
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
    const container: TransportClass =
      outcome.why === "timeout"
        ? {
            state: readinessTerms.starting,
            reason: readinessTerms.no_answer_in_wait,
            evidence: readinessTerms.probed,
            elapsedMs: took,
          }
        : {
            state: readinessTerms.unavailable,
            reason: readinessTerms.unreachable,
            evidence: readinessTerms.probed,
            elapsedMs: took,
          };
    return transportReport(env, workerRevision, container);
  }
  const answer = classifyHostReply(outcome.value);
  if (answer.kind === "transport") {
    return transportReport(env, workerRevision, { ...answer.container, elapsedMs: took });
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
