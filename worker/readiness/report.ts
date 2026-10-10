// SPDX-License-Identifier: AGPL-3.0-only
// The closed readiness report (WP-21.07, cloud.readiness.v1) as the Worker holds it, and the strict reader of the Container host's reply.
// The host judges the report (C# ReadinessEvaluator). This reader only refuses a reply outside the closed shape, so a malformed or foreign
// reply is never believed. Nothing here carries content.
import {
  readinessComponentIds,
  readinessEnvironments,
  readinessEvidence,
  readinessReasons,
  readinessSchema,
  readinessStates,
  readinessStatuses,
  type ComponentId,
  type ComponentState,
  type Evidence,
  type Reason,
  type ReadinessEnvironment,
  type ReadinessStatus,
} from "../tables/cloud-tables.generated.ts";

export interface ComponentReport {
  readonly state: ComponentState;
  readonly reason?: Reason;
  readonly evidence?: Evidence;
  /** The names of the declared bindings that are missing (a closed, declared set; never a value). */
  readonly missing?: readonly string[];
  /** Whole milliseconds the check took; absent when nothing was awaited. */
  readonly elapsedMs?: number;
}

export type Components = Readonly<Record<ComponentId, ComponentReport>>;

/** What the Container host reported about itself. Present only when the host's reply was a valid report. */
export interface ReadinessHost {
  readonly manifestHash: string;
  readonly schemaVersion: string;
  readonly revision?: string;
}

export interface ReadinessReport {
  readonly schema: typeof readinessSchema;
  readonly status: ReadinessStatus;
  /** True only when the status is `ready`. */
  readonly ready: boolean;
  readonly environment: ReadinessEnvironment;
  readonly workerRevision: string;
  readonly components: Components;
  readonly host?: ReadinessHost;
}

const hex64 = /^[0-9a-f]{64}$/u;
const maxRevisionLength = 80;
const maxSchemaVersionLength = 8;
const maxElapsedMs = 60_000;

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function isOneOf<T extends string>(value: unknown, list: readonly T[]): value is T {
  return typeof value === "string" && (list as readonly string[]).includes(value);
}

/** True only when the record has no member outside the allowed names. */
function closed(record: Record<string, unknown>, allowed: readonly string[]): boolean {
  return Object.keys(record).every((key) => allowed.includes(key));
}

function parseComponent(value: unknown): ComponentReport | null {
  if (!isRecord(value) || !closed(value, ["state", "reason", "evidence", "missing", "elapsedMs"]))
    return null;
  const { state, reason, evidence, missing, elapsedMs } = value;
  if (!isOneOf(state, readinessStates)) return null;
  if (reason !== undefined && !isOneOf(reason, readinessReasons)) return null;
  if (evidence !== undefined && !isOneOf(evidence, readinessEvidence)) return null;
  if (
    missing !== undefined &&
    (!Array.isArray(missing) || missing.some((name) => typeof name !== "string"))
  )
    return null;
  if (
    elapsedMs !== undefined &&
    (typeof elapsedMs !== "number" ||
      !Number.isInteger(elapsedMs) ||
      elapsedMs < 0 ||
      elapsedMs > maxElapsedMs)
  )
    return null;
  return {
    state,
    ...(reason === undefined ? {} : { reason }),
    ...(evidence === undefined ? {} : { evidence }),
    ...(missing === undefined ? {} : { missing: missing as string[] }),
    ...(elapsedMs === undefined ? {} : { elapsedMs }),
  };
}

function parseComponents(value: unknown): Components | null {
  if (!isRecord(value) || !closed(value, readinessComponentIds)) return null;
  const parsed: Partial<Record<ComponentId, ComponentReport>> = {};
  for (const id of readinessComponentIds) {
    const component = parseComponent(value[id]);
    if (component === null) return null;
    parsed[id] = component;
  }
  return parsed as Components;
}

function parseHost(value: unknown): ReadinessHost | null {
  if (!isRecord(value) || !closed(value, ["manifestHash", "schemaVersion", "revision"]))
    return null;
  const { manifestHash, schemaVersion, revision } = value;
  if (typeof manifestHash !== "string" || !hex64.test(manifestHash)) return null;
  if (typeof schemaVersion !== "string" || schemaVersion.length > maxSchemaVersionLength)
    return null;
  if (
    revision !== undefined &&
    (typeof revision !== "string" || revision.length > maxRevisionLength)
  )
    return null;
  return {
    manifestHash,
    schemaVersion,
    ...(revision === undefined ? {} : { revision }),
  };
}

/** Strict reading of the host's readiness reply. Anything outside the closed shape is invalid and yields null. */
export function parseHostReport(bytes: Uint8Array): ReadinessReport | null {
  let value: unknown;
  try {
    value = JSON.parse(new TextDecoder("utf-8", { fatal: true, ignoreBOM: false }).decode(bytes));
  } catch {
    return null;
  }
  if (!isRecord(value)) return null;
  if (
    !closed(value, [
      "schema",
      "status",
      "ready",
      "environment",
      "workerRevision",
      "components",
      "host",
    ])
  )
    return null;
  const { schema, status, ready, environment, workerRevision, components, host } = value;
  if (schema !== readinessSchema) return null;
  if (!isOneOf(status, readinessStatuses)) return null;
  // The two statements must agree: a host cannot be ready in one member and not in the other.
  if (typeof ready !== "boolean" || ready !== (status === "ready")) return null;
  if (!isOneOf(environment, readinessEnvironments)) return null;
  if (typeof workerRevision !== "string" || workerRevision.length > maxRevisionLength) return null;
  const parsedComponents = parseComponents(components);
  if (parsedComponents === null) return null;
  const parsedHost = parseHost(host);
  if (parsedHost === null) return null;
  return {
    schema: readinessSchema,
    status,
    ready,
    environment,
    workerRevision,
    components: parsedComponents,
    host: parsedHost,
  };
}
