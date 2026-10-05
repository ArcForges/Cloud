// SPDX-License-Identifier: AGPL-3.0-only
// The HTTP form of a readiness report and its no-content log line. A ready report is 200; every other status is
// 503, with a two second `Retry-After` only when waiting can help (starting or unavailable) and none for a
// misconfigured deployment, which a retry cannot repair. The body holds the closed report and nothing else.
import {
  componentIds,
  isTransient,
  retryAfterSeconds,
  type ComponentReport,
  type ReadinessReport,
} from "./model.ts";

export function readinessResponse(report: ReadinessReport): Response {
  const headers = new Headers({
    "content-type": "application/json",
    "cache-control": "no-store",
    "x-content-type-options": "nosniff",
  });
  if (!report.ready && isTransient(report.status))
    headers.set("retry-after", String(retryAfterSeconds));
  return new Response(JSON.stringify(wireOf(report)), {
    status: report.ready ? 200 : 503,
    headers,
  });
}

/**
 * The wire form. `ready`, `manifestHash`, `schemaVersion` and `revision` keep the names the operator scenarios already
 * read (the host's own values, present only when the host's reply was valid); the rest is the separated report.
 */
export function wireOf(report: ReadinessReport): Record<string, unknown> {
  return {
    schema: report.schema,
    status: report.status,
    ready: report.ready,
    environment: report.environment,
    workerRevision: report.workerRevision,
    components: report.components,
    ...(report.host
      ? {
          manifestHash: report.host.manifestHash,
          schemaVersion: report.host.schemaVersion,
          ...(report.host.revision === undefined ? {} : { revision: report.host.revision }),
        }
      : {}),
  };
}

const describe = (report: ComponentReport): string =>
  report.reason ? `${report.state}:${report.reason}` : report.state;

/**
 * One log line: the status, the environment and each component as `state` or `state:reason`, all from the closed
 * vocabulary. No request, identifier, binding value, secret, error text or duration is ever logged.
 */
export function readinessLogEvent(report: ReadinessReport): Record<string, unknown> {
  return {
    event: "cloud.readiness",
    status: report.status,
    environment: report.environment,
    components: Object.fromEntries(componentIds.map((id) => [id, describe(report.components[id])])),
  };
}
