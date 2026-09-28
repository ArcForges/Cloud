import { lstatSync, readFileSync, readdirSync } from "node:fs";
import { join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const DEFAULT_MONITORING_ROOT = new URL(".", import.meta.url);
const REQUIRED_PAGE_ALERTS = new Set([
  "cloud-api-unavailable",
  "server-error-rate-spike",
  "database-unavailable",
  "oldest-message-age-critical",
  "dead-letter-growth",
  "one-time-code-delivery-failure-spike",
  "remote-connection-collapse",
  "backup-lag-beyond-objective",
  "payment-provider-webhook-backlog",
  "managed-ai-routes-unavailable",
  "data-integrity-alarm",
]);

const EXPECTED_CAPABILITIES = new Set([
  "cloud-api",
  "identity",
  "sync-control-plane",
  "realtime",
  "managed-ai",
]);

const EXPECTED_DEPENDENCIES = new Set([
  "edge-ingress",
  "primary-database",
  "object-storage",
  "message-queue",
  "identity-delivery",
  "payment-provider",
  "realtime-transport",
  "managed-ai-provider",
]);

const ALLOWED_SIGNALS = new Set([
  "capability.cloud-api.success-rate-bp",
  "capability.cloud-api.server-error-rate-bp",
  "dependency.primary-database.consecutive-failures",
  "dependency.message-queue.oldest-message-age-seconds",
  "dependency.message-queue.dead-letter-growth-count",
  "dependency.identity-delivery.failure-rate-bp",
  "capability.realtime.connection-loss-rate-bp",
  "dependency.object-storage.backup-lag-seconds",
  "dependency.payment-provider.webhook-oldest-age-seconds",
  "capability.managed-ai.route-availability-bp",
  "dependency.primary-database.integrity-alarm-count",
]);

const ROUTE_CLASSES = new Set(["page", "ticket", "dashboard"]);
const SEVERITIES = new Set(["SEV0", "SEV1", "SEV2", "SEV3"]);
const OPERATORS = new Set(["lt", "lte", "gt", "gte"]);

function requireValue(condition, message) {
  if (!condition) {
    throw new TypeError(message);
  }
}

function requireExactKeys(value, required, message) {
  requireValue(value !== null && typeof value === "object" && !Array.isArray(value), message);
  const actual = Object.keys(value).sort();
  const expected = [...required].sort();
  requireValue(
    actual.length === expected.length && actual.every((key, index) => key === expected[index]),
    message,
  );
}

function validateObjectives(objectives) {
  requireExactKeys(
    objectives,
    ["schema", "scope", "windowSeconds", "aggregation", "capabilities", "dependencies"],
    "Unknown SLI objective shape.",
  );
  requireValue(
    objectives.schema === "arcforges.cloud.sli-objectives.v1" &&
      objectives.scope === "internal-engineering-objectives" &&
      objectives.windowSeconds === 2592000 &&
      objectives.aggregation ===
        "capability-and-dependency-only-no-cross-capability-platform-total",
    "Invalid SLI objective authority or scope.",
  );

  for (const [rows, expected, label] of [
    [objectives.capabilities, EXPECTED_CAPABILITIES, "capability"],
    [objectives.dependencies, EXPECTED_DEPENDENCIES, "dependency"],
  ]) {
    requireValue(Array.isArray(rows), `SLI ${label} objectives must be an array.`);
    const ids = new Set();
    for (const row of rows) {
      const allowedKeys =
        label === "capability"
          ? ["id", "success", "targetBasisPoints"]
          : ["id", "targetBasisPoints"];
      requireExactKeys(row, allowedKeys, `Invalid ${label} objective shape.`);
      requireValue(
        typeof row.id === "string" && expected.has(row.id) && !ids.has(row.id),
        `Unknown or duplicate SLI ${label} objective.`,
      );
      requireValue(
        Number.isInteger(row.targetBasisPoints) &&
          row.targetBasisPoints > 0 &&
          row.targetBasisPoints < 10000,
        `Invalid ${label} target; targets must leave a measurable error budget.`,
      );
      if (label === "capability") {
        requireValue(
          typeof row.success === "string" && row.success.trim().length > 0,
          "Capability objectives require user-visible success semantics.",
        );
      }
      ids.add(row.id);
    }
    requireValue(
      ids.size === expected.size && [...expected].every((id) => ids.has(id)),
      `Incomplete SLI ${label} objective set.`,
    );
  }
}

function createAggregate(id, targetBasisPoints) {
  return { id, targetBasisPoints, sampleCount: 0, goodCount: 0 };
}

function presentAggregate(aggregate) {
  const badCount = aggregate.sampleCount - aggregate.goodCount;
  if (aggregate.sampleCount === 0) {
    return {
      ...aggregate,
      badCount,
      successRateBasisPoints: null,
      errorBudgetConsumedBasisPoints: null,
      errorBudgetRemainingBasisPoints: null,
      status: "insufficient-data",
    };
  }

  const successRateBasisPoints = Math.floor((aggregate.goodCount * 10000) / aggregate.sampleCount);
  const budgetRateBasisPoints = 10000 - aggregate.targetBasisPoints;
  const errorBudgetConsumedBasisPoints = Math.ceil(
    (badCount * 10000 * 10000) / (aggregate.sampleCount * budgetRateBasisPoints),
  );

  return {
    ...aggregate,
    badCount,
    successRateBasisPoints,
    errorBudgetConsumedBasisPoints,
    errorBudgetRemainingBasisPoints: Math.max(0, 10000 - errorBudgetConsumedBasisPoints),
    status: successRateBasisPoints >= aggregate.targetBasisPoints ? "on-target" : "below-target",
  };
}

/**
 * Computes independent user-visible capability and dependency objectives from
 * pre-aggregated, bounded observations. The input deliberately has no free-form
 * dimensions and no cross-capability platform total.
 */
export function calculateIndicators(objectives, observations) {
  validateObjectives(objectives);
  requireValue(Array.isArray(observations), "SLI observations must be an array.");

  const capabilities = Object.fromEntries(
    objectives.capabilities.map((row) => [row.id, createAggregate(row.id, row.targetBasisPoints)]),
  );
  const dependencies = Object.fromEntries(
    objectives.dependencies.map((row) => [row.id, createAggregate(row.id, row.targetBasisPoints)]),
  );

  for (const observation of observations) {
    requireExactKeys(
      observation,
      ["capability", "outcome", "dependency"],
      "Invalid SLI observation; only closed, bounded dimensions are accepted.",
    );
    requireValue(
      Object.hasOwn(capabilities, observation.capability),
      "Unknown SLI capability group.",
    );
    requireValue(
      observation.outcome === "good" || observation.outcome === "bad",
      "SLI outcome must be good or bad.",
    );
    requireValue(
      observation.dependency === null || Object.hasOwn(dependencies, observation.dependency),
      "Unknown SLI dependency attribution.",
    );

    const capability = capabilities[observation.capability];
    capability.sampleCount += 1;
    if (observation.outcome === "good") {
      capability.goodCount += 1;
    }

    if (observation.dependency !== null) {
      const dependency = dependencies[observation.dependency];
      dependency.sampleCount += 1;
      if (observation.outcome === "good") {
        dependency.goodCount += 1;
      }
    }
  }

  return {
    windowSeconds: objectives.windowSeconds,
    capabilities: Object.fromEntries(
      Object.entries(capabilities).map(([id, value]) => [id, presentAggregate(value)]),
    ),
    dependencies: Object.fromEntries(
      Object.entries(dependencies).map(([id, value]) => [id, presentAggregate(value)]),
    ),
  };
}

export function validateAlert(alert, routing, runbookPaths, objectives) {
  requireExactKeys(
    alert,
    [
      "schema",
      "id",
      "capabilityGroup",
      "dependencyId",
      "condition",
      "severity",
      "routeClass",
      "runbook",
    ].filter(
      (key) =>
        (key !== "capabilityGroup" && key !== "dependencyId") || Object.hasOwn(alert ?? {}, key),
    ),
    "Invalid alert shape.",
  );
  requireValue(
    alert.schema === "arcforges.cloud.alert.v1" &&
      typeof alert.id === "string" &&
      /^[a-z0-9]+(?:-[a-z0-9]+)*$/.test(alert.id),
    "Invalid alert identity.",
  );
  requireExactKeys(
    alert.condition,
    ["signal", "operator", "threshold", "windowSeconds", "minimumSamples"],
    "Invalid alert condition shape.",
  );
  requireValue(
    ALLOWED_SIGNALS.has(alert.condition.signal) &&
      OPERATORS.has(alert.condition.operator) &&
      Number.isSafeInteger(alert.condition.threshold) &&
      alert.condition.threshold >= 0 &&
      Number.isSafeInteger(alert.condition.windowSeconds) &&
      alert.condition.windowSeconds >= 1 &&
      alert.condition.windowSeconds <= 2592000 &&
      Number.isSafeInteger(alert.condition.minimumSamples) &&
      alert.condition.minimumSamples >= 1,
    `Invalid or unbounded alert condition: ${alert.id}.`,
  );
  if (alert.condition.signal.endsWith("-bp")) {
    requireValue(
      alert.condition.threshold <= 10000,
      `Basis-point threshold is outside its range: ${alert.id}.`,
    );
  }
  requireValue(SEVERITIES.has(alert.severity), `Invalid alert severity: ${alert.id}.`);
  const destination = routeAlert(alert, routing);
  requireValue(
    typeof destination.target === "string" && /^[a-z][a-z0-9-]*$/.test(destination.target),
    `Alert route has no stable logical destination: ${alert.id}.`,
  );
  requireValue(
    typeof alert.runbook === "string" &&
      /^runbooks\/[a-z0-9]+(?:-[a-z0-9]+)*\.md$/.test(alert.runbook) &&
      runbookPaths.has(alert.runbook),
    `Alert does not name an existing indexed runbook: ${alert.id}.`,
  );

  if (alert.capabilityGroup !== undefined) {
    requireValue(
      objectives.capabilities.some((row) => row.id === alert.capabilityGroup),
      `Unknown alert capability group: ${alert.id}.`,
    );
  }
  if (alert.dependencyId !== undefined) {
    requireValue(
      objectives.dependencies.some((row) => row.id === alert.dependencyId),
      `Unknown alert dependency attribution: ${alert.id}.`,
    );
  }
  requireValue(
    alert.capabilityGroup !== undefined || alert.dependencyId !== undefined,
    `Alert must be attributed to a capability or dependency: ${alert.id}.`,
  );

  const capabilitySignal = alert.condition.signal.match(/^capability\.([a-z0-9-]+)\./);
  const dependencySignal = alert.condition.signal.match(/^dependency\.([a-z0-9-]+)\./);
  if (capabilitySignal !== null) {
    requireValue(
      alert.capabilityGroup === capabilitySignal[1],
      `Alert signal and capability attribution differ: ${alert.id}.`,
    );
  }
  if (dependencySignal !== null) {
    requireValue(
      alert.dependencyId === dependencySignal[1],
      `Alert signal and dependency attribution differ: ${alert.id}.`,
    );
  }

  return destination;
}

export function routeAlert(alert, routing) {
  requireValue(
    alert !== null && typeof alert === "object" && ROUTE_CLASSES.has(alert.routeClass),
    "Unknown alert route class.",
  );
  requireValue(
    routing !== null &&
      typeof routing === "object" &&
      routing.schema === "arcforges.cloud.alert-routing.v1" &&
      routing.destinations !== null &&
      typeof routing.destinations === "object" &&
      ROUTE_CLASSES.has(alert.routeClass) &&
      typeof routing.destinations[alert.routeClass] === "string" &&
      routing.destinations[alert.routeClass].length > 0,
    `No logical destination is configured for the ${alert.routeClass} route.`,
  );
  return {
    routeClass: alert.routeClass,
    target: routing.destinations[alert.routeClass],
  };
}

export const monitoringSchema = Object.freeze({
  expectedCapabilities: Object.freeze([...EXPECTED_CAPABILITIES]),
  expectedDependencies: Object.freeze([...EXPECTED_DEPENDENCIES]),
  allowedSignals: Object.freeze([...ALLOWED_SIGNALS]),
  routeClasses: Object.freeze([...ROUTE_CLASSES]),
});

function readJson(root, relativePath) {
  const path = join(root, ...relativePath.split("/"));
  const stat = lstatSync(path);
  requireValue(stat.isFile(), `Monitoring input is not a regular file: ${relativePath}.`);
  return JSON.parse(readFileSync(path, "utf8"));
}

function indexedPaths(index, expectedSchema, folder, extension) {
  requireExactKeys(index, ["schema", "files"], `Invalid ${folder} index shape.`);
  requireValue(
    index.schema === expectedSchema && Array.isArray(index.files),
    `Invalid ${folder} index schema.`,
  );
  const seen = new Set();
  for (const path of index.files) {
    const relativePath = typeof path === "string" ? path.slice(folder.length + 1) : "";
    const extensionless = relativePath.endsWith(extension)
      ? relativePath.slice(0, -extension.length)
      : "";
    requireValue(
      typeof path === "string" &&
        !path.includes("\\") &&
        path.startsWith(`${folder}/`) &&
        extensionless.length > 0 &&
        /^[a-z0-9]+(?:-[a-z0-9]+)*$/.test(extensionless),
      `Invalid ${folder} index path.`,
    );
    requireValue(!seen.has(path), `Unsafe or duplicate ${folder} index path.`);
    seen.add(path);
  }
  return seen;
}

function directoryFiles(root, folder, extension) {
  const directory = join(root, folder);
  requireValue(
    lstatSync(directory).isDirectory(),
    `Monitoring ${folder} path must be a real directory.`,
  );
  return readdirSync(directory, { withFileTypes: true })
    .filter((entry) => entry.name !== "index.json")
    .map((entry) => {
      requireValue(
        entry.isFile(),
        `Unexpected directory or link in monitoring ${folder}: ${entry.name}.`,
      );
      requireValue(
        entry.name.endsWith(extension),
        `Unclassified file in monitoring ${folder}: ${entry.name}.`,
      );
      return `${folder}/${entry.name}`;
    })
    .sort();
}

function validateDashboard(dashboard, objectives) {
  requireExactKeys(
    dashboard,
    [
      "schema",
      "scope",
      "source",
      "windowSeconds",
      "capabilityGroups",
      "dependencyGroups",
      "visibleFields",
      "aggregateAcrossCapabilities",
      "emptyWindowState",
    ],
    "Invalid error-budget dashboard shape.",
  );
  requireValue(
    dashboard.schema === "arcforges.cloud.error-budget-view.v1" &&
      dashboard.scope === "internal-engineering-only" &&
      dashboard.source === "../sli-objectives.json" &&
      dashboard.windowSeconds === objectives.windowSeconds &&
      dashboard.aggregateAcrossCapabilities === false &&
      dashboard.emptyWindowState === "insufficient-data" &&
      Array.isArray(dashboard.capabilityGroups) &&
      Array.isArray(dashboard.dependencyGroups) &&
      Array.isArray(dashboard.visibleFields),
    "Invalid error-budget dashboard semantics.",
  );
  requireValue(
    JSON.stringify(dashboard.capabilityGroups) ===
      JSON.stringify(objectives.capabilities.map((row) => row.id)) &&
      JSON.stringify(dashboard.dependencyGroups) ===
        JSON.stringify(objectives.dependencies.map((row) => row.id)),
    "Error-budget dashboard groups must match the objectives exactly and in order.",
  );
  const requiredFields = new Set([
    "user-visible-success-rate-basis-points",
    "internal-objective-basis-points",
    "error-budget-consumed-basis-points",
    "error-budget-remaining-basis-points",
    "sample-count",
    "dependency-attribution",
  ]);
  requireValue(
    dashboard.visibleFields.length === requiredFields.size &&
      dashboard.visibleFields.every((field) => requiredFields.has(field)),
    "Error-budget dashboard omits or adds a field outside the reviewed view.",
  );
}

/** Loads and validates the complete, indexed monitoring artifact tree. */
export function loadMonitoring(root = fileURLToPath(DEFAULT_MONITORING_ROOT)) {
  const monitoringRoot = resolve(root);
  const objectives = readJson(monitoringRoot, "sli-objectives.json");
  validateObjectives(objectives);

  const routing = readJson(monitoringRoot, "alert-routing.json");
  requireExactKeys(routing, ["schema", "destinations"], "Invalid alert routing shape.");
  requireExactKeys(
    routing.destinations,
    [...ROUTE_CLASSES],
    "Alert routes must explicitly define page, ticket and dashboard destinations.",
  );
  requireValue(
    routing.schema === "arcforges.cloud.alert-routing.v1" &&
      [...ROUTE_CLASSES].every(
        (route) =>
          typeof routing.destinations[route] === "string" &&
          /^[a-z][a-z0-9-]*$/.test(routing.destinations[route]),
      ) &&
      new Set(Object.values(routing.destinations)).size === ROUTE_CLASSES.size,
    "Invalid or ambiguous logical alert destinations.",
  );

  const dashboard = readJson(monitoringRoot, "dashboard/error-budget.json");
  validateDashboard(dashboard, objectives);

  const alertIndex = readJson(monitoringRoot, "alerts/index.json");
  const alertPaths = indexedPaths(alertIndex, "arcforges.cloud.alert-index.v1", "alerts", ".json");
  const actualAlertPaths = new Set(
    directoryFiles(monitoringRoot, "alerts", ".json").filter(
      (path) => path !== "alerts/index.json",
    ),
  );
  requireValue(
    alertPaths.size === actualAlertPaths.size &&
      [...actualAlertPaths].every((path) => alertPaths.has(path)),
    "Alert index does not exactly classify the monitor files.",
  );

  const runbookIndex = readJson(monitoringRoot, "runbooks/index.json");
  const runbookPaths = indexedPaths(
    runbookIndex,
    "arcforges.cloud.monitoring-runbook-index.v1",
    "runbooks",
    ".md",
  );
  const actualRunbookPaths = new Set(directoryFiles(monitoringRoot, "runbooks", ".md"));
  requireValue(
    runbookPaths.size === actualRunbookPaths.size &&
      [...actualRunbookPaths].every((path) => runbookPaths.has(path)),
    "Runbook index does not exactly classify the runbook files.",
  );

  const alerts = [];
  for (const path of alertPaths) {
    const alert = readJson(monitoringRoot, path);
    requireValue(
      path === `alerts/${alert.id}.json`,
      `Alert file path and identifier differ: ${path}.`,
    );
    validateAlert(alert, routing, runbookPaths, objectives);
    alerts.push(alert);
  }
  requireValue(
    alerts.length === REQUIRED_PAGE_ALERTS.size &&
      alerts.every((alert) => REQUIRED_PAGE_ALERTS.has(alert.id) && alert.routeClass === "page") &&
      [...REQUIRED_PAGE_ALERTS].every((id) => alerts.some((alert) => alert.id === id)),
    "The page-worthy alert set differs from the reviewed AL-02 catalogue.",
  );

  for (const path of runbookPaths) {
    const runbookFile = join(monitoringRoot, ...path.split("/"));
    const stat = lstatSync(runbookFile);
    requireValue(stat.isFile(), `Indexed runbook does not exist: ${path}.`);
    const content = readFileSync(runbookFile, "utf8");
    requireValue(
      [
        "## Preconditions",
        "## Decisions",
        "## Steps",
        "## Verification",
        "## Rollback and escalation",
      ].every((heading) => content.includes(heading)) &&
        content.includes("Rehearsal status: not recorded here; OPS.03 owns runbook rehearsal") &&
        !/\b(?:TODO|TBD|lorem ipsum)\b/i.test(content),
      `Runbook is incomplete or claims an unrecorded rehearsal: ${path}.`,
    );
  }

  return {
    objectives,
    routing,
    dashboard,
    alerts,
    alertPaths,
    runbookPaths,
  };
}
