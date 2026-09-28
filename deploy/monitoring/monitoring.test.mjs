import assert from "node:assert/strict";
import { cpSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { fileURLToPath } from "node:url";
import test from "node:test";
import {
  calculateIndicators,
  loadMonitoring,
  monitoringSchema,
  routeAlert,
  validateAlert,
} from "./sli.mjs";

const MONITORING_ROOT = fileURLToPath(new URL(".", import.meta.url));
const policy = loadMonitoring();

test("capability objectives are user-visible, bounded and independent", () => {
  assert.deepEqual(
    new Set(policy.objectives.capabilities.map((row) => row.id)),
    new Set(["cloud-api", "identity", "sync-control-plane", "realtime", "managed-ai"]),
  );
  assert.equal(policy.objectives.scope, "internal-engineering-objectives");
  assert.equal(policy.dashboard.aggregateAcrossCapabilities, false);
  assert.equal(policy.objectives.windowSeconds, 30 * 24 * 60 * 60);
  assert.equal(Object.hasOwn(calculateIndicators(policy.objectives, []), "platform"), false);
});

test("synthetic user-visible failures burn only their capability and dependency budgets", () => {
  const result = calculateIndicators(policy.objectives, [
    { capability: "cloud-api", outcome: "good", dependency: null },
    { capability: "identity", outcome: "good", dependency: "identity-delivery" },
    { capability: "sync-control-plane", outcome: "good", dependency: null },
    { capability: "realtime", outcome: "bad", dependency: "realtime-transport" },
    { capability: "managed-ai", outcome: "bad", dependency: "managed-ai-provider" },
  ]);

  assert.equal(result.capabilities["cloud-api"].successRateBasisPoints, 10000);
  assert.equal(result.capabilities.identity.successRateBasisPoints, 10000);
  assert.equal(result.capabilities["sync-control-plane"].successRateBasisPoints, 10000);
  assert.equal(result.capabilities.realtime.successRateBasisPoints, 0);
  assert.equal(result.capabilities["managed-ai"].successRateBasisPoints, 0);
  assert.equal(result.dependencies["realtime-transport"].badCount, 1);
  assert.equal(result.dependencies["managed-ai-provider"].badCount, 1);
  assert.equal(result.dependencies["identity-delivery"].goodCount, 1);
  assert.equal(result.dependencies["primary-database"].status, "insufficient-data");
});

test("error-budget visibility uses exact objective math and does not hide over-budget burn", () => {
  const observations = [
    ...Array.from({ length: 998 }, () => ({
      capability: "cloud-api",
      outcome: "good",
      dependency: null,
    })),
    ...Array.from({ length: 2 }, () => ({
      capability: "cloud-api",
      outcome: "bad",
      dependency: null,
    })),
  ];
  const measured = calculateIndicators(policy.objectives, observations).capabilities["cloud-api"];

  assert.equal(measured.sampleCount, 1000);
  assert.equal(measured.successRateBasisPoints, 9980);
  assert.equal(measured.targetBasisPoints, 9990);
  assert.equal(measured.errorBudgetConsumedBasisPoints, 20000);
  assert.equal(measured.errorBudgetRemainingBasisPoints, 0);
  assert.equal(measured.status, "below-target");

  const empty = calculateIndicators(policy.objectives, []).capabilities.identity;
  assert.equal(empty.status, "insufficient-data");
  assert.equal(empty.successRateBasisPoints, null);
  assert.equal(empty.errorBudgetConsumedBasisPoints, null);
});

test("closed SLI dimensions reject unknown groups, secret-like labels and extra fields", () => {
  assert.throws(
    () =>
      calculateIndicators(policy.objectives, [
        { capability: "all-platform", outcome: "bad", dependency: null },
      ]),
    /Unknown SLI capability group/,
  );
  assert.throws(
    () =>
      calculateIndicators(policy.objectives, [
        {
          capability: "identity",
          outcome: "bad",
          dependency: "https://token.invalid/secret",
        },
      ]),
    /Unknown SLI dependency attribution/,
  );
  assert.throws(
    () =>
      calculateIndicators(policy.objectives, [
        {
          capability: "identity",
          outcome: "good",
          dependency: null,
          userId: "private-marker",
        },
      ]),
    /closed, bounded dimensions/,
  );
  assert.throws(
    () =>
      calculateIndicators(policy.objectives, [
        { capability: "identity", outcome: "maybe", dependency: null },
      ]),
    /outcome must be good or bad/,
  );
});

test("the alert set is complete, page-routed and every link resolves to an indexed file", () => {
  const expected = new Set([
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
  assert.deepEqual(new Set(policy.alerts.map((alert) => alert.id)), expected);
  assert.equal(policy.alerts.length, expected.size);
  for (const alert of policy.alerts) {
    assert.equal(alert.routeClass, "page");
    assert.equal(policy.runbookPaths.has(alert.runbook), true);
    assert.equal(routeAlert(alert, policy.routing).target, policy.routing.destinations.page);
  }
});

test("page, ticket and dashboard classes resolve only to distinct logical destinations", () => {
  assert.deepEqual(monitoringSchema.routeClasses, ["page", "ticket", "dashboard"]);
  for (const routeClass of monitoringSchema.routeClasses) {
    assert.equal(
      routeAlert({ routeClass }, policy.routing).target,
      policy.routing.destinations[routeClass],
    );
  }
  assert.equal(new Set(Object.values(policy.routing.destinations)).size, 3);
  assert.throws(
    () => routeAlert({ routeClass: "email-everyone" }, policy.routing),
    /Unknown alert route class/,
  );
});

test("invalid alert routes and missing runbooks fail closed", () => {
  const alert = policy.alerts[0];
  assert.throws(
    () =>
      validateAlert(
        { ...alert, routeClass: "email-everyone" },
        policy.routing,
        policy.runbookPaths,
        policy.objectives,
      ),
    /Unknown alert route class/,
  );
  assert.throws(
    () =>
      validateAlert(
        { ...alert, runbook: "runbooks/not-present.md" },
        policy.routing,
        policy.runbookPaths,
        policy.objectives,
      ),
    /existing indexed runbook/,
  );
  assert.throws(
    () =>
      validateAlert(
        { ...alert, runbook: "../README.md" },
        policy.routing,
        policy.runbookPaths,
        policy.objectives,
      ),
    /existing indexed runbook/,
  );
  assert.throws(
    () =>
      validateAlert(
        { ...alert, condition: { ...alert.condition, signal: "capability.user.secret" } },
        policy.routing,
        policy.runbookPaths,
        policy.objectives,
      ),
    /Invalid or unbounded alert condition/,
  );
});

function copiedMonitoringTree() {
  const temporaryRoot = mkdtempSync(join(tmpdir(), "ops01-monitoring-"));
  const copy = join(temporaryRoot, "monitoring");
  mkdirSync(copy);
  cpSync(MONITORING_ROOT, copy, { recursive: true });
  return {
    root: copy,
    cleanup: () => rmSync(temporaryRoot, { recursive: true, force: true }),
  };
}

test("deleting an alert target or index entry is detected", () => {
  const fixture = copiedMonitoringTree();
  try {
    const runbook = policy.alerts[0].runbook;
    rmSync(join(fixture.root, ...runbook.split("/")));
    assert.throws(() => loadMonitoring(fixture.root), /Runbook index does not exactly classify/);
  } finally {
    fixture.cleanup();
  }

  const secondFixture = copiedMonitoringTree();
  try {
    const indexPath = join(secondFixture.root, "alerts", "index.json");
    const index = JSON.parse(readFileSync(indexPath, "utf8"));
    index.files.pop();
    writeFileSync(indexPath, JSON.stringify(index));
    assert.throws(
      () => loadMonitoring(secondFixture.root),
      /Alert index does not exactly classify/,
    );
  } finally {
    secondFixture.cleanup();
  }
});

test("duplicate index entries and unindexed runbooks are rejected", () => {
  const fixture = copiedMonitoringTree();
  try {
    const indexPath = join(fixture.root, "alerts", "index.json");
    const index = JSON.parse(readFileSync(indexPath, "utf8"));
    index.files.push(index.files[0]);
    writeFileSync(indexPath, JSON.stringify(index));
    assert.throws(() => loadMonitoring(fixture.root), /duplicate alerts index path/);
  } finally {
    fixture.cleanup();
  }

  const secondFixture = copiedMonitoringTree();
  try {
    writeFileSync(join(secondFixture.root, "runbooks", "unindexed-runbook.md"), "# Unindexed\n");
    assert.throws(
      () => loadMonitoring(secondFixture.root),
      /Runbook index does not exactly classify/,
    );
  } finally {
    secondFixture.cleanup();
  }
});
