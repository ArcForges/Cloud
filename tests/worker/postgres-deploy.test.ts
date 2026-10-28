// SPDX-License-Identifier: AGPL-3.0-only
// Offline checks of the PostgreSQL deployment step (tooling/postgres-deploy.ts) and of the center's provisioning targets
// (eng/verification/center-provision.ts): the sealed executable receives credentials by variable name only, promotion requires
// the passed gate record of exactly its target and revision, production and acceptance never share a database or a runtime
// role, and the production resources are refused outside AF-PROD-01.
import assert from "node:assert/strict";
import test from "node:test";
import {
  centerEntrypoint,
  centerVariables,
  directUrlSecret,
  dockerArguments,
  postgresTargets,
  requirePostgresGate,
} from "../../tooling/postgres-deploy.ts";
import {
  centerLifecycle,
  centerResources,
  provisionCenter,
} from "../../eng/verification/center-provision.ts";

const secret =
  "postgresql://owner:synthetic-secret@ep-a-1.eu-central-1.aws.neon.tech/neondb?sslmode=require&channel_binding=require";

test("the executable reads the migration URL from the deployment secret, and the targets never share a database or a role", () => {
  assert.equal(directUrlSecret, "NEON_DATABASE_URL_DIRECT");
  assert.throws(() => centerVariables("production", {}), /NEON_DATABASE_URL_DIRECT/u);
  const production = centerVariables("production", { [directUrlSecret]: secret });
  assert.deepEqual(production, {
    ARCFORGES_CENTER_MODE: "official-hosted",
    ARCFORGES_CENTER_MIGRATION_DATABASE_URL: secret,
    ARCFORGES_CENTER_RUNTIME_ROLE: "arcforges_center_runtime",
  });
  const acceptance = centerVariables("acceptance", { [directUrlSecret]: secret });
  assert.equal(acceptance.ARCFORGES_CENTER_DATABASE_NAME, "arcforges_acceptance");
  assert.equal(acceptance.ARCFORGES_CENTER_RUNTIME_ROLE, "arcforges_acceptance_runtime");
  assert.notEqual(postgresTargets.production.runtimeRole, postgresTargets.acceptance.runtimeRole);
  assert.equal(
    postgresTargets.production.ensureDatabase,
    false,
    "production never creates its database here",
  );
  for (const settings of Object.values(postgresTargets))
    assert.match(settings.runtimeRole, /^[a-z][a-z0-9_]{2,40}$/u);
});

test("docker receives variable names only, and the container is locked down", () => {
  const variables = centerVariables("acceptance", { [directUrlSecret]: secret });
  const args = dockerArguments("arcforges-cloud:ci.1", Object.keys(variables), ["migrate"]);
  assert(!args.join(" ").includes("synthetic-secret"), "a credential reached the command line");
  for (const name of Object.keys(variables)) assert(args.includes(name));
  assert.equal(args.filter((value) => value.includes("=")).length, 0);
  for (const flag of ["--read-only", "--rm", "no-new-privileges"])
    assert(args.includes(flag), flag);
  assert.deepEqual(args.slice(args.indexOf("--cap-drop"), args.indexOf("--cap-drop") + 2), [
    "--cap-drop",
    "ALL",
  ]);
  assert.deepEqual(args.slice(-4), [
    "--entrypoint",
    centerEntrypoint,
    "arcforges-cloud:ci.1",
    "migrate",
  ]);
  const rotation = dockerArguments("image", ["A"], ["admin", "rotate-runtime-credential"], {
    secretsDirectory: "/tmp/arcforges-runtime-x",
    user: "1001:1001",
  });
  assert(rotation.includes("/tmp/arcforges-runtime-x:/secrets"));
  assert.deepEqual(rotation.slice(rotation.indexOf("--user"), rotation.indexOf("--user") + 2), [
    "--user",
    "1001:1001",
  ]);
  assert.throws(() => dockerArguments("image", ["a=b"], ["migrate"]));
  assert.throws(() =>
    dockerArguments("image", ["A"], ["migrate"], { secretsDirectory: "relative" }),
  );
});

test("promotion requires the passed PostgreSQL gate of exactly its target and revision", () => {
  const revision = "a".repeat(40);
  const passed = { target: "production" as const, revision, status: "passed" as const };
  assert.doesNotThrow(() => requirePostgresGate(passed, "production", revision));
  assert.throws(() => requirePostgresGate(undefined, "production", revision), /did not run/u);
  assert.throws(
    () => requirePostgresGate({ ...passed, status: "failed" }, "production", revision),
    /did not pass/u,
  );
  assert.throws(() => requirePostgresGate(passed, "acceptance", revision));
  assert.throws(() => requirePostgresGate(passed, "production", "b".repeat(40)));
});

test("the center's resources: acceptance only, with the declared lifecycle", async () => {
  await assert.rejects(
    provisionCenter(
      {
        account: "0".repeat(32),
        request: () => assert.fail("no request"),
        accountPath: (rest) => rest,
      },
      "production",
    ),
    /AF-PROD-01/u,
  );
  assert.notEqual(centerResources.acceptance.bucket, centerResources.production.bucket);
  for (const queue of centerResources.acceptance.queues)
    assert(!centerResources.production.queues.includes(queue));
  assert.deepEqual(
    centerLifecycle.map((rule) => [rule.id, rule.conditions.prefix]),
    [
      ["support-bundles-30-days", "support-bundles/"],
      ["abort-incomplete-uploads", ""],
    ],
  );
  assert.equal(centerLifecycle[0]?.deleteObjectsTransition?.condition.maxAge, 30 * 24 * 60 * 60);
});
