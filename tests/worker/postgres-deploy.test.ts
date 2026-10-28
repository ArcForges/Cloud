// SPDX-License-Identifier: AGPL-3.0-only
// Offline checks of the PostgreSQL deployment step (tooling/postgres-deploy.ts) and of the center's provisioning targets
// (eng/verification/center-provision.ts): the sealed executable receives credentials by variable name only, promotion requires
// the passed gate record of exactly its target and revision, production and acceptance never share a database or a runtime
// role, the runtime credential's slot is confirmed only after a successful promotion, and the production resources are refused
// outside AF-PROD-01.
import assert from "node:assert/strict";
import { existsSync, readFileSync } from "node:fs";
import { writeFile } from "node:fs/promises";
import path from "node:path";
import test from "node:test";
import {
  type CenterRunner,
  centerEntrypoint,
  centerVariables,
  directUrlSecret,
  dockerArguments,
  postgresTargets,
  requirePostgresGate,
  withRuntimeCredential,
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

/** A fake of the sealed executable: rotate writes the secret file, confirm fails as told. */
function fakeCenter(confirmFailures: number) {
  const calls: string[][] = [];
  const directories: string[] = [];
  let failures = confirmFailures;
  const runner: CenterRunner = async (_image, variables, command, options) => {
    calls.push(command);
    assert.equal(
      variables[directUrlSecret],
      undefined,
      "the deployment secret is passed under the executable's own name",
    );
    if (command[1] === "rotate-runtime-credential") {
      assert(options?.secretsDirectory);
      directories.push(options.secretsDirectory);
      await writeFile(
        path.join(options.secretsDirectory, "runtime.json"),
        JSON.stringify({ ARCFORGES_CENTER_DATABASE_URL: "postgresql://synthetic-runtime" }),
      );
      return { slot: "b", loginRole: "arcforges_center_runtime_b" };
    }
    assert.deepEqual(command, ["admin", "confirm-runtime-credential", "--slot", "b"]);
    if (failures-- > 0)
      throw new Error(
        "arcforges-center admin confirm-runtime-credential --slot b exited with code 1.",
      );
    return { slot: "b", promotedAt: "2026-10-28T00:00:00Z" };
  };
  return { runner, calls, directories };
}

const environment = { [directUrlSecret]: secret };

test("the slot is confirmed as promoted only after the deployment succeeded", async () => {
  const fake = fakeCenter(0);
  const published: Record<string, string>[] = [];
  const rotation = await withRuntimeCredential(
    "production",
    "image",
    async (secrets) => {
      published.push(secrets);
      assert.equal(fake.calls.length, 1, "nothing is confirmed before the deployment finished");
    },
    { runner: fake.runner, environment, confirmDelayMs: 1 },
  );
  assert.deepEqual(fake.calls, [
    ["admin", "rotate-runtime-credential"],
    ["admin", "confirm-runtime-credential", "--slot", "b"],
  ]);
  assert.deepEqual(published, [
    { ARCFORGES_CENTER_DATABASE_URL: "postgresql://synthetic-runtime" },
  ]);
  assert.equal(rotation.slot, "b");
  assert.equal(rotation.promotedAt, "2026-10-28T00:00:00Z");
  assert(!existsSync(fake.directories[0] ?? ""), "the runner-local secret directory is removed");
});

test("a failed deployment leaves its slot unconfirmed, so the retry rotates that slot again", async () => {
  const fake = fakeCenter(0);
  await assert.rejects(
    withRuntimeCredential(
      "acceptance",
      "image",
      async () => {
        throw new Error("wrangler deploy failed");
      },
      { runner: fake.runner, environment, confirmDelayMs: 1 },
    ),
    /wrangler deploy failed/u,
  );
  assert.deepEqual(fake.calls, [["admin", "rotate-runtime-credential"]]);
  assert(!existsSync(fake.directories[0] ?? ""));
});

test("a confirmation is retried, and one that keeps failing names the slot, the state and the recovery", async () => {
  const flaky = fakeCenter(1);
  const rotation = await withRuntimeCredential("production", "image", async () => {}, {
    runner: flaky.runner,
    environment,
    confirmDelayMs: 1,
  });
  assert.equal(rotation.promotedAt, "2026-10-28T00:00:00Z");
  assert.equal(
    flaky.calls.filter((command) => command[1] === "confirm-runtime-credential").length,
    2,
  );
  const failing = fakeCenter(10);
  let published = 0;
  await assert.rejects(
    withRuntimeCredential(
      "acceptance",
      "image",
      async () => {
        published++;
      },
      { runner: failing.runner, environment, confirmAttempts: 3, confirmDelayMs: 1 },
    ),
    (error: Error) => {
      for (const expected of [
        /slot b/u,
        /behind the live revision/u,
        /confirm-runtime-credential --slot b/u,
        /ARCFORGES_CENTER_RUNTIME_ROLE=arcforges_acceptance_runtime/u,
        /ARCFORGES_CENTER_DATABASE_NAME=arcforges_acceptance/u,
        /after 3 attempts/u,
      ])
        assert.match(error.message, expected);
      assert(
        !error.message.includes("synthetic-secret"),
        "the recovery message quotes no credential",
      );
      return true;
    },
  );
  assert.equal(published, 1);
  assert.equal(
    failing.calls.filter((command) => command[1] === "confirm-runtime-credential").length,
    3,
  );
});

test("both deployments promote inside the rotation, which confirms the slot afterwards", () => {
  for (const file of ["tooling/cloudflare.ts", "eng/verification/proof-cloudflare.ts"]) {
    const source = readFileSync(path.resolve(import.meta.dirname, "../..", file), "utf8");
    const start = source.indexOf("withRuntimeCredential(");
    assert(start > 0, `${file} rotates through withRuntimeCredential`);
    const callback = source.slice(start, source.indexOf("\n  });\n", start));
    assert.match(
      callback,
      /"deploy"|deployArguments/u,
      `${file} runs wrangler deploy inside the rotation`,
    );
    assert(
      !source.includes("confirm-runtime-credential"),
      `${file} confirms only through withRuntimeCredential`,
    );
  }
});
