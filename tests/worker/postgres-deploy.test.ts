// SPDX-License-Identifier: AGPL-3.0-only
// Offline checks of the PostgreSQL deployment step (tooling/postgres-deploy.ts) and of the center's provisioning targets
// (eng/verification/center-provision.ts): the sealed executable receives credentials by variable name only, promotion requires
// the passed gate record of exactly its target and revision, production and acceptance never share a database or a runtime
// role, the runtime credential's slot is confirmed only after a successful promotion, and the production resources are refused
// outside AF-PROD-01.
import assert from "node:assert/strict";
import { execFileSync, spawnSync } from "node:child_process";
import { existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { writeFile } from "node:fs/promises";
import path from "node:path";
import test from "node:test";
import {
  type CenterRunner,
  centerEntrypoint,
  centerVariables,
  directUrlSecret,
  dockerArguments,
  migrateTarget,
  CenterExit,
  checkHelloCredential,
  postgresTargets,
  readLiveSlots,
  recordMigration,
  requirePostgresGate,
  slotLabel,
  slotOfMessage,
  unknownSlotStatus,
  withRuntimeCredential,
} from "../../tooling/postgres-deploy.ts";
import { scratchDirectory } from "./support/scratch.ts";
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
function fakeCenter(
  confirmFailures: number,
  confirmed: string[] = [],
  neverRotated: string[] = [],
) {
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
      // Named the live slot, the executable takes the other one; otherwise its record says b.
      const slot = command[2] === "--live-slot" ? (command[3] === "a" ? "b" : "a") : "b";
      return { slot, loginRole: `arcforges_center_runtime_${slot}` };
    }
    assert.equal(command.slice(0, 3).join(" "), "admin confirm-runtime-credential --slot");
    const slot = command[3];
    if (neverRotated.includes(String(slot)))
      throw new CenterExit(
        `arcforges-center admin confirm-runtime-credential --slot ${slot} exited with code 4.`,
        unknownSlotStatus,
      );
    if (failures-- > 0)
      throw new Error(
        `arcforges-center admin confirm-runtime-credential --slot ${slot} exited with code 1.`,
      );
    return {
      slot,
      promotedAt: "2026-10-28T00:00:00Z",
      alreadyConfirmed: confirmed.includes(String(slot)),
    };
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
  assert.equal(slotOfMessage(`${slotLabel("a")} proof-command-key=proof-test`), "a");
  assert.equal(slotOfMessage(`${slotLabel("b")} proof-command-key=proof-test`), "b");
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
    assert.match(
      callback,
      /"--message",\s*(?:slotLabel\(|`\$\{slotLabel\()/u,
      `${file} labels the new version with its runtime slot`,
    );
    if (file === "eng/verification/proof-cloudflare.ts") {
      assert.match(
        source,
        /liveSlots: proofSlots/u,
        "proof uses its fail-closed live-version check",
      );
      assert.match(source, /readProofLiveSlots\(/u, "proof reads and checks live versions");
      assert(
        source.indexOf("await proofSlots()") < source.indexOf("await withProofCommandKey("),
        "proof checks live slots before key registration",
      );
    } else {
      assert.match(
        source,
        /liveSlots: \(\) =>\s*readLiveSlots\(/u,
        `${file} reads the live slots before rotating`,
      );
    }
  }
});

test("the gate record carries the migration's result and the server's version number", () => {
  const record = {
    target: "production" as const,
    revision: "a".repeat(40),
    status: "failed" as const,
  };
  const result = {
    state: "current",
    grants: "reconciled",
    database: "neondb",
    version: 1,
    runtimeRole: "arcforges_center_runtime",
    serverVersionNum: 180004,
    testedMajor: 18,
    serverMajorMatchesTested: true,
    logging: { pgStatStatementsTrack: "top", logStatement: "none", logMinDurationStatement: "-1" },
    ran: [{ name: "0001_platform_store.sql" }],
  };
  assert.throws(
    () => recordMigration({ ...record }, { ...result, serverVersionNum: undefined }),
    /server version/u,
  );
  assert.throws(() => recordMigration({ ...record }, { ...result, state: "pending" }));
  const passed: Parameters<typeof recordMigration>[0] = { ...record };
  recordMigration(passed, result);
  assert.deepEqual(passed, {
    ...record,
    status: "passed",
    database: "neondb",
    version: 1,
    runtimeRole: "arcforges_center_runtime",
    serverVersionNum: 180004,
    testedMajor: 18,
    serverMajorMatchesTested: true,
    logging: { pgStatStatementsTrack: "top", logStatement: "none", logMinDurationStatement: "-1" },
    applied: ["0001_platform_store.sql"],
  });
  // Another major passes with a warning.
  const other: Parameters<typeof recordMigration>[0] = { ...record };
  recordMigration(other, { ...result, serverVersionNum: 170006, serverMajorMatchesTested: false });
  assert.equal(other.status, "passed");
  assert.deepEqual(other.warnings, [
    "the server's PostgreSQL major 17 differs from the tested major 18",
  ]);
});

/** A fake Wrangler: the live deployment's versions and each version's message, as `--json` prints them. */
function fakeWrangler(versions: { id: string; percentage: number; message?: string }[] | Error) {
  const calls: string[][] = [];
  const reader = async (args: string[]) => {
    calls.push(args);
    if (versions instanceof Error) throw versions;
    if (args[0] === "deployments")
      return JSON.stringify({
        id: "d",
        versions: versions.map((version) => ({
          version_id: version.id,
          percentage: version.percentage,
        })),
      });
    const version = versions.find((entry) => entry.id === args[2]);
    assert(version);
    return JSON.stringify({
      id: version.id,
      annotations: version.message === undefined ? {} : { "workers/message": version.message },
    });
  };
  return { reader, calls };
}

const versionA = "0d6d1f5c-0000-4000-8000-00000000000a";
const versionB = "0d6d1f5c-0000-4000-8000-00000000000b";

test("the live versions' slots are read from Wrangler's JSON, and a failure falls back", async () => {
  assert.equal(slotLabel("b"), "runtime-slot=b");
  assert.equal(slotOfMessage("runtime-slot=a"), "a");
  assert.equal(slotOfMessage("release 1 runtime-slot=b"), "b");
  assert.equal(slotOfMessage("runtime-slot=c"), undefined);
  const config = ["--config", "artifacts/deploy.wrangler.json", "--env", ""];
  const labelled = fakeWrangler([{ id: versionB, percentage: 100, message: "runtime-slot=b" }]);
  assert.deepEqual(await readLiveSlots(labelled.reader, config), {
    labelled: ["b"],
    unlabelled: 0,
  });
  assert.deepEqual(labelled.calls, [
    ["deployments", "status", "--json", ...config],
    ["versions", "view", versionB, "--json", ...config],
  ]);
  const unlabelled = fakeWrangler([{ id: versionA, percentage: 100 }]);
  assert.deepEqual(await readLiveSlots(unlabelled.reader, config), { labelled: [], unlabelled: 1 });
  const unreadable = await readLiveSlots(
    fakeWrangler(new Error("wrangler exited with code 1.")).reader,
    config,
  );
  assert.match(unreadable.unreadable ?? "", /exited with code 1/u);
});

test("a labelled live slot behind the record is confirmed first, then the other slot is rotated", async () => {
  const fake = fakeCenter(0);
  const wrangler = fakeWrangler([{ id: versionB, percentage: 100, message: "runtime-slot=b" }]);
  const lines: string[] = [];
  const labels: string[] = [];
  const rotation = await withRuntimeCredential(
    "production",
    "image",
    async (_secrets, rotated) => {
      labels.push(slotLabel(String(rotated.slot)));
    },
    {
      runner: fake.runner,
      environment,
      confirmDelayMs: 1,
      liveSlots: () => readLiveSlots(wrangler.reader, []),
      log: (line) => lines.push(line),
    },
  );
  assert.deepEqual(fake.calls, [
    ["admin", "confirm-runtime-credential", "--slot", "b"],
    ["admin", "rotate-runtime-credential", "--live-slot", "b"],
    ["admin", "confirm-runtime-credential", "--slot", "a"],
  ]);
  assert.equal(rotation.slot, "a");
  assert.deepEqual(labels, ["runtime-slot=a"], "the new version is labelled with its slot");
  assert(lines.some((line) => /uses runtime slot b/u.test(line)));
  assert(
    lines.some((line) => /recorded the live slot b as promoted/u.test(line)),
    "the self-heal is logged",
  );
});

test("an unlabelled or unreadable live version leaves the slot to the record, and says so", async () => {
  for (const versions of [[{ id: versionA, percentage: 100 }], new Error("no deployments")]) {
    const fake = fakeCenter(0);
    const lines: string[] = [];
    const wrangler = fakeWrangler(versions);
    await withRuntimeCredential("acceptance", "image", async () => {}, {
      runner: fake.runner,
      environment,
      confirmDelayMs: 1,
      liveSlots: () => readLiveSlots(wrangler.reader, []),
      log: (line) => lines.push(line),
    });
    assert.deepEqual(fake.calls, [
      ["admin", "rotate-runtime-credential"],
      ["admin", "confirm-runtime-credential", "--slot", "b"],
    ]);
    assert(
      lines.some((line) => /follows the database record/u.test(line)),
      lines.join(" "),
    );
  }
});

test("live versions on both slots, or on a slot and an unlabelled credential, refuse the rotation", async () => {
  for (const versions of [
    [
      { id: versionA, percentage: 60, message: "runtime-slot=a" },
      { id: versionB, percentage: 40, message: "runtime-slot=b" },
    ],
    [
      { id: versionA, percentage: 60 },
      { id: versionB, percentage: 40, message: "runtime-slot=b" },
    ],
  ]) {
    const fake = fakeCenter(0);
    const wrangler = fakeWrangler(versions);
    let published = 0;
    await assert.rejects(
      withRuntimeCredential(
        "production",
        "image",
        async () => {
          published++;
        },
        {
          runner: fake.runner,
          environment,
          liveSlots: () => readLiveSlots(wrangler.reader, []),
          log: () => {},
        },
      ),
      /gradual rollout/u,
    );
    assert.deepEqual(fake.calls, [], "no slot was confirmed or rotated");
    assert.equal(published, 0);
  }
});

test("the C# Hello's credential must name the migration role before PUBLIC's CONNECT is revoked", () => {
  const hello =
    "postgresql://owner:synthetic-secret@ep-a-1-pooler.eu-central-1.aws.neon.tech/neondb?sslmode=require&channel_binding=require";
  assert.deepEqual(checkHelloCredential("production", { [directUrlSecret]: secret }), {
    status: "skipped",
    reason: "NEON_DATABASE_URL is not set for this step; nothing to compare",
  });
  const same = checkHelloCredential("production", {
    [directUrlSecret]: secret,
    NEON_DATABASE_URL: hello,
  });
  assert.equal(same.status, "same-role");
  assert.equal(same.sameDatabase, true);
  const other = hello.replace("owner:", "reader:");
  for (const target of ["production", "acceptance"] as const)
    assert.throws(
      () => checkHelloCredential(target, { [directUrlSecret]: secret, NEON_DATABASE_URL: other }),
      (error: Error) => {
        assert.match(error.message, /Point NEON_DATABASE_URL at the migration \(owner\) role/u);
        assert(
          !/GRANT CONNECT/u.test(error.message),
          "no remedy that the check could never accept",
        );
        for (const value of ["synthetic-secret", "reader", "ep-a-1", "neondb"])
          assert(!error.message.includes(value), `the refusal quotes ${value}`);
        return true;
      },
    );
  // Acceptance has its own database: only the role is compared.
  const acceptance = checkHelloCredential("acceptance", {
    [directUrlSecret]: secret,
    NEON_DATABASE_URL: hello.replace("/neondb", "/elsewhere"),
  });
  assert.equal(acceptance.status, "same-role");
  assert.equal(acceptance.sameDatabase, undefined);
});

test("a live slot this database never rotated is not self-healed: the other slot is rotated, once, with its own reason", async () => {
  const fake = fakeCenter(0, [], ["b"]);
  const wrangler = fakeWrangler([{ id: versionB, percentage: 100, message: "runtime-slot=b" }]);
  const lines: string[] = [];
  const rotation = await withRuntimeCredential("acceptance", "image", async () => {}, {
    runner: fake.runner,
    environment,
    confirmDelayMs: 1,
    liveSlots: () => readLiveSlots(wrangler.reader, []),
    log: (line) => lines.push(line),
  });
  assert.deepEqual(fake.calls, [
    ["admin", "confirm-runtime-credential", "--slot", "b"],
    ["admin", "rotate-runtime-credential", "--live-slot", "b"],
    ["admin", "confirm-runtime-credential", "--slot", "a"],
  ]);
  assert.equal(rotation.slot, "a");
  assert(
    lines.some(
      (line) =>
        /record has no row for the live version's slot b/u.test(line) &&
        /cannot be confirmed/u.test(line),
    ),
    lines.join(" "),
  );
  assert(
    !lines.some((line) => /behind the live version/u.test(line)),
    "no post-promotion recovery text",
  );
});

test("a restore that left the record without the live slot is handled like a new database", async () => {
  // Live version labelled b; the restored record holds a only, so confirming b exits with status 4.
  const fake = fakeCenter(0, ["a"], ["b"]);
  const wrangler = fakeWrangler([{ id: versionB, percentage: 100, message: "runtime-slot=b" }]);
  const lines: string[] = [];
  const rotation = await withRuntimeCredential("production", "image", async () => {}, {
    runner: fake.runner,
    environment,
    confirmDelayMs: 1,
    liveSlots: () => readLiveSlots(wrangler.reader, []),
    log: (line) => lines.push(line),
  });
  assert.equal(rotation.slot, "a");
  assert.equal(
    fake.calls.filter(
      (command) => command.join(" ") === "admin confirm-runtime-credential --slot b",
    ).length,
    1,
  );
  assert(lines.some((line) => /record has no row for the live version's slot b/u.test(line)));
});

test("phase 1 refuses deployment before loading a candidate or handing out credentials", async () => {
  for (const target of ["production", "acceptance"] as const)
    await assert.rejects(
      () => migrateTarget(target),
      /security bridge successor is not yet bound/u,
    );
});

test("the actual deployment CLI refuses before candidate, child or gate-file effects", async (t) => {
  const directory = scratchDirectory("ctr06-phase1-deploy-", t);
  const repository = path.resolve(import.meta.dirname, "../..");
  const preload = path.join(directory, "preload.mjs");
  await writeFile(
    preload,
    `
import { mock } from "node:test";
import { writeFileSync } from "node:fs";
import { pathToFileURL } from "node:url";
import path from "node:path";
const source = process.env.CTR06_GATE_SOURCE;
const scratch = process.env.CTR06_GATE_SCRATCH;
const child = await import("node:child_process");
mock.module("node:child_process", { namedExports: { ...child, spawn: () => {
  writeFileSync(path.join(scratch, "child-touched"), "unexpected"); throw new Error("unexpected child");
} } });
const project = pathToFileURL(path.join(source, "tooling/project.ts")).href;
mock.module(project, { namedExports: { verifyCandidate: async () => {
  writeFileSync(path.join(scratch, "candidate-touched"), "unexpected"); throw new Error("unexpected candidate");
} } });
`,
  );
  for (const target of ["production", "acceptance"]) {
    const env: NodeJS.ProcessEnv = {
      PATH: process.env.PATH,
      SystemRoot: process.env.SystemRoot,
      WINDIR: process.env.WINDIR,
      HOME: directory,
      TMP: directory,
      TEMP: directory,
      CTR06_GATE_SOURCE: repository,
      CTR06_GATE_SCRATCH: directory,
      GITHUB_ACTIONS: "true",
      GITHUB_REPOSITORY: "ArcForges/Cloud",
      GITHUB_REF: "refs/heads/main",
      NEON_DATABASE_URL_DIRECT: "postgresql://owner:synthetic-private@127.0.0.1/fixture",
    };
    const result = spawnSync(
      process.execPath,
      [
        "--experimental-test-module-mocks",
        "--import",
        preload,
        path.join(repository, "tooling/postgres-deploy.ts"),
        "migrate",
        "--target",
        target,
      ],
      { cwd: directory, env, encoding: "utf8", timeout: 15000, windowsHide: true },
    );
    assert.equal(result.error, undefined);
    assert.equal(result.status, 1);
    assert.match(result.stderr, /security bridge successor is not yet bound/u);
    assert.doesNotMatch(result.stderr, /synthetic-private|unsettled top-level await/u);
    assert.equal(existsSync(path.join(directory, "candidate-touched")), false);
    assert.equal(existsSync(path.join(directory, "child-touched")), false);
    assert.equal(existsSync(path.join(directory, "artifacts")), false);
  }
});

// Preserve the earlier cycle/timeout tests against the exact pre-phase-1
// commit, in an isolated source fixture. They are historical evidence, not a
// current phase-1 deployment or promotion path.
let historicalCycle: string | undefined;
function historicalCycleSource(repository: string): string {
  if (historicalCycle) return historicalCycle;
  const directory = scratchDirectory("ctr06-historical-cycle-");
  const commit = "ffc5b481badbfc0108a1673c8aa24e122404eb13";
  for (const file of [
    "package.json",
    "tooling/postgres-deploy.ts",
    "tooling/process.ts",
    "tooling/project.ts",
    "tooling/ctr06-publisher.ts",
    "tooling/ctr06-bridge.ts",
    "tooling/neon-runtime.ts",
    "tooling/sensitive-process.ts",
    "eng/verification/proof-deploy.ts",
    "worker/foundation/proof-command-key.ts",
  ]) {
    const bytes = execFileSync("git", ["show", `${commit}:${file}`], {
      cwd: repository,
      maxBuffer: 4 * 1024 * 1024,
    });
    const destination = path.join(directory, file);
    mkdirSync(path.dirname(destination), { recursive: true });
    writeFileSync(destination, bytes);
  }
  historicalCycle = directory;
  return directory;
}

// Execute the historical CLI as the entry module. The preloader substitutes only the
// candidate identity and external process/provider transports; it does not
// replace the schema-10 import of the actual publisher in the cycle cases.
for (const scenario of [
  { name: "production bridge guard", mode: "guard", target: "production", exit: 1 },
  { name: "acceptance bridge guard", mode: "guard", target: "acceptance", exit: 1 },
  { name: "awaited provider refusal", mode: "provider", target: "production", exit: 1 },
  { name: "awaited provider cancellation", mode: "abort", target: "production", exit: 1 },
  { name: "real provider child deadline", mode: "timeout", target: "production", exit: 1 },
  { name: "status child nonzero", mode: "status-fail", target: "production", exit: 1 },
  { name: "unknown history", mode: "refused", target: "production", exit: 1 },
  { name: "runner child nonzero", mode: "runner-fail", target: "production", exit: 1 },
  { name: "fresh pending migration", mode: "fresh", target: "production", exit: 0 },
  { name: "migration child nonzero", mode: "migrate-fail", target: "production", exit: 1 },
] as const) {
  test(`the historical PostgreSQL CLI awaits ${scenario.name} and records its gate`, async (t) => {
    const directory = scratchDirectory("ctr06-deploy-cycle-", t);
    const repository = path.resolve(import.meta.dirname, "../..");
    const historical = historicalCycleSource(repository);
    const preload = path.join(directory, "preload.mjs");
    const docker = path.join(directory, "docker.mjs");
    await writeFile(
      preload,
      String.raw`
import { mock } from "node:test";
import { appendFileSync } from "node:fs";
import { pathToFileURL } from "node:url";
import path from "node:path";
const child = await import("node:child_process");
const src = process.env.CTR06_CYCLE_WORKTREE;
const scratch = process.env.CTR06_CYCLE_SCRATCH;
const mode = process.env.CTR06_CYCLE_MODE;
mock.module("node:child_process", { namedExports: { ...child, spawn: (command, args, options) =>
  command === "docker" ? child.spawn(process.execPath, [path.join(scratch, "docker.mjs"), ...args], options) : child.spawn(command, args, options)
} });
const url = (file) => pathToFileURL(path.join(src, "tooling", file)).href;
const processUrl = url("process.ts");
const realProcess = await import(processUrl);
mock.module(processUrl, { namedExports: { ...realProcess, root: scratch } });
mock.module(url("project.ts"), { namedExports: { verifyCandidate: async () => ({ image: "mock:sealed", imageId: "sha256:mock", revision: "a".repeat(40), dirty: false }) } });
const sensitiveUrl = url("sensitive-process.ts");
const realSensitive = await import(sensitiveUrl);
mock.module(sensitiveUrl, { namedExports: { ...realSensitive, runSensitive: async () => {
  appendFileSync(path.join(scratch, "events.log"), "provider-enter\n");
  if (mode === "timeout") return await realSensitive.runSensitive("head", process.execPath, ["-e", "setTimeout(() => {}, 10000)"], process.env, "json", { deadlineMs: 100, killGraceMs: 100 });
  await new Promise((resolve) => setTimeout(resolve, 40));
  const error = new Error(mode === "abort" ? "fixture-provider-cancelled" : "fixture-provider-refused");
  if (mode === "abort") error.name = "AbortError";
  throw error;
} } });
if (mode === "runner-fail") mock.module(url("ctr06-publisher.ts"), { namedExports: {
  promoteCTR06Bridge: async (_target, image, variables, center) => {
    await new Promise((resolve) => setTimeout(resolve, 40));
    return await center(image, variables, ["admin", "prepare-ctr06-bridge"]);
  }
} });
`,
    );
    await writeFile(
      docker,
      String.raw`
import { appendFileSync } from "node:fs";
import path from "node:path";
const args = process.argv.slice(2);
const mode = process.env.CTR06_CYCLE_MODE;
appendFileSync(path.join(process.env.CTR06_CYCLE_SCRATCH, "calls.jsonl"), JSON.stringify(args) + "\n");
if (args[0] === "load") process.exit(0);
if (args[0] === "image" && args[1] === "inspect") { console.log("sha256:mock"); process.exit(0); }
if (args[0] === "run" && args.at(-2) === "admin" && args.at(-1) === "ensure-database") { console.log(JSON.stringify({created:false})); process.exit(0); }
if (args[0] === "run" && args.at(-2) === "migrate" && args.at(-1) === "status") {
  if (mode === "status-fail") process.exit(23);
  console.log(JSON.stringify({state: mode === "refused" ? "refused" : "pending", version: 10, runtimeRoleExists: mode !== "fresh" && mode !== "migrate-fail", serverVersionNum: 180006}));
  process.exit(0);
}
if (args[0] === "run" && args.at(-2) === "admin" && args.at(-1) === "prepare-ctr06-bridge") process.exit(27);
if (args[0] === "run" && args.at(-1) === "migrate") {
  if (mode === "migrate-fail") process.exit(31);
  await new Promise((resolve) => setTimeout(resolve, 40));
  console.log(JSON.stringify({state:"current", grants:"reconciled", database:"fixture", version:11, runtimeRole:"arcforges_center_runtime", serverVersionNum:180006, testedMajor:18, serverMajorMatchesTested:true, ran:[]}));
  process.exit(0);
}
console.error("unexpected synthetic docker call"); process.exit(42);
`,
    );
    const env: NodeJS.ProcessEnv = {
      PATH: process.env.PATH,
      SystemRoot: process.env.SystemRoot,
      WINDIR: process.env.WINDIR,
      HOME: directory,
      TMP: directory,
      TEMP: directory,
      CTR06_CYCLE_WORKTREE: historical,
      CTR06_CYCLE_SCRATCH: directory,
      CTR06_CYCLE_MODE: scenario.mode,
      GITHUB_ACTIONS: "true",
      GITHUB_REPOSITORY: "ArcForges/Cloud",
      GITHUB_REF: "refs/heads/main",
      GITHUB_EVENT_NAME:
        scenario.mode === "guard"
          ? scenario.target === "production"
            ? "workflow_dispatch"
            : "push"
          : "push",
      GITHUB_SHA: "a".repeat(40),
      CLOUDFLARE_ACCOUNT_ID: "c".repeat(32),
      CLOUDFLARE_API_TOKEN: "synthetic-provider-only",
      NEON_DATABASE_URL_DIRECT: "postgresql://synthetic@127.0.0.1/fixture",
    };
    const result = spawnSync(
      process.execPath,
      [
        "--experimental-test-module-mocks",
        "--import",
        preload,
        path.join(historical, "tooling", "postgres-deploy.ts"),
        "migrate",
        "--target",
        scenario.target,
      ],
      { cwd: repository, env, encoding: "utf8", timeout: 15_000, windowsHide: true },
    );
    assert.equal(result.error, undefined, result.stderr);
    assert.equal(result.signal, null, result.stderr);
    assert.equal(result.status, scenario.exit, result.stderr);
    assert(!result.stderr.includes("unsettled top-level await"));
    const gate = JSON.parse(
      readFileSync(
        path.join(directory, "artifacts", `postgres-gate-${scenario.target}.json`),
        "utf8",
      ),
    ) as { target: string; revision: string; status: string; version?: number };
    assert.equal(gate.target, scenario.target);
    assert.equal(gate.revision, "a".repeat(40));
    assert.equal(gate.status, scenario.exit === 0 ? "passed" : "failed");
    const calls = readFileSync(path.join(directory, "calls.jsonl"), "utf8")
      .trim()
      .split("\n")
      .map((line) => JSON.parse(line) as string[]);
    assert(calls.some((call) => call.at(-2) === "migrate" && call.at(-1) === "status"));
    if (scenario.target === "acceptance")
      assert(calls.some((call) => call.at(-1) === "ensure-database"));
    if (scenario.mode === "guard") assert.match(result.stderr, /ciContext/u);
    if (scenario.mode === "provider" || scenario.mode === "abort") {
      assert.match(result.stderr, /fixture-provider-(refused|cancelled)/u);
      assert.equal(readFileSync(path.join(directory, "events.log"), "utf8"), "provider-enter\n");
    }
    if (scenario.mode === "timeout") {
      assert.match(result.stderr, /current Cloud main revision could not be verified/u);
      assert.equal(readFileSync(path.join(directory, "events.log"), "utf8"), "provider-enter\n");
    }
    if (scenario.mode === "status-fail") assert.match(result.stderr, /exited with code 23/u);
    if (scenario.mode === "refused") assert.match(result.stderr, /history differs/u);
    if (scenario.mode === "runner-fail") assert.match(result.stderr, /exited with code 27/u);
    if (scenario.mode === "migrate-fail") assert.match(result.stderr, /exited with code 31/u);
    if (scenario.mode === "fresh") assert.equal(gate.version, 11);
  });
}
