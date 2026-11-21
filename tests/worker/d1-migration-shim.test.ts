// SPDX-License-Identifier: AGPL-3.0-only
// CLOUD.84 U9/U10 (S41(1)): the Node shim of the D1 migration tooling forwards argv and environment unchanged, runs only a sealed migrator
// whose digest the candidate manifest records, and never puts the secret in an argument. The migration decisions are C#; their replacement
// tests are tests/ArcForges.Cloud.Tests/Reduction/MigrationRunnerTests.cs and DeployTests.cs.
import assert from "node:assert/strict";
import { execFileSync, spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import { mkdirSync, mkdtempSync, readdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import test from "node:test";
import {
  developmentInvocation,
  prepareInvocation,
  sealedInvocation,
} from "../../eng/migrations/shim.ts";
import { assertNoD1Binding } from "../../tooling/project.ts";
import { goCandidateFiles } from "../../tooling/proof-candidate.ts";
import { probeInvocation, probeProject } from "../../tooling/protocol.ts";
import {
  sealedToolExecutable,
  sealedToolName,
  verifySealedTool,
} from "../../tooling/sealed-tool.ts";

const token = "cf-test-token-0123456789abcdef";

test("the development invocation keeps the argument order and runs the tool project's migrate command", () => {
  const invocation = developmentInvocation(["deploy", "--target", "proof"], { A: "1" });
  assert.equal(invocation.command, "dotnet");
  assert.deepEqual(invocation.args, [
    "run",
    "--project",
    "tools/ArcForges.Cloud.Generation",
    "--",
    "migrate",
    "deploy",
    "--target",
    "proof",
  ]);
  assert.deepEqual(invocation.env, { A: "1" });
});

test("the sealed invocation runs the extracted executable with migrate and the same arguments", () => {
  const invocation = sealedInvocation(
    "/work/ArcForges.Cloud.Generation",
    ["check", "--base", "origin/main"],
    {},
  );
  assert.equal(invocation.command, "/work/ArcForges.Cloud.Generation");
  assert.deepEqual(invocation.args, ["migrate", "check", "--base", "origin/main"]);
});

test("the secret travels only in the environment and never in an argument", () => {
  const env = { CLOUDFLARE_API_TOKEN: token, GITHUB_SHA: "0".repeat(40) };
  for (const invocation of [
    developmentInvocation(["deploy", "--target", "production"], env),
    sealedInvocation("/work/ArcForges.Cloud.Generation", ["deploy", "--target", "production"], env),
  ]) {
    assert.equal(invocation.env.CLOUDFLARE_API_TOKEN, token);
    assert.equal(
      invocation.args.some((argument) => argument.includes(token)),
      false,
    );
  }
});

test("a sealed tool is accepted only when its digest equals the candidate manifest's record", () => {
  const archive = Buffer.from("sealed tool bytes");
  const digest = createHash("sha256").update(archive).digest("hex");
  const manifest = JSON.stringify({ schema: 1, files: { [sealedToolName]: digest } });
  assert.doesNotThrow(() => verifySealedTool(archive, manifest));
  assert.throws(
    () => verifySealedTool(Buffer.from("another tool"), manifest),
    /does not match the candidate manifest/u,
  );
  assert.throws(
    () => verifySealedTool(archive, JSON.stringify({ schema: 1, files: {} })),
    /does not match the candidate manifest/u,
  );
});

test("the current Go candidate omits the historical tool and rejects D1 bindings", () => {
  assert.equal(goCandidateFiles.length, 9);
  assert(!goCandidateFiles.some((member) => member === String(sealedToolName)));
  assert.doesNotThrow(() => assertNoD1Binding({ name: "arcforges-cloud" }));
  for (const config of [undefined, { d1_databases: [] }, { d1_databases: [{ binding: "DB" }] }])
    assert.throws(() => assertNoD1Binding(config));
  const archive = Buffer.from("historical tool");
  const digest = createHash("sha256").update(archive).digest("hex");
  assert.throws(
    () =>
      verifySealedTool(
        archive,
        JSON.stringify({ schema: 2, runtime: "go", files: { [sealedToolName]: digest } }),
      ),
    /requires a historical schema-1 candidate/u,
  );
});

test("the original D1 candidate still binds its locked sealed tool in immutable source", () => {
  const repository = path.join(import.meta.dirname, "../..");
  const revision = "9b8796eac760982d9814f371b820b736ddd945c4";
  const original = execFileSync("git", ["show", revision + ":tooling/project.ts"], {
    cwd: repository,
    encoding: "utf8",
  });
  assert.match(original, /sealedToolName/u);
  assert.match(original, /-p:PublishSingleFile=false/u);
  assert.match(original, /reviewedToolLock\.equals\(await readFile\(toolLockFile\)\)/u);
});

/** A repository root with a candidate whose sealed tool is a real tar archive of one apphost; the manifest may record another digest. */
function withSealedCandidate<T>(use: (root: string) => T, recordedDigest?: string): T {
  const root = mkdtempSync(path.join(tmpdir(), "arcforges-sealed-"));
  try {
    const staging = path.join(root, "staging");
    const candidate = path.join(root, "artifacts", "candidate");
    mkdirSync(staging, { recursive: true });
    mkdirSync(candidate, { recursive: true });
    writeFileSync(path.join(staging, sealedToolExecutable), "#!/bin/sh\n");
    const archived = spawnSync(
      "tar",
      ["-cf", `artifacts/candidate/${sealedToolName}`, "-C", "staging", "."],
      { cwd: root },
    );
    assert.equal(archived.status, 0, "the test archive could not be created");
    const digest = createHash("sha256")
      .update(readFileSync(path.join(candidate, sealedToolName)))
      .digest("hex");
    writeFileSync(
      path.join(candidate, "manifest.json"),
      JSON.stringify({ schema: 1, files: { [sealedToolName]: recordedDigest ?? digest } }),
    );
    return use(root);
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
}

function extractedDirectories(root: string): string[] {
  return readdirSync(path.join(root, "artifacts")).filter((name) =>
    name.startsWith("sealed-tool-"),
  );
}

test("a deploy with a sealed candidate runs the extracted tool, checked against the manifest", () => {
  withSealedCandidate((root) => {
    const invocation = prepareInvocation(
      ["deploy", "--target", "proof"],
      { GITHUB_ACTIONS: "true" },
      root,
    );
    assert.equal(path.basename(invocation.command), sealedToolExecutable);
    assert.equal(readFileSync(invocation.command, "utf8"), "#!/bin/sh\n");
    assert.deepEqual(invocation.args, ["migrate", "deploy", "--target", "proof"]);
  });
});

test("a deploy whose sealed tool differs from the manifest refuses before extraction", () => {
  withSealedCandidate((root) => {
    assert.throws(
      () => prepareInvocation(["deploy", "--target", "proof"], { GITHUB_ACTIONS: "true" }, root),
      /does not match the candidate manifest/u,
    );
    assert.deepEqual(extractedDirectories(root), []);
  }, "0".repeat(64));
});

// CLOUD.84 S45(3): a deployment job never builds from source. Only a local run or a CI source check may.
function withoutCandidate<T>(use: (root: string) => T): T {
  const root = mkdtempSync(path.join(tmpdir(), "arcforges-shim-"));
  try {
    return use(root);
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
}

test("a GitHub Actions deploy without a candidate manifest refuses and builds nothing", () => {
  withoutCandidate((root) => {
    assert.throws(
      () =>
        prepareInvocation(["deploy", "--target", "production"], { GITHUB_ACTIONS: "true" }, root),
      /nothing is built or run/,
    );
  });
});

test("every other migrate command in GitHub Actions without a candidate manifest refuses (CLOUD.84 S45(3))", () => {
  withoutCandidate((root) => {
    for (const argv of [
      ["deploy", "--target", "proof"],
      ["backfill", "--target", "production"],
      ["cutover", "--target", "production"],
      ["anything-else"],
    ]) {
      assert.throws(
        () => prepareInvocation(argv, { GITHUB_ACTIONS: "true" }, root),
        /nothing is built or run/,
        `the migrate command ${argv[0]} must refuse without a candidate`,
      );
    }
  });
});

test("a GitHub Actions refusal names the candidate and never falls back to dotnet run", () => {
  withoutCandidate((root) => {
    let thrown: unknown;
    try {
      prepareInvocation(["deploy", "--target", "proof"], { GITHUB_ACTIONS: "true" }, root);
    } catch (error) {
      thrown = error;
    }
    assert.ok(thrown instanceof Error);
    assert.match(thrown.message, /candidate manifest is absent/);
    assert.doesNotMatch(thrown.message, /dotnet/);
  });
});

test("a local deploy without a candidate manifest may build the migrator from the tree", () => {
  withoutCandidate((root) => {
    const invocation = prepareInvocation(["deploy", "--target", "proof"], {}, root);
    assert.equal(invocation.command, "dotnet");
    assert.equal(invocation.args[0], "run");
  });
});

test("the CI source check reads the tree even when the Go candidate cache contains an older tool", () => {
  withoutCandidate((root) => {
    const env = { GITHUB_ACTIONS: "true" };
    const checkSource = () => {
      const invocation = prepareInvocation(["check", "--base", "origin/main"], env, root);
      assert.equal(invocation.command, "dotnet");
      assert.deepEqual(invocation.args.slice(-4), ["migrate", "check", "--base", "origin/main"]);
    };
    checkSource();

    const candidate = path.join(root, "artifacts", "candidate");
    mkdirSync(candidate, { recursive: true });
    const obsolete = "cached historical tool fixture";
    writeFileSync(path.join(candidate, sealedToolName), obsolete);
    writeFileSync(
      path.join(candidate, "manifest.json"),
      JSON.stringify({ schema: 2, runtime: "go", files: {} }),
    );
    checkSource();
    assert.throws(
      () => prepareInvocation(["deploy", "--target", "proof"], env, root),
      /historical schema-1 candidate/u,
    );
    assert.deepEqual(extractedDirectories(root), []);
    assert.equal(readFileSync(path.join(candidate, sealedToolName), "utf8"), obsolete);
  });
});

test("the current Hello consumer refuses all CI source invocations", () => {
  for (const env of [{ GITHUB_ACTIONS: "true" }, { CI: "true" }])
    assert.throws(
      () => probeInvocation(["probe", "https://example.test", "true"], env),
      /independent Hello consumer runs locally/u,
    );
});

test("the local Hello probe uses the standalone locked consumer and preserves each argument", () => {
  const invocation = probeInvocation(["probe", "https://example.test", "true"], {});
  assert.equal(invocation.command, "dotnet");
  assert.match(probeProject, /ArcForges\.Cloud\.Consumer\.csproj$/u);
  assert.deepEqual(invocation.args, [
    "run",
    "--project",
    probeProject,
    "-c",
    "Release",
    "--",
    "probe",
    "https://example.test",
    "true",
  ]);
});
