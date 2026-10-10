// SPDX-License-Identifier: AGPL-3.0-only
// CLOUD.84 U9/U10 (S41(1)): the Node shim of the D1 migration tooling forwards argv and environment unchanged, runs only a sealed migrator
// whose digest the candidate manifest records, and never puts the secret in an argument. The migration decisions are C#; their replacement
// tests are tests/ArcForges.Cloud.Tests/Reduction/MigrationRunnerTests.cs and DeployTests.cs.
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
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
import { toolPublishArguments } from "../../tooling/project.ts";
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
  const manifest = JSON.stringify({ files: { [sealedToolName]: digest } });
  assert.doesNotThrow(() => verifySealedTool(archive, manifest));
  assert.throws(
    () => verifySealedTool(Buffer.from("another tool"), manifest),
    /does not match the candidate manifest/u,
  );
  assert.throws(
    () => verifySealedTool(archive, JSON.stringify({ files: {} })),
    /does not match the candidate manifest/u,
  );
});

test("the candidate job seals one tool archive, which both the probe runner and the shim run", () => {
  const project = readFileSync(path.join(import.meta.dirname, "../../tooling/project.ts"), "utf8");
  assert.match(project, /path\.join\(candidateDir, sealedToolName\)/u);
  assert.doesNotMatch(project, /arcforges-probe|arcforges-migrator/u);
  const shim = readFileSync(path.join(import.meta.dirname, "../../eng/migrations/shim.ts"), "utf8");
  assert.match(shim, /extractSealedTool\(root\)/u);
  const protocol = readFileSync(
    path.join(import.meta.dirname, "../../tooling/protocol.ts"),
    "utf8",
  );
  assert.match(protocol, /extractSealedTool\(repositoryRoot\)/u);
  assert.equal(sealedToolName, "arcforges-tool.tar");
});

// CLOUD.84 S38(2): the CI restore is locked, and the reviewed tool lock has no Microsoft.NET.ILLink.Tasks. Nothing in the tool publish may
// imply that pack, and the candidate never rewrites or restores the lock: it must come out of the publish unchanged.
test("the tool publish is self-contained and non-single-file, and implies no ILLink pack", () => {
  const args = toolPublishArguments("out");
  assert.deepEqual(args.slice(0, 2), ["publish", probeProject]);
  assert.ok(args.includes("-p:PublishSingleFile=false"));
  const runtime = args.indexOf("-r");
  assert.deepEqual(args.slice(runtime, runtime + 4), [
    "-r",
    "linux-x64",
    "--self-contained",
    "true",
  ]);
  const illinkProperties =
    /PublishSingleFile=true|PublishTrimmed|PublishAot|EnableSingleFileAnalyzer|EnableTrimAnalyzer|EnableAotAnalyzer|IsAotCompatible|IsTrimmable/iu;
  for (const argument of args) assert.doesNotMatch(argument, illinkProperties);
  const repository = path.join(import.meta.dirname, "../..");
  for (const file of [
    "tools/ArcForges.Cloud.Generation/ArcForges.Cloud.Generation.csproj",
    "Directory.Build.props",
    "Directory.Build.targets",
  ])
    assert.doesNotMatch(readFileSync(path.join(repository, file), "utf8"), illinkProperties, file);
  const lock = JSON.parse(
    readFileSync(
      path.join(repository, "tools/ArcForges.Cloud.Generation/packages.lock.json"),
      "utf8",
    ),
  ) as { dependencies: Record<string, Record<string, unknown>> };
  for (const frame of Object.values(lock.dependencies))
    assert.equal(Object.hasOwn(frame, "Microsoft.NET.ILLink.Tasks"), false);
});

test("the candidate never snapshots or restores the reviewed tool lock; a changed lock fails it", () => {
  const project = readFileSync(path.join(import.meta.dirname, "../../tooling/project.ts"), "utf8");
  assert.doesNotMatch(project, /writeFile\((probeLock|toolLockFile)/u);
  assert.doesNotMatch(project, /PublishSingleFile=true/u);
  assert.match(project, /reviewedToolLock\.equals\(await readFile\(toolLockFile\)\)/u);
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
      JSON.stringify({ files: { [sealedToolName]: recordedDigest ?? digest } }),
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

test("a CI source check without a candidate manifest reads the tree, as the source job's check:physical does", () => {
  withoutCandidate((root) => {
    const invocation = prepareInvocation(
      ["check", "--base", "origin/main"],
      { GITHUB_ACTIONS: "true" },
      root,
    );
    assert.equal(invocation.command, "dotnet");
    assert.deepEqual(invocation.args.slice(-4), ["migrate", "check", "--base", "origin/main"]);
  });
});

test("the Hello probe in GitHub Actions runs only the sealed candidate tool, checked against the manifest", () => {
  withSealedCandidate((root) => {
    const invocation = probeInvocation(
      ["probe", "https://example.test", "false"],
      { GITHUB_ACTIONS: "true" },
      root,
    );
    assert.equal(path.basename(invocation.command), sealedToolExecutable);
    assert.equal(readFileSync(invocation.command, "utf8"), "#!/bin/sh\n");
    assert.ok(invocation.directory);
    assert.equal(path.dirname(invocation.command), invocation.directory);
    assert.deepEqual(invocation.args, ["probe", "https://example.test", "false"]);
  });
});

test("the Hello probe in CI refuses a sealed tool whose digest differs from the manifest", () => {
  withSealedCandidate((root) => {
    for (const env of [{ GITHUB_ACTIONS: "true" }, { CI: "true" }])
      assert.throws(
        () => probeInvocation(["probe", "https://example.test", "false"], env, root),
        /does not match the candidate manifest/u,
      );
    assert.deepEqual(extractedDirectories(root), []);
  }, "f".repeat(64));
});

test("the Hello probe in GitHub Actions without a candidate refuses and never falls back to dotnet run", () => {
  withoutCandidate((root) => {
    let thrown: unknown;
    try {
      probeInvocation(["probe", "https://example.test", "true"], { GITHUB_ACTIONS: "true" }, root);
    } catch (error) {
      thrown = error;
    }
    assert.ok(thrown instanceof Error);
    assert.match(thrown.message, /candidate manifest is absent/u);
    assert.doesNotMatch(thrown.message, /dotnet/u);
  });
});

test("the Hello probe in GitHub Actions refuses a candidate without the sealed tool", () => {
  withoutCandidate((root) => {
    mkdirSync(path.join(root, "artifacts", "candidate"), { recursive: true });
    writeFileSync(path.join(root, "artifacts", "candidate", "manifest.json"), "{}");
    assert.throws(
      () =>
        probeInvocation(
          ["probe", "https://example.test", "true"],
          { GITHUB_ACTIONS: "true" },
          root,
        ),
      /no sealed tool/u,
    );
  });
});

test("outside CI the Hello probe runs the tool project with dotnet run", () => {
  const invocation = probeInvocation(["probe", "https://example.test", "true"], {});
  assert.equal(invocation.command, "dotnet");
  assert.ok(invocation.args.includes(probeProject));
  assert.equal(invocation.directory, undefined);
});
