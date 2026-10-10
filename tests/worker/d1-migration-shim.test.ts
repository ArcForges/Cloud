// SPDX-License-Identifier: AGPL-3.0-only
// CLOUD.84 U9/U10 (S41(1)): the Node shim of the D1 migration tooling forwards argv and environment unchanged, runs only a sealed migrator
// whose digest the candidate manifest records, and never puts the secret in an argument. The migration decisions are C#; their replacement
// tests are tests/ArcForges.Cloud.Tests/Reduction/MigrationRunnerTests.cs and DeployTests.cs.
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import path from "node:path";
import test from "node:test";
import {
  developmentInvocation,
  sealedArchiveName,
  sealedInvocation,
  verifySealedArchive,
} from "../../eng/migrations/shim.ts";

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

test("a sealed migrator is accepted only when its digest equals the candidate manifest's record", () => {
  const archive = Buffer.from("sealed migrator bytes");
  const digest = createHash("sha256").update(archive).digest("hex");
  const manifest = JSON.stringify({ files: { [sealedArchiveName]: digest } });
  assert.doesNotThrow(() => verifySealedArchive(archive, manifest));
  assert.throws(
    () => verifySealedArchive(Buffer.from("another migrator"), manifest),
    /does not match the candidate manifest/u,
  );
  assert.throws(
    () => verifySealedArchive(archive, JSON.stringify({ files: {} })),
    /does not match the candidate manifest/u,
  );
});

test("the candidate job seals the migrator under the name the shim checks", () => {
  const project = readFileSync(path.join(import.meta.dirname, "../../tooling/project.ts"), "utf8");
  assert.match(project, /"arcforges-migrator\.tar"/u);
  assert.match(project, /sealedMigratorName, "-C"|path\.join\(candidateDir, sealedMigratorName\)/u);
  const shim = readFileSync(path.join(import.meta.dirname, "../../eng/migrations/shim.ts"), "utf8");
  assert.match(shim, /export const sealedArchiveName = "arcforges-migrator\.tar"/u);
});
