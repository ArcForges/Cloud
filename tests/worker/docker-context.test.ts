// SPDX-License-Identifier: AGPL-3.0-only
// The Docker build context must carry every C# source folder of the host and of every project it
// references: a folder missing from .dockerignore compiles locally and fails only in the hosted image build.
import assert from "node:assert/strict";
import { readdirSync, readFileSync } from "node:fs";
import path from "node:path";
import test from "node:test";

const root = path.resolve(import.meta.dirname, "../..");

/** Every folder of a project that holds C# sources, relative to the repository root. */
function sourceFolders(directory: string): string[] {
  const folders: string[] = [];
  const entries = readdirSync(path.join(root, directory), { withFileTypes: true });
  if (entries.some((entry) => entry.isFile() && entry.name.endsWith(".cs")))
    folders.push(directory);
  for (const entry of entries)
    if (entry.isDirectory() && !["bin", "obj"].includes(entry.name))
      folders.push(...sourceFolders(path.posix.join(directory, entry.name)));
  return folders;
}
/** The one glob form the context uses: `*` stands for one path segment, as in Go's filepath.Match. */
function matches(rule: string, target: string) {
  const expression = rule
    .split("*")
    .map((part) => part.replaceAll(/[.+?^${}()|[\]\\]/gu, String.raw`\$&`))
    .join("[^/]*");
  return new RegExp(`^${expression}$`, "u").test(target);
}

const rules = readFileSync(path.join(root, ".dockerignore"), "utf8")
  .split("\n")
  .map((line) => line.trim())
  .filter(Boolean);
const includes = rules.filter((rule) => rule.startsWith("!")).map((rule) => rule.slice(1));
const admitted = (target: string) => includes.some((rule) => matches(rule, target));
const projects = readdirSync(path.join(root, "src"), { withFileTypes: true })
  .filter((entry) => entry.isDirectory() && entry.name.startsWith("ArcForges.Cloud"))
  .map((entry) => `src/${entry.name}`);

test("every source project of the image is admitted to the Docker context by explicit directory and file rules", () => {
  assert(projects.includes("src/ArcForges.Cloud"));
  assert(projects.includes("src/ArcForges.Cloud.Storage.D1"));
  assert.equal(projects.filter((project) => project.includes(".Modules.")).length, 20);
  const host = sourceFolders("src/ArcForges.Cloud");
  assert(host.includes("src/ArcForges.Cloud/Foundation") && host.includes("src/ArcForges.Cloud"));
  for (const project of projects) {
    const name = path.posix.basename(project);
    for (const file of [`${name}.csproj`, "packages.lock.json"])
      assert(admitted(`${project}/${file}`), `Missing file rule for ${project}/${file}`);
    for (const folder of sourceFolders(project)) {
      assert(admitted(`${folder}/`), `Missing directory rule for ${folder}`);
      assert(admitted(`${folder}/Example.cs`), `Missing source rule for ${folder}`);
    }
  }
});

test("a rule never admits tests, the Worker, the plan files, build output or a stray file", () => {
  for (const forbidden of [
    "!tests/",
    "!worker/",
    "!storage/",
    "!storage/plans/",
    "!eng/verification/",
  ])
    assert(!rules.includes(forbidden), forbidden);
  for (const target of [
    "tests/ArcForges.Cloud.Tests/Example.cs",
    "worker/index.ts",
    "storage/plans/foundation/readiness.sql",
    "src/ArcForges.Cloud/obj/Example.cs",
    "src/ArcForges.Cloud/bin/Example.cs",
    "src/ArcForges.Cloud.Modules.Identity/obj/project.assets.json",
    "src/ArcForges.Cloud.Storage.D1/Example.sql",
    "src/ArcForges.Cloud.Modules.Identity/Notes.md",
  ])
    assert(!admitted(target) || target.includes("/bin/") || target.includes("/obj/"), target);
  // Build output stays excluded by the closing rules whatever the earlier rules admit.
  assert(rules.indexOf("**/bin/") > rules.indexOf("!src/ArcForges.Cloud.Storage.D1/*.cs"));
  assert(rules.indexOf("**/obj/") > rules.indexOf("!src/ArcForges.Cloud.Storage.D1/*.cs"));
});

test("the image restores and publishes the whole source tree under the locked restore", () => {
  const dockerfile = readFileSync(path.join(root, "Dockerfile"), "utf8");
  assert(
    /^COPY src\/ \.\/src\/$/mu.test(dockerfile),
    "the Dockerfile copies the admitted src tree",
  );
  assert(dockerfile.includes("dotnet restore src/ArcForges.Cloud --locked-mode"));
  assert(
    dockerfile.indexOf("COPY src/ ./src/") <
      dockerfile.indexOf("dotnet restore src/ArcForges.Cloud --locked-mode"),
    "every referenced project and its lock file is in the context before the locked restore",
  );
});
