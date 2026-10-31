// SPDX-License-Identifier: AGPL-3.0-only
// The Docker build context must carry every C# source folder of the host and of every project it
// references: a folder missing from .dockerignore compiles locally and fails only in the hosted image build.
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
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

/**
 * Every folder of the Go center that holds a non-test Go source or a file the executable embeds: a migration, a page template
 * (`*.gohtml`), the account pages' script and style sheet (`static/*.js`, `static/*.css`) or the plan catalogue's development fixtures
 * (`fixtures/*.json`).
 */
function centerFolders(directory: string): { folder: string; files: string[] }[] {
  const entries = readdirSync(path.join(root, directory), { withFileTypes: true });
  const files = entries
    .filter(
      (entry) =>
        entry.isFile() &&
        ((entry.name.endsWith(".go") && !entry.name.endsWith("_test.go")) ||
          entry.name.endsWith(".sql") ||
          entry.name.endsWith(".gohtml") ||
          (directory.endsWith("/static") && /\.(?:js|css)$/u.test(entry.name)) ||
          (directory.endsWith("/fixtures") && entry.name.endsWith(".json"))),
    )
    .map((entry) => entry.name);
  const folders = files.length > 0 ? [{ folder: directory, files }] : [];
  for (const entry of entries)
    if (entry.isDirectory() && entry.name !== "testdata")
      folders.push(...centerFolders(path.posix.join(directory, entry.name)));
  return folders;
}

test("every package of the Go center and its embedded migrations are admitted to the Docker context", () => {
  const folders = [
    ...centerFolders("center/internal"),
    ...centerFolders("center/cmd/arcforges-center"),
  ];
  const names = folders.map((entry) => entry.folder);
  for (const expected of [
    "center/internal/store/migrate",
    "center/internal/schema/migrations",
    "center/cmd/arcforges-center",
    "center/internal/pages/templates",
    "center/internal/pages/static",
  ])
    assert(names.includes(expected), expected);
  for (const { folder, files } of folders) {
    assert(admitted(`${folder}/`), `Missing directory rule for ${folder}`);
    for (const file of files)
      assert(admitted(`${folder}/${file}`), `Missing file rule for ${folder}/${file}`);
  }
  assert(!admitted("center/internal/schema/migrations/notes.md"));
  // The embedded assets are admitted by name, and a stray file of those folders is not.
  assert(!admitted("center/internal/pages/templates/notes.md"));
  assert(!admitted("center/internal/pages/static/notes.md"));
  assert(!admitted("center/internal/pages/static/account.map"));
  assert(
    rules.indexOf("center/**/*_test.go") > rules.indexOf("!center/internal/store/migrate/*.go"),
  );
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

/**
 * Whether the Docker context carries a Go center file: an include rule names it (by the same file rules as above, so a stray file of
 * a carried folder is not carried) and none of the closing exclusions of the center removes it again (`center/tools/`,
 * `center/cmd/center-gen/`, every `testdata` folder, every test file). `**` crosses directories, `*` stays inside one, and a trailing
 * slash names a directory and all it holds.
 */
function carried(target: string): boolean {
  if (!admitted(target)) return false;
  const excludes = rules.filter((rule) => rule.startsWith("center/"));
  assert(excludes.length >= 4, "the closing exclusions of the center were found");
  return !excludes.some((rule) => {
    const directory = rule.endsWith("/");
    const expression = (directory ? rule.slice(0, -1) : rule)
      .split("**/")
      .map((part) =>
        part
          .split("*")
          .map((literal) => literal.replaceAll(/[.+?^${}()|[\]\\]/gu, String.raw`\$&`))
          .join("[^/]*"),
      )
      .join("(?:.*/)?");
    return new RegExp(`^${expression}${directory ? "/.*" : ""}$`, "u").test(target);
  });
}

/** The input files of the release profile the provenance inventory names (the image's, then the Worker's). */
function activeProfile(): {
  image: { inputs: Record<string, string> };
  worker: { inputs: Record<string, string> };
  id: string;
} {
  const inventory = JSON.parse(
    readFileSync(path.join(root, "eng/provenance/files.json"), "utf8"),
  ) as { artifacts: string[] };
  const record = JSON.parse(
    readFileSync(
      path.join(root, "eng/provenance/records", `${inventory.artifacts[0]}.json`),
      "utf8",
    ),
  ) as { artifactTargets: { profile: string }[] };
  return JSON.parse(
    readFileSync(path.join(root, record.artifactTargets[0]?.profile ?? ""), "utf8"),
  );
}

test("the matcher of the Docker context follows the rules the file states", () => {
  for (const [target, expected] of [
    ["center/cmd/arcforges-center/main.go", true],
    ["center/cmd/arcforges-center/operator.go", true],
    ["center/cmd/arcforges-center/operator_test.go", false],
    ["center/cmd/center-gen/main.go", false],
    ["center/internal/entitlement/operator.go", true],
    ["center/internal/entitlement/operator_test.go", false],
    ["center/internal/entitlement/testdata/csharp-resolver-vectors.json", false],
    ["center/internal/schema/migrations/0003_entitlement.sql", true],
    ["center/internal/pages/templates/operations-review.gohtml", true],
    ["center/internal/pages/templates/notes.md", false],
    ["center/internal/feature/fixtures/development.json", true],
    ["center/internal/identity/passkey/virtual/virtual.go", true],
    ["center/tools/anything.go", false],
    ["center/README.md", false],
    ["tests/worker/docker-context.test.ts", false],
  ] as const)
    assert.equal(carried(target), expected, target);
});

// Every file the Docker context carries from the Go center is compiled or embedded into the shipped image, so it is an input the
// release profile must bind: a carried file the profile does not name could change after the admission with no successor record
// (records-1: the role-granting commands of the executable were once such a file).
test("every file of the center that the Docker context carries is an input of the active release profile", () => {
  const profile = activeProfile();
  const tracked = execFileSync("git", ["ls-files", "center"], { cwd: root, encoding: "utf8" })
    .split("\n")
    .filter((name) => name !== "");
  const carriedFiles = tracked.filter(carried);
  assert(carriedFiles.length > 100, "the files of the center were found");
  assert(carriedFiles.includes("center/cmd/arcforges-center/main.go"));
  const unbound = carriedFiles.filter((name) => profile.image.inputs[name] === undefined);
  assert.deepEqual(
    unbound,
    [],
    `the Docker context carries files that ${profile.id} does not bind`,
  );
});
