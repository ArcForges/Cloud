// SPDX-License-Identifier: AGPL-3.0-only
// The nineteen module boundaries as files: the owner registry, the module projects, their references, the host listing and the
// solution agree. The C# architecture tests (ModuleBoundaryTests) enforce the same from the compiled side. The last tests keep the
// test files from leaving temporary directories behind (support/scratch.ts).
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { existsSync, mkdirSync, mkdtempSync, readdirSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import test from "node:test";
import { ownerRegistry, parseOwnerRegistry } from "../../eng/verification/storage-plans.ts";
import { repositoryRoot } from "./support/sqlite-d1.ts";

const read = (relative: string) => readFileSync(path.join(repositoryRoot, relative), "utf8");
const modules = parseOwnerRegistry(read(ownerRegistry))
  .owners.filter((entry) => entry.kind === "module")
  .map((entry) => entry.className);
const project = (name: string) =>
  `src/ArcForges.Cloud.Modules.${name}/ArcForges.Cloud.Modules.${name}.csproj`;
const includes = (xml: string, element: string) =>
  [...xml.matchAll(new RegExp(`<${element}\\s+Include="([^"]+)"`, "gu"))].map(
    (match) => match[1] ?? "",
  );

test("the registry, the module projects and the host listing name the same nineteen modules", () => {
  assert.equal(modules.length, 19);
  assert.equal(new Set(modules).size, 19);
  const directories = readdirSync(path.join(repositoryRoot, "src"))
    .filter(
      (name) =>
        name.startsWith("ArcForges.Cloud.Modules.") &&
        name !== "ArcForges.Cloud.Modules.Abstractions",
    )
    .map((name) => name.slice("ArcForges.Cloud.Modules.".length));
  assert.deepEqual(directories.toSorted(), modules.toSorted());
  const listing = read("src/ArcForges.Cloud/Composition/ModuleBoundaries.cs");
  const solution = read("Cloud.slnx");
  const host = read("src/ArcForges.Cloud/ArcForges.Cloud.csproj");
  for (const name of modules) {
    assert(existsSync(path.join(repositoryRoot, project(name))), name);
    assert(
      existsSync(path.join(repositoryRoot, `src/ArcForges.Cloud.Modules.${name}/${name}Module.cs`)),
    );
    assert(listing.includes(`${name}Module.Instance`), `${name} is listed by the host`);
    assert(solution.includes(project(name)), `${name} is in the solution`);
    assert(
      host.includes(`../ArcForges.Cloud.Modules.${name}/ArcForges.Cloud.Modules.${name}.csproj`),
    );
  }
  assert.equal([...listing.matchAll(/Module\.Instance,/gu)].length, 19);
});

test("a module references only the Abstractions and no package, and the shared projects reference no module", () => {
  for (const name of modules) {
    const xml = read(project(name));
    assert.deepEqual(includes(xml, "ProjectReference"), [
      "../ArcForges.Cloud.Modules.Abstractions/ArcForges.Cloud.Modules.Abstractions.csproj",
    ]);
    assert.deepEqual(includes(xml, "PackageReference"), [], name);
    assert.deepEqual(includes(xml, "FrameworkReference"), [], name);
    const source = read(`src/ArcForges.Cloud.Modules.${name}/${name}Module.cs`);
    for (const other of modules.filter((candidate) => candidate !== name))
      assert(!source.includes(`ArcForges.Cloud.Modules.${other}`), `${name} names ${other}`);
    assert(
      !/ArcForges\.Cloud\.(?:Composition|Ingress|Foundation|Storage|Hmac)\b/u.test(source),
      name,
    );
  }
  const abstractions = read(
    "src/ArcForges.Cloud.Modules.Abstractions/ArcForges.Cloud.Modules.Abstractions.csproj",
  );
  assert.deepEqual(includes(abstractions, "ProjectReference"), []);
  assert.deepEqual(includes(abstractions, "PackageReference"), []);
  const storage = read("src/ArcForges.Cloud.Storage.D1/ArcForges.Cloud.Storage.D1.csproj");
  // The plan bridge references the Abstractions project only to implement its generic plan-execution port (COM.16), never a module.
  assert.deepEqual(includes(storage, "ProjectReference"), [
    "../ArcForges.Cloud.Modules.Abstractions/ArcForges.Cloud.Modules.Abstractions.csproj",
  ]);
  assert.deepEqual(includes(storage, "PackageReference"), ["ArcForges.Contracts.CloudInternal"]);
});

test("only the host project references the modules and nothing under src references the host", () => {
  for (const entry of readdirSync(path.join(repositoryRoot, "src"))) {
    const file = `src/${entry}/${entry}.csproj`;
    if (!existsSync(path.join(repositoryRoot, file))) continue;
    const references = includes(read(file), "ProjectReference");
    if (entry === "ArcForges.Cloud") continue;
    assert(
      references.every(
        (reference) => !reference.endsWith("/ArcForges.Cloud/ArcForges.Cloud.csproj"),
      ),
      `${entry} references the host`,
    );
    if (!entry.startsWith("ArcForges.Cloud.Modules."))
      assert(
        // The plan bridge references the shared Abstractions project to implement the plan-execution port (COM.16), never a module.
        references.every(
          (reference) =>
            !reference.includes(".Modules.") ||
            (entry === "ArcForges.Cloud.Storage.D1" &&
              reference.endsWith("/ArcForges.Cloud.Modules.Abstractions.csproj")),
        ),
        `${entry} references a module`,
      );
  }
});

/**
 * Files that may call mkdtemp or mkdtempSync directly. Each removes what it creates, also when its test fails
 * (try/finally or a test.after hook). A new test file uses scratchDirectory from support/scratch.ts instead;
 * add an entry here only with a reason.
 */
const allowed: Record<string, string> = {
  "tests/worker/support/scratch.ts": "the helper itself",
  "tests/worker/module-layout.test.ts":
    "this guard makes the empty TMPDIR of its child process and removes it in a finally block",
  "tests/worker/browser-acceptance.test.ts": "removes every directory in a test.after hook",
  "tests/worker/node-approve.test.ts": "removes every directory in a test.after hook",
  "tests/worker/proof-bootstrap.test.ts": "removes every directory in a test.after hook",
  "tests/worker/commit-tail-writes.test.ts":
    "removes it in a finally block, also when the test body throws",
  "tests/worker/commit-tail.test.ts":
    "removes it in a finally block, also when the test body throws",
  "tests/worker/d1-migration-shim.test.ts":
    "removes it in a finally block, also when the test body throws",
  "tests/worker/d1-physical-schema.test.ts":
    "removes it in a finally block, also when the test body throws",
  "tests/worker/identity-core-oracle.test.ts": "removes its directory with t.after (Cloud #136)",
  "tests/worker/proof-assets.test.ts":
    "removes it in a finally block, also when the test body throws",
  "tests/worker/proof-cloudflare.test.ts":
    "removes it in a finally block, also when the test body throws",
  "tooling/dependency-policy.test.ts":
    "removes it in a finally block, also when the test body throws",
  "deploy/monitoring/monitoring.test.mjs":
    "its fixture returns a cleanup that every test calls in a finally block",
};

const mkdtempCall = /\bmkdtemp(?:Sync)?\b/u;
const scratchRoots = ["tests", "tooling", "deploy", "eng"];
const testFile = /\.test\.(?:ts|mjs)$|(?:^|\/)support\//u;

function* walk(directory: string): Generator<string> {
  for (const entry of readdirSync(path.join(repositoryRoot, directory), { withFileTypes: true })) {
    if (entry.name === "node_modules" || entry.name === "bin" || entry.name === "obj") continue;
    const relative = `${directory}/${entry.name}`;
    if (entry.isDirectory()) yield* walk(relative);
    else if (/\.(?:ts|mjs)$/u.test(entry.name) && testFile.test(relative)) yield relative;
  }
}

test("no test file creates a temporary directory except through scratchDirectory", () => {
  const offenders: string[] = [];
  const seen = new Set<string>();
  for (const root of scratchRoots)
    for (const file of walk(root)) {
      if (!mkdtempCall.test(readFileSync(path.join(repositoryRoot, file), "utf8"))) continue;
      seen.add(file);
      if (!(file in allowed)) offenders.push(file);
    }
  assert.deepEqual(
    offenders,
    [],
    "call scratchDirectory from tests/worker/support/scratch.ts instead of mkdtemp or mkdtempSync",
  );
  for (const file of Object.keys(allowed))
    assert(
      seen.has(file),
      `the allow-list names ${file}, which no longer calls mkdtemp: remove the entry`,
    );
});

for (const mode of ["pass", "throw"]) {
  test(`scratchDirectory leaves no directory behind when the test body ${mode === "throw" ? "throws" : "passes"}`, () => {
    const parent = mkdtempSync(path.join(tmpdir(), "scratch-hygiene-"));
    try {
      const temporary = path.join(parent, "tmp");
      mkdirSync(temporary);
      // A child of `node --test` inherits NODE_TEST_CONTEXT and would then report nothing.
      const { NODE_TEST_CONTEXT: _context, ...inherited } = process.env;
      const run = spawnSync(
        process.execPath,
        ["--test", path.join(repositoryRoot, "tests/worker/support/scratch-probe.ts")],
        {
          env: {
            ...inherited,
            TMPDIR: temporary,
            TMP: temporary,
            TEMP: temporary,
            SCRATCH_PROBE_MODE: mode,
          },
          encoding: "utf8",
        },
      );
      if (mode === "pass") assert.equal(run.status, 0, run.stdout + run.stderr);
      else
        assert.notEqual(
          run.status,
          0,
          "the probe must fail so the cleanup is exercised on failure",
        );
      assert.match(run.stdout, /relies on the exit hook/u, "the probe did not run");
      assert.deepEqual(readdirSync(temporary), [], "the probe left a directory behind");
    } finally {
      rmSync(parent, { recursive: true, force: true });
    }
  });
}
