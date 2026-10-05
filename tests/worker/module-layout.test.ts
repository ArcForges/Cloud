// SPDX-License-Identifier: AGPL-3.0-only
// The nineteen module boundaries as files: the owner registry, the module projects, their references, the host listing and the
// solution agree. The C# architecture tests (ModuleBoundaryTests) enforce the same from the compiled side.
import assert from "node:assert/strict";
import { existsSync, readdirSync, readFileSync } from "node:fs";
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
        references.every((reference) => !reference.includes(".Modules.")),
        `${entry} references a module`,
      );
  }
});
