// SPDX-License-Identifier: AGPL-3.0-only
// The Docker build context must carry every C# source folder of the host: a folder missing from
// .dockerignore compiles locally and fails only in the hosted image build.
import assert from "node:assert/strict";
import { readdirSync, readFileSync } from "node:fs";
import path from "node:path";
import test from "node:test";

const root = path.resolve(import.meta.dirname, "../..");
const project = "src/ArcForges.Cloud";

function sourceFolders(directory: string, relative = ""): string[] {
  const folders: string[] = [];
  const entries = readdirSync(path.join(root, project, directory), { withFileTypes: true });
  if (entries.some((entry) => entry.isFile() && entry.name.endsWith(".cs"))) folders.push(relative);
  for (const entry of entries)
    if (entry.isDirectory() && !["bin", "obj"].includes(entry.name))
      folders.push(
        ...sourceFolders(path.join(directory, entry.name), path.posix.join(relative, entry.name)),
      );
  return folders;
}

test("every host source folder is admitted to the Docker context by explicit directory and file rules", () => {
  const rules = new Set(
    readFileSync(path.join(root, ".dockerignore"), "utf8")
      .split("\n")
      .map((line) => line.trim())
      .filter(Boolean),
  );
  const folders = sourceFolders("");
  assert(folders.includes(""), "the root source folder exists");
  assert(folders.includes("Storage") && folders.includes("Foundation"));
  for (const folder of folders) {
    const prefix = folder ? `${project}/${folder}` : project;
    assert(rules.has(`!${prefix}/*.cs`), `Missing source rule for ${prefix}`);
    if (folder) assert(rules.has(`!${prefix}/`), `Missing directory rule for ${prefix}`);
  }
  // Test projects, build output and the plan SQL are never part of the image context.
  for (const forbidden of ["!tests/", "!worker/", "!src/ArcForges.Cloud/Storage/Plans/"])
    assert(!rules.has(forbidden), forbidden);
});
