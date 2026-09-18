// SPDX-License-Identifier: AGPL-3.0-only
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { lstatSync, readFileSync, realpathSync } from "node:fs";
import path from "node:path";

const owner = "Cloud";

export function evaluatedManagedLicences(root: string) {
  const source = auditLicences(root);
  const evaluatedMSBuild = source.projects
    .filter((row) => row.kind === "msbuild")
    .flatMap((row) =>
      ["Debug", "Release"].map((configuration) => {
        const evaluated = JSON.parse(
          execFileSync(
            "dotnet",
            [
              "msbuild",
              row.path,
              "-t:ArcForgesVerifyLicenceBoundary",
              `-p:Configuration=${configuration}`,
              "-getProperty:PackageLicenseExpression,LicenceBoundary",
              "-getItem:ProjectReference",
              "-verbosity:quiet",
            ],
            { cwd: root, encoding: "utf8", windowsHide: true },
          ),
        ) as {
          Properties: { PackageLicenseExpression: string; LicenceBoundary: string };
          Items: { ProjectReference: { FullPath: string }[] };
        };
        assert.deepEqual(evaluated.Properties, {
          PackageLicenseExpression: "AGPL-3.0-only",
          LicenceBoundary: "AGPL",
        });
        return {
          path: row.path,
          configuration,
          properties: evaluated.Properties,
          references: evaluated.Items.ProjectReference.map((item) =>
            path.relative(root, item.FullPath).split(path.sep).join("/"),
          ),
        };
      }),
    );
  return { ...source, evaluatedMSBuild };
}
const extensions = new Set([".csproj", ".fsproj", ".vbproj", ".vcxproj", ".esproj"]);
const npmOwners = new Set([
  "@arcforges/proto",
  "@arcforges/api-client",
  "@arcforges/contract-fixtures",
  "@arcforges/ai-internal",
  "@arcforges/ai",
  "@arcforges/cloud-workspace",
  "@arcforges/web-workspace",
  "@arcforges/web-site",
  "@arcforges/web-ui",
]);
interface Row {
  path: string;
  kind: string;
}
interface Manifest {
  name: string;
  license: string;
  arcforges: { licenceBoundary: string };
  dependencies?: Record<string, string>;
  devDependencies?: Record<string, string>;
  peerDependencies?: Record<string, string>;
  optionalDependencies?: Record<string, string>;
}
function kind(file: string): string | undefined {
  if (extensions.has(path.extname(file))) return "msbuild";
  return (
    {
      "package.json": "npm",
      "build.gradle.kts": "gradle",
      "build.gradle": "gradle",
      "CMakeLists.txt": "cmake",
    } as Record<string, string>
  )[path.basename(file)];
}
function checkPackage(name: string) {
  if (name.toLowerCase().startsWith("@arcforges/"))
    assert(npmOwners.has(name), `Unknown first-party package owner: ${name}`);
  if (name.toLowerCase().startsWith("arcforges."))
    assert(
      ["arcforges.contracts.publicapi", "arcforges.build.policy"].includes(name.toLowerCase()),
      `Unknown first-party package owner: ${name}`,
    );
  if (name.toLowerCase().startsWith("io.github.arcforges:"))
    assert(
      ["contracts-proto", "contracts-client", "contracts-connect-client", "contract-fixtures"].some(
        (module) => name === `io.github.arcforges:${module}`,
      ),
      `Unknown first-party package owner: ${name}`,
    );
}
const xml = (text: string) => text.replace(/<!--[\s\S]*?-->/gu, "");
const values = (text: string, key: string) =>
  [...xml(text).matchAll(new RegExp(`<${key}(?:\\s[^>]*)?>([^<]*)</${key}>`, "gu"))].map(
    (match) => match[1],
  );
export function auditLicences(root: string) {
  root = realpathSync(root);
  const git = (...args: string[]) =>
    execFileSync("git", args, { cwd: root, encoding: "utf8", windowsHide: true }).trim();
  const files = [
    ...new Set(
      git("ls-files", "-z", "--cached", "--others", "--exclude-standard")
        .split("\0")
        .filter(Boolean),
    ),
  ].sort();
  const read = (file: string) => {
    const full = path.resolve(root, file);
    assert(
      full.startsWith(root + path.sep) && realpathSync(full).startsWith(root + path.sep),
      `Escaped input: ${file}`,
    );
    for (let current = full; current !== root; current = path.dirname(current))
      assert(!lstatSync(current).isSymbolicLink(), `Linked input: ${file}`);
    return readFileSync(full, "utf8");
  };
  const policy = JSON.parse(read("eng/policy/licence-boundary.json")) as {
    schemaVersion: number;
    repository: string;
    spdxLicense: string;
    licenceBoundary: string;
    projects: Row[];
  };
  assert.deepEqual(Object.keys(policy).sort(), [
    "licenceBoundary",
    "projects",
    "repository",
    "schemaVersion",
    "spdxLicense",
  ]);
  assert.equal(policy.schemaVersion, 1);
  assert.equal(policy.repository, owner);
  assert.equal(policy.spdxLicense, "AGPL-3.0-only");
  assert.equal(policy.licenceBoundary, "AGPL");
  const actual = files
    .filter((file) => kind(file))
    .map((file) => ({ path: file, kind: kind(file) }));
  assert(actual.length > 0);
  assert.deepEqual(
    [...policy.projects].sort((a, b) => a.path.localeCompare(b.path, "en")),
    [...actual].sort((a, b) => a.path.localeCompare(b.path, "en")),
    "Project licence inventory drift.",
  );
  const npmNames = new Map(
    actual
      .filter((row) => row.kind === "npm")
      .map((row) => [(JSON.parse(read(row.path)) as Manifest).name, row.path]),
  );
  assert.equal(
    npmNames.size,
    actual.filter((row) => row.kind === "npm").length,
    "Duplicate npm identity.",
  );
  const projectNames = new Set(
    actual
      .filter((row) => row.kind === "msbuild")
      .map((row) => path.basename(row.path, path.extname(row.path)).toLowerCase()),
  );
  const edges: { source: string; target: string; kind: string }[] = [];
  for (const row of actual) {
    const text = read(row.path);
    if (row.kind === "npm") {
      const manifest = JSON.parse(text) as Manifest;
      assert.equal(manifest.license, "AGPL-3.0-only", `Incorrect SPDX: ${row.path}`);
      assert.deepEqual(
        manifest.arcforges,
        { licenceBoundary: "AGPL" },
        `Incorrect boundary: ${row.path}`,
      );
      for (const section of [
        "dependencies",
        "devDependencies",
        "peerDependencies",
        "optionalDependencies",
      ] as const)
        for (const [name, version] of Object.entries(manifest[section] ?? {})) {
          assert(
            !/^(?:file:|link:|git\+|\.\.?\/)/u.test(version),
            `Unpublished source reference: ${name}`,
          );
          if (!npmNames.has(name)) checkPackage(name);
          if (version.startsWith("npm:")) {
            const alias = version.slice(4);
            const end = alias.indexOf("@", 1);
            checkPackage(end < 0 ? alias : alias.slice(0, end));
          }
          edges.push({
            source: row.path,
            target: npmNames.get(name) ?? name,
            kind: npmNames.has(name) ? "project" : "package",
          });
        }
    } else if (row.kind === "msbuild") {
      assert.deepEqual(
        values(text, "PackageLicenseExpression"),
        ["AGPL-3.0-only"],
        `Incorrect SPDX: ${row.path}`,
      );
      assert.deepEqual(
        values(text, "LicenceBoundary"),
        ["AGPL"],
        `Incorrect boundary: ${row.path}`,
      );
      for (const name of [...values(text, "AssemblyName"), ...values(text, "PackageId")])
        if (name) projectNames.add(name.toLowerCase());
    } else if (row.kind === "gradle") {
      for (const [key, value] of [
        ["spdxLicense", "AGPL-3.0-only"],
        ["licenceBoundary", "AGPL"],
      ])
        assert.deepEqual(
          [...text.matchAll(new RegExp(`extra\\["${key}"\\]\\s*=\\s*"([^"\\n]+)"`, "gu"))].map(
            (match) => match[1],
          ),
          [value],
          `Incorrect Gradle declaration: ${row.path}`,
        );
    } else throw new Error(`A new build system needs a reviewed licence verifier: ${row.path}`);
  }
  for (const file of files) {
    const name = path.basename(file);
    if (extensions.has(path.extname(file)) || [".props", ".targets"].includes(path.extname(file))) {
      const text = xml(read(file));
      for (const [key, expected] of [
        ["PackageLicenseExpression", "AGPL-3.0-only"],
        ["LicenceBoundary", "AGPL"],
      ] as const)
        assert(
          values(text, key).every((value) => value === expected),
          `Imported licence override: ${file}`,
        );
      for (const match of text.matchAll(/<ProjectReference\s[^>]*?Include=["']([^"']+)["']/gu)) {
        const include = match[1];
        assert(include, "Missing project-reference path.");
        assert(!/[$@*?;]/u.test(include), `Nonliteral reference: ${file}`);
        const target = path
          .relative(root, path.resolve(root, path.dirname(file), include.replaceAll("\\", "/")))
          .split(path.sep)
          .join("/");
        assert(
          actual.some((row) => row.path === target && row.kind === "msbuild"),
          `Escaped/unregistered reference: ${file}`,
        );
        edges.push({ source: file, target, kind: "project" });
      }
      for (const match of text.matchAll(
        /<Package(?:Reference|Version)\s[^>]*?(?:Include|Update)=["']([^"']+)["']/gu,
      )) {
        assert(match[1], "Missing package-reference identity.");
        checkPackage(match[1]);
      }
    } else if (name === "package-lock.json") {
      const locked = JSON.parse(read(file)) as { packages: Record<string, { name?: string }> };
      for (const [name, entry] of Object.entries(locked.packages)) {
        const identity = entry.name ?? name.split("node_modules/").at(-1) ?? "";
        if (!npmNames.has(identity)) checkPackage(identity);
      }
    } else if (name === "packages.lock.json") {
      const locked = JSON.parse(read(file)) as {
        dependencies: Record<string, Record<string, { type: string }>>;
      };
      for (const framework of Object.values(locked.dependencies))
        for (const [name, entry] of Object.entries(framework)) {
          if (entry.type.toLowerCase() === "project")
            assert(projectNames.has(name.toLowerCase()), `Unknown locked project: ${name}`);
          else checkPackage(name);
        }
    } else if (name.endsWith(".lockfile")) {
      for (const line of read(file).split("\n"))
        if (line && !line.startsWith("#")) checkPackage(line.split(":").slice(0, 2).join(":"));
    } else if (/^(?:build|settings)\.gradle(?:\.kts)?$/u.test(name)) {
      const text = read(file);
      assert(
        !/includeBuild\s*\(|mavenLocal\s*\(/u.test(text),
        `Unpublished Gradle source: ${file}`,
      );
      assert(
        !/\bproject\(\s*["']:/u.test(text),
        `New Gradle project graph requires licence review: ${file}`,
      );
      for (const match of text.matchAll(/io\.github\.arcforges:[A-Za-z0-9_.-]+/gu))
        checkPackage(match[0]);
    }
  }
  return {
    result: "passed",
    repository: owner,
    commit: git("rev-parse", "HEAD"),
    dirty: Boolean(git("status", "--porcelain")),
    projects: actual.map((row) => ({
      ...row,
      spdxLicense: "AGPL-3.0-only",
      licenceBoundary: "AGPL",
    })),
    references: edges,
    findings: [],
    evidenceClass: "source-and-npm-project-inventory-with-locked-first-party-references",
  };
}
