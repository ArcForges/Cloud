// SPDX-License-Identifier: AGPL-3.0-only
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import os from "node:os";
import path from "node:path";
import { test } from "node:test";
import { auditLicences } from "../../tooling/licence-boundary.ts";

function fixture() {
  const root = mkdtempSync(path.join(os.tmpdir(), "licence-inventory-"));
  execFileSync("git", ["init", "-q"], { cwd: root, windowsHide: true });
  execFileSync(
    "git",
    [
      "-c",
      "user.name=Licence Test",
      "-c",
      "user.email=licence@example.invalid",
      "-c",
      "commit.gpgsign=false",
      "commit",
      "--allow-empty",
      "-qm",
      "fixture",
    ],
    { cwd: root, windowsHide: true },
  );
  const write = (file: string, value: unknown) => {
    mkdirSync(path.dirname(path.join(root, file)), { recursive: true });
    writeFileSync(path.join(root, file), typeof value === "string" ? value : JSON.stringify(value));
  };
  const policy = {
    schemaVersion: 1,
    repository: "Cloud",
    spdxLicense: "AGPL-3.0-only",
    licenceBoundary: "AGPL",
    projects: [{ path: "package.json", kind: "npm" }],
  };
  const manifest = {
    name: "@arcforges/test",
    license: "AGPL-3.0-only",
    arcforges: { licenceBoundary: "AGPL" },
  };
  write("eng/policy/licence-boundary.json", policy);
  write("package.json", manifest);
  const cleanup = () => {
    assert.equal(path.dirname(root), os.tmpdir());
    assert(path.basename(root).startsWith("licence-inventory-"));
    rmSync(root, { recursive: true });
  };
  return { root, write, policy, manifest, cleanup };
}
test("Git inventory checks existing and newly added projects", () => {
  const f = fixture();
  try {
    assert.equal(auditLicences(f.root).projects.length, 1);
    f.write("unregistered/package.json", f.manifest);
    assert.throws(() => auditLicences(f.root), /inventory drift/u);
  } finally {
    f.cleanup();
  }
});
test("a missing boundary and edited owner assignment both fail", () => {
  const f = fixture();
  try {
    f.write("package.json", { ...f.manifest, arcforges: {} });
    assert.throws(() => auditLicences(f.root), /Incorrect boundary/u);
    f.write("package.json", f.manifest);
    f.policy.licenceBoundary = "Apache";
    f.write("eng/policy/licence-boundary.json", f.policy);
    assert.throws(() => auditLicences(f.root));
  } finally {
    f.cleanup();
  }
});
test("inconsistent managed SPDX, imported overrides and escaped references fail", () => {
  const f = fixture();
  try {
    f.policy.projects.push({ path: "app.csproj", kind: "msbuild" });
    f.write("eng/policy/licence-boundary.json", f.policy);
    const project =
      "<Project><PropertyGroup><PackageLicenseExpression>AGPL-3.0-only</PackageLicenseExpression><LicenceBoundary>AGPL</LicenceBoundary></PropertyGroup></Project>";
    f.write("app.csproj", project);
    assert.equal(auditLicences(f.root).projects.length, 2);
    f.write("app.csproj", project.replace("AGPL-3.0-only", "Apache-2.0"));
    assert.throws(() => auditLicences(f.root), /Incorrect SPDX/u);
    f.write(
      "app.csproj",
      project.replace(
        "</Project>",
        '<ItemGroup><ProjectReference Include="../outside.csproj" /></ItemGroup></Project>',
      ),
    );
    assert.throws(() => auditLicences(f.root), /Escaped\/unregistered/u);
    f.write("app.csproj", project);
    f.write(
      "Directory.Build.props",
      "<Project><PropertyGroup><LicenceBoundary>Apache</LicenceBoundary></PropertyGroup></Project>",
    );
    assert.throws(() => auditLicences(f.root), /Imported licence override/u);
  } finally {
    f.cleanup();
  }
});
test("unknown locked transitive packages and unversioned npm aliases fail", () => {
  const f = fixture();
  try {
    f.write("package-lock.json", { packages: { "node_modules/@arcforges/unknown": {} } });
    assert.throws(() => auditLicences(f.root), /Unknown first-party/u);
    f.write("package-lock.json", { packages: {} });
    f.write("package.json", { ...f.manifest, dependencies: { alias: "npm:@arcforges/unknown" } });
    assert.throws(() => auditLicences(f.root), /Unknown first-party/u);
  } finally {
    f.cleanup();
  }
});
test("Gradle declarations and unpublished source inputs are checked", () => {
  const f = fixture();
  try {
    f.policy.projects.push({ path: "build.gradle.kts", kind: "gradle" });
    f.write("eng/policy/licence-boundary.json", f.policy);
    f.write(
      "build.gradle.kts",
      'extra["spdxLicense"] = "AGPL-3.0-only"\nextra["licenceBoundary"] = "Apache"\n',
    );
    assert.throws(() => auditLicences(f.root), /Incorrect Gradle/u);
    f.write(
      "build.gradle.kts",
      'extra["spdxLicense"] = "AGPL-3.0-only"\nextra["licenceBoundary"] = "AGPL"\nmavenLocal()\n',
    );
    assert.throws(() => auditLicences(f.root), /Unpublished Gradle/u);
  } finally {
    f.cleanup();
  }
});

test("comments cannot join fragments into a licence declaration", () => {
  const f = fixture();
  try {
    f.policy.projects.push({ path: "app.csproj", kind: "msbuild" });
    f.write("eng/policy/licence-boundary.json", f.policy);
    f.write(
      "app.csproj",
      "<Project><PropertyGroup><PackageLicenseExpression>AGPL-3.0-only</PackageLicenseExpression><LicenceB<!-- split -->oundary>AGPL</LicenceBoundary></PropertyGroup></Project>",
    );
    assert.throws(() => auditLicences(f.root), /Incorrect boundary/u);
  } finally {
    f.cleanup();
  }
});
