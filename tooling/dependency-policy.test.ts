// SPDX-License-Identifier: AGPL-3.0-only
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import path from "node:path";
import test from "node:test";
import {
  auditDependencies,
  digest,
  immutableCoordinates,
  validateHistoricalCoordinates,
  validateClosure,
  validateCsharpImports,
  validateImports,
  validatePolicy,
  type Policy,
} from "./dependency-policy.ts";

const root = process.cwd();
const baseline = JSON.parse(readFileSync("eng/policy/dependency-policy.json", "utf8")) as Policy;
const lock = JSON.parse(readFileSync("package-lock.json", "utf8"));
const firstDependency = Object.keys(baseline.closure)[0];
assert(firstDependency, "Fixture requires an admitted dependency");
test("actual repository admission", () => {
  assert.equal(auditDependencies(root).result, "passed");
});
test("forbidden licence", () => {
  const packages = structuredClone(lock.packages);
  packages[firstDependency].license = "GPL-3.0-only";
  assert.throws(() => validateClosure(baseline, packages), /Forbidden licence/u);
});
test("floating tag", () => {
  const packages = structuredClone(lock.packages);
  packages[firstDependency].version = "latest";
  assert.throws(() => validateClosure(baseline, packages), /Floating version/u);
});
test("same version with altered bytes", () => {
  const packages = structuredClone(lock.packages);
  packages[firstDependency].integrity = `sha512-${Buffer.alloc(64).toString("base64")}`;
  assert.throws(() => validateClosure(baseline, packages), /mutable-version/u);
});
test("wrong publisher", () => {
  const policy = structuredClone(baseline);
  policy.firstParty["@arcforges/proto"] = { publisher: "other/Contracts", visibility: "public" };
  assert.throws(() => validatePolicy(policy), /Wrong publisher/u);
});
test("untrusted registry", () => {
  const packages = structuredClone(lock.packages);
  packages[firstDependency].resolved = "https://registry.npmjs.org.evil.invalid/p.tgz";
  assert.throws(
    () => validateClosure(baseline, packages),
    /Untrusted feed|Wrong publisher artifact/u,
  );
});
test("upgrade needs input-bound review and framework assessment", () => {
  const policy = structuredClone(baseline);
  policy.inputs["package-lock.json"] = "0".repeat(64);
  assert.throws(() => validatePolicy(policy), /Upgrade review/u);
  policy.review.inputs = structuredClone(policy.inputs);
  policy.review.runtimeAssessment = "";
  assert.throws(() => validatePolicy(policy), /runtimeAssessment/u);
});
test("native additions need adoption evidence", () => {
  const policy = structuredClone(baseline);
  policy.native.mode = "anything-installed";
  assert.throws(() => validatePolicy(policy), /Native adoption/u);
});
test("public sources reject static, re-export and dynamic internal imports", () => {
  for (const source of [
    'import x from "@arcforges/ai-internal";',
    'export * from "@arcforges/proto/internal";',
    'void import("@arcforges/storage-internal");',
    'const x = require("@arcforges/ai-internal");',
  ])
    assert.throws(() => validateImports(root, "src/example.ts", source, baseline), /[Ii]nternal/u);
});
test("source cannot escape into a sibling repository", () => {
  assert.throws(
    () => validateImports(root, "example.ts", 'import "../Contracts/private.ts";', baseline),
    /Sibling source/u,
  );
  validateImports(root, "src/example.ts", 'import type { X } from "@arcforges/proto";', baseline);
});
test("stable closure cannot inherit foundation candidates", () => {
  const policy = structuredClone(baseline);
  policy.channel = "stable";
  assert.throws(() => validateClosure(policy, lock.packages), /Prerelease/u);
});
test("input hashes are portable, content sensitive and independent of outer metadata", () => {
  assert.equal(digest("a\r\n"), digest("a\n"));
  assert.notEqual(digest("a\n"), digest("b\n"));
  assert(path.isAbsolute(root));
});

test("reviewed successor cannot replace bytes for an admitted coordinate", () => {
  assert.throws(
    () =>
      validateHistoricalCoordinates(
        { "example@1.0.0": "sha512-original" },
        { "example@1.0.0": "sha512-replacement" },
      ),
    /despite successor review/u,
  );
  validateHistoricalCoordinates(
    { "example@1.0.0": "sha512-original" },
    { "example@1.0.1": "sha512-new-version" },
  );
});
test("comments and escaped module names do not bypass public import scope", () => {
  assert.throws(
    () =>
      validateImports(
        root,
        "src/example.ts",
        'import /* comment */ "@arcforges/ai-internal";',
        baseline,
      ),
    /internal/u,
  );
  assert.throws(
    () =>
      validateImports(root, "src/example.ts", `void import(\`@arcforges/\${kind}\`);`, baseline),
    /Computed import/u,
  );
});

test("duplicate nested coordinates cannot hide different package bytes", () => {
  assert.throws(
    () =>
      immutableCoordinates({
        "node_modules/example": { version: "1.0.0", integrity: "sha512-first" },
        "node_modules/parent/node_modules/example": {
          version: "1.0.0",
          integrity: "sha512-second",
        },
      }),
    /Conflicting integrity/u,
  );
});

const withInternalPackage = () => {
  const policy = structuredClone(baseline);
  policy.firstParty["@arcforges/ai-internal"] = {
    publisher: "ArcForges/Contracts",
    visibility: "internal",
  };
  return policy;
};
test("only the explicitly named private generated package is admitted, and only for Cloud", () => {
  validatePolicy(withInternalPackage());
  const unnamed = structuredClone(baseline);
  unnamed.firstParty["@arcforges/storage-internal"] = {
    publisher: "ArcForges/Contracts",
    visibility: "internal",
  };
  assert.throws(() => validatePolicy(unnamed), /Unadmitted internal/u);
  const exposed = withInternalPackage();
  exposed.firstParty["@arcforges/ai-internal"] = {
    publisher: "ArcForges/Contracts",
    visibility: "public",
  };
  assert.throws(() => validatePolicy(exposed), /Internal package/u);
  const publicClient = withInternalPackage();
  publicClient.firstParty["@arcforges/proto"] = {
    publisher: "ArcForges/Contracts",
    visibility: "internal",
  };
  assert.throws(() => validatePolicy(publicClient), /Internal package/u);
  const other = withInternalPackage();
  other.repository = "Web";
  assert.throws(() => validatePolicy(other), /outside its owner/u);
  const foreign = withInternalPackage();
  foreign.firstParty["@arcforges/ai-internal"] = {
    publisher: "other/Contracts",
    visibility: "internal",
  };
  assert.throws(() => validatePolicy(foreign), /Wrong publisher/u);
});
test("the private generated package is importable only by Worker sources at its exact root", () => {
  const policy = withInternalPackage();
  validateImports(root, "worker/storage.ts", 'import { x } from "@arcforges/ai-internal";', policy);
  for (const [file, source] of [
    ["src/example.ts", 'import { x } from "@arcforges/ai-internal";'],
    ["packages/example.ts", 'export * from "@arcforges/ai-internal";'],
    ["worker/storage.ts", 'import { x } from "@arcforges/ai-internal/dist/index.js";'],
    ["worker/storage.ts", 'import { x } from "@arcforges/storage-internal";'],
    ["worker/storage.ts", 'void import("@arcforges/ai-internal/gen");'],
  ] as const)
    assert.throws(() => validateImports(root, file, source, policy), /[Ii]nternal/u);
});
test("private generated C# records are importable only by the Cloud host and its tests", () => {
  const source = "using ArcForges.Contracts.CloudInternal.Storage.V1;\n";
  validateCsharpImports("src/ArcForges.Cloud/Storage/Example.cs", source);
  validateCsharpImports("tests/ArcForges.Cloud.Tests/Example.cs", source);
  for (const file of ["tests/ArcForges.Cloud.Consumer/Program.cs", "src/Other/Example.cs"])
    assert.throws(() => validateCsharpImports(file, source), /Unadmitted private/u);
  assert.throws(
    () =>
      validateCsharpImports(
        "src/ArcForges.Cloud/Example.cs",
        "using ArcForges.Contracts.Internal.Storage;\n",
      ),
    /Unadmitted private/u,
  );
  assert.throws(
    () =>
      validateCsharpImports(
        "tests/ArcForges.Cloud.Consumer/Program.cs",
        "var x = global::ArcForges.Contracts.CloudInternal.Storage.V1.ExecutePlanRequest.Default;\n",
      ),
    /Unadmitted private/u,
  );
});
