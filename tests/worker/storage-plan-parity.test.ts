// SPDX-License-Identifier: AGPL-3.0-only
// CLOUD.84 S40(1): the C# generator is the only generator of the storage plans, and the TypeScript test-support helpers in
// eng/verification/storage-plans.ts are kept only so that the remaining suites can build a manifest. This parity test makes the two
// impossible to drift apart: the manifest built here must carry the same hash and the same plans as the C# outputs.
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import path from "node:path";
import test from "node:test";
import { buildManifest, type PlanDefinition } from "../../eng/verification/storage-plans.ts";
import { manifestHash, plans } from "../../worker/storage/plans.generated.ts";
import { repositoryRoot } from "./support/sqlite-d1.ts";

const read = (relative: string) => readFileSync(path.join(repositoryRoot, relative), "utf8");
const byIdentity = (a: { id: string; version: number }, b: { id: string; version: number }) =>
  a.id === b.id ? a.version - b.version : a.id < b.id ? -1 : 1;

const manifest = buildManifest(repositoryRoot);
const csharpManifest = read("src/ArcForges.Cloud.Storage.D1/PlanManifest.g.cs");
const csharpHash = /public const string Hash = "([0-9a-f]{64})";/u.exec(csharpManifest)?.[1];

test("the TypeScript test-support manifest has the C# manifest hash and the Worker dictionary hash", () => {
  assert.ok(csharpHash, "PlanManifest.g.cs declares its manifest hash");
  assert.equal(manifest.manifestHash, csharpHash);
  assert.equal(manifest.manifestHash, manifestHash);
});

test("the TypeScript-built plans equal the Worker dictionary statement for statement", () => {
  const built = manifest.plans
    .map((plan: PlanDefinition) => ({
      id: plan.id,
      version: plan.version,
      access: plan.access,
      maxRows: plan.maxRows,
      // The family roles stay in the manifest; the Worker dictionary keeps the one shape of every plan.
      statements: plan.statements.map(({ sql, params, returns }) => ({ sql, params, returns })),
    }))
    .toSorted(byIdentity);
  assert.equal(built.length, plans.length);
  assert.deepEqual(built, [...plans].toSorted(byIdentity));
});

test("every plan is declared by the C# manifest, and the expanded family plans carry the same identities", () => {
  for (const plan of manifest.plans) {
    assert.ok(
      csharpManifest.includes(`"${plan.id}"`),
      `${plan.id}@${plan.version} is missing from PlanManifest.g.cs`,
    );
  }
  const expanded = JSON.parse(read("storage/plans/families.expanded.json")) as {
    plans: { id: string; version: number; sha256: string }[];
  };
  const familyPlans = manifest.plans
    .filter((plan) => plan.family !== undefined)
    .map(({ id, version, sha256 }) => ({ id, version, sha256 }));
  assert.ok(familyPlans.length > 0, "the family plans are present");
  assert.deepEqual(
    expanded.plans.map(({ id, version, sha256 }) => ({ id, version, sha256 })).toSorted(byIdentity),
    familyPlans.toSorted(byIdentity),
  );
});
