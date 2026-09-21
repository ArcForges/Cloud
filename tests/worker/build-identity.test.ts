// SPDX-License-Identifier: AGPL-3.0-only
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { test } from "node:test";
import {
  axes,
  candidateEnvironment,
  expectedIdentity,
  imageBuildVariables,
  resolveAxes,
  sourceBuild,
  verifyHealthIdentity,
  verifyIdentity,
} from "../../tooling/build-identity.ts";

function fixture() {
  const catalog = JSON.parse(
    readFileSync(new URL("../../eng/version-sources.json", import.meta.url), "utf8"),
  ) as {
    schemaVersion: number;
    owner: string;
    axes: Record<string, { kind: string; sources?: string[]; alias?: string }>;
  };
  const sources: Record<string, string> = {};
  for (const name of axes) {
    const kind = catalog.axes[name]?.kind;
    assert(kind);
    catalog.axes[name] = { kind, sources: [`${name}.json`] };
    sources[`${name}.json`] =
      kind === "contracts"
        ? JSON.stringify({
            schema: "fixture.rpc.v1",
            dirty: false,
            descriptorSha256: "a".repeat(64),
          })
        : kind === "native-abi"
          ? "#define ARC_ABI_MAJOR 1\n#define ARC_ABI_MINOR 0\n"
          : kind === "packages"
            ? JSON.stringify({
                dependencies: { net10: { fixture: { type: "Direct", resolved: "1.0" } } },
              })
            : JSON.stringify({
                [kind === "migrations" ? "migrations" : "versions"]: [
                  { subject: "fixture", version: "1.0" },
                ],
              });
  }
  return {
    catalog,
    sources,
    read: (name: string) => {
      const value = sources[name];
      assert(value);
      return value;
    },
  };
}

test("each of nine independently sourced axes changes alone and deterministically", () => {
  const f = fixture();
  const initial = resolveAxes(f.catalog, f.read);
  assert.deepEqual(Object.keys(initial), axes);
  assert.deepEqual(resolveAxes(f.catalog, f.read), initial);
  for (const name of axes) {
    const key = `${name}.json`;
    const original = f.read(key);
    f.sources[key] = original.replace(
      name === "ContractSet" ? "rpc.v1" : name === "NativeAbiVersion" ? "MAJOR 1" : "1.0",
      name === "ContractSet" ? "rpc.v2" : name === "NativeAbiVersion" ? "MAJOR 2" : "2.0",
    );
    const changed = resolveAxes(f.catalog, f.read);
    for (const axis of axes) {
      if (axis === name) assert.notDeepEqual(initial[axis], changed[axis]);
      else assert.deepEqual(initial[axis], changed[axis]);
    }
    f.sources[key] = original;
  }
});

test("catalog rejects missing, unknown, aliased and unsafe sources", () => {
  for (const mode of ["missing", "unknown", "alias", "path", "duplicate", "version"]) {
    const f = fixture();
    if (mode === "missing") delete f.catalog.axes.AppVersion;
    if (mode === "unknown") f.catalog.axes.OtherVersion = { kind: "release" };
    if (mode === "alias")
      f.catalog.axes.AppVersion = {
        kind: "release",
        sources: ["AppVersion.json"],
        alias: "PackageVersion",
      };
    if (mode === "path") f.catalog.axes.AppVersion = { kind: "release", sources: ["../secret"] };
    if (mode === "duplicate")
      f.sources["AppVersion.json"] = JSON.stringify({
        versions: [
          { subject: "app", version: "1" },
          { subject: "app", version: "2" },
        ],
      });
    if (mode === "version")
      f.sources["AppVersion.json"] = JSON.stringify({
        versions: [{ subject: "app", version: "ContractSet" }],
      });
    assert.throws(() => resolveAxes(f.catalog, f.read));
  }
});

test("npm lock versions retain coordinate identity and exclude the workspace release", () => {
  const f = fixture();
  f.sources["PackageVersion.json"] = JSON.stringify({
    lockfileVersion: 3,
    packages: { "": { version: "99.0" }, "node_modules/example": { version: "2.3.4" } },
  });
  const packages = resolveAxes(f.catalog, f.read).PackageVersion as {
    values: { subject: string; version: string }[];
  };
  assert.equal(packages.values.length, 1);
  assert.equal(packages.values[0]?.subject, "pkg:npm/node_modules/example");
  assert.equal(packages.values[0]?.version, "2.3.4");
});

test("dirty, wrong-source, missing and malformed CI inputs fail closed", () => {
  const commit = "a".repeat(40);
  const env = {
    GITHUB_ACTIONS: "true",
    GITHUB_SHA: commit,
    GITHUB_REPOSITORY: "ArcForges/Cloud",
    GITHUB_RUN_ID: "123",
    GITHUB_RUN_ATTEMPT: "2",
  };
  assert.equal(sourceBuild(commit, 100, false, env).buildId, "123.2");
  assert.throws(() => sourceBuild(commit, 100, true, env));
  assert.throws(() => sourceBuild(commit, 0, false, env));
  for (const key of ["GITHUB_SHA", "GITHUB_REPOSITORY", "GITHUB_RUN_ID", "GITHUB_RUN_ATTEMPT"])
    assert.throws(() => sourceBuild(commit, 100, false, { ...env, [key]: "" }));
  assert.equal(sourceBuild(commit, 100, true, {}).kind, "local");
});

test("rehashed identity and runtime health cannot substitute any source, axis or run", () => {
  const version =
    process.env.GITHUB_ACTIONS === "true"
      ? `0.1.0-ci.${process.env.GITHUB_RUN_NUMBER}.${process.env.GITHUB_RUN_ATTEMPT}`
      : "0.1.0-local.1";
  const expected = expectedIdentity(version);
  verifyIdentity(expected, version);
  verifyHealthIdentity({ artifact: expected.artifact, build: expected.build }, expected);
  for (const field of [
    "sourceCommit",
    "dirty",
    "buildId",
    "pipelineRun",
    "sourceDateEpoch",
    "kind",
  ]) {
    const changed = structuredClone(expected);
    Object.assign(changed.build, {
      [field]:
        field === "dirty" ? !changed.build.dirty : field === "sourceDateEpoch" ? 1 : "invalid",
    });
    assert.throws(() => verifyIdentity(changed, version));
    assert.throws(() =>
      verifyHealthIdentity({ artifact: changed.artifact, build: changed.build }, expected),
    );
  }
  const changed = structuredClone(expected);
  changed.axes.ContractSet = { status: "present", values: [] };
  assert.throws(() => verifyIdentity(changed, version));
  const variables = imageBuildVariables(expected);
  assert.equal(variables.BUILD_ID, expected.build.buildId);
  assert.equal(variables.SOURCE_COMMIT, expected.build.sourceCommit);
  assert.equal(variables.APP_VERSION, version);
});

test("deployment retry retains the original candidate attempt without accepting another run", () => {
  const env = { GITHUB_ACTIONS: "true", GITHUB_RUN_NUMBER: "14", GITHUB_RUN_ATTEMPT: "2" };
  assert.equal(candidateEnvironment("0.1.0-ci.14.1", env).GITHUB_RUN_ATTEMPT, "1");
  assert.equal(candidateEnvironment("0.1.0-ci.14.2", env).GITHUB_RUN_ATTEMPT, "2");
  assert.throws(() => candidateEnvironment("0.1.0-ci.14.3", env));
  assert.throws(() => candidateEnvironment("0.1.0-ci.13.1", env));
  assert.throws(() => candidateEnvironment("0.1.0-local.1", env));
  assert.equal(env.GITHUB_RUN_ATTEMPT, "2");
});
