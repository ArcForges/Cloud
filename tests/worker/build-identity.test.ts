// SPDX-License-Identifier: AGPL-3.0-only
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
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
  const health = {
    artifact: expected.artifact,
    build: expected.build,
    runtime: "go",
    nativeAot: false,
  };
  verifyHealthIdentity(health, expected);
  assert.throws(() => verifyHealthIdentity({ ...health, runtime: "csharp" }, expected));
  assert.throws(() => verifyHealthIdentity({ ...health, nativeAot: true }, expected));
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
      verifyHealthIdentity(
        { ...health, artifact: changed.artifact, build: changed.build },
        expected,
      ),
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

test("the historical Contracts receipt shape resolves through the Hello schema source entry", () => {
  const f = fixture();
  const hello = "public/proto/arcforges/hello/v1/hello.proto";
  const receipt = (sources: Record<string, string>, extra: Record<string, unknown> = {}) =>
    JSON.stringify({
      dirty: false,
      descriptorSha256: "b".repeat(64),
      schemaSources: sources,
      ...extra,
    });
  f.sources["ContractSet.json"] = receipt({
    [hello]: "c".repeat(64),
    "other.proto": "d".repeat(64),
  });
  const resolved = resolveAxes(f.catalog, f.read);
  const contract = resolved.ContractSet as {
    values: {
      subject: string;
      version: string;
      descriptorSha256: string;
      source: { path: string };
    }[];
  };
  const [value] = contract.values;
  assert.equal(contract.values.length, 1);
  assert.equal(value?.subject, "arcforges.hello");
  assert.equal(value?.version, "1");
  assert.equal(value?.descriptorSha256, "b".repeat(64));
  assert.equal(value?.source.path, "ContractSet.json");
  // The descriptor still moves the axis, so a changed contract set cannot hide.
  f.sources["ContractSet.json"] = receipt(
    { [hello]: "c".repeat(64) },
    { descriptorSha256: "e".repeat(64) },
  );
  assert.notDeepEqual(resolveAxes(f.catalog, f.read).ContractSet, resolved.ContractSet);
  for (const bad of [
    receipt({ "other.proto": "d".repeat(64) }),
    receipt({ [hello]: "not-a-hash" }),
    receipt({ [hello]: "c".repeat(64) }, { dirty: true }),
    receipt({ [hello]: "c".repeat(64) }, { descriptorSha256: "short" }),
    JSON.stringify({ dirty: false, descriptorSha256: "b".repeat(64) }),
  ]) {
    f.sources["ContractSet.json"] = bad;
    assert.throws(() => resolveAxes(f.catalog, f.read));
  }
});

test("the historical NuGet source still resolves only against its original package pin", () => {
  const f = fixture();
  const source = "packages/contracts/source.json";
  f.catalog.axes.ContractSet = { kind: "contracts", sources: [source] };
  f.sources[source] = JSON.stringify({
    schema: "arcforges.hello.v1",
    version: "1.0.0-ci.287.1",
    dirty: false,
    descriptorSha256: "a".repeat(64),
  });
  f.sources["Directory.Packages.props"] =
    '<PackageVersion Include="ArcForges.Contracts.PublicApi" Version="1.0.0-ci.287.1" />';
  assert.deepEqual(resolveAxes(f.catalog, f.read).ContractSet, {
    status: "present",
    values: [
      {
        subject: "arcforges.hello",
        version: "1",
        source: { path: source, sha256: createHash("sha256").update(f.read(source)).digest("hex") },
        descriptorSha256: "a".repeat(64),
      },
    ],
  });
  f.sources["Directory.Packages.props"] = f
    .read("Directory.Packages.props")
    .replace("287.1", "481.1");
  assert.throws(() => resolveAxes(f.catalog, f.read));
});

function goFixture() {
  const f = fixture();
  const source = "center/dependencies.json";
  f.catalog.axes.ContractSet = { kind: "contracts", sources: [source] };
  f.catalog.axes.PackageVersion = { kind: "packages", sources: [source, "PackageVersion.json"] };
  const contracts = {
    path: "github.com/ArcForges/Contracts/go",
    repository: "https://github.com/ArcForges/Contracts",
    commit: "a".repeat(40),
    version: "v1.0.0-ci.481.1",
    sum: `h1:${"a".repeat(43)}=`,
    goModSum: `h1:${"b".repeat(43)}=`,
  };
  const inputs = {
    "go.mod": `module github.com/ArcForges/Cloud/center\n\nrequire ${contracts.path} ${contracts.version}\n`,
    "go.sum": `${contracts.path} ${contracts.version} ${contracts.sum}\n${contracts.path} ${contracts.version}/go.mod ${contracts.goModSum}\n`,
  };
  const runtimeModules = [contracts];
  const record = () => {
    for (const [name, value] of Object.entries(inputs)) f.sources[`center/${name}`] = value;
    f.sources[source] = JSON.stringify({
      schemaVersion: 1,
      inputs: Object.fromEntries(
        Object.entries(inputs).map(([name, value]) => [
          name,
          createHash("sha256").update(value).digest("hex"),
        ]),
      ),
      runtimeModules,
    });
  };
  record();
  return { ...f, source, contracts, inputs, runtimeModules, record };
}

test("Go ContractSet identifies the exact published module without claiming a descriptor hash", () => {
  const f = goFixture();
  const identity = resolveAxes(f.catalog, f.read);
  const expectedValue = {
    subject: `pkg:go/${f.contracts.path}`,
    version: "1.0.0-ci.481.1",
    source: { path: f.source, sha256: createHash("sha256").update(f.read(f.source)).digest("hex") },
  };
  assert.deepEqual(identity.ContractSet, {
    status: "present",
    values: [{ ...expectedValue, goModule: f.contracts }],
  });
  assert.deepEqual((identity.PackageVersion as { values: unknown[] }).values[0], expectedValue);
});

test("the production candidate uses the Go and Worker lock inputs", () => {
  const version =
    process.env.GITHUB_ACTIONS === "true"
      ? `0.1.0-ci.${process.env.GITHUB_RUN_NUMBER}.${process.env.GITHUB_RUN_ATTEMPT}`
      : "0.1.0-local.1";
  const identity = expectedIdentity(version);
  const contract = identity.axes.ContractSet as {
    values: { source: { path: string }; descriptorSha256?: string }[];
  };
  const packages = identity.axes.PackageVersion as { values: { subject: string }[] };
  assert.equal(contract.values.length, 1);
  assert.equal(contract.values[0]?.source.path, "center/dependencies.json");
  assert.equal(contract.values[0]?.descriptorSha256, undefined);
  assert(packages.values.some((value) => value.subject.startsWith("pkg:go/")));
  assert(packages.values.some((value) => value.subject.startsWith("pkg:npm/")));
  assert(!packages.values.some((value) => value.subject.startsWith("pkg:nuget/")));
});

test("Go source identity refuses input drift, missing or changed checksum, pin, or producer", () => {
  const f = goFixture();
  f.sources["center/go.mod"] = `${f.read("center/go.mod")}\n`;
  assert.throws(() => resolveAxes(f.catalog, f.read), /module file differs/);
  f.record();
  f.sources["center/go.sum"] = `${f.read("center/go.sum")}\n`;
  assert.throws(() => resolveAxes(f.catalog, f.read), /sum file differs/);

  const cases = [
    {
      change: (x: ReturnType<typeof goFixture>) => {
        x.inputs["go.sum"] = x.inputs["go.sum"].split("\n")[0] ?? "";
      },
      problem: /metadata hash is missing/,
    },
    {
      change: (x: ReturnType<typeof goFixture>) => {
        x.contracts.sum = `h1:${"z".repeat(43)}=`;
      },
      problem: /archive hash is missing/,
    },
    {
      change: (x: ReturnType<typeof goFixture>) => {
        x.inputs["go.mod"] = x.inputs["go.mod"].replace("481.1", "480.1");
      },
      problem: /pin differs/,
    },
    {
      change: (x: ReturnType<typeof goFixture>) => {
        x.contracts.repository = "https://github.com/other/Contracts";
      },
      problem: /github\.com\/ArcForges\/Contracts/,
    },
    {
      change: (x: ReturnType<typeof goFixture>) => {
        x.contracts.commit = "invalid";
      },
      problem: /invalid/,
    },
    {
      change: (x: ReturnType<typeof goFixture>) => {
        x.runtimeModules.push(x.contracts);
      },
      problem: /Duplicate Go runtime module/,
    },
  ];
  for (const { change, problem } of cases) {
    const fixture = goFixture();
    change(fixture);
    fixture.record();
    assert.throws(() => resolveAxes(fixture.catalog, fixture.read), problem);
  }
});
