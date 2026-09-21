// SPDX-License-Identifier: AGPL-3.0-only
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import path from "node:path";
import { gitEnvironment, root } from "./process.ts";

export const axes = [
  "AppVersion",
  "ContractSet",
  "CapabilityVersion",
  "NativeFormatVersion",
  "StorageSchemaVersion",
  "NativeAbiVersion",
  "PolicySchemaVersion",
  "ExtensionProtocolVersion",
  "PackageVersion",
];
const kinds = [
  "release",
  "contracts",
  "declarations",
  "declarations",
  "migrations",
  "native-abi",
  "declarations",
  "declarations",
  "packages",
];
function object(value: unknown): Record<string, unknown> {
  assert(value && typeof value === "object" && !Array.isArray(value));
  return value as Record<string, unknown>;
}
function string(value: unknown): string {
  assert.equal(typeof value, "string");
  return value as string;
}
function array(value: unknown): unknown[] {
  assert(Array.isArray(value));
  return value;
}
function digest(value: string) {
  return createHash("sha256").update(value).digest("hex");
}

export function resolveAxes(catalog: unknown, read: (source: string) => string) {
  const document = object(catalog);
  assert.equal(document.schemaVersion, 1);
  assert.equal(document.owner, "Cloud");
  const definitions = object(document.axes);
  assert.deepEqual(Object.keys(definitions).sort(), [...axes].sort());
  const result: Record<string, unknown> = {};
  for (const [index, name] of axes.entries()) {
    const definition = object(definitions[name]);
    const kind = string(definition.kind);
    assert.equal(kind, kinds[index]);
    if (definition.absence !== undefined) {
      assert(
        Object.keys(definition).every((key) =>
          ["kind", "absence", "reason", "producer"].includes(key),
        ),
      );
      assert(["not-produced", "not-applicable"].includes(string(definition.absence)));
      assert(string(definition.reason).trim());
      if (definition.absence === "not-produced") assert(string(definition.producer).trim());
      result[name] = {
        status: definition.absence,
        reason: definition.reason,
        ...(definition.producer === undefined ? {} : { producer: definition.producer }),
      };
      continue;
    }
    assert(Object.keys(definition).every((key) => ["kind", "sources"].includes(key)));
    const values = new Map<string, Record<string, unknown>>();
    for (const item of array(definition.sources)) {
      const sourcePath = string(item);
      assert(
        !/[\\:]/u.test(sourcePath) &&
          sourcePath.split("/").every((part) => part && part !== "." && part !== ".."),
      );
      const content = read(sourcePath).replaceAll("\r\n", "\n");
      const source = { path: sourcePath, sha256: digest(content) };
      const add = (subject: string, version: string, descriptorSha256?: string) => {
        assert(subject.trim() && /^[0-9]+(?:\.[0-9]+)*(?:[-+][A-Za-z0-9.-]+)?$/u.test(version));
        assert(!values.has(subject), "Duplicate version subject");
        values.set(subject, {
          subject,
          version,
          source,
          ...(descriptorSha256 ? { descriptorSha256 } : {}),
        });
      };
      if (kind === "native-abi") {
        const major = /#define\s+ARC_ABI_MAJOR\s+(\d+)/u.exec(content)?.[1];
        const minor = /#define\s+ARC_ABI_MINOR\s+(\d+)/u.exec(content)?.[1];
        assert(major && minor);
        add(sourcePath, `${major}.${minor}`);
        continue;
      }
      const input = object(JSON.parse(content));
      if (kind === "contracts") {
        const schema = /^([a-zA-Z0-9_.]+)\.v([1-9][0-9]*)$/u.exec(string(input.schema));
        assert(schema?.[1] && schema[2]);
        assert.match(string(input.descriptorSha256), /^[a-f0-9]{64}$/u);
        assert.equal(input.dirty, false);
        add(schema[1], schema[2], string(input.descriptorSha256));
      } else if (kind === "packages") {
        if (input.lockfileVersion !== undefined) {
          for (const [name, value] of Object.entries(object(input.packages)))
            if (name) add(`pkg:npm/${name}`, string(object(value).version));
        } else {
          for (const [framework, dependencies] of Object.entries(object(input.dependencies)))
            for (const [name, value] of Object.entries(object(dependencies))) {
              const dependency = object(value);
              if (dependency.type !== "Project")
                add(`pkg:nuget/${name}?target=${framework}`, string(dependency.resolved));
            }
        }
      } else {
        const declarations = array(input[kind === "migrations" ? "migrations" : "versions"]);
        for (const value of kind === "migrations" ? declarations.slice(-1) : declarations) {
          const declaration = object(value);
          add(string(declaration.subject), string(declaration.version));
        }
      }
    }
    assert(kind === "packages" || values.size > 0);
    result[name] = {
      status: "present",
      values: [...values.keys()].sort().map((key) => values.get(key)),
    };
  }
  return result;
}

export function sourceBuild(commit: string, epoch: number, dirty: boolean, env: NodeJS.ProcessEnv) {
  assert.match(commit, /^[a-f0-9]{40}$/u);
  assert(Number.isSafeInteger(epoch) && epoch > 0);
  const ci = env.GITHUB_ACTIONS === "true";
  const run = ci ? env.GITHUB_RUN_ID : null;
  const attempt = ci ? Number(env.GITHUB_RUN_ATTEMPT) : null;
  if (ci) {
    assert.equal(dirty, false);
    assert.equal(env.GITHUB_SHA, commit);
    assert.equal(env.GITHUB_REPOSITORY, "ArcForges/Cloud");
    assert.match(run ?? "", /^[1-9][0-9]*$/u);
    assert(Number.isSafeInteger(attempt) && attempt !== null && attempt > 0);
  }
  return {
    sourceCommit: commit,
    dirty,
    kind: ci ? "ci" : "local",
    buildId: ci ? `${run}.${attempt}` : `local.${commit}`,
    runId: run,
    runAttempt: attempt,
    pipelineRun: ci ? `https://github.com/ArcForges/Cloud/actions/runs/${run}` : null,
    sourceDateEpoch: epoch,
  };
}

export function candidateEnvironment(version: string, environment: NodeJS.ProcessEnv) {
  const producer = { ...environment };
  if (producer.GITHUB_ACTIONS === "true") {
    const release = /^0\.1\.0-ci\.([1-9][0-9]*)\.([1-9][0-9]*)$/u.exec(version);
    assert(release?.[1] && release[2]);
    assert.equal(release[1], producer.GITHUB_RUN_NUMBER);
    assert(
      Number(release[2]) <= Number(producer.GITHUB_RUN_ATTEMPT),
      "Candidate is from a future attempt",
    );
    producer.GITHUB_RUN_ATTEMPT = release[2];
  }
  return producer;
}

export function expectedIdentity(version: string) {
  const git = (...args: string[]) =>
    execFileSync("git", args, {
      cwd: root,
      encoding: "utf8",
      windowsHide: true,
      timeout: 30000,
      env: gitEnvironment(),
    }).trim();
  const commit = git("rev-parse", "HEAD");
  const producer = candidateEnvironment(version, process.env);
  const build = sourceBuild(
    commit,
    Number(git("show", "-s", "--format=%ct", commit)),
    git("status", "--porcelain").length > 0,
    producer,
  );
  const read = (name: string) => {
    if (name === "assembly/release.json")
      return JSON.stringify({ versions: [{ subject: "Cloud", version }] });
    if (name === "packages/contracts/source.json")
      return readFileSync(
        path.join(root, "node_modules/@arcforges/api-client/source.json"),
        "utf8",
      );
    return readFileSync(path.join(root, name), "utf8");
  };
  // The restored NuGet and npm producer receipts must match byte-for-byte in actual runtime verification.
  const contracts = object(JSON.parse(read("packages/contracts/source.json")));
  const pins = readFileSync(path.join(root, "Directory.Packages.props"), "utf8");
  const pinned = /Include="ArcForges.Contracts.PublicApi" Version="([^"]+)"/u.exec(pins)?.[1];
  assert.equal(contracts.version, pinned);
  return {
    schema: "arcforges.build-identity.v1",
    owner: "Cloud",
    artifact: { id: "Cloud", version },
    build,
    axes: resolveAxes(JSON.parse(read("eng/version-sources.json")), read),
  };
}

export type Identity = ReturnType<typeof expectedIdentity>;
export function verifyIdentity(actual: unknown, version: string) {
  assert.deepEqual(
    actual,
    expectedIdentity(version),
    "Built identity differs from independent source/run/version inputs",
  );
}
export function imageBuildVariables(identity: Identity) {
  const build = identity.build;
  return {
    SOURCE_REVISION: build.sourceCommit + (build.dirty ? "-dirty" : ""),
    SOURCE_COMMIT: build.sourceCommit,
    SOURCE_DIRTY: String(build.dirty),
    APP_VERSION: identity.artifact.version,
    BUILD_KIND: build.kind,
    BUILD_ID: build.buildId,
    PIPELINE_RUN: build.pipelineRun ?? "local",
    SOURCE_EPOCH: String(build.sourceDateEpoch),
  };
}
export function verifyHealthIdentity(health: unknown, identity: Identity) {
  const actual = object(health);
  assert.deepEqual(actual.build, identity.build, "Running compiled build identity differs");
  assert.deepEqual(actual.artifact, identity.artifact, "Running application release differs");
}
