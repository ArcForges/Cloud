// SPDX-License-Identifier: AGPL-3.0-only
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import test from "node:test";
import {
  auditDependencies,
  digest,
  historicalReviews,
  immutableCoordinates,
  introducingCommit,
  validateHistoricalCoordinates,
  validateClosure,
  validateIsolated,
  validateManifests,
  validateCsharpImports,
  validateImports,
  validatePolicy,
  type Policy,
} from "./dependency-policy.ts";

const root = process.cwd();
const baseline = JSON.parse(readFileSync("eng/policy/dependency-policy.json", "utf8")) as Policy;
const lock = JSON.parse(readFileSync("package-lock.json", "utf8"));
// A package of the root project's own lock (the isolated packages' entries are keyed under their directory and sort first).
const firstDependency = Object.keys(baseline.closure).find((key) =>
  key.startsWith("node_modules/"),
);
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
  policy.firstParty["@arcforges/ai-internal"] = {
    publisher: "other/Contracts",
    visibility: "internal",
  };
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
  // No public client package remains admitted (CLOUD.84 U2); a public source import needs its admitted public name.
  const publicClient = structuredClone(baseline);
  publicClient.firstParty["@arcforges/example-client"] = {
    publisher: "ArcForges/Contracts",
    visibility: "public",
  };
  validateImports(
    root,
    "src/example.ts",
    'import type { X } from "@arcforges/example-client";',
    publicClient,
  );
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
  // The retired public client names stay unadmitted: a policy cannot re-admit them by name.
  const retired = withInternalPackage();
  retired.firstParty["@arcforges/proto"] = {
    publisher: "ArcForges/Contracts",
    visibility: "public",
  };
  assert.throws(() => validatePolicy(retired), /Unadmitted internal/u);
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
test("private generated C# records are importable only by the Cloud host, its plan bridge and its tests", () => {
  const source = "using ArcForges.Contracts.CloudInternal.Storage.V1;\n";
  validateCsharpImports("src/ArcForges.Cloud/Foundation/Example.cs", source);
  validateCsharpImports("src/ArcForges.Cloud.Storage.D1/Example.cs", source);
  validateCsharpImports("tests/ArcForges.Cloud.Tests/Example.cs", source);
  for (const file of [
    "tests/ArcForges.Cloud.Consumer/Program.cs",
    "src/Other/Example.cs",
    "src/ArcForges.Cloud.Modules.Identity/Example.cs",
    "src/ArcForges.Cloud.Modules.Abstractions/Example.cs",
    "src/ArcForges.Cloud.Storage.D1Other/Example.cs",
  ])
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
test("a receipt introduced inside a merge commit is found and bound to that merge, not to a side draft", () => {
  const dir = mkdtempSync(path.join(tmpdir(), "dependency-merge-receipt-"));
  const env = Object.fromEntries(
    Object.entries(process.env).filter(([name]) => !name.toUpperCase().startsWith("GIT_")),
  );
  const git = (...args: string[]) =>
    execFileSync(
      "git",
      [
        "-c",
        "user.name=Fixture",
        "-c",
        "user.email=fixture@example.invalid",
        "-c",
        "commit.gpgsign=false",
        "-c",
        "core.autocrlf=false",
        ...args,
      ],
      { cwd: dir, encoding: "utf8", windowsHide: true, env },
    ).trim();
  const receipt = "eng/policy/dependency-reviews/merged-r1.json";
  try {
    git("init", "-q", "-b", "main");
    writeFileSync(path.join(dir, "README.md"), "base\n");
    git("add", ".");
    git("commit", "-q", "-m", "base");
    mkdirSync(path.join(dir, path.dirname(receipt)), { recursive: true });
    git("checkout", "-q", "-b", "side");
    writeFileSync(path.join(dir, "side.txt"), "side\n");
    git("add", ".");
    git("commit", "-q", "-m", "side");
    // A draft receipt on the side branch never reaches main, so it is not an admitted version.
    writeFileSync(path.join(dir, receipt), '{"review":{"status":"draft"}}\n');
    git("add", ".");
    git("commit", "-q", "-m", "side draft receipt");
    git("checkout", "-q", "main");
    writeFileSync(path.join(dir, "main.txt"), "main\n");
    git("add", ".");
    git("commit", "-q", "-m", "main");
    git("merge", "-q", "--no-ff", "--no-commit", "side");
    const admitted = '{"review":{"status":"approved"}}\n';
    writeFileSync(path.join(dir, receipt), admitted);
    git("add", ".");
    git("commit", "-q", "-m", "merge side with the approved receipt");
    const merge = git("rev-parse", "HEAD");
    assert.deepEqual(historicalReviews(dir), [receipt]);
    assert.equal(introducingCommit(dir, receipt), merge);
    assert.equal(git("show", `${merge}:${receipt}`), admitted.trim());
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

// An isolated package (AF-CTR-03 A2): its own manifest, lock and .npmrc, never installed by the root project, admitted by directory
// and bound to the closure under that directory's prefix.
const isolatedDirectory = "eng/verification/browser";
const isolatedFiles = () => ({
  manifest: JSON.parse(readFileSync(`${isolatedDirectory}/package.json`, "utf8")) as Record<
    string,
    unknown
  >,
  lock: JSON.parse(readFileSync(`${isolatedDirectory}/package-lock.json`, "utf8")) as {
    packages: Record<string, Record<string, unknown>>;
    lockfileVersion: number;
  },
  npmrc: readFileSync(`${isolatedDirectory}/.npmrc`, "utf8"),
});
const check = (
  files: ReturnType<typeof isolatedFiles>,
  manifest: unknown = files.manifest,
  lockFile: unknown = files.lock,
  npmrc: string = files.npmrc,
) => validateIsolated(isolatedDirectory, JSON.stringify(manifest), JSON.stringify(lockFile), npmrc);
test("an isolated package is admitted by directory and its locked packages join the closure under the directory's prefix", () => {
  assert.deepEqual(baseline.isolated, [isolatedDirectory]);
  const files = isolatedFiles();
  const packages = check(files);
  assert.deepEqual(Object.keys(packages), [`${isolatedDirectory}/node_modules/playwright-core`]);
  // The root lock does not have it: the root project never installs it.
  assert(!Object.keys(lock.packages).some((key) => key.includes("playwright")));
  // The admitted closure holds it, with the bytes and the licence of the lock.
  const entry = baseline.closure[`${isolatedDirectory}/node_modules/playwright-core`];
  assert.equal(entry?.version, "1.63.0");
  assert.equal(entry?.integrity, files.lock.packages["node_modules/playwright-core"]?.integrity);
  assert.equal(entry?.license, "Apache-2.0");
  validateClosure(baseline, { ...lock.packages, ...packages });
  // A package that is locked but not admitted, or admitted but no longer locked, is refused.
  const extra = structuredClone(files.lock);
  extra.packages["node_modules/other"] = {
    ...extra.packages["node_modules/playwright-core"],
    version: "1.0.0",
  };
  assert.throws(
    () => validateClosure(baseline, { ...lock.packages, ...check(files, files.manifest, extra) }),
    /Unadmitted dependency/u,
  );
  assert.throws(() => validateClosure(baseline, lock.packages), /Unadmitted dependency/u);
});
test("an isolated package must be private, its own root, exact, hook-free and installed without scripts", () => {
  const files = isolatedFiles();
  const mutate = (change: (manifest: Record<string, unknown>) => void) => {
    const manifest = structuredClone(files.manifest);
    change(manifest);
    return manifest;
  };
  assert.throws(
    () =>
      check(
        files,
        mutate((m) => (m.private = false)),
      ),
    /not private/u,
  );
  assert.throws(
    () =>
      check(
        files,
        mutate((m) => (m.workspaces = ["x"])),
      ),
    /workspaces/u,
  );
  assert.throws(
    () =>
      check(
        files,
        mutate((m) => (m.overrides = { a: "1.0.0" })),
      ),
    /overrides/u,
  );
  for (const hook of ["preinstall", "install", "postinstall", "prepare"])
    assert.throws(
      () =>
        check(
          files,
          mutate((m) => (m.scripts = { [hook]: "node x.js" })),
        ),
      /install hook/u,
      hook,
    );
  assert.throws(
    () =>
      check(
        files,
        mutate((m) => (m.dependencies = { "playwright-core": "^1.63.0" })),
      ),
    /drift|Floating/u,
  );
  assert.throws(
    () =>
      check(
        files,
        mutate((m) => (m.dependencies = { "playwright-core": "1.63.1" })),
      ),
    /drift/u,
  );
  assert.throws(
    () =>
      check(
        files,
        mutate((m) => (m.devDependencies = { typescript: "7.0.2" })),
      ),
    /drift/u,
  );
  for (const npmrc of [
    "save-exact=true\nengine-strict=true\n",
    "ignore-scripts=false\nsave-exact=true\nengine-strict=true\n",
    "ignore-scripts=true\n",
  ])
    assert.throws(() => check(files, files.manifest, files.lock, npmrc), /without scripts/u);
  const lockWith = (
    change: (packages: Record<string, Record<string, unknown>>) => void,
    version = 3,
  ) => {
    const copy = structuredClone(files.lock);
    copy.lockfileVersion = version;
    change(copy.packages);
    return copy;
  };
  assert.throws(
    () =>
      check(
        files,
        files.manifest,
        lockWith(() => {}, 2),
      ),
    /version/u,
  );
  // A range that the lock's root states too is not a drift but is still floating.
  assert.throws(
    () =>
      check(
        files,
        mutate((m) => {
          m.dependencies = { "playwright-core": "^1.63.0" };
        }),
        lockWith((p) => {
          const root = p[""];
          if (root) root.dependencies = { "playwright-core": "^1.63.0" };
        }),
      ),
    /Floating selector/u,
  );
  assert.throws(
    () =>
      check(
        files,
        files.manifest,
        lockWith((p) => {
          const entry = p["node_modules/playwright-core"];
          if (entry) entry.hasInstallScript = true;
        }),
      ),
    /install script/u,
  );
  assert.throws(
    () =>
      check(
        files,
        files.manifest,
        lockWith((p) => {
          const entry = p["node_modules/playwright-core"];
          if (entry) entry.link = true;
        }),
      ),
    /links a package/u,
  );
  assert.throws(
    () =>
      check(
        files,
        files.manifest,
        lockWith((p) => {
          p["../outside/x"] = { version: "1.0.0" };
        }),
      ),
    /outside node_modules/u,
  );
  assert.throws(
    () =>
      check(
        files,
        files.manifest,
        lockWith((p) => {
          delete p["node_modules/playwright-core"];
        }),
      ),
    /locks nothing/u,
  );
  assert.throws(
    () =>
      check(
        files,
        files.manifest,
        lockWith((p) => {
          delete p[""];
        }),
      ),
    /lock root/u,
  );
  assert.throws(
    () =>
      check(
        files,
        files.manifest,
        lockWith((p) => {
          const root = p[""];
          if (root) root.dependencies = { "playwright-core": "1.62.1" };
        }),
      ),
    /drift/u,
  );
});
test("an isolated directory is named plainly and once", () => {
  for (const bad of ["", "/abs", "../x", "a/../b", "a//b", "a/./b", "a b", "a\\b"]) {
    const policy = structuredClone(baseline);
    policy.isolated = [bad];
    assert.throws(() => validatePolicy(policy), /Malformed isolated/u, JSON.stringify(bad));
  }
  const repeated = structuredClone(baseline);
  repeated.isolated = [isolatedDirectory, isolatedDirectory];
  assert.throws(() => validatePolicy(repeated), /Repeated isolated/u);
});
test("a package.json that the policy does not admit is refused, wherever it is, and an admitted isolated one is not", () => {
  const policy = { manifests: ["package.json"], isolated: [isolatedDirectory] };
  const repository = [
    "package.json",
    `${isolatedDirectory}/package.json`,
    "README.md",
    "tooling/dependency-policy.ts",
  ];
  validateManifests(repository, policy);
  // A nested manifest the policy does not name, in the tree of an isolated package or beside it.
  for (const stray of [
    "eng/other/package.json",
    `${isolatedDirectory}/sub/package.json`,
    "tests/package.json",
    "node-tools/package.json",
  ])
    assert.throws(
      () => validateManifests([...repository, stray], policy),
      /Unadmitted workspace manifest/u,
      stray,
    );
  // An admitted manifest that is gone is as wrong as one that is new.
  assert.throws(
    () => validateManifests(["package.json"], policy),
    /Unadmitted workspace manifest/u,
  );
  // Without the isolated list the nested manifest is not admitted.
  assert.throws(
    () => validateManifests(repository, { manifests: ["package.json"] }),
    /Unadmitted workspace manifest/u,
  );
  validateManifests(["package.json"], { manifests: ["package.json"] });
});
test("the repository audit refuses a package.json the policy does not admit (the call is pinned, not only the function)", () => {
  const dir = mkdtempSync(path.join(tmpdir(), "dependency-stray-manifest-"));
  const env = Object.fromEntries(
    Object.entries(process.env).filter(([name]) => !name.toUpperCase().startsWith("GIT_")),
  );
  const git = (...args: string[]) =>
    execFileSync(
      "git",
      [
        "-c",
        "user.name=Fixture",
        "-c",
        "user.email=fixture@example.invalid",
        "-c",
        "commit.gpgsign=false",
        "-c",
        "core.autocrlf=false",
        ...args,
      ],
      { cwd: dir, encoding: "utf8", windowsHide: true, env },
    ).trim();
  const write = (file: string, text: string) => {
    mkdirSync(path.dirname(path.join(dir, file)), { recursive: true });
    writeFileSync(path.join(dir, file), text);
  };
  try {
    git("init", "-q", "-b", "main");
    // The policy and its reviews as they are, and every manifest the policy admits (their content is not read before the check).
    for (const file of execFileSync("git", ["ls-files", "eng/policy"], {
      cwd: root,
      encoding: "utf8",
    })
      .split("\n")
      .filter(Boolean))
      write(file, readFileSync(path.join(root, file), "utf8"));
    for (const manifest of [
      ...baseline.manifests,
      ...(baseline.isolated ?? []).map((directory) => `${directory}/package.json`),
    ])
      write(manifest, "{}\n");
    git("add", ".");
    git("commit", "-q", "-m", "policy and admitted manifests");
    // Without a stray manifest the audit gets past the manifest check (and stops on something else in this bare repository).
    assert.throws(
      () => auditDependencies(dir),
      (error: unknown) => !/Unadmitted workspace manifest/u.test(String(error)),
    );
    write("eng/other/package.json", "{}\n");
    assert.throws(() => auditDependencies(dir), /Unadmitted workspace manifest/u);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});
