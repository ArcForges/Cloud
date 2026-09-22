// SPDX-License-Identifier: AGPL-3.0-only
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { execFileSync } from "node:child_process";
import { readFileSync, realpathSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

type Entry = {
  version?: string;
  resolved?: string;
  integrity?: string;
  license?: string;
  link?: boolean;
  inBundle?: boolean;
  name?: string;
};
type Review = {
  owner: string;
  reviewer: string;
  date: string;
  rationale: string;
  inputs: Record<string, string>;
  checks: string[];
  runtimeAssessment: string;
  maintenance: string;
};
export type Policy = {
  schemaVersion: number;
  repository: string;
  sourceCommit: string;
  reviewRecord: string;
  manifests: string[];
  inputs: Record<string, string>;
  review: Review;
  closure: Record<string, Entry>;
  foundationCandidates: Record<string, string>;
  buildToolPrereleases: Record<string, string>;
  firstParty: Record<string, { publisher: string; visibility: string }>;
  registry: string;
  channel: string;
  artifactRecords: string[];
  native: { mode: string; evidence: string[] };
};
const gitEnvironment = () =>
  Object.fromEntries(
    Object.entries(process.env).filter(([name]) => !name.toUpperCase().startsWith("GIT_")),
  );
const sections = ["dependencies", "devDependencies", "peerDependencies", "optionalDependencies"];
const exact = /^\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?$/u;
const requiredChecks = [
  "locked-restore",
  "licence-provenance",
  "security",
  "class-compilation",
  "compatibility",
  "sbom",
  "framework-posture",
];
export function digest(text: string) {
  return createHash("sha256").update(text.replaceAll("\r\n", "\n")).digest("hex");
}
export function validatePolicy(policy: Policy) {
  assert.equal(policy.schemaVersion, 1);
  assert(["Cloud", "AI", "Web"].includes(policy.repository), "Unknown owner");
  assert.match(policy.sourceCommit, /^[a-f0-9]{40}$/u);
  assert.equal(policy.registry, "https://registry.npmjs.org/");
  assert(["foundation-candidate", "stable"].includes(policy.channel));
  assert(Object.keys(policy.inputs).length > 0, "Missing admitted input closure");
  assert.deepEqual(
    policy.review.inputs,
    policy.inputs,
    "Upgrade review does not bind admitted inputs",
  );
  for (const field of [
    "owner",
    "reviewer",
    "date",
    "rationale",
    "runtimeAssessment",
    "maintenance",
  ] as const)
    assert(policy.review[field]?.trim().length > 8, `Missing upgrade review ${field}`);
  for (const check of requiredChecks)
    assert(policy.review.checks.includes(check), `Missing upgrade gate: ${check}`);
  assert(policy.artifactRecords.length > 0, "Missing shipped closure authority");
  assert.equal(
    policy.native.mode,
    "existing-artifact-closure-only",
    "Native adoption requires AD-01 through AD-08",
  );
  assert(policy.native.evidence.length > 0, "Missing native closure evidence");
  for (const [name, entry] of Object.entries(policy.firstParty)) {
    assert(
      ["@arcforges/proto", "@arcforges/api-client"].includes(name),
      `Unadmitted internal/first-party package: ${name}`,
    );
    assert.equal(entry.publisher, "ArcForges/Contracts", `Wrong publisher: ${name}`);
    assert.equal(entry.visibility, "public", `Internal package: ${name}`);
  }
}
export function immutableCoordinates(closure: Record<string, Entry>) {
  const coordinates: Record<string, string> = {};
  for (const [key, entry] of Object.entries(closure)) {
    if (!entry.integrity) continue;
    const coordinate = `${entry.name ?? key.split("node_modules/").at(-1)}@${entry.version}`;
    const previous = coordinates[coordinate];
    assert(
      !previous || previous === entry.integrity,
      `Conflicting integrity across nested coordinates: ${coordinate}`,
    );
    coordinates[coordinate] = entry.integrity;
  }
  return coordinates;
}
export function validateHistoricalCoordinates(
  admitted: Record<string, string>,
  current: Record<string, string>,
) {
  for (const [coordinate, integrity] of Object.entries(admitted))
    if (current[coordinate])
      assert.equal(
        current[coordinate],
        integrity,
        `Immutable version changed despite successor review: ${coordinate}`,
      );
}
export function validateClosure(policy: Policy, packages: Record<string, Entry>) {
  const actual = Object.fromEntries(
    Object.entries(packages)
      .filter(([name, entry]) => name.includes("node_modules/") && !entry.link)
      .map(([name, entry]) => [
        name,
        Object.fromEntries(
          Object.entries(entry).filter(([key]) =>
            ["version", "resolved", "integrity", "license", "inBundle", "name"].includes(key),
          ),
        ) as Entry,
      ]),
  );
  for (const [key, entry] of Object.entries(actual)) {
    assert(
      entry.license &&
        !/(?:^|[ (])(?:GPL-[^ )]+|NOASSERTION|UNKNOWN|UNLICENSED)(?:$|[ )])/u.test(entry.license),
      `Forbidden licence: ${key}`,
    );
    assert(entry.version && exact.test(entry.version), `Floating version: ${key}`);
    const name = entry.name ?? key.split("node_modules/").at(-1);
    assert(name, `Missing dependency identity: ${key}`);
    if (name.startsWith("@arcforges/"))
      assert(policy.firstParty[name], `Unadmitted publisher/internal package: ${name}`);
    if (entry.version.includes("-")) {
      assert.equal(policy.channel, "foundation-candidate", `Prerelease in stable closure: ${name}`);
      const admitted = name.startsWith("@arcforges/")
        ? policy.foundationCandidates
        : policy.buildToolPrereleases;
      assert.equal(admitted[name], entry.version, `Unadmitted prerelease: ${name}`);
      if (!name.startsWith("@arcforges/"))
        assert(
          (packages[key] as Entry & { dev?: boolean }).dev,
          `Preview package entered runtime class: ${name}`,
        );
    }
    if (name.startsWith("@arcforges/")) {
      const expected = `${policy.registry}${name}/-/${name.split("/").at(-1)}-${entry.version}.tgz`;
      assert.equal(entry.resolved, expected, `Wrong publisher artifact coordinate: ${name}`);
    }
    let current = key;
    let artifact = entry;
    while (artifact.inBundle) {
      if (artifact.resolved || artifact.integrity) registry(artifact, current);
      const boundary = current.lastIndexOf("/node_modules/");
      assert(boundary > 0, `Orphan bundled dependency: ${key}`);
      current = current.slice(0, boundary);
      const parent = packages[current];
      assert(parent && !parent.link, `Unverified bundle ancestor: ${key}`);
      artifact = parent;
    }
    registry(artifact, current);
  }
  assert.deepEqual(
    actual,
    policy.closure,
    "Unadmitted dependency, licence or mutable-version integrity; review the changed closure",
  );
}
function registry(entry: Entry, name: string) {
  const url = new URL(entry.resolved ?? "invalid:");
  assert(
    url.origin === "https://registry.npmjs.org" &&
      !url.username &&
      !url.password &&
      !url.search &&
      !url.hash,
    `Untrusted feed: ${name}`,
  );
  assert.match(
    entry.integrity ?? "",
    /^sha512-[A-Za-z0-9+/]{86}==$/u,
    `Missing lock integrity: ${name}`,
  );
}
export function validateImports(root: string, file: string, source: string, policy: Policy) {
  const check = (value: string) => {
    if (value.startsWith("@arcforges/")) {
      const name = value.split("/").slice(0, 2).join("/");
      const workspace =
        ["@arcforges/web-ui", "@arcforges/web-site"].includes(name) && policy.repository === "Web";
      assert(
        workspace || policy.firstParty[name]?.visibility === "public",
        `Forbidden internal import: ${file}: ${value}`,
      );
      assert(workspace || value === name, `Internal or unadmitted package subpath: ${value}`);
    }
    if (value.startsWith(".")) {
      const target = path.resolve(root, path.dirname(file), value);
      assert(target.startsWith(root + path.sep), `Sibling source import: ${file}: ${value}`);
      assert(
        !/(?:^|[\\/])(?:ai-internal|storage-internal)(?:[\\/]|$)/iu.test(target),
        `Private generated source: ${file}`,
      );
    }
    assert(
      !/^(?:https?:|file:|git\+|[A-Za-z]:[\\/]|\/)/u.test(value),
      `External source import: ${file}: ${value}`,
    );
  };
  // Tokenize comments and strings before inspecting module declarations; fixture text is not executable syntax.
  const tokens: { value: string; literal: boolean }[] = [];
  const lexical =
    /\/\*[\s\S]*?\*\/|\/\/[^\r\n]*|"(?:\\[\s\S]|[^"\\])*"|'(?:\\[\s\S]|[^'\\])*'|`(?:\\[\s\S]|[^`\\])*`|[A-Za-z_$][\w$]*|[^\s]/gu;
  for (const match of source.matchAll(lexical)) {
    const raw = match[0];
    if (raw.startsWith("//") || raw.startsWith("/*")) continue;
    const literal = ['"', "'", "`"].includes(raw.charAt(0));
    const value = literal
      ? raw
          .slice(1, -1)
          .replace(
            /\\u\{([a-f\d]+)\}|\\u([a-f\d]{4})|\\x([a-f\d]{2})|\\([\s\S])/giu,
            (_all, wide: string, unicode: string, hex: string, escaped: string) =>
              wide || unicode || hex
                ? String.fromCodePoint(Number.parseInt(wide || unicode || hex, 16))
                : escaped,
          )
      : raw;
    tokens.push({ value, literal });
  }
  for (let index = 0; index < tokens.length; index++) {
    const token = tokens[index];
    assert(token, "Missing import token");
    if (token.literal) continue;
    const next = tokens[index + 1];
    if (["import", "require"].includes(token.value) && next?.value === "(") {
      const argument = tokens[index + 2];
      assert(
        argument?.literal && !argument.value.includes("${"),
        `Computed import needs explicit admission: ${file}`,
      );
      check(argument.value);
    } else if (["import", "from"].includes(token.value) && next?.literal) check(next.value);
  }
}
export function auditDependencies(root: string) {
  root = realpathSync(root);
  const read = (file: string) => {
    const full = realpathSync(path.resolve(root, file));
    assert(full.startsWith(root + path.sep), `Escaped dependency input: ${file}`);
    return readFileSync(full, "utf8");
  };
  const policy = JSON.parse(read("eng/policy/dependency-policy.json")) as Policy;
  validatePolicy(policy);
  const activeReview = JSON.parse(read(policy.reviewRecord)) as {
    review: Review;
    packages: Record<string, string>;
    supersedes: string | null;
  };
  assert.deepEqual(activeReview.review, policy.review, "Missing reviewed successor receipt");
  const git = (...args: string[]) =>
    execFileSync("git", args, {
      cwd: root,
      encoding: "utf8",
      windowsHide: true,
      env: gitEnvironment(),
    }).trim();
  const historical = [
    ...new Set(
      git(
        "log",
        "HEAD",
        "--diff-filter=A",
        "--name-only",
        "--format=",
        "--",
        "eng/policy/dependency-reviews/",
      )
        .split("\n")
        .filter(Boolean),
    ),
  ];
  const coordinates = immutableCoordinates(policy.closure);
  assert.deepEqual(
    activeReview.packages,
    coordinates,
    "Review does not bind immutable package coordinates",
  );
  for (const file of historical) {
    const introduced = git("log", "HEAD", "--diff-filter=A", "--format=%H", "--", file)
      .split("\n")
      .at(-1);
    assert(introduced, `Missing original review commit: ${file}`);
    const original = git("show", `${introduced}:${file}`);
    assert.equal(read(file).trim(), original, `Immutable review modified: ${file}`);
    const admitted = JSON.parse(original) as { packages: Record<string, string> };
    validateHistoricalCoordinates(admitted.packages, coordinates);
  }
  if (activeReview.supersedes)
    assert(historical.includes(activeReview.supersedes), "Missing predecessor review");
  else
    assert(
      historical.length === 0 || historical.includes(policy.reviewRecord),
      "Upgrade requires predecessor review",
    );
  const files = execFileSync(
    "git",
    ["ls-files", "-z", "--cached", "--others", "--exclude-standard"],
    { cwd: root, encoding: "utf8", windowsHide: true, env: gitEnvironment() },
  )
    .split("\0")
    .filter(Boolean);
  const manifests = files.filter((file) => path.basename(file) === "package.json");
  assert.deepEqual(manifests.sort(), [...policy.manifests].sort(), "Unadmitted workspace manifest");
  const inputNames = new Set([
    "package.json",
    "package-lock.json",
    ".node-version",
    ".java-version",
    ".npmrc",
    "NuGet.Config",
    "global.json",
    "Directory.Packages.props",
    "Dockerfile",
    "wrangler.json",
    "wrangler.jsonc",
    "gradle.lockfile",
    "verification-metadata.xml",
    "libs.versions.toml",
    "settings.gradle.kts",
    "build.gradle.kts",
    "gradle-wrapper.properties",
    "vcpkg.json",
    "vcpkg-configuration.json",
  ]);
  for (const file of files) {
    if (
      inputNames.has(path.basename(file)) ||
      /\.(?:csproj|esproj|props|targets)$/u.test(file) ||
      file.endsWith("packages.lock.json")
    )
      assert(
        Object.hasOwn(policy.inputs, file),
        `New dependency input requires admission: ${file}`,
      );
    if (/^(?:src|tests)\//u.test(file) && file.endsWith(".cs"))
      assert(
        !/\b(?:using|global::)\s*ArcForges\.Contracts\.(?:Internal|Storage|AIInternal)\b/u.test(
          read(file),
        ),
        `Unadmitted private generated C# import: ${file}`,
      );
  }
  const lock = JSON.parse(read("package-lock.json")) as {
    packages: Record<string, Entry & Record<string, unknown>>;
    lockfileVersion: number;
  };
  assert.equal(lock.lockfileVersion, 3);
  for (const file of policy.manifests) {
    const manifest = JSON.parse(read(file)) as Record<string, Record<string, string>>;
    const entry = lock.packages[file === "package.json" ? "" : path.posix.dirname(file)];
    assert(entry, `Missing workspace lock: ${file}`);
    for (const section of sections) {
      assert.deepEqual(
        manifest[section] ?? {},
        entry[section] ?? {},
        `Manifest/lock drift: ${file}`,
      );
      for (const [name, version] of Object.entries(manifest[section] ?? {}))
        assert(exact.test(version), `Floating selector: ${name}`);
    }
  }
  validateClosure(policy, lock.packages);
  for (const [file, expected] of Object.entries(policy.inputs))
    assert.equal(digest(read(file)), expected, `Dependency input changed without review: ${file}`);
  const inventory = JSON.parse(read("eng/provenance/files.json")) as { artifacts: string[] };
  assert.deepEqual(
    inventory.artifacts,
    policy.artifactRecords,
    "Shipped dependency class changed without admission",
  );
  for (const file of files.filter(
    (file) =>
      /^(?:src|worker|apps|packages)\//u.test(file) && /\.(?:ts|tsx|mjs|js|cts|mts)$/u.test(file),
  ))
    validateImports(root, file, read(file), policy);
  return {
    result: "passed",
    repository: policy.repository,
    dependencies: Object.keys(policy.closure).length,
    inputs: Object.keys(policy.inputs).length,
    evidence:
      "offline dependency admission; existing provenance and candidate gates retain redistribution authority",
  };
}
if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url))
  console.log(JSON.stringify(auditDependencies(process.cwd()), null, 2));
