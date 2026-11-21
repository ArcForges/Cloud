// SPDX-License-Identifier: AGPL-3.0-only
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { readFileSync } from "node:fs";
import path from "node:path";
import test from "node:test";

const root = path.resolve(import.meta.dirname, "../..");
const read = (file: string) => readFileSync(path.join(root, file), "utf8");

// This model covers the anchored paths, star globs and globstar paths in this repository.
// A rule can match a parent directory, and a later matching rule overrides it.
const rules = read(".dockerignore")
  .split(/\r?\n/u)
  .map((line) => line.trim())
  .filter((line) => line && !line.startsWith("#"))
  .map((line) => {
    const include = line.startsWith("!");
    const glob = (include ? line.slice(1) : line).replace(/\/$/u, "");
    assert.match(glob, /^[A-Za-z0-9._/*-]+$/u, "Extend the context test for new pattern syntax");
    const expression = glob
      .split(/(\*\*\/|\*\*|\*)/u)
      .map((part) => {
        if (part === "**/") return "(?:.*/)?";
        if (part === "**") return ".*";
        if (part === "*") return "[^/]*";
        return part.replaceAll(".", "\\.");
      })
      .join("");
    return { include, pattern: new RegExp(`^${expression}$`, "u") };
  });

function carried(target: string): boolean {
  const segments = target.split("/");
  const parents = segments.map((_, index) => segments.slice(0, index + 1).join("/"));
  let include = true;
  for (const rule of rules)
    if (parents.some((parent) => rule.pattern.test(parent))) include = rule.include;
  return include;
}

const tracked = execFileSync("git", ["ls-files", "-z", "center"], { cwd: root, encoding: "utf8" })
  .split("\0")
  .filter(Boolean);

test("tracked executable sources and embedded runtime assets are admitted to the Go image", () => {
  const testDirectories = /\/(?:arctest|virtual|mailtest|nodetest|mobiletest|testdata)\//u;
  const required = tracked.filter((name) => {
    if (name.startsWith("center/cmd/arcforges-center/")) return !name.endsWith("_test.go");
    if (!name.startsWith("center/internal/") || testDirectories.test(name)) return false;
    return (
      (name.endsWith(".go") && !name.endsWith("_test.go")) ||
      name.endsWith(".sql") ||
      name.endsWith(".gohtml") ||
      /\/(?:static\/account\.(?:js|css)|fixtures\/host-v2\.json|migrate\/[a-z0-9_]+_inventory\.txt)$/u.test(
        name,
      )
    );
  });
  assert(required.length > 100, "Runtime source inventory is missing");
  for (const name of [
    "center/go.mod",
    "center/go.sum",
    "center/toolchain.json",
    "center/dependencies.json",
    ...required,
  ])
    assert(carried(name), name);
});

test("the runtime context omits local overrides, test tools, and the retired C# Center", () => {
  for (const name of [
    "center/go.work",
    "center/go.work.sum",
    "center/vendor/github.com/example/module.go",
    "center/cmd/arcforges-center/operator_test.go",
    "center/cmd/arcforges-center/extra.s",
    "center/cmd/node-probe/main.go",
    "center/cmd/mobile-probe/main.go",
    "center/cmd/center-gen/main.go",
    "center/internal/mail/mailtest/smtpserver.go",
    "center/internal/identity/passkey/virtual/virtual.go",
    "center/internal/nodetest/nodetest.go",
    "center/internal/mobiletest/mobiletest.go",
    "center/internal/schema/migrations/notes.md",
    "center/internal/pages/templates/notes.md",
    "center/internal/pages/static/account.map",
    "center/internal/store/migrate/unreviewed.txt",
    "center/internal/feature/fixtures/unaudited.json",
    "center/internal/newpackage/unreviewed/subfolder/other.bin",
    "center/internal/entitlement/testdata/legacy-vectors.json",
    "center/tools/go.mod",
    "src/ArcForges.Cloud/ArcForges.Cloud.csproj",
    "src/ArcForges.Cloud.Storage.D1/Example.cs",
    "worker/index.ts",
    "storage/plans/foundation/readiness.sql",
    "tests/worker/docker-context.test.ts",
    "artifacts/candidate/docker-image.tar",
  ])
    assert.equal(carried(name), false, name);
  assert(carried("artifacts/image-notices/Go.LICENSE.txt"));
});

test("the image builds the locked Go runtime and starts only that executable", () => {
  const dockerfile = read("Dockerfile");
  assert.match(dockerfile, /^COPY center\/ \.\/$/mu);
  assert.match(dockerfile, /GOTOOLCHAIN=local GOFLAGS=-mod=readonly/u);
  assert.match(dockerfile, /go mod download && go mod verify/u);
  assert.match(dockerfile, /sha256sum --check --quiet \/tmp\/center-modules\.sha256/u);
  assert.match(dockerfile, /CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath/u);
  assert.match(dockerfile, /^COPY --from=build \/out\/arcforges-center \.\/$/mu);
  assert.match(dockerfile, /^USER \$APP_UID$/mu);
  assert.match(dockerfile, /^ENTRYPOINT \["\/app\/arcforges-center"\]$/mu);
  assert.doesNotMatch(
    dockerfile,
    /\/app\/ArcForges\.Cloud|dotnet (?:publish|restore)|^COPY src\//mu,
  );
});

test("the active image profile binds every tracked Center file carried by Docker", () => {
  const inventory = JSON.parse(read("eng/provenance/files.json")) as { artifacts: string[] };
  const record = JSON.parse(read(`eng/provenance/records/${inventory.artifacts[0]}.json`)) as {
    artifactTargets: { profile: string }[];
  };
  const profile = JSON.parse(read(record.artifactTargets[0]?.profile ?? "")) as {
    image: { inputs: Record<string, string> };
    id: string;
  };
  const carriedFiles = tracked.filter(carried);
  assert(carriedFiles.includes("center/cmd/arcforges-center/main.go"));
  assert.deepEqual(
    carriedFiles.filter((name) => profile.image.inputs[name] === undefined),
    [],
    `the Docker context carries files that ${profile.id} does not bind`,
  );
});
