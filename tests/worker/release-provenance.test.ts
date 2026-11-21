// SPDX-License-Identifier: AGPL-3.0-only
import assert from "node:assert/strict";
import {
  cpSync,
  lstatSync,
  mkdirSync,
  readdirSync,
  readFileSync,
  realpathSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import os from "node:os";
import path from "node:path";
import { before, test } from "node:test";
import { auditProvenance, hash, object, parseDocument } from "../../tooling/provenance.ts";
import {
  legalBundle,
  releaseProfile,
  stageImageNotices,
  verifyBridgeAsset,
  verifyImageFiles,
  verifyReleaseFiles,
  verifySecurityBridgeProfile,
  verifyWorker,
} from "../../tooling/release-provenance.ts";
import { root } from "../../tooling/process.ts";
import { expectedIdentity } from "../../tooling/build-identity.ts";
import { goCandidateFiles } from "../../tooling/proof-candidate.ts";
import { stageCandidateDirectory, verifyCandidate } from "../../tooling/project.ts";
import { scratchDirectory } from "./support/scratch.ts";

let worker: Buffer;
let metadata: Record<string, unknown>;
let revision: string;
before(() => {
  // npm's pretest builds these actual inputs once, outside the test runner's process context.
  worker = readFileSync(path.join(root, "artifacts/provenance-test-worker/index.js"));
  metadata = object(
    parseDocument(readFileSync(path.join(root, "artifacts/provenance-test-worker/meta.json"))),
  );
  const source = auditProvenance(root);
  revision = source.sourceCommit + (source.dirty ? "-dirty" : "");
  stageImageNotices(root, revision);
});

test("real locked Wrangler output matches the approved exact Worker closure", () => {
  const result = verifyWorker(root, worker, metadata);
  // The approved closure is the active release profile's: verifyWorker has already compared the bundle, its inputs and its emitted
  // inputs with it, so the expectation here is derived from the real build and not copied from an earlier one.
  const outputs = object(metadata.outputs);
  const script = Object.keys(outputs).find((name) => name.endsWith("/index.js"));
  assert(script);
  assert.equal(result.sha256, hash(worker));
  assert.equal(result.bytes, worker.length);
  assert.deepEqual(Object.keys(result.inputs).sort(), Object.keys(object(metadata.inputs)).sort());
  assert.deepEqual(
    [...result.outputInputs].sort(),
    Object.keys(object(object(outputs[script]).inputs)).sort(),
  );
  assert(result.outputInputs.length > 0 && Object.keys(result.inputs).length > 0);
});
test("the active profile binds both bridge assets and refuses substituted bytes", () => {
  const { profile } = releaseProfile(root);
  for (const platform of ["linux", "windows"] as const) {
    assert.equal(
      profile.bridgeAssets.assets[platform].name,
      `arcforges-ctr06-bridge-8e5-${platform}-amd64.zip`,
    );
    assert.throws(() => verifyBridgeAsset(root, platform, Buffer.from("not the bridge asset")));
    const fixture = process.env[`ARCFORGES_TEST_CTR06_${platform.toUpperCase()}_BUNDLE`];
    if (fixture) {
      const real = readFileSync(fixture);
      assert.equal(
        verifyBridgeAsset(root, platform, real).sha256,
        profile.bridgeAssets.assets[platform].sha256,
      );
      const changed = Buffer.from(real);
      const offset = Math.floor(changed.length / 2);
      changed.writeUInt8(changed.readUInt8(offset) ^ 1, offset);
      assert.throws(() => verifyBridgeAsset(root, platform, changed));
    }
  }
});

test("security bridge producer admission has an exact input set and independent source/compiler pins", () => {
  const { profile } = releaseProfile(root);
  verifySecurityBridgeProfile(root, profile.securityBridge);
  for (const mutate of [
    (security: Record<string, unknown>) => {
      security.sourceCommit = "a".repeat(40);
    },
    (security: Record<string, unknown>) => {
      security.sourceTree = "a".repeat(40);
    },
    (security: Record<string, unknown>) => {
      security.sourceArchiveSha256 = "a".repeat(64);
    },
    (security: Record<string, unknown>) => {
      security.compiler = "go1.27.3";
    },
    (security: Record<string, unknown>) => {
      security.windowsArchiveSha256 = "a".repeat(64);
    },
    (security: Record<string, unknown>) => {
      delete object(security.producerInputs)["tooling/ctr06-security-bridge-producer.ts"];
    },
    (security: Record<string, unknown>) => {
      delete object(security.producerInputs)["tooling/ctr06-bootstrap-broker.ts"];
    },
    (security: Record<string, unknown>) => {
      object(security.producerInputs)["tooling/ctr06-bootstrap-gate.ts"] = "a".repeat(64);
    },
    (security: Record<string, unknown>) => {
      object(security.producerInputs)["tooling/unreviewed.ts"] = "a".repeat(64);
    },
    (security: Record<string, unknown>) => {
      object(security.producerInputs)["tooling/ctr06-security-bridge-producer.ts"] = "a".repeat(64);
    },
  ]) {
    const security = structuredClone(profile.securityBridge) as unknown as Record<string, unknown>;
    mutate(security);
    assert.throws(() => verifySecurityBridgeProfile(root, security));
  }
});

test("reject changed Worker bytes independently of any supplied outer hash", () => {
  const changed = Buffer.concat([worker, Buffer.from("\nexport const injected = true;\n")]);
  assert.notEqual(hash(changed), hash(worker));
  assert.throws(
    () => verifyWorker(root, changed, metadata),
    /Changed or unclassified Worker bytes/u,
  );
});
test("reject new parsed source, emitted source, resource and runtime imports", () => {
  for (const change of ["input", "emitted", "resource", "import"]) {
    const meta = structuredClone(metadata);
    const outputs = object(meta.outputs);
    const script = Object.keys(outputs).find((name) => name.endsWith("/index.js"));
    assert(script);
    const output = object(outputs[script]);
    if (change === "input") object(meta.inputs)["node_modules/unreviewed/index.js"] = {};
    if (change === "emitted") object(output.inputs)["unreviewed.js"] = { bytesInOutput: 1 };
    if (change === "resource") outputs["artifacts/provenance-test-worker/extra.wasm"] = {};
    if (change === "import")
      output.imports = [{ path: "unreviewed:runtime", kind: "import-statement", external: true }];
    assert.throws(() => verifyWorker(root, worker, meta));
  }
});

/** The files below a directory as sorted relative paths with forward slashes. */
function filesUnder(directory: string, prefix = ""): string[] {
  return readdirSync(path.join(directory, prefix), { withFileTypes: true })
    .flatMap((entry) => {
      const relative = prefix === "" ? entry.name : `${prefix}/${entry.name}`;
      return entry.isDirectory() ? filesUnder(directory, relative) : [relative];
    })
    .sort();
}

test("repeat image staging isolates old cached legal files and retains their bytes", (t) => {
  const artifacts = scratchDirectory("cloud-image-notices-repeat-", t);
  const staged = path.join(artifacts, "image-notices");
  cpSync(path.join(root, "artifacts/image-notices"), staged, { recursive: true });
  const expected = filesUnder(staged);
  const obsolete = [
    "Contracts.NOTICE.txt",
    "DotNet.AspNetCore.NOTICES.txt",
    "DotNet.LICENSE.txt",
    "DotNet.Runtime.NOTICES.txt",
    "Grpc.LICENSE.txt",
    "Npgsql.LICENSE.txt",
    "Protobuf.LICENSE.txt",
  ].map((file) => `third-party/${file}`);
  // Match the failed cache's names without depending on retired live licence files.
  for (const file of obsolete)
    writeFileSync(path.join(staged, file), `Cached fixture for ${file}\n`);

  stageImageNotices(root, revision, artifacts);
  assert.deepEqual(filesUnder(staged), expected);
  const previous = readdirSync(artifacts).find((name) =>
    name.startsWith("image-notices-previous-"),
  );
  assert(previous);
  for (const file of obsolete)
    assert.equal(
      readFileSync(path.join(artifacts, previous, "image-notices", file), "utf8"),
      `Cached fixture for ${file}\n`,
    );

  const provenance = path.join(staged, "provenance.json");
  const generation = lstatSync(staged, { bigint: true }).ino;
  const prior = object(parseDocument(readFileSync(provenance)));
  prior.revision = "a".repeat(40);
  Object.assign(object(prior.source), { commit: prior.revision, dirty: false });
  writeFileSync(provenance, `${JSON.stringify(prior, null, 2)}\n`);
  stageImageNotices(root, revision, artifacts);
  assert.equal(object(parseDocument(readFileSync(provenance))).revision, revision);
  assert.equal(lstatSync(staged, { bigint: true }).ino, generation);
  assert.deepEqual(readdirSync(artifacts).sort(), ["image-notices", previous].sort());
});

function imageFixture() {
  const directory = scratchDirectory("cloud-image-provenance-");
  cpSync(path.join(root, "artifacts/image-notices"), path.join(directory, "notices"), {
    recursive: true,
  });
  cpSync(path.join(root, "LICENSE"), path.join(directory, "LICENSE"));
  // An explicitly synthetic ELF prefix tests legal packaging only; Docker tests execute the real binary.
  writeFileSync(path.join(directory, "arcforges-center"), Buffer.from([127, 69, 76, 70, 2]));
  const cleanup = () => {
    assert.equal(path.dirname(directory), os.tmpdir());
    assert(path.basename(directory).startsWith("cloud-image-provenance-"));
    rmSync(directory, { recursive: true });
  };
  return { directory, cleanup };
}

test("candidate staging preserves the cached generation until the exact Go bundle verifies", async (t) => {
  const artifacts = realpathSync(scratchDirectory("cloud-candidate-repeat-", t));
  const destination = path.join(artifacts, "candidate");
  const retired = "arcforges-tool.tar";
  const oldArchive = Buffer.from("original cached managed tool fixture\n");
  const oldManifest = Buffer.from('{"runtime":"native-aot"}\n');
  mkdirSync(destination);
  writeFileSync(path.join(destination, retired), oldArchive);
  writeFileSync(path.join(destination, "manifest.json"), oldManifest);

  const fixture = imageFixture();
  t.after(fixture.cleanup);
  const version = "0.1.0-local.1";
  const image = "arcforges-cloud:local.1";
  const imageId = `sha256:${"a".repeat(64)}`;
  const identity = expectedIdentity(version);
  const imageReceipt = {
    schemaVersion: 1,
    imageId,
    ...verifyImageFiles(root, revision, fixture.directory),
  };
  function prepare(directory: string) {
    const write = (file: string, value: unknown) =>
      writeFileSync(path.join(directory, file), JSON.stringify(value));
    write("build-identity.json", identity);
    write("image-provenance.json", imageReceipt);
    write("legal-notices.json", legalBundle(root, revision));
    write("worker-meta.json", metadata);
    writeFileSync(path.join(directory, "worker.js"), worker);
    // Docker and the proof Worker are represented by explicit fixture bytes; the verifier binds their hashes.
    writeFileSync(path.join(directory, "docker-image.tar"), "synthetic image archive");
    writeFileSync(path.join(directory, "proof-worker.js"), "export {};");
    write("proof-worker-meta.json", {});
    write("wrangler.json", {
      name: "arcforges-cloud",
      main: "./worker.js",
      no_bundle: true,
      vars: {
        SOURCE_REVISION: revision,
        BUILD_IDENTITY: JSON.stringify(identity.build),
        ARCFORGES_HELLO_RUNTIME: "go",
      },
      containers: [{ image, max_instances: 1 }],
      env: { proof: {} },
    });
    write("manifest.json", {
      schema: 2,
      runtime: "go",
      revision,
      dirty: revision.endsWith("-dirty"),
      version,
      image,
      imageId,
      files: Object.fromEntries(
        goCandidateFiles.map((file) => [file, hash(readFileSync(path.join(directory, file)))]),
      ),
    });
  }

  await assert.rejects(
    stageCandidateDirectory(artifacts, async (directory) => {
      prepare(directory);
      writeFileSync(path.join(directory, retired), oldArchive);
      return verifyCandidate(directory);
    }),
    { code: "ERR_ASSERTION" },
  );
  assert.deepEqual(readdirSync(artifacts), ["candidate"]);
  assert.deepEqual(readFileSync(path.join(destination, retired)), oldArchive);
  assert.deepEqual(readFileSync(path.join(destination, "manifest.json")), oldManifest);

  const verified = await stageCandidateDirectory(artifacts, async (directory) => {
    prepare(directory);
    return verifyCandidate(directory);
  });
  assert.deepEqual(await verifyCandidate(destination), verified);
  assert.deepEqual(readdirSync(destination).sort(), [...goCandidateFiles, "manifest.json"].sort());
  const archived = readdirSync(artifacts).filter((name) => name !== "candidate");
  assert.equal(archived.length, 1);
  const [previous] = archived;
  assert(previous);
  assert.match(previous, /^candidate-previous-/u);
  assert.deepEqual(readFileSync(path.join(artifacts, previous, "candidate", retired)), oldArchive);
  assert.deepEqual(
    readFileSync(path.join(artifacts, previous, "candidate", "manifest.json")),
    oldManifest,
  );
});

test("complete image legal fixture validates and binds source and concrete member hashes", () => {
  const f = imageFixture();
  try {
    const result = verifyImageFiles(root, revision, f.directory);
    assert.equal(result.revision, revision);
    // The members are the files of the staged image, and the base legal texts the receipt's own: both come from the active release
    // profile through the staging, not from a count written here.
    const staged = filesUnder(f.directory);
    assert.deepEqual(Object.keys(result.members).sort(), staged);
    const receipt = object(
      parseDocument(readFileSync(path.join(f.directory, "notices/provenance.json"))),
    );
    assert.deepEqual(result.baseLegal, receipt.baseLegal);
    assert(staged.length > 3 && Object.keys(result.baseLegal).length > 0);
  } finally {
    f.cleanup();
  }
});
for (const [change, refusal] of [
  ["missing licence", /Unclassified or missing image member/u],
  ["changed notice", /Changed image legal text: NOTICE/u],
  ["extra resource", /Unclassified or missing image member/u],
  ["retired C# executable", /Unclassified or missing image member/u],
  ["wrong source", /Changed image source receipt/u],
  ["same-length changed source", /Changed image source receipt/u],
] as const)
  test(`reject image with ${change}`, () => {
    const f = imageFixture();
    try {
      if (change === "missing licence")
        rmSync(path.join(f.directory, "notices/third-party/Go.LICENSE.txt"));
      if (change === "changed notice")
        writeFileSync(path.join(f.directory, "notices/NOTICE"), "MIT\n");
      if (change === "extra resource")
        writeFileSync(path.join(f.directory, "unreviewed.js"), "extra");
      if (change === "retired C# executable")
        writeFileSync(path.join(f.directory, "ArcForges.Cloud"), Buffer.from([127, 69, 76, 70, 1]));
      if (change === "wrong source")
        writeFileSync(path.join(f.directory, "notices/provenance.json"), "{}\n");
      if (change === "same-length changed source") {
        const file = path.join(f.directory, "notices/provenance.json");
        const bytes = readFileSync(file);
        const offset = bytes.length - 2;
        bytes.writeUInt8(bytes.readUInt8(offset) ^ 1, offset);
        writeFileSync(file, bytes);
      }
      assert.throws(() => verifyImageFiles(root, revision, f.directory), refusal);
    } finally {
      f.cleanup();
    }
  });
test("distribution cannot omit legal text or substitute a source receipt", () => {
  const f = imageFixture();
  try {
    const candidate = path.join(f.directory, "candidate");
    const imageId = `sha256:${"a".repeat(64)}`;
    const image = {
      schemaVersion: 1,
      imageId,
      ...verifyImageFiles(root, revision, f.directory),
    };
    mkdirSync(candidate);
    const write = (file: string, value: unknown) =>
      writeFileSync(path.join(candidate, file), JSON.stringify(value));
    writeFileSync(path.join(candidate, "worker.js"), worker);
    write("worker-meta.json", metadata);
    write("image-provenance.json", image);
    const legal = legalBundle(root, revision);
    write("legal-notices.json", legal);
    verifyReleaseFiles(root, candidate, revision, imageId);
    assert(Object.hasOwn(legal.files, "third-party/Containers.LICENSE.txt"));
    delete legal.files["third-party/Containers.LICENSE.txt"];
    write("legal-notices.json", legal);
    assert.throws(
      () => verifyReleaseFiles(root, candidate, revision, imageId),
      /Changed distributed legal/u,
    );
    write("legal-notices.json", legalBundle(root, revision));
    write("image-provenance.json", { ...image, revision: "b".repeat(40) });
    assert.throws(() => verifyReleaseFiles(root, candidate, revision, imageId));
  } finally {
    f.cleanup();
  }
});

test("reject a missing or non-native executable in the Go image", () => {
  const fixture = imageFixture();
  try {
    writeFileSync(path.join(fixture.directory, "arcforges-center"), "not an ELF executable");
    assert.throws(() => verifyImageFiles(root, revision, fixture.directory), /Missing native ELF/u);
    rmSync(path.join(fixture.directory, "arcforges-center"));
    assert.throws(
      () => verifyImageFiles(root, revision, fixture.directory),
      /Unclassified or missing image member/u,
    );
  } finally {
    fixture.cleanup();
  }
});
