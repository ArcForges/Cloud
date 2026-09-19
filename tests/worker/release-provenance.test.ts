// SPDX-License-Identifier: AGPL-3.0-only
import assert from "node:assert/strict";
import { cpSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import os from "node:os";
import path from "node:path";
import { before, test } from "node:test";
import { auditProvenance, hash, object, parseDocument } from "../../tooling/provenance.ts";
import {
  legalBundle,
  stageImageNotices,
  verifyImageFiles,
  verifyReleaseFiles,
  verifyWorker,
} from "../../tooling/release-provenance.ts";
import { root, run, wrangler } from "../../tooling/process.ts";

let worker: Buffer;
let metadata: Record<string, unknown>;
let revision: string;
before(async () => {
  await run(
    process.execPath,
    [
      wrangler,
      "deploy",
      "--dry-run",
      "--containers-rollout",
      "none",
      "--outdir",
      "artifacts/provenance-test-worker",
      "--metafile",
      "artifacts/provenance-test-worker/meta.json",
    ],
    true,
  );
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
  assert.equal(result.sha256, "37d36ff37803fd4dfc5fef623ddc4a1b5e607d50782c3bf7c949b1dbb4e8fa9c");
  assert.equal(result.bytes, 61911);
  assert.equal(Object.keys(result.inputs).length, 6);
  assert.equal(result.outputInputs.length, 5);
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

function imageFixture() {
  const directory = mkdtempSync(path.join(os.tmpdir(), "cloud-image-provenance-"));
  cpSync(path.join(root, "artifacts/image-notices"), path.join(directory, "notices"), {
    recursive: true,
  });
  cpSync(path.join(root, "LICENSE"), path.join(directory, "LICENSE"));
  // An explicitly synthetic ELF prefix tests legal packaging only; Docker tests execute the real binary.
  writeFileSync(path.join(directory, "ArcForges.Cloud"), Buffer.from([127, 69, 76, 70, 1]));
  const cleanup = () => {
    assert.equal(path.dirname(directory), os.tmpdir());
    assert(path.basename(directory).startsWith("cloud-image-provenance-"));
    rmSync(directory, { recursive: true });
  };
  return { directory, cleanup };
}
test("complete image legal fixture validates and binds source and concrete member hashes", () => {
  const f = imageFixture();
  try {
    const result = verifyImageFiles(root, revision, f.directory);
    assert.equal(result.revision, revision);
    assert.equal(Object.keys(result.baseLegal).length, 6);
    assert.equal(Object.keys(result.members).length, 11);
  } finally {
    f.cleanup();
  }
});
for (const change of ["missing licence", "changed notice", "extra resource", "wrong source"])
  test(`reject image with ${change}`, () => {
    const f = imageFixture();
    try {
      if (change === "missing licence")
        rmSync(path.join(f.directory, "notices/third-party/Protobuf.LICENSE.txt"));
      if (change === "changed notice")
        writeFileSync(
          path.join(f.directory, "notices/third-party/DotNet.Runtime.NOTICES.txt"),
          "MIT\n",
        );
      if (change === "extra resource")
        writeFileSync(path.join(f.directory, "unreviewed.js"), "extra");
      if (change === "wrong source")
        writeFileSync(path.join(f.directory, "notices/provenance.json"), "{}\n");
      assert.throws(() => verifyImageFiles(root, revision, f.directory));
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
