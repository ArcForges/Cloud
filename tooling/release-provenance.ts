// SPDX-License-Identifier: AGPL-3.0-only
import assert from "node:assert/strict";
import { lstatSync, mkdirSync, readdirSync, writeFileSync } from "node:fs";
import path from "node:path";
import {
  auditProvenance,
  digest,
  hash,
  inventoryPath,
  object,
  parseDocument,
  readOwned,
  relative,
  store,
  text,
  validateRecord,
} from "./provenance.ts";
import { root, run, writeJson } from "./process.ts";

interface ReleaseProfile {
  schemaVersion: 1;
  id: string;
  ownerCommit: string;
  worker: {
    sha256: string;
    inputs: Record<string, string>;
    outputInputs: string[];
    externalImports: string[];
    exports: string[];
    packages: Record<string, { version: string; integrity: string }>;
    legalFiles: string[];
  };
  image: {
    baseImage: string;
    buildImage: string;
    inputs: Record<string, string>;
    baseLegal: Record<string, string>;
    legalFiles: string[];
  };
}
function list(value: unknown): string[] {
  assert(Array.isArray(value) && value.length > 0, "Expected nonempty list");
  const result = value.map(text);
  assert.equal(result.length, new Set(result).size, "Duplicate profile entry");
  return result;
}
function read(root: string, name: string) {
  return object(parseDocument(readOwned(root, name)));
}
function normalized(root: string, name: string) {
  return new TextDecoder("utf-8", { fatal: true })
    .decode(readOwned(root, name))
    .replaceAll("\r\n", "\n");
}
export function releaseProfile(owner: string) {
  const inventory = read(owner, inventoryPath);
  const artifacts = list(inventory.artifacts);
  assert.equal(artifacts.length, 2, "Unexpected Cloud artifact registrations");
  let profilePath = "";
  let profileHash = "";
  const kinds: string[] = [];
  for (const id of artifacts) {
    const record = validateRecord(read(owner, `${store}${id}.json`));
    assert(Array.isArray(record.artifactTargets) && record.artifactTargets.length === 1);
    const target = object(record.artifactTargets[0]);
    const kind = text(target.kind);
    kinds.push(kind);
    const worker = kind === "worker-bundle";
    assert.equal(
      target.project,
      worker ? "package.json" : "src/ArcForges.Cloud/ArcForges.Cloud.csproj",
    );
    assert.equal(target.package, worker ? "arcforges-cloud-worker" : "arcforges-cloud-container");
    const currentPath = relative(target.profile);
    const currentHash = digest(target.sha256);
    if (profilePath) assert.equal(currentPath, profilePath, "Inconsistent release profiles");
    if (profileHash) assert.equal(currentHash, profileHash, "Inconsistent release profile hashes");
    profilePath = currentPath;
    profileHash = currentHash;
  }
  assert.deepEqual(kinds.sort(), ["native-image-notices", "worker-bundle"]);
  assert.equal(hash(readOwned(owner, profilePath), "lf"), profileHash, "Changed release profile");
  const p = object(read(owner, profilePath), "schemaVersion id ownerCommit worker image");
  assert.equal(p.schemaVersion, 1);
  assert.match(text(p.id), /^cloud-release-r[1-9][0-9]*$/u);
  digest(p.ownerCommit, 40);
  const worker = object(
    p.worker,
    "sha256 inputs outputInputs externalImports exports packages legalFiles",
  );
  digest(worker.sha256);
  const image = object(p.image, "baseImage buildImage inputs baseLegal legalFiles");
  for (const inputs of [object(worker.inputs), object(image.inputs)]) {
    assert(Object.keys(inputs).length > 0, "Empty source closure");
    for (const [name, expected] of Object.entries(inputs))
      assert.equal(
        hash(readOwned(owner, relative(name)), "lf"),
        digest(expected),
        `Changed build input: ${name}`,
      );
  }
  for (const field of [worker.outputInputs, worker.legalFiles, image.legalFiles])
    list(field).forEach(relative);
  list(worker.externalImports);
  list(worker.exports);
  const lock = object(read(owner, "package-lock.json").packages);
  for (const [name, value] of Object.entries(object(worker.packages))) {
    const expected = object(value, "version integrity");
    const installed = read(owner, `node_modules/${relative(name)}/package.json`);
    const locked = object(lock[`node_modules/${name}`]);
    assert.equal(installed.version, text(expected.version), `Changed installed generator: ${name}`);
    assert.equal(locked.version, expected.version);
    assert.equal(locked.integrity, text(expected.integrity), `Changed package integrity: ${name}`);
  }
  const from = normalized(owner, "Dockerfile")
    .split("\n")
    .filter((line) => line.startsWith("FROM "));
  assert.deepEqual(
    from,
    [`FROM ${text(image.buildImage)} AS build`, `FROM ${text(image.baseImage)}`],
    "Changed image producer/base",
  );
  for (const [name, expected] of Object.entries(object(image.baseLegal))) {
    assert(
      name.startsWith("/usr/share/doc/") && name.endsWith("/copyright"),
      "Unexpected base legal path",
    );
    relative(name.slice(1));
    digest(expected);
  }
  const profile = p as unknown as ReleaseProfile;
  return { profile, profilePath, profileHash, artifacts: artifacts.sort() };
}

export function legalBundle(owner: string, revision: string) {
  const source = auditProvenance(owner);
  assert.equal(
    revision,
    source.sourceCommit + (source.dirty ? "-dirty" : ""),
    "Wrong legal source revision",
  );
  const { profile, profilePath, profileHash, artifacts } = releaseProfile(owner);
  const files: Record<string, string> = {};
  for (const name of [
    ...new Set([...profile.worker.legalFiles, ...profile.image.legalFiles]),
  ].sort())
    files[name] = normalized(owner, name);
  const records: Record<string, unknown> = {};
  for (const id of source.activeRecords) records[id] = read(owner, `${store}${id}.json`);
  return {
    schemaVersion: 1,
    repository: "https://github.com/ArcForges/Cloud",
    revision,
    source: { commit: source.sourceCommit, dirty: source.dirty, noticeSha256: source.noticeSha256 },
    profile: { path: profilePath, sha256: profileHash },
    artifacts,
    records,
    files,
  };
}

export function verifyWorker(owner: string, bundle: Buffer, metadata: unknown) {
  const { profile, artifacts } = releaseProfile(owner);
  const meta = object(metadata, "inputs outputs");
  assert.equal(hash(bundle), profile.worker.sha256, "Changed or unclassified Worker bytes");
  assert.deepEqual(
    Object.keys(object(meta.inputs)).sort(),
    Object.keys(profile.worker.inputs).sort(),
    "Changed Worker input closure",
  );
  const outputs = object(meta.outputs);
  const names = Object.keys(outputs).sort();
  assert.equal(names.length, 2, "Unclassified generated Worker resource");
  const scriptName = names.find((name) => name.endsWith("/index.js"));
  assert(scriptName);
  relative(scriptName);
  assert.deepEqual(names, [scriptName, `${scriptName}.map`].sort());
  const output = object(outputs[scriptName]);
  assert.equal(output.entryPoint, "worker/index.ts");
  assert.equal(output.bytes, bundle.length);
  assert.deepEqual(
    Object.keys(object(output.inputs)).sort(),
    [...profile.worker.outputInputs].sort(),
    "Changed emitted Worker closure",
  );
  assert.deepEqual(list(output.exports).sort(), [...profile.worker.exports].sort());
  assert(Array.isArray(output.imports));
  const imports = output.imports.map((item) => {
    const entry = object(item, "path kind external");
    assert.equal(entry.external, true);
    assert.equal(entry.kind, "import-statement");
    return text(entry.path);
  });
  assert.deepEqual(imports.sort(), [...profile.worker.externalImports].sort());
  return {
    sha256: hash(bundle),
    bytes: bundle.length,
    records: artifacts,
    inputs: profile.worker.inputs,
    outputInputs: profile.worker.outputInputs,
  };
}

function fileTree(directory: string): string[] {
  const result: string[] = [];
  const walk = (relativeDirectory: string) => {
    for (const entry of readdirSync(path.join(directory, relativeDirectory))) {
      const name = path.posix.join(relativeDirectory, entry);
      const info = lstatSync(path.join(directory, name));
      assert(!info.isSymbolicLink(), "Linked image notice");
      if (info.isDirectory()) walk(name);
      else {
        assert(info.isFile(), "Non-regular image notice");
        result.push(name);
      }
    }
  };
  walk("");
  return result.sort();
}
function json(value: unknown) {
  return Buffer.from(`${JSON.stringify(value, null, 2)}\n`);
}
function imageReceipt(owner: string, revision: string) {
  const bundle = legalBundle(owner, revision);
  const { profile } = releaseProfile(owner);
  return {
    schemaVersion: 1,
    revision,
    source: bundle.source,
    profile: bundle.profile,
    records: bundle.records,
    legal: Object.fromEntries(
      profile.image.legalFiles.map((file) => [file, hash(Buffer.from(text(bundle.files[file])))]),
    ),
    baseLegal: profile.image.baseLegal,
  };
}
export function stageImageNotices(owner: string, revision: string) {
  const folder = path.join(owner, "artifacts/image-notices");
  const { profile } = releaseProfile(owner);
  for (const file of profile.image.legalFiles) {
    const target = path.join(folder, file);
    mkdirSync(path.dirname(target), { recursive: true });
    writeFileSync(target, normalized(owner, file));
  }
  writeFileSync(path.join(folder, "provenance.json"), json(imageReceipt(owner, revision)));
  assert.deepEqual(
    fileTree(folder),
    [...profile.image.legalFiles, "provenance.json"].sort(),
    "Unexpected staged image material",
  );
}
export function verifyImageFiles(owner: string, revision: string, directory: string) {
  const { profile } = releaseProfile(owner);
  const expected = [
    "ArcForges.Cloud",
    "LICENSE",
    "notices/provenance.json",
    ...profile.image.legalFiles.map((name) => `notices/${name}`),
  ].sort();
  assert.deepEqual(fileTree(directory), expected, "Unclassified or missing image member");
  const receipt = imageReceipt(owner, revision);
  assert.deepEqual(
    readOwned(directory, "notices/provenance.json"),
    json(receipt),
    "Changed image source receipt",
  );
  assert.equal(
    hash(readOwned(directory, "LICENSE"), "lf"),
    hash(readOwned(owner, "LICENSE"), "lf"),
  );
  const members: Record<string, string> = {};
  for (const name of expected) members[name] = hash(readOwned(directory, name));
  for (const [name, expectedHash] of Object.entries(receipt.legal))
    assert.equal(members[`notices/${name}`], expectedHash, `Changed image legal text: ${name}`);
  assert(
    readOwned(directory, "ArcForges.Cloud")
      .subarray(0, 4)
      .equals(Buffer.from([127, 69, 76, 70])),
    "Missing native ELF executable",
  );
  return {
    revision,
    profile: receipt.profile,
    members,
    records: Object.keys(receipt.records).sort(),
    baseLegal: receipt.baseLegal,
  };
}

export async function verifyImageProvenance(
  containerId: string,
  revision: string,
  imageId: string,
) {
  assert.match(containerId, /^[a-f0-9]{64}$/u);
  const relativeDirectory = `artifacts/image-audit/${containerId}`;
  const directory = path.join(root, relativeDirectory);
  mkdirSync(directory, { recursive: true });
  await run("docker", ["cp", `${containerId}:/app/.`, `${relativeDirectory}/app`]);
  const receipt = verifyImageFiles(root, revision, path.join(directory, "app"));
  mkdirSync(path.join(directory, "base"), { recursive: true });
  for (const [name, expected] of Object.entries(receipt.baseLegal)) {
    const file = `${relativeDirectory}/base/${name.split("/").at(-2)}.txt`;
    // The exact reviewed openssl copyright symlink points to libssl3t64. Docker follows it.
    await run("docker", ["cp", "--follow-link", `${containerId}:${name}`, file]);
    assert.equal(hash(readOwned(root, file)), expected, `Changed base legal material: ${name}`);
  }
  const result = { schemaVersion: 1, imageId, ...receipt };
  await writeJson(path.join(root, "artifacts/evidence/image-provenance.json"), result);
  return result;
}

export async function verifyStoredImage(image: string, imageId: string, revision: string) {
  const id = await run("docker", ["create", image], true);
  try {
    return await verifyImageProvenance(id, revision, imageId);
  } finally {
    await run("docker", ["rm", id]);
  }
}

export function verifyReleaseFiles(
  owner: string,
  directory: string,
  revision: string,
  imageId: string,
) {
  const bundle = legalBundle(owner, revision);
  assert.deepEqual(
    read(directory, "legal-notices.json"),
    bundle,
    "Changed distributed legal/provenance bundle",
  );
  const image = object(
    read(directory, "image-provenance.json"),
    "schemaVersion imageId revision profile members records baseLegal",
  );
  assert.equal(image.schemaVersion, 1);
  assert.equal(image.imageId, imageId);
  assert.equal(image.revision, revision);
  const expected = imageReceipt(owner, revision);
  assert.deepEqual(image.profile, expected.profile);
  assert.deepEqual(image.records, Object.keys(expected.records).sort());
  assert.deepEqual(image.baseLegal, expected.baseLegal);
  const members = object(image.members);
  const known: Record<string, string> = {
    LICENSE: hash(readOwned(owner, "LICENSE"), "lf"),
    "notices/provenance.json": hash(json(expected)),
  };
  for (const [file, value] of Object.entries(expected.legal)) known[`notices/${file}`] = value;
  assert.deepEqual(Object.keys(members).sort(), [...Object.keys(known), "ArcForges.Cloud"].sort());
  digest(members["ArcForges.Cloud"]);
  for (const [file, value] of Object.entries(known))
    assert.equal(members[file], value, `Altered legal image receipt: ${file}`);
  return verifyWorker(
    owner,
    readOwned(directory, "worker.js"),
    read(directory, "worker-meta.json"),
  );
}
