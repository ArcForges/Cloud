// SPDX-License-Identifier: AGPL-3.0-only
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { createPublicKey, verify } from "node:crypto";
import { constants, closeSync, fstatSync, lstatSync, openSync, readSync } from "node:fs";
import {
  chmod,
  lstat,
  mkdir,
  mkdtemp,
  readdir,
  rename,
  rm,
  rmdir,
  writeFile,
} from "node:fs/promises";
import { devNull, tmpdir } from "node:os";
import path from "node:path";
import { parseArgs } from "node:util";
import { pathToFileURL } from "node:url";
import { profileBundleAssetName, verifyProfileBundle } from "../eng/verification/proof-deploy.ts";
import { gitEnvironment } from "./process.ts";
import { digest, git, hash, object, parseDocument, text } from "./provenance.ts";
import { requireDashboardBundle } from "./self-host-static-origin.ts";

const repositories = ["ArcForges/Cloud", "ArcForges/Web"] as const;
type Repository = (typeof repositories)[number];
type Producer = { repo: Repository; commit: string; tree: string };
type Archive = { name: string; length: number; sha256: string };
type Qualification = "candidate" | "main";
type Envelope = {
  schema: 1;
  kind: "self-host";
  rid: "linux-x64";
  archive: Archive;
  producers: Producer[];
  qualification: Qualification;
};
type Entries = Map<string, Buffer>;
type MainAuthority = { cloud: string; web: string; admission: string };
type VerifyOptions = {
  archive: string;
  publicKey: string;
  allowCandidate?: boolean;
  main?: MainAuthority;
};

const maxMetadata = 64 * 1024;
const maxArchive = 96 * 1024 * 1024;
const maxProfile = 24 * 1024 * 1024;
const archiveName = "arcforges-self-host-linux-x64.tar";
const centerBinary = "bin/arcforges-center";
const cohortName = "cohort.json";
const postgres = { major: 18, schema: 17 };
const configFiles = [
  "Caddyfile",
  "arcforges-center.service",
  "caddy.env.example",
  "caddy.service.d/arcforges-env.conf",
  "center.env.example",
  "migration.env.example",
  "operator-inputs.py",
  "pg_hba.conf.example",
  "postgresql.conf.example",
];
const cloudFiles = {
  "notices/cloud/LICENSE": "LICENSE",
  "notices/cloud/NOTICE": "NOTICE",
  "notices/cloud/dependencies.json": "center/dependencies.json",
};
const webFiles = {
  "notices/web/LICENSE": "LICENSE",
  "notices/web/THIRD_PARTY_NOTICES.md": "THIRD_PARTY_NOTICES.md",
  "notices/web/NOTICE.txt": "eng/provenance/NOTICE.txt",
  "notices/web/toolchain.json": "global.json",
  "notices/web/App.packages.lock.json": "src/ArcForges.Web.App/packages.lock.json",
  "notices/web/Operations.packages.lock.json": "src/ArcForges.Web.Operations/packages.lock.json",
  "notices/web/Ui.packages.lock.json": "src/ArcForges.Web.Ui/packages.lock.json",
};
const candidateFiles = ["build-identity.json", "image-provenance.json", "legal-notices.json"];
const cloudManifest = "notices/cloud/candidate-manifest.json";
const blockSize = 512;

function json(value: unknown): Buffer {
  return Buffer.from(`${JSON.stringify(value, null, 2)}\n`);
}

function readBounded(file: string, limit: number): Buffer {
  const expected = lstatSync(file);
  assert(expected.isFile() && expected.size <= limit, "File is not regular or exceeds its limit");
  const flags = process.platform === "win32" ? 0 : constants.O_NOFOLLOW | constants.O_NONBLOCK;
  const handle = openSync(file, constants.O_RDONLY | flags);
  try {
    const actual = fstatSync(handle);
    assert(
      actual.isFile() &&
        actual.dev === expected.dev &&
        actual.ino === expected.ino &&
        actual.size === expected.size,
      "File changed while opening",
    );
    const contents = Buffer.alloc(actual.size + 1);
    let offset = 0;
    while (offset < contents.length) {
      const count = readSync(handle, contents, offset, contents.length - offset, null);
      if (count === 0) break;
      offset += count;
    }
    assert.equal(offset, actual.size, "File changed while reading");
    return contents.subarray(0, offset);
  } finally {
    closeSync(handle);
  }
}

function producer(value: unknown): Producer {
  const row = object(value, "repo commit tree");
  const repo = row.repo;
  assert(repo === "ArcForges/Cloud" || repo === "ArcForges/Web", "Unexpected producer");
  return { repo, commit: digest(row.commit, 40), tree: digest(row.tree, 40) };
}

function parseEnvelope(bytes: Buffer): Envelope {
  const raw = object(parseDocument(bytes), "schema kind rid archive producers qualification");
  assert.equal(raw.schema, 1, "Unsupported cohort envelope");
  assert.equal(raw.kind, "self-host", "Expected a self-host cohort");
  assert.equal(raw.rid, "linux-x64", "Unsupported cohort architecture");
  const qualification = raw.qualification;
  assert(qualification === "candidate" || qualification === "main", "Unknown qualification");
  assert(Array.isArray(raw.producers), "Missing producers");
  const producers = raw.producers.map(producer);
  assert.deepEqual(
    producers.map((row) => row.repo),
    [...repositories],
    "Wrong producer set",
  );
  const archive = object(raw.archive, "name length sha256");
  assert.equal(archive.name, archiveName, "Unexpected cohort archive name");
  assert(
    typeof archive.length === "number" &&
      Number.isSafeInteger(archive.length) &&
      archive.length >= 2 * blockSize &&
      archive.length <= maxArchive,
    "Invalid cohort archive length",
  );
  return {
    schema: 1,
    kind: "self-host",
    rid: "linux-x64",
    qualification,
    producers,
    archive: { name: archiveName, length: archive.length, sha256: digest(archive.sha256) },
  };
}

function verifyRemote(directory: string, repo: Repository) {
  const url = git(directory, "remote", "get-url", "origin");
  assert(
    [
      `https://github.com/${repo}`,
      `https://github.com/${repo}.git`,
      `git@github.com:${repo}.git`,
      `ssh://git@github.com/${repo}.git`,
    ].includes(url),
    "Git origin does not match the producer",
  );
}

function checkout(directory: string, repo: Repository): Producer {
  verifyRemote(directory, repo);
  assert.equal(git(directory, "status", "--porcelain"), "", "Producer checkout is dirty");
  return producer({
    repo,
    commit: git(directory, "--no-replace-objects", "rev-parse", "HEAD"),
    tree: git(directory, "--no-replace-objects", "rev-parse", "HEAD^{tree}"),
  });
}

function verifyMain(producers: Producer[], authority: MainAuthority) {
  const registry = object(
    parseDocument(readBounded(authority.admission, maxMetadata)),
    "schema admitted denied archiveSha256",
  );
  assert.equal(registry.schema, 1, "Unsupported admission record");
  assert(
    Array.isArray(registry.admitted) && Array.isArray(registry.denied),
    "Invalid admission record",
  );
  assert.deepEqual(registry.admitted.map(producer), producers, "Cohort is not currently admitted");
  const denied = registry.denied.map(producer);
  for (const row of producers) {
    assert(
      !denied.some((old) => old.repo === row.repo && old.commit === row.commit),
      "Producer is withdrawn",
    );
    const directory = row.repo === "ArcForges/Cloud" ? authority.cloud : authority.web;
    verifyRemote(directory, row.repo);
    assert.equal(
      git(directory, "--no-replace-objects", "rev-parse", `${row.commit}^{tree}`),
      row.tree,
      "Wrong producer tree",
    );
    execFileSync(
      "git",
      [
        "--no-replace-objects",
        "merge-base",
        "--is-ancestor",
        row.commit,
        "refs/remotes/origin/main",
      ],
      {
        cwd: directory,
        env: gitEnvironment(),
        timeout: 30000,
        stdio: "ignore",
        windowsHide: true,
      },
    );
  }
  return digest(registry.archiveSha256);
}

function sourceBlob(directory: string, source: Producer, name: string, limit: number): Buffer {
  return execFileSync(
    "git",
    ["--no-replace-objects", "cat-file", "blob", `${source.commit}:${name}`],
    {
      cwd: directory,
      env: gitEnvironment(),
      maxBuffer: limit,
      timeout: 30000,
      windowsHide: true,
    },
  );
}

async function verifyCloudCandidate(
  directory: string,
  source: Producer,
  candidateDirectory: string,
) {
  // Checkout trusted Git objects into an owned directory. The producer's mutable working files
  // and index flags cannot affect the stock verifier or any of its imports.
  const temporary = await mkdtemp(path.join(tmpdir(), "arcforges-cohort-verifier-"));
  const verifier = path.join(temporary, "cloud");
  const hooks = path.join(temporary, "hooks");
  const env = { ...gitEnvironment(), GIT_CONFIG_NOSYSTEM: "1", GIT_CONFIG_GLOBAL: devNull };
  const gitPrivate = (cwd: string, ...args: string[]) =>
    execFileSync("git", ["--no-replace-objects", ...args], {
      cwd,
      env,
      timeout: 120000,
      stdio: "ignore",
      windowsHide: true,
    });
  try {
    await mkdir(hooks);
    gitPrivate(
      temporary,
      "clone",
      "--quiet",
      "--shared",
      "--no-checkout",
      `--template=${hooks}`,
      "--",
      path.resolve(directory),
      verifier,
    );
    gitPrivate(verifier, "config", "core.hooksPath", hooks);
    gitPrivate(verifier, "config", "core.autocrlf", "false");
    gitPrivate(verifier, "config", "core.fsmonitor", "false");
    gitPrivate(verifier, "remote", "set-url", "origin", "https://github.com/ArcForges/Cloud.git");
    const main = digest(
      git(directory, "--no-replace-objects", "rev-parse", "refs/remotes/origin/main"),
      40,
    );
    gitPrivate(verifier, "update-ref", "refs/remotes/origin/main", main);
    // The stock provenance audit selects origin/main when the producer is on a named branch.
    gitPrivate(verifier, "checkout", "--quiet", "-B", "verify-self-host-cohort", source.commit);
    assert.deepEqual(
      checkout(verifier, source.repo),
      source,
      "Verifier checkout differs from the producer",
    );
    const stock = (await import(
      pathToFileURL(path.join(verifier, "tooling/project.ts")).href
    )) as typeof import("./project.ts");
    const npmCli = path.resolve(
      path.dirname(process.execPath),
      process.platform === "win32"
        ? "node_modules/npm/bin/npm-cli.js"
        : "../lib/node_modules/npm/bin/npm-cli.js",
    );
    const npm = (...args: string[]) =>
      execFileSync(process.execPath, [npmCli, ...args], {
        cwd: verifier,
        encoding: "utf8",
        timeout: 120000,
        windowsHide: true,
      }).trim();
    await stock.verifyToolchain(process.version, npm("--version"));
    npm("ci", "--offline", "--ignore-scripts", "--no-audit", "--no-fund");
    const result = await stock.verifyCandidate(path.resolve(candidateDirectory));
    assert.deepEqual(checkout(verifier, source.repo), source, "Verifier source changed");
    return result;
  } finally {
    await rm(temporary, { recursive: true, force: true });
  }
}

function createHeader(name: string, size: number): Buffer {
  const head = Buffer.alloc(blockSize);
  const octal = (number: number, width: number) =>
    `${number.toString(8).padStart(width - 1, "0")}\0`;
  head.write(name, 0, 100, "ascii");
  head.write(octal(0o644, 8), 100, "ascii");
  head.write(octal(0, 8), 108, "ascii");
  head.write(octal(0, 8), 116, "ascii");
  head.write(octal(size, 12), 124, "ascii");
  head.write(octal(0, 12), 136, "ascii");
  head.fill(32, 148, 156);
  head.write("0", 156, "ascii");
  head.write("ustar\0", 257, "ascii");
  head.write("00", 263, "ascii");
  const checksum = head.reduce((sum, byte) => sum + byte, 0);
  head.write(`${checksum.toString(8).padStart(6, "0")}\0 `, 148, "ascii");
  return head;
}

function makeTar(entries: Entries): Buffer {
  const pieces: Buffer[] = [];
  for (const [name, bytes] of [...entries].sort(([left], [right]) => (left < right ? -1 : 1))) {
    assert(name.length < 100 && bytes.length > 0, "Invalid cohort member");
    pieces.push(
      createHeader(name, bytes.length),
      bytes,
      Buffer.alloc((blockSize - (bytes.length % blockSize)) % blockSize),
    );
  }
  pieces.push(Buffer.alloc(2 * blockSize));
  const size = pieces.reduce((sum, bytes) => sum + bytes.length, 0);
  assert(size <= maxArchive, "Cohort archive exceeds its limit");
  return Buffer.concat(pieces, size);
}

function readTar(bytes: Buffer): Entries {
  assert(bytes.length >= 2 * blockSize && bytes.length % blockSize === 0, "Invalid cohort TAR");
  const entries = new Map<string, Buffer>();
  let offset = 0;
  let previous = "";
  while (offset + 2 * blockSize < bytes.length) {
    const head = bytes.subarray(offset, offset + blockSize);
    const end = head.indexOf(0);
    assert(end > 0 && end < 100, "Invalid cohort member name");
    const name = head.subarray(0, end).toString("ascii");
    assert(
      /^[A-Za-z0-9_][A-Za-z0-9._-]*(?:\/[A-Za-z0-9_][A-Za-z0-9._-]*)*$/u.test(name),
      "Invalid cohort member path",
    );
    assert(
      name > previous && entries.size < 64,
      "Duplicate, unordered or excessive cohort members",
    );
    const size = Number.parseInt(head.subarray(124, 135).toString("ascii"), 8);
    assert(
      Number.isSafeInteger(size) && size > 0 && head.equals(createHeader(name, size)),
      "Invalid cohort member header",
    );
    const start = offset + blockSize;
    offset = start + Math.ceil(size / blockSize) * blockSize;
    assert(
      offset <= bytes.length - 2 * blockSize &&
        bytes.subarray(start + size, offset).every((byte) => byte === 0),
      "Invalid cohort member bounds or padding",
    );
    entries.set(name, bytes.subarray(start, start + size));
    previous = name;
  }
  assert(
    bytes.length - offset === 2 * blockSize && bytes.subarray(offset).every((byte) => byte === 0),
    "Invalid cohort archive terminator",
  );
  return entries;
}

function member(entries: Entries, name: string): Buffer {
  const bytes = entries.get(name);
  assert(bytes, `Missing cohort member: ${name}`);
  return bytes;
}

function nativeExecutable(bytes: Buffer) {
  assert(
    bytes.length >= 64 &&
      bytes.subarray(0, 7).equals(Buffer.from([127, 69, 76, 70, 2, 1, 1])) &&
      [2, 3].includes(bytes.readUInt16LE(16)) &&
      bytes.readUInt16LE(18) === 62,
    "Expected a Linux x86-64 ELF executable",
  );
}

function webReceipt(value: unknown) {
  const row = object(value, "source runId artifactId artifactZipSha256 profileSha256");
  const source = producer(row.source);
  assert.equal(source.repo, "ArcForges/Web");
  const runId = text(row.runId);
  const artifactId = text(row.artifactId);
  assert.match(runId, /^[1-9][0-9]{0,15}$/u, "Invalid Web workflow run ID");
  assert.match(artifactId, /^[1-9][0-9]{0,15}$/u, "Invalid Web artifact ID");
  return {
    source,
    runId,
    artifactId,
    artifactZipSha256: digest(row.artifactZipSha256),
    profileSha256: digest(row.profileSha256),
  };
}

function validatePayload(entries: Entries, envelope: Envelope) {
  const metadata = object(parseDocument(member(entries, cohortName)), "schema cloud web postgres");
  assert.equal(metadata.schema, 1, "Unsupported self-host payload");
  const web = webReceipt(metadata.web);
  assert.deepEqual(web.source, envelope.producers[1], "Web profile belongs to another producer");
  const profileName = `web/${profileBundleAssetName(web.profileSha256)}`;
  const expected = [
    cohortName,
    centerBinary,
    profileName,
    cloudManifest,
    ...configFiles.map((name) => `setup/${name}`),
    ...Object.keys(cloudFiles),
    ...Object.keys(webFiles),
    ...candidateFiles.map((name) => `notices/cloud/${name}`),
  ].sort();
  assert.deepEqual([...entries.keys()], expected, "Missing or unclassified cohort members");
  const cloud = object(metadata.cloud, "version imageId candidateManifestSha256");
  assert.match(text(cloud.version), /^0\.1\.0-(?:ci\.[0-9]+\.[0-9]+|local\.[0-9]+)$/u);
  assert.match(text(cloud.imageId), /^sha256:[a-f0-9]{64}$/u);
  const cloudManifestBytes = member(entries, cloudManifest);
  assert.equal(
    hash(cloudManifestBytes),
    digest(cloud.candidateManifestSha256),
    "Cloud manifest digest mismatch",
  );
  const candidate = object(
    parseDocument(cloudManifestBytes),
    "schema runtime revision dirty version image imageId files",
  );
  assert.equal(candidate.schema, 2);
  assert.equal(candidate.runtime, "go");
  assert.equal(candidate.dirty, false);
  assert.equal(
    candidate.revision,
    envelope.producers[0]?.commit,
    "Cloud candidate belongs to another producer",
  );
  assert.equal(candidate.version, cloud.version);
  assert.equal(candidate.imageId, cloud.imageId);
  const files = object(candidate.files);
  for (const name of candidateFiles) {
    assert.equal(
      hash(member(entries, `notices/cloud/${name}`)),
      digest(files[name]),
      `Cloud candidate member changed: ${name}`,
    );
  }
  const imageReceipt = object(
    parseDocument(member(entries, "notices/cloud/image-provenance.json")),
  );
  assert.equal(imageReceipt.imageId, cloud.imageId, "Image identity mismatch");
  assert.equal(imageReceipt.revision, envelope.producers[0]?.commit, "Image source mismatch");
  const executable = member(entries, centerBinary);
  nativeExecutable(executable);
  assert.equal(
    hash(executable),
    digest(object(imageReceipt.members)["arcforges-center"]),
    "Center differs from the verified image",
  );
  assert.deepEqual(object(metadata.postgres, "major schema"), postgres);
  requireDashboardBundle(verifyProfileBundle(member(entries, profileName), web.profileSha256));
  return { profileName, profileSha256: web.profileSha256 };
}

export function verifySelfHostCohort(options: VerifyOptions) {
  const signature = readBounded(`${options.archive}.manifest.sig`, 64);
  const manifest = readBounded(`${options.archive}.manifest.json`, maxMetadata);
  const publicKey = readBounded(options.publicKey, 1024).toString("ascii");
  assert.match(
    publicKey,
    /^-----BEGIN PUBLIC KEY-----\r?\n[A-Za-z0-9+/=\r\n]+-----END PUBLIC KEY-----\r?\n?$/u,
    "Expected an independent PEM SPKI public key",
  );
  const key = createPublicKey(publicKey);
  assert(
    key.asymmetricKeyType === "ed25519" &&
      signature.length === 64 &&
      verify(null, manifest, key, signature),
    "Invalid cohort signature",
  );
  const envelope = parseEnvelope(manifest);
  assert.equal(
    path.basename(options.archive),
    envelope.archive.name,
    "Cohort archive name mismatch",
  );
  if (envelope.qualification === "main") {
    assert(
      options.main,
      "Main qualification requires a trusted admission record and Git producer repositories",
    );
    assert.equal(
      envelope.archive.sha256,
      verifyMain(envelope.producers, options.main),
      "Cohort archive is not currently admitted",
    );
  } else {
    assert(options.allowCandidate, "Candidate is allowed only for explicit private qualification");
  }
  const bytes = readBounded(options.archive, envelope.archive.length);
  assert(
    bytes.length === envelope.archive.length && hash(bytes) === envelope.archive.sha256,
    "Cohort archive integrity mismatch",
  );
  const entries = readTar(bytes);
  return { envelope, entries, ...validatePayload(entries, envelope) };
}

export async function stageSelfHostCohort(options: VerifyOptions, parent: string) {
  assert(
    process.platform === "linux" && process.arch === "x64",
    "Self-host staging requires Linux x86-64",
  );
  const verified = verifySelfHostCohort(options);
  const directory = path.resolve(parent);
  assert(
    (await lstat(directory)).isDirectory(),
    "Staging parent must be a real operator-owned directory",
  );
  const target = path.join(directory, verified.envelope.archive.sha256);
  const temporary = await mkdtemp(path.join(directory, ".arcforges-cohort-"));
  try {
    for (const [name, bytes] of verified.entries) {
      const file = path.join(temporary, name);
      await mkdir(path.dirname(file), { recursive: true, mode: 0o755 });
      await writeFile(file, bytes, { flag: "wx", mode: name === centerBinary ? 0o755 : 0o644 });
    }
    // An existing release is never overwritten. A competing publisher uses the same lock.
    const lock = `${target}.lock`;
    await mkdir(lock, { mode: 0o700 });
    try {
      assert(
        !(await readdir(directory)).includes(path.basename(target)),
        "Verified release already exists",
      );
      await chmod(temporary, 0o755);
      await rename(temporary, target);
    } finally {
      await rmdir(lock);
    }
    return {
      release: target,
      profile: path.join(target, verified.profileName),
      profileSha256: verified.profileSha256,
    };
  } finally {
    await rm(temporary, { recursive: true, force: true });
  }
}

type AssembleOptions = {
  cloud: string;
  web: string;
  candidate: string;
  center: string;
  profile: string;
  webReceipt: string;
  output: string;
  qualification: Qualification;
  main?: MainAuthority;
};

export async function assembleSelfHostCohort(options: AssembleOptions) {
  const cloud = checkout(options.cloud, "ArcForges/Cloud");
  const web = checkout(options.web, "ArcForges/Web");
  const migrations = git(
    options.cloud,
    "ls-tree",
    "-r",
    "--name-only",
    cloud.commit,
    "center/internal/schema/migrations/",
  ).split("\n");
  assert.equal(
    migrations.length,
    postgres.schema,
    "Center schema differs from the cohort's supported schema",
  );
  const producers = [cloud, web];
  let admittedArchive: string | undefined;
  if (options.qualification === "main") {
    assert(options.main, "Main qualification requires independently admitted producers");
    admittedArchive = verifyMain(producers, options.main);
  }
  const candidate = await verifyCloudCandidate(options.cloud, cloud, options.candidate);
  assert.equal(candidate.revision, cloud.commit, "Cloud candidate belongs to another checkout");
  assert.equal(candidate.dirty, false, "Cloud candidate is dirty");
  const candidateManifest = readBounded(path.join(options.candidate, "manifest.json"), maxMetadata);
  assert.deepEqual(
    parseDocument(candidateManifest),
    candidate,
    "Cloud manifest changed during verification",
  );

  const profile = webReceipt(parseDocument(readBounded(options.webReceipt, maxMetadata)));
  assert.deepEqual(profile.source, web, "Web receipt belongs to another checkout");
  const profileName = profileBundleAssetName(profile.profileSha256);
  assert.equal(path.basename(options.profile), profileName, "Unexpected Web profile filename");
  const entries: Entries = new Map([
    [
      cohortName,
      json({
        schema: 1,
        cloud: {
          version: candidate.version,
          imageId: candidate.imageId,
          candidateManifestSha256: hash(candidateManifest),
        },
        web: profile,
        postgres,
      }),
    ],
    [centerBinary, readBounded(options.center, maxArchive)],
    [`web/${profileName}`, readBounded(options.profile, maxProfile)],
    [cloudManifest, candidateManifest],
  ]);
  for (const name of configFiles) {
    entries.set(
      `setup/${name}`,
      sourceBlob(options.cloud, cloud, `deploy/self-host/${name}`, maxMetadata),
    );
  }
  for (const [name, source] of Object.entries(cloudFiles)) {
    entries.set(name, sourceBlob(options.cloud, cloud, source, 4 * 1024 * 1024));
  }
  for (const [name, source] of Object.entries(webFiles)) {
    entries.set(name, sourceBlob(options.web, web, source, 4 * 1024 * 1024));
  }
  for (const name of candidateFiles) {
    const bytes = readBounded(path.join(options.candidate, name), 4 * 1024 * 1024);
    assert.equal(hash(bytes), candidate.files[name], `Cloud candidate member changed: ${name}`);
    entries.set(`notices/cloud/${name}`, bytes);
  }
  assert.deepEqual(checkout(options.cloud, cloud.repo), cloud, "Cloud checkout changed");
  assert.deepEqual(checkout(options.web, web.repo), web, "Web checkout changed");
  const archive = makeTar(entries);
  const archiveSha256 = hash(archive);
  if (admittedArchive !== undefined)
    assert.equal(
      archiveSha256,
      admittedArchive,
      "Assembled cohort archive is not currently admitted",
    );
  const envelope: Envelope = {
    schema: 1,
    kind: "self-host",
    rid: "linux-x64",
    qualification: options.qualification,
    producers,
    archive: { name: archiveName, length: archive.length, sha256: archiveSha256 },
  };
  validatePayload(readTar(archive), envelope);
  const target = path.join(path.resolve(options.output), archiveName);
  // Use a fresh output directory. The resulting envelope must be signed separately before install.
  await mkdir(path.dirname(target), { mode: 0o700 });
  try {
    await writeFile(target, archive, { flag: "wx", mode: 0o600 });
    await writeFile(`${target}.manifest.json`, json(envelope), { flag: "wx", mode: 0o600 });
  } catch (error) {
    await rm(path.dirname(target), { recursive: true });
    throw error;
  }
  return { archive: target, envelope };
}

if (import.meta.main) {
  const [command, ...args] = process.argv.slice(2);
  assert(
    command === "assemble" || command === "verify" || command === "stage",
    "Use assemble, verify or stage",
  );
  const { values } = parseArgs({
    args,
    options: {
      "cloud-repo": { type: "string" },
      "web-repo": { type: "string" },
      admission: { type: "string" },
      candidate: { type: "string" },
      center: { type: "string" },
      profile: { type: "string" },
      "web-receipt": { type: "string" },
      output: { type: "string" },
      qualification: { type: "string" },
      archive: { type: "string" },
      "public-key": { type: "string" },
      "allow-candidate": { type: "boolean" },
      staging: { type: "string" },
    },
  });
  const requireOption = (name: keyof typeof values) => {
    const value = values[name];
    assert(typeof value === "string" && value.length > 0, `Missing --${name}`);
    return value;
  };
  const main = values.admission
    ? {
        admission: requireOption("admission"),
        cloud: requireOption("cloud-repo"),
        web: requireOption("web-repo"),
      }
    : undefined;
  if (command === "assemble") {
    const qualification = requireOption("qualification");
    assert(qualification === "candidate" || qualification === "main", "Unknown qualification");
    const assembled = await assembleSelfHostCohort({
      cloud: requireOption("cloud-repo"),
      web: requireOption("web-repo"),
      candidate: requireOption("candidate"),
      center: requireOption("center"),
      profile: requireOption("profile"),
      webReceipt: requireOption("web-receipt"),
      output: requireOption("output"),
      qualification,
      main,
    });
    console.log(JSON.stringify(assembled, null, 2));
  } else {
    const options = {
      archive: requireOption("archive"),
      publicKey: requireOption("public-key"),
      allowCandidate: values["allow-candidate"],
      main,
    };
    const result =
      command === "verify"
        ? verifySelfHostCohort(options).envelope
        : await stageSelfHostCohort(options, requireOption("staging"));
    console.log(JSON.stringify(result, null, 2));
  }
}
