// SPDX-License-Identifier: AGPL-3.0-only
// Re-read the two same-run native producer artifacts and make one closed carrier. No publication authority.
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import {
  chmodSync,
  closeSync,
  constants,
  copyFileSync,
  lstatSync,
  mkdirSync,
  openSync,
  readFileSync,
  readdirSync,
} from "node:fs";
import path from "node:path";
import { pathToFileURL } from "node:url";
import { actualBridgeProducer } from "./ctr06-security-bridge-source.ts";
import { securityBridgeLegal } from "./ctr06-security-bridge-legal.ts";
import {
  childEnvironment,
  driver,
  outputDirectory,
  run,
  sha256,
  verifyBridgeProofWorker,
  verifyToolAssemblies,
  verifyWorkerConfig,
  writeJson,
} from "./ctr06-security-bridge-producer.ts";
import { object, parseDocument, readOwned } from "./provenance.ts";
import { root } from "./process.ts";
import { releaseProfile } from "./release-provenance.ts";

interface Member {
  sha256: string;
  size: number;
}
interface LinuxRecord {
  schema: string;
  producer: unknown;
  source: unknown;
  identity: unknown;
  image: string;
  imageId: string;
  compiler: Record<string, unknown>;
  dockerfileSha256: string;
  toolInputs: unknown;
  assemblyEvidence: unknown;
  toolMembers: Record<string, { sha256: string; size: number; mode: number }>;
  workerEvidence: unknown;
  proofEvidence: unknown;
  nonrootLegal: unknown;
  members: Record<string, Member>;
}
interface WindowsRecord {
  schema: string;
  producer: unknown;
  source: unknown;
  identity: unknown;
  native: {
    compiler: Record<string, unknown>;
    binarySha256: string;
    sourceArchiveSha256: string;
    binary: { identity: unknown };
  };
  bundle: { sha256: string; size: number; members: number; binarySha256: string };
}
const json = (directory: string, name: string) => parseDocument(readOwned(directory, name));
function closedFiles(directory: string, members: Record<string, Member>, extra: string[]) {
  assert.deepEqual(
    readdirSync(directory).sort(),
    [...Object.keys(members), ...extra].sort(),
    "Artifact member set differs",
  );
  for (const [name, expected] of Object.entries(members)) {
    const data = readOwned(directory, name);
    assert.deepEqual(
      expected,
      { sha256: sha256(data), size: data.length },
      `Artifact changed: ${name}`,
    );
  }
}
function checkCompiler(value: Record<string, unknown>, platform: "linux" | "windows") {
  assert.equal(value.platform, `${platform}/amd64`);
  assert.equal(value.version, `go version go1.27.4 ${platform}/amd64`);
  assert.equal(value.compilerVersion, "compile version go1.27.4");
  assert.equal(
    value.archiveSha256,
    platform === "linux"
      ? "7226736c2339719cda28fbf3a54d71aa63bcefe376e98cef00034268dab24840"
      : "178ab98950ac69ab25069307dc6ade79f3816e414cce95b4da166a115cde1e7e",
  );
  assert.equal(value.regularFiles, 15659);
}

export async function sealSecurityBridge(
  source: string,
  linux: string,
  windows: string,
  goArchive: string,
  go: string,
  outputName: string,
) {
  assert.equal(process.platform, "linux");
  for (const name of [source, linux, windows, goArchive, go]) assert(path.isAbsolute(name));
  const input = actualBridgeProducer(root, source);
  // The checked-in active admission must bind this exact bootstrap producer closure.
  releaseProfile(root);
  assert.equal(process.version, "v24.21.0");
  assert.equal(path.basename(go), "go");
  const sealCompiler = driver("verify-compiler", {
    platform: "linux",
    goArchive,
    goRoot: path.dirname(path.dirname(go)),
  });
  checkCompiler(sealCompiler, "linux");
  const output = outputDirectory(outputName);
  const work = path.join(output, "work");
  const stage = path.join(output, "stage");
  const sealed = path.join(output, "sealed");
  mkdirSync(work, { mode: 0o700 });
  mkdirSync(stage, { mode: 0o700 });
  mkdirSync(sealed, { mode: 0o700 });
  const linuxManifestBytes = readOwned(linux, "manifest.json");
  const l = object(
    parseDocument(linuxManifestBytes),
    "schema producer source identity image imageId compiler dockerfileSha256 toolInputs assemblyEvidence toolMembers workerEvidence proofEvidence nonrootLegal members",
  ) as unknown as LinuxRecord;
  assert.equal(l.schema, "arcforges.ctr06-security-bridge-linux.v1");
  assert.deepEqual(l.producer, input.producer);
  assert.deepEqual(l.source, input.source);
  assert.deepEqual(l.identity, input.identity);
  assert.equal(
    l.image,
    `arcforges-ctr06-security-bridge:ci.${input.producer.runNumber}.${input.producer.runAttempt}`,
  );
  checkCompiler(l.compiler, "linux");
  const linuxZip = `arcforges-ctr06-security-bridge-${input.version}-linux-amd64.zip`;
  const linuxNames = [
    linuxZip,
    "arcforges-tool.tar",
    "build-identity.json",
    "docker-image.tar",
    "image-provenance.json",
    "legal-notices.json",
    "oci-inventory.json",
    "proof-worker-meta.json",
    "proof-worker.js",
    "worker-meta.json",
    "worker.js",
    "wrangler.json",
  ].sort();
  assert.deepEqual(Object.keys(l.members).sort(), linuxNames);
  closedFiles(linux, l.members, ["manifest.json"]);
  assert.deepEqual(json(linux, "build-identity.json"), input.identity);
  run("npm", ["ci", "--ignore-scripts"], source);
  const legal = await securityBridgeLegal(source, root);
  assert.deepEqual(json(linux, "legal-notices.json"), legal.bundle);
  const image = object(json(linux, "image-provenance.json")) as {
    imageId: string;
    revision: string;
    profile: unknown;
    members: Record<string, string>;
    records: string[];
    baseLegal: unknown;
    supplementalGoLegal: unknown;
  };
  assert.equal(image.imageId, l.imageId);
  assert.equal(image.revision, input.source.commit);
  assert.deepEqual(image.profile, legal.bundle.profile);
  assert.deepEqual(image.records, Object.keys(legal.bundle.records).sort());
  assert.deepEqual(image.baseLegal, legal.imageReceipt.baseLegal);
  const supplemental = Object.fromEntries(
    Object.entries(legal.securityGo).map(([name, bytes]) => [name, sha256(bytes)]),
  );
  assert.deepEqual(image.supplementalGoLegal, supplemental);
  const expectedLegal: Record<string, string> = {
    LICENSE: sha256(readOwned(source, "LICENSE")),
    "notices/provenance.json": sha256(
      Buffer.from(`${JSON.stringify(legal.imageReceipt, null, 2)}\n`),
    ),
  };
  for (const [name, digest] of Object.entries(legal.imageReceipt.legal))
    expectedLegal[`notices/${name}`] = digest as string;
  for (const [name, digest] of Object.entries(supplemental))
    expectedLegal[`notices/${name}`] = digest;
  assert.deepEqual(
    Object.keys(image.members).sort(),
    [...Object.keys(expectedLegal), "ArcForges.Cloud", "arcforges-center"].sort(),
  );
  for (const [name, digest] of Object.entries(expectedLegal))
    assert.equal(image.members[name], digest);
  const expectedNonroot = {
    uid: 1654,
    members: Object.fromEntries(
      Object.entries(expectedLegal).map(([name, value]) => [`/app/${name}`, value]),
    ),
  };
  assert.deepEqual(l.nonrootLegal, expectedNonroot, "Non-root legal read evidence differs");
  const oci = driver("verify-oci", {
    archive: path.join(linux, "docker-image.tar"),
    imageId: l.imageId,
    tag: l.image,
    appMembers: image.members,
  });
  assert.deepEqual(json(linux, "oci-inventory.json"), oci);
  const nativeLinux = driver("verify-native", {
    platform: "linux",
    bundle: path.join(linux, linuxZip),
    producerSource: root,
    go,
    compiler: l.compiler,
    producer: input.producer,
    identity: input.identity,
    binarySha256: image.members["arcforges-center"],
  });
  assert.equal(nativeLinux.sha256, l.members[linuxZip]?.sha256);
  const workerEvidence = legal.verifyWorker(
    source,
    readOwned(linux, "worker.js"),
    json(linux, "worker-meta.json"),
  );
  assert.deepEqual(workerEvidence, l.workerEvidence);
  const proofEvidence = verifyBridgeProofWorker(
    legal.profile,
    readOwned(linux, "proof-worker.js"),
    readOwned(linux, "proof-worker-meta.json"),
  );
  assert.deepEqual(proofEvidence, l.proofEvidence);
  verifyWorkerConfig(
    json(linux, "wrangler.json") as Parameters<typeof verifyWorkerConfig>[0],
    input.identity.build,
    l.image,
  );
  const toolExtract = path.join(work, "tool-assemblies");
  const tool = driver("extract-verified-tool", {
    archive: path.join(linux, "arcforges-tool.tar"),
    destination: toolExtract,
    members: l.toolMembers,
  });
  assert.equal(tool.assemblies, Object.keys(l.assemblyEvidence as Record<string, unknown>).length);
  assert.deepEqual(
    verifyToolAssemblies(source, work, toolExtract, input.identity),
    l.assemblyEvidence,
  );
  const windowsReceiptBytes = readOwned(windows, "windows-receipt.json");
  const w = object(
    parseDocument(windowsReceiptBytes),
    "schema producer source identity native bundle",
  ) as unknown as WindowsRecord;
  assert.equal(w.schema, "arcforges.ctr06-security-bridge-windows.v1");
  assert.deepEqual(w.producer, input.producer);
  assert.deepEqual(w.source, input.source);
  assert.deepEqual(w.identity, input.identity);
  assert.equal(w.native.sourceArchiveSha256, input.source.archiveSha256);
  checkCompiler(w.native.compiler, "windows");
  assert.deepEqual(w.native.binary.identity, {
    artifact: input.identity.artifact,
    build: input.identity.build,
  });
  const windowsZip = `arcforges-ctr06-security-bridge-${input.version}-windows-amd64.zip`;
  closedFiles(windows, { [windowsZip]: { sha256: w.bundle.sha256, size: w.bundle.size } }, [
    "windows-receipt.json",
  ]);
  const windowsReadback = driver("verify-windows-from-native-job", {
    bundle: path.join(windows, windowsZip),
    producerSource: root,
    go,
    compiler: w.native.compiler,
    producer: input.producer,
    identity: input.identity,
    binarySha256: w.native.binarySha256,
  });
  assert.deepEqual(windowsReadback, w.bundle);
  const combined: Record<string, Member> = {};
  const manifests = {
    linux: {
      ...l.members,
      "manifest.json": { sha256: sha256(linuxManifestBytes), size: linuxManifestBytes.length },
    },
    windows: {
      [windowsZip]: { sha256: w.bundle.sha256, size: w.bundle.size },
      "windows-receipt.json": {
        sha256: sha256(windowsReceiptBytes),
        size: windowsReceiptBytes.length,
      },
    },
  };
  for (const [label, directory] of [
    ["linux", linux],
    ["windows", windows],
  ] as const) {
    const target = path.join(stage, label);
    mkdirSync(target, { mode: 0o755 });
    chmodSync(target, 0o755);
    const expectedMembers = manifests[label];
    assert.deepEqual(readdirSync(directory).sort(), Object.keys(expectedMembers).sort());
    for (const [name, expected] of Object.entries(expectedMembers)) {
      const dest = path.join(target, name);
      copyFileSync(path.join(directory, name), dest, constants.COPYFILE_EXCL);
      // These are newly-created public carrier members; no pre-existing path is changed.
      chmodSync(dest, 0o644);
      const data = readFileSync(dest);
      const copied = { sha256: sha256(data), size: data.length };
      assert.deepEqual(
        copied,
        expected,
        `Artifact changed during carrier creation: ${label}/${name}`,
      );
      combined[`${label}/${name}`] = copied;
    }
  }
  const manifest = {
    schema: "arcforges.ctr06-security-bridge-carrier.v1",
    producer: input.producer,
    source: input.source,
    identity: input.identity,
    linuxManifestSha256: sha256(linuxManifestBytes),
    windowsReceiptSha256: sha256(windowsReceiptBytes),
    members: combined,
  };
  const manifestPath = path.join(stage, "manifest.json");
  writeJson(manifestPath, manifest);
  chmodSync(manifestPath, 0o644);
  combined["manifest.json"] = {
    sha256: sha256(readFileSync(manifestPath)),
    size: lstatSync(manifestPath).size,
  };
  const raw = path.join(work, "carrier.tar");
  run(
    "tar",
    [
      "--sort=name",
      "--mtime=@0",
      "--owner=0",
      "--group=0",
      "--numeric-owner",
      "-cf",
      raw,
      "-C",
      stage,
      ".",
    ],
    root,
  );
  const carrierName = `arcforges-ctr06-security-bridge-${input.version}.tar.gz`;
  const carrier = path.join(sealed, carrierName);
  const fd = openSync(carrier, "wx", 0o644);
  try {
    execFileSync("gzip", ["-n", "-c", raw], {
      stdio: ["ignore", fd, "inherit"],
      timeout: 600000,
      env: childEnvironment(),
    });
  } finally {
    closeSync(fd);
  }
  const checked = driver("verify-carrier", { archive: carrier, members: combined });
  writeJson(path.join(sealed, "bootstrap-receipt.json"), {
    schema: "arcforges.ctr06-security-bridge-bootstrap.v1",
    producer: input.producer,
    source: input.source,
    version: input.version,
    carrier: { name: carrierName, ...checked },
    manifestSha256: combined["manifest.json"]?.sha256,
  });
}

if (import.meta.url === pathToFileURL(process.argv[1] ?? "").href) {
  const [source, linux, windows, goArchive, go, output] = process.argv.slice(2);
  assert(
    source && linux && windows && goArchive && go && output,
    "usage: seal /source /linux-artifact /windows-artifact /go-archive /go /runner-temp-output",
  );
  await sealSecurityBridge(source, linux, windows, goArchive, go, output);
}
