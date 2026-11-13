// SPDX-License-Identifier: AGPL-3.0-only
// Dedicated 8e5 security-bridge construction. This program does not publish or authorize a release.
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { createHash } from "node:crypto";
import {
  chmodSync,
  copyFileSync,
  lstatSync,
  mkdirSync,
  readFileSync,
  readdirSync,
  realpathSync,
  writeFileSync,
} from "node:fs";
import path from "node:path";
import { pathToFileURL } from "node:url";
import { imageBuildVariables } from "./build-identity.ts";
import {
  actualBridgeProducer,
  bridgeSource,
  securityBridgeDockerfile,
  verifySecurityGoArchive,
  verifyTrackedBridgeSource,
} from "./ctr06-security-bridge-source.ts";
import {
  securityBridgeLegal,
  stageSecurityBridgeNotices,
  verifySecurityBridgeImageFiles,
} from "./ctr06-security-bridge-legal.ts";
import { root } from "./process.ts";
import { releaseProfile } from "./release-provenance.ts";
import type { WorkerConfig } from "./project.ts";

export const sha256 = (bytes: Buffer) => createHash("sha256").update(bytes).digest("hex");
export const jsonBytes = (value: unknown) => Buffer.from(`${JSON.stringify(value, null, 2)}\n`);
const readJson = <T>(name: string): T => JSON.parse(readFileSync(name, "utf8")) as T;
export function writeJson(name: string, value: unknown) {
  writeFileSync(name, jsonBytes(value), { flag: "wx" });
}

// Build tools have no reason to receive tokens, the GitHub event payload, or provider/database
// configuration. The actual GitHub identity is independently checked in this process first and is
// passed only as public, validated build metadata. Docker does not inherit host GitHub variables.
export function childEnvironment() {
  const allowed = [
    "PATH",
    "HOME",
    "USERPROFILE",
    "LOCALAPPDATA",
    "SYSTEMROOT",
    "WINDIR",
    "COMSPEC",
    "PATHEXT",
    "TMP",
    "TEMP",
    "TMPDIR",
    "LANG",
    "LC_ALL",
    "DOTNET_ROOT",
  ];
  return {
    ...Object.fromEntries(
      allowed.filter((key) => process.env[key] !== undefined).map((key) => [key, process.env[key]]),
    ),
    CI: "true",
    GOTOOLCHAIN: "local",
    GOWORK: "off",
    GOFLAGS: "-mod=readonly",
    GOTELEMETRY: "off",
    CGO_ENABLED: "0",
    WRANGLER_SEND_METRICS: "false",
    PYTHONDONTWRITEBYTECODE: "1",
  };
}
export function run(
  command: string,
  args: string[],
  cwd: string,
  capture = false,
  input?: Buffer,
): Buffer {
  return execFileSync(command, args, {
    cwd,
    windowsHide: true,
    timeout: 600000,
    maxBuffer: 256 * 1024 * 1024,
    env: childEnvironment(),
    input,
    stdio: [input ? "pipe" : "ignore", capture ? "pipe" : "inherit", "inherit"],
  }) as Buffer;
}
export function driver(operation: string, input: unknown) {
  return JSON.parse(
    run(
      "python",
      [path.join(root, "eng/verification/ctr06_security_bridge_driver.py"), operation],
      root,
      true,
      jsonBytes(input),
    ).toString("utf8"),
  );
}
export function outputDirectory(name: string) {
  assert(path.isAbsolute(name) && process.env.RUNNER_TEMP, "Use a new private runner-temp output");
  const parent = realpathSync(path.dirname(name));
  assert.equal(parent, realpathSync(process.env.RUNNER_TEMP));
  mkdirSync(name, { mode: 0o700 });
  return name;
}
function goRoot(go: string, platform: "linux" | "windows") {
  assert(path.isAbsolute(go));
  const actual = realpathSync(go);
  assert.equal(path.basename(actual).toLowerCase(), platform === "windows" ? "go.exe" : "go");
  assert(lstatSync(actual).isFile());
  return path.dirname(path.dirname(actual));
}
function argsForImage(identity: ReturnType<typeof actualBridgeProducer>["identity"]) {
  return Object.entries(imageBuildVariables(identity)).flatMap(([key, value]) => [
    "--build-arg",
    `${key}=${value}`,
  ]);
}
function assertSourceClean(source: string) {
  verifyTrackedBridgeSource(source);
}
export function verifyWorkerConfig(config: WorkerConfig, build: unknown, image: string) {
  assert.equal(config.name, "arcforges-cloud");
  assert.equal(config.main, "./worker.js");
  assert.equal(config.no_bundle, true);
  assert.equal(config.vars.SOURCE_REVISION, bridgeSource.commit);
  assert.equal(config.vars.BUILD_IDENTITY, JSON.stringify(build));
  assert.equal(config.containers.length, 1);
  assert.equal(config.containers[0].image, image);
  assert.equal(config.containers[0].max_instances, 1);
}
export function verifyBridgeProofWorker(
  profile: { worker: { inputs: Record<string, string>; outputInputs: string[] } },
  bytes: Buffer,
  metaBytes: Buffer,
) {
  assert.equal(
    sha256(metaBytes),
    "adfc6c0c1329eba52e37dbfdfe53581d89ab0ed884ed215ea3507cbb832a27e8",
    "Changed historical-source proof Worker metadata",
  );
  const meta = JSON.parse(metaBytes.toString("utf8")) as {
    inputs: Record<string, unknown>;
    outputs: Record<
      string,
      {
        entryPoint: string;
        bytes: number;
        inputs: Record<string, unknown>;
        exports: string[];
        imports: unknown[];
      }
    >;
  };
  assert.equal(
    sha256(bytes),
    "b4eb36509ffe1af337bbdb4f5423dce0fade787b88de60aa890cb5cd18d6d703",
    "Changed historical-source proof Worker bytes",
  );
  assert.deepEqual(Object.keys(meta).sort(), ["inputs", "outputs"]);
  const replacement = (names: string[]) => {
    assert(names.includes("worker/index.ts") && !names.includes("worker/acceptance/entry.ts"));
    return names
      .map((name) => (name === "worker/index.ts" ? "worker/acceptance/entry.ts" : name))
      .sort();
  };
  assert.deepEqual(
    Object.keys(meta.inputs).sort(),
    replacement(Object.keys(profile.worker.inputs)),
  );
  const name = "artifacts/worker-bundle-proof/entry.js";
  assert.deepEqual(Object.keys(meta.outputs).sort(), [name, `${name}.map`].sort());
  const output = meta.outputs[name];
  assert(output);
  assert.equal(output.entryPoint, "worker/acceptance/entry.ts");
  assert.equal(output.bytes, bytes.length);
  assert.deepEqual(
    Object.keys(output.inputs).sort(),
    replacement([...profile.worker.outputInputs]),
  );
  assert.deepEqual(
    [...output.exports].sort(),
    [
      "ContainerProxy",
      "FoundationContainer",
      "FoundationJobCoordinator",
      "HarnessRunAlarm",
      "default",
    ].sort(),
  );
  assert.deepEqual(output.imports, [
    { path: "cloudflare:workers", kind: "import-statement", external: true },
  ]);
  return {
    sha256: sha256(bytes),
    bytes: bytes.length,
    inputPaths: Object.keys(meta.inputs).sort(),
  };
}

export function verifyToolAssemblies(
  source: string,
  work: string,
  tool: string,
  identity: ReturnType<typeof actualBridgeProducer>["identity"],
) {
  const sdk = run("dotnet", ["--version"], root, true).toString("utf8").trim();
  assert.equal(sdk, "10.0.403");
  const inspect = path.join(work, "metadata-verifier");
  mkdirSync(inspect, { mode: 0o700 });
  copyFileSync(
    path.join(root, "eng/verification/ctr06-security-bridge-metadata.cs"),
    path.join(inspect, "Program.cs"),
  );
  writeFileSync(
    path.join(inspect, "Verifier.csproj"),
    '<Project Sdk="Microsoft.NET.Sdk"><PropertyGroup><OutputType>Exe</OutputType><TargetFramework>net10.0</TargetFramework><ImplicitUsings>enable</ImplicitUsings><Nullable>enable</Nullable><TreatWarningsAsErrors>true</TreatWarningsAsErrors></PropertyGroup></Project>\n',
  );
  writeFileSync(
    path.join(inspect, "global.json"),
    '{"sdk":{"version":"10.0.403","rollForward":"disable"}}\n',
  );
  writeFileSync(
    path.join(inspect, "NuGet.Config"),
    "<configuration><packageSources><clear /></packageSources></configuration>\n",
  );
  run(
    "dotnet",
    ["build", "Verifier.csproj", "-c", "Release", "--configfile", "NuGet.Config"],
    inspect,
  );
  const projects = run("git", ["ls-files", "src/*.csproj", "src/**/*.csproj"], source, true)
    .toString("utf8")
    .trim()
    .split("\n");
  const assemblies = [
    ...projects.map((name) => `${path.posix.basename(name, ".csproj")}.dll`),
    "ArcForges.Cloud.Generation.dll",
  ].sort();
  const expected = path.join(inspect, "expected.json");
  writeJson(expected, { ...identity, assemblies });
  return JSON.parse(
    run(
      "dotnet",
      [path.join(inspect, "bin/Release/net10.0/Verifier.dll"), tool, expected],
      inspect,
      true,
    ).toString("utf8"),
  );
}

export async function buildSecurityBridge(
  platform: "linux" | "windows",
  source: string,
  goArchive: string,
  go: string,
  outputName: string,
) {
  assert.equal(
    process.platform,
    platform === "windows" ? "win32" : "linux",
    "A native build is required",
  );
  assert(path.isAbsolute(source) && path.isAbsolute(goArchive));
  const input = actualBridgeProducer(root, source);
  // The checked-in active admission must bind this exact bootstrap producer closure.
  releaseProfile(root);
  assert.equal(process.version, "v24.21.0", "Select the pinned Node release");
  const output = outputDirectory(outputName);
  const work = path.join(output, "work");
  const sealed = path.join(output, "sealed");
  mkdirSync(work, { mode: 0o700 });
  mkdirSync(sealed, { mode: 0o700 });
  const compilerRoot = goRoot(go, platform);
  const binary = path.join(
    work,
    platform === "windows" ? "arcforges-center.exe" : "arcforges-center",
  );
  const nativeName = `arcforges-ctr06-security-bridge-${input.version}-${platform}-amd64.zip`;
  const nativeZip = path.join(sealed, nativeName);
  if (platform === "windows") {
    const native = driver("build-native", {
      platform,
      source,
      goArchive,
      goRoot: compilerRoot,
      output: binary,
      identity: input.identity,
    });
    const zipped = driver("seal-native", {
      platform,
      source,
      producerSource: root,
      binary,
      goArchive,
      goRoot: compilerRoot,
      producer: input.producer,
      identity: input.identity,
      binarySha256: native.binarySha256,
      output: nativeZip,
    });
    const checked = driver("verify-native", {
      platform,
      bundle: nativeZip,
      producerSource: root,
      go,
      compiler: native.compiler,
      producer: input.producer,
      identity: input.identity,
      binarySha256: native.binarySha256,
    });
    assert.equal(zipped.sha256, checked.sha256);
    assertSourceClean(source);
    writeJson(path.join(sealed, "windows-receipt.json"), {
      schema: "arcforges.ctr06-security-bridge-windows.v1",
      producer: input.producer,
      source: input.source,
      identity: input.identity,
      native,
      bundle: checked,
    });
    return;
  }
  const archiveBytes = readFileSync(goArchive);
  verifySecurityGoArchive(archiveBytes);
  const goContext = path.join(work, "go-context");
  mkdirSync(goContext, { mode: 0o700 });
  writeFileSync(path.join(goContext, "go.tar.gz"), archiveBytes, { flag: "wx", mode: 0o600 });
  const dockerfile = path.join(work, "Dockerfile");
  writeFileSync(
    dockerfile,
    securityBridgeDockerfile(readFileSync(path.join(source, "Dockerfile"), "utf8")),
    { flag: "wx" },
  );
  const toolContext = path.join(work, "tool-context");
  const toolInputs = driver("tool-context", { source, destination: toolContext });
  assert.equal(
    run("npm", ["--version"], source, true).toString("utf8").trim(),
    "11.19.0",
    "Select the pinned npm release",
  );
  run("npm", ["ci", "--ignore-scripts"], source);
  const legal = await securityBridgeLegal(source, root);
  stageSecurityBridgeNotices(source, legal);
  const image = `arcforges-ctr06-security-bridge:ci.${input.producer.runNumber}.${input.producer.runAttempt}`;
  const common = [
    "buildx",
    "build",
    "--platform",
    "linux/amd64",
    "--provenance=false",
    "--build-context",
    `bridge_go_archive=${goContext}`,
    "--build-context",
    `bridge_tool_source=${toolContext}`,
    "-f",
    dockerfile,
    ...argsForImage(input.identity),
  ];
  const tool = path.join(work, "tool-output");
  run(
    "docker",
    [...common, "--target", "security-tool", "--output", `type=local,dest=${tool}`, source],
    root,
  );
  const assemblyEvidence = verifyToolAssemblies(source, work, tool, input.identity);
  const toolMembers = Object.fromEntries(
    readdirSync(tool)
      .sort()
      .map((name) => {
        const file = path.join(tool, name);
        const info = lstatSync(file);
        assert(info.isFile() && !info.isSymbolicLink(), "Unexpected sealed tool member");
        return [
          name,
          { sha256: sha256(readFileSync(file)), size: info.size, mode: info.mode & 0o777 },
        ];
      }),
  );
  const toolArchive = path.join(sealed, "arcforges-tool.tar");
  run(
    "tar",
    [
      "--sort=name",
      "--mtime=@0",
      "--owner=0",
      "--group=0",
      "--numeric-owner",
      "-cf",
      toolArchive,
      "-C",
      tool,
      ".",
    ],
    root,
  );
  run("docker", [...common, "--load", "--tag", image, source], root);
  let container = "";
  try {
    const info = JSON.parse(
      run("docker", ["image", "inspect", image], root, true).toString("utf8"),
    )[0];
    assert.equal(info.Os, "linux");
    assert.equal(info.Architecture, "amd64");
    assert.equal(info.Config.User, "1654");
    assert.deepEqual(info.Config.Entrypoint, ["/app/ArcForges.Cloud"]);
    assert.equal(info.Config.Labels["org.opencontainers.image.revision"], bridgeSource.commit);
    const sandbox = [
      "run",
      "--rm",
      "--network",
      "none",
      "--read-only",
      "--cap-drop",
      "ALL",
      "--security-opt",
      "no-new-privileges",
    ];
    const csharp = JSON.parse(
      run("docker", [...sandbox, image, "--build-info"], root, true).toString("utf8"),
    );
    assert.deepEqual(csharp, input.identity);
    const center = JSON.parse(
      run(
        "docker",
        [...sandbox, "--entrypoint", "/app/arcforges-center", image, "version"],
        root,
        true,
      ).toString("utf8"),
    );
    assert.deepEqual(center.artifact, input.identity.artifact);
    assert.deepEqual(center.build, input.identity.build);
    container = run("docker", ["create", image], root, true).toString("utf8").trim();
    assert.match(container, /^[0-9a-f]{64}$/u);
    const app = path.join(work, "app");
    mkdirSync(app, { mode: 0o700 });
    run("docker", ["cp", `${container}:/app/.`, app], root);
    const appEvidence = verifySecurityBridgeImageFiles(source, app, legal);
    for (const [name, expected] of Object.entries(appEvidence.baseLegal)) {
      const destination = path.join(work, `base-legal-${sha256(Buffer.from(name))}.txt`);
      run("docker", ["cp", "--follow-link", `${container}:${name}`, destination], root);
      assert.equal(sha256(readFileSync(destination)), expected);
    }
    copyFileSync(path.join(app, "arcforges-center"), binary);
    const native = driver("image-binary", {
      source,
      goArchive,
      goRoot: compilerRoot,
      binary,
      identity: input.identity,
    });
    // Prove effective access using the image's declared non-root UID, not only mode bits.
    const probe = path.join(work, "nonroot-legal-probe");
    assert(!probe.includes(","), "Docker bind mount path cannot contain a comma");
    run(
      go,
      [
        "build",
        "-trimpath",
        "-ldflags",
        "-s -w",
        "-o",
        probe,
        path.join(root, "eng/verification/ctr06_security_bridge_nonroot_probe.go"),
      ],
      root,
    );
    chmodSync(probe, 0o755);
    const nonroot = JSON.parse(
      run(
        "docker",
        [
          ...sandbox,
          "--user",
          "1654:1654",
          "--mount",
          `type=bind,src=${probe},dst=/ctr06-probe,readonly`,
          "--entrypoint",
          "/ctr06-probe",
          image,
        ],
        root,
        true,
      ).toString("utf8"),
    );
    const expectedLegal = Object.fromEntries(
      Object.entries(appEvidence.members)
        .filter(([name]) => name === "LICENSE" || name.startsWith("notices/"))
        .map(([name, hash]) => [`/app/${name}`, hash]),
    );
    assert.equal(nonroot.uid, 1654);
    assert.deepEqual(
      nonroot.members,
      expectedLegal,
      "The image user cannot read every legal member",
    );
    const zipped = driver("seal-native", {
      platform,
      source,
      producerSource: root,
      binary,
      goArchive,
      goRoot: compilerRoot,
      producer: input.producer,
      identity: input.identity,
      binarySha256: native.binarySha256,
      output: nativeZip,
    });
    const checked = driver("verify-native", {
      platform,
      bundle: nativeZip,
      producerSource: root,
      go,
      compiler: native.compiler,
      producer: input.producer,
      identity: input.identity,
      binarySha256: native.binarySha256,
    });
    assert.equal(zipped.sha256, checked.sha256);
    const imageTar = path.join(sealed, "docker-image.tar");
    run("docker", ["save", "--output", imageTar, image], root);
    const oci = driver("verify-oci", {
      archive: imageTar,
      imageId: info.Id,
      tag: image,
      appMembers: appEvidence.members,
    });
    writeJson(path.join(sealed, "oci-inventory.json"), oci);
    const wrangler = path.join(source, "node_modules/wrangler/bin/wrangler.js");
    const primary = path.join(source, "artifacts/worker-bundle");
    const proof = path.join(source, "artifacts/worker-bundle-proof");
    run(
      process.execPath,
      [
        wrangler,
        "deploy",
        "--dry-run",
        "--containers-rollout",
        "none",
        "--outdir",
        "artifacts/worker-bundle",
        "--metafile",
        "artifacts/worker-bundle/bundle-meta.json",
      ],
      source,
    );
    const worker = readFileSync(path.join(primary, "index.js"));
    const metadata = readJson<unknown>(path.join(primary, "bundle-meta.json"));
    const workerEvidence = legal.verifyWorker(source, worker, metadata);
    mkdirSync(path.join(source, "artifacts/proof-assets"), { recursive: true });
    run(
      process.execPath,
      [
        wrangler,
        "deploy",
        "--dry-run",
        "--env",
        "proof",
        "--containers-rollout",
        "none",
        "--outdir",
        "artifacts/worker-bundle-proof",
        "--metafile",
        "artifacts/worker-bundle-proof/bundle-meta.json",
      ],
      source,
    );
    const proofMetaBytes = readFileSync(path.join(proof, "bundle-meta.json"));
    const proofBytes = readFileSync(path.join(proof, "entry.js"));
    const proofEvidence = verifyBridgeProofWorker(legal.profile, proofBytes, proofMetaBytes);
    writeFileSync(path.join(sealed, "worker.js"), worker, { flag: "wx" });
    copyFileSync(path.join(primary, "bundle-meta.json"), path.join(sealed, "worker-meta.json"));
    copyFileSync(path.join(proof, "entry.js"), path.join(sealed, "proof-worker.js"));
    writeFileSync(path.join(sealed, "proof-worker-meta.json"), proofMetaBytes, { flag: "wx" });
    const config = readJson<WorkerConfig>(path.join(source, "wrangler.json"));
    delete config.$schema;
    config.main = "./worker.js";
    config.no_bundle = true;
    config.vars.SOURCE_REVISION = bridgeSource.commit;
    config.vars.BUILD_IDENTITY = JSON.stringify(input.identity.build);
    config.containers[0].image = image;
    verifyWorkerConfig(config, input.identity.build, image);
    writeJson(path.join(sealed, "wrangler.json"), config);
    writeJson(path.join(sealed, "build-identity.json"), input.identity);
    writeJson(path.join(sealed, "legal-notices.json"), legal.bundle);
    writeJson(path.join(sealed, "image-provenance.json"), {
      imageId: info.Id,
      ...appEvidence,
      supplementalGoLegal: Object.fromEntries(
        Object.entries(legal.securityGo).map(([name, bytes]) => [name, sha256(bytes)]),
      ),
    });
    assertSourceClean(source);
    const members = Object.fromEntries(
      readdirSync(sealed)
        .sort()
        .map((name) => {
          const file = path.join(sealed, name);
          assert(lstatSync(file).isFile());
          return [name, { sha256: sha256(readFileSync(file)), size: lstatSync(file).size }];
        }),
    );
    writeJson(path.join(sealed, "manifest.json"), {
      schema: "arcforges.ctr06-security-bridge-linux.v1",
      producer: input.producer,
      source: input.source,
      identity: input.identity,
      image,
      imageId: info.Id,
      compiler: native.compiler,
      dockerfileSha256: sha256(readFileSync(dockerfile)),
      toolInputs,
      assemblyEvidence,
      toolMembers,
      workerEvidence,
      proofEvidence,
      nonrootLegal: nonroot,
      members,
    });
  } finally {
    if (container) run("docker", ["rm", container], root);
  }
}

if (import.meta.url === pathToFileURL(process.argv[1] ?? "").href) {
  const [platform, source, archive, go, output] = process.argv.slice(2);
  assert(
    (platform === "linux" || platform === "windows") && source && archive && go && output,
    "usage: producer linux|windows /source /go-archive /go /runner-temp-output",
  );
  await buildSecurityBridge(platform, source, archive, go, output);
}
