// SPDX-License-Identifier: AGPL-3.0-only
// Source and run identity for the AF-CTR-06 security bridge. This does not authorize publication.
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import path from "node:path";
import { resolveAxes } from "./build-identity.ts";
import { gitEnvironment } from "./process.ts";
import { parseDocument, readOwned } from "./provenance.ts";

export const bridgeSource = {
  commit: "8e5f6e26aa97b123d9f60b91f780364a094e74cd",
  tree: "4a315ea6b47d96c3262e8111fcc26ad1957097f2",
  archiveSha256: "ea07d57bdc0acf43c2e58bdc3666d8334185600f46e903e2d5a109547e59293c",
  epoch: 1794319148,
} as const;

const workflowRef = "ArcForges/Cloud/.github/workflows/ci.yml@refs/heads/main";
const hexCommit = /^[0-9a-f]{40}$/u;
const number = /^[1-9][0-9]{0,14}$/u;
const hash = (value: Buffer | string) => createHash("sha256").update(value).digest("hex");

function object(value: unknown): Record<string, unknown> {
  assert(value !== null && typeof value === "object" && !Array.isArray(value), "Expected object");
  return value as Record<string, unknown>;
}

export type ProducerFacts = {
  head: string;
  tree: string;
  clean: boolean;
  sourceCommit: string;
  sourceTree: string;
  sourceEpoch: number;
  sourceArchiveSha256: string;
  sourceIsAncestor: boolean;
};

/** Checks a GitHub main-push context; callers must obtain facts from the actual Git checkout. */
export function validateBridgeProducer(
  env: NodeJS.ProcessEnv,
  eventValue: unknown,
  facts: ProducerFacts,
) {
  const event = object(eventValue);
  const repository = object(event.repository);
  assert.equal(env.GITHUB_ACTIONS, "true");
  assert.equal(env.GITHUB_EVENT_NAME, "push");
  assert.equal(env.GITHUB_REPOSITORY, "ArcForges/Cloud");
  assert.equal(env.GITHUB_SERVER_URL, "https://github.com");
  assert.equal(env.GITHUB_REF, "refs/heads/main");
  assert.equal(env.GITHUB_REF_PROTECTED, "true");
  assert.equal(env.GITHUB_WORKFLOW_REF, workflowRef);
  assert.match(env.GITHUB_SHA ?? "", hexCommit);
  assert.equal(env.GITHUB_WORKFLOW_SHA, env.GITHUB_SHA);
  assert.equal(event.ref, env.GITHUB_REF);
  assert.equal(event.after, env.GITHUB_SHA);
  assert.equal(event.deleted, false);
  assert.equal(repository.full_name, env.GITHUB_REPOSITORY);
  assert.equal(repository.default_branch, "main");
  for (const key of ["GITHUB_RUN_ID", "GITHUB_RUN_NUMBER", "GITHUB_RUN_ATTEMPT"] as const) {
    assert.match(env[key] ?? "", number, `Invalid ${key}`);
    assert(Number.isSafeInteger(Number(env[key])), `Unsafe ${key}`);
  }
  assert.equal(facts.head, env.GITHUB_SHA, "The producer checkout is not this push");
  assert.match(facts.tree, hexCommit);
  assert.equal(facts.clean, true, "The producer checkout is dirty");
  assert.equal(facts.sourceCommit, bridgeSource.commit);
  assert.equal(facts.sourceTree, bridgeSource.tree);
  assert.equal(facts.sourceEpoch, bridgeSource.epoch);
  assert.equal(facts.sourceArchiveSha256, bridgeSource.archiveSha256);
  assert.equal(
    facts.sourceIsAncestor,
    true,
    "The bridge source is not an ancestor of this producer",
  );
  const runId = env.GITHUB_RUN_ID as string;
  const runNumber = env.GITHUB_RUN_NUMBER as string;
  const runAttempt = Number(env.GITHUB_RUN_ATTEMPT);
  return {
    producer: {
      repository: env.GITHUB_REPOSITORY,
      workflowRef,
      commit: facts.head,
      tree: facts.tree,
      runId,
      runNumber,
      runAttempt,
      pipelineRun: `https://github.com/ArcForges/Cloud/actions/runs/${runId}`,
    },
    source: bridgeSource,
    version: `0.1.0-ci.${runNumber}.${runAttempt}`,
  };
}

function git(directory: string, args: string[], binary = false): Buffer {
  return execFileSync("git", args, {
    cwd: directory,
    windowsHide: true,
    timeout: 30000,
    maxBuffer: 128 * 1024 * 1024,
    env: gitEnvironment(),
    encoding: binary ? "buffer" : undefined,
  });
}
function gitText(directory: string, ...args: string[]) {
  return git(directory, args).toString("utf8").trim();
}

/** Reads actual producer and source Git objects. No caller-provided claims enter this check. */
export function collectBridgeFacts(producerDirectory: string): ProducerFacts {
  assert(path.isAbsolute(producerDirectory), "Producer directory must be absolute");
  const head = gitText(producerDirectory, "rev-parse", "HEAD");
  const sourceCommit = gitText(producerDirectory, "rev-parse", `${bridgeSource.commit}^{commit}`);
  let sourceIsAncestor = false;
  try {
    git(producerDirectory, ["merge-base", "--is-ancestor", sourceCommit, head]);
    sourceIsAncestor = true;
  } catch {
    // A failed ancestry check is always rejection, never a fallback.
  }
  return {
    head,
    tree: gitText(producerDirectory, "rev-parse", "HEAD^{tree}"),
    clean: gitText(producerDirectory, "status", "--porcelain=v1", "--untracked-files=all") === "",
    sourceCommit,
    sourceTree: gitText(producerDirectory, "rev-parse", `${sourceCommit}^{tree}`),
    sourceEpoch: Number(gitText(producerDirectory, "show", "-s", "--format=%ct", sourceCommit)),
    sourceArchiveSha256: hash(
      git(producerDirectory, ["archive", "--format=tar", sourceCommit], true),
    ),
    sourceIsAncestor,
  };
}

/** Check tracked source again after generated files appear and before loading its code. */
export function verifyTrackedBridgeSource(sourceDirectory: string) {
  assert(path.isAbsolute(sourceDirectory), "Bridge source directory must be absolute");
  assert.equal(gitText(sourceDirectory, "rev-parse", "HEAD"), bridgeSource.commit);
  assert.equal(gitText(sourceDirectory, "rev-parse", "HEAD^{tree}"), bridgeSource.tree);
  assert.equal(
    gitText(sourceDirectory, "status", "--porcelain=v1", "--untracked-files=all"),
    "",
    "Bridge tracked source differs",
  );
}

/** A fresh private checkout prevents ignored or untracked input from entering the old build. */
export function verifyFreshBridgeSource(sourceDirectory: string) {
  verifyTrackedBridgeSource(sourceDirectory);
  assert.equal(
    gitText(
      sourceDirectory,
      "status",
      "--porcelain=v1",
      "--ignored=matching",
      "--untracked-files=all",
    ),
    "",
    "Bridge source must be fresh, without ignored or untracked inputs",
  );
  assert.equal(
    hash(git(sourceDirectory, ["archive", "--format=tar", "HEAD"], true)),
    bridgeSource.archiveSha256,
  );
}

/** The ordinary sourceBuild remains unchanged; this independently binds 8e5 to the real new producer. */
export function bridgeIdentity(
  sourceDirectory: string,
  producer: ReturnType<typeof validateBridgeProducer>,
) {
  const read = (name: string) => {
    if (name === "assembly/release.json")
      return JSON.stringify({ versions: [{ subject: "Cloud", version: producer.version }] });
    if (name === "packages/contracts/source.json") name = "eng/generated/contracts-identity.json";
    return readOwned(sourceDirectory, name).toString("utf8");
  };
  // The axis resolver used here must be byte-identical to the one in the fixed historical source.
  assert.equal(
    hash(readFileSync(path.join(import.meta.dirname, "build-identity.ts"))),
    hash(readOwned(sourceDirectory, "tooling/build-identity.ts")),
    "The bridge identity resolver differs from the reviewed source",
  );
  const contracts = object(parseDocument(read("packages/contracts/source.json")));
  const props = read("Directory.Packages.props");
  assert.equal(
    contracts.version,
    /Include="ArcForges.Contracts.PublicApi" Version="([^"]+)"/u.exec(props)?.[1],
  );
  assert.equal(contracts.version, "1.0.0-ci.287.1");
  return {
    schema: "arcforges.build-identity.v1",
    owner: "Cloud",
    artifact: { id: "Cloud", version: producer.version },
    build: {
      sourceCommit: bridgeSource.commit,
      dirty: false,
      kind: "ci",
      buildId: `${producer.producer.runId}.${producer.producer.runAttempt}`,
      runId: producer.producer.runId,
      runAttempt: producer.producer.runAttempt,
      pipelineRun: producer.producer.pipelineRun,
      sourceDateEpoch: bridgeSource.epoch,
    },
    axes: resolveAxes(parseDocument(read("eng/version-sources.json")), read),
  };
}

/** This is an input check only; in particular, it does not prove the absence of delegated credentials. */
export function actualBridgeProducer(producerDirectory: string, sourceDirectory: string) {
  const eventPath = process.env.GITHUB_EVENT_PATH;
  assert(eventPath && path.isAbsolute(eventPath), "Missing GitHub event payload");
  const event = parseDocument(readFileSync(eventPath));
  const producer = validateBridgeProducer(
    process.env,
    event,
    collectBridgeFacts(producerDirectory),
  );
  verifyFreshBridgeSource(sourceDirectory);
  return { ...producer, identity: bridgeIdentity(sourceDirectory, producer) };
}

// The old source is unchanged. The derived file changes only the pinned Go archive acquisition
// and the licence COPY mode, so the image user can read that legal text regardless of host umask.
export const securityBridgeGoArchive = {
  name: "go1.27.4.linux-amd64.tar.gz",
  sha256: "7226736c2339719cda28fbf3a54d71aa63bcefe376e98cef00034268dab24840",
  version: "go1.27.4",
} as const;
const oldGoInstall = `RUN curl --fail --silent --show-error --location https://go.dev/dl/go1.27.3.linux-amd64.tar.gz -o /tmp/go.tar.gz \\
    && echo "65efbc80fdc1fa2cd2631cad5b481777a68e8725f34e89f50fc6ac714e379b40  /tmp/go.tar.gz" | sha256sum -c - \\
    && tar -C /usr/local -xzf /tmp/go.tar.gz && rm /tmp/go.tar.gz`;
const securityGoInstall = `COPY --from=bridge_go_archive /go.tar.gz /tmp/go.tar.gz
RUN echo "${securityBridgeGoArchive.sha256}  /tmp/go.tar.gz" | sha256sum -c - \\
    && tar -C /usr/local -xzf /tmp/go.tar.gz && rm /tmp/go.tar.gz \\
    && test "$(/usr/local/go/bin/go version)" = "go version go1.27.4 linux/amd64"`;

const securityToolStage = `FROM build AS security-tool-build
WORKDIR /source
COPY --from=bridge_tool_source /ArcForges.Cloud.Generation ./tools/ArcForges.Cloud.Generation
RUN sha256sum tools/ArcForges.Cloud.Generation/packages.lock.json > /tmp/tool-lock.sha \\
    && dotnet restore tools/ArcForges.Cloud.Generation/ArcForges.Cloud.Generation.csproj --locked-mode \\
    && dotnet publish tools/ArcForges.Cloud.Generation/ArcForges.Cloud.Generation.csproj -c Release -r linux-x64 --self-contained true --no-restore \\
    -p:PublishSingleFile=false -p:DebugType=none -p:CloudSourceArchive=true \\
    -p:SourceRevisionId="$SOURCE_COMMIT" -p:ArcForgesSourceCommit="$SOURCE_COMMIT" -p:CloudSourceDirty="$SOURCE_DIRTY" \\
    -p:Version="$APP_VERSION" -p:ArcForgesBuildKind="$BUILD_KIND" -p:ArcForgesBuildId="$BUILD_ID" \\
    -p:ArcForgesPipelineRun="$PIPELINE_RUN" -p:ArcForgesSourceDateEpoch="$SOURCE_EPOCH" -o /tool-output \\
    && sha256sum -c /tmp/tool-lock.sha
FROM scratch AS security-tool
COPY --from=security-tool-build /tool-output/ /

`;

export function securityBridgeDockerfile(source: string) {
  assert.equal(source.split(oldGoInstall).length, 2, "Historical Go build block differs");
  const oldLicenseCopy = "COPY LICENSE ./LICENSE";
  const runtimeFrom = "FROM mcr.microsoft.com/dotnet/runtime-deps:";
  assert.equal(source.split(oldLicenseCopy).length, 2, "Historical licence copy differs");
  assert.equal(source.split(runtimeFrom).length, 2, "Historical runtime stage differs");
  return source
    .replace(oldGoInstall, securityGoInstall)
    .replace(oldLicenseCopy, "COPY --chmod=0644 LICENSE ./LICENSE")
    .replace(runtimeFrom, securityToolStage + runtimeFrom);
}

export function verifySecurityGoArchive(bytes: Buffer) {
  assert.equal(hash(bytes), securityBridgeGoArchive.sha256, "Security bridge Go archive differs");
}
