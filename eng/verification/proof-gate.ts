// SPDX-License-Identifier: AGPL-3.0-only
// The gate of the proof deployment (owner decision of 2026-11-04, CI simplification after N1; AD-0020).
//
// A `proof=deploy` dispatch of .github/workflows/ci.yml runs no hosted validation and builds no candidate. Its `proof-gate` job runs
// `node eng/verification/proof-gate.ts gate` without any secret and proves, through the GitHub API and failing closed on any doubt:
//   a. the dispatched commit (GITHUB_SHA) is the head of main and is the merge commit of a merged pull request into main (its second
//      parent is the PR head) or a fast-forward (the commit is the PR head itself, or no PR merged as it and the commit carries the
//      statuses itself);
//   b. tree identity: the tree of the dispatched commit equals the tree of the commit the host legs verified (the PR head, or the
//      commit itself), and on that commit the latest status of each of `arcforges/linux` and `arcforges/windows` is `success`;
//   c. trusted poster: each counted status was created by the account the host legs report with (deku2026, a User) and has exactly
//      the shape eng/verify.py writes (no target URL; the description `<n> steps passed in <s>s on <machine> (profile full)`);
//   d. the successful main-push run of ci.yml for the same commit exists, its candidate job succeeded and its candidate artifact
//      (`cloud-candidate-<run>-<attempt>`) is unexpired and names that run and commit.
// The `deploy-proof` job then runs `node eng/verification/proof-gate.ts fetch`: it re-reads that artifact by its ID, downloads it,
// checks its SHA-256 against the API's digest, unpacks it into artifacts/candidate and checks that the sealed manifest
// (manifest.json, build-identity.json, image-provenance.json) names exactly the dispatched commit, the main-push run and its
// version, and that the checkout is that commit and tree, before anything is migrated or deployed. The deployment's own checks
// (verifyCandidate, the release provenance, the migration gates) then run unchanged on it; tooling/build-identity.ts accepts the
// producer run that the gate named (ARCFORGES_CANDIDATE_RUN_*) on a dispatch only.
//
// Nothing is ever rebuilt: without such a run or artifact (expired, failed, never built) the dispatch fails with the reason.
import { execFileSync, spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import {
  appendFileSync,
  closeSync,
  existsSync,
  lstatSync,
  mkdirSync,
  openSync,
  readdirSync,
  readFileSync,
  rmSync,
} from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

export const repository = "ArcForges/Cloud";
export const workflowPath = ".github/workflows/ci.yml";
export const candidateJobName = "Native AOT image and Worker build";
/** The two host verification contexts (eng/verify.py CONTEXTS); both must be `success` on the verified commit. */
export const hostContexts = ["arcforges/linux", "arcforges/windows"] as const;
/** The account whose host legs report the statuses (eng/verify.py run-and-report with the owner's status credential). */
export const trustedPoster = { login: "deku2026", id: 263133346, type: "User" } as const;
/** The success description of eng/verify.py (Reporter.post after a passed leg); the profile is always `full` (eng/verify_steps.py). */
export const successDescription =
  /^[1-9][0-9]* steps passed in [0-9]+s on [A-Za-z0-9._-]{1,64} \(profile full\)$/u;
/** At most this many pages of 100 statuses are read; more is refused rather than half-read. */
export const maxStatusPages = 10;
export const fallback =
  "Nothing was deployed. Re-run both host legs (python eng/verify.py run-and-report) on the PR head and dispatch again, " +
  "or merge again; the proof dispatch never rebuilds the candidate.";

export function candidateArtifactName(runId: number, attempt: number): string {
  return `cloud-candidate-${runId}-${attempt}`;
}

/** A refusal of the gate: the dispatch stops with this message and deploys nothing. */
export class GateRefusal extends Error {
  constructor(message: string) {
    super(message);
    this.name = "GateRefusal";
  }
}

function refuse(message: string): never {
  throw new GateRefusal(message);
}

function check(condition: unknown, message: string): asserts condition {
  if (!condition) refuse(message);
}

type Json = Record<string, unknown>;

function object(value: unknown, what: string): Json {
  check(
    typeof value === "object" && value !== null && !Array.isArray(value),
    `${what}: not an object`,
  );
  return value as Json;
}

function list(value: unknown, what: string): unknown[] {
  check(Array.isArray(value), `${what}: not a list`);
  return value;
}

function text(value: unknown, what: string): string {
  check(typeof value === "string", `${what}: not a string`);
  return value;
}

function count(value: unknown, what: string): number {
  check(
    typeof value === "number" && Number.isSafeInteger(value) && value > 0,
    `${what}: not a positive integer`,
  );
  return value;
}

const commitSha = /^[0-9a-f]{40}$/u;
const instant = /^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$/u;
const artifactDigest = /^sha256:[0-9a-f]{64}$/u;

function sha(value: unknown, what: string): string {
  const result = text(value, what);
  check(commitSha.test(result), `${what}: not a commit SHA`);
  return result;
}

/** Reads one GitHub REST endpoint (a path below https://api.github.com/, with its query) and returns the parsed JSON. */
export type Get = (endpoint: string) => unknown;

export interface CountedStatus {
  context: string;
  id: number;
  createdAt: string;
}

export interface GateResult {
  sha: string;
  tree: string;
  /** The commit the host legs verified: the merged PR head, or the dispatched commit itself (fast-forward). */
  verifiedCommit: string;
  kind: "merge" | "fast-forward";
  pullRequest: number | null;
  statuses: CountedStatus[];
  run: { id: number; number: number; attempt: number };
  /** The attempt of the run whose candidate job built the artifact (the artifact name and the version carry it). */
  candidateAttempt: number;
  artifact: { id: number; name: string; digest: string; size: number };
}

interface GitCommit {
  sha: string;
  tree: string;
  parents: string[];
}

const api = `repos/${repository}`;

function gitCommit(get: Get, commit: string): GitCommit {
  const value = object(get(`${api}/git/commits/${commit}`), `commit ${commit}`);
  const found = sha(value.sha, `commit ${commit}`);
  check(found === commit, `the API answered commit ${found} for ${commit}`);
  return {
    sha: found,
    tree: sha(object(value.tree, `the tree of ${commit}`).sha, `the tree of ${commit}`),
    parents: list(value.parents, `the parents of ${commit}`).map((parent) =>
      sha(object(parent, `a parent of ${commit}`).sha, `a parent of ${commit}`),
    ),
  };
}

/** 1a: the dispatched commit is main's head and a PR merge commit (or a fast-forward); returns the commit the host legs verified. */
function mergeOrigin(
  get: Get,
  commit: GitCommit,
): { verified: string; kind: GateResult["kind"]; pullRequest: number | null } {
  const main = object(get(`${api}/git/ref/heads/main`), "the main ref");
  check(main.ref === "refs/heads/main", "the API answered another ref for main");
  const head = object(main.object, "the main ref");
  check(head.type === "commit", "main does not point at a commit");
  const mainSha = sha(head.sha, "the head of main");
  check(
    mainSha === commit.sha,
    `The dispatched commit ${commit.sha} is not the head of main (${mainSha}); dispatch again on the current main.`,
  );
  const merged = list(
    get(`${api}/commits/${commit.sha}/pulls?per_page=100`),
    `the pull requests of ${commit.sha}`,
  )
    .map((entry) => object(entry, `a pull request of ${commit.sha}`))
    .filter((pull) => {
      const base = object(pull.base, "a pull request base");
      return (
        pull.merge_commit_sha === commit.sha &&
        typeof pull.merged_at === "string" &&
        instant.test(pull.merged_at) &&
        base.ref === "main" &&
        object(base.repo, "a pull request base repository").full_name === repository
      );
    });
  check(
    merged.length <= 1,
    `${merged.length} pull requests name ${commit.sha} as their merge commit; the gate cannot tell which one was verified.`,
  );
  const pull = merged[0];
  if (pull === undefined) {
    // No pull request was merged as this commit: only a fast-forward to a commit that carries the host statuses itself.
    return { verified: commit.sha, kind: "fast-forward", pullRequest: null };
  }
  const number = count(pull.number, "the pull request number");
  const prHead = sha(object(pull.head, "the pull request head").sha, "the pull request head");
  if (prHead === commit.sha) return { verified: prHead, kind: "fast-forward", pullRequest: number };
  check(
    commit.parents.length === 2 && commit.parents[1] === prHead,
    `${commit.sha} is not the merge commit of PR #${number}: its parents are ${commit.parents.join(", ") || "none"}, the PR head is ${prHead} (a squash or rebase merge is not a verified tree).`,
  );
  return { verified: prHead, kind: "merge", pullRequest: number };
}

function statusesOf(get: Get, commit: string): Json[] {
  const all: Json[] = [];
  for (let page = 1; page <= maxStatusPages; page++) {
    const entries = list(
      get(`${api}/commits/${commit}/statuses?per_page=100&page=${page}`),
      `the statuses of ${commit}`,
    );
    for (const entry of entries) all.push(object(entry, `a status of ${commit}`));
    if (entries.length < 100) return all;
  }
  refuse(
    `${commit} has more than ${maxStatusPages * 100} statuses; the gate does not read a partial list.`,
  );
}

/** 1b and 1c: the latest status of one context on the verified commit is a success that the host legs' account posted. */
export function countedStatus(statuses: Json[], context: string, commit: string): CountedStatus {
  const ofContext = statuses.filter((status) => status.context === context);
  check(
    ofContext.length > 0,
    `${commit} has no ${context} status: the host leg did not report on the verified commit. ${fallback}`,
  );
  const keyed = ofContext.map((status) => {
    const createdAt = text(status.created_at, `a ${context} status time`);
    check(instant.test(createdAt), `a ${context} status time is not an RFC 3339 UTC instant`);
    return { status, createdAt, id: count(status.id, `a ${context} status id`) };
  });
  // The latest status counts: a later failure, error or pending (or a status of anyone else) supersedes an earlier success.
  const latest = keyed.reduce((a, b) =>
    b.createdAt > a.createdAt || (b.createdAt === a.createdAt && b.id > a.id) ? b : a,
  );
  const { status } = latest;
  check(
    status.state === "success",
    `The latest ${context} status on ${commit} (id ${latest.id}) is ${String(status.state)}, not success. ${fallback}`,
  );
  const creator = object(status.creator, `the creator of ${context} status ${latest.id}`);
  check(
    creator.login === trustedPoster.login &&
      creator.id === trustedPoster.id &&
      creator.type === trustedPoster.type,
    `The latest ${context} status on ${commit} (id ${latest.id}) was not created by the host legs' account ${trustedPoster.login}. ${fallback}`,
  );
  check(
    status.target_url === null,
    `The latest ${context} status on ${commit} (id ${latest.id}) has a target URL; eng/verify.py never sets one. ${fallback}`,
  );
  check(
    typeof status.description === "string" && successDescription.test(status.description),
    `The latest ${context} status on ${commit} (id ${latest.id}) does not have the description eng/verify.py writes for a passed full leg. ${fallback}`,
  );
  return { context, id: latest.id, createdAt: latest.createdAt };
}

/** 1d: the one successful main-push run of ci.yml for the commit. */
function mainPushRun(
  get: Get,
  commit: string,
): { id: number; number: number; attempt: number; repositoryId: number } {
  const listing = object(
    get(
      `${api}/actions/workflows/ci.yml/runs?event=push&branch=main&head_sha=${commit}&exclude_pull_requests=true&per_page=100`,
    ),
    "the main-push runs",
  );
  const runs = list(listing.workflow_runs, "the main-push runs").map((entry) =>
    object(entry, "a main-push run"),
  );
  check(listing.total_count === runs.length, "the main-push runs are not all on one page");
  const matching = runs.filter(
    (run) =>
      run.head_sha === commit &&
      run.event === "push" &&
      run.head_branch === "main" &&
      run.path === workflowPath &&
      object(run.repository, "a run repository").full_name === repository &&
      object(run.head_repository, "a run head repository").full_name === repository,
  );
  check(
    matching.length > 0,
    `No main-push run of ${workflowPath} exists for ${commit}. The proof dispatch deploys only the candidate that the main push built and never builds one; wait for the main push or merge again.`,
  );
  check(
    matching.length === 1,
    `${matching.length} main-push runs exist for ${commit}; the gate does not choose between them.`,
  );
  const run = matching[0] as Json;
  const id = count(run.id, "the main-push run id");
  check(
    run.status === "completed",
    `The main-push run ${id} for ${commit} is ${String(run.status)}; dispatch again after it completed.`,
  );
  check(
    run.conclusion === "success",
    `The main-push run ${id} for ${commit} concluded ${String(run.conclusion)}, not success; its candidate is not deployed. ${fallback}`,
  );
  return {
    id,
    number: count(run.run_number, "the main-push run number"),
    attempt: count(run.run_attempt, "the main-push run attempt"),
    repositoryId: count(object(run.repository, "a run repository").id, "the repository id"),
  };
}

function candidateJob(get: Get, run: { id: number; attempt: number }, commit: string): number {
  const listing = object(
    get(`${api}/actions/runs/${run.id}/jobs?filter=latest&per_page=100`),
    `the jobs of run ${run.id}`,
  );
  const jobs = list(listing.jobs, `the jobs of run ${run.id}`).map((entry) =>
    object(entry, `a job of run ${run.id}`),
  );
  check(listing.total_count === jobs.length, `the jobs of run ${run.id} are not all on one page`);
  const named = jobs.filter((job) => job.name === candidateJobName);
  check(named.length === 1, `run ${run.id} has ${named.length} jobs named ${candidateJobName}`);
  const job = named[0] as Json;
  check(
    job.run_id === run.id && job.head_sha === commit,
    `the candidate job does not belong to run ${run.id} of ${commit}`,
  );
  check(
    job.status === "completed" && job.conclusion === "success",
    `The candidate job of run ${run.id} did not succeed (${String(job.conclusion)}). ${fallback}`,
  );
  const attempt = count(job.run_attempt, "the candidate job attempt");
  check(attempt <= run.attempt, "the candidate job is from a later attempt than its run");
  return attempt;
}

/** The candidate artifact of the main-push run, as the API describes it; shared by both phases. */
export function checkArtifact(
  value: unknown,
  expected: { name: string; runId: number; repositoryId: number; sha: string },
): { id: number; name: string; digest: string; size: number } {
  const artifact = object(value, `the artifact ${expected.name}`);
  check(artifact.name === expected.name, `the artifact is not ${expected.name}`);
  check(
    artifact.expired === false,
    `The candidate artifact ${expected.name} of run ${expected.runId} has expired (30-day retention). Merge again to build a new main-push candidate; the proof dispatch never rebuilds it.`,
  );
  const origin = object(artifact.workflow_run, `the run of ${expected.name}`);
  check(
    origin.id === expected.runId &&
      origin.head_sha === expected.sha &&
      origin.head_branch === "main" &&
      origin.repository_id === expected.repositoryId &&
      origin.head_repository_id === expected.repositoryId,
    `The artifact ${expected.name} was not uploaded by the main-push run ${expected.runId} of ${expected.sha}. ${fallback}`,
  );
  const digest = text(artifact.digest, `the digest of ${expected.name}`);
  check(artifactDigest.test(digest), `the artifact ${expected.name} has no SHA-256 digest`);
  return {
    id: count(artifact.id, `the id of ${expected.name}`),
    name: expected.name,
    digest,
    size: count(artifact.size_in_bytes, `the size of ${expected.name}`),
  };
}

function candidateArtifact(
  get: Get,
  run: { id: number; repositoryId: number },
  attempt: number,
  commit: string,
): GateResult["artifact"] {
  const name = candidateArtifactName(run.id, attempt);
  const listing = object(
    get(`${api}/actions/runs/${run.id}/artifacts?per_page=100`),
    `the artifacts of run ${run.id}`,
  );
  const artifacts = list(listing.artifacts, `the artifacts of run ${run.id}`).map((entry) =>
    object(entry, `an artifact of run ${run.id}`),
  );
  check(
    listing.total_count === artifacts.length,
    `the artifacts of run ${run.id} are not all on one page`,
  );
  const named = artifacts.filter((artifact) => artifact.name === name);
  check(
    named.length === 1,
    `The main-push run ${run.id} holds ${named.length === 0 ? "no" : named.length} artifact ${name}. ${fallback}`,
  );
  return checkArtifact(named[0], {
    name,
    runId: run.id,
    repositoryId: run.repositoryId,
    sha: commit,
  });
}

/** Proves 1a to 1d for the dispatched commit; throws a GateRefusal (or any API error) on any doubt. */
export function evaluateGate(get: Get, dispatched: string): GateResult {
  check(commitSha.test(dispatched), "GITHUB_SHA is not a commit SHA");
  const commit = gitCommit(get, dispatched);
  const origin = mergeOrigin(get, commit);
  const verifiedTree =
    origin.verified === commit.sha ? commit.tree : gitCommit(get, origin.verified).tree;
  check(
    verifiedTree === commit.tree,
    `The tree of ${commit.sha} (${commit.tree}) is not the tree the host legs verified at ${origin.verified} (${verifiedTree}). ${fallback}`,
  );
  const statuses = statusesOf(get, origin.verified);
  const counted = hostContexts.map((context) => countedStatus(statuses, context, origin.verified));
  const run = mainPushRun(get, commit.sha);
  const candidateAttempt = candidateJob(get, run, commit.sha);
  const artifact = candidateArtifact(get, run, candidateAttempt, commit.sha);
  return {
    sha: commit.sha,
    tree: commit.tree,
    verifiedCommit: origin.verified,
    kind: origin.kind,
    pullRequest: origin.pullRequest,
    statuses: counted,
    run: { id: run.id, number: run.number, attempt: run.attempt },
    candidateAttempt,
    artifact,
  };
}

/** The step outputs of the gate job (GITHUB_OUTPUT lines); the deploy job receives exactly these. */
export function gateOutputs(result: GateResult): Record<string, string> {
  return {
    sha: result.sha,
    tree: result.tree,
    "verified-commit": result.verifiedCommit,
    "run-id": String(result.run.id),
    "run-number": String(result.run.number),
    "run-attempt": String(result.run.attempt),
    "candidate-attempt": String(result.candidateAttempt),
    "artifact-id": String(result.artifact.id),
    "artifact-digest": result.artifact.digest,
  };
}

export interface FetchInput {
  sha: string;
  tree: string;
  runId: number;
  runNumber: number;
  runAttempt: number;
  candidateAttempt: number;
  artifactId: number;
  artifactDigest: string;
}

const positive = /^[1-9][0-9]{0,15}$/u;

/** The deploy job's view of the gate: the outputs it was handed, each checked for shape. */
export function fetchInput(environment: Record<string, string | undefined>): FetchInput {
  const number = (name: string) => {
    const value = environment[name] ?? "";
    check(positive.test(value), `${name} is not set by the gate job`);
    return Number(value);
  };
  const tree = environment.PROOF_GATE_TREE ?? "";
  check(commitSha.test(tree), "PROOF_GATE_TREE is not set by the gate job");
  const digest = environment.PROOF_GATE_ARTIFACT_DIGEST ?? "";
  check(artifactDigest.test(digest), "PROOF_GATE_ARTIFACT_DIGEST is not set by the gate job");
  const input = {
    sha: sha(environment.GITHUB_SHA, "GITHUB_SHA"),
    tree,
    runId: number("ARCFORGES_CANDIDATE_RUN_ID"),
    runNumber: number("ARCFORGES_CANDIDATE_RUN_NUMBER"),
    runAttempt: number("ARCFORGES_CANDIDATE_RUN_ATTEMPT"),
    candidateAttempt: number("PROOF_GATE_CANDIDATE_ATTEMPT"),
    artifactId: number("PROOF_GATE_ARTIFACT_ID"),
    artifactDigest: digest,
  };
  check(
    input.candidateAttempt <= input.runAttempt,
    "the candidate attempt is later than its run's",
  );
  return input;
}

/** A flat archive of plain file names; anything with a directory, a dot name or a repeat is refused before extraction. */
export function checkEntries(entries: string[]): string[] {
  const seen = new Set<string>();
  for (const entry of entries) {
    check(
      /^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/u.test(entry),
      `the candidate archive holds an entry that is not a plain file name`,
    );
    check(!seen.has(entry), "the candidate archive holds an entry twice");
    seen.add(entry);
  }
  check(seen.has("manifest.json"), "the candidate archive holds no manifest.json");
  return [...seen].sort();
}

function readJsonFile(directory: string, name: string): Json {
  let parsed: unknown;
  try {
    parsed = JSON.parse(readFileSync(path.join(directory, name), "utf8"));
  } catch {
    refuse(`the candidate's ${name} is missing or not JSON`);
  }
  return object(parsed, `the candidate's ${name}`);
}

function fileSha256(file: string): string {
  return createHash("sha256").update(readFileSync(file)).digest("hex");
}

/**
 * The sealed manifest names exactly the dispatched commit, the main-push run and its version: manifest.json (revision, clean, version,
 * the file digests of every member), build-identity.json (the source commit and the producing run) and image-provenance.json (the
 * revision and the image of the manifest). Every member is a regular file. The tree is the commit's (checked against the checkout).
 */
export function checkSealedCandidate(directory: string, input: FetchInput): { version: string } {
  const entries = readdirSync(directory).sort();
  for (const entry of entries)
    check(
      lstatSync(path.join(directory, entry)).isFile(),
      `the candidate member ${entry} is not a regular file`,
    );
  const manifest = readJsonFile(directory, "manifest.json");
  check(manifest.schema === 1, "the candidate manifest has another schema");
  check(
    manifest.revision === input.sha && manifest.dirty === false,
    `The candidate manifest does not name the clean commit ${input.sha}. ${fallback}`,
  );
  const version = `0.1.0-ci.${input.runNumber}.${input.candidateAttempt}`;
  check(
    manifest.version === version,
    `The candidate manifest's version is not ${version} (the main-push run ${input.runId}). ${fallback}`,
  );
  const files = object(manifest.files, "the candidate manifest's files");
  check(
    JSON.stringify([...Object.keys(files), "manifest.json"].sort()) === JSON.stringify(entries),
    "the candidate members are not exactly the manifest's files",
  );
  for (const [name, digest] of Object.entries(files))
    check(
      digest === fileSha256(path.join(directory, name)),
      `the candidate member ${name} does not match its manifest digest`,
    );
  const identity = readJsonFile(directory, "build-identity.json");
  const build = object(identity.build, "the candidate's build identity");
  check(
    build.sourceCommit === input.sha &&
      build.dirty === false &&
      build.kind === "ci" &&
      build.runId === String(input.runId) &&
      build.runAttempt === input.candidateAttempt &&
      build.buildId === `${input.runId}.${input.candidateAttempt}` &&
      build.pipelineRun === `https://github.com/${repository}/actions/runs/${input.runId}`,
    `The candidate's build identity does not name ${input.sha} built by the main-push run ${input.runId}. ${fallback}`,
  );
  check(
    object(identity.artifact, "the candidate's artifact identity").version === version,
    "the candidate's build identity names another version",
  );
  const image = readJsonFile(directory, "image-provenance.json");
  check(
    image.revision === input.sha && image.imageId === manifest.imageId,
    `The candidate's image provenance does not name ${input.sha} and the manifest's image. ${fallback}`,
  );
  return { version };
}

/** The checkout the deploy job runs from is the dispatched commit with the gate's tree. */
export function checkCheckout(head: string, headTree: string, input: FetchInput): void {
  check(head === input.sha, `the checkout is ${head}, not the dispatched ${input.sha}`);
  check(
    headTree === input.tree,
    `the checkout's tree ${headTree} is not the tree ${input.tree} the gate proved`,
  );
}

export interface FetchPorts {
  get: Get;
  /** Writes the artifact archive (GET actions/artifacts/<id>/zip) to the file. */
  download: (artifactId: number, file: string) => void;
  /** The entry names of a zip archive. */
  entries: (file: string) => string[];
  /** Extracts a zip archive into an empty directory. */
  extract: (file: string, directory: string) => void;
  head: () => { sha: string; tree: string };
}

/** The deploy job's phase: re-read, download, digest-check, unpack and check the gated artifact; returns the candidate version. */
export function fetchCandidate(
  ports: FetchPorts,
  input: FetchInput,
  root: string,
): { version: string } {
  const head = ports.head();
  checkCheckout(head.sha, head.tree, input);
  const name = candidateArtifactName(input.runId, input.candidateAttempt);
  const run = object(ports.get(`${api}/actions/runs/${input.runId}`), `run ${input.runId}`);
  const runRepository = object(run.repository, "the run repository");
  check(
    run.id === input.runId &&
      run.head_sha === input.sha &&
      run.event === "push" &&
      run.head_branch === "main" &&
      run.path === workflowPath &&
      run.status === "completed" &&
      run.conclusion === "success" &&
      run.run_number === input.runNumber &&
      runRepository.full_name === repository,
    `run ${input.runId} is not the successful main push of ${input.sha} that the gate found`,
  );
  const repositoryId = count(runRepository.id, "the repository id");
  const artifact = checkArtifact(ports.get(`${api}/actions/artifacts/${input.artifactId}`), {
    name,
    runId: input.runId,
    repositoryId,
    sha: input.sha,
  });
  check(
    artifact.id === input.artifactId && artifact.digest === input.artifactDigest,
    "the artifact's ID or digest changed since the gate read it",
  );
  const archive = path.join(root, "artifacts", `${name}.zip`);
  const directory = path.join(root, "artifacts", "candidate");
  check(
    !existsSync(directory),
    "artifacts/candidate exists before the gated candidate was fetched",
  );
  mkdirSync(path.dirname(archive), { recursive: true });
  try {
    ports.download(input.artifactId, archive);
    const digest = `sha256:${fileSha256(archive)}`;
    check(
      digest === input.artifactDigest,
      `The downloaded ${name} has the digest ${digest}, not the API's ${input.artifactDigest}. ${fallback}`,
    );
    checkEntries(ports.entries(archive));
    mkdirSync(directory);
    ports.extract(archive, directory);
  } finally {
    rmSync(archive, { force: true });
  }
  return checkSealedCandidate(directory, input);
}

// The runner side: gh (preinstalled on GitHub-hosted runners, authenticated by GH_TOKEN), unzip and git.
function gh(endpoint: string): unknown {
  return JSON.parse(
    execFileSync(
      "gh",
      ["api", "--hostname", "github.com", "-H", "X-GitHub-Api-Version: 2022-11-28", endpoint],
      {
        encoding: "utf8",
        maxBuffer: 64 * 1024 * 1024,
        timeout: 60_000,
        stdio: ["ignore", "pipe", "pipe"],
      },
    ),
  );
}

function ghDownload(artifactId: number, file: string): void {
  const descriptor = openSync(file, "wx", 0o600);
  try {
    const result = spawnSync(
      "gh",
      ["api", "--hostname", "github.com", `${api}/actions/artifacts/${artifactId}/zip`],
      { stdio: ["ignore", descriptor, "pipe"], timeout: 300_000 },
    );
    check(result.status === 0, `the download of artifact ${artifactId} failed`);
  } finally {
    closeSync(descriptor);
  }
}

function unzipEntries(file: string): string[] {
  return execFileSync("unzip", ["-Z1", file], { encoding: "utf8", timeout: 60_000 })
    .split("\n")
    .filter((line) => line !== "");
}

function unzipInto(file: string, directory: string): void {
  execFileSync("unzip", ["-q", "-n", file, "-d", directory], {
    stdio: "inherit",
    timeout: 300_000,
  });
}

function gitHead(root: string): { sha: string; tree: string } {
  const git = (...args: string[]) =>
    execFileSync("git", args, { cwd: root, encoding: "utf8", timeout: 30_000 }).trim();
  return { sha: git("rev-parse", "HEAD"), tree: git("rev-parse", "HEAD^{tree}") };
}

/** The dispatch context both phases require: CI, this repository, a manual dispatch on main. */
export function requireDispatch(environment: Record<string, string | undefined>): string {
  check(environment.GITHUB_ACTIONS === "true", "The proof gate runs in GitHub Actions only.");
  check(environment.GITHUB_REPOSITORY === repository, `The proof gate runs in ${repository} only.`);
  check(
    environment.GITHUB_EVENT_NAME === "workflow_dispatch",
    "The proof gate runs on a manual dispatch only.",
  );
  check(environment.GITHUB_REF === "refs/heads/main", "Only main may touch the proof environment.");
  return sha(environment.GITHUB_SHA, "GITHUB_SHA");
}

export function main(
  phase: string,
  environment: Record<string, string | undefined> = process.env,
): void {
  const dispatched = requireDispatch(environment);
  const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../..");
  if (phase === "gate") {
    const result = evaluateGate(gh, dispatched);
    console.log(
      `Proof gate: ${result.sha} (tree ${result.tree}) is the head of main, a ${result.kind}${
        result.pullRequest === null ? "" : ` of PR #${result.pullRequest}`
      }; the host legs verified ${result.verifiedCommit} with the same tree.`,
    );
    for (const status of result.statuses)
      console.log(
        `  ${status.context}: success by ${trustedPoster.login}, status ${status.id} at ${status.createdAt} (the latest of its context)`,
      );
    console.log(
      `  main-push run ${result.run.id} (#${result.run.number}, attempt ${result.run.attempt}) succeeded; candidate ${result.artifact.name} (artifact ${result.artifact.id}, ${result.artifact.digest}, ${result.artifact.size} bytes).`,
    );
    const output = environment.GITHUB_OUTPUT ?? "";
    check(output !== "", "GITHUB_OUTPUT is not set");
    appendFileSync(
      output,
      Object.entries(gateOutputs(result))
        .map(([key, value]) => `${key}=${value}\n`)
        .join(""),
    );
    return;
  }
  if (phase === "fetch") {
    const input = fetchInput(environment);
    check(input.sha === dispatched, "the gate's commit is not this run's");
    const { version } = fetchCandidate(
      {
        get: gh,
        download: ghDownload,
        entries: unzipEntries,
        extract: unzipInto,
        head: () => gitHead(root),
      },
      input,
      root,
    );
    console.log(
      `Proof candidate: ${version} of ${input.sha} from the main-push run ${input.runId}, artifact ${input.artifactId} (${input.artifactDigest}) verified and unpacked into artifacts/candidate.`,
    );
    return;
  }
  refuse("Use gate or fetch.");
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  try {
    main(process.argv[2] ?? "");
  } catch (error) {
    console.error(`Proof gate refused: ${error instanceof Error ? error.message : String(error)}`);
    process.exitCode = 1;
  }
}
