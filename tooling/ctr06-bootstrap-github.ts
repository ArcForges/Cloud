// SPDX-License-Identifier: AGPL-3.0-only
// Public GitHub metadata checks only. They do not prove authority coverage, a lease or publication.
import assert from "node:assert/strict";
import { countedStatus, hostContexts, maxStatusPages } from "../eng/verification/proof-gate.ts";
import type { ApprovedBootstrap, AttemptTarget } from "./ctr06-bootstrap-registry.ts";
import { object, parseDocument } from "./provenance.ts";

const api = "https://api.github.com/repos/ArcForges/Cloud";
const repositoryId = 1372264358;
const positive = /^[1-9][0-9]{0,14}$/u;
const hex40 = /^[a-f0-9]{40}$/u;
const expectedJobs = [
  "Require authenticated bootstrap authority evidence",
  "Construct security bridge (Linux)",
  "Construct security bridge (Windows)",
  "Verify and seal the same-run bridge carrier",
];
export type GithubGet = (path: string) => Promise<unknown>;
function number(value: unknown): number {
  assert(
    typeof value === "number" && Number.isSafeInteger(value) && value > 0,
    "Invalid GitHub numeric identity",
  );
  return value;
}
function validId(value: string): void {
  assert(positive.test(value) && Number.isSafeInteger(Number(value)), "Invalid GitHub identifier");
}

/** Fixed public endpoint with bounded response and timeout. It never supplies or reads a token. */
async function getPublic(pathname: string): Promise<unknown> {
  assert(
    /^\/(?:actions\/runs\/[0-9]+\/attempts\/[0-9]+(?:\/jobs\?per_page=100&page=[0-9]+)?|actions\/artifacts\/[0-9]+|git\/commits\/[a-f0-9]{40}|pulls\/155|releases\/tags\/(?:ctr06-security-bridge-cloud-0\.1\.0-ci\.[0-9]+\.[0-9]+|cloud-0\.1\.0-ci\.615\.1)|releases\/[0-9]+\/assets\?per_page=100&page=1|git\/ref\/tags\/(?:ctr06-security-bridge-cloud-0\.1\.0-ci\.[0-9]+\.[0-9]+|cloud-0\.1\.0-ci\.615\.1)|git\/tags\/[a-f0-9]{40}|git\/ref\/heads\/main|compare\/[a-f0-9]{40}\.\.\.[a-f0-9]{40}|commits\/[a-f0-9]{40}\/statuses\?per_page=100&page=[0-9]+)$/u.test(
      pathname,
    ),
    "Unsupported public GitHub path",
  );
  const response = await fetch(api + pathname, {
    redirect: "error",
    signal: AbortSignal.timeout(15_000),
    headers: {
      accept: "application/vnd.github+json",
      "user-agent": "arcforges-ctr06-readonly",
      "x-github-api-version": "2022-11-28",
    },
  });
  if (response.status === 404 && pathname.startsWith("/releases/tags/")) return null;
  assert(response.ok && response.body, "Public GitHub metadata unavailable");
  const length = response.headers.get("content-length");
  if (length !== null) assert(/^[0-9]+$/u.test(length) && Number(length) <= 4 * 1024 * 1024);
  const reader = response.body.getReader();
  const parts: Buffer[] = [];
  let size = 0;
  try {
    for (;;) {
      const result = await reader.read();
      if (result.done) break;
      size += result.value.byteLength;
      assert(size <= 4 * 1024 * 1024, "GitHub response exceeds limit");
      parts.push(Buffer.from(result.value));
    }
  } finally {
    await reader.cancel().catch(() => undefined);
  }
  return parseDocument(Buffer.concat(parts));
}

/** Read and validate public run/job/artifact/PR/host-status metadata. This is not independent review or gate-proof authority. */
export async function inspectGithubBootstrapMetadata(
  get: GithubGet,
  target: AttemptTarget,
  approval: ApprovedBootstrap,
) {
  for (const id of [target.run, target.runNumber, target.attempt, target.artifactId]) validId(id);
  assert(
    hex40.test(target.producer) &&
      hex40.test(approval.approvedHead) &&
      hex40.test(approval.approvedTree),
  );
  assert.equal(target.producer, approval.merge);
  const run = object(await get(`/actions/runs/${target.run}/attempts/${target.attempt}`));
  assert.equal(number(run.id), Number(target.run));
  assert.equal(number(run.run_number), Number(target.runNumber));
  assert.equal(number(run.run_attempt), Number(target.attempt));
  assert.equal(run.event, "push");
  assert.equal(run.path, ".github/workflows/ci.yml");
  assert.equal(run.head_sha, target.producer);
  assert.equal(run.head_branch, "main");
  assert.equal(number(object(run.repository).id), repositoryId);
  assert.equal(number(object(run.head_repository).id), repositoryId);
  assert(
    run.status === "in_progress" || (run.status === "completed" && run.conclusion === "success"),
    "Bootstrap run not eligible",
  );
  const allJobs: Record<string, unknown>[] = [];
  let total: number | undefined;
  for (let page = 1; page <= 10; page++) {
    const response = object(
      await get(
        `/actions/runs/${target.run}/attempts/${target.attempt}/jobs?per_page=100&page=${page}`,
      ),
    );
    assert(
      typeof response.total_count === "number" &&
        Number.isSafeInteger(response.total_count) &&
        response.total_count >= 0 &&
        response.total_count <= 1000,
    );
    if (total === undefined) total = response.total_count;
    assert.equal(response.total_count, total, "Job page total changed");
    assert(Array.isArray(response.jobs) && response.jobs.length <= 100);
    allJobs.push(...response.jobs.map((item) => object(item)));
    if (allJobs.length >= total) break;
    assert.equal(response.jobs.length, 100, "Job page incomplete");
  }
  assert.equal(allJobs.length, total, "Incomplete job pages");
  const ids = new Set<number>();
  const matched = new Map<string, number>();
  let gateCompletedAt: number | undefined;
  for (const job of allJobs) {
    const id = number(job.id);
    assert(!ids.has(id), "Duplicate job ID");
    ids.add(id);
    if (typeof job.name !== "string" || !expectedJobs.includes(job.name)) continue;
    assert(!matched.has(job.name), "Duplicate required job");
    assert.equal(number(job.run_id), Number(target.run));
    assert.equal(number(job.run_attempt), Number(target.attempt));
    assert.equal(job.head_sha, target.producer);
    assert.equal(job.status, "completed");
    assert.equal(job.conclusion, "success");
    matched.set(job.name, id);
    if (job.name === expectedJobs[0]) {
      assert(
        typeof job.completed_at === "string" && !Number.isNaN(Date.parse(job.completed_at)),
        "Gate completion time unavailable",
      );
      gateCompletedAt = Math.floor(Date.parse(job.completed_at) / 1000);
    }
  }
  assert.equal(matched.size, expectedJobs.length, "Required gate, build or seal job is missing");
  assert(
    gateCompletedAt !== undefined && gateCompletedAt <= Math.floor(Date.now() / 1000) + 30,
    "Invalid gate completion time",
  );
  const artifact = object(await get(`/actions/artifacts/${target.artifactId}`));
  assert.equal(number(artifact.id), Number(target.artifactId));
  assert.equal(artifact.name, `ctr06-security-sealed-${target.run}-${target.attempt}`);
  assert.equal(artifact.expired, false);
  assert.equal(artifact.digest, `sha256:${target.artifactApiDigest}`);
  const zipSize = number(artifact.size_in_bytes);
  assert(zipSize <= 1024 * 1024 * 1024);
  const origin = object(artifact.workflow_run);
  assert.equal(number(origin.id), Number(target.run));
  assert.equal(number(origin.repository_id), repositoryId);
  assert.equal(number(origin.head_repository_id), repositoryId);
  assert.equal(origin.head_sha, target.producer);
  assert.equal(origin.head_branch, "main");
  const pull = object(await get("/pulls/155"));
  assert.equal(number(pull.number), 155);
  assert.equal(pull.state, "closed");
  assert(typeof pull.merged_at === "string" && !Number.isNaN(Date.parse(pull.merged_at)));
  assert.equal(pull.merged, true, "Pull request is not merged");
  assert.equal(pull.merge_commit_sha, approval.merge);
  const head = object(pull.head);
  assert.equal(head.sha, approval.approvedHead);
  assert.equal(number(object(head.repo).id), repositoryId);
  const base = object(pull.base);
  assert.equal(base.ref, "main");
  assert.equal(number(object(base.repo).id), repositoryId);
  const commit = object(await get(`/git/commits/${target.producer}`));
  assert.equal(commit.sha, target.producer);
  assert.equal(object(commit.tree).sha, approval.approvedTree);
  assert(
    Array.isArray(commit.parents) &&
      commit.parents.length === 2 &&
      object(commit.parents[1]).sha === approval.approvedHead,
    "Merge parent differs",
  );
  const mainRef = object(await get("/git/ref/heads/main"));
  assert.equal(mainRef.ref, "refs/heads/main");
  const mainSha = object(mainRef.object).sha;
  assert(typeof mainSha === "string" && hex40.test(mainSha));
  if (mainSha !== target.producer) {
    const comparison = object(await get(`/compare/${target.producer}...${mainSha}`));
    assert.equal(comparison.status, "ahead", "Reviewed merge is not an ancestor of current main");
    assert.equal(object(comparison.merge_base_commit).sha, target.producer);
  }
  const statuses: Record<string, unknown>[] = [];
  for (let page = 1; page <= maxStatusPages; page++) {
    const result = await get(
      `/commits/${approval.approvedHead}/statuses?per_page=100&page=${page}`,
    );
    assert(Array.isArray(result) && result.length <= 100);
    statuses.push(...result.map((value) => object(value)));
    if (result.length < 100) break;
    assert(page < maxStatusPages, "Host statuses exceed read bound");
  }
  const checkedStatuses = hostContexts.map((context) =>
    countedStatus(statuses, context, approval.approvedHead),
  );
  return {
    run: target.run,
    attempt: target.attempt,
    artifactId: target.artifactId,
    artifactZipDigest: target.artifactApiDigest,
    artifactZipSize: zipSize,
    jobs: Object.fromEntries(matched),
    gateCompletedAt,
    statuses: checkedStatuses,
  };
}

/** Live public-read adapter. Other authority domains and gate-proof storage are not provided here. */
export function readPublicGithubBootstrap(target: AttemptTarget, approval: ApprovedBootstrap) {
  return inspectGithubBootstrapMetadata(getPublic, target, approval);
}

async function checkedReleaseAssets(
  get: GithubGet,
  tag: string,
  commit: string,
  data: Record<string, unknown>,
) {
  assert.equal(data.tag_name, tag);
  assert.equal(data.target_commitish, commit);
  assert.equal(data.draft, false);
  assert.equal(data.prerelease, true);
  assert(typeof data.published_at === "string" && !Number.isNaN(Date.parse(data.published_at)));
  const releaseId = String(number(data.id));
  const ref = object(await get(`/git/ref/tags/${tag}`));
  assert.equal(ref.ref, `refs/tags/${tag}`);
  const pointer = object(ref.object);
  assert(typeof pointer.sha === "string" && hex40.test(pointer.sha));
  if (pointer.type === "commit")
    assert.equal(pointer.sha, commit, "Release tag points to another commit");
  else {
    assert.equal(pointer.type, "tag", "Unsupported release tag object");
    const annotated = object(await get(`/git/tags/${pointer.sha}`));
    assert.equal(annotated.sha, pointer.sha);
    assert.equal(annotated.tag, tag);
    const destination = object(annotated.object);
    assert.equal(destination.type, "commit");
    assert.equal(destination.sha, commit, "Annotated release tag points to another commit");
  }
  assert(
    Array.isArray(data.assets) && data.assets.length === 2,
    "Published asset set is incomplete or ambiguous",
  );
  const listing = await get(`/releases/${releaseId}/assets?per_page=100&page=1`);
  assert(
    Array.isArray(listing) && listing.length === 2,
    "Published asset listing is incomplete or ambiguous",
  );
  const assets = listing.map((value) => object(value));
  const advertised = data.assets.map((value) => object(value));
  const ids = new Set<number>();
  for (const item of assets) {
    const id = number(item.id);
    assert(!ids.has(id));
    ids.add(id);
    const other = advertised.find((value) => value.id === id);
    assert(other);
    for (const key of ["name", "state", "digest", "size"] as const)
      assert.equal(item[key], other[key], "Asset listing differs from release metadata");
  }
  return { releaseId, assets };
}

/** A public 404 cannot exclude drafts, private visibility or an in-flight publication. */
export async function inspectGithubPublishedRelease(get: GithubGet, target: AttemptTarget) {
  for (const id of [target.run, target.runNumber, target.attempt, target.artifactId]) validId(id);
  const tag = `ctr06-security-bridge-cloud-0.1.0-ci.${target.runNumber}.${target.attempt}`;
  assert.equal(target.release, tag);
  const raw = await get(`/releases/tags/${tag}`);
  const observedAt = Math.floor(Date.now() / 1000);
  if (raw === null)
    return {
      state: "unknown",
      observedAt,
      tag: null,
      merge: null,
      artifactDigest: null,
      artifactSize: null,
      receiptDigest: null,
      receiptSize: null,
      run: null,
      runNumber: null,
      attempt: null,
      sourceArtifactId: null,
      releaseId: null,
      assetId: null,
      receiptAssetId: null,
    };
  const data = object(raw);
  const { releaseId, assets } = await checkedReleaseAssets(get, tag, target.producer, data);
  const carrierName = `arcforges-ctr06-security-bridge-0.1.0-ci.${target.runNumber}.${target.attempt}.tar.gz`;
  const carrier = assets.find((item) => item.name === carrierName);
  const receipt = assets.find((item) => item.name === "bootstrap-receipt.json");
  assert(carrier && receipt);
  const assetId = String(number(carrier.id));
  const receiptAssetId = String(number(receipt.id));
  assert.notEqual(assetId, receiptAssetId);
  assert.equal(carrier.state, "uploaded");
  assert.equal(receipt.state, "uploaded");
  assert.equal(carrier.digest, `sha256:${target.artifactDigest}`);
  assert.equal(number(carrier.size), Number(target.artifactSize));
  assert.equal(receipt.digest, `sha256:${target.receiptDigest}`);
  assert.equal(number(receipt.size), Number(target.receiptSize));
  return {
    state: "present",
    observedAt,
    tag,
    merge: target.producer,
    artifactDigest: target.artifactDigest,
    artifactSize: Number(target.artifactSize),
    receiptDigest: target.receiptDigest,
    receiptSize: Number(target.receiptSize),
    run: target.run,
    runNumber: target.runNumber,
    attempt: target.attempt,
    sourceArtifactId: target.artifactId,
    releaseId,
    assetId,
    receiptAssetId,
  };
}

export function readPublicGithubPublishedRelease(target: AttemptTarget) {
  return inspectGithubPublishedRelease(getPublic, target);
}

/** Historical metadata verification only. This does not authorize execution of the retired 615 bridge. */
export async function inspectHistorical615Metadata(get: GithubGet) {
  const tag = "cloud-0.1.0-ci.615.1";
  const commit = "8e5f6e26aa97b123d9f60b91f780364a094e74cd";
  const data = object(await get(`/releases/tags/${tag}`));
  const { releaseId, assets } = await checkedReleaseAssets(get, tag, commit, data);
  assert.equal(releaseId, "440439135");
  const carrier = assets.find((item) => item.name === "cloud-0.1.0-ci.615.1.tar.gz");
  const evidence = assets.find((item) => item.name === "deployment.json");
  assert(carrier && evidence);
  assert.equal(number(carrier.id), 731653316);
  assert.equal(carrier.state, "uploaded");
  assert.equal(carrier.size, 80057627);
  assert.equal(
    carrier.digest,
    "sha256:d9c52a13c54b073758866c9e02168cc1e527cca92257df259e97298a5aa2a466",
  );
  assert.equal(number(evidence.id), 731653317);
  assert.equal(evidence.state, "uploaded");
  assert.equal(evidence.size, 483);
  assert.equal(
    evidence.digest,
    "sha256:2ac2d246e91d9a060d66471d089cddbbb54d3da7e171840978cfc3058d6956e0",
  );
  return {
    historicalOnly: true,
    tag,
    commit,
    releaseId,
    carrierAssetId: String(carrier.id),
    evidenceAssetId: String(evidence.id),
  };
}
export function readPublicHistorical615Metadata() {
  return inspectHistorical615Metadata(getPublic);
}
