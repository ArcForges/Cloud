// SPDX-License-Identifier: AGPL-3.0-only
// Shared broker state machine. Production requires a source-reviewed profile; tests inject isolated external ports.
import assert from "node:assert/strict";
import { createHash, randomBytes } from "node:crypto";
import type { BootstrapJournal } from "./ctr06-bootstrap-journal.ts";
import { inspectGateProof } from "./ctr06-bootstrap-gate.ts";
import { inspectBootstrapZip } from "./ctr06-bootstrap-zip.ts";
import {
  inspectGithubBootstrapMetadata,
  readPublicGithubBootstrap,
  readPublicGithubPublishedRelease,
  type GithubGet,
} from "./ctr06-bootstrap-github.ts";
import {
  verifyCollectorIdentity,
  verifyCollectorIdentityWithKeys,
  type CollectorIdentity,
} from "./ctr06-bootstrap-oidc.ts";
import {
  requireReviewedAuthorityProfile,
  type ReviewedAuthorityProfile,
} from "./ctr06-bootstrap-profile.ts";
import { checkObservedPageChain, evaluateObservedAuthority } from "./ctr06-bootstrap-policy.ts";
import {
  assessObservedReconciliation,
  type ExpectedRelease,
  type PublishedRelease,
} from "./ctr06-bootstrap-reconcile.ts";
import {
  BootstrapRegistry,
  replayBootstrap,
  type ApprovedBootstrap,
  type AttemptTarget,
} from "./ctr06-bootstrap-registry.ts";
import { object, parseDocument } from "./provenance.ts";

const sha = (value: Buffer | string) => createHash("sha256").update(value).digest("hex");
const identifier = /^[A-Za-z0-9._:-]{1,128}$/u;
type Phase = "association" | "issue" | "use";
type Lease = { id: string; revision: string; holder: string; start: number; end: number };
export type CollectorObservation = { payload: Buffer; token: string };
type Capability = { id: string; targetDigest: string; value: Buffer };

/** A production implementation must be selected by reviewed source and independently validate its
 * authoritative coverage and actual enforcement; self-reported fields are not evidence of either. */
export interface BrokerPorts {
  reviewedApproval(): Promise<ApprovedBootstrap>;
  readGate(target: AttemptTarget): Promise<CollectorObservation>;
  verifyGateReadback(
    proof: CollectorObservation,
    target: AttemptTarget,
    jobId: number,
  ): Promise<void>;
  observe(target: AttemptTarget, phase: Phase, challenge: string): Promise<CollectorObservation>;
  openArtifact(target: AttemptTarget): Promise<{
    artifactId: string;
    producer: string;
    run: string;
    attempt: string;
    bytes: AsyncIterable<Uint8Array>;
  }>;
  verifyCoverage(payload: Buffer, lease: Lease, target: AttemptTarget): Promise<void>;
  verifyLease(lease: Lease, target: AttemptTarget): Promise<void>;
  issue(target: AttemptTarget, issueId: string, lease: Lease): Promise<Capability>;
  publish(
    target: AttemptTarget,
    issueId: string,
    capability: Buffer,
    lease: Lease,
    verifiedArtifact: Buffer,
  ): Promise<void>;
  revoke(issueId: string): Promise<void>;
  history(target: AttemptTarget, issueIds: string[]): Promise<unknown>;
}

export function brokerTargetDigest(target: AttemptTarget): string {
  return sha(
    `arcforges:ctr06:broker-target:v1\0${JSON.stringify({
      run: target.run,
      runNumber: target.runNumber,
      attempt: target.attempt,
      producer: target.producer,
      eventDigest: target.eventDigest,
      gateDigest: target.gateDigest,
      gateChallenge: target.gateChallenge,
      artifactId: target.artifactId,
      artifactDigest: target.artifactDigest,
      artifactApiDigest: target.artifactApiDigest,
      receiptDigest: target.receiptDigest,
      receiptSize: target.receiptSize,
      artifactSize: target.artifactSize,
      release: target.release,
    })}`,
  );
}
function targetFromFields(f: Record<string, string>): AttemptTarget {
  return {
    run: f.run as string,
    runNumber: f.runNumber as string,
    attempt: f.attempt as string,
    producer: f.producer as string,
    eventDigest: f.eventDigest as string,
    gateDigest: f.gateDigest as string,
    gateChallenge: f.gateChallenge as string,
    artifactId: f.artifactId as string,
    artifactDigest: f.artifactDigest as string,
    artifactApiDigest: f.artifactApiDigest as string,
    receiptDigest: f.receiptDigest as string,
    receiptSize: f.receiptSize as string,
    artifactSize: f.artifactSize as string,
    release: f.release as string,
  };
}
function release(target: AttemptTarget): ExpectedRelease {
  return {
    tag: target.release,
    merge: target.producer,
    artifactDigest: target.artifactDigest,
    artifactSize: Number(target.artifactSize),
    receiptDigest: target.receiptDigest,
    receiptSize: Number(target.receiptSize),
    run: target.run,
    runNumber: target.runNumber,
    attempt: target.attempt,
    sourceArtifactId: target.artifactId,
  };
}
function time(value: unknown): number {
  assert(
    typeof value === "number" && Number.isSafeInteger(value) && value >= 0,
    "Invalid observation time",
  );
  return value;
}
function text(value: unknown): string {
  assert(typeof value === "string" && identifier.test(value), "Invalid observation identifier");
  return value;
}

async function verifyCollector(
  profile: BrokerTrustProfile,
  proof: CollectorObservation,
  target: AttemptTarget,
  at: number,
): Promise<void> {
  if (profile.kind === "github-oidc") {
    const identity = await profile.collectorRun(proof, target);
    assert.equal(
      identity.sourceSha,
      profile.collectorSourceSha,
      "Collector source differs from reviewed profile",
    );
    await verifyCollectorIdentity(proof.payload, proof.token, identity, at);
  } else {
    verifyCollectorIdentityWithKeys(
      proof.payload,
      proof.token,
      profile.collector,
      at,
      profile.softwareJwks,
    );
  }
}

async function checkedObservation(
  boundary: BrokerPorts,
  profile: BrokerTrustProfile,
  approval: ApprovedBootstrap,
  target: AttemptTarget,
  phase: Phase,
): Promise<{ lease: Lease; digest: string }> {
  const challenge = randomBytes(32).toString("hex");
  const observation = await boundary.observe(target, phase, challenge);
  assert(observation.payload.length > 0 && observation.payload.length <= 1024 * 1024);
  const now = Math.floor(Date.now() / 1000);
  await verifyCollector(profile, observation, target, now);
  const data = object(
    parseDocument(observation.payload),
    "schema phase challenge targetDigest producer eventDigest originalRun lease sources authority",
  );
  assert.equal(data.schema, "arcforges.ctr06.bootstrap-authority.v1");
  assert.equal(data.phase, phase);
  assert.equal(data.challenge, challenge, "Observation challenge differs");
  assert.equal(data.targetDigest, brokerTargetDigest(target), "Observation target differs");
  assert.equal(data.producer, approval.merge);
  assert.equal(data.eventDigest, approval.eventDigest);
  assert.equal(data.originalRun, approval.originalRun);
  const rawLease = object(data.lease, "id revision holder start end");
  const lease: Lease = {
    id: text(rawLease.id),
    revision: text(rawLease.revision),
    holder: text(rawLease.holder),
    start: time(rawLease.start),
    end: time(rawLease.end),
  };
  assert(
    lease.start <= now && now < lease.end && lease.end - lease.start <= 300,
    "Lease outside interval",
  );
  assert.equal(lease.holder, `${target.run}:${target.attempt}`, "Wrong lease holder");
  const domains = profile.requiredDomains;
  assert(
    domains.length > 0 &&
      new Set(domains).size === domains.length &&
      domains.every((value) => identifier.test(value)),
    "Invalid reviewed source scope",
  );
  assert(
    Array.isArray(data.sources) && data.sources.length === domains.length,
    "Incomplete source domains",
  );
  const seen = new Set<string>();
  for (const raw of data.sources) {
    const source = object(raw, "domain revision pages");
    const domain = text(source.domain);
    assert(domains.includes(domain) && !seen.has(domain), "Unknown or duplicate source domain");
    seen.add(domain);
    assert.equal(source.revision, lease.revision, "Lease/source revision differs");
    assert.equal(checkObservedPageChain(source.pages).revision, lease.revision);
  }
  evaluateObservedAuthority(data.authority);
  await boundary.verifyCoverage(observation.payload, lease, target);
  await boundary.verifyLease(lease, target);
  assert(Math.floor(Date.now() / 1000) < lease.end, "Lease expired during verification");
  return { lease, digest: sha(observation.payload) };
}

/**
 * Runs the same parsing, RS256 verification, decisions and durable transitions for reviewed live
 * ports and isolated test ports. A signature or graph alone cannot establish source completeness.
 */
async function runBrokerEngine(
  journal: BootstrapJournal,
  target: AttemptTarget,
  boundary: BrokerPorts,
  profile: BrokerTrustProfile,
  signal?: AbortSignal,
): Promise<PublishedRelease> {
  signal?.throwIfAborted();
  const registry = new BootstrapRegistry(journal);
  const approval = await boundary.reviewedApproval();
  const github =
    profile.kind === "github-oidc"
      ? await readPublicGithubBootstrap(target, approval)
      : await inspectGithubBootstrapMetadata(profile.githubGet(target), target, approval);
  const gateJob = github.jobs["Require authenticated bootstrap authority evidence"];
  assert(typeof gateJob === "number" && github.gateCompletedAt !== undefined);
  const gate = await boundary.readGate(target);
  const checkedGate = await inspectGateProof(
    {
      producer: target.producer,
      run: target.run,
      runNumber: target.runNumber,
      attempt: target.attempt,
      originalRun: approval.originalRun,
      eventDigest: target.eventDigest,
      challenge: target.gateChallenge,
    },
    gate,
    github.gateCompletedAt,
    profile.requiredDomains,
    (proof, at) => verifyCollector(profile, proof, target, at),
  );
  assert.equal(checkedGate.digest, target.gateDigest, "Gate proof digest differs");
  await boundary.verifyGateReadback(gate, target, gateJob);
  let admission = registry.reserve(approval, target);
  if (admission === "association-required") {
    const association = await checkedObservation(
      boundary,
      profile,
      approval,
      target,
      "association",
    );
    registry.associateRun(approval, target.run, association.digest);
    admission = registry.reserve(approval, target);
  }
  assert(admission !== "association-required");
  const state = replayBootstrap(journal.read().map((entry) => entry.event));
  const events = journal.read().map((entry) => entry.event);
  let priorPublished: PublishedRelease | undefined;
  for (const previous of state.attempts.values()) {
    const prior = targetFromFields(previous.fields);
    const issueIds = events
      .filter(
        (event) =>
          event.kind === "issue_intent" &&
          event.fields.run === prior.run &&
          event.fields.attempt === prior.attempt,
      )
      .map((event) => event.fields.issueId as string);
    if (issueIds.length === 0) continue;
    const returned = await boundary.history(prior, issueIds);
    const raw =
      profile.kind === "github-oidc"
        ? {
            ...object(returned, "github credentials operations"),
            github: await readPublicGithubPublishedRelease(prior),
          }
        : returned;
    const observed = assessObservedReconciliation(
      raw,
      issueIds,
      release(prior),
      Math.floor(Date.now() / 1000),
    );
    assert.notEqual(
      observed.kind,
      "unknown",
      "Prior issuer, publication or credential outcome remains UNKNOWN",
    );
    if (observed.kind === "published") {
      assert(!priorPublished, "Conflicting multiple prior releases");
      const { kind: _kind, ...actualRelease } = observed;
      priorPublished = actualRelease;
      if (!["published", "safe"].includes(previous.status))
        registry.reconciliation(prior, "published", sha(JSON.stringify(raw)));
      else
        assert.equal(
          previous.status,
          "published",
          "A prior safe record conflicts with publication",
        );
    } else {
      assert.notEqual(previous.status, "published", "Previously published asset disappeared");
      if (!["safe", "prepared"].includes(previous.status))
        registry.reconciliation(prior, "safe", sha(JSON.stringify(raw)));
    }
  }
  if (priorPublished) return priorPublished;
  admission = registry.reserve(approval, target);
  assert.equal(admission, "ready", "Prior state cannot safely issue");
  signal?.throwIfAborted();
  const artifact = await boundary.openArtifact(target);
  assert.equal(artifact.artifactId, target.artifactId);
  assert.equal(artifact.producer, target.producer);
  assert.equal(artifact.run, target.run);
  assert.equal(artifact.attempt, target.attempt);
  const artifactHash = createHash("sha256");
  const chunks: Buffer[] = [];
  let artifactSize = 0;
  for await (const chunk of artifact.bytes) {
    assert(chunk instanceof Uint8Array && chunk.byteLength > 0, "Invalid artifact stream");
    artifactSize += chunk.byteLength;
    assert(artifactSize <= 512 * 1024 * 1024, "Artifact exceeds limit");
    const bytes = Buffer.from(chunk);
    artifactHash.update(bytes);
    chunks.push(bytes);
  }
  assert.equal(artifactSize, github.artifactZipSize, "GitHub ZIP size differs");
  assert.equal(artifactHash.digest("hex"), target.artifactApiDigest, "GitHub ZIP digest differs");
  const verifiedArtifact = inspectBootstrapZip(
    Buffer.concat(chunks, artifactSize),
    target,
    approval,
  );
  signal?.throwIfAborted();
  const issueProof = await checkedObservation(boundary, profile, approval, target, "issue");
  signal?.throwIfAborted();
  const issueId = `issue-${randomBytes(24).toString("hex")}`;
  registry.issueIntent(target, issueId); // durable before any issuer request
  let capability: Capability | undefined;
  try {
    capability = await boundary.issue(target, issueId, issueProof.lease);
    assert(
      identifier.test(capability.id) &&
        Buffer.isBuffer(capability.value) &&
        capability.value.length > 0 &&
        capability.value.length <= 4096,
    );
    assert.equal(
      capability.targetDigest,
      brokerTargetDigest(target),
      "Issued capability has a different target",
    );
  } catch (error) {
    registry.issueResult(target, issueId, { status: "unknown" });
    if (capability && Buffer.isBuffer(capability.value)) capability.value.fill(0);
    await boundary.revoke(issueId).catch(() => undefined);
    throw error;
  }
  try {
    registry.issueResult(target, issueId, { status: "issued", capabilityId: capability.id });
    signal?.throwIfAborted();
    const useProof = await checkedObservation(boundary, profile, approval, target, "use");
    assert.equal(useProof.lease.id, issueProof.lease.id, "Lease changed between issuance and use");
    assert.equal(useProof.lease.revision, issueProof.lease.revision, "Lease revision changed");
    await boundary.verifyLease(useProof.lease, target);
    assert(Math.floor(Date.now() / 1000) < useProof.lease.end, "Lease expired before use");
    signal?.throwIfAborted();
    registry.publicationIntent(target, issueId); // durable before any publisher request
    try {
      await boundary.publish(target, issueId, capability.value, useProof.lease, verifiedArtifact);
      signal?.throwIfAborted();
      await boundary.revoke(issueId);
      const returned = await boundary.history(target, [issueId]);
      const raw =
        profile.kind === "github-oidc"
          ? {
              ...object(returned, "github credentials operations"),
              github: await readPublicGithubPublishedRelease(target),
            }
          : returned;
      const checked = assessObservedReconciliation(
        raw,
        [issueId],
        release(target),
        Math.floor(Date.now() / 1000),
      );
      assert.equal(
        checked.kind,
        "published",
        "Publication or credential readback is not authoritative",
      );
      registry.publication(target, { status: "published", observedDigest: target.artifactDigest });
      const { kind: _kind, ...actualRelease } = checked;
      return actualRelease;
    } catch (error) {
      registry.publication(target, { status: "unknown" });
      throw error;
    }
  } finally {
    capability.value.fill(0);
    // A failure here never changes the journal to safe: only a later issuer readback can do that.
    await boundary.revoke(issueId).catch(() => undefined);
  }
}

async function sanitizedBroker(
  journal: BootstrapJournal,
  target: AttemptTarget,
  ports: BrokerPorts,
  profile: BrokerTrustProfile,
  signal?: AbortSignal,
): Promise<PublishedRelease> {
  try {
    return await runBrokerEngine(journal, target, ports, profile, signal);
  } catch {
    if (signal?.aborted) throw new DOMException("Bootstrap broker cancelled", "AbortError");
    throw new Error("Bootstrap broker refused; reconcile any uncertain outcome");
  }
}

/** Test keys are accepted only through this isolated component-test entry, never the production entry. */
export type IsolatedTestProfile = {
  kind: "isolated-test";
  collector: CollectorIdentity;
  softwareJwks: Buffer;
  requiredDomains: readonly string[];
  githubGet(target: AttemptTarget): GithubGet;
};
type BrokerTrustProfile = ReviewedAuthorityProfile | IsolatedTestProfile;
export async function runIsolatedBroker(
  journal: BootstrapJournal,
  target: AttemptTarget,
  profile: IsolatedTestProfile,
  ports: BrokerPorts,
  signal?: AbortSignal,
) {
  assert.equal(profile.kind, "isolated-test");
  return sanitizedBroker(journal, target, ports, profile, signal);
}
/** The independently controlled production broker selects its collector and adapters only from reviewed source. */
export async function runProductionBroker(
  journal: BootstrapJournal,
  target: AttemptTarget,
  signal?: AbortSignal,
) {
  const profile = requireReviewedAuthorityProfile();
  let ports: BrokerPorts;
  try {
    ports = profile.createPorts();
  } catch {
    throw new Error("Bootstrap broker refused; reconcile any uncertain outcome");
  }
  return sanitizedBroker(journal, target, ports, profile, signal);
}
