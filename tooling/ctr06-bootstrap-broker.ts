// SPDX-License-Identifier: AGPL-3.0-only
// Shared broker state machine. Production requires a source-reviewed profile; tests inject isolated external ports.
import assert from "node:assert/strict";
import { createHash, randomBytes } from "node:crypto";
import type { BootstrapJournal } from "./ctr06-bootstrap-journal.ts";
import { inspectGateProof } from "./ctr06-bootstrap-gate.ts";
import { inspectBootstrapZip } from "./ctr06-bootstrap-zip.ts";
import {
  inspectGithubBootstrapMetadata,
  inspectGithubPublishedRelease,
  readPublicGithubBootstrap,
  readPublicGithubPublishedRelease,
  type GithubGet,
} from "./ctr06-bootstrap-github.ts";
import {
  verifyCollectorIdentity,
  verifyCollectorIdentityWithKeys,
  requireFreshWindow,
  type AuthenticatedWindow,
  type CollectorIdentity,
} from "./ctr06-bootstrap-oidc.ts";
import {
  requireReviewedAuthorityProfile,
  type ReviewedAuthorityProfile,
} from "./ctr06-bootstrap-profile.ts";
import {
  evaluateObservedAuthority,
  inspectSourceEvidence,
  type AuthorityLease,
  type AuthoritySourceProfile,
} from "./ctr06-bootstrap-policy.ts";
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
type Lease = AuthorityLease;
export type CollectorObservation = { payload: Buffer; token: string };
type Capability = { id: string; targetDigest: string; value: Buffer };
export type EffectAuthorization = Readonly<{
  phase: "issue" | "use";
  challenge: string;
  proof: CollectorObservation;
  digest: string;
  lease: Lease;
  window: AuthenticatedWindow;
}>;

/** A production implementation must be selected by reviewed source and independently validate its
 * authoritative coverage and actual enforcement; self-reported fields are not evidence of either. */
export interface BrokerPorts {
  reviewedApproval(): Promise<ApprovedBootstrap>;
  readGate(target: AttemptTarget): Promise<CollectorObservation>;
  verifyGateReadback(
    proof: CollectorObservation,
    target: AttemptTarget,
    jobId: number,
    lease: Lease,
    at: number,
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
  // The independently controlled issuer must verify the signed proof, source controls, lease and
  // fencing at its atomic effect boundary; accepting a broker-supplied boolean is not authorization.
  issue(
    target: AttemptTarget,
    issueId: string,
    authorization: EffectAuthorization,
  ): Promise<Capability>;
  publish(
    target: AttemptTarget,
    issueId: string,
    capability: Buffer,
    authorization: EffectAuthorization,
    verifiedArtifact: Buffer,
  ): Promise<void>;
  revoke(issueId: string): Promise<void>;
  history(target: AttemptTarget, issueIds: string[]): Promise<unknown>;
  /** Verify independently authenticated, complete private release/issuer/publisher history. */
  verifyHistory(history: unknown, target: AttemptTarget, issueIds: string[]): Promise<unknown>;
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

async function verifyCollector(
  profile: BrokerTrustProfile,
  proof: CollectorObservation,
  target: AttemptTarget,
  at: number,
): Promise<AuthenticatedWindow> {
  if (profile.kind === "github-oidc") {
    const identity = await profile.collectorRun(proof, target);
    assert.equal(
      identity.sourceSha,
      profile.collectorSourceSha,
      "Collector source differs from reviewed profile",
    );
    return verifyCollectorIdentity(proof.payload, proof.token, identity, at);
  } else {
    await profile.beforeKeys?.(); // test-only transport delay; keys remain fixed in the test profile
    return verifyCollectorIdentityWithKeys(
      proof.payload,
      proof.token,
      profile.collector,
      at,
      profile.softwareJwks,
    );
  }
}

async function validateObservation(
  boundary: BrokerPorts,
  profile: BrokerTrustProfile,
  approval: ApprovedBootstrap,
  target: AttemptTarget,
  phase: Phase,
  challenge: string,
  observation: CollectorObservation,
): Promise<{ lease: Lease; digest: string; window: AuthenticatedWindow }> {
  assert(observation.payload.length > 0 && observation.payload.length <= 1024 * 1024);
  const now = Math.floor(Date.now() / 1000);
  const authenticatedDigest = sha(observation.payload);
  const window = await verifyCollector(profile, observation, target, now);
  assert.equal(sha(observation.payload), authenticatedDigest, "Authenticated observation changed");
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
  const lease = inspectSourceEvidence(
    data.lease,
    data.sources,
    now,
    `${target.run}:${target.attempt}`,
    profile.requiredSources,
  );
  evaluateObservedAuthority(data.authority);
  await boundary.verifyCoverage(Buffer.from(observation.payload), lease, target);
  await boundary.verifyLease(lease, target);
  assert.equal(sha(observation.payload), authenticatedDigest, "Authenticated observation changed");
  const current = Math.floor(Date.now() / 1000);
  requireFreshWindow(window, current);
  assert.deepEqual(
    inspectSourceEvidence(
      data.lease,
      data.sources,
      current,
      `${target.run}:${target.attempt}`,
      profile.requiredSources,
    ),
    lease,
    "Authenticated source lease changed",
  );
  return { lease, digest: authenticatedDigest, window };
}

async function checkedObservation(
  boundary: BrokerPorts,
  profile: BrokerTrustProfile,
  approval: ApprovedBootstrap,
  target: AttemptTarget,
  phase: Phase,
) {
  const challenge = randomBytes(32).toString("hex");
  const raw = await boundary.observe(target, phase, challenge);
  const proof = { payload: Buffer.from(raw.payload), token: raw.token };
  const verified = await validateObservation(
    boundary,
    profile,
    approval,
    target,
    phase,
    challenge,
    proof,
  );
  return { ...verified, phase, challenge, proof };
}

function requireCurrentEffect(
  proof: EffectAuthorization,
  profile: BrokerTrustProfile,
  target: AttemptTarget,
): void {
  const now = Math.floor(Date.now() / 1000);
  requireFreshWindow(proof.window, now);
  assert.equal(sha(proof.proof.payload), proof.digest, "Authenticated effect payload changed");
  const data = object(
    parseDocument(proof.proof.payload),
    "schema phase challenge targetDigest producer eventDigest originalRun lease sources authority",
  );
  assert.equal(data.phase, proof.phase);
  assert.equal(data.challenge, proof.challenge);
  assert.equal(data.targetDigest, brokerTargetDigest(target));
  assert.deepEqual(
    inspectSourceEvidence(
      data.lease,
      data.sources,
      now,
      `${target.run}:${target.attempt}`,
      profile.requiredSources,
    ),
    proof.lease,
    "Effect source lease differs",
  );
}

/** Independently controlled issuer/publisher adapters must use equivalent real signature, source and
 * fence checks at their own atomic effect-acceptance boundary. The callback accepts the effect
 * synchronously under the provider's actual fence; an asynchronous queued callback is not a fence.
 * This helper is also used by the isolated external-provider fixture, not only by the broker caller. */
export async function acceptFencedEffect<T>(
  boundary: BrokerPorts,
  profile: BrokerTrustProfile,
  approval: ApprovedBootstrap,
  target: AttemptTarget,
  authorization: EffectAuthorization,
  effect: () => T,
): Promise<T> {
  const verified = await validateObservation(
    boundary,
    profile,
    approval,
    target,
    authorization.phase,
    authorization.challenge,
    authorization.proof,
  );
  assert.deepEqual(verified.lease, authorization.lease, "Effect lease or source fence differs");
  assert.deepEqual(verified.window, authorization.window, "Authenticated effect window differs");
  assert.equal(verified.digest, authorization.digest, "Authenticated effect digest differs");
  requireCurrentEffect(authorization, profile, target);
  const accepted = effect();
  assert(!(accepted instanceof Promise), "Effect acceptance must be synchronous under the fence");
  return accepted;
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
      : await inspectGithubBootstrapMetadata(profile.githubGet(target, boundary), target, approval);
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
    profile.requiredSources,
    (proof, at) => verifyCollector(profile, proof, target, at),
  );
  assert.equal(checkedGate.digest, target.gateDigest, "Gate proof digest differs");
  await boundary.verifyGateReadback(
    gate,
    target,
    gateJob,
    checkedGate.lease,
    github.gateCompletedAt,
  );
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
  async function readReconciliation(request: AttemptTarget, issueIds: string[]) {
    const returned = await boundary.history(request, issueIds);
    const authenticated = await boundary.verifyHistory(returned, request, issueIds);
    const privateData = object(authenticated, "privateGithub credentials operations");
    const publicGithub =
      profile.kind === "github-oidc"
        ? await readPublicGithubPublishedRelease(request)
        : await inspectGithubPublishedRelease(profile.githubGet(request, boundary), request);
    const raw = { ...privateData, publicGithub };
    return {
      raw,
      observed: assessObservedReconciliation(
        raw,
        issueIds,
        release(request),
        Math.floor(Date.now() / 1000),
      ),
    };
  }
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
    const { raw, observed } = await readReconciliation(prior, issueIds);
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
    assert.equal(issueProof.phase, "issue");
    requireCurrentEffect(issueProof as EffectAuthorization, profile, target);
    capability = await boundary.issue(target, issueId, issueProof as EffectAuthorization);
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
    assert.equal(useProof.lease.fence, issueProof.lease.fence, "Lease fence changed");
    assert.deepEqual(
      useProof.lease.sources,
      issueProof.lease.sources,
      "Lease source revisions changed",
    );
    await boundary.verifyLease(useProof.lease, target);
    assert(Math.floor(Date.now() / 1000) < useProof.lease.end, "Lease expired before use");
    signal?.throwIfAborted();
    registry.publicationIntent(target, issueId); // durable before any publisher request
    try {
      assert.equal(useProof.phase, "use");
      requireCurrentEffect(useProof as EffectAuthorization, profile, target);
      await boundary.publish(
        target,
        issueId,
        capability.value,
        useProof as EffectAuthorization,
        verifiedArtifact,
      );
      signal?.throwIfAborted();
      await boundary.revoke(issueId);
      const { observed: checked } = await readReconciliation(target, [issueId]);
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
  requiredSources: readonly AuthoritySourceProfile[];
  githubGet(target: AttemptTarget, boundary: BrokerPorts): GithubGet;
  beforeKeys?(): Promise<void>;
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
