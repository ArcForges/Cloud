// SPDX-License-Identifier: AGPL-3.0-only
// Synthetic provider, issuer and publication service for isolated tests; never production authority.
import assert from "node:assert/strict";
import { createHash, generateKeyPairSync, sign, verify } from "node:crypto";
import { crc32, deflateRawSync } from "node:zlib";
import type {
  BrokerPorts,
  EffectAuthorization,
  IsolatedTestProfile,
} from "../../../tooling/ctr06-bootstrap-broker.ts";
import { acceptFencedEffect, brokerTargetDigest } from "../../../tooling/ctr06-bootstrap-broker.ts";
import { bridgeSource } from "../../../tooling/ctr06-security-bridge-source.ts";
import {
  sourceObservationMessage,
  sourceEnforcementMessage,
  type LeaseSource,
  type AuthorityLease,
} from "../../../tooling/ctr06-bootstrap-policy.ts";
import { verifyAuthenticatedHistoryWithKey } from "../../../tooling/ctr06-bootstrap-reconcile.ts";
import type {
  ApprovedBootstrap,
  AttemptTarget,
} from "../../../tooling/ctr06-bootstrap-registry.ts";

export const approval: ApprovedBootstrap = {
  approvedHead: "a".repeat(40),
  approvedTree: "b".repeat(40),
  merge: "c".repeat(40),
  originalRun: "123",
  eventDigest: "d".repeat(64),
};
export function target(
  attempt = "1",
  run = "123",
  runNumber = "456",
  challenge = "1".repeat(64),
): AttemptTarget {
  const value: AttemptTarget = {
    run,
    runNumber,
    attempt,
    producer: approval.merge,
    eventDigest: approval.eventDigest,
    gateDigest: "e".repeat(64),
    artifactId: "789",
    artifactDigest: createHash("sha256").update(fixtureArtifact).digest("hex"),
    artifactApiDigest: "0".repeat(64),
    receiptDigest: "0".repeat(64),
    receiptSize: "1",
    gateChallenge: challenge,
    artifactSize: String(fixtureArtifact.length),
    release: `ctr06-security-bridge-cloud-0.1.0-ci.${runNumber}.${attempt}`,
  };
  value.gateDigest = createHash("sha256").update(gatePayload(value)).digest("hex");
  value.receiptDigest = createHash("sha256").update(syntheticReceipt(value)).digest("hex");
  value.receiptSize = String(syntheticReceipt(value).length);
  value.artifactApiDigest = createHash("sha256").update(syntheticZip(value)).digest("hex");
  return value;
}
const fixtureArtifact = Buffer.from("isolated synthetic sealed artifact");
export function syntheticReceipt(value: AttemptTarget): Buffer {
  const version = `0.1.0-ci.${value.runNumber}.${value.attempt}`;
  return Buffer.from(
    JSON.stringify({
      schema: "arcforges.ctr06-security-bridge-bootstrap.v1",
      producer: {
        repository: "ArcForges/Cloud",
        workflowRef: "ArcForges/Cloud/.github/workflows/ci.yml@refs/heads/main",
        commit: value.producer,
        tree: approval.approvedTree,
        runId: value.run,
        runNumber: value.runNumber,
        runAttempt: Number(value.attempt),
        pipelineRun: `https://github.com/ArcForges/Cloud/actions/runs/${value.run}`,
      },
      source: bridgeSource,
      version,
      carrier: {
        name: `arcforges-ctr06-security-bridge-${version}.tar.gz`,
        sha256: value.artifactDigest,
        size: fixtureArtifact.length,
        members: 16,
      },
      manifestSha256: "e".repeat(64),
    }),
  );
}
export function zipFixture(
  entries: readonly (readonly [string, Buffer])[],
  deflate = false,
  descriptor = false,
  trailing = false,
): Buffer {
  const locals: Buffer[] = [];
  const central: Buffer[] = [];
  let offset = 0;
  for (const [name, body] of entries) {
    const n = Buffer.from(name);
    const checksum = crc32(body);
    const encoded = deflate ? deflateRawSync(body) : body;
    const compressed = trailing ? Buffer.concat([encoded, Buffer.from("junk")]) : encoded;
    const local = Buffer.alloc(30);
    local.writeUInt32LE(0x04034b50, 0);
    local.writeUInt16LE(20, 4);
    if (descriptor) local.writeUInt16LE(8, 6);
    if (deflate) local.writeUInt16LE(8, 8);
    if (!descriptor) {
      local.writeUInt32LE(checksum, 14);
      local.writeUInt32LE(compressed.length, 18);
      local.writeUInt32LE(body.length, 22);
    }
    local.writeUInt16LE(n.length, 26);
    const header = Buffer.alloc(46);
    header.writeUInt32LE(0x02014b50, 0);
    header.writeUInt16LE(0x0314, 4);
    header.writeUInt16LE(20, 6);
    if (descriptor) header.writeUInt16LE(8, 8);
    if (deflate) header.writeUInt16LE(8, 10);
    header.writeUInt32LE(checksum, 16);
    header.writeUInt32LE(compressed.length, 20);
    header.writeUInt32LE(body.length, 24);
    header.writeUInt16LE(n.length, 28);
    header.writeUInt32LE((0o100644 << 16) >>> 0, 38);
    header.writeUInt32LE(offset, 42);
    const trailer = Buffer.alloc(descriptor ? 16 : 0);
    if (descriptor) {
      trailer.writeUInt32LE(0x08074b50, 0);
      trailer.writeUInt32LE(checksum, 4);
      trailer.writeUInt32LE(compressed.length, 8);
      trailer.writeUInt32LE(body.length, 12);
    }
    locals.push(local, n, compressed, trailer);
    central.push(header, n);
    offset += local.length + n.length + compressed.length + trailer.length;
  }
  const directory = Buffer.concat(central);
  const end = Buffer.alloc(22);
  end.writeUInt32LE(0x06054b50, 0);
  end.writeUInt16LE(entries.length, 8);
  end.writeUInt16LE(entries.length, 10);
  end.writeUInt32LE(directory.length, 12);
  end.writeUInt32LE(offset, 16);
  return Buffer.concat([...locals, directory, end]);
}
export function syntheticZip(value: AttemptTarget): Buffer {
  const version = `0.1.0-ci.${value.runNumber}.${value.attempt}`;
  return zipFixture([
    ["bootstrap-receipt.json", syntheticReceipt(value)],
    [`arcforges-ctr06-security-bridge-${version}.tar.gz`, fixtureArtifact],
  ]);
}
const domains = [
  "credentials",
  "database",
  "federation",
  "github-apps",
  "github-organization",
  "github-repository",
  "github-workflows",
  "provider-deployment",
];
export const sourceProfiles = domains.map((domain) => ({
  domain,
  namespace: `namespace-${domain}`,
  provider: `provider-${domain}`,
  observationType: "mock-authenticated-v1",
  enforcementType: "mock-enforcement-v1",
}));
function evidence(holder: string, now: number, sourceAge = 0) {
  const collectedAt = now - sourceAge;
  const refs = sourceProfiles.map((profile, index) => ({
    domain: profile.domain,
    namespace: profile.namespace,
    provider: profile.provider,
    revision: `revision-${index + 1}`,
  }));
  const lease = {
    id: "lease1",
    holder,
    fence: "fence1",
    start: collectedAt - 1,
    end: now + 120,
    sources: refs,
  };
  const sources = refs.map((ref) => {
    const pages = [
      { cursor: null, next: null as string | null, revision: ref.revision, ids: [ref.domain] },
    ];
    const digest = createHash("sha256").update(JSON.stringify(pages)).digest("hex");
    return {
      ...ref,
      collectedAt,
      pages,
      observation: {
        type: "mock-authenticated-v1",
        provider: ref.provider,
        revision: ref.revision,
        digest,
        attestation: sign(
          "RSA-SHA256",
          sourceObservationMessage(ref, collectedAt, digest),
          sourcePair.privateKey,
        ).toString("base64url"),
      },
      enforcement: {
        type: "mock-enforcement-v1",
        leaseId: lease.id,
        fence: lease.fence,
        revision: ref.revision,
        receipt: sign(
          "RSA-SHA256",
          sourceEnforcementMessage(ref, lease),
          sourcePair.privateKey,
        ).toString("base64url"),
      },
    };
  });
  return { lease, sources };
}
function mutateEvidence(value: ReturnType<typeof evidence>, failure: string) {
  const first = value.sources[0];
  assert(first?.pages[0]);
  if (failure === "missing-domain") value.sources.pop();
  if (failure === "missing-page") first.pages[0].next = "missing";
  if (failure === "revision") first.revision = "changed";
  if (failure === "provider") first.provider = "other-provider";
  if (failure === "namespace") first.namespace = "other-namespace";
  if (failure === "old-observation") first.collectedAt -= 121;
  if (failure === "observation-identity") first.observation.provider = "other-provider";
  if (failure === "page-digest") first.observation.digest = "0".repeat(64);
  if (failure === "receipt") first.enforcement.receipt = "";
  if (failure === "missing-receipt") Reflect.deleteProperty(first.enforcement, "receipt");
  if (failure === "missing-attestation") Reflect.deleteProperty(first.observation, "attestation");
  if (failure === "forged-observation")
    first.observation.attestation = Buffer.alloc(256).toString("base64url");
  if (failure === "forged-receipt")
    first.enforcement.receipt = Buffer.alloc(256).toString("base64url");
  if (failure === "fence") first.enforcement.fence = "other-fence";
  if (failure === "unknown-control") first.enforcement.type = "unsupported-control";
  if (failure === "missing-lease-source") value.lease.sources.pop();
  if (failure === "pseudo-aggregate") {
    const ref = value.lease.sources[0];
    assert(ref);
    ref.revision = "aggregate-revision";
  }
}
const gateEpoch = Math.floor(Date.now() / 1000) - 90;
function gatePayload(
  value: Pick<
    AttemptTarget,
    "producer" | "run" | "runNumber" | "attempt" | "eventDigest" | "gateChallenge"
  >,
  failure = "",
  epoch = gateEpoch,
  sourceAge = 0,
) {
  const observations = evidence(`${value.run}:${value.attempt}`, epoch, sourceAge);
  mutateEvidence(observations, failure);
  return Buffer.from(
    JSON.stringify({
      schema: "arcforges.ctr06.bootstrap-gate.v1",
      producer: value.producer,
      run: value.run,
      runNumber: value.runNumber,
      attempt: value.attempt,
      originalRun: approval.originalRun,
      eventDigest: value.eventDigest,
      challenge: value.gateChallenge,
      source: bridgeSource,
      ...observations,
      authority: {
        roots: ["runner"],
        principals: [{ id: "runner", capabilities: ["publication"] }],
        relationships: [],
      },
    }),
  );
}
const encode = (value: unknown) => Buffer.from(JSON.stringify(value)).toString("base64url");
type Entry = {
  credential: "active" | "revoked" | "expired" | "unknown";
  operation: "not_started" | "no_effect" | "inflight" | "unknown" | "published";
  secret: Buffer;
};

const collector = { sourceSha: "9".repeat(40), runId: "345", runAttempt: "1" };
const pair = generateKeyPairSync("rsa", { modulusLength: 2048 });
const sourcePair = generateKeyPairSync("rsa", { modulusLength: 2048 });
export function githubFixture(value: AttemptTarget) {
  const repo = { id: 1372264358 };
  const names = [
    "Require authenticated bootstrap authority evidence",
    "Construct security bridge (Linux)",
    "Construct security bridge (Windows)",
    "Verify and seal the same-run bridge carrier",
  ];
  const jobs = names.map((name, index) => ({
    id: 100 + index,
    name,
    run_id: Number(value.run),
    run_attempt: Number(value.attempt),
    head_sha: value.producer,
    status: "completed",
    conclusion: "success",
    completed_at: new Date(gateEpoch * 1000).toISOString(),
  }));
  const statuses = ["arcforges/linux", "arcforges/windows"].map((context, index) => ({
    id: 900 + index,
    state: "success",
    context,
    description: "15 steps passed in 100s on linux-host (profile full)",
    target_url: null,
    created_at: "2026-11-11T10:00:00Z",
    creator: { login: "deku2026", id: 263133346, type: "User" },
  }));
  const answers: Record<string, unknown> = {
    [`/actions/runs/${value.run}/attempts/${value.attempt}`]: {
      id: Number(value.run),
      run_number: Number(value.runNumber),
      run_attempt: Number(value.attempt),
      event: "push",
      path: ".github/workflows/ci.yml",
      head_sha: value.producer,
      head_branch: "main",
      status: "in_progress",
      conclusion: null,
      repository: repo,
      head_repository: repo,
    },
    [`/actions/runs/${value.run}/attempts/${value.attempt}/jobs?per_page=100&page=1`]: {
      total_count: jobs.length,
      jobs,
    },
    [`/actions/artifacts/${value.artifactId}`]: {
      id: Number(value.artifactId),
      name: `ctr06-security-sealed-${value.run}-${value.attempt}`,
      expired: false,
      digest: `sha256:${value.artifactApiDigest}`,
      size_in_bytes: syntheticZip(value).length,
      workflow_run: {
        id: Number(value.run),
        repository_id: repo.id,
        head_repository_id: repo.id,
        head_sha: value.producer,
        head_branch: "main",
      },
    },
    "/pulls/155": {
      number: 155,
      state: "closed",
      merged: true,
      merged_at: "2026-11-11T10:00:00Z",
      merge_commit_sha: approval.merge,
      head: { sha: approval.approvedHead, repo },
      base: { ref: "main", repo },
    },
    "/git/ref/heads/main": { ref: "refs/heads/main", object: { sha: value.producer } },
    [`/git/commits/${value.producer}`]: {
      sha: value.producer,
      tree: { sha: approval.approvedTree },
      parents: [{ sha: "0".repeat(40) }, { sha: approval.approvedHead }],
    },
    [`/commits/${approval.approvedHead}/statuses?per_page=100&page=1`]: statuses,
  };
  return answers;
}
export const testProfile: IsolatedTestProfile = {
  kind: "isolated-test",
  collector,
  requiredSources: sourceProfiles,
  githubGet: (value, boundary) => async (key) => {
    const answers = githubFixture(value);
    if (key in answers) return structuredClone(answers[key]);
    assert(boundary instanceof SyntheticAuthority);
    return boundary.publicMetadata(value, key);
  },
  softwareJwks: Buffer.from(
    JSON.stringify({
      keys: [
        { ...pair.publicKey.export({ format: "jwk" }), kid: "fixture", use: "sig", alg: "RS256" },
      ],
    }),
  ),
};

export function prepareSyntheticGate(
  context: Pick<
    AttemptTarget,
    "producer" | "run" | "runNumber" | "attempt" | "eventDigest" | "gateChallenge"
  >,
  failure = "",
  options: { epoch?: number; sourceAge?: number } = {},
) {
  const epoch = options.epoch ?? gateEpoch;
  const payload = gatePayload(context, failure, epoch, options.sourceAge ?? 0);
  const claims = {
    iss: "https://token.actions.githubusercontent.com",
    aud: `arcforges:ctr06:bootstrap-authority:v1:${createHash("sha256").update(payload).digest("hex")}`,
    sub: "repo:ArcForges/Cloud:ref:refs/heads/main",
    repository: "ArcForges/Cloud",
    repository_id: "1372264358",
    repository_owner_id: "279581753",
    ref: "refs/heads/main",
    ref_protected: "true",
    workflow_ref: "ArcForges/Cloud/.github/workflows/ctr06-authority-collector.yml@refs/heads/main",
    workflow_sha: collector.sourceSha,
    sha: collector.sourceSha,
    event_name: "workflow_dispatch",
    run_id: collector.runId,
    run_attempt: collector.runAttempt,
    runner_environment: "github-hosted",
    jti: "synthetic-gate",
    iat: epoch - 1,
    nbf: epoch - 1,
    exp: epoch + 60,
  };
  const prefix = `${encode({ alg: "RS256", kid: "fixture", typ: "JWT" })}.${encode(claims)}`;
  const signature = sign("RSA-SHA256", Buffer.from(prefix), pair.privateKey).toString("base64url");
  return { payload, token: `${prefix}.${signature}` };
}

export class SyntheticAuthority implements BrokerPorts {
  readonly assetSize = fixtureArtifact.length;
  readonly entries = new Map<string, Entry>();
  readonly calls: string[] = [];
  actual: AttemptTarget | undefined;
  failure = "";
  failurePhase = "";
  phase = "";
  tokenLifetimeSeconds = 60;
  sourceAgeSeconds = 0;
  sourceAgePhase = "";
  lastTiming: Record<string, { collectedAt: number; expiresAt: number; leaseEnd: number }> = {};
  blockRevocation = false;
  historyUnavailable = false;
  publicUnknown = false;
  privateAbsent = false;
  publicReads = 0;
  currentFence = "fence1";
  #prior: { payload: Buffer; token: string } | undefined;
  async reviewedApproval() {
    this.calls.push("reviewed");
    return { ...approval };
  }
  #gate: { payload: Buffer; token: string } | undefined;
  retainPreparedGate(proof: { payload: Buffer; token: string }) {
    this.#gate = proof;
  }
  async readGate(request: AttemptTarget) {
    this.calls.push("gate-proof");
    return this.#gate ?? prepareSyntheticGate(request);
  }
  async verifyGateReadback(
    proof: { payload: Buffer; token: string },
    _target: AttemptTarget,
    jobId: number,
    lease: AuthorityLease,
  ) {
    this.calls.push("gate-readback");
    assert.equal(jobId, 100);
    if (this.failure === "gate-readback") throw new Error("synthetic gate readback unavailable");
    await this.verifyCoverage(proof.payload, lease);
  }
  async observe(request: AttemptTarget, phase: "association" | "issue" | "use", challenge: string) {
    this.calls.push(`observe:${phase}`);
    const now = Math.floor(Date.now() / 1000);
    this.phase = phase;
    const sourceAge = this.sourceAgePhase === phase ? this.sourceAgeSeconds : 0;
    const observations = evidence(`${request.run}:${request.attempt}`, now, sourceAge);
    this.lastTiming[phase] = {
      collectedAt: now - sourceAge,
      expiresAt: now + this.tokenLifetimeSeconds,
      leaseEnd: observations.lease.end,
    };
    if (!this.failurePhase || this.failurePhase === phase) {
      mutateEvidence(observations, this.failure);
      if (this.failure === "expired") observations.lease.end = now - 1;
    }
    const authority = {
      roots: ["runner"],
      principals: [
        { id: "runner", capabilities: [this.failure === "database" ? "database" : "publication"] },
      ],
      relationships: [],
    };
    const payload = Buffer.from(
      JSON.stringify({
        schema: "arcforges.ctr06.bootstrap-authority.v1",
        phase,
        challenge,
        targetDigest: brokerTargetDigest(request),
        producer: approval.merge,
        eventDigest: approval.eventDigest,
        originalRun: approval.originalRun,
        ...observations,
        authority,
      }),
    );
    const claims = {
      iss: "https://token.actions.githubusercontent.com",
      aud: `arcforges:ctr06:bootstrap-authority:v1:${createHash("sha256").update(payload).digest("hex")}`,
      sub: "repo:ArcForges/Cloud:ref:refs/heads/main",
      repository: "ArcForges/Cloud",
      repository_id: "1372264358",
      repository_owner_id: "279581753",
      ref: "refs/heads/main",
      ref_protected: "true",
      workflow_ref:
        "ArcForges/Cloud/.github/workflows/ctr06-authority-collector.yml@refs/heads/main",
      workflow_sha: collector.sourceSha,
      sha: collector.sourceSha,
      event_name: "workflow_dispatch",
      run_id: collector.runId,
      run_attempt: collector.runAttempt,
      runner_environment: "github-hosted",
      jti: "synthetic-jti",
      iat: now - 1,
      nbf: now - 1,
      exp: now + this.tokenLifetimeSeconds,
    };
    if (this.failure === "issuer") claims.iss = "https://invalid.example";
    const prefix = `${encode({ alg: "RS256", kid: "fixture", typ: "JWT" })}.${encode(claims)}`;
    const signature = sign("RSA-SHA256", Buffer.from(prefix), pair.privateKey).toString(
      "base64url",
    );
    const next = { payload, token: `${prefix}.${signature}` };
    if (this.failure === "replay" && this.#prior) return this.#prior;
    this.#prior = next;
    return next;
  }
  async openArtifact(request: AttemptTarget) {
    this.calls.push("artifact");
    const content =
      this.failure === "tampered-artifact" ? Buffer.from("tampered") : syntheticZip(request);
    return {
      artifactId: request.artifactId,
      producer: request.producer,
      run: request.run,
      attempt: request.attempt,
      bytes: (async function* () {
        yield content;
      })(),
    };
  }
  async verifyCoverage(payload: Buffer, lease: AuthorityLease) {
    this.calls.push("coverage");
    if (this.failure === "coverage") throw new Error("synthetic coverage unavailable");
    const document = JSON.parse(payload.toString("utf8")) as {
      sources: {
        domain: string;
        namespace: string;
        provider: string;
        revision: string;
        collectedAt: number;
        observation: { digest: string; attestation: string };
        enforcement: { receipt: string };
      }[];
    };
    for (const source of document.sources) {
      const ref: LeaseSource = {
        domain: source.domain,
        namespace: source.namespace,
        provider: source.provider,
        revision: source.revision,
      };
      assert(
        verify(
          "RSA-SHA256",
          sourceObservationMessage(ref, source.collectedAt, source.observation.digest),
          sourcePair.publicKey,
          Buffer.from(source.observation.attestation, "base64url"),
        ),
        "synthetic source observation signature differs",
      );
      assert(
        verify(
          "RSA-SHA256",
          sourceEnforcementMessage(ref, lease),
          sourcePair.publicKey,
          Buffer.from(source.enforcement.receipt, "base64url"),
        ),
        "synthetic enforcement receipt differs",
      );
    }
  }
  async verifyLease(lease: AuthorityLease) {
    this.calls.push("lease");
    if (this.failure === "lease-loss" || lease.fence !== this.currentFence)
      throw new Error("synthetic lease lost or fenced");
  }
  async issue(request: AttemptTarget, issueId: string, authorization: EffectAuthorization) {
    this.calls.push("issue");
    return acceptFencedEffect(this, testProfile, approval, request, authorization, () => {
      assert.equal(authorization.phase, "issue");
      const secret = Buffer.from("PRIVATE-CAPABILITY-FIXTURE");
      this.entries.set(issueId, {
        credential: "active",
        operation: "not_started",
        secret: Buffer.from(secret),
      });
      if (this.failure === "issue-unknown") throw new Error("synthetic issuer response lost");
      return {
        id: `credential-${issueId}`,
        targetDigest: brokerTargetDigest(request),
        value: secret,
      };
    });
  }
  async publish(
    request: AttemptTarget,
    issueId: string,
    capability: Buffer,
    authorization: EffectAuthorization,
    verifiedArtifact: Buffer,
  ) {
    this.calls.push("publish");
    return acceptFencedEffect(this, testProfile, approval, request, authorization, () => {
      assert.equal(authorization.phase, "use");
      const entry = this.entries.get(issueId);
      assert(entry);
      assert.equal(entry.credential, "active");
      assert.deepEqual(capability, entry.secret);
      assert.deepEqual(verifiedArtifact, fixtureArtifact);
      entry.operation = "published";
      this.actual = { ...request };
      if (this.failure === "publish-unknown") throw new Error("synthetic publisher response lost");
    });
  }
  async revoke(issueId: string) {
    this.calls.push("revoke");
    if (this.blockRevocation) throw new Error("synthetic issuer unavailable");
    const entry = this.entries.get(issueId);
    if (entry) entry.credential = "revoked";
  }
  async history(request: AttemptTarget, issueIds: string[]) {
    this.calls.push("history");
    if (this.historyUnavailable) throw new Error("synthetic readback unavailable");
    const now = Math.floor(Date.now() / 1000);
    const credentials = issueIds.map((issueId) => {
      const entry = this.entries.get(issueId);
      assert(entry);
      return { issueId, state: entry.credential, observedAt: now, expiresAt: now + 60 };
    });
    const operations = issueIds.map((issueId) => {
      const entry = this.entries.get(issueId);
      assert(entry);
      const publication =
        entry.operation === "published" && this.actual ? this.publishedIdentity(this.actual) : null;
      return { issueId, state: entry.operation, observedAt: now, publication };
    });
    const actual =
      !this.privateAbsent && this.actual?.release === request.release ? this.actual : undefined;
    const github = actual
      ? {
          state: "present",
          observedAt: now,
          tag: actual.release,
          merge: actual.producer,
          artifactDigest: actual.artifactDigest,
          artifactSize: this.assetSize,
          receiptDigest: actual.receiptDigest,
          receiptSize: Number(actual.receiptSize),
          run: actual.run,
          runNumber: actual.runNumber,
          attempt: actual.attempt,
          sourceArtifactId: actual.artifactId,
          releaseId: "9001",
          assetId: "9002",
          receiptAssetId: "9003",
        }
      : {
          state: "absent",
          observedAt: now,
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
    void request;
    const payload = Buffer.from(
      JSON.stringify({
        schema: "arcforges.ctr06.private-history.v1",
        targetDigest: brokerTargetDigest(request),
        issueIds,
        privateGithub: github,
        credentials,
        operations,
      }),
    );
    return {
      payload,
      signature: sign("RSA-SHA256", payload, sourcePair.privateKey).toString("base64url"),
    };
  }
  async verifyHistory(history: unknown, request: AttemptTarget, issueIds: string[]) {
    this.calls.push("history-authenticated");
    if (this.failure === "history-authentication")
      throw new Error("synthetic private source unavailable");
    assert(
      history && typeof history === "object" && "payload" in history && "signature" in history,
    );
    assert(Buffer.isBuffer(history.payload) && typeof history.signature === "string");
    return verifyAuthenticatedHistoryWithKey(
      history.payload,
      history.signature,
      sourcePair.publicKey,
      brokerTargetDigest(request),
      issueIds,
    );
  }
  publishedIdentity(actual: AttemptTarget) {
    return {
      tag: actual.release,
      merge: actual.producer,
      artifactDigest: actual.artifactDigest,
      artifactSize: this.assetSize,
      receiptDigest: actual.receiptDigest,
      receiptSize: Number(actual.receiptSize),
      run: actual.run,
      runNumber: actual.runNumber,
      attempt: actual.attempt,
      sourceArtifactId: actual.artifactId,
      releaseId: "9001",
      assetId: "9002",
      receiptAssetId: "9003",
    };
  }
  publicMetadata(request: AttemptTarget, key: string): unknown {
    this.publicReads++;
    const actual = this.actual;
    if (key.startsWith("/releases/tags/")) {
      if (this.publicUnknown || !actual || actual.release !== request.release) return null;
      const carrier = `arcforges-ctr06-security-bridge-0.1.0-ci.${actual.runNumber}.${actual.attempt}.tar.gz`;
      return {
        id: 9001,
        tag_name: actual.release,
        target_commitish: actual.producer,
        draft: false,
        prerelease: true,
        published_at: "2026-11-11T12:00:00Z",
        assets: [
          {
            id: 9002,
            name: carrier,
            state: "uploaded",
            digest: `sha256:${actual.artifactDigest}`,
            size: Number(actual.artifactSize),
          },
          {
            id: 9003,
            name: "bootstrap-receipt.json",
            state: "uploaded",
            digest: `sha256:${actual.receiptDigest}`,
            size: Number(actual.receiptSize),
          },
        ],
      };
    }
    assert(actual && actual.release === request.release);
    if (key.startsWith("/git/ref/tags/"))
      return {
        ref: `refs/tags/${actual.release}`,
        object: { type: "commit", sha: actual.producer },
      };
    if (key.startsWith("/releases/9001/assets?"))
      return (
        this.publicMetadata(request, `/releases/tags/${request.release}`) as { assets: unknown[] }
      ).assets;
    throw new Error("unexpected synthetic public release read");
  }
}
