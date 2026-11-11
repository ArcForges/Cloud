// SPDX-License-Identifier: AGPL-3.0-only
// Synthetic provider, issuer and publication service for isolated tests; never production authority.
import assert from "node:assert/strict";
import { createHash, generateKeyPairSync, sign } from "node:crypto";
import { crc32, deflateRawSync } from "node:zlib";
import type { BrokerPorts, IsolatedTestProfile } from "../../../tooling/ctr06-bootstrap-broker.ts";
import { brokerTargetDigest } from "../../../tooling/ctr06-bootstrap-broker.ts";
import { bridgeSource } from "../../../tooling/ctr06-security-bridge-source.ts";
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
const gateEpoch = Math.floor(Date.now() / 1000) - 90;
function gatePayload(
  value: Pick<
    AttemptTarget,
    "producer" | "run" | "runNumber" | "attempt" | "eventDigest" | "gateChallenge"
  >,
) {
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
      lease: {
        id: "lease1",
        revision: "rev1",
        holder: `${value.run}:${value.attempt}`,
        start: gateEpoch - 1,
        end: gateEpoch + 120,
      },
      sources: domains.map((domain) => ({
        domain,
        revision: "rev1",
        pages: [{ cursor: null, next: null, revision: "rev1", ids: [domain] }],
      })),
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
  requiredDomains: domains,
  githubGet: (value) => async (key) => {
    const answers = githubFixture(value);
    assert(key in answers, `unexpected mock GitHub read ${key}`);
    return structuredClone(answers[key]);
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
) {
  const payload = gatePayload(context);
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
    iat: gateEpoch - 1,
    nbf: gateEpoch - 1,
    exp: gateEpoch + 60,
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
  blockRevocation = false;
  historyUnavailable = false;
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
  async verifyGateReadback(_proof: unknown, _target: AttemptTarget, jobId: number) {
    this.calls.push("gate-readback");
    assert.equal(jobId, 100);
    if (this.failure === "gate-readback") throw new Error("synthetic gate readback unavailable");
  }
  async observe(request: AttemptTarget, phase: "association" | "issue" | "use", challenge: string) {
    this.calls.push(`observe:${phase}`);
    const now = Math.floor(Date.now() / 1000);
    const sources = domains.map((domain) => ({
      domain,
      revision: "rev1",
      pages: [{ cursor: null, next: null as string | null, revision: "rev1", ids: [domain] }],
    }));
    if (this.failure === "missing-domain") sources.pop();
    const first = sources[0];
    assert(first?.pages[0]);
    if (this.failure === "missing-page") first.pages[0].next = "missing";
    if (this.failure === "revision") first.revision = "changed";
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
        lease: {
          id: "lease1",
          revision: "rev1",
          holder: `${request.run}:${request.attempt}`,
          start: now - 1,
          end: this.failure === "expired" ? now - 1 : now + 120,
        },
        sources,
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
      exp: now + 60,
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
  async verifyCoverage() {
    this.calls.push("coverage");
    if (this.failure === "coverage") throw new Error("synthetic coverage unavailable");
  }
  async verifyLease() {
    this.calls.push("lease");
    if (this.failure === "lease-loss") throw new Error("synthetic lease lost");
  }
  async issue(request: AttemptTarget, issueId: string) {
    this.calls.push("issue");
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
  }
  async publish(
    request: AttemptTarget,
    issueId: string,
    capability: Buffer,
    _lease: unknown,
    verifiedArtifact: Buffer,
  ) {
    this.calls.push("publish");
    const entry = this.entries.get(issueId);
    assert(entry);
    assert.equal(entry.credential, "active");
    assert.deepEqual(capability, entry.secret);
    assert.deepEqual(verifiedArtifact, fixtureArtifact);
    entry.operation = "published";
    this.actual = { ...request };
    if (this.failure === "publish-unknown") throw new Error("synthetic publisher response lost");
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
      return { issueId, state: entry.operation, observedAt: now };
    });
    const actual = this.actual;
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
    return { github, credentials, operations };
  }
}
