// SPDX-License-Identifier: AGPL-3.0-only
// Durable identity and transition rules. This registry never authenticates a caller or issues a credential.
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import type { BootstrapJournal, JournalEvent } from "./ctr06-bootstrap-journal.ts";

const repository = "1372264358";
const exception = "AF-CTR-06-security-bridge";
const purpose = "build-publish-only";
const gitHash = /^[a-f0-9]{40}$/u;
const hash = /^[a-f0-9]{64}$/u;
const number = /^[1-9][0-9]{0,14}$/u;
const identifier = /^[A-Za-z0-9._:-]{1,128}$/u;
const sha = (value: string) => createHash("sha256").update(value).digest("hex");

type Fields = Record<string, string>;
export type ApprovedBootstrap = {
  approvedHead: string;
  approvedTree: string;
  merge: string;
  originalRun: string;
  eventDigest: string;
};
export type AttemptTarget = {
  run: string;
  runNumber: string;
  attempt: string;
  producer: string;
  eventDigest: string;
  gateDigest: string;
  gateChallenge: string;
  artifactId: string;
  artifactDigest: string;
  artifactApiDigest: string;
  receiptDigest: string;
  receiptSize: string;
  artifactSize: string;
  release: string;
};
type AttemptStatus =
  "prepared" | "issuing" | "issued" | "publishing" | "unknown" | "safe" | "published";
type Attempt = {
  fields: Fields;
  status: AttemptStatus;
  issueId?: string;
  capabilityId?: string;
  observedDigest?: string;
};
type State = {
  authorization?: Fields;
  attempts: Map<string, Attempt>;
  issues: Set<string>;
  associations: Map<string, string>;
};

function validNumber(value: string): boolean {
  return number.test(value) && Number.isSafeInteger(Number(value));
}
function exact(fields: Fields, names: string): void {
  assert.deepEqual(
    Object.keys(fields).sort(),
    names.split(" ").sort(),
    "Unexpected registry fields",
  );
}
function authorization(approval: ApprovedBootstrap): Fields {
  assert(
    gitHash.test(approval.approvedHead) &&
      gitHash.test(approval.approvedTree) &&
      gitHash.test(approval.merge),
  );
  assert(validNumber(approval.originalRun) && hash.test(approval.eventDigest));
  return {
    repository,
    exception,
    purpose,
    approvedHead: approval.approvedHead,
    approvedTree: approval.approvedTree,
    merge: approval.merge,
    producer: approval.merge,
    originalRun: approval.originalRun,
    eventDigest: approval.eventDigest,
  };
}
function targetFields(target: AttemptTarget, auth: Fields): Fields {
  assert(
    validNumber(target.run) &&
      validNumber(target.runNumber) &&
      validNumber(target.attempt) &&
      validNumber(target.artifactId) &&
      validNumber(target.artifactSize) &&
      Number(target.artifactSize) <= 512 * 1024 * 1024 &&
      validNumber(target.receiptSize) &&
      Number(target.receiptSize) <= 64 * 1024,
  );
  assert.equal(target.producer, auth.producer, "Producer differs from approved merge");
  assert.equal(target.eventDigest, auth.eventDigest, "Original event differs");
  assert(
    hash.test(target.gateDigest) &&
      hash.test(target.gateChallenge) &&
      hash.test(target.artifactDigest) &&
      hash.test(target.artifactApiDigest) &&
      hash.test(target.receiptDigest),
  );
  assert.equal(
    target.release,
    `ctr06-security-bridge-cloud-0.1.0-ci.${target.runNumber}.${target.attempt}`,
  );
  const fields = {
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
  };
  const targetDigest = sha(`arcforges:ctr06:bootstrap-target:v1\0${JSON.stringify(fields)}`);
  return { ...fields, targetDigest };
}
function key(fields: Fields): string {
  return `${fields.run}:${fields.attempt}`;
}
function attemptFor(state: State, fields: Fields): Attempt {
  const attempt = state.attempts.get(key(fields));
  assert(attempt, "Unknown attempt");
  return attempt;
}

/** Replays all events and rejects inconsistent histories; it does not authenticate the event source. */
export function replayBootstrap(entries: readonly JournalEvent[]): State {
  const state: State = { attempts: new Map(), issues: new Set(), associations: new Map() };
  for (const event of entries) {
    const f = event.fields;
    if (event.kind === "authorization") {
      exact(
        f,
        "repository exception purpose approvedHead approvedTree merge producer originalRun eventDigest",
      );
      assert(!state.authorization && state.attempts.size === 0, "Repeated authorization");
      assert.deepEqual(
        f,
        authorization({
          approvedHead: f.approvedHead as string,
          approvedTree: f.approvedTree as string,
          merge: f.merge as string,
          originalRun: f.originalRun as string,
          eventDigest: f.eventDigest as string,
        }),
      );
      state.authorization = f;
    } else if (event.kind === "run_association") {
      exact(f, "run originalRun producer eventDigest associationDigest");
      assert(state.authorization, "Run association lacks authorization");
      assert(validNumber(f.run as string) && f.run !== state.authorization.originalRun);
      assert.equal(f.originalRun, state.authorization.originalRun);
      assert.equal(f.producer, state.authorization.producer);
      assert.equal(f.eventDigest, state.authorization.eventDigest);
      assert(hash.test(f.associationDigest as string));
      assert(!state.associations.has(f.run as string), "Duplicate run association");
      state.associations.set(f.run as string, f.associationDigest as string);
    } else if (event.kind === "attempt") {
      exact(
        f,
        "run runNumber attempt producer eventDigest gateDigest gateChallenge artifactId artifactDigest artifactApiDigest receiptDigest receiptSize artifactSize release targetDigest",
      );
      assert(state.authorization, "Attempt lacks authorization");
      assert(
        f.run === state.authorization.originalRun || state.associations.has(f.run as string),
        "Attempt has no original-event association",
      );
      assert.deepEqual(
        f,
        targetFields(
          {
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
          },
          state.authorization,
        ),
      );
      assert(!state.attempts.has(key(f)), "Duplicate attempt record");
      for (const previous of state.attempts.values()) {
        if (previous.fields.run === f.run) {
          assert.equal(
            previous.fields.runNumber,
            f.runNumber,
            "Run number changed between attempts",
          );
          assert(
            Number(previous.fields.attempt) < Number(f.attempt),
            "Attempt order is not increasing",
          );
        }
      }
      state.attempts.set(key(f), { fields: f, status: "prepared" });
    } else if (event.kind === "issue_intent") {
      exact(f, "run attempt issueId");
      const current = attemptFor(state, f);
      assert(current.status === "prepared" || current.status === "safe", "Attempt cannot issue");
      assert(
        identifier.test(f.issueId as string) && !state.issues.has(f.issueId as string),
        "Reused issue identity",
      );
      assert(
        [...state.attempts.values()].every(
          (other) => other === current || other.status === "safe" || other.status === "prepared",
        ),
        "Prior outcome is not safe",
      );
      current.issueId = f.issueId;
      current.capabilityId = undefined;
      current.status = "issuing";
      state.issues.add(f.issueId as string);
    } else if (event.kind === "issue_result") {
      const current = attemptFor(state, f);
      assert(
        current.status === "issuing" && f.issueId === current.issueId,
        "Unexpected issuer outcome",
      );
      if (f.status === "issued") {
        exact(f, "run attempt issueId status capabilityId");
        assert(identifier.test(f.capabilityId as string));
        current.capabilityId = f.capabilityId;
        current.status = "issued";
      } else {
        exact(f, "run attempt issueId status");
        assert(f.status === "unknown", "Unverified issuer outcome");
        current.status = "unknown";
      }
    } else if (event.kind === "publish_intent") {
      exact(f, "run attempt issueId");
      const current = attemptFor(state, f);
      assert(
        current.status === "issued" && current.issueId === f.issueId,
        "Publication lacks current capability",
      );
      current.status = "publishing";
    } else if (event.kind === "publication") {
      const current = attemptFor(state, f);
      assert(current.status === "publishing", "Unexpected publication outcome");
      if (f.status === "published") {
        exact(f, "run attempt status observedDigest");
        assert.equal(
          f.observedDigest,
          current.fields.artifactDigest,
          "Published asset digest differs",
        );
        current.observedDigest = f.observedDigest;
        current.status = "published";
      } else {
        exact(f, "run attempt status");
        assert(f.status === "unknown", "Unverified publication outcome");
        current.status = "unknown";
      }
    } else if (event.kind === "reconciliation") {
      exact(f, "run attempt status observedDigest");
      const current = attemptFor(state, f);
      assert(
        ["issuing", "issued", "publishing", "unknown"].includes(current.status),
        "Nothing to reconcile",
      );
      assert(hash.test(f.observedDigest as string), "Missing reconciliation evidence digest");
      assert(f.status === "safe" || f.status === "published", "Unverified reconciliation outcome");
      if (f.status === "published") current.observedDigest = current.fields.artifactDigest;
      current.status = f.status;
    } else throw new Error("Unexpected registry event");
  }
  return state;
}

/**
 * Persistence primitive only. Its caller must independently authenticate the approved origin and
 * provider observations before recording anything; these methods cannot authorize live publication.
 */
export class BootstrapRegistry {
  readonly #journal: BootstrapJournal;
  constructor(journal: BootstrapJournal) {
    this.#journal = journal;
  }
  #state(): State {
    return replayBootstrap(this.#journal.read().map((entry) => entry.event));
  }
  #append(event: JournalEvent): void {
    const candidate = this.#journal.read().map((entry) => entry.event);
    replayBootstrap([...candidate, event]);
    this.#journal.append(event);
  }
  reserve(
    approval: ApprovedBootstrap,
    target: AttemptTarget,
  ): "ready" | "reconcile" | "readback" | "association-required" {
    let state = this.#state();
    const expectedAuth = authorization(approval);
    if (!state.authorization) {
      this.#append({ kind: "authorization", fields: expectedAuth });
      state = this.#state();
    }
    assert.deepEqual(state.authorization, expectedAuth, "Another bootstrap is not authorized");
    assert(state.authorization);
    const fields = targetFields(target, state.authorization);
    const existing = state.attempts.get(key(fields));
    if (existing) assert.deepEqual(existing.fields, fields, "Immutable attempt target differs");
    if (target.run !== approval.originalRun && !state.associations.has(target.run))
      return "association-required";
    if (!existing) {
      this.#append({ kind: "attempt", fields });
      state = this.#state();
    }
    const all = [...state.attempts.values()];
    if (all.some((attempt) => attempt.status === "published")) return "readback";
    if (all.some((attempt) => !["prepared", "safe"].includes(attempt.status))) return "reconcile";
    return "ready"; // caller must freshly verify external authority and, after earlier attempts, reconcile again
  }
  /** Records a digest only after the caller authenticated a real association with the original event.
   * A digest, this method or a caller-provided statement is not itself authority. */
  associateRun(approval: ApprovedBootstrap, run: string, associationDigest: string): void {
    const state = this.#state();
    assert.deepEqual(
      state.authorization,
      authorization(approval),
      "Another bootstrap is not authorized",
    );
    assert(validNumber(run) && run !== approval.originalRun && hash.test(associationDigest));
    const existing = state.associations.get(run);
    if (existing !== undefined) {
      assert.equal(existing, associationDigest, "Run association is immutable");
      return;
    }
    this.#append({
      kind: "run_association",
      fields: {
        run,
        originalRun: approval.originalRun,
        producer: approval.merge,
        eventDigest: approval.eventDigest,
        associationDigest,
      },
    });
  }
  #assertTarget(target: AttemptTarget): void {
    const state = this.#state();
    assert(state.authorization, "Missing bootstrap authorization");
    const fields = targetFields(target, state.authorization);
    assert.deepEqual(
      state.attempts.get(key(fields))?.fields,
      fields,
      "Immutable attempt target differs",
    );
  }
  issueIntent(target: AttemptTarget, issueId: string): void {
    this.#assertTarget(target);
    this.#append({
      kind: "issue_intent",
      fields: { run: target.run, attempt: target.attempt, issueId },
    });
  }
  issueResult(
    target: AttemptTarget,
    issueId: string,
    result: { status: "issued"; capabilityId: string } | { status: "unknown" },
  ): void {
    this.#assertTarget(target);
    this.#append({
      kind: "issue_result",
      fields: { run: target.run, attempt: target.attempt, issueId, ...result },
    });
  }
  publicationIntent(target: AttemptTarget, issueId: string): void {
    this.#assertTarget(target);
    this.#append({
      kind: "publish_intent",
      fields: { run: target.run, attempt: target.attempt, issueId },
    });
  }
  publication(
    target: AttemptTarget,
    result: { status: "published"; observedDigest: string } | { status: "unknown" },
  ): void {
    this.#assertTarget(target);
    this.#append({
      kind: "publication",
      fields: { run: target.run, attempt: target.attempt, ...result },
    });
  }
  reconciliation(
    target: AttemptTarget,
    status: "safe" | "published",
    observedDigest: string,
  ): void {
    this.#assertTarget(target);
    this.#append({
      kind: "reconciliation",
      fields: { run: target.run, attempt: target.attempt, status, observedDigest },
    });
  }
}
