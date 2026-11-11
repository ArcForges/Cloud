// SPDX-License-Identifier: AGPL-3.0-only
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { createHash, randomBytes } from "node:crypto";
import { verifyCollectorIdentityWithKeys } from "../../tooling/ctr06-bootstrap-oidc.ts";
import path from "node:path";
import { test } from "node:test";
import { runIsolatedBroker } from "../../tooling/ctr06-bootstrap-broker.ts";
import { BootstrapJournal } from "../../tooling/ctr06-bootstrap-journal.ts";
import { replayBootstrap } from "../../tooling/ctr06-bootstrap-registry.ts";
import {
  approval,
  prepareSyntheticGate,
  SyntheticAuthority,
  target,
  testProfile,
} from "./support/ctr06-bootstrap-mock.ts";
import { scratchDirectory } from "./support/scratch.ts";

if (process.platform === "linux") {
  test("mock external provider drives real proof, journal, issuer/use/revoke and checked publication", async (t) => {
    const root = scratchDirectory("ctr06-broker-", t);
    const journal = new BootstrapJournal(root);
    const mock = new SyntheticAuthority();
    const first = await runIsolatedBroker(journal, target(), testProfile, mock);
    assert.deepEqual(first, {
      tag: target().release,
      artifactDigest: target().artifactDigest,
      artifactSize: mock.assetSize,
      receiptDigest: target().receiptDigest,
      receiptSize: Number(target().receiptSize),
      merge: target().producer,
      run: target().run,
      runNumber: target().runNumber,
      attempt: target().attempt,
      sourceArtifactId: target().artifactId,
      releaseId: "9001",
      assetId: "9002",
      receiptAssetId: "9003",
    });
    assert.deepEqual(mock.calls, [
      "reviewed",
      "gate-proof",
      "gate-readback",
      "coverage",
      "artifact",
      "observe:issue",
      "coverage",
      "lease",
      "issue",
      "coverage",
      "lease",
      "observe:use",
      "coverage",
      "lease",
      "lease",
      "publish",
      "coverage",
      "lease",
      "revoke",
      "history",
      "history-authenticated",
      "revoke",
    ]);
    const events = journal.read();
    assert.deepEqual(
      events.map((x) => x.event.kind),
      ["authorization", "attempt", "issue_intent", "issue_result", "publish_intent", "publication"],
    );
    assert(!JSON.stringify(events).includes("PRIVATE-CAPABILITY"));
    const issueCount = mock.calls.filter((x) => x === "issue").length;
    assert.deepEqual(await runIsolatedBroker(journal, target(), testProfile, mock), first);
    assert.deepEqual(await runIsolatedBroker(journal, target("2"), testProfile, mock), first);
    assert.equal(mock.calls.filter((x) => x === "issue").length, issueCount);
    await assert.rejects(
      runIsolatedBroker(
        journal,
        { ...target(), artifactDigest: "0".repeat(64) },
        testProfile,
        mock,
      ),
      /Bootstrap broker refused/,
    );
    journal.close();
  });

  test("pre-artifact gate proof is historical; issuance still requires a fresh proof and lease", async (t) => {
    const root = scratchDirectory("ctr06-gate-order-", t);
    const journal = new BootstrapJournal(root);
    const mock = new SyntheticAuthority();
    const challenge = randomBytes(32).toString("hex");
    const beforeArtifact = {
      producer: approval.merge,
      run: "123",
      runNumber: "456",
      attempt: "1",
      eventDigest: approval.eventDigest,
      gateChallenge: challenge,
    };
    const proof = prepareSyntheticGate(beforeArtifact);
    assert.equal("artifactId" in beforeArtifact, false);
    assert.throws(() =>
      verifyCollectorIdentityWithKeys(
        proof.payload,
        proof.token,
        testProfile.collector,
        Math.floor(Date.now() / 1000),
        testProfile.softwareJwks,
      ),
    );
    mock.retainPreparedGate(proof);
    const afterBuild = target("1", "123", "456", challenge);
    assert.equal(afterBuild.gateDigest, createHash("sha256").update(proof.payload).digest("hex"));
    const result = await runIsolatedBroker(journal, afterBuild, testProfile, mock);
    assert.equal(result.tag, afterBuild.release);
    assert(mock.calls.indexOf("gate-proof") < mock.calls.indexOf("artifact"));
    assert(mock.calls.indexOf("artifact") < mock.calls.indexOf("observe:issue"));
    assert(mock.calls.indexOf("observe:issue") < mock.calls.indexOf("issue"));
    assert(mock.calls.indexOf("observe:use") < mock.calls.indexOf("publish"));
    journal.close();
  });

  test("lost publication response remains UNKNOWN and later returns actual existing release", async (t) => {
    const root = scratchDirectory("ctr06-broker-", t);
    let journal = new BootstrapJournal(root);
    const mock = new SyntheticAuthority();
    mock.failure = "publish-unknown";
    await assert.rejects(
      runIsolatedBroker(journal, target(), testProfile, mock),
      /Bootstrap broker refused/,
    );
    assert.equal(
      [...replayBootstrap(journal.read().map((x) => x.event)).attempts.values()][0]?.status,
      "unknown",
    );
    journal.close();
    journal = new BootstrapJournal(root);
    mock.failure = "";
    const result = await runIsolatedBroker(journal, target("2"), testProfile, mock);
    assert.equal(result.tag, target().release);
    assert.equal(mock.calls.filter((x) => x === "issue").length, 1);
    journal.close();
  });

  test("unknown live credential and unavailable readback block later attempt and cross-run", async (t) => {
    const root = scratchDirectory("ctr06-broker-", t);
    const journal = new BootstrapJournal(root);
    const mock = new SyntheticAuthority();
    mock.failure = "issue-unknown";
    mock.blockRevocation = true;
    await assert.rejects(
      runIsolatedBroker(journal, target(), testProfile, mock),
      /Bootstrap broker refused/,
    );
    mock.failure = "";
    await assert.rejects(
      runIsolatedBroker(journal, target("2"), testProfile, mock),
      /Bootstrap broker refused/,
    );
    await assert.rejects(
      runIsolatedBroker(journal, target("1", "124", "457"), testProfile, mock),
      /Bootstrap broker refused/,
    );
    assert.equal(mock.calls.filter((x) => x === "issue").length, 1);
    mock.historyUnavailable = true;
    await assert.rejects(
      runIsolatedBroker(journal, target("2"), testProfile, mock),
      /Bootstrap broker refused/,
    );
    assert.equal(mock.calls.filter((x) => x === "issue").length, 1);
    journal.close();
  });

  test("verified no effect and issuer revocation permit genuine cross-run retry under original authorization", async (t) => {
    const root = scratchDirectory("ctr06-broker-", t);
    let journal = new BootstrapJournal(root);
    const mock = new SyntheticAuthority();
    mock.failure = "issue-unknown";
    await assert.rejects(runIsolatedBroker(journal, target(), testProfile, mock));
    journal.close();
    journal = new BootstrapJournal(root);
    mock.failure = "";
    const actual = target("1", "124", "457");
    assert.equal((await runIsolatedBroker(journal, actual, testProfile, mock)).tag, actual.release);
    const kinds = journal.read().map((x) => x.event.kind);
    assert.equal(kinds.filter((x) => x === "authorization").length, 1);
    assert.equal(kinds.filter((x) => x === "run_association").length, 1);
    assert(kinds.includes("reconciliation"));
    journal.close();
  });

  test("invalid or replayed observations, missing source pages and denied paths never issue", async (t) => {
    for (const failure of [
      "missing-domain",
      "missing-page",
      "revision",
      "database",
      "issuer",
      "expired",
      "lease-loss",
      "coverage",
      "tampered-artifact",
    ]) {
      const root = scratchDirectory("ctr06-broker-", t);
      const journal = new BootstrapJournal(root);
      const mock = new SyntheticAuthority();
      mock.failure = failure;
      await assert.rejects(runIsolatedBroker(journal, target(), testProfile, mock));
      assert.equal(mock.calls.includes("issue"), false, failure);
      journal.close();
    }
    const root = scratchDirectory("ctr06-broker-", t);
    const journal = new BootstrapJournal(root);
    const mock = new SyntheticAuthority();
    mock.failure = "issue-unknown";
    await assert.rejects(
      runIsolatedBroker(journal, target(), testProfile, mock),
      /Bootstrap broker refused/,
    );
    mock.failure = "replay";
    await assert.rejects(
      runIsolatedBroker(journal, target(), testProfile, mock),
      /Bootstrap broker refused/,
    );
    assert.equal(mock.calls.filter((x) => x === "issue").length, 1);
    assert.equal(mock.calls.includes("publish"), false);
    journal.close();
  });

  test("signed gate and fresh issue/use observations require each distinct source and its matching fenced evidence", async (t) => {
    const failures = [
      "missing-domain",
      "missing-page",
      "revision",
      "provider",
      "namespace",
      "old-observation",
      "observation-identity",
      "page-digest",
      "receipt",
      "missing-receipt",
      "missing-attestation",
      "forged-observation",
      "forged-receipt",
      "fence",
      "unknown-control",
      "missing-lease-source",
      "pseudo-aggregate",
    ];
    for (const failure of failures) {
      const root = scratchDirectory("ctr06-gate-sources-", t);
      const journal = new BootstrapJournal(root);
      const mock = new SyntheticAuthority();
      const request = target();
      const proof = prepareSyntheticGate(request, failure);
      request.gateDigest = createHash("sha256").update(proof.payload).digest("hex");
      mock.retainPreparedGate(proof);
      await assert.rejects(runIsolatedBroker(journal, request, testProfile, mock), failure);
      assert.deepEqual(journal.read(), [], failure);
      journal.close();
    }
    for (const phase of ["issue", "use"])
      for (const failure of failures) {
        const root = scratchDirectory("ctr06-fresh-sources-", t);
        const journal = new BootstrapJournal(root);
        const mock = new SyntheticAuthority();
        mock.failure = failure;
        mock.failurePhase = phase;
        await assert.rejects(
          runIsolatedBroker(journal, target(), testProfile, mock),
          `${phase}:${failure}`,
        );
        assert.equal(mock.actual, undefined, `${phase}:${failure}`);
        if (phase === "issue") assert.equal(mock.entries.size, 0, failure);
        journal.close();
      }
  });

  test("actual time after delayed keys, coverage, lease, journal and boundary blocks expired issue/use proofs", async (t) => {
    const sleep = () => new Promise<void>((resolve) => setTimeout(resolve, 1250));
    for (const phase of ["issue", "use"] as const)
      for (const stage of ["keys", "coverage", "lease", "journal", "boundary"] as const) {
        const root = scratchDirectory("ctr06-expiry-", t);
        const journal = new BootstrapJournal(root);
        const mock = new SyntheticAuthority();
        mock.tokenLifetimeSeconds = 1;
        let delayed = false;
        const delay = async () => {
          if (!delayed && mock.phase === phase) {
            delayed = true;
            await sleep();
          }
        };
        const profile = { ...testProfile, beforeKeys: stage === "keys" ? delay : undefined };
        if (stage === "coverage") {
          const original = mock.verifyCoverage.bind(mock);
          mock.verifyCoverage = async (...args) => {
            await delay();
            await original(...args);
          };
        }
        if (stage === "lease") {
          const original = mock.verifyLease.bind(mock);
          mock.verifyLease = async (...args) => {
            await delay();
            await original(...args);
          };
        }
        if (stage === "journal") {
          const original = journal.append.bind(journal);
          journal.append = (event) => {
            const result = original(event);
            if (
              !delayed &&
              event.kind === (phase === "issue" ? "issue_intent" : "publish_intent")
            ) {
              delayed = true;
              Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, 1250);
            }
            return result;
          };
        }
        if (stage === "boundary" && phase === "issue") {
          const original = mock.issue.bind(mock);
          mock.issue = async (...args) => {
            await delay();
            return original(...args);
          };
        }
        if (stage === "boundary" && phase === "use") {
          const original = mock.publish.bind(mock);
          mock.publish = async (...args) => {
            await delay();
            return original(...args);
          };
        }
        await assert.rejects(
          runIsolatedBroker(journal, target(), profile, mock),
          `${phase}:${stage}`,
        );
        assert.equal(delayed, true, `${phase}:${stage}`);
        assert.equal(mock.actual, undefined, `${phase}:${stage}`);
        if (phase === "issue") assert.equal(mock.entries.size, 0, `${phase}:${stage}`);
        else for (const entry of mock.entries.values()) assert.notEqual(entry.credential, "active");
        journal.close();
      }
  });

  test("issuer and publisher independently reject altered authenticated windows, source fences and stale workers", async (t) => {
    for (const phase of ["issue", "use"] as const)
      for (const mutation of ["window", "fence", "payload", "stale-worker"] as const) {
        const root = scratchDirectory("ctr06-fenced-effect-", t);
        const journal = new BootstrapJournal(root);
        const mock = new SyntheticAuthority();
        const alter = (authorization: Parameters<typeof mock.issue>[2]) => {
          if (mutation === "stale-worker") {
            mock.currentFence = "new-fence";
            return authorization;
          }
          if (mutation === "window")
            return {
              ...authorization,
              window: { ...authorization.window, expiresAt: authorization.window.expiresAt + 120 },
            };
          if (mutation === "fence")
            return { ...authorization, lease: { ...authorization.lease, fence: "other-fence" } };
          return {
            ...authorization,
            proof: {
              ...authorization.proof,
              payload: Buffer.concat([authorization.proof.payload, Buffer.from(" ")]),
            },
          };
        };
        if (phase === "issue") {
          const original = mock.issue.bind(mock);
          mock.issue = (request, issueId, proof) => original(request, issueId, alter(proof));
        } else {
          const original = mock.publish.bind(mock);
          mock.publish = (request, issueId, capability, proof, artifact) =>
            original(request, issueId, capability, alter(proof), artifact);
        }
        await assert.rejects(
          runIsolatedBroker(journal, target(), testProfile, mock),
          `${phase}:${mutation}`,
        );
        assert.equal(mock.actual, undefined, `${phase}:${mutation}`);
        if (phase === "issue") assert.equal(mock.entries.size, 0, mutation);
        else for (const entry of mock.entries.values()) assert.notEqual(entry.credential, "active");
        journal.close();
      }
  });

  test("public and private release conflicts cannot authorize repeat or another run", async (t) => {
    for (const mode of ["public-unknown", "private-absent", "history-unavailable"]) {
      const root = scratchDirectory("ctr06-release-views-", t);
      const journal = new BootstrapJournal(root);
      const mock = new SyntheticAuthority();
      await runIsolatedBroker(journal, target(), testProfile, mock);
      if (mode === "public-unknown") mock.publicUnknown = true;
      if (mode === "history-unavailable") mock.historyUnavailable = true;
      if (mode === "private-absent") mock.privateAbsent = true;
      for (const request of [target(), target("2"), target("1", "124", "457")])
        await assert.rejects(runIsolatedBroker(journal, request, testProfile, mock), mode);
      assert.equal(mock.calls.filter((call) => call === "issue").length, 1);
      assert(mock.publicReads > 0 || mode === "history-unavailable");
      journal.close();
    }
  });

  test("gate proof digest, challenge, signature and authenticated readback bind issuance to the actual attempt", async (t) => {
    for (const failure of ["digest", "challenge", "signature", "readback"]) {
      const root = scratchDirectory("ctr06-gate-", t);
      const journal = new BootstrapJournal(root);
      const mock = new SyntheticAuthority();
      let request = target();
      if (failure === "digest") request = { ...request, gateDigest: "0".repeat(64) };
      if (failure === "challenge") request = { ...request, gateChallenge: "0".repeat(64) };
      if (failure === "readback") mock.failure = "gate-readback";
      if (failure === "signature") {
        const original = mock.readGate.bind(mock);
        mock.readGate = async (...args) => {
          const proof = await original(...args);
          return { ...proof, token: `${proof.token.slice(0, -3)}bad` };
        };
      }
      await assert.rejects(runIsolatedBroker(journal, request, testProfile, mock));
      assert.equal(mock.calls.includes("issue"), false, failure);
      assert.deepEqual(journal.read(), []);
      journal.close();
    }
  });

  test("external errors never return provider text, capability material or raw OIDC", async (t) => {
    const root = scratchDirectory("ctr06-broker-redact-", t);
    const journal = new BootstrapJournal(root);
    const mock = new SyntheticAuthority();
    mock.readGate = async () => {
      throw new Error("PRIVATE-CAPABILITY-FIXTURE RAW-OIDC-FIXTURE");
    };
    await assert.rejects(
      runIsolatedBroker(journal, target(), testProfile, mock),
      (error: Error) => {
        assert.equal(error.message, "Bootstrap broker refused; reconcile any uncertain outcome");
        assert.doesNotMatch(error.stack ?? "", /PRIVATE-CAPABILITY-FIXTURE|RAW-OIDC-FIXTURE/);
        return true;
      },
    );
    assert.deepEqual(journal.read(), []);
    journal.close();
  });

  test("cancellation after issuance revokes and requires real readback before retry", async (t) => {
    const root = scratchDirectory("ctr06-broker-", t);
    let journal = new BootstrapJournal(root);
    const mock = new SyntheticAuthority();
    const controller = new AbortController();
    const original = mock.issue.bind(mock);
    mock.issue = async (...args) => {
      const issued = await original(...args);
      controller.abort();
      return issued;
    };
    await assert.rejects(
      runIsolatedBroker(journal, target(), testProfile, mock, controller.signal),
      {
        name: "AbortError",
      },
    );
    assert.equal(mock.calls.includes("publish"), false);
    assert.equal(
      [...replayBootstrap(journal.read().map((x) => x.event)).attempts.values()][0]?.status,
      "issued",
    );
    journal.close();
    journal = new BootstrapJournal(root);
    mock.issue = original;
    assert.equal(
      (await runIsolatedBroker(journal, target("2"), testProfile, mock)).tag,
      target("2").release,
    );
    assert(mock.calls.includes("history"));
    journal.close();
  });

  test("cancellation after publication records UNKNOWN and recovers only the actual release", async (t) => {
    const root = scratchDirectory("ctr06-broker-", t);
    const journal = new BootstrapJournal(root);
    const mock = new SyntheticAuthority();
    const controller = new AbortController();
    const original = mock.publish.bind(mock);
    mock.publish = async (...args) => {
      await original(...args);
      controller.abort();
    };
    await assert.rejects(
      runIsolatedBroker(journal, target(), testProfile, mock, controller.signal),
      {
        name: "AbortError",
      },
    );
    assert.equal(
      [...replayBootstrap(journal.read().map((x) => x.event)).attempts.values()][0]?.status,
      "unknown",
    );
    assert.equal(
      (await runIsolatedBroker(journal, target("2"), testProfile, mock)).tag,
      target().release,
    );
    assert.equal(mock.calls.filter((x) => x === "issue").length, 1);
    journal.close();
  });

  test("real journal lock excludes concurrent worker while issuer call is in flight", async (t) => {
    const root = scratchDirectory("ctr06-broker-", t);
    const journal = new BootstrapJournal(root);
    const mock = new SyntheticAuthority();
    let release!: () => void;
    let ready!: () => void;
    const waiting = new Promise<void>((resolve) => {
      release = resolve;
    });
    const entered = new Promise<void>((resolve) => {
      ready = resolve;
    });
    const original = mock.issue.bind(mock);
    mock.issue = async (...args) => {
      ready();
      await waiting;
      return original(...args);
    };
    const pending = runIsolatedBroker(journal, target(), testProfile, mock);
    await entered;
    assert.throws(() => new BootstrapJournal(root), /EEXIST/);
    assert.match(readFileSync(path.join(root, "event-00000003.json"), "utf8"), /issue_intent/);
    release();
    await pending;
    journal.close();
  });
} else {
  test("the real broker journal is not supported on Windows", () => {
    assert.throws(() => new BootstrapJournal(path.resolve("ctr06-not-created")), /only on Linux/);
  });
}
