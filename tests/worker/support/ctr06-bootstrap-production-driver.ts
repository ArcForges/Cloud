// SPDX-License-Identifier: AGPL-3.0-only
// This separate process substitutes only unavailable authority configuration and HTTPS transports.
// The production-kind broker entry, parsers, RSA verification, journal and decisions remain real.
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { mock, test } from "node:test";
import {
  requireFreshWindow,
  verifyCollectorIdentityWithKeys,
} from "../../../tooling/ctr06-bootstrap-oidc.ts";
import { scratchDirectory } from "./scratch.ts";

let reviewedProfile: unknown;
mock.module(new URL("../../../tooling/ctr06-bootstrap-profile.ts", import.meta.url).href, {
  namedExports: {
    requireReviewedAuthorityProfile: () => {
      assert(reviewedProfile, "No isolated reviewed profile fixture");
      return reviewedProfile;
    },
  },
});
const { runProductionBroker } = await import("../../../tooling/ctr06-bootstrap-broker.ts");
const { BootstrapJournal } = await import("../../../tooling/ctr06-bootstrap-journal.ts");
const {
  SyntheticAuthority,
  approval,
  githubFixture,
  sourceProfiles,
  target,
  testProfile,
  instrumentInternalLease,
  checkInternalLease,
} = await import("./ctr06-bootstrap-mock.ts");

test("production kind uses real decisions for success, safe-empty, conflict and expiry", async (t) => {
  const originalFetch = globalThis.fetch;
  let current = target();
  let external = new SyntheticAuthority();
  let delayPhase = "";
  let delayMs = 1250;
  let delayed = false;
  let waitForAuthenticatedExpiry = false;
  let expiry: {
    window?: ReturnType<typeof verifyCollectorIdentityWithKeys>;
    proof?: { payload: Buffer; token: string };
    digest: string;
    reachedAt: number;
  } = { digest: "", reachedAt: -1 };
  let publicReads = 0;
  reviewedProfile = {
    kind: "github-oidc",
    collectorSourceSha: "9".repeat(40),
    requiredSources: sourceProfiles,
    collectorRun: async () => ({ sourceSha: "9".repeat(40), runId: "345", runAttempt: "1" }),
    createPorts: () => external,
  };
  globalThis.fetch = async (input) => {
    const url = String(input);
    if (url === "https://token.actions.githubusercontent.com/.well-known/jwks") {
      if (!delayed && delayPhase && external.phase === delayPhase) {
        delayed = true;
        if (waitForAuthenticatedExpiry) {
          const window = expiry.window;
          assert(window, "Target proof must be authenticated before its JWKS wait");
          const remaining = window.expiresAt * 1000 - Date.now();
          assert(remaining > 0 && remaining <= 5000, "Target proof must be fresh at JWKS entry");
          expiry.reachedAt = Math.floor(Date.now() / 1000);
          await new Promise<void>((resolve) => setTimeout(resolve, remaining + 50));
          assert(Math.floor(Date.now() / 1000) >= window.expiresAt);
        } else {
          await new Promise<void>((resolve) => setTimeout(resolve, delayMs));
        }
      }
      return new Response(testProfile.softwareJwks.toString("utf8"));
    }
    const prefix = "https://api.github.com/repos/ArcForges/Cloud";
    assert(url.startsWith(prefix), "Unexpected external test transport");
    const path = url.slice(prefix.length);
    const answers = githubFixture(current);
    if (path in answers) return new Response(JSON.stringify(answers[path]));
    publicReads++;
    const value = external.publicMetadata(external.actual ?? current, path);
    return value === null
      ? new Response(null, { status: 404 })
      : new Response(JSON.stringify(value));
  };
  try {
    {
      const journal = new BootstrapJournal(scratchDirectory("ctr06-production-kind-success-", t));
      const first = await runProductionBroker(journal, current);
      assert.equal(first.tag, current.release);
      assert.deepEqual(await runProductionBroker(journal, current), first);
      current = target("2");
      assert.deepEqual(await runProductionBroker(journal, current), first);
      assert.equal(external.calls.filter((value) => value === "issue").length, 1);
      assert(publicReads > 0);
      external.publicUnknown = true;
      const previousReads = publicReads;
      current = target("1", "124", "457");
      await assert.rejects(runProductionBroker(journal, current));
      assert(
        publicReads > previousReads,
        "production branch must read the conflicting public state",
      );
      assert.equal(external.calls.filter((value) => value === "issue").length, 1);
      external.publicUnknown = false;
      external.privateAbsent = true;
      const beforePrivateConflict = publicReads;
      await assert.rejects(runProductionBroker(journal, current));
      assert(
        publicReads > beforePrivateConflict,
        "production branch must compare both release sources",
      );
      assert.equal(external.calls.filter((value) => value === "issue").length, 1);
      journal.close();
    }
    {
      external = new SyntheticAuthority();
      current = target();
      const journal = new BootstrapJournal(scratchDirectory("ctr06-production-kind-retry-", t));
      external.failure = "issue-unknown";
      await assert.rejects(runProductionBroker(journal, current));
      external.failure = "";
      current = target("1", "124", "457");
      const actual = await runProductionBroker(journal, current);
      assert.equal(actual.tag, current.release);
      assert.equal(external.calls.filter((value) => value === "issue").length, 2);
      journal.close();
    }
    {
      external = new SyntheticAuthority();
      current = target();
      const journal = new BootstrapJournal(scratchDirectory("ctr06-production-kind-live-cap-", t));
      external.failure = "issue-unknown";
      external.blockRevocation = true;
      await assert.rejects(runProductionBroker(journal, current));
      external.failure = "";
      current = target("2");
      await assert.rejects(runProductionBroker(journal, current));
      assert.equal(external.calls.filter((value) => value === "issue").length, 1);
      journal.close();
    }
    for (const phase of ["issue", "use"] as const) {
      external = new SyntheticAuthority();
      current = target();
      delayPhase = phase;
      delayed = false;
      waitForAuthenticatedExpiry = true;
      expiry = { digest: "", reachedAt: -1 };
      const observe = external.observe.bind(external);
      external.observe = async (...args) => {
        // Keep all preceding non-target proofs valid while reaching the intended target phase.
        external.tokenLifetimeSeconds = args[1] === phase ? 5 : 60;
        const proof = await observe(...args);
        if (args[1] === phase) {
          expiry.proof = proof;
          expiry.digest = createHash("sha256").update(proof.payload).digest("hex");
          expiry.window = verifyCollectorIdentityWithKeys(
            proof.payload,
            proof.token,
            testProfile.collector,
            Math.floor(Date.now() / 1000),
            testProfile.softwareJwks,
          );
        }
        return proof;
      };
      const journal = new BootstrapJournal(scratchDirectory("ctr06-production-kind-expiry-", t));
      await assert.rejects(
        runProductionBroker(journal, current),
        /^Error: Bootstrap broker refused; reconcile any uncertain outcome$/,
      );
      assert.equal(delayed, true, `${phase}: target JWKS boundary not reached`);
      const checkedProof = expiry.proof;
      const checkedWindow = expiry.window;
      assert(checkedProof && checkedWindow, `${phase}: no authenticated target proof`);
      const now = Math.floor(Date.now() / 1000);
      const timing = external.lastTiming[phase];
      assert(timing && now < timing.leaseEnd && now - timing.collectedAt <= 120);
      assert(expiry.reachedAt < checkedWindow.expiresAt && now >= checkedWindow.expiresAt);
      assert.equal(createHash("sha256").update(checkedProof.payload).digest("hex"), expiry.digest);
      assert.throws(() => requireFreshWindow(checkedWindow, now), /not fresh/);
      assert.throws(() =>
        verifyCollectorIdentityWithKeys(
          checkedProof.payload,
          checkedProof.token,
          testProfile.collector,
          now,
          testProfile.softwareJwks,
        ),
      );
      assert.equal(external.actual, undefined);
      if (phase === "issue") assert.equal(external.entries.size, 0);
      else
        for (const entry of external.entries.values()) assert.notEqual(entry.credential, "active");
      console.log(
        JSON.stringify({
          kind: "github-oidc",
          phase,
          stage: "keys",
          reachedAt: expiry.reachedAt,
          authenticatedExpiry: checkedWindow.expiresAt,
          refusedAt: now,
          sourceAgeAtRefusal: now - timing.collectedAt,
          leaseRemaining: timing.leaseEnd - now,
          rejection: "sanitized-broker-refusal-after-authenticated-expiry",
        }),
      );
      journal.close();
    }
    waitForAuthenticatedExpiry = false;
    for (const phase of ["issue", "use"] as const)
      for (const stage of ["keys", "coverage", "lease", "journal", "boundary"] as const) {
        external = new SyntheticAuthority();
        external.sourceAgeSeconds = 119;
        external.sourceAgePhase = phase;
        current = target();
        delayPhase = stage === "keys" ? phase : "";
        delayMs = 2100;
        delayed = false;
        const journal = new BootstrapJournal(
          scratchDirectory("ctr06-production-kind-source-age-", t),
        );
        const delay = async () => {
          if (!delayed && external.phase === phase) {
            delayed = true;
            await new Promise<void>((resolve) => setTimeout(resolve, 2100));
          }
        };
        if (stage === "coverage") {
          const original = external.verifyCoverage.bind(external);
          external.verifyCoverage = async (...args) => {
            await delay();
            await original(...args);
          };
        }
        if (stage === "lease") {
          const original = external.verifyLease.bind(external);
          external.verifyLease = async (...args) => {
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
              Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, 2100);
            }
            return result;
          };
        }
        if (stage === "boundary" && phase === "issue") {
          const original = external.issue.bind(external);
          external.issue = async (...args) => {
            await delay();
            return original(...args);
          };
        }
        if (stage === "boundary" && phase === "use") {
          const original = external.publish.bind(external);
          external.publish = async (...args) => {
            await delay();
            return original(...args);
          };
        }
        await assert.rejects(runProductionBroker(journal, current), `${phase}:${stage}`);
        const timing = external.lastTiming[phase];
        assert(timing && delayed);
        const now = Math.floor(Date.now() / 1000);
        assert(now - timing.collectedAt > 120 && now < timing.expiresAt && now < timing.leaseEnd);
        assert.equal(external.actual, undefined);
        if (phase === "issue") assert.equal(external.entries.size, 0);
        else
          for (const entry of external.entries.values())
            assert.notEqual(entry.credential, "active");
        console.log(
          JSON.stringify({
            kind: "github-oidc",
            phase,
            stage,
            sourceAgeAtRefusal: now - timing.collectedAt,
            jwtRemaining: timing.expiresAt - now,
            leaseRemaining: timing.leaseEnd - now,
          }),
        );
        journal.close();
      }
    for (const phase of ["issue", "use"] as const) {
      external = new SyntheticAuthority();
      external.sourceAgeSeconds = 119;
      external.sourceAgePhase = phase;
      current = target();
      delayPhase = "";
      delayed = false;
      const journal = new BootstrapJournal(
        scratchDirectory("ctr06-production-kind-source-boundary-", t),
      );
      let observedAge = -1;
      const waitAtBoundary = async () => {
        const timing = external.lastTiming[phase];
        assert(timing);
        const delay = Math.max(0, (timing.collectedAt + 120) * 1000 + 50 - Date.now());
        await new Promise<void>((resolve) => setTimeout(resolve, delay));
        observedAge = Math.floor(Date.now() / 1000) - timing.collectedAt;
        assert.equal(observedAge, 120);
      };
      if (phase === "issue") {
        const original = external.issue.bind(external);
        external.issue = async (...args) => {
          await waitAtBoundary();
          return original(...args);
        };
      } else {
        const original = external.publish.bind(external);
        external.publish = async (...args) => {
          await waitAtBoundary();
          return original(...args);
        };
      }
      assert.equal((await runProductionBroker(journal, current)).tag, current.release);
      assert.equal(observedAge, 120);
      console.log(
        JSON.stringify({
          kind: "github-oidc",
          phase,
          sourceAgeAtBoundary: observedAge,
          effect: "accepted",
        }),
      );
      journal.close();
    }
    for (const phase of ["issue", "use"] as const)
      for (const crossed of [false, true]) {
        external = new SyntheticAuthority();
        // Exercise the same real helper using production-kind identity verification too; only
        // unavailable HTTPS/JWKS and provider ports are substituted by this isolated driver.
        external.effectProfile = reviewedProfile as typeof external.effectProfile;
        current = target();
        delayPhase = "";
        delayed = false;
        const journal = new BootstrapJournal(
          scratchDirectory("ctr06-production-kind-helper-lease-age-", t),
        );
        const trace = instrumentInternalLease(external, phase, crossed);
        if (crossed) {
          await assert.rejects(
            runProductionBroker(journal, current),
            /^Error: Bootstrap broker refused; reconcile any uncertain outcome$/,
          );
          assert.equal(external.actual, undefined);
          if (phase === "issue") assert.equal(external.entries.size, 0);
          else
            for (const entry of external.entries.values()) {
              assert.notEqual(entry.operation, "published");
              assert.notEqual(entry.credential, "active");
            }
        } else {
          assert.equal((await runProductionBroker(journal, current)).tag, current.release);
        }
        console.log(
          JSON.stringify({
            kind: "github-oidc",
            effectVerifierProfile: external.effectProfile.kind,
            ...checkInternalLease(trace, external, current, phase, crossed),
          }),
        );
        journal.close();
      }
    assert.equal(approval.merge, current.producer);
  } finally {
    globalThis.fetch = originalFetch;
    reviewedProfile = undefined;
  }
});
