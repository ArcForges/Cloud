// SPDX-License-Identifier: AGPL-3.0-only
// This separate process substitutes only unavailable authority configuration and HTTPS transports.
// The production-kind broker entry, parsers, RSA verification, journal and decisions remain real.
import assert from "node:assert/strict";
import { mock, test } from "node:test";
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
const { SyntheticAuthority, approval, githubFixture, sourceProfiles, target, testProfile } =
  await import("./ctr06-bootstrap-mock.ts");

test("production kind uses real decisions for success, safe-empty, conflict and expiry", async (t) => {
  const originalFetch = globalThis.fetch;
  let current = target();
  let external = new SyntheticAuthority();
  let delayPhase = "";
  let delayed = false;
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
        await new Promise<void>((resolve) => setTimeout(resolve, 1250));
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
    for (const phase of ["issue", "use"]) {
      external = new SyntheticAuthority();
      external.tokenLifetimeSeconds = 1;
      current = target();
      delayPhase = phase;
      delayed = false;
      const journal = new BootstrapJournal(scratchDirectory("ctr06-production-kind-expiry-", t));
      await assert.rejects(runProductionBroker(journal, current));
      assert.equal(delayed, true);
      assert.equal(external.actual, undefined);
      if (phase === "issue") assert.equal(external.entries.size, 0);
      else
        for (const entry of external.entries.values()) assert.notEqual(entry.credential, "active");
      journal.close();
    }
    assert.equal(approval.merge, current.producer);
  } finally {
    globalThis.fetch = originalFetch;
    reviewedProfile = undefined;
  }
});
