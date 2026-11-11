// SPDX-License-Identifier: AGPL-3.0-only
// Cryptographic and semantic gate binding; authenticated source coverage is checked separately.
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { bridgeSource } from "./ctr06-security-bridge-source.ts";
import { checkObservedPageChain, evaluateObservedAuthority } from "./ctr06-bootstrap-policy.ts";
import { object, parseDocument } from "./provenance.ts";

export type GateContext = {
  producer: string;
  run: string;
  runNumber: string;
  attempt: string;
  originalRun: string;
  eventDigest: string;
  challenge: string;
};
export type GateObservation = { payload: Buffer; token: string };
type VerifyIdentity = (proof: GateObservation, at: number) => Promise<void>;
const id = /^[A-Za-z0-9._:-]{1,128}$/u;
const digest = (bytes: Buffer) => createHash("sha256").update(bytes).digest("hex");

/** This checks signed bytes and modeled facts. A reviewed adapter must separately authenticate full source coverage and actual enforcement. */
export async function inspectGateProof(
  expected: GateContext,
  proof: GateObservation,
  at: number,
  domains: readonly string[],
  verifyIdentity: VerifyIdentity,
) {
  assert(proof.payload.length > 0 && proof.payload.length <= 1024 * 1024);
  assert(Number.isSafeInteger(at) && at >= 0);
  await verifyIdentity(proof, at);
  const data = object(
    parseDocument(proof.payload),
    "schema producer run runNumber attempt originalRun eventDigest challenge source lease sources authority",
  );
  assert.equal(data.schema, "arcforges.ctr06.bootstrap-gate.v1");
  for (const key of [
    "producer",
    "run",
    "runNumber",
    "attempt",
    "originalRun",
    "eventDigest",
    "challenge",
  ] as const)
    assert.equal(data[key], expected[key], `Gate ${key} differs`);
  assert(
    /^[a-f0-9]{64}$/u.test(expected.challenge) && /^[a-f0-9]{64}$/u.test(expected.eventDigest),
  );
  assert.deepEqual(data.source, bridgeSource);
  const lease = object(data.lease, "id revision holder start end");
  assert(
    typeof lease.id === "string" &&
      id.test(lease.id) &&
      typeof lease.revision === "string" &&
      id.test(lease.revision),
  );
  assert.equal(lease.holder, `${expected.run}:${expected.attempt}`);
  assert(
    typeof lease.start === "number" &&
      Number.isSafeInteger(lease.start) &&
      typeof lease.end === "number" &&
      Number.isSafeInteger(lease.end),
  );
  assert(
    lease.start <= at && at < lease.end && lease.end - lease.start <= 300,
    "Gate lease outside its observation interval",
  );
  assert(
    domains.length > 0 &&
      new Set(domains).size === domains.length &&
      domains.every((value) => id.test(value)),
  );
  assert(
    Array.isArray(data.sources) && data.sources.length === domains.length,
    "Gate source domains incomplete",
  );
  const seen = new Set<string>();
  for (const raw of data.sources) {
    const source = object(raw, "domain revision pages");
    assert(
      typeof source.domain === "string" &&
        domains.includes(source.domain) &&
        !seen.has(source.domain),
    );
    seen.add(source.domain);
    assert.equal(source.revision, lease.revision);
    assert.equal(checkObservedPageChain(source.pages).revision, lease.revision);
  }
  evaluateObservedAuthority(data.authority);
  return { digest: digest(proof.payload), lease };
}
