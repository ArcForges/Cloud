// SPDX-License-Identifier: AGPL-3.0-only
// Cryptographic and semantic gate binding; authenticated source coverage is checked separately.
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { bridgeSource } from "./ctr06-security-bridge-source.ts";
import {
  evaluateObservedAuthority,
  inspectSourceEvidence,
  type AuthoritySourceProfile,
} from "./ctr06-bootstrap-policy.ts";
import type { AuthenticatedWindow } from "./ctr06-bootstrap-oidc.ts";
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
type VerifyIdentity = (proof: GateObservation, at: number) => Promise<AuthenticatedWindow>;
const digest = (bytes: Buffer) => createHash("sha256").update(bytes).digest("hex");

/** This checks signed bytes and modeled facts. A reviewed adapter must separately authenticate full source coverage and actual enforcement. */
export async function inspectGateProof(
  expected: GateContext,
  proof: GateObservation,
  at: number,
  profiles: readonly AuthoritySourceProfile[],
  verifyIdentity: VerifyIdentity,
) {
  assert(proof.payload.length > 0 && proof.payload.length <= 1024 * 1024);
  assert(Number.isSafeInteger(at) && at >= 0);
  const window = await verifyIdentity(proof, at);
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
  const lease = inspectSourceEvidence(
    data.lease,
    data.sources,
    at,
    `${expected.run}:${expected.attempt}`,
    profiles,
  );
  evaluateObservedAuthority(data.authority);
  return { digest: digest(proof.payload), lease, window };
}
