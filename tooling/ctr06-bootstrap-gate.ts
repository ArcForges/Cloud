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
import { requireFreshWindow, type AuthenticatedWindow } from "./ctr06-bootstrap-oidc.ts";
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
  const authenticatedDigest = digest(proof.payload);
  const window = await verifyIdentity(proof, at);
  assert.equal(digest(proof.payload), authenticatedDigest, "Authenticated gate payload changed");
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
  return { digest: authenticatedDigest, lease, window };
}

/** Current pre-artifact gate: recheck the authenticated source set and JWT after the last external
 * control wait. Historical job readback must instead call inspectGateProof at the recorded job time. */
export async function inspectCurrentGateProof(
  expected: GateContext,
  proof: GateObservation,
  profiles: readonly AuthoritySourceProfile[],
  verifyIdentity: VerifyIdentity,
  verifyControls: (lease: ReturnType<typeof inspectSourceEvidence>) => Promise<void>,
) {
  const at = Math.floor(Date.now() / 1000);
  const checked = await inspectGateProof(expected, proof, at, profiles, verifyIdentity);
  await verifyControls(checked.lease);
  requireCurrentGateProof(expected, proof, profiles, checked);
  return checked;
}

/** Call at the actual current-gate output boundary; an awaited caller can resume later. */
export function requireCurrentGateProof(
  expected: GateContext,
  proof: GateObservation,
  profiles: readonly AuthoritySourceProfile[],
  checked: Awaited<ReturnType<typeof inspectGateProof>>,
): void {
  assert.equal(digest(proof.payload), checked.digest, "Authenticated gate payload changed");
  const current = Math.floor(Date.now() / 1000);
  requireFreshWindow(checked.window, current);
  const data = object(
    parseDocument(proof.payload),
    "schema producer run runNumber attempt originalRun eventDigest challenge source lease sources authority",
  );
  assert.deepEqual(
    inspectSourceEvidence(
      data.lease,
      data.sources,
      current,
      `${expected.run}:${expected.attempt}`,
      profiles,
    ),
    checked.lease,
    "Gate source lease differs",
  );
}
