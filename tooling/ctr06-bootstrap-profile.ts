// SPDX-License-Identifier: AGPL-3.0-only
// No provider scope, enforced lease or publication broker has been reviewed for live use.
import type { BrokerPorts, CollectorObservation } from "./ctr06-bootstrap-broker.ts";
import type { CollectorIdentity } from "./ctr06-bootstrap-oidc.ts";
import type { ApprovedBootstrap, AttemptTarget } from "./ctr06-bootstrap-registry.ts";
import type { validateBridgeProducer } from "./ctr06-security-bridge-source.ts";

/** A future profile is fixed in reviewed source, not supplied by an owner, request or provider. */
export type ReviewedAuthorityProfile = {
  kind: "github-oidc";
  collectorSourceSha: string;
  requiredDomains: readonly string[];
  /** Independently authenticate the collector run from reviewed GitHub metadata. */
  collectorRun(
    observation: CollectorObservation,
    target: Pick<AttemptTarget, "producer" | "run" | "attempt">,
  ): Promise<CollectorIdentity>;
  /** Return only the source-reviewed, provider-specific coverage, enforcement and issuer adapters. */
  createPorts(): BrokerPorts;
  /** Read-only collectors and source-specific controls; they never expose a publication credential. */
  gateApproval(
    producer: ReturnType<typeof validateBridgeProducer>,
    eventDigest: string,
  ): Promise<ApprovedBootstrap>;
  collectGate(
    producer: ReturnType<typeof validateBridgeProducer>,
    approval: ApprovedBootstrap,
    challenge: string,
  ): Promise<CollectorObservation>;
  verifyGateControls(
    proof: CollectorObservation,
    producer: ReturnType<typeof validateBridgeProducer>,
    approval: ApprovedBootstrap,
  ): Promise<void>;
  submitPublication(
    producer: ReturnType<typeof validateBridgeProducer>,
    carrier: {
      artifactId: string;
      artifactSha256: string;
      size: number;
      receiptSha256: string;
      receiptSize: number;
      gateDigest: string;
      gateChallenge: string;
    },
  ): Promise<void>;
};

export function reviewedAuthorityProfile(): ReviewedAuthorityProfile | undefined {
  // No host, owner-controlled URL, mock key, signed JSON or boolean can manufacture a profile.
  return undefined;
}
export function requireReviewedAuthorityProfile(): ReviewedAuthorityProfile {
  const profile = reviewedAuthorityProfile();
  if (!profile)
    throw new Error(
      "NOT PROVEN: no reviewed live collector, coverage/enforcement adapters or broker profile is configured",
    );
  return profile;
}
