// SPDX-License-Identifier: AGPL-3.0-only
// The environment of the proof Container comes from Worker secrets and variables only; production
// passes nothing, so the host's foundation module stays disabled there.
import { proofEnabled, type FoundationEnv } from "./types.ts";

const forwarded: readonly (readonly [keyof FoundationEnv, string])[] = [
  ["HMAC_C2W_KEY_ID", "AF_HMAC_C2W_KEY_ID"],
  ["HMAC_C2W_SECRET", "AF_HMAC_C2W_SECRET"],
  ["HMAC_W2C_KEY_ID", "AF_HMAC_W2C_KEY_ID"],
  ["HMAC_W2C_SECRET", "AF_HMAC_W2C_SECRET"],
  ["HMAC_W2C_PREVIOUS_KEY_ID", "AF_HMAC_W2C_PREVIOUS_KEY_ID"],
  ["HMAC_W2C_PREVIOUS_SECRET", "AF_HMAC_W2C_PREVIOUS_SECRET"],
  ["CSRF_SECRET", "AF_CSRF_SECRET"],
  ["ALLOWED_ORIGIN", "AF_ALLOWED_ORIGIN"],
  ["REALM_ID", "AF_REALM_ID"],
  ["RECOVERY_GENERATION", "AF_RECOVERY_GENERATION"],
];

export function containerEnvironment(env: Partial<FoundationEnv>): Record<string, string> {
  if (!proofEnabled(env)) return {};
  const result: Record<string, string> = { ARCFORGES_FOUNDATION_PROOF: "enabled" };
  for (const [source, target] of forwarded) {
    const value = env[source];
    if (typeof value === "string" && value !== "") result[target] = value;
  }
  return result;
}
