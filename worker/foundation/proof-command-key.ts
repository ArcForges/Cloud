// SPDX-License-Identifier: AGPL-3.0-only
// A proof deployment names exactly one generated command-key secret. This name is public; its value is never configuration text.
export const proofCommandKeyBindingVariable = "ARCFORGES_CENTER_PROOF_COMMAND_KEY_BINDING";
const proofCommandKeyBinding = /^ARCFORGES_CENTER_KEY_PROOF_[A-F0-9]{32}$/u;

export function isProofCommandKeyBinding(value: unknown): value is string {
  return typeof value === "string" && proofCommandKeyBinding.test(value);
}
