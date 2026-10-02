// SPDX-License-Identifier: AGPL-3.0-only
// Direction-specific private signing keys from deployment secrets (never from source).
import { parseSecret, type SigningKey } from "./signing.ts";

export type Direction = "C2W" | "W2C";

export interface PrivateKeyEnv {
  HMAC_C2W_KEY_ID?: string;
  HMAC_C2W_SECRET?: string;
  HMAC_C2W_PREVIOUS_KEY_ID?: string;
  HMAC_C2W_PREVIOUS_SECRET?: string;
  HMAC_W2C_KEY_ID?: string;
  HMAC_W2C_SECRET?: string;
  HMAC_W2C_PREVIOUS_KEY_ID?: string;
  HMAC_W2C_PREVIOUS_SECRET?: string;
}

export interface KeyPair {
  readonly current: SigningKey;
  readonly previous?: SigningKey;
}

function one(id: string | undefined, secret: string | undefined): SigningKey | null | undefined {
  if (id === undefined && secret === undefined) return undefined;
  const bytes = parseSecret(secret);
  return id && bytes ? { id, secret: bytes } : null;
}

/**
 * The current key is required. The previous key may be absent (no rotation overlap), but a
 * half-configured or malformed previous key makes the whole direction unusable instead of being
 * silently ignored. Current and previous identifiers must differ.
 */
export function loadKeys(env: PrivateKeyEnv, direction: Direction): KeyPair | null {
  const current =
    direction === "C2W"
      ? one(env.HMAC_C2W_KEY_ID, env.HMAC_C2W_SECRET)
      : one(env.HMAC_W2C_KEY_ID, env.HMAC_W2C_SECRET);
  if (!current) return null;
  const previous =
    direction === "C2W"
      ? one(env.HMAC_C2W_PREVIOUS_KEY_ID, env.HMAC_C2W_PREVIOUS_SECRET)
      : one(env.HMAC_W2C_PREVIOUS_KEY_ID, env.HMAC_W2C_PREVIOUS_SECRET);
  if (previous === null) return null;
  if (previous && previous.id === current.id) return null;
  return previous ? { current, previous } : { current };
}

export function verificationKeys(pair: KeyPair): SigningKey[] {
  return pair.previous ? [pair.current, pair.previous] : [pair.current];
}
