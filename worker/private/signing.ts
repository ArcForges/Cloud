// SPDX-License-Identifier: AGPL-3.0-only
// Private request signing of contracts 05 section 2. Defense in depth behind the outbound-handler
// and service-binding boundary: it never replaces them and it keeps no nonce ledger.
import { base64UrlDecode, base64UrlEncode } from "./encoding.ts";

export const maxSkewSeconds = 60;
export const secretByteLength = 32;

export interface SigningKey {
  readonly id: string;
  readonly secret: Uint8Array;
}

export interface SignatureHeaders {
  "x-af-key-id": string;
  "x-af-time": string;
  "x-af-nonce": string;
  "x-af-request-id": string;
  "x-af-signature": string;
}

export interface SignedRequestParts {
  method: string;
  /** Exact encoded path and query as sent on the wire. */
  pathAndQuery: string;
  /** Lowercase hex SHA-256 of the body, or the declared content hash of a byte transfer. */
  bodySha256Hex: string;
  requestId: string;
  time: string;
  nonce: string;
}

const uuid = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/u;
const keyId = /^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$/u;
const epochSeconds = /^[1-9][0-9]{0,15}$/u;
const nonceText = /^[A-Za-z0-9_-]{22}$/u;
const hash = /^[0-9a-f]{64}$/u;

/** A deployment secret is exactly 256 random bits as unpadded base64url. */
export function parseSecret(text: string | undefined): Uint8Array | null {
  if (text === undefined) return null;
  const bytes = base64UrlDecode(text);
  return bytes?.length === secretByteLength ? bytes : null;
}

export function signingText(parts: SignedRequestParts): string {
  return [
    parts.method,
    parts.pathAndQuery,
    parts.time,
    parts.nonce,
    parts.requestId,
    parts.bodySha256Hex,
  ].join("\n");
}

async function importKey(secret: Uint8Array, usage: "sign" | "verify") {
  return crypto.subtle.importKey(
    "raw",
    secret as BufferSource,
    { name: "HMAC", hash: "SHA-256" },
    false,
    [usage],
  );
}

export async function sign(parts: SignedRequestParts, key: SigningKey): Promise<SignatureHeaders> {
  const signature = await crypto.subtle.sign(
    "HMAC",
    await importKey(key.secret, "sign"),
    new TextEncoder().encode(signingText(parts)),
  );
  return {
    "x-af-key-id": key.id,
    "x-af-time": parts.time,
    "x-af-nonce": parts.nonce,
    "x-af-request-id": parts.requestId,
    "x-af-signature": base64UrlEncode(new Uint8Array(signature)),
  };
}

export function newNonce(): string {
  return base64UrlEncode(crypto.getRandomValues(new Uint8Array(16)));
}

export type Verification = { ok: true; keyId: string; requestId: string } | { ok: false };

/**
 * Verifies the header shapes, the clock skew, the key identifier and the signature (constant time)
 * before the caller reads the body. Every failure is the same result so a reply cannot say why.
 */
export async function verify(
  request: { method: string; pathAndQuery: string; bodySha256Hex: string; headers: Headers },
  keys: readonly SigningKey[],
  nowSeconds: number,
): Promise<Verification> {
  const fail = { ok: false } as const;
  const { headers } = request;
  const id = headers.get("x-af-key-id") ?? "";
  const time = headers.get("x-af-time") ?? "";
  const nonce = headers.get("x-af-nonce") ?? "";
  const requestId = headers.get("x-af-request-id") ?? "";
  const signature = headers.get("x-af-signature") ?? "";
  if (
    !keyId.test(id) ||
    !epochSeconds.test(time) ||
    !nonceText.test(nonce) ||
    !uuid.test(requestId) ||
    !hash.test(request.bodySha256Hex)
  )
    return fail;
  if (Math.abs(nowSeconds - Number(time)) > maxSkewSeconds) return fail;
  const provided = base64UrlDecode(signature);
  if (provided?.length !== 32) return fail;
  const key = keys.find((candidate) => candidate.id === id);
  if (!key) return fail;
  const valid = await crypto.subtle.verify(
    "HMAC",
    await importKey(key.secret, "verify"),
    provided as BufferSource,
    new TextEncoder().encode(
      signingText({
        method: request.method,
        pathAndQuery: request.pathAndQuery,
        bodySha256Hex: request.bodySha256Hex,
        requestId,
        time,
        nonce,
      }),
    ),
  );
  return valid ? { ok: true, keyId: id, requestId } : fail;
}
