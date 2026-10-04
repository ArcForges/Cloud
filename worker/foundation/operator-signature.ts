// SPDX-License-Identifier: AGPL-3.0-only
// Request signatures for the proof-only operator surface. The Worker holds only an Ed25519 PUBLIC key
// (a plain variable), so the private key can live with the operator who runs the live scenarios and
// no shared secret has to travel between CI, Cloudflare and a workstation.
import { base64UrlDecode } from "../private/encoding.ts";

export const operatorScheme = "AF-Operator";
export const operatorMaxSkewSeconds = 60;
const header = /^AF-Operator t=(\d{10}),n=([A-Za-z0-9_-]{22}),s=([A-Za-z0-9_-]{86})$/u;

/** The exact text the operator signs: scheme, method, exact path, time, nonce and body hash. */
export function operatorMessage(
  method: string,
  pathname: string,
  time: string,
  nonce: string,
  bodySha256Hex: string,
): string {
  return `AF-OPERATOR-V1\n${method}\n${pathname}\n${time}\n${nonce}\n${bodySha256Hex}`;
}

export function operatorAuthorization(time: string, nonce: string, signature: string): string {
  return `${operatorScheme} t=${time},n=${nonce},s=${signature}`;
}

export function isOperatorAuthorization(value: string | null): boolean {
  return value?.startsWith(`${operatorScheme} `) === true;
}

/** True only for a well-formed, fresh signature by the configured public key over this request. */
export async function verifyOperatorSignature(
  authorization: string | null,
  request: { method: string; pathname: string; bodySha256Hex: string },
  publicKey: string | undefined,
  nowSeconds: number,
): Promise<boolean> {
  const match = header.exec(authorization ?? "");
  if (!match || publicKey === undefined) return false;
  const [, time = "", nonce = "", signatureText = ""] = match;
  if (Math.abs(nowSeconds - Number(time)) > operatorMaxSkewSeconds) return false;
  const raw = base64UrlDecode(publicKey);
  const signature = base64UrlDecode(signatureText);
  if (raw?.length !== 32 || signature?.length !== 64) return false;
  try {
    const key = await crypto.subtle.importKey("raw", raw as BufferSource, "Ed25519", false, [
      "verify",
    ]);
    return await crypto.subtle.verify(
      "Ed25519",
      key,
      signature as BufferSource,
      new TextEncoder().encode(
        operatorMessage(request.method, request.pathname, time, nonce, request.bodySha256Hex),
      ) as BufferSource,
    );
  } catch {
    return false;
  }
}
