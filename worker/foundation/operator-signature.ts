// SPDX-License-Identifier: AGPL-3.0-only
// Request signatures for the proof-only operator surface. The Worker holds only an Ed25519 PUBLIC key
// (a plain variable), so the private key can live with the operator who runs the live scenarios and
// no shared secret has to travel between CI, Cloudflare and a workstation.
import { base64UrlDecode } from "../private/encoding.ts";
import {
  operatorHeaderPattern as header,
  operatorMaxSkewSeconds,
  operatorPublicKeyBytes,
  operatorSignatureBytes,
} from "../tables/cloud-tables.generated.ts";

export { operatorMaxSkewSeconds };
export const operatorScheme = "AF-Operator";

/** The exact text the operator signs: scheme, method, exact host and path, time, nonce and body hash. */
export function operatorMessage(
  method: string,
  host: string,
  pathname: string,
  time: string,
  nonce: string,
  bodySha256Hex: string,
): string {
  return `AF-OPERATOR-V2\n${method}\n${host}\n${pathname}\n${time}\n${nonce}\n${bodySha256Hex}`;
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
  request: { method: string; host: string; pathname: string; bodySha256Hex: string },
  publicKey: string | undefined,
  nowSeconds: number,
): Promise<boolean> {
  const match = header.exec(authorization ?? "");
  if (!match || publicKey === undefined) return false;
  const [, time = "", nonce = "", signatureText = ""] = match;
  if (Math.abs(nowSeconds - Number(time)) > operatorMaxSkewSeconds) return false;
  const raw = base64UrlDecode(publicKey);
  const signature = base64UrlDecode(signatureText);
  if (raw?.length !== operatorPublicKeyBytes || signature?.length !== operatorSignatureBytes)
    return false;
  try {
    const key = await crypto.subtle.importKey("raw", raw as BufferSource, "Ed25519", false, [
      "verify",
    ]);
    return await crypto.subtle.verify(
      "Ed25519",
      key,
      signature as BufferSource,
      new TextEncoder().encode(
        operatorMessage(
          request.method,
          request.host,
          request.pathname,
          time,
          nonce,
          request.bodySha256Hex,
        ),
      ) as BufferSource,
    );
  } catch {
    return false;
  }
}
