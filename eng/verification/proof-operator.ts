// SPDX-License-Identifier: AGPL-3.0-only
// The operator side of the proof surface's request signature (worker/foundation/operator-signature.ts).
// The Ed25519 PRIVATE key is generated and kept in a local file of the operator who runs the live
// scenarios; it is never printed, never committed and never sent anywhere. Only the base64url public
// key leaves this machine (it is committed in wrangler.json as the PROOF_OPERATOR_VERIFIER value),
// so no shared secret has to be handled by a person or stored in CI.
import {
  createPrivateKey,
  createPublicKey,
  generateKeyPairSync,
  randomBytes,
  sign,
  type KeyObject,
} from "node:crypto";
import { chmodSync, existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { homedir } from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { sha256Hex } from "../../worker/private/encoding.ts";
import {
  operatorAuthorization,
  operatorMessage,
} from "../../worker/foundation/operator-signature.ts";

export function defaultKeyFile(): string {
  return (
    process.env.PROOF_OPERATOR_KEY_FILE ??
    path.join(homedir(), ".arcforges", "proof-operator", "ed25519-private.pem")
  );
}

/** The 32-byte raw public key as unpadded base64url (the Worker's PROOF_OPERATOR_VERIFIER). */
export function publicKeyText(privateKey: KeyObject): string {
  const spki = createPublicKey(privateKey).export({ format: "der", type: "spki" });
  // An Ed25519 SubjectPublicKeyInfo is a 12-byte prefix followed by the raw 32-byte key.
  return spki.subarray(spki.length - 32).toString("base64url");
}

export function loadOperatorKey(file = defaultKeyFile()): KeyObject {
  if (!existsSync(file))
    throw new Error(
      "No operator key file; run `node eng/verification/proof-operator.ts init` or set PROOF_OPERATOR_KEY_FILE.",
    );
  const key = createPrivateKey(readFileSync(file));
  if (key.asymmetricKeyType !== "ed25519") throw new Error("The operator key must be Ed25519.");
  return key;
}

/** Creates the key file when absent (mode 0600) and returns its public key; never overwrites. */
export function initOperatorKey(file = defaultKeyFile()): string {
  if (existsSync(file)) return publicKeyText(loadOperatorKey(file));
  const { privateKey } = generateKeyPairSync("ed25519");
  mkdirSync(path.dirname(file), { recursive: true });
  writeFileSync(file, privateKey.export({ format: "pem", type: "pkcs8" }), {
    mode: 0o600,
    flag: "wx",
  });
  try {
    chmodSync(file, 0o600);
  } catch {
    // Not every file system supports modes.
  }
  return publicKeyText(privateKey);
}

/** The Authorization header value for one operator request. */
export async function signOperatorRequest(
  key: KeyObject,
  method: string,
  pathname: string,
  body: Uint8Array,
  options: { nowSeconds?: number; nonce?: string } = {},
): Promise<string> {
  const time = String(options.nowSeconds ?? Math.floor(Date.now() / 1000));
  const nonce = options.nonce ?? randomBytes(16).toString("base64url");
  const message = operatorMessage(method, pathname, time, nonce, await sha256Hex(body));
  return operatorAuthorization(
    time,
    nonce,
    sign(null, Buffer.from(message), key).toString("base64url"),
  );
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const command = process.argv[2];
  if (command === "init") console.log(initOperatorKey());
  else if (command === "public") console.log(publicKeyText(loadOperatorKey()));
  else throw new Error("Use init or public; both print only the public key.");
}
