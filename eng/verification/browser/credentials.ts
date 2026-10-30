// SPDX-License-Identifier: AGPL-3.0-only
// The proof owner's saved passkey (AF-CTR-03 A2). The acceptance script enrolls the owner with Chromium's virtual authenticator;
// the credential the authenticator makes (including its PRIVATE key) is exported through the DevTools WebAuthn domain and kept in a
// file only the current user can read, so that later runs sign in as the same owner (the bootstrap works once). The file grants the
// owner's and the operator's rights over the proof environment: it is never printed, logged, committed or sent anywhere, and every
// error here names the path or the problem, never a value.
import path from "node:path";
import {
  type Machine,
  assertUserOnly,
  ensureUserOnlyDirectory,
  readUserOnlyFile,
  realMachine,
  replaceUserOnlyFile,
  writeUserOnlyFile,
} from "../user-only.ts";

export const credentialFileName = "owner-credential.json";

/** A credential as the DevTools WebAuthn domain exports and imports it (binary values are base64). */
export interface VirtualCredential {
  credentialId: string;
  isResidentCredential: boolean;
  rpId: string;
  /** Base64 PKCS#8 private key. Secret. */
  privateKey: string;
  userHandle?: string;
  signCount: number;
  largeBlob?: string;
}

export interface CredentialFile {
  version: 1;
  /** The center's public base URL the credentials belong to (its RP ID is the host). */
  baseUrl: string;
  rpId: string;
  displayName: string;
  createdAt: string;
  updatedAt: string;
  credentials: VirtualCredential[];
}

const base64 = /^[A-Za-z0-9+/_-]+={0,2}$/u;
const instant = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,3})?Z$/u;

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

/** Checks one exported credential; the problem names the field and never the value. */
export function checkCredential(value: unknown): VirtualCredential {
  if (!isRecord(value)) throw new Error("A saved credential is not an object.");
  const { credentialId, isResidentCredential, rpId, privateKey, userHandle, signCount, largeBlob } =
    value;
  if (typeof credentialId !== "string" || !base64.test(credentialId))
    throw new Error("A saved credential has no valid credentialId.");
  if (typeof isResidentCredential !== "boolean")
    throw new Error("A saved credential has no isResidentCredential.");
  if (typeof rpId !== "string" || rpId === "") throw new Error("A saved credential has no rpId.");
  if (typeof privateKey !== "string" || !base64.test(privateKey))
    throw new Error("A saved credential has no valid privateKey.");
  if (userHandle !== undefined && (typeof userHandle !== "string" || !base64.test(userHandle)))
    throw new Error("A saved credential has an invalid userHandle.");
  if (typeof signCount !== "number" || !Number.isSafeInteger(signCount) || signCount < 0)
    throw new Error("A saved credential has an invalid signCount.");
  if (largeBlob !== undefined && (typeof largeBlob !== "string" || !base64.test(largeBlob)))
    throw new Error("A saved credential has an invalid largeBlob.");
  const credential: VirtualCredential = {
    credentialId,
    isResidentCredential,
    rpId,
    privateKey,
    signCount,
  };
  if (userHandle !== undefined) credential.userHandle = userHandle;
  if (largeBlob !== undefined) credential.largeBlob = largeBlob;
  return credential;
}

/** Parses a credential file's text strictly. */
export function parseCredentialFile(text: string): CredentialFile {
  let value: unknown;
  try {
    value = JSON.parse(text);
  } catch {
    throw new Error("The credential file is not JSON.");
  }
  if (!isRecord(value)) throw new Error("The credential file is not an object.");
  if (value.version !== 1) throw new Error("The credential file has an unknown version.");
  const { baseUrl, rpId, displayName, createdAt, updatedAt, credentials } = value;
  if (typeof baseUrl !== "string" || typeof rpId !== "string" || rpId === "")
    throw new Error("The credential file names no center.");
  if (typeof displayName !== "string" || displayName === "")
    throw new Error("The credential file names no owner.");
  if (typeof createdAt !== "string" || !instant.test(createdAt))
    throw new Error("The credential file has no creation time.");
  if (typeof updatedAt !== "string" || !instant.test(updatedAt))
    throw new Error("The credential file has no update time.");
  if (!Array.isArray(credentials) || credentials.length === 0)
    throw new Error("The credential file holds no credential.");
  const checked = credentials.map(checkCredential);
  if (new Set(checked.map((credential) => credential.credentialId)).size !== checked.length)
    throw new Error("The credential file repeats a credential.");
  return { version: 1, baseUrl, rpId, displayName, createdAt, updatedAt, credentials: checked };
}

/** The strings of a credential that must never appear in any output: the key, the handle and the ID. */
export function credentialSecrets(credentials: readonly VirtualCredential[]): string[] {
  return credentials.flatMap((credential) =>
    [credential.privateKey, credential.userHandle, credential.credentialId].filter(
      (text): text is string => typeof text === "string" && text !== "",
    ),
  );
}

export function defaultStateDirectory(
  environment: Record<string, string | undefined>,
  home: string,
): string {
  const configured = environment.PROOF_ACCEPTANCE_DIR;
  return configured ? configured : path.join(home, ".arcforges", "proof-acceptance");
}

/** The owner's credential file in a user-only directory. */
export class CredentialStore {
  readonly file: string;
  private readonly machine: Machine;

  constructor(directory: string, machine: Machine = realMachine()) {
    this.file = path.join(directory, credentialFileName);
    this.machine = machine;
  }

  /** Makes the directory private (before anything is written to it). */
  prepare(): void {
    ensureUserOnlyDirectory(path.dirname(this.file), this.machine);
  }

  exists(): boolean {
    try {
      assertUserOnly(this.file, this.machine);
      return true;
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code === "ENOENT") return false;
      throw error;
    }
  }

  load(): CredentialFile {
    return parseCredentialFile(readUserOnlyFile(this.file, this.machine));
  }

  /** Writes the first credential file; an existing one is an error. */
  create(file: Omit<CredentialFile, "version" | "createdAt" | "updatedAt">, now: Date): void {
    const stamp = now.toISOString();
    const content: CredentialFile = { version: 1, ...file, createdAt: stamp, updatedAt: stamp };
    parseCredentialFile(JSON.stringify(content));
    writeUserOnlyFile(this.file, `${JSON.stringify(content)}\n`, this.machine);
  }

  /**
   * Replaces the saved credentials with the authenticator's current ones (counters included). It refuses an export that would lose
   * a saved credential (unless the caller names it in `dropping`) or lower a counter: either would mean the authenticator lost its
   * state, and the saved file is then the only copy of the owner's key.
   */
  save(
    credentials: readonly VirtualCredential[],
    now: Date,
    options: { dropping?: readonly string[] } = {},
  ): void {
    const current = this.load();
    const next = credentials.map(checkCredential);
    const dropping = new Set(options.dropping ?? []);
    for (const saved of current.credentials) {
      const found = next.find((credential) => credential.credentialId === saved.credentialId);
      if (found === undefined) {
        if (!dropping.has(saved.credentialId))
          throw new Error("The authenticator's export lacks a saved credential; the file is kept.");
      } else if (found.signCount < saved.signCount) {
        throw new Error(
          "The authenticator's export lowers a credential's counter; the file is kept.",
        );
      }
    }
    const content: CredentialFile = {
      ...current,
      updatedAt: now.toISOString(),
      credentials: next,
    };
    parseCredentialFile(JSON.stringify(content));
    replaceUserOnlyFile(this.file, `${JSON.stringify(content)}\n`, this.machine);
  }
}
