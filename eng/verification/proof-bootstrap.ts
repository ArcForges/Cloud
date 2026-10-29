// SPDX-License-Identifier: AGPL-3.0-only
// The owner bootstrap of the acceptance center (AF-CTR-03 A2, AD-0021 section 6), run on the owner's own machine:
//
//   node eng/verification/proof-bootstrap.ts [--hours 24] [--dir <directory>]
//
// It generates the one-time token (`afb1.` and 43 base64url characters, 256 bits) and writes it, with its digest and expiry, to
// a new file that only the current user can read (owner-bootstrap.json in ~/.arcforges/proof-bootstrap, or PROOF_BOOTSTRAP_DIR
// or --dir; an existing file is never replaced). It prints ONLY the SHA-256 of the token text and the expiry, in the form the two
// inputs of the protected `deploy` dispatch take (bootstrap_sha256, bootstrap_expires_at). The token is never printed and never
// leaves the machine: CI and the Worker see the digest alone, and the browser acceptance script reads the file and types the
// token into the page itself.
//
// The bootstrap is one-shot: the first `CompleteEnrollment` with the token creates the owner account, and the token is then
// spent. After the owner exists, dispatch without the two inputs (the Worker then starts the center without a bootstrap).
import { createHash, randomBytes } from "node:crypto";
import { existsSync } from "node:fs";
import { homedir } from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { maxBootstrapLeadMs } from "./proof-deploy.ts";
import { type Machine, readUserOnlyFile, realMachine, writeUserOnlyFile } from "./user-only.ts";

export const tokenPrefix = "afb1.";
export const bootstrapFileName = "owner-bootstrap.json";
const tokenPattern = /^afb1\.[A-Za-z0-9_-]{43}$/u;
const digestPattern = /^[0-9a-f]{64}$/u;
const instantPattern = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$/u;

export interface BootstrapRecord {
  version: 1;
  /** The one-time token: `afb1.` and 43 base64url characters. Secret. */
  token: string;
  /** SHA-256 of the exact token text, lowercase hexadecimal (what `printf %s "$TOKEN" | sha256sum` prints). */
  sha256: string;
  /** The expiry, an RFC 3339 UTC instant to the second. */
  expiresAt: string;
}

export function defaultBootstrapDirectory(
  environment: Record<string, string | undefined> = process.env,
): string {
  const configured = environment.PROOF_BOOTSTRAP_DIR;
  return configured ? configured : path.join(homedir(), ".arcforges", "proof-bootstrap");
}

export function digestOfToken(token: string): string {
  return createHash("sha256").update(token, "utf8").digest("hex");
}

/** A new bootstrap valid for `hours` hours (1 to 168) from `now`. */
export function generateBootstrap(options: {
  hours: number;
  now?: Date;
  random?: (bytes: number) => Uint8Array;
}): BootstrapRecord {
  const { hours } = options;
  if (!Number.isInteger(hours) || hours < 1 || hours > maxBootstrapLeadMs / 3_600_000)
    throw new Error("--hours is a whole number from 1 to 168.");
  const now = options.now ?? new Date();
  const random = options.random ?? randomBytes;
  const bytes = random(32);
  if (bytes.length !== 32) throw new Error("The random source must give 32 bytes.");
  const token = `${tokenPrefix}${Buffer.from(bytes).toString("base64url")}`;
  const expires = new Date(Math.floor((now.getTime() + hours * 3_600_000) / 1000) * 1000);
  return {
    version: 1,
    token,
    sha256: digestOfToken(token),
    expiresAt: `${expires.toISOString().slice(0, 19)}Z`,
  };
}

/** Parses and checks a bootstrap file's text; it names the problem and never echoes a value. */
export function parseBootstrapRecord(text: string): BootstrapRecord {
  let value: unknown;
  try {
    value = JSON.parse(text);
  } catch {
    throw new Error("The bootstrap file is not JSON.");
  }
  if (typeof value !== "object" || value === null)
    throw new Error("The bootstrap file is not an object.");
  const record = value as Record<string, unknown>;
  const { token, sha256, expiresAt } = record;
  if (record.version !== 1) throw new Error("The bootstrap file has an unknown version.");
  if (typeof token !== "string" || !tokenPattern.test(token))
    throw new Error("The bootstrap file holds no valid token.");
  if (typeof sha256 !== "string" || !digestPattern.test(sha256) || sha256 !== digestOfToken(token))
    throw new Error("The bootstrap file's digest is not the token's.");
  if (typeof expiresAt !== "string" || !instantPattern.test(expiresAt))
    throw new Error("The bootstrap file's expiry is not an RFC 3339 UTC instant.");
  return { version: 1, token, sha256, expiresAt };
}

/** Reads the bootstrap file (after checking that only the current user can read it) and returns its record. */
export function readBootstrapFile(file: string, machine: Machine = realMachine()): BootstrapRecord {
  return parseBootstrapRecord(readUserOnlyFile(file, machine));
}

/** Creates the bootstrap file; an existing file is an error (a spent or pending token is never replaced). */
export function createBootstrapFile(
  directory: string,
  record: BootstrapRecord,
  machine: Machine = realMachine(),
): string {
  const file = path.join(directory, bootstrapFileName);
  if (existsSync(file))
    throw new Error(
      `${file} exists. A bootstrap is one-shot: delete the file to start over (its token is spent or no longer wanted).`,
    );
  writeUserOnlyFile(file, `${JSON.stringify(record)}\n`, machine);
  return file;
}

export interface Output {
  out(line: string): void;
}

/**
 * Runs the command. The only lines it writes are the two dispatch inputs; the token, the file's content and its path are not
 * among them.
 */
export function runBootstrap(
  argv: string[],
  io: Output,
  options: {
    environment?: Record<string, string | undefined>;
    now?: Date;
    random?: (bytes: number) => Uint8Array;
    machine?: Machine;
  } = {},
): void {
  let hours = 24;
  let directory = defaultBootstrapDirectory(options.environment);
  for (let index = 0; index < argv.length; index += 1) {
    const flag = argv[index];
    const value = argv[index + 1];
    if (flag === "--hours" && value !== undefined && /^\d+$/u.test(value)) hours = Number(value);
    else if (flag === "--dir" && value !== undefined && value !== "") directory = value;
    else throw new Error("Usage: proof-bootstrap.ts [--hours 1..168] [--dir <directory>]");
    index += 1;
  }
  const record = generateBootstrap({ hours, now: options.now, random: options.random });
  createBootstrapFile(directory, record, options.machine);
  io.out(`bootstrap_sha256: ${record.sha256}`);
  io.out(`bootstrap_expires_at: ${record.expiresAt}`);
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  try {
    runBootstrap(process.argv.slice(2), { out: (line) => console.log(line) });
  } catch (error) {
    console.error(error instanceof Error ? error.message : "The bootstrap could not be created.");
    process.exitCode = 1;
  }
}
