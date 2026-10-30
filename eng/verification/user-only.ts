// SPDX-License-Identifier: AGPL-3.0-only
// Files and directories only their owner can read (AF-CTR-03 A2): the owner bootstrap token and the acceptance run's saved
// passkey. On POSIX a directory is mode 0700 and a file 0600; on Windows the DACL is replaced by one entry for the current user
// (`icacls /inheritance:r /grant:r`), set on the directory first so that a file created in it never inherits another principal.
// Every first write is exclusive (a file is never replaced by it) and the permission is verified after the write. Nothing in this
// module prints a file's content, and a failure names the path only.
import { spawnSync } from "node:child_process";
import { randomBytes } from "node:crypto";
import {
  chmodSync,
  closeSync,
  existsSync,
  mkdirSync,
  openSync,
  readFileSync,
  readdirSync,
  renameSync,
  rmSync,
  statSync,
  writeFileSync,
} from "node:fs";
import path from "node:path";

/** What the module needs from the machine; tests replace it. */
export interface Machine {
  platform: NodeJS.Platform;
  /** Runs a command to completion and returns its standard output; it throws on a non-zero exit. */
  run(command: string, args: string[]): string;
  /** The POSIX user ID of the process. */
  uid(): number | undefined;
}

export function realMachine(): Machine {
  return {
    platform: process.platform,
    run(command, args) {
      const result = spawnSync(command, args, { encoding: "utf8", windowsHide: true });
      if (result.error) throw result.error;
      if (result.status !== 0)
        throw new Error(`${path.basename(command)} exited with status ${String(result.status)}.`);
      return result.stdout;
    },
    uid: () => (typeof process.getuid === "function" ? process.getuid() : undefined),
  };
}

/** The current Windows user: its `DOMAIN\name` and its SID, from `whoami /user /fo csv /nh`. */
export function parseWhoami(output: string): { name: string; sid: string } {
  const match = /^"([^"]+)","(S-1-[0-9-]+)"\s*$/mu.exec(output);
  if (!match?.[1] || !match[2]) throw new Error("Cannot determine the current Windows user.");
  return { name: match[1], sid: match[2] };
}

/** The principals of an `icacls <path>` listing: the text before `:(` of every entry, the first one after the path. */
export function parseIcaclsPrincipals(output: string, target: string): string[] {
  const principals: string[] = [];
  for (const raw of output.split(/\r?\n/u)) {
    let line = raw.trim();
    // icacls prints the path as the file system knows it (its case, backslashes), which may differ from the argument's.
    if (line.toLowerCase().startsWith(target.toLowerCase()))
      line = line.slice(target.length).trim();
    const at = line.indexOf(":(");
    if (at > 0) principals.push(line.slice(0, at).trim());
  }
  return principals;
}

/** The icacls arguments that leave one entry, full control for the SID, and no inherited entry. */
export function windowsGrantArguments(target: string, sid: string, directory: boolean): string[] {
  return [target, "/inheritance:r", "/grant:r", `*${sid}:${directory ? "(OI)(CI)F" : "F"}`];
}

function restrictWindows(machine: Machine, target: string, directory: boolean): void {
  const user = parseWhoami(machine.run("whoami", ["/user", "/fo", "csv", "/nh"]));
  machine.run("icacls", windowsGrantArguments(path.resolve(target), user.sid, directory));
}

function assertWindowsOnlyUser(machine: Machine, target: string): void {
  const user = parseWhoami(machine.run("whoami", ["/user", "/fo", "csv", "/nh"]));
  const full = path.resolve(target);
  const principals = parseIcaclsPrincipals(machine.run("icacls", [full]), full);
  const own = [user.name.toLowerCase(), user.sid.toLowerCase()];
  if (principals.length === 0 || principals.some((entry) => !own.includes(entry.toLowerCase())))
    throw new Error(`${target} is readable by more than its owner.`);
}

/**
 * Makes the directory private to its owner and verifies it. Only a directory this call creates, or one that holds nothing but the
 * tool's own files (`own` names them), is restricted: a directory someone else filled (`--dir .` in a checkout, a profile folder) is
 * refused untouched, because the Windows grant removes every other entry of the directory and of what it holds. Parents of a new
 * directory are created with their ordinary permissions.
 */
export function ensureUserOnlyDirectory(
  directory: string,
  machine: Machine = realMachine(),
  own: (name: string) => boolean = () => false,
): void {
  if (existsSync(directory)) {
    if (!statSync(directory).isDirectory()) throw new Error(`${directory} is not a directory.`);
    if (readdirSync(directory).some((name) => !own(name)))
      throw new Error(
        `${directory} exists and holds files that are not this tool's; name a new or an empty directory.`,
      );
  } else {
    mkdirSync(path.dirname(directory), { recursive: true });
    // Not recursive: if the directory appears meanwhile, this fails instead of restricting someone else's.
    mkdirSync(directory, { mode: 0o700 });
  }
  if (machine.platform === "win32") restrictWindows(machine, directory, true);
  else chmodSync(directory, 0o700);
  assertUserOnly(directory, machine);
}

/**
 * Writes a new file for its owner alone. The write is exclusive: an existing file is an error, never replaced. The directory is
 * made user-only first, so the file is private from its first byte; the file's own permission is then set and verified.
 */
export function writeUserOnlyFile(
  file: string,
  data: string | Uint8Array,
  machine: Machine = realMachine(),
): void {
  const directory = path.dirname(file);
  // A directory that exists is checked, never changed here; a new one is made private before the file is created in it.
  if (existsSync(directory)) assertUserOnly(directory, machine);
  else ensureUserOnlyDirectory(directory, machine);
  const descriptor = openSync(file, "wx", 0o600);
  try {
    writeFileSync(descriptor, data);
  } finally {
    closeSync(descriptor);
  }
  if (machine.platform === "win32") restrictWindows(machine, file, false);
  else chmodSync(file, 0o600);
  assertUserOnly(file, machine);
}

/**
 * Replaces the content of an existing user-only file (the saved credential after each assertion) all at once: the new content is
 * written to a new private file in the same private directory and renamed over the old one, so a failure leaves the old content
 * whole. The old file must already be private.
 */
export function replaceUserOnlyFile(
  file: string,
  data: string | Uint8Array,
  machine: Machine = realMachine(),
): void {
  assertUserOnly(file, machine);
  const temporary = `${file}.${randomBytes(6).toString("hex")}.tmp`;
  writeUserOnlyFile(temporary, data, machine);
  try {
    renameSync(temporary, file);
  } catch (error) {
    rmSync(temporary, { force: true });
    throw error;
  }
  assertUserOnly(file, machine);
}

/** Throws unless only the current user can read the path (it names the path, never content). */
export function assertUserOnly(target: string, machine: Machine = realMachine()): void {
  if (machine.platform === "win32") {
    assertWindowsOnlyUser(machine, target);
    return;
  }
  const status = statSync(target);
  const uid = machine.uid();
  if ((status.mode & 0o077) !== 0 || (uid !== undefined && status.uid !== uid))
    throw new Error(`${target} is readable by more than its owner.`);
}

/** Reads a user-only file after verifying its permission and its directory's. */
export function readUserOnlyFile(file: string, machine: Machine = realMachine()): string {
  assertUserOnly(path.dirname(file), machine);
  assertUserOnly(file, machine);
  return readFileSync(file, "utf8");
}
