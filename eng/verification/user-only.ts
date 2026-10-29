// SPDX-License-Identifier: AGPL-3.0-only
// Files and directories only their owner can read (AF-CTR-03 A2): the owner bootstrap token and the acceptance run's saved
// passkey. On POSIX a directory is mode 0700 and a file 0600; on Windows the DACL is replaced by one entry for the current user
// (`icacls /inheritance:r /grant:r`), set on the directory first so that a file created in it never inherits another principal.
// Every first write is exclusive (a file is never replaced by it) and the permission is verified after the write. Nothing in this
// module prints a file's content, and a failure names the path only.
import { spawnSync } from "node:child_process";
import {
  chmodSync,
  closeSync,
  mkdirSync,
  openSync,
  readFileSync,
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
    if (line.startsWith(target)) line = line.slice(target.length).trim();
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
  machine.run("icacls", windowsGrantArguments(target, user.sid, directory));
}

function assertWindowsOnlyUser(machine: Machine, target: string): void {
  const user = parseWhoami(machine.run("whoami", ["/user", "/fo", "csv", "/nh"]));
  const principals = parseIcaclsPrincipals(machine.run("icacls", [target]), target);
  const own = [user.name.toLowerCase(), user.sid.toLowerCase()];
  if (principals.length === 0 || principals.some((entry) => !own.includes(entry.toLowerCase())))
    throw new Error(`${target} is readable by more than its owner.`);
}

/** Creates the directory (and its parents) for its owner alone; an existing one is tightened and verified. */
export function ensureUserOnlyDirectory(directory: string, machine: Machine = realMachine()): void {
  mkdirSync(directory, { recursive: true, mode: 0o700 });
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
  ensureUserOnlyDirectory(path.dirname(file), machine);
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

/** Replaces a user-only file's content in place (the saved credential after each assertion); the file must already be private. */
export function rewriteUserOnlyFile(
  file: string,
  data: string | Uint8Array,
  machine: Machine = realMachine(),
): void {
  assertUserOnly(file, machine);
  const descriptor = openSync(file, "w");
  try {
    writeFileSync(descriptor, data);
  } finally {
    closeSync(descriptor);
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
