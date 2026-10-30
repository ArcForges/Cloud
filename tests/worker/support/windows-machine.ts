// SPDX-License-Identifier: AGPL-3.0-only
// A Windows machine for the tests of the user-only files (AF-CTR-03 A2): it records its commands, answers `whoami` as Windows does and
// `icacls <path>` with the listing a test chooses, and, like the real icacls, FAILS (a non-zero exit status, which the real machine
// turns into an error) for a path that is not on the disk. The first tests had a machine that answered for any path, which hid that
// the first run on a real Windows host stopped in `exists()` of a credential file that was not there.
import { existsSync } from "node:fs";
import path from "node:path";
import type { Machine } from "../../../eng/verification/user-only.ts";

export const sid = "S-1-5-21-1111111111-2222222222-3333333333-1001";
export const whoami = `"workstation-1\\tester","${sid}"\r\n`;

/** The listing of a path that only the user can use. */
export const onlyTester = (target: string) =>
  `${target} WORKSTATION-1\\tester:(OI)(CI)(F)\r\n\r\nSuccessfully processed 1 files; Failed processing 0 files\r\n`;

export function windowsMachine(listing: (target: string) => string = onlyTester) {
  const commands: string[][] = [];
  const machine: Machine = {
    platform: "win32",
    run(command, args) {
      commands.push([command, ...args]);
      if (command === "whoami") return whoami;
      if (command === "icacls" && args.length === 1) {
        const target = args[0] ?? "";
        if (!existsSync(target)) throw new Error("icacls exited with status 2.");
        return listing(path.resolve(target));
      }
      return "";
    },
    uid: () => undefined,
  };
  return { machine, commands };
}

/** The commands that changed a DACL (a grant), not the ones that read one. */
export const grants = (commands: readonly string[][]) =>
  commands.filter((entry) => entry[0] === "icacls" && entry.length > 2);
