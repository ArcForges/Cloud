// SPDX-License-Identifier: AGPL-3.0-only
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";

/**
 * The only way a test creates a scratch directory.
 *
 * The directory is removed when the running test finishes (pass `t`, the TestContext, to remove it then, even if the test fails),
 * and in any case when the test process exits, so a directory made outside a test body (a module-level fixture) or by a helper
 * that throws half way is removed as well. A repository test (module-layout.test.ts) fails when a test file calls
 * mkdtemp or mkdtempSync directly instead of using this helper.
 */
const pending = new Set<string>();
let exitHookInstalled = false;

function remove(directory: string): void {
  pending.delete(directory);
  rmSync(directory, { recursive: true, force: true });
}

export function scratchDirectory(prefix: string, t?: { after(fn: () => void): void }): string {
  if (!exitHookInstalled) {
    exitHookInstalled = true;
    process.on("exit", () => {
      for (const directory of [...pending]) remove(directory);
    });
  }
  const directory = mkdtempSync(path.join(tmpdir(), prefix));
  pending.add(directory);
  t?.after(() => remove(directory));
  return directory;
}
