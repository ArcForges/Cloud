// SPDX-License-Identifier: AGPL-3.0-only
// Historical CTR06 publication remains in the reviewed Cloud checkout and never runs for current Go candidates.
import { constants as fsConstants } from "node:fs";
import { copyFile } from "node:fs/promises";
import { requireSecurityBridgeSuccessor } from "./ctr06-security-bridge-gate.ts";
import type { CenterRunner, PostgresTarget } from "./postgres-deploy.ts";

/** Reuse a release carrier downloaded by the same guarded build when present.
 * The carrier is still verified by its pinned digest before any use.
 */
export async function copyStagedBridgeCarrier(
  staged: string,
  destination: string,
): Promise<boolean> {
  try {
    await copyFile(staged, destination, fsConstants.COPYFILE_EXCL);
    return true;
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === "ENOENT") return false;
    throw error;
  }
}

export async function withOwnedCleanup<T>(
  work: () => Promise<T>,
  cleanup: () => Promise<void>,
): Promise<T> {
  let result: T;
  try {
    result = await work();
  } catch (error) {
    try {
      await cleanup();
    } catch (cleanupError) {
      throw new AggregateError(
        [error, cleanupError],
        "Bridge promotion and owned cleanup both failed.",
      );
    }
    throw error;
  }
  await cleanup();
  return result;
}

/** Refuse legacy publication before accessing any inputs or resources. */
export async function promoteCTR06Bridge(
  _target: PostgresTarget,
  _candidateImage: string,
  _variables: Record<string, string>,
  _center: CenterRunner,
): Promise<Record<string, unknown>> {
  requireSecurityBridgeSuccessor();
  throw new Error(
    "CTR06 publication is archival-only at Cloud 9b8796eac760982d9814f371b820b736ddd945c4.",
  );
}
