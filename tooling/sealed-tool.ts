// SPDX-License-Identifier: AGPL-3.0-only
// The sealed tool of the candidate (CLOUD.84 S33(3)(b), S38(2), S41(1)). The candidate job publishes tools/ArcForges.Cloud.Generation
// once, self-contained for linux-x64 and NOT single-file, so that no ILLink pack is restored and the committed tool lock stays byte-identical
// under the locked CI restore. It archives the publish output in a fixed order with fixed metadata as one candidate member and seals the
// member's SHA-256 in the candidate manifest. The Hello probe (`probe`, tooling/protocol.ts) and the D1 migrator (`migrate`,
// eng/migrations/shim.ts) both run that one sealed binary. A runner checks the digest against the manifest before it extracts and runs it.
//
// This module imports only Node built-ins, so the deploy-time shim can load it without the rest of the tooling.
import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import { existsSync, mkdtempSync, readFileSync } from "node:fs";
import path from "node:path";

/** The candidate member that holds the sealed tool archive. */
export const sealedToolName = "arcforges-tool.tar";
/** The apphost of the tool inside the archive. */
export const sealedToolExecutable = "ArcForges.Cloud.Generation";

/** The candidate manifest path under a repository root. */
export function candidateManifestPath(root: string): string {
  return path.join(root, "artifacts", "candidate", "manifest.json");
}

/** The SHA-256 of the sealed archive, which must equal the digest that the candidate manifest records for it. */
export function verifySealedTool(archive: Uint8Array, manifestText: string): void {
  const manifest = JSON.parse(manifestText) as { files?: Record<string, string> };
  const expected = manifest.files?.[sealedToolName];
  const actual = createHash("sha256").update(archive).digest("hex");
  if (expected === undefined || expected !== actual)
    throw new Error("the sealed tool does not match the candidate manifest; nothing is run");
}

export interface ExtractedTool {
  /** The directory the archive was extracted to (under artifacts/), which the caller may remove after the run. */
  directory: string;
  /** The extracted apphost. */
  executable: string;
}

/**
 * Checks the sealed tool against the candidate manifest and extracts it into a fresh directory under artifacts/. Every failure refuses:
 * an absent manifest, an absent archive, a digest that differs from the manifest, or a failed extraction. Nothing is built from source here.
 */
export function extractSealedTool(root: string): ExtractedTool {
  const manifestPath = candidateManifestPath(root);
  if (!existsSync(manifestPath))
    throw new Error(
      "the candidate manifest is absent; the sealed tool cannot be checked, nothing is run",
    );
  const archivePath = path.join(path.dirname(manifestPath), sealedToolName);
  if (!existsSync(archivePath)) throw new Error("the candidate has no sealed tool; nothing is run");
  verifySealedTool(readFileSync(archivePath), readFileSync(manifestPath, "utf8"));
  const directory = mkdtempSync(path.join(root, "artifacts", "sealed-tool-"));
  // Relative, forward-slash paths keep a drive letter out of the archive arguments (a GNU tar on Windows reads "C:" as a host).
  const posix = (file: string) => path.relative(root, file).split(path.sep).join("/");
  const extracted = spawnSync("tar", ["-xf", posix(archivePath), "-C", posix(directory)], {
    cwd: root,
    stdio: "inherit",
  });
  if (extracted.status !== 0)
    throw new Error("the sealed tool could not be extracted; nothing is run");
  const executable = path.join(directory, sealedToolExecutable);
  if (!existsSync(executable)) throw new Error("the sealed tool has no executable; nothing is run");
  return { directory, executable };
}
