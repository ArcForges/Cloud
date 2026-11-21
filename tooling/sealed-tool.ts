// SPDX-License-Identifier: AGPL-3.0-only
// The schema-1 sealed tool of the historical D1 candidate. Current Go candidates have no tool archive.
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
  const manifest = JSON.parse(manifestText) as { schema?: number; files?: Record<string, string> };
  if (manifest.schema !== 1)
    throw new Error("the sealed tool requires a historical schema-1 candidate");
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
