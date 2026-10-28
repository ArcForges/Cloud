// SPDX-License-Identifier: AGPL-3.0-only
import { mkdtemp, writeFile, unlink, rmdir } from "node:fs/promises";
import os from "node:os";
import path from "node:path";

export function neonRuntimeSecret(
  enabled: unknown,
  environment: Readonly<Record<string, string | undefined>>,
): { NEON_DATABASE_URL: string } | undefined {
  if (enabled === undefined || enabled === "" || enabled === "disabled") return undefined;
  const value = environment.NEON_DATABASE_URL;
  const invalid = () =>
    new Error("Enabled Neon Hello requires the NEON_DATABASE_URL deployment secret.");
  if (enabled !== "enabled" || !value) throw invalid();
  let uri: URL;
  try {
    uri = new URL(value);
  } catch {
    throw invalid();
  }
  if (
    !["postgres:", "postgresql:"].includes(uri.protocol) ||
    !uri.hostname.startsWith("ep-") ||
    !uri.hostname.endsWith(".neon.tech") ||
    !uri.hostname.includes("-pooler.") ||
    !uri.username ||
    !uri.password ||
    uri.password.includes("*") ||
    uri.pathname === "/" ||
    (uri.port !== "" && uri.port !== "5432") ||
    !["require", "verify-full"].includes(uri.searchParams.get("sslmode") ?? "") ||
    uri.searchParams.get("channel_binding") !== "require"
  )
    throw invalid();
  return { NEON_DATABASE_URL: value };
}

export async function withNeonRuntimeSecret(
  secret: Readonly<Record<string, string>> | undefined,
  publish: (arguments_: string[]) => Promise<void>,
): Promise<void> {
  if (!secret || Object.keys(secret).length === 0) return publish([]);
  // Outside candidate/artifact directories: the secret must never be packaged or uploaded as evidence.
  const directory = await mkdtemp(path.join(os.tmpdir(), "arcforges-neon-"));
  const file = path.join(directory, "runtime.json");
  try {
    await writeFile(file, JSON.stringify(secret), { mode: 0o600, flag: "wx" });
    await publish(["--secrets-file", file]);
  } finally {
    await unlink(file).catch((error: NodeJS.ErrnoException) => {
      if (error.code !== "ENOENT") throw error;
    });
    await rmdir(directory);
  }
}
