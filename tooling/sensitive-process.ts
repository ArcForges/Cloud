// SPDX-License-Identifier: AGPL-3.0-only
// Runs secret-bearing proof deployment steps without exposing a child's output or exception text. A successful JSON command is
// captured only up to a fixed bound for internal public-metadata validation; stderr is always discarded.
import { spawn } from "node:child_process";
import { root } from "./process.ts";

type Stage = "registration" | "inspection" | "runtime" | "provider" | "upload";
const messages: Record<Stage, string> = {
  registration: "Proof command-key registration did not complete; its outcome may be unknown.",
  inspection: "Proof command-key inspection did not complete.",
  runtime: "Proof runtime credential command did not complete.",
  provider: "Proof provider metadata could not be read.",
  upload: "Proof deployment did not complete; its outcome may be unknown.",
};
const maxJsonBytes = 32 * 1024;

export class SensitiveProcessError extends Error {
  readonly exitCode: number | null;

  constructor(stage: Stage, exitCode: number | null) {
    super(messages[stage]);
    this.exitCode = exitCode;
  }
}

export async function runSensitive(
  stage: Stage,
  command: string,
  args: readonly string[],
  environment: NodeJS.ProcessEnv,
  output: "json" | "discard",
): Promise<unknown> {
  return new Promise((resolve, reject) => {
    const failure = (exitCode: number | null = null) =>
      reject(new SensitiveProcessError(stage, exitCode));
    let child: ReturnType<typeof spawn>;
    try {
      child = spawn(command, [...args], {
        cwd: root,
        windowsHide: true,
        stdio: ["ignore", "pipe", "pipe"],
        env: { ...environment, WRANGLER_SEND_METRICS: "false" },
        timeout: 180_000,
      });
    } catch {
      failure();
      return;
    }
    let bytes = 0;
    let overflow = false;
    const chunks: Buffer[] = [];
    child.stdout?.on("data", (chunk: Buffer) => {
      if (output === "discard" || overflow) return;
      bytes += chunk.length;
      if (bytes > maxJsonBytes) {
        overflow = true;
        chunks.length = 0;
      } else chunks.push(chunk);
    });
    child.stderr?.on("data", () => {});
    child.once("error", () => failure());
    child.once("close", (code) => {
      if (code !== 0 || overflow) {
        failure(overflow ? null : code);
        return;
      }
      if (output === "discard") {
        resolve(undefined);
        return;
      }
      try {
        resolve(JSON.parse(Buffer.concat(chunks).toString("utf8").trim()));
      } catch {
        failure();
      }
    });
  });
}
