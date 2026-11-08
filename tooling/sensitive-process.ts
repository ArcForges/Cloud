// SPDX-License-Identifier: AGPL-3.0-only
// Runs secret-bearing proof deployment steps without exposing a child's output or exception text. A successful JSON command is
// captured only up to a fixed bound for internal public-metadata validation; stderr is always discarded.
import { spawn } from "node:child_process";
import path from "node:path";
import { root } from "./process.ts";

type Stage =
  | "candidate"
  | "head"
  | "image"
  | "push"
  | "registration"
  | "inspection"
  | "runtime"
  | "provider"
  | "upload";
const messages: Record<Stage, string> = {
  candidate: "The sealed proof candidate could not be verified.",
  head: "The current Cloud main revision could not be verified.",
  image: "The sealed proof image could not be verified.",
  push: "The proof image push did not complete; its outcome may be unknown.",
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

/** A closed baseline environment: no token, database URL, bootstrap value, arbitrary Node option or unneeded CI secret. */
export function proofProcessEnvironment(
  environment: NodeJS.ProcessEnv,
  additional: readonly string[] = [],
): NodeJS.ProcessEnv {
  const names = [
    "PATH",
    "HOME",
    "USERPROFILE",
    "SystemRoot",
    "WINDIR",
    "TEMP",
    "TMP",
    "TMPDIR",
    "LANG",
    "LC_ALL",
    "CI",
    ...additional,
  ];
  return Object.fromEntries(
    names.flatMap((name) => {
      const value = environment[name];
      return value === undefined ? [] : [[name, value]];
    }),
  );
}

/** Deadlines can be shortened by synthetic tests; the protected workflow uses the fixed production defaults. */
export interface SensitiveDeadline {
  deadlineMs?: number;
  killGraceMs?: number;
}

export async function runSensitive(
  stage: Stage,
  command: string,
  args: readonly string[],
  environment: NodeJS.ProcessEnv,
  output: "json" | "discard",
  options: SensitiveDeadline = {},
): Promise<unknown> {
  const deadlineMs = options.deadlineMs ?? 180_000;
  const killGraceMs = options.killGraceMs ?? 1_000;
  if (
    !Number.isSafeInteger(deadlineMs) ||
    deadlineMs < 1 ||
    !Number.isSafeInteger(killGraceMs) ||
    killGraceMs < 1
  )
    throw new SensitiveProcessError(stage, null);
  return new Promise((resolve, reject) => {
    let child: ReturnType<typeof spawn>;
    try {
      child = spawn(command, [...args], {
        cwd: root,
        windowsHide: true,
        // The protected job runs on Linux. Its own process group also contains subprocesses that inherit its pipes.
        detached: process.platform !== "win32",
        stdio: ["ignore", "pipe", "pipe"],
        env: { ...environment, WRANGLER_SEND_METRICS: "false" },
      });
    } catch {
      reject(new SensitiveProcessError(stage, null));
      return;
    }
    let bytes = 0;
    let interrupted = false;
    let settled = false;
    let escalation: ReturnType<typeof setTimeout> | undefined;
    const chunks: Buffer[] = [];
    const finish = (error: SensitiveProcessError | undefined, value?: unknown) => {
      if (settled) return;
      settled = true;
      clearTimeout(deadline);
      if (escalation !== undefined) clearTimeout(escalation);
      if (error) reject(error);
      else resolve(value);
    };
    const signalOwned = (signal: "SIGTERM" | "SIGKILL") => {
      if (child.pid === undefined) return;
      try {
        if (process.platform !== "win32") process.kill(-child.pid, signal);
        else child.kill(signal);
      } catch {
        // If the group has already disappeared, still try the owned direct child; never expose the error or arguments.
        try {
          child.kill(signal);
        } catch {
          /* already exited */
        }
      }
    };
    const terminate = () => {
      if (interrupted || settled) return;
      interrupted = true;
      chunks.length = 0;
      if (process.platform === "win32" && child.pid !== undefined) {
        // The protected job is Linux; on Windows use the OS's explicit tree operation for local test processes.
        try {
          const systemRoot = process.env.SystemRoot ?? process.env.WINDIR ?? "C:\\Windows";
          const killer = spawn(
            path.join(systemRoot, "System32", "taskkill.exe"),
            ["/PID", String(child.pid), "/T", "/F"],
            {
              windowsHide: true,
              stdio: "ignore",
              env: { SystemRoot: systemRoot },
            },
          );
          killer.on("error", () => {});
          killer.unref();
        } catch {
          /* The hard direct-child fallback below still applies. */
        }
      } else signalOwned("SIGTERM");
      escalation = setTimeout(() => {
        signalOwned("SIGKILL");
        // A descendant can retain a pipe after its parent exits; do not wait on pipe close indefinitely.
        child.stdout?.destroy();
        child.stderr?.destroy();
        child.unref();
        finish(new SensitiveProcessError(stage, null));
      }, killGraceMs);
    };
    const deadline = setTimeout(terminate, deadlineMs);
    child.stdout?.on("data", (chunk: Buffer) => {
      if (output === "discard" || interrupted) return;
      bytes += chunk.length;
      if (bytes > maxJsonBytes) terminate();
      else chunks.push(chunk);
    });
    child.stderr?.on("data", () => {});
    child.once("error", () => finish(new SensitiveProcessError(stage, null)));
    child.once("close", (code) => {
      if (interrupted) {
        signalOwned("SIGKILL");
        finish(new SensitiveProcessError(stage, null));
        return;
      }
      if (code !== 0) {
        finish(new SensitiveProcessError(stage, code));
        return;
      }
      if (output === "discard") {
        finish(undefined);
        return;
      }
      try {
        finish(undefined, JSON.parse(Buffer.concat(chunks).toString("utf8").trim()));
      } catch {
        finish(new SensitiveProcessError(stage, null));
      }
    });
  });
}
