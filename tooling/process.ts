// SPDX-License-Identifier: AGPL-3.0-only
import { spawn } from "node:child_process";
import { createHash } from "node:crypto";
import { createReadStream } from "node:fs";
import { mkdir, readFile, writeFile } from "node:fs/promises";
import path from "node:path";

export const root = path.resolve(import.meta.dirname, "..");
export const candidateDir = path.join(root, "artifacts", "candidate");
export const wrangler = path.join(root, "node_modules", "wrangler", "bin", "wrangler.js");

export function gitEnvironment(): NodeJS.ProcessEnv {
  return Object.fromEntries(Object.entries(process.env).filter(([key]) => !key.startsWith("GIT_")));
}

export async function run(command: string, args: string[], capture = false): Promise<string> {
  // Some Windows machines expose Docker only through a WSL wrapper. No shell interpolation.
  if (
    command === "docker" &&
    process.platform === "win32" &&
    process.env.CLOUD_DOCKER_WSL === "1"
  ) {
    args = ["-e", "docker", ...args];
    command = "wsl.exe";
  }
  return new Promise((resolve, reject) => {
    const child = spawn(command, args, {
      cwd: root,
      windowsHide: true,
      stdio: capture ? ["ignore", "pipe", "inherit"] : "inherit",
      env: {
        ...(command === "git" ? gitEnvironment() : process.env),
        WRANGLER_SEND_METRICS: "false",
      },
    });
    let output = "";
    child.stdout?.on("data", (chunk: Buffer) => {
      output += chunk.toString();
    });
    child.on("error", reject);
    child.on("exit", (code) => {
      if (code === 0) resolve(output.trim());
      else reject(new Error(`${path.basename(command)} exited with code ${code}.`));
    });
  });
}

export async function readJson<T>(file: string): Promise<T> {
  return JSON.parse(await readFile(file, "utf8")) as T;
}

export async function writeJson(file: string, value: unknown): Promise<void> {
  await mkdir(path.dirname(file), { recursive: true });
  await writeFile(file, `${JSON.stringify(value, null, 2)}\n`);
}

export async function sha256(file: string): Promise<string> {
  const hash = createHash("sha256");
  for await (const chunk of createReadStream(file)) hash.update(chunk);
  return hash.digest("hex");
}
