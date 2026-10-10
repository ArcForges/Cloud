// SPDX-License-Identifier: AGPL-3.0-only
// The Node shim of the D1 migration tooling (CLOUD.84 U9, U10, S41(1)). It forwards argv and environment to the migrator and makes no
// migration decision: the decisions are the C# rules in src/ArcForges.Cloud.Storage.D1 (MigrationRunner and Deploy), run by the
// `migrate` command of tools/ArcForges.Cloud.Generation.
//
// In a deployment job the migrator is the sealed tool archive that the candidate job produced (artifacts/candidate/arcforges-tool.tar,
// tooling/sealed-tool.ts). Its SHA-256 is checked against the candidate manifest before it is extracted and run, so a job never runs a
// migrator that the candidate did not seal. Outside a candidate (local development and the quality job) it runs the same tool project with
// dotnet run.
import { spawnSync } from "node:child_process";
import { existsSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { candidateManifestPath, extractSealedTool } from "../../tooling/sealed-tool.ts";

export const repositoryRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../..");
export const toolProject = "tools/ArcForges.Cloud.Generation";

export interface Invocation {
  command: string;
  args: string[];
  env: NodeJS.ProcessEnv;
}

/** The invocation of the migrator for development: the tool project through dotnet run. Argument order is kept. */
export function developmentInvocation(argv: readonly string[], env: NodeJS.ProcessEnv): Invocation {
  return {
    command: "dotnet",
    args: ["run", "--project", toolProject, "--", "migrate", ...argv],
    env,
  };
}

/** The invocation of a sealed migrator extracted to a directory: its executable, then the migrate command. */
export function sealedInvocation(
  executable: string,
  argv: readonly string[],
  env: NodeJS.ProcessEnv,
): Invocation {
  return { command: executable, args: ["migrate", ...argv], env };
}

/**
 * The read-only source check of the hosted Source job (`check --base origin/main`, run by check:physical). It reads the tree and changes no
 * database, so it is the one command that GitHub Actions may run without a candidate.
 */
export const sourceCheckCommand = "check";

/**
 * The migrator to run: the sealed archive when a candidate is present (checked and extracted), else the tool project. Under GitHub Actions
 * the migrator never falls back to a build from source (AGENTS.md; CLOUD.84 S41(1), S45(3)): without the candidate manifest every command
 * refuses, except the read-only source check. Only a local run may build the migrator from the tree.
 */
export function prepareInvocation(
  argv: readonly string[],
  env: NodeJS.ProcessEnv,
  root: string,
): Invocation {
  if (!existsSync(candidateManifestPath(root))) {
    if (env.GITHUB_ACTIONS === "true" && argv[0] !== sourceCheckCommand)
      throw new Error(
        "the candidate manifest is absent in GitHub Actions; nothing is built or run",
      );
    return developmentInvocation(argv, env);
  }
  return sealedInvocation(extractSealedTool(root).executable, argv, env);
}

/** Runs the migrator with the given arguments and the process environment, and returns its exit code. */
export function runMigrator(
  argv: readonly string[],
  env: NodeJS.ProcessEnv = process.env,
  root = repositoryRoot,
): number {
  let invocation: Invocation;
  try {
    invocation = prepareInvocation(argv, env, root);
  } catch (error) {
    process.stderr.write(`${error instanceof Error ? error.message : String(error)}\n`);
    return 1;
  }
  const result = spawnSync(invocation.command, invocation.args, {
    cwd: root,
    env: invocation.env,
    stdio: "inherit",
  });
  if (result.error) {
    process.stderr.write(`the migrator could not be started (${result.error.name}); nothing is run
`);
    return 1;
  }
  return result.status ?? 1;
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  process.exitCode = runMigrator(process.argv.slice(2));
}
