// SPDX-License-Identifier: AGPL-3.0-only
// Command line of the D1 migration tooling.
//
//   node eng/migrations/cli.ts check [--base <ref>]      validate the catalog, the lock and the pending files; with --base, the lock must extend the base branch's lock
//   node eng/migrations/cli.ts lock                       lock numbered files that are not locked yet (first lock of a baseline)
//   node eng/migrations/cli.ts assign [file ...]          integration owner, at merge: number the pending migrations and lock them
//   node eng/migrations/cli.ts plan                       list what is pending (offline)
//   node eng/migrations/cli.ts status|compat|apply [--stop-after N] [--allow-contract]
//        against the Cloudflare D1 REST API of the account and database named by CLOUDFLARE_ACCOUNT_ID, D1_DATABASE_ID and
//        the secret CLOUDFLARE_API_TOKEN (read from the environment by the gated deployment job; never printed)
import { execFileSync } from "node:child_process";
import { randomUUID } from "node:crypto";
import path from "node:path";
import { fileURLToPath } from "node:url";
import {
  appendOnlyProblems,
  assignPending,
  checkPending,
  defaultMigrationsDirectory,
  listPending,
  loadCatalog,
  lockNumbered,
  lockFileName,
  readLock,
  repositoryRoot,
} from "./catalog.ts";
import { RestMigrationClient } from "./clients.ts";
import { applyPending, compatibility, status } from "./runner.ts";

function flag(argv: string[], name: string): string | undefined {
  const at = argv.indexOf(name);
  return at >= 0 ? argv[at + 1] : undefined;
}

function requireEnv(name: string): string {
  const value = process.env[name];
  if (!value) {
    process.stderr.write(`${name} is not set\n`);
    process.exit(2);
  }
  return value;
}

export async function main(argv: string[]): Promise<number> {
  const [command, ...rest] = argv;
  const directory = defaultMigrationsDirectory;
  switch (command) {
    case "check": {
      const catalog = loadCatalog(directory);
      checkPending(directory);
      const base = flag(rest, "--base");
      if (base) {
        const relative = path
          .relative(repositoryRoot, path.join(directory, lockFileName))
          .replaceAll("\\", "/");
        let baseText: string;
        try {
          baseText = execFileSync("git", ["show", `${base}:${relative}`], {
            cwd: repositoryRoot,
            encoding: "utf8",
          });
        } catch {
          process.stderr.write(`the lock does not exist at ${base}; nothing to compare\n`);
          baseText = JSON.stringify({ schemaVersion: 1, migrations: [] });
        }
        const problems = appendOnlyProblems(baseText, readLock(directory));
        if (problems.length > 0) {
          for (const problem of problems) process.stderr.write(`${problem}\n`);
          return 1;
        }
      }
      process.stdout.write(
        `migrations ok: ${catalog.length} numbered, ${listPending(directory).length} pending\n`,
      );
      return 0;
    }
    case "lock": {
      const entries = lockNumbered(directory);
      loadCatalog(directory);
      process.stdout.write(`locked ${entries.length} migrations\n`);
      return 0;
    }
    case "assign": {
      const assigned = assignPending(directory, rest.length > 0 ? rest : undefined);
      process.stdout.write(`assigned ${assigned.length}: ${assigned.join(", ")}\n`);
      return 0;
    }
    case "plan": {
      for (const migration of loadCatalog(directory))
        process.stdout.write(
          `${migration.file} ${migration.mode} ${migration.statements.length} statements\n`,
        );
      for (const file of listPending(directory)) process.stdout.write(`pending ${file}\n`);
      return 0;
    }
    case "status":
    case "compat":
    case "apply": {
      const client = new RestMigrationClient({
        accountId: requireEnv("CLOUDFLARE_ACCOUNT_ID"),
        databaseId: requireEnv("D1_DATABASE_ID"),
        apiToken: requireEnv("CLOUDFLARE_API_TOKEN"),
      });
      const migrations = loadCatalog(directory);
      if (command === "status") {
        process.stdout.write(`${JSON.stringify(await status(client, migrations), null, 2)}\n`);
        return 0;
      }
      if (command === "compat") {
        // Whether this build may use a database that may be ahead of it (a rolled-back release): the horizons decide.
        const current = await status(client, migrations);
        const verdict = compatibility(current, { schemaVersion: migrations.length - 1 });
        const report = {
          ...verdict,
          schemaVersion: current.schemaVersion,
          readHorizon: current.readHorizon,
          writeHorizon: current.writeHorizon,
          databaseAhead: current.databaseAhead,
        };
        process.stdout.write(`${JSON.stringify(report, null, 2)}
`);
        return verdict.canWrite ? 0 : 1;
      }
      const stopAfter = flag(rest, "--stop-after");
      const result = await applyPending({
        client,
        migrations,
        runner: process.env.GITHUB_RUN_ID
          ? `gh-${process.env.GITHUB_RUN_ID}-${process.env.GITHUB_RUN_ATTEMPT ?? "1"}-${process.env.GITHUB_JOB ?? "job"}`
          : `local-${randomUUID()}`,
        now: Date.now,
        compatibility: {
          sourceRevision: process.env.SOURCE_REVISION ?? "local",
          planManifestHash: process.env.PLAN_MANIFEST_HASH ?? "",
          abi: process.env.ABI_VERSION ?? "",
          runtime: process.env.RUNTIME_VERSION ?? "",
        },
        ...(stopAfter === undefined ? {} : { stopAfter: Number(stopAfter) }),
        allowContract: rest.includes("--allow-contract"),
      });
      process.stdout.write(`${JSON.stringify(result, null, 2)}\n`);
      return 0;
    }
    default:
      process.stderr.write(
        "usage: node eng/migrations/cli.ts check|lock|assign|plan|status|apply\n",
      );
      return 2;
  }
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  main(process.argv.slice(2)).then(
    (code) => {
      process.exitCode = code;
    },
    (error: unknown) => {
      process.stderr.write(`${error instanceof Error ? error.message : String(error)}\n`);
      process.exitCode = 1;
    },
  );
}
