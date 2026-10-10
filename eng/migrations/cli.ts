// SPDX-License-Identifier: AGPL-3.0-only
// Command line of the D1 migration tooling (CLOUD.84 U9, S41(1)). This file is a shim: it forwards argv and environment to the migrator
// (eng/migrations/shim.ts), whose `migrate` command holds every catalog, lock and live decision in C#.
//
//   node eng/migrations/cli.ts check [--base <ref>]      validate the catalog, the lock and the pending files; with --base, the lock must extend the base branch's lock
//   node eng/migrations/cli.ts lock                       lock numbered files that are not locked yet (first lock of a baseline)
//   node eng/migrations/cli.ts assign [file ...]          integration owner, at merge: number the pending migrations and lock them
//   node eng/migrations/cli.ts plan                       list what is pending (offline)
//   node eng/migrations/cli.ts status|compat|apply [--stop-after N] [--allow-contract]
//        against the Cloudflare D1 REST API of the account and database named by CLOUDFLARE_ACCOUNT_ID, D1_DATABASE_ID and
//        the secret CLOUDFLARE_API_TOKEN (read from the environment by the gated deployment job; never printed)
import path from "node:path";
import { fileURLToPath } from "node:url";
import { runMigrator } from "./shim.ts";

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  process.exitCode = runMigrator(process.argv.slice(2));
}
