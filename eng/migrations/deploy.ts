// SPDX-License-Identifier: AGPL-3.0-only
// The deployment-time caller of the D1 migration step (CLOUD.70; CLOUD.84 U10, S41(1)): the gated step of the deployment jobs that brings a
// deployed business database to the schema of the build that is about to be promoted. It never runs from the Container.
//
// This file is a shim: it forwards argv and environment to the sealed migrator (eng/migrations/shim.ts). The target selection, the release
// plan, the context and identity checks, the excluded-build and gate refusals and the gate record are C# decisions in
// src/ArcForges.Cloud.Storage.D1/Deploy, run by `migrate deploy` in tools/ArcForges.Cloud.Generation. A failing step exits non-zero, the
// workflow steps that promote run only after it succeeded, and tooling/cloudflare.ts refuses to promote without the gate record it writes.
//
//   node eng/migrations/deploy.ts deploy --target production|proof   the gated live step (CI only, secret from the environment)
//
// Environment (names only): CLOUDFLARE_ACCOUNT_ID, CLOUDFLARE_API_TOKEN (secret, never printed), optional D1_DATABASE_ID (overrides the
// lookup by the configured database name), GITHUB_* from the runner.
import path from "node:path";
import { fileURLToPath } from "node:url";
import { runMigrator } from "./shim.ts";

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  process.exitCode = runMigrator(["deploy", ...process.argv.slice(2)]);
}
