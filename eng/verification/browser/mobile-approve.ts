// SPDX-License-Identifier: AGPL-3.0-only
// The mobile-approve run (AF-CTR-04 part M, H3): acceptance.ts --mobile-approve. Run from the repository root, after `npm ci` in this
// directory, beside center/cmd/mobile-probe (MobileProbe, the MOCKED app):
//
//   go run ./cmd/mobile-probe -center <base URL> -dir <dir> -case approve-1 -scenario approve       (in center/, one per case)
//   node eng/verification/browser/mobile-approve.ts --base-url <base URL> --watch <dir> [--cases 4]
//
// The browser is the pinned Chromium with the saved owner credential (MOCKED hardware: a virtual authenticator in a real browser);
// mobile-probe is a MOCKED app. See acceptance.ts --help and docs/center-mobile.md (H3 checklist).
import path from "node:path";
import { fileURLToPath } from "node:url";
import { main, realDependencies } from "./acceptance.ts";

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url))
  process.exitCode = await main(["--mobile-approve", ...process.argv.slice(2)], realDependencies());
