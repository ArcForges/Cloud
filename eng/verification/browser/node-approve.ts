// SPDX-License-Identifier: AGPL-3.0-only
// The node-approve run (AF-CTR-04 E3): acceptance.ts --node-approve. Run from the repository root, after `npm ci` in this directory,
// beside center/cmd/node-probe on the same machine (its loopback receiver must be the browser's):
//
//   go run ./center/cmd/node-probe -center <base URL> -flow pkce -dir <dir> -case pkce-1     (in center/, one per case)
//   node eng/verification/browser/node-approve.ts --base-url <base URL> --watch <dir> [--cases 2] [--negative]
//
// The browser is the pinned Chromium with the saved owner credential (MOCKED hardware: a virtual authenticator in a real browser);
// node-probe is a MOCKED node; the ArcForges node's end-to-end test (CloudSignInTests) writes the same handshake files as a REAL node.
// See acceptance.ts --help.
import path from "node:path";
import { fileURLToPath } from "node:url";
import { main, realDependencies } from "./acceptance.ts";

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url))
  process.exitCode = await main(["--node-approve", ...process.argv.slice(2)], realDependencies());
