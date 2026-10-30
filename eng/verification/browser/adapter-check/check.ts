// SPDX-License-Identifier: AGPL-3.0-only
// Run after `npm ci` in the parent directory, from the repository root:
//   npx tsc -p eng/verification/browser/adapter-check/tsconfig.json
// It fails to compile if the installed playwright-core no longer has the shapes that ../driver.ts uses. The root type check does
// not include this directory (the root project never installs playwright-core).
import * as playwright from "playwright-core";
import type { PwModule } from "../driver.ts";

const adapted: PwModule = playwright;
void adapted;
