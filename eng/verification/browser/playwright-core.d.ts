// SPDX-License-Identifier: AGPL-3.0-only
// The root project never installs playwright-core (eng/verification/browser is a package of its own), so its type check sees the module
// as untyped. driver.ts casts it to the subset of the API it uses, and adapter-check/ compiles that subset against the installed
// package's own types.
declare module "playwright-core";
