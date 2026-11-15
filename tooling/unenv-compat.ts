// SPDX-License-Identifier: AGPL-3.0-only
// Adapt Wrangler's environment-description API to the pinned stable unenv API.
import assert from "node:assert/strict";
import { env, nodeless, type Preset } from "unenv";

type CloudflarePreset = Omit<Preset, "inject"> & {
  inject?: Record<string, string | string[] | false>;
};

export function defineEnv(options: { presets: CloudflarePreset[]; npmShims: boolean }) {
  assert.deepEqual(Object.keys(options).sort(), ["npmShims", "presets"]);
  const merged = env(
    ...(options.npmShims ? [{ ...nodeless, polyfill: [] }] : []),
    ...(options.presets as Preset[]),
  );
  // New presets use false to remove a previous global injection. Stable unenv's
  // merger retains that sentinel, while Wrangler expects only module references.
  merged.inject = Object.fromEntries(
    Object.entries(merged.inject).filter(([, value]) => value !== (false as unknown)),
  );
  merged.external = [...new Set(merged.external)];
  merged.polyfill = [...new Set(merged.polyfill)];
  return { env: merged };
}
