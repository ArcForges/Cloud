// SPDX-License-Identifier: AGPL-3.0-only
// Keep the owned options boundary while using Wrangler's required environment API.
import assert from "node:assert/strict";
import { defineEnv as upstreamDefineEnv, type Preset } from "unenv";

export function defineEnv(options: { presets: Preset[]; npmShims: boolean }) {
  assert.deepEqual(Object.keys(options).sort(), ["npmShims", "presets"]);
  return upstreamDefineEnv(options);
}
