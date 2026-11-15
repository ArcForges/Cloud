// SPDX-License-Identifier: AGPL-3.0-only
// Complete BLAKE3's asynchronous WebAssembly initialization before Wrangler hashes assets.
import { load } from "blake3-wasm";
import assert from "node:assert/strict";
import { createRequire, registerHooks } from "node:module";
import { resolve } from "node:path";

registerHooks({
  resolve(specifier, context, nextResolve) {
    if (specifier === "unenv" && context.parentURL?.replaceAll("\\", "/").includes("/wrangler/")) {
      return { url: new URL("./unenv-compat.ts", import.meta.url).href, shortCircuit: true };
    }
    // Cloudflare's current preset names the v2 paths; stable unenv exposes the
    // same runtime category below runtime/, with node modules in index files.
    if (specifier.startsWith("unenv/node/")) {
      return nextResolve(
        `unenv/runtime/node/${specifier.slice("unenv/node/".length)}/index`,
        context,
      );
    }
    if (/^unenv\/(?:mock|npm|polyfill)\//u.test(specifier)) {
      return nextResolve(specifier.replace("unenv/", "unenv/runtime/"), context);
    }
    return nextResolve(specifier, context);
  },
});

await load();

// Adapted from Web 829cf665f52e595b767c0a209815096f448912af, AGPL-3.0-only.
// Wrangler's current dev controller still constructs V4 options, then calls the V5 converter. The selected stable
// Miniflare is V4, so that options object is already in its native format. Keep this bridge in the owned invocation
// layer; the pinned vendor packages remain byte-identical to their registry archives.
const require = createRequire(import.meta.url);
const fromWrangler = createRequire(require.resolve("wrangler"));
assert.equal(fromWrangler("miniflare/package.json").version, "4.20260730.0");
const miniflare = fromWrangler("miniflare") as {
  convertV4MiniflareOptions?: (options: unknown) => unknown;
  resolveDevRegistryPath?: (directory?: string) => string;
  getDefaultDevRegistryPath: () => string;
};
assert.equal(miniflare.convertV4MiniflareOptions, undefined);
assert.equal(miniflare.resolveDevRegistryPath, undefined);
assert.equal(typeof miniflare.getDefaultDevRegistryPath, "function");
miniflare.convertV4MiniflareOptions = (options: unknown) => options;
miniflare.resolveDevRegistryPath = (directory?: string) =>
  directory === undefined ? miniflare.getDefaultDevRegistryPath() : resolve(directory);
