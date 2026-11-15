// SPDX-License-Identifier: AGPL-3.0-only
// Complete BLAKE3's asynchronous WebAssembly initialization before Wrangler hashes assets.
import { load } from "blake3-wasm";
import { registerHooks } from "node:module";

registerHooks({
  resolve(specifier, context, nextResolve) {
    if (specifier === "unenv" && context.parentURL?.replaceAll("\\", "/").includes("/wrangler/")) {
      return { url: new URL("./unenv-compat.ts", import.meta.url).href, shortCircuit: true };
    }
    // Cloudflare's current preset names the v2 paths; stable unenv exposes the
    // same runtime category below runtime/, with node modules in index files.
    if (specifier.startsWith("unenv/node/")) {
      return nextResolve(`unenv/runtime/node/${specifier.slice("unenv/node/".length)}/index`, context);
    }
    if (/^unenv\/(?:mock|npm|polyfill)\//u.test(specifier)) {
      return nextResolve(specifier.replace("unenv/", "unenv/runtime/"), context);
    }
    return nextResolve(specifier, context);
  },
});

await load();
