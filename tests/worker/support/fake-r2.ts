// SPDX-License-Identifier: AGPL-3.0-only
// An in-memory R2 stand-in that, like R2, verifies a declared SHA-256 of the received bytes.
import { createHash } from "node:crypto";
import { readBounded } from "../../../worker/private/bounded-body.ts";
import type { R2Like, R2ObjectBodyLike, R2ObjectLike } from "../../../worker/foundation/types.ts";

export interface FakeR2 extends R2Like {
  readonly objects: Map<string, { bytes: Uint8Array; customMetadata: Record<string, string> }>;
  puts: number;
}

export function createFakeR2(): FakeR2 {
  const objects: FakeR2["objects"] = new Map();
  const fake: FakeR2 = {
    objects,
    puts: 0,
    async put(key, value, options): Promise<R2ObjectLike | null> {
      fake.puts++;
      if (options.onlyIf?.etagDoesNotMatch === "*" && objects.has(key)) return null;
      const bytes =
        value instanceof Uint8Array ? value : await readBounded(value, 64 * 1024 * 1024);
      if (createHash("sha256").update(bytes).digest("hex") !== options.sha256)
        throw new Error("The SHA-256 checksum you specified did not match what we received.");
      objects.set(key, { bytes, customMetadata: options.customMetadata });
      return { size: bytes.length, customMetadata: options.customMetadata };
    },
    head(key) {
      const stored = objects.get(key);
      return Promise.resolve(
        stored ? { size: stored.bytes.length, customMetadata: stored.customMetadata } : null,
      );
    },
    get(key, options): Promise<R2ObjectBodyLike | null> {
      const stored = objects.get(key);
      if (!stored) return Promise.resolve(null);
      const slice = options
        ? stored.bytes.slice(options.range.offset, options.range.offset + options.range.length)
        : stored.bytes;
      return Promise.resolve({
        size: stored.bytes.length,
        customMetadata: stored.customMetadata,
        body: new ReadableStream({
          start(controller) {
            controller.enqueue(slice);
            controller.close();
          },
        }),
      });
    },
    delete(key) {
      objects.delete(key);
      return Promise.resolve();
    },
  };
  return fake;
}
