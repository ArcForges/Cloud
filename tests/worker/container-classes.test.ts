// SPDX-License-Identifier: AGPL-3.0-only
// Pins that the production Container class is the unchanged Hello class and that the outbound
// interception, the environment hook and the foundation handlers belong only to the proof class.
import assert from "node:assert/strict";
import { register } from "node:module";
import test from "node:test";

// `cloudflare:workers` only exists inside workerd; a minimal stand-in lets the real Worker module
// and the real @cloudflare/containers registry run under Node.
const stub = [
  "export class DurableObject { constructor(ctx, env) { this.ctx = ctx; this.env = env; } }",
  "export class WorkerEntrypoint { constructor(ctx, env) { this.ctx = ctx; this.env = env; } }",
  "export const env = {};",
].join("\n");
const hooks = `
export async function resolve(specifier, context, next) {
  if (specifier === "cloudflare:workers")
    return { url: "data:text/javascript,${encodeURIComponent(stub)}", shortCircuit: true };
  try {
    return await next(specifier, context);
  } catch (error) {
    // The package is authored for bundlers and imports its own files without an extension.
    if (specifier.startsWith(".") && !/[.][cm]?[jt]s$/u.test(specifier))
      return next(specifier + ".js", context);
    throw error;
  }
}`;
register(`data:text/javascript,${encodeURIComponent(hooks)}`);

type Statics = { outboundByHost?: Record<string, unknown>; outboundHandlers?: unknown };
type Constructable = (new (ctx: object, env: object) => Record<string, unknown>) & Statics;
// Imported through a variable so the Node-side project does not type-check the workerd-only module.
const workerModule = "../../worker/index.ts";
const worker = (await import(workerModule)) as unknown as {
  CloudContainer: Constructable;
  FoundationContainer: Constructable;
  ContainerProxy: unknown;
};
const { CloudContainer, FoundationContainer } = worker;

// Only what the constructor touches; the deferred start-up callback is deliberately not run.
const containerContext = {
  container: { running: false },
  storage: {
    kv: { get: () => undefined, put: () => undefined },
    sql: { exec: () => [] },
  },
  blockConcurrencyWhile: () => Promise.resolve(),
};

test("the production Container class registers exactly the ai.internal outbound host (HAR.40 reviewed change)", () => {
  assert.deepEqual(Object.keys(CloudContainer.outboundByHost ?? {}), ["ai.internal"]);
  assert.equal(typeof CloudContainer.outboundByHost?.["ai.internal"], "function");
  assert.equal(
    CloudContainer.outboundHandlers,
    undefined,
    "no named handler set beyond the ai.internal host",
  );
});

test("the production Container class has no constructor, environment hook or foundation import", () => {
  assert.deepEqual(Object.getOwnPropertyNames(CloudContainer.prototype), ["constructor"]);
  const source = CloudContainer.toString();
  assert.doesNotMatch(source, /constructor|envVars|containerEnvironment|Foundation/u);
});

test("the production Container keeps the Hello settings and no environment variables", () => {
  const instance = new CloudContainer(containerContext, {
    FOUNDATION_PROOF: "enabled",
    HMAC_C2W_SECRET: "x",
  });
  assert.equal(instance.defaultPort, 8080);
  assert.equal(instance.sleepAfter, "60s");
  assert.equal(instance.enableInternet, false);
  assert.deepEqual(instance.envVars, {}, "no foundation variable reaches the production class");
});

test("only the proof class carries the storage, objects and harness alarm hosts and the environment hook; ai.internal stays production-only", () => {
  assert.deepEqual(Object.keys(FoundationContainer.outboundByHost ?? {}).sort(), [
    "harness.internal",
    "objects.internal",
    "storage.internal",
  ]);
  assert.equal(typeof FoundationContainer.outboundByHost?.["harness.internal"], "function");
  assert.equal(
    CloudContainer.outboundByHost?.["harness.internal"],
    undefined,
    "the production class never reaches the harness alarm host",
  );
  assert.equal(Object.getPrototypeOf(FoundationContainer), CloudContainer);
  assert.equal(
    FoundationContainer.outboundByHost?.["ai.internal"],
    undefined,
    "the proof class never reaches the ai.internal handler",
  );

  const disabled = new FoundationContainer(containerContext, {});
  assert.deepEqual(disabled.envVars, {}, "without the proof flag the proof class passes nothing");
  assert.equal(disabled.enableInternet, false);
  const enabled = new FoundationContainer(containerContext, { FOUNDATION_PROOF: "enabled" });
  assert.equal((enabled.envVars as Record<string, string>).ARCFORGES_FOUNDATION_PROOF, "enabled");
});

test("the 60 second sleep timer never stops a Container that has a request or a stream in flight", () => {
  // A server stream may live longer than sleepAfter (streamLifetimeMs). The library counts every proxied
  // request until its response body ends and treats the Container as active meanwhile; this pins that
  // behavior of the exact locked @cloudflare/containers so an upgrade cannot silently end open streams.
  const container = new CloudContainer(containerContext, {}) as Record<string, unknown> & {
    inflightRequests: number;
    sleepAfterMs: number;
    isActivityExpired(): boolean;
  };
  assert.equal(container.sleepAfter, "60s");
  container.sleepAfterMs = Date.now() - 1_000;
  container.inflightRequests = 0;
  assert.equal(container.isActivityExpired(), true, "an idle Container sleeps after sleepAfter");
  container.sleepAfterMs = Date.now() - 1_000;
  container.inflightRequests = 1;
  assert.equal(container.isActivityExpired(), false, "an open request or stream keeps it awake");
  assert.ok(container.sleepAfterMs > Date.now(), "and the sleep window is renewed");
});
