// SPDX-License-Identifier: AGPL-3.0-only
// Pins that the production Container class is the unchanged Hello class and that the outbound
// interception, the environment hook and the foundation handlers belong only to the proof class.
import assert from "node:assert/strict";
import { readdirSync, readFileSync, statSync } from "node:fs";
import path from "node:path";
import { register } from "node:module";
import test from "node:test";
import { classifyStartFailureResponse } from "../../worker/readiness/container.ts";

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
// The production entry carries the production class only; the proof entry carries the proof class (CLOUD.84 D1).
const workerModule = "../../worker/index.ts";
const proofModule = "../../worker/proof/entry.ts";
const worker = (await import(workerModule)) as unknown as {
  CloudContainer: Constructable;
  ContainerProxy: unknown;
};
const proof = (await import(proofModule)) as unknown as {
  FoundationContainer: Constructable;
};
const acceptanceModule = "../../worker/acceptance/entry.ts";
const acceptance = (await import(acceptanceModule)) as unknown as {
  FoundationContainer: Constructable;
  FoundationJobCoordinator: new (ctx: object, env: object) => { alarm(): Promise<void> };
  HarnessRunAlarm: new (ctx: object, env: object) => { alarm(): Promise<void> };
  default: unknown;
};
const { CloudContainer } = worker;
const { FoundationContainer } = proof;
type Settings = { entrypoint?: string[]; envVars: Record<string, string>; enableInternet: boolean };
const containerModule = "../../worker/foundation/cloud-container.ts";
const { centerContainerSettings, startDigest, startDigestKey } = (await import(
  containerModule
)) as unknown as {
  centerContainerSettings(environment: Record<string, string>): Settings;
  startDigest(revision: string, settings: Settings): Promise<string>;
  startDigestKey: string;
};

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

test("the production Container forwards only Neon configuration and keeps proof classes isolated", () => {
  const environment = {
    ARCFORGES_NEON_HELLO: "enabled",
    NEON_DATABASE_URL: "synthetic-runtime-secret",
    NEON_DATABASE_URL_DIRECT: "never-forward",
    HMAC_C2W_SECRET: "never-forward",
  };
  const enabled = new CloudContainer(containerContext, environment);
  assert.equal(enabled.enableInternet, true);
  assert.deepEqual(enabled.envVars, {
    ARCFORGES_NEON_HELLO: "enabled",
    NEON_DATABASE_URL: "synthetic-runtime-secret",
  });
  assert.throws(
    () => new CloudContainer(containerContext, { ARCFORGES_NEON_HELLO: "enabled" }),
    /configuration/u,
  );
  const proof = new FoundationContainer(containerContext, environment);
  assert.equal(proof.enableInternet, false);
  assert.deepEqual(proof.envVars, {});
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

test("the Go center is selected only for the production class and proof remains C#", () => {
  const environment = {
    ARCFORGES_HELLO_RUNTIME: "go",
    ARCFORGES_NEON_HELLO: "enabled",
    NEON_DATABASE_URL: "synthetic",
    ARCFORGES_CENTER_MODE: "official-hosted",
    ARCFORGES_CENTER_PUBLIC_BASE_URL: "https://center.example/api",
  };
  const production = new CloudContainer(containerContext, environment);
  assert.deepEqual(production.entrypoint, ["/app/arcforges-center"]);
  // The center's mode and base URL pass through unchanged; the center itself refuses a missing or invalid value.
  assert.deepEqual(production.envVars, {
    ARCFORGES_CENTER_MODE: "official-hosted",
    ARCFORGES_CENTER_PUBLIC_BASE_URL: "https://center.example/api",
    ARCFORGES_CENTER_SURFACES: "none",
    ARCFORGES_CENTER_CLIENT_IP_HEADER: "x-arcforges-client-ip",
    ARCFORGES_NEON_HELLO: "enabled",
    NEON_DATABASE_URL: "synthetic",
  });
  assert.equal(production.enableInternet, true);
  const proof = new FoundationContainer(containerContext, environment);
  assert.equal(proof.entrypoint, undefined);
  assert.equal(proof.enableInternet, false);
  assert.throws(
    () => new CloudContainer(containerContext, { ARCFORGES_HELLO_RUNTIME: "unknown" }),
    /Unknown Hello runtime/u,
  );
});

test("without a mode the Go center gets none and refuses to start; the C# runtime gets no center variable", () => {
  const unconfigured = new CloudContainer(containerContext, { ARCFORGES_HELLO_RUNTIME: "go" });
  assert.deepEqual(unconfigured.entrypoint, ["/app/arcforges-center"]);
  assert.equal(unconfigured.enableInternet, false);
  assert.equal(
    (unconfigured.envVars as Record<string, string> | undefined)?.ARCFORGES_CENTER_MODE,
    undefined,
  );
  const csharp = new CloudContainer(containerContext, {
    ARCFORGES_HELLO_RUNTIME: "csharp",
    ARCFORGES_CENTER_MODE: "official-hosted",
  });
  assert.equal(csharp.entrypoint, undefined);
  assert.equal(
    (csharp.envVars as Record<string, string> | undefined)?.ARCFORGES_CENTER_MODE,
    undefined,
  );
});

const centerEnvironment = {
  ARCFORGES_HELLO_RUNTIME: "go",
  ARCFORGES_NEON_HELLO: "enabled",
  NEON_DATABASE_URL: "synthetic-hello-credential",
  NEON_DATABASE_URL_DIRECT: "never-forward",
  ARCFORGES_CENTER_DATABASE_URL: "synthetic-runtime-credential",
  ARCFORGES_CENTER_MODE: "official-hosted",
  ARCFORGES_CENTER_PUBLIC_BASE_URL: "https://center.example/api",
  ARCFORGES_CENTER_PLAN_CONFIGURATION: "development-fixtures",
};

test("a Go center with a store gets the runtime role's URL and never the Hello's own Neon credential", () => {
  const production = new CloudContainer(containerContext, centerEnvironment);
  assert.deepEqual(production.envVars, {
    ARCFORGES_CENTER_MODE: "official-hosted",
    ARCFORGES_CENTER_PUBLIC_BASE_URL: "https://center.example/api",
    ARCFORGES_CENTER_PLAN_CONFIGURATION: "development-fixtures",
    ARCFORGES_CENTER_SURFACES: "none",
    ARCFORGES_CENTER_CLIENT_IP_HEADER: "x-arcforges-client-ip",
    ARCFORGES_CENTER_DATABASE_URL: "synthetic-runtime-credential",
    ARCFORGES_NEON_HELLO: "enabled",
  });
  assert.equal(production.enableInternet, true);
  // With a store the Hello needs no Neon credential of its own.
  const { NEON_DATABASE_URL: _hello, ...withoutHello } = centerEnvironment;
  assert.doesNotThrow(() => new CloudContainer(containerContext, withoutHello));
  // The C# host never receives the center's runtime credential.
  const csharp = new CloudContainer(containerContext, {
    ...centerEnvironment,
    ARCFORGES_HELLO_RUNTIME: "csharp",
  });
  assert.equal((csharp.envVars as Record<string, string>).ARCFORGES_CENTER_DATABASE_URL, undefined);
  assert.equal(
    (csharp.envVars as Record<string, string>).NEON_DATABASE_URL,
    "synthetic-hello-credential",
  );
});

test("the Go center gets the surfaces the Worker forwards and always the client-address header", () => {
  const settings = (flag: string | undefined) =>
    new CloudContainer(containerContext, { ...centerEnvironment, FLAGSHIP_SURFACES: flag })
      .envVars as Record<string, string>;
  assert.equal(settings("identity").ARCFORGES_CENTER_SURFACES, "identity");
  // The center refuses to start on an unknown surface name; the Worker forwards none of it, so it passes "none" instead.
  for (const flag of [undefined, "", "Identity", "identity,identity", "identity, operations"])
    assert.equal(settings(flag).ARCFORGES_CENTER_SURFACES, "none", String(flag));
  assert.equal(settings("identity").ARCFORGES_CENTER_CLIENT_IP_HEADER, "x-arcforges-client-ip");
  const csharp = new CloudContainer(containerContext, {
    ARCFORGES_HELLO_RUNTIME: "csharp",
    FLAGSHIP_SURFACES: "identity",
  }).envVars as Record<string, string> | undefined;
  assert.equal(csharp?.ARCFORGES_CENTER_SURFACES, undefined);
  assert.equal(csharp?.ARCFORGES_CENTER_CLIENT_IP_HEADER, undefined);
});

test("the Go center gets the identity policy override only where an environment sets one", () => {
  const policy = '{"anonymousFlowsLimit":600,"anonymousFlowsWindow":"1h"}';
  const settings = (value: string | undefined) =>
    new CloudContainer(containerContext, {
      ...centerEnvironment,
      ARCFORGES_CENTER_IDENTITY_POLICY: value,
    }).envVars as Record<string, string>;
  assert.equal(settings(policy).ARCFORGES_CENTER_IDENTITY_POLICY, policy);
  assert.equal(settings(undefined).ARCFORGES_CENTER_IDENTITY_POLICY, undefined);
  const csharp = new CloudContainer(containerContext, {
    ARCFORGES_HELLO_RUNTIME: "csharp",
    ARCFORGES_CENTER_IDENTITY_POLICY: policy,
  }).envVars as Record<string, string> | undefined;
  assert.equal(csharp?.ARCFORGES_CENTER_IDENTITY_POLICY, undefined);
});

test("the Go center gets the Android app identity only where an environment sets one (AF-CTR-04 part M)", () => {
  const identity =
    '[{"packageName":"com.arcforges.prooftest","sha256CertFingerprints":["AB"],"testOnly":true}]';
  const settings = (value: string | undefined) =>
    new CloudContainer(containerContext, {
      ...centerEnvironment,
      ARCFORGES_CENTER_ANDROID_APP: value,
    }).envVars as Record<string, string>;
  assert.equal(settings(identity).ARCFORGES_CENTER_ANDROID_APP, identity);
  assert.equal(settings(undefined).ARCFORGES_CENTER_ANDROID_APP, undefined);
  // The debug scheme is a self-hosted center's own variable: the hosted Worker never passes it.
  const withDebug = new CloudContainer(containerContext, {
    ...centerEnvironment,
    ARCFORGES_CENTER_MOBILE_DEBUG_REDIRECT: "com.arcforges.android.debug",
  } as never).envVars as Record<string, string>;
  assert.equal(withDebug.ARCFORGES_CENTER_MOBILE_DEBUG_REDIRECT, undefined);
});

test("the acceptance entry runs the Go center under the proof Container class and keeps the retired classes inert", async () => {
  const {
    FoundationContainer: AcceptanceContainer,
    FoundationJobCoordinator,
    HarnessRunAlarm,
  } = acceptance;
  assert.equal(Object.getPrototypeOf(AcceptanceContainer), CloudContainer);
  // The outbound registry is keyed by class name, which the retired C# proof class shares in this test process; the acceptance
  // entry itself registers no host and imports none of the proof foundation.
  const source = readFileSync(new URL(acceptanceModule, import.meta.url), "utf8");
  assert(!source.includes("outboundByHost"), "the acceptance class registers no outbound host");
  for (const forbidden of [
    "../proof/",
    "../foundation/entry",
    "../foundation/durable",
    "../harness/",
    "../storage/",
  ])
    assert(!source.includes(forbidden), `the acceptance entry imports ${forbidden}`);
  const container = new AcceptanceContainer(containerContext, centerEnvironment);
  assert.deepEqual(container.entrypoint, ["/app/arcforges-center"]);
  assert.equal(
    (container.envVars as Record<string, string>).ARCFORGES_CENTER_DATABASE_URL,
    "synthetic-runtime-credential",
  );
  assert.equal((container.envVars as Record<string, string>).NEON_DATABASE_URL, undefined);
  // The acceptance entry routes like the production entry without importing it (layer-entry: nothing imports the Worker entry).
  assert(source.includes('from "../router.ts"') && !source.includes("../index.ts"));
  type Entry = { fetch(request: Request, env: never, context: never): Promise<Response> };
  const production = ((await import(workerModule)) as { default: Entry }).default;
  for (const entry of [acceptance.default as Entry, production]) {
    const response = await entry.fetch(
      new Request("https://proof.arcforges.com/not-a-route"),
      {} as never,
      { waitUntil() {} } as never,
    );
    assert.equal(response.status, 404);
  }
  for (const Retained of [FoundationJobCoordinator, HarnessRunAlarm]) {
    const instance = new Retained({ storage: {} }, {});
    assert.equal((instance as { fetch?: unknown }).fetch, undefined, "no fetch handler");
    assert.equal(await instance.alarm(), undefined);
  }
});

// AF-CTR-03: a Container image rollout restarts a running center with the new image but its previous start environment. The
// Container class restarts such a center with this Worker version's settings before it forwards any request.
type Following = Record<string, unknown> & {
  fetch(request: Request): Promise<Response>;
  containerFetch(request: Request): Promise<Response>;
  staleStopMs: number;
  staleDestroyMs: number;
  entrypoint?: string[];
  envVars: Record<string, string>;
  enableInternet: boolean;
};

/** A Container runtime stand-in: a center that exits on SIGTERM, only on SIGKILL or never, and the Durable Object's storage. */
function runtime(
  running: boolean,
  recorded: string | undefined,
  exitsOn: "SIGTERM" | "SIGKILL" | "never",
) {
  const events: string[] = [];
  const stored = new Map<string, unknown>();
  if (recorded !== undefined) stored.set(startDigestKey, recorded);
  const container = {
    running,
    signal(signal: number) {
      events.push(`signal ${signal}`);
      if (exitsOn === "SIGTERM")
        setTimeout(() => {
          container.running = false;
        }, 20);
    },
    async destroy() {
      events.push("destroy");
      if (exitsOn !== "never") container.running = false;
    },
    monitor: () => new Promise(() => {}),
  };
  const ctx = {
    container,
    storage: {
      get: async (key: string) => stored.get(key),
      put: async (key: string, value: unknown) => {
        if (key === startDigestKey) events.push("record");
        stored.set(key, value);
      },
      kv: { get: () => undefined, put: () => undefined },
      sql: { exec: () => [] },
    },
    blockConcurrencyWhile: () => Promise.resolve(),
  };
  return { ctx, container, events, stored };
}

const versionEnvironment = {
  ...centerEnvironment,
  SOURCE_REVISION: "b".repeat(40),
  FLAGSHIP_SURFACES: "identity",
};

/** A Container instance whose forwarding is recorded: the library would start a stopped center and forward the request. */
function following(
  Class: Constructable,
  state: ReturnType<typeof runtime>,
  environment: object = versionEnvironment,
): Following {
  const instance = new Class(state.ctx, environment) as unknown as Following;
  instance.containerFetch = async (request: Request) => {
    state.events.push(
      `forward ${new URL(request.url).pathname} to a ${state.container.running ? "running" : "stopped"} center`,
    );
    state.container.running = true;
    return new Response("answered");
  };
  return instance;
}

const settingsOf = (instance: Following): Settings => ({
  entrypoint: instance.entrypoint,
  enableInternet: instance.enableInternet,
  envVars: instance.envVars,
});

const health = () => new Request("http://container/healthz");

test("a center left running under another start environment is restarted with this version's settings before any request", async () => {
  for (const Class of [CloudContainer, acceptance.FoundationContainer]) {
    for (const recorded of ["digest-of-the-previous-version", undefined]) {
      const state = runtime(true, recorded, "SIGTERM");
      const instance = following(Class, state);
      const response = await instance.fetch(health());
      assert.equal(await response.text(), "answered");
      assert.deepEqual(
        state.events,
        ["signal 15", "record", "forward /healthz to a stopped center"],
        String(recorded),
      );
      assert.equal(
        state.stored.get(startDigestKey),
        await startDigest(versionEnvironment.SOURCE_REVISION, settingsOf(instance)),
      );
      // The restarted center is current: the next request (the Hello) is forwarded at once.
      await instance.fetch(
        new Request("http://container/arcforges.cloud.v1.HelloService/SayHello", {
          method: "POST",
        }),
      );
      assert.equal(state.events.length, 4);
      assert.equal(
        state.events[3],
        "forward /arcforges.cloud.v1.HelloService/SayHello to a running center",
      );
    }
  }
});

test("a center started with this version's settings is never restarted, and a stopped one is recorded before its start", async () => {
  const probe = following(CloudContainer, runtime(false, undefined, "never"));
  const current = await startDigest(versionEnvironment.SOURCE_REVISION, settingsOf(probe));
  const running = runtime(true, current, "never");
  await following(CloudContainer, running).fetch(health());
  assert.deepEqual(running.events, ["forward /healthz to a running center"]);
  const stopped = runtime(false, "digest-of-the-previous-version", "never");
  await following(CloudContainer, stopped).fetch(health());
  assert.deepEqual(stopped.events, ["record", "forward /healthz to a stopped center"]);
  assert.equal(stopped.stored.get(startDigestKey), current);
});

test("requests that arrive during the restart share it and none reaches the previous center", async () => {
  const state = runtime(true, "digest-of-the-previous-version", "SIGTERM");
  const instance = following(CloudContainer, state);
  const responses = await Promise.all([1, 2, 3].map(() => instance.fetch(health())));
  for (const response of responses) assert.equal(await response.text(), "answered");
  assert.deepEqual(state.events, [
    "signal 15",
    "record",
    "forward /healthz to a stopped center",
    "forward /healthz to a running center",
    "forward /healthz to a running center",
  ]);
});

test("a center that ignores SIGTERM is killed within the bound; one that survives is never forwarded to", async () => {
  const killed = runtime(true, "digest-of-the-previous-version", "SIGKILL");
  const instance = following(CloudContainer, killed);
  instance.staleStopMs = 50;
  assert.equal(await (await instance.fetch(health())).text(), "answered");
  assert.deepEqual(killed.events, [
    "signal 15",
    "destroy",
    "record",
    "forward /healthz to a stopped center",
  ]);

  const stuck = runtime(true, "digest-of-the-previous-version", "never");
  const refusing = following(CloudContainer, stuck);
  refusing.staleStopMs = 50;
  refusing.staleDestroyMs = 50;
  const response = await refusing.fetch(health());
  assert.equal(response.status, 500);
  // The library's own start-failure text: the Worker answers it as a retryable start failure, since nothing was forwarded.
  assert.equal(await classifyStartFailureResponse(response), "start_failed");
  assert.deepEqual(stuck.events, ["signal 15", "destroy"]);
  assert.equal(stuck.stored.get(startDigestKey), "digest-of-the-previous-version");
});

test("the start digest covers the revision, the entrypoint, the egress switch and every variable, in no particular order", async () => {
  const base: Settings = {
    entrypoint: ["/app/arcforges-center"],
    enableInternet: true,
    envVars: {
      ARCFORGES_CENTER_SURFACES: "identity",
      ARCFORGES_CENTER_DATABASE_URL: "synthetic-slot-1",
    },
  };
  const digest = await startDigest("r1", base);
  assert.match(digest, /^[0-9a-f]{64}$/u);
  assert.equal(
    await startDigest("r1", {
      ...base,
      envVars: {
        ARCFORGES_CENTER_DATABASE_URL: "synthetic-slot-1",
        ARCFORGES_CENTER_SURFACES: "identity",
      },
    }),
    digest,
  );
  for (const changed of [
    startDigest("r2", base),
    startDigest("r1", { ...base, entrypoint: undefined }),
    startDigest("r1", { ...base, enableInternet: false }),
    startDigest("r1", { ...base, envVars: { ...base.envVars, ARCFORGES_CENTER_SURFACES: "none" } }),
    startDigest("r1", {
      ...base,
      envVars: { ...base.envVars, ARCFORGES_CENTER_DATABASE_URL: "synthetic-slot-2" },
    }),
    startDigest("r1", {
      ...base,
      envVars: { ...base.envVars, ARCFORGES_CENTER_IDENTITY_POLICY: "{}" },
    }),
  ])
    assert.notEqual(await changed, digest);
});

// AF-CTR-03 A2: the owner bootstrap of a protected proof dispatch (the digest of a one-time token and its expiry) reaches the center
// as its own variables, never reaches the C# runtime, and restarts a center that was started under another one.
test("the Worker passes the owner bootstrap through to the center and restarts it when the bootstrap changes", async () => {
  const bootstrap = {
    ARCFORGES_CENTER_BOOTSTRAP_SHA256:
      "09e0b22a38f1d38f287867c42c2969cf2063ee0194d43f87cb6f1ec7654df8b8",
    ARCFORGES_CENTER_BOOTSTRAP_EXPIRES_AT: "2026-11-02T10:00:00Z",
  };
  const environment = {
    ARCFORGES_HELLO_RUNTIME: "go",
    ARCFORGES_CENTER_MODE: "official-hosted",
    ARCFORGES_CENTER_PUBLIC_BASE_URL: "https://proof.arcforges.com/api",
    ARCFORGES_CENTER_PLAN_CONFIGURATION: "development-fixtures",
    FLAGSHIP_SURFACES: "identity,pages",
  };
  const plain = centerContainerSettings(environment);
  assert.equal(plain.envVars.ARCFORGES_CENTER_SURFACES, "identity,pages");
  assert.equal(plain.envVars.ARCFORGES_CENTER_BOOTSTRAP_SHA256, undefined);
  assert.equal(plain.envVars.ARCFORGES_CENTER_BOOTSTRAP_EXPIRES_AT, undefined);
  const bootstrapped = centerContainerSettings({ ...environment, ...bootstrap });
  assert.equal(
    bootstrapped.envVars.ARCFORGES_CENTER_BOOTSTRAP_SHA256,
    bootstrap.ARCFORGES_CENTER_BOOTSTRAP_SHA256,
  );
  assert.equal(
    bootstrapped.envVars.ARCFORGES_CENTER_BOOTSTRAP_EXPIRES_AT,
    bootstrap.ARCFORGES_CENTER_BOOTSTRAP_EXPIRES_AT,
  );
  const revision = "c".repeat(40);
  assert.notEqual(await startDigest(revision, plain), await startDigest(revision, bootstrapped));
  // The C# runtime never receives one.
  assert.deepEqual(centerContainerSettings({ ...bootstrap }).envVars, {});
});

// PLT-18: ARCFORGES_CENTER_DISABLED_FEATURES is a self-hosted operator's own limit (center/internal/config refuses it in
// official-hosted mode). The hosted center's availability comes from the plan catalogue and the account's entitlement alone, so the
// Worker must never hand the variable to the Container, whatever its own environment or a stray binding says.
test("the self-hosted operator's feature limits are never passed to the hosted center (PLT-18)", () => {
  const name = "ARCFORGES_CENTER_DISABLED_FEATURES";
  for (const runtime of ["go", "csharp", "", undefined]) {
    const settings = centerContainerSettings({
      ...(runtime === undefined ? {} : { ARCFORGES_HELLO_RUNTIME: runtime }),
      ARCFORGES_CENTER_MODE: "official-hosted",
      ARCFORGES_CENTER_PUBLIC_BASE_URL: "https://proof.arcforges.com/api",
      ARCFORGES_CENTER_PLAN_CONFIGURATION: "development-fixtures",
      FLAGSHIP_SURFACES: "identity,pages",
      [name]: "push,remote.control",
    });
    assert(
      !Object.hasOwn(settings.envVars, name),
      `the ${runtime ?? "default"} runtime was handed it`,
    );
    assert(!Object.values(settings.envVars).some((value) => value.includes("remote.control")));
  }
  // No environment of wrangler.json sets it, and no source of the Worker names it.
  const root = new URL("../../", import.meta.url).pathname;
  const wrangler = JSON.parse(readFileSync(path.join(root, "wrangler.json"), "utf8")) as {
    vars?: Record<string, unknown>;
    env?: Record<string, { vars?: Record<string, unknown> }>;
  };
  for (const [environment, vars] of [
    ["production", wrangler.vars],
    ...Object.entries(wrangler.env ?? {}).map(([key, value]) => [key, value.vars] as const),
  ] as const)
    assert(
      !Object.hasOwn(vars ?? {}, name),
      `wrangler.json environment ${environment} sets ${name}`,
    );
  const sources: string[] = [];
  const walk = (directory: string) => {
    for (const entry of readdirSync(directory)) {
      const file = path.join(directory, entry);
      if (statSync(file).isDirectory()) walk(file);
      else if (file.endsWith(".ts")) sources.push(file);
    }
  };
  walk(path.join(root, "worker"));
  assert(sources.length > 20, "the Worker sources were found");
  for (const file of sources)
    assert(
      !readFileSync(file, "utf8").includes(name),
      `${path.relative(root, file)} names ${name}`,
    );
});

// AF-CTR-03 (mail): the Worker hands the Go center the mail variables of the provider ARCFORGES_CENTER_MAIL_PROVIDER names and
// nothing else. The names are the center's own (center/internal/config/mail.go), so the lists are compared with that file. MOCKED:
// synthetic values made of words; no provider is contacted and no deployed environment names one.
const mailPrefix = "ARCFORGES_CENTER_MAIL_";
const centerSource = readFileSync(
  new URL("../../center/internal/config/mail.go", import.meta.url),
  "utf8",
);
/** Every mail variable the center's configuration declares, read from its source. */
const centerMailNames = [
  ...centerSource.matchAll(/^\tEnvMail\w+\s*=\s*"(ARCFORGES_CENTER_MAIL_\w+)"$/gmu),
].map((match) => match[1] as string);
const mailCommon = ["PROVIDER", "FROM", "FROM_NAME", "TIMEOUT"].map((name) => mailPrefix + name);
const mailPostmark = ["POSTMARK_TOKEN", "POSTMARK_STREAM"].map((name) => mailPrefix + name);
const mailSmtp = ["SMTP_HOST", "SMTP_PORT", "SMTP_MODE", "SMTP_USERNAME", "SMTP_PASSWORD"].map(
  (name) => mailPrefix + name,
);
const goCenter = {
  ARCFORGES_HELLO_RUNTIME: "go",
  ARCFORGES_CENTER_MODE: "official-hosted",
  ARCFORGES_CENTER_PUBLIC_BASE_URL: "https://proof.arcforges.com/api",
  ARCFORGES_CENTER_PLAN_CONFIGURATION: "development-fixtures",
  FLAGSHIP_SURFACES: "identity",
};
/** Every mail variable set to a synthetic value, with the provider as given. */
function everyMailVariable(provider: unknown): Record<string, string> {
  const values: Record<string, string> = {};
  for (const name of centerMailNames)
    values[name] = `synthetic-word-${name.slice(mailPrefix.length)}`;
  values[`${mailPrefix}PROVIDER`] = provider as string;
  return values;
}
const mailKeys = (settings: Settings) =>
  Object.keys(settings.envVars)
    .filter((name) => name.startsWith(mailPrefix))
    .sort();

test("the Worker's mail lists are the center's eleven variables, split by provider as the center splits them", () => {
  assert.equal(centerMailNames.length, 11);
  assert.deepEqual(
    [...centerMailNames].sort(),
    [...mailCommon, ...mailPostmark, ...mailSmtp].sort(),
  );
  assert.deepEqual(
    mailKeys(centerContainerSettings({ ...goCenter, ...everyMailVariable("postmark") })),
    [...mailCommon, ...mailPostmark].sort(),
  );
  assert.deepEqual(
    mailKeys(centerContainerSettings({ ...goCenter, ...everyMailVariable("smtp") })),
    [...mailCommon, ...mailSmtp].sort(),
  );
});

test("the Go center gets the values of the named provider unchanged and nothing the provider does not read", () => {
  for (const [provider, own, foreign] of [
    ["postmark", mailPostmark, mailSmtp],
    ["smtp", mailSmtp, mailPostmark],
  ] as const) {
    const all = everyMailVariable(provider);
    // A value with white space at its edges arrives byte for byte: the center's own rule (R10) refuses a pasted newline, and a Worker
    // that trimmed it would repair the mistake silently and hide it from the operator.
    all[`${mailPrefix}FROM_NAME`] = "  synthetic\n";
    all[`${mailPrefix}TIMEOUT`] = " ";
    const { envVars } = centerContainerSettings({ ...goCenter, ...all });
    for (const name of [...mailCommon, ...own]) assert.equal(envVars[name], all[name], name);
    for (const name of foreign)
      assert(!Object.hasOwn(envVars, name), `${provider} was handed ${name}`);
  }
});

test("an unset, empty or disabled provider hands the center no mail variable, whatever else is set", () => {
  for (const provider of [undefined, "", "disabled"]) {
    const values = everyMailVariable(provider);
    if (provider === undefined) delete values[`${mailPrefix}PROVIDER`];
    const settings = centerContainerSettings({ ...goCenter, ...values });
    assert.deepEqual(mailKeys(settings), [], String(provider));
    assert(
      !Object.values(settings.envVars).some((value) => value.startsWith("synthetic-word-")),
      "a mail value was handed on",
    );
  }
  // Production names no provider: its container is the Go center without a mail variable.
  assert.deepEqual(mailKeys(centerContainerSettings(goCenter)), []);
});

test("an unknown provider is a fixed error that names no value, and so is a value that is not a string", () => {
  const unknown = [
    "ses",
    "Postmark",
    "POSTMARK",
    " postmark",
    "postmark ",
    "SMTP",
    " smtp",
    "smtp\n",
    "disabled ",
    "Disabled",
    "none",
    "smtps",
    "toString",
    "__proto__",
    "constructor",
    "1",
  ];
  for (const provider of unknown)
    assert.throws(
      () => centerContainerSettings({ ...goCenter, ...everyMailVariable(provider) }),
      (error: Error) => error.message === "Unknown mail provider.",
      provider,
    );
  for (const provider of [1, true, null, {}, [], ["postmark"]])
    assert.throws(
      () => centerContainerSettings({ ...goCenter, ...everyMailVariable(provider) }),
      (error: Error) => error.message === "Unknown mail provider.",
      JSON.stringify(provider),
    );
});

test("only a non-empty string is handed on, and the C# runtime never receives a mail variable", () => {
  const values = everyMailVariable("postmark");
  values[`${mailPrefix}FROM_NAME`] = "";
  values[`${mailPrefix}POSTMARK_STREAM`] = undefined as unknown as string;
  values[`${mailPrefix}TIMEOUT`] = 5 as unknown as string;
  const { envVars } = centerContainerSettings({ ...goCenter, ...values });
  for (const name of ["FROM_NAME", "POSTMARK_STREAM", "TIMEOUT"])
    assert(!Object.hasOwn(envVars, mailPrefix + name), name);
  assert.equal(envVars[`${mailPrefix}POSTMARK_TOKEN`], values[`${mailPrefix}POSTMARK_TOKEN`]);
  for (const runtime of ["csharp", "", undefined]) {
    for (const provider of ["postmark", "smtp", "ses"]) {
      const settings = centerContainerSettings({
        ...(runtime === undefined ? {} : { ARCFORGES_HELLO_RUNTIME: runtime }),
        ...everyMailVariable(provider),
      });
      assert.deepEqual(settings.envVars, {}, `${runtime ?? "default"} runtime, ${provider}`);
    }
  }
});

test("a mail variable never widens the egress switch, and a rotated credential restarts the center", async () => {
  const database = { ARCFORGES_CENTER_DATABASE_URL: "synthetic-runtime-credential" };
  assert.equal(
    centerContainerSettings({ ...goCenter, ...everyMailVariable("smtp") }).enableInternet,
    false,
  );
  assert.equal(
    centerContainerSettings({ ...goCenter, ...database, ...everyMailVariable("smtp") })
      .enableInternet,
    true,
  );
  const revision = "d".repeat(40);
  const first = centerContainerSettings({ ...goCenter, ...everyMailVariable("postmark") });
  const rotated = centerContainerSettings({
    ...goCenter,
    ...everyMailVariable("postmark"),
    [`${mailPrefix}POSTMARK_TOKEN`]: "synthetic-word-rotated",
  });
  assert.notEqual(await startDigest(revision, first), await startDigest(revision, rotated));
  // Switching mail off restarts it too: the variables are part of what a start hands the Container.
  const off = centerContainerSettings(goCenter);
  assert.notEqual(await startDigest(revision, first), await startDigest(revision, off));
});

test("the production Container class hands the mail variables to a configured center and none to a disabled one", () => {
  const environment = {
    ...goCenter,
    ARCFORGES_CENTER_DATABASE_URL: "synthetic-runtime-credential",
  };
  const configured = new CloudContainer(containerContext, {
    ...environment,
    ...everyMailVariable("smtp"),
  });
  assert.deepEqual(
    Object.keys(configured.envVars as Record<string, string>)
      .filter((name) => name.startsWith(mailPrefix))
      .sort(),
    [...mailCommon, ...mailSmtp].sort(),
  );
  const disabled = new CloudContainer(containerContext, {
    ...environment,
    ...everyMailVariable("disabled"),
  });
  assert.deepEqual(
    Object.keys(disabled.envVars as Record<string, string>).filter((name) =>
      name.startsWith(mailPrefix),
    ),
    [],
  );
});
