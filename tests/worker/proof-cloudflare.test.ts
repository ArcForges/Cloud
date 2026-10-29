// SPDX-License-Identifier: AGPL-3.0-only
// Offline checks of the CI-only proof access, provisioning and receipt logic against a fake
// Cloudflare API. The real account is exercised only by the manually dispatched workflow jobs.
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { mkdtemp, rm, stat } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import test from "node:test";
import {
  CloudflareApi,
  checkProofDomainFree,
  postDeployChecks,
  prepareProofScript,
  report,
  probeAccess,
  provision,
  releaseDownloadArguments,
  requireContext,
  verifyAndStageProofAssets,
} from "../../eng/verification/proof-cloudflare.ts";
import {
  profileBundleAssetName,
  profileBundlePin,
  proofAssetsDirName,
  proofQueueNames,
  siteArchiveAssetName,
  siteArchivePin,
} from "../../eng/verification/proof-deploy.ts";

const account = "0".repeat(32);
const token = `${"a".repeat(12)}-${"b".repeat(12)}`;
const d1Id = "11111111-1111-4111-8111-111111111111";
const queueId = (name: string) => createHash("md5").update(name).digest("hex");

interface Consumer {
  consumer_id: string;
  type: string;
  script?: string;
  service?: string;
}

interface State {
  d1: { uuid: string; name: string }[];
  buckets: string[];
  lifecycles: Map<string, unknown[]>;
  queues: string[];
  /** Consumers by queue name. */
  consumers: Record<string, Consumer[]>;
  /** The proof script's cron schedules; null answers 404 (no such script). */
  schedules: unknown[] | null;
  /** The proof script's service metadata; null answers 404 (no such script). */
  service: { migration_tag?: string } | null;
  /** Pages the queue list by this size with the given `result_info`; null answers one page without it. */
  queuePaging: { size: number; info: "total_pages" | "total_count" } | null;
  denied: Set<string>;
  calls: string[];
  workersDev: boolean;
  domains: { hostname: string; service: string }[];
  routes: { pattern: string; script: string }[];
  zone: boolean;
  dns: unknown[];
  subdomain: Record<string, unknown> | null;
}
function fakeCloudflare(overrides: Partial<State> = {}) {
  const state: State = {
    d1: [],
    buckets: [],
    lifecycles: new Map(),
    queues: [],
    consumers: {},
    schedules: null,
    service: null,
    queuePaging: null,
    denied: new Set(),
    calls: [],
    workersDev: false,
    domains: [{ hostname: "proof.arcforges.com", service: "arcforges-cloud-proof" }],
    routes: [{ pattern: "arcforges.com/api/*", script: "arcforges-cloud" }],
    zone: true,
    dns: [],
    subdomain: null,
    ...overrides,
  };
  // The fake removes consumers in place; a shared fixture must not see another fake's removals.
  state.consumers = structuredClone(state.consumers);
  const reply = (
    result: unknown,
    status = 200,
    errors: unknown[] = [],
    resultInfo?: Record<string, number>,
  ) =>
    Response.json(
      { success: status < 400, errors, result, ...(resultInfo ? { result_info: resultInfo } : {}) },
      { status },
    );
  const fetcher: typeof fetch = (input, init) => {
    const url = new URL(String(input));
    const endpoint = url.pathname.replace("/client/v4", "");
    const method = init?.method ?? "GET";
    assert.equal(new Headers(init?.headers).get("authorization"), `Bearer ${token}`);
    state.calls.push(`${method} ${endpoint}`);
    const family = [...state.denied].find((prefix) => endpoint.includes(prefix));
    if (family)
      return Promise.resolve(
        reply(null, 403, [{ code: 10000, message: `Authentication error ${token}` }]),
      );
    const body = init?.body ? (JSON.parse(String(init.body)) as Record<string, string>) : {};
    if (endpoint.endsWith("/tokens/verify")) return Promise.resolve(reply({ status: "active" }));
    if (endpoint === "/zones") return Promise.resolve(reply(state.zone ? [{ id: "zone1" }] : []));
    if (endpoint.startsWith("/zones/zone1/workers/routes"))
      return Promise.resolve(reply(state.routes));
    if (endpoint.startsWith("/zones/zone1/dns_records")) return Promise.resolve(reply(state.dns));
    if (endpoint.endsWith("/workers/scripts")) return Promise.resolve(reply([]));
    if (endpoint.endsWith("/workers/domains"))
      return Promise.resolve(reply(url.searchParams.get("hostname") ? state.domains : []));
    if (endpoint.endsWith("/subdomain"))
      return Promise.resolve(reply(state.subdomain ?? { enabled: state.workersDev }));
    if (endpoint.endsWith("/d1/database")) {
      if (method === "POST") {
        state.d1.push({ uuid: d1Id, name: body.name ?? "" });
        return Promise.resolve(reply({ uuid: d1Id }));
      }
      return Promise.resolve(reply(state.d1));
    }
    if (endpoint.endsWith("/r2/buckets")) {
      if (method === "POST") {
        state.buckets.push(body.name ?? "");
        return Promise.resolve(reply({ name: body.name }));
      }
      return Promise.resolve(reply({ buckets: state.buckets.map((name) => ({ name })) }));
    }
    const lifecycle = /\/r2\/buckets\/([^/]+)\/lifecycle$/u.exec(endpoint);
    if (lifecycle) {
      const name = lifecycle[1] ?? "";
      if (!state.buckets.includes(name)) return Promise.resolve(reply(null, 404));
      if (method === "PUT") {
        state.lifecycles.set(name, (JSON.parse(String(init?.body)) as { rules: unknown[] }).rules);
        return Promise.resolve(reply(null));
      }
      return Promise.resolve(reply({ rules: state.lifecycles.get(name) ?? [] }));
    }
    const bucket = /\/r2\/buckets\/(.+)$/u.exec(endpoint);
    if (bucket)
      return Promise.resolve(
        state.buckets.includes(bucket[1] ?? "")
          ? reply({ name: bucket[1] })
          : reply(null, 404, [{ code: 10006, message: "bucket not found" }]),
      );
    if (endpoint.endsWith("/queues")) {
      if (method === "POST") {
        state.queues.push(body.queue_name ?? "");
        return Promise.resolve(reply({ queue_name: body.queue_name }));
      }
      const page = Number(url.searchParams.get("page") ?? "1");
      const records = state.queues.map((queue_name) => ({
        queue_id: queueId(queue_name),
        queue_name,
        consumers: state.consumers[queue_name] ?? [],
      }));
      const paging = state.queuePaging;
      if (paging === null) return Promise.resolve(reply(page > 1 ? [] : records));
      // A provider that pages by its own size, whatever per_page asked for.
      const slice = records.slice((page - 1) * paging.size, page * paging.size);
      const info = { page, per_page: paging.size, count: slice.length };
      return Promise.resolve(
        reply(slice, 200, [], {
          ...info,
          ...(paging.info === "total_pages"
            ? { total_pages: Math.ceil(records.length / paging.size) }
            : { total_count: records.length }),
        }),
      );
    }
    const consumer = /\/queues\/([0-9a-f]{32})\/consumers\/([0-9a-f]{32})$/u.exec(endpoint);
    if (consumer && method === "DELETE") {
      const name = state.queues.find((queue) => queueId(queue) === consumer[1]) ?? "";
      const list = state.consumers[name] ?? [];
      if (!list.some((entry) => entry.consumer_id === consumer[2]))
        return Promise.resolve(reply(null, 404));
      state.consumers[name] = list.filter((entry) => entry.consumer_id !== consumer[2]);
      return Promise.resolve(reply(null));
    }
    if (endpoint.endsWith("/workers/scripts/arcforges-cloud-proof/schedules"))
      return Promise.resolve(
        state.schedules === null ? reply(null, 404) : reply({ schedules: state.schedules }),
      );
    if (endpoint.endsWith("/workers/services/arcforges-cloud-proof"))
      return Promise.resolve(
        state.service === null
          ? reply(null, 404)
          : reply({ default_environment: { script: state.service } }),
      );
    return Promise.resolve(reply(null, 404));
  };
  return { api: new CloudflareApi(account, token, fetcher), state };
}

test("access probes name each capability and never print a token", async () => {
  const { api } = fakeCloudflare();
  const checks = await probeAccess(api);
  assert(
    checks.every((check) => check.ok),
    JSON.stringify(checks),
  );
  assert.deepEqual(
    checks.filter((check) => check.required).map((check) => check.name),
    ["Workers Scripts read", "D1 read", "R2 read", "Queues read", "Zone read (arcforges.com)"],
  );
  const denied = fakeCloudflare({ denied: new Set(["/d1/", "/queues"]) });
  const failed = await probeAccess(denied.api);
  assert.deepEqual(
    failed.filter((check) => !check.ok && check.required).map((check) => check.name),
    ["D1 read", "Queues read"],
  );
  assert(
    JSON.stringify(failed).includes("10000 Authentication error [redacted]"),
    "provider messages are kept and token text is removed",
  );
  assert(!JSON.stringify(failed).includes(token));
});

test("provisioning creates exactly the reserved resources once and is idempotent", async () => {
  const { api, state } = fakeCloudflare();
  const first = await provision(api);
  assert.equal(first.d1DatabaseId, d1Id);
  // AF-CTR-02: the retained proof D1 database and the center's acceptance bucket (with its lifecycle rules) and queues.
  const lifecycle = "lifecycle support-bundles-30-days, abort-incomplete-uploads";
  assert.deepEqual(first.actions, [
    "D1 arcforges-proof-business: created",
    "R2 arcforges-acceptance-center: created",
    `R2 arcforges-acceptance-center: ${lifecycle}`,
    "Queue arcforges-acceptance-center-events: created",
    "Queue arcforges-acceptance-center-events-dlq: created",
  ]);
  assert.equal(state.calls.filter((call) => call.startsWith("POST")).length, 4);
  assert.deepEqual(
    (state.lifecycles.get("arcforges-acceptance-center") as { id: string }[]).map(
      (rule) => rule.id,
    ),
    ["support-bundles-30-days", "abort-incomplete-uploads"],
  );
  state.calls.length = 0;
  const second = await provision(api);
  assert.deepEqual(
    second.actions.map((entry) => entry.split(": ")[1]),
    ["exists", "exists", lifecycle, "exists", "exists"],
  );
  assert.equal(state.calls.filter((call) => call.startsWith("POST")).length, 0);
  // Resources of other names are never mistaken for the reserved ones.
  const other = fakeCloudflare({
    d1: [{ uuid: "22222222-2222-4222-8222-222222222222", name: "arcforges-proof-business-x" }],
  });
  assert.equal((await provision(other.api)).d1DatabaseId, d1Id);
  // A refused create is an error naming the cause.
  const refused = fakeCloudflare({ denied: new Set(["/r2/"]) });
  await assert.rejects(provision(refused.api), /R2 create failed/u);
});

test("post-deployment receipts require workers.dev off, the custom domain and the production route", async () => {
  const good = fakeCloudflare();
  assert((await postDeployChecks(good.api)).every((check) => check.ok));
  assert.equal(
    (await postDeployChecks(fakeCloudflare({ workersDev: true }).api)).filter(
      (check) => !check.ok,
    )[0]?.name,
    "workers.dev and preview URLs disabled for the proof Worker",
  );
  const noDomain = await postDeployChecks(fakeCloudflare({ domains: [] }).api);
  assert(noDomain.some((check) => !check.ok && check.name.startsWith("custom domain")));
  const lostRoute = await postDeployChecks(fakeCloudflare({ routes: [] }).api);
  assert(lostRoute.some((check) => !check.ok && check.name.startsWith("production route")));
  const stolen = await postDeployChecks(
    fakeCloudflare({
      routes: [
        { pattern: "arcforges.com/api/*", script: "arcforges-cloud" },
        { pattern: "arcforges.com/proof/*", script: "arcforges-cloud-proof" },
      ],
    }).api,
  );
  assert(stolen.some((check) => !check.ok && check.name === "no proof Worker route on the zone"));
});

test("receipts fail closed: unknown zone, absent or unsafe workers.dev state, foreign domain", async () => {
  const failures = async (overrides: Partial<State>) =>
    (await postDeployChecks(fakeCloudflare(overrides).api))
      .filter((check) => check.required && !check.ok)
      .map((check) => check.name);
  // A zone that cannot be found must not skip the production-route assertions.
  assert.deepEqual(await failures({ zone: false }), [
    "zone arcforges.com readable for the route receipts",
  ]);
  const workersDev = "workers.dev and preview URLs disabled for the proof Worker";
  // Only an explicit enabled=false passes; an absent field, an enabled one or enabled previews fail.
  assert.deepEqual(await failures({ subdomain: {} }), [workersDev]);
  assert.deepEqual(await failures({ subdomain: { enabled: true } }), [workersDev]);
  assert.deepEqual(await failures({ subdomain: { enabled: false, previews_enabled: true } }), [
    workersDev,
  ]);
  assert.deepEqual(await failures({ subdomain: { enabled: false, previews_enabled: false } }), []);
  // A custom domain attached to another service is not the proof Worker's domain.
  assert.deepEqual(
    await failures({ domains: [{ hostname: "proof.arcforges.com", service: "arcforges-cloud" }] }),
    ["custom domain proof.arcforges.com serves arcforges-cloud-proof"],
  );
});

test("report fails on any failed required check and passes optional ones", () => {
  const quiet = (checks: Parameters<typeof report>[1]) => {
    const original = console.log;
    console.log = () => {};
    try {
      report("test", checks);
    } finally {
      console.log = original;
    }
  };
  quiet([
    { name: "a", required: true, ok: true, detail: "" },
    { name: "b", required: false, ok: false, detail: "" },
  ]);
  assert.throws(
    () => quiet([{ name: "needed", required: true, ok: false, detail: "" }]),
    /1 required check\(s\) failed: needed/u,
  );
});

test("an existing DNS record or foreign domain stops the attach unless it is the proof Worker's own", async () => {
  await checkProofDomainFree(fakeCloudflare({ domains: [] }).api);
  // A redeploy: the domain already serves the proof Worker and its record exists.
  await checkProofDomainFree(fakeCloudflare({ dns: [{ type: "A" }] }).api);
  await assert.rejects(
    checkProofDomainFree(fakeCloudflare({ domains: [], dns: [{ type: "CNAME" }] }).api),
    /DNS record .* exists/u,
  );
  await assert.rejects(
    checkProofDomainFree(
      fakeCloudflare({ domains: [{ hostname: "proof.arcforges.com", service: "arcforges-cloud" }] })
        .api,
    ),
    /already serves another Worker/u,
  );
  await assert.rejects(checkProofDomainFree(fakeCloudflare({ zone: false }).api), /not visible/u);
  await assert.rejects(
    checkProofDomainFree(fakeCloudflare({ domains: [], denied: new Set(["/dns_records"]) }).api),
    /DNS lookup .* failed/u,
  );
  await assert.rejects(
    checkProofDomainFree(fakeCloudflare({ denied: new Set(["/workers/domains"]) }).api),
    /domains lookup failed/u,
  );
});

test("the proof environment is reachable only from a manual run on main with the account inputs", () => {
  const good = {
    GITHUB_ACTIONS: "true",
    GITHUB_REPOSITORY: "ArcForges/Cloud",
    GITHUB_REF: "refs/heads/main",
    GITHUB_EVENT_NAME: "workflow_dispatch",
    CLOUDFLARE_ACCOUNT_ID: account,
    CLOUDFLARE_API_TOKEN: token,
  };
  assert.deepEqual(requireContext(good, "access"), { account, token });
  for (const bad of [
    { GITHUB_ACTIONS: "" },
    { GITHUB_REPOSITORY: "Other/Cloud" },
    { GITHUB_REF: "refs/heads/task" },
    { GITHUB_EVENT_NAME: "push" },
    { GITHUB_EVENT_NAME: "pull_request" },
    { CLOUDFLARE_ACCOUNT_ID: "short" },
    { CLOUDFLARE_API_TOKEN: "" },
  ])
    assert.throws(() => requireContext({ ...good, ...bad }, "deploy"));
  assert.throws(() => requireContext(good, "delete"));
});

test("each Web release asset is downloaded from its pinned release by its digest name", () => {
  assert.match(profileBundlePin.digest, /^[0-9a-f]{64}$/u);
  assert.match(siteArchivePin.digest, /^[0-9a-f]{64}$/u);
  assert.deepEqual(
    releaseDownloadArguments(
      profileBundlePin,
      profileBundleAssetName(profileBundlePin.digest),
      "artifacts/web-release",
    ),
    [
      "release",
      "download",
      profileBundlePin.release,
      "--repo",
      profileBundlePin.repository,
      "--pattern",
      `web-profiles-${profileBundlePin.digest}.tar`,
      "--dir",
      "artifacts/web-release",
    ],
  );
  assert.deepEqual(
    releaseDownloadArguments(
      siteArchivePin,
      siteArchiveAssetName(siteArchivePin.digest),
      "artifacts/web-release",
    ),
    [
      "release",
      "download",
      siteArchivePin.release,
      "--repo",
      siteArchivePin.repository,
      "--pattern",
      `web-site-${siteArchivePin.digest}.tar`,
      "--dir",
      "artifacts/web-release",
    ],
  );
});

test("an asset that does not match its pinned digest stops the staging before anything is written", async () => {
  const root = await mkdtemp(path.join(tmpdir(), "arcforges-cloud-proof-"));
  try {
    await assert.rejects(
      verifyAndStageProofAssets(
        { profile: Buffer.from("not a bundle"), site: Buffer.from("not a site") },
        root,
      ),
      /does not match the pinned digest/u,
    );
    await assert.rejects(stat(path.join(root, "artifacts", proofAssetsDirName)));
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

// AF-CTR-02 follow-up: the retired C# proof consumers are detached before the acceptance bundle is uploaded.
// The checked-in proof environment, from which the deployment generates its configuration: migrations v1 and
// harness-run-alarm-v1, `triggers: {}` and no queue consumer.
const proof = (
  JSON.parse(readFileSync(path.resolve(import.meta.dirname, "../../wrangler.json"), "utf8")) as {
    env: { proof: Record<string, unknown> };
  }
).env.proof;
const [wake, wakeDlq] = proofQueueNames;
const worker = (script: string, id: string): Consumer => ({
  consumer_id: id.repeat(32),
  type: "worker",
  script,
});
const deletes = (calls: string[]) => calls.filter((call) => call.startsWith("DELETE "));
const detachCall = (queue: string, id: string) =>
  `DELETE /accounts/${account}/queues/${queueId(queue)}/consumers/${id.repeat(32)}`;
const centerQueues = [
  "arcforges-acceptance-center-events",
  "arcforges-acceptance-center-events-dlq",
];

test("the proof script's consumers of both retired queues are detached, once", async () => {
  const { api, state } = fakeCloudflare({
    queues: [...centerQueues, ...proofQueueNames],
    consumers: {
      [wake]: [worker("arcforges-cloud-proof", "a")],
      [wakeDlq]: [worker("arcforges-cloud-proof", "d")],
    },
    schedules: [],
    service: { migration_tag: "harness-run-alarm-v1" },
  });
  assert.deepEqual(await prepareProofScript(api, proof), {
    retiredConsumers: [
      { queue: wake, outcome: "detached" },
      { queue: wakeDlq, outcome: "detached" },
    ],
    cronSchedules: 0,
    migrationTag: "harness-run-alarm-v1",
  });
  assert.deepEqual(deletes(state.calls), [detachCall(wake, "a"), detachCall(wakeDlq, "d")]);
  // Only the consumer registrations went: every queue stays, and nothing but those two consumers is deleted or written.
  assert.deepEqual(state.queues, [...centerQueues, ...proofQueueNames]);
  assert.deepEqual(state.consumers, { [wake]: [], [wakeDlq]: [] });
  assert(
    state.calls.every(
      (call) =>
        call.startsWith("GET ") ||
        /^DELETE \/accounts\/0{32}\/queues\/[0-9a-f]{32}\/consumers\/[0-9a-f]{32}$/u.test(call),
    ),
    state.calls.join("\n"),
  );
  // A rerun finds nothing attached and changes nothing.
  state.calls.length = 0;
  const again = await prepareProofScript(api, proof);
  assert.deepEqual(again.retiredConsumers, [
    { queue: wake, outcome: "not attached" },
    { queue: wakeDlq, outcome: "not attached" },
  ]);
  assert.deepEqual(deletes(state.calls), []);
});

test("nothing attached means no call, and another script's consumers are never touched", async () => {
  const notAttached = [
    { queue: wake, outcome: "not attached" },
    { queue: wakeDlq, outcome: "not attached" },
  ];
  // Both queues exist without a consumer, or do not exist at all.
  for (const queues of [[...proofQueueNames], []]) {
    const { api, state } = fakeCloudflare({ queues });
    const result = await prepareProofScript(api, proof);
    assert.deepEqual(result, {
      retiredConsumers: notAttached,
      cronSchedules: 0,
      migrationTag: null,
    });
    assert.deepEqual(deletes(state.calls), []);
  }
  // Consumers of other scripts (and a pull consumer) stay on the retired queues, beside a detached proof consumer.
  const others = {
    [wake]: [
      worker("arcforges-cloud", "b"),
      worker("arcforges-cloud-proof", "a"),
      { consumer_id: "c".repeat(32), type: "http_pull" },
    ],
    [wakeDlq]: [worker("arcforges-cloud-proof-x", "e")],
  };
  const { api, state } = fakeCloudflare({ queues: [...proofQueueNames], consumers: others });
  assert.deepEqual((await prepareProofScript(api, proof)).retiredConsumers, [
    { queue: wake, outcome: "detached" },
    { queue: wakeDlq, outcome: "not attached" },
  ]);
  assert.deepEqual(deletes(state.calls), [detachCall(wake, "a")]);
  assert.deepEqual(
    Object.fromEntries(
      Object.entries(state.consumers).map(([queue, list]) => [
        queue,
        list.map((entry) => entry.consumer_id[0]),
      ]),
    ),
    { [wake]: ["b", "c"], [wakeDlq]: ["e"] },
  );
});

test("anything unknown, or any API failure, stops before a consumer is detached", async () => {
  const attached = {
    queues: [...centerQueues, ...proofQueueNames],
    consumers: {
      [wake]: [worker("arcforges-cloud-proof", "a")],
      [wakeDlq]: [worker("arcforges-cloud-proof", "d")],
    },
  };
  const refused = async (overrides: Partial<State>, pattern: RegExp) => {
    const { api, state } = fakeCloudflare({ ...attached, ...overrides });
    await assert.rejects(prepareProofScript(api, proof), pattern);
    assert.deepEqual(deletes(state.calls), [], String(pattern));
    assert.equal(state.consumers[wake]?.length, 1);
  };
  // A proof consumer on any other queue is not this deployment's to remove.
  await refused(
    {
      consumers: {
        ...attached.consumers,
        "arcforges-acceptance-center-events": [worker("arcforges-cloud-proof", "f")],
      },
    },
    /Queue arcforges-acceptance-center-events has a consumer for arcforges-cloud-proof .* Nothing was deployed/u,
  );
  // The configuration declares no triggers.crons, so a live schedule would stay beside a bundle that declares none.
  await refused(
    { schedules: [{ cron: "*/5 * * * *" }] },
    /1 cron schedule\(s\) that the proof configuration does not declare/u,
  );
  // A Durable Object migration tag the configuration does not list.
  await refused(
    { service: { migration_tag: "v2" } },
    /migration tag v2 is not in the configuration/u,
  );
  // Unreadable state is a refusal, not an assumption.
  await refused(
    { denied: new Set(["/queues"]) },
    /Listing the queues failed .*nothing was deployed/u,
  );
  await refused({ denied: new Set(["/schedules"]) }, /cron schedules failed/u);
  await refused({ denied: new Set(["/workers/services/"]) }, /metadata failed/u);
  // Without Queues write the removal fails: the deployment stops and names the owner's action.
  const { api, state } = fakeCloudflare({ ...attached, denied: new Set(["/consumers/"]) });
  await assert.rejects(
    prepareProofScript(api, proof),
    /consumer of arcforges-proof-wake, arcforges-proof-wake-dlq is still attached \(arcforges-proof-wake: http 403.*Queues write permission, which only the owner can add\. Nothing was deployed\./u,
  );
  assert.equal(state.consumers[wake]?.length, 1);
  assert.deepEqual(state.queues, [...centerQueues, ...proofQueueNames]);
  // A partial removal still stops the deployment, and says which consumer did go.
  const partial = fakeCloudflare({
    ...attached,
    denied: new Set([`/queues/${queueId(wakeDlq)}/consumers/`]),
  });
  await assert.rejects(
    prepareProofScript(partial.api, proof),
    /consumer of arcforges-proof-wake-dlq is still attached .* Detached: arcforges-proof-wake\. Nothing was deployed\./u,
  );
  assert.deepEqual(partial.state.consumers, {
    [wake]: [],
    [wakeDlq]: [worker("arcforges-cloud-proof", "d")],
  });
});

test("the deployment prepares the proof script before the credential rotation and the upload, and records it", () => {
  const source = readFileSync(
    path.resolve(import.meta.dirname, "../../eng/verification/proof-cloudflare.ts"),
    "utf8",
  );
  const deploy = source.slice(source.indexOf("async function deploy("));
  const prepared = deploy.indexOf("await prepareProofScript(");
  assert(prepared > 0);
  assert(prepared < deploy.indexOf("withRuntimeCredential("));
  assert(prepared < deploy.indexOf('"deploy",'));
  for (const field of ["retiredQueueConsumers:", "cronSchedules:", "migrationTag:"])
    assert(deploy.slice(deploy.indexOf("proof-deployment.json")).includes(field), field);
});

test("both deployments record the configured surfaces the deployed version starts the center with, and the local checks compare them", () => {
  // AF-CTR-03: the Container restarts a center left running under another version's start environment before it serves a
  // request, so the center's health should state the configured surfaces the deployment evidence records. The evidence is computed
  // from the configuration, not observed: the production live check and the local Worker check compare it with the health, and for
  // proof the post-deploy acceptance does (CI makes no live call).
  const read = (file: string) =>
    readFileSync(path.resolve(import.meta.dirname, "../..", file), "utf8");
  const proofSource = read("eng/verification/proof-cloudflare.ts");
  const record = proofSource.slice(proofSource.indexOf("proof-deployment.json"));
  assert(
    record.includes("configuredSurfaces: centerSurfaces(config.env.proof.vars.FLAGSHIP_SURFACES)"),
  );
  const production = read("tooling/cloudflare.ts");
  const deployment = production.slice(production.indexOf("await writeJson(deploymentFile, {"));
  assert(
    deployment.includes(
      "center: { configuredSurfaces: centerSurfaces(config.vars.FLAGSHIP_SURFACES) }",
    ),
  );
  assert.match(production, /center\?\.surfaces,\s*deployment\.center\.configuredSurfaces,/u);
  assert.match(
    read("tooling/project.ts"),
    /center\?\.surfaces,\s*centerSurfaces\(config\.vars\.FLAGSHIP_SURFACES\),/u,
  );
});

test("consumers and schedules that the proof configuration declares are accepted, others refused", async () => {
  const events = "arcforges-acceptance-center-events";
  const attached = {
    queues: [...centerQueues, ...proofQueueNames],
    consumers: {
      [wake]: [worker("arcforges-cloud-proof", "a")],
      [wakeDlq]: [worker("arcforges-cloud-proof", "d")],
      [events]: [worker("arcforges-cloud-proof", "f")],
    },
    schedules: [{ cron: "0 * * * *" }],
  };
  // A later acceptance configuration with an outbox sink and a cron: Wrangler updates that consumer and replaces the schedules.
  const declared = {
    ...proof,
    queues: { consumers: [{ queue: events }] },
    triggers: { crons: ["0 * * * *"] },
  };
  const { api, state } = fakeCloudflare(attached);
  const result = await prepareProofScript(api, declared);
  assert.deepEqual(result.retiredConsumers, [
    { queue: wake, outcome: "detached" },
    { queue: wakeDlq, outcome: "detached" },
  ]);
  assert.equal(result.cronSchedules, 1);
  assert.deepEqual(deletes(state.calls), [detachCall(wake, "a"), detachCall(wakeDlq, "d")]);
  assert.equal(state.consumers[events]?.length, 1);
  // Declared crons replace every live schedule, so a changed expression is not a refusal (crons: [] clears them all).
  for (const crons of [["*/10 * * * *"], []]) {
    const changed = fakeCloudflare(attached);
    await prepareProofScript(changed.api, { ...declared, triggers: { crons } });
    assert.equal(deletes(changed.state.calls).length, 2);
  }
  // A proof consumer on a queue that the configuration does not consume is still refused.
  const other = fakeCloudflare({
    ...attached,
    queues: [...attached.queues, "arcforges-other"],
    consumers: { ...attached.consumers, "arcforges-other": [worker("arcforges-cloud-proof", "e")] },
  });
  await assert.rejects(
    prepareProofScript(other.api, declared),
    /Queue arcforges-other has a consumer for arcforges-cloud-proof that the proof configuration does not declare/u,
  );
  assert.deepEqual(deletes(other.state.calls), []);
  // A configuration that consumes a retired queue again is refused before anything is read.
  const reused = fakeCloudflare(attached);
  await assert.rejects(
    prepareProofScript(reused.api, { ...proof, queues: { consumers: [{ queue: wakeDlq }] } }),
    /consumes arcforges-proof-wake-dlq, the retired C# proof queue/u,
  );
  assert.deepEqual(reused.state.calls, []);
});

test("the queue list follows the provider's paging details, within 20 pages", async () => {
  // 45 queues, 20 per page whatever per_page asked for: the retired ones are on the third page.
  const many = [...Array.from({ length: 43 }, (_, index) => `queue-${index}`), ...proofQueueNames];
  const consumers = {
    [wake]: [worker("arcforges-cloud-proof", "a")],
    [wakeDlq]: [worker("arcforges-cloud-proof", "d")],
  };
  for (const info of ["total_pages", "total_count"] as const) {
    const { api, state } = fakeCloudflare({
      queues: many,
      consumers,
      queuePaging: { size: 20, info },
    });
    const result = await prepareProofScript(api, proof);
    assert.deepEqual(
      result.retiredConsumers.map((entry) => entry.outcome),
      ["detached", "detached"],
      info,
    );
    const pages = state.calls.filter((call) => call === `GET /accounts/${account}/queues`);
    // Three pages for the preflight and three for the re-read after the removals; never a fourth.
    assert.equal(pages.length, 6, info);
    assert.deepEqual(state.consumers, { [wake]: [], [wakeDlq]: [] });
  }
  // A list that claims more than 20 pages stops the deployment.
  const endless = fakeCloudflare({
    queues: Array.from({ length: 21 }, (_, index) => `queue-${index}`),
    queuePaging: { size: 1, info: "total_pages" },
  });
  await assert.rejects(prepareProofScript(endless.api, proof), /did not end after 20 pages/u);
  assert.deepEqual(deletes(endless.state.calls), []);
});
