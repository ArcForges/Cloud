// SPDX-License-Identifier: AGPL-3.0-only
// Offline checks of the CI-only proof access, provisioning and receipt logic against a fake
// Cloudflare API. The real account is exercised only by the manually dispatched workflow jobs.
import assert from "node:assert/strict";
import test from "node:test";
import {
  CloudflareApi,
  checkProofDomainFree,
  postDeployChecks,
  report,
  probeAccess,
  provision,
  requireContext,
} from "../../eng/verification/proof-cloudflare.ts";

const account = "0".repeat(32);
const token = `${"a".repeat(12)}-${"b".repeat(12)}`;
const d1Id = "11111111-1111-4111-8111-111111111111";

interface State {
  d1: { uuid: string; name: string }[];
  buckets: string[];
  queues: string[];
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
    queues: [],
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
  const reply = (result: unknown, status = 200, errors: unknown[] = []) =>
    Response.json({ success: status < 400, errors, result }, { status });
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
      return Promise.resolve(reply(state.queues.map((queue_name) => ({ queue_name }))));
    }
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
  assert.deepEqual(first.actions, [
    "D1 arcforges-proof-business: created",
    "R2 arcforges-proof-objects: created",
    "Queue arcforges-proof-wake: created",
    "Queue arcforges-proof-wake-dlq: created",
  ]);
  assert.equal(state.calls.filter((call) => call.startsWith("POST")).length, 4);
  state.calls.length = 0;
  const second = await provision(api);
  assert.deepEqual(
    second.actions.map((entry) => entry.split(": ")[1]),
    ["exists", "exists", "exists", "exists"],
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
