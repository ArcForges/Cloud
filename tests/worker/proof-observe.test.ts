// SPDX-License-Identifier: AGPL-3.0-only
// Offline checks of the read-only observation of the proof Container application (manual dispatch `proof=observe`,
// CLOUD.71) against a fake provider API, and of its wiring into the manual dispatch. The real account is read only by
// the manually dispatched workflow job.
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import path from "node:path";
import test from "node:test";
import {
  CloudflareApi,
  instanceState,
  main,
  observe,
  observedFieldsOf,
  proofContainerApplication,
  requireContext,
} from "../../eng/verification/proof-cloudflare.ts";

const repository = path.resolve(import.meta.dirname, "../..");
const account = "0123456789abcdef0123456789abcdef";
const token = `${"t".repeat(16)}-${"u".repeat(16)}`;
const applicationId = "11111111-2222-4333-8444-555555555555";
const digest = "c".repeat(64);

interface Fake {
  applications: unknown[];
  denied: string[];
  logs: number;
}

function fakeProvider(overrides: Partial<Fake> = {}) {
  const state: Fake = {
    applications: [
      { id: "99999999-2222-4333-8444-555555555555", name: "arcforges-cloud-cloudcontainer" },
      { id: applicationId, name: proofContainerApplication },
    ],
    denied: [],
    logs: 403,
    ...overrides,
  };
  const calls: { method: string; endpoint: string; body: unknown }[] = [];
  const reply = (result: unknown, status = 200, errors: unknown[] = []) =>
    Response.json({ success: status < 400, errors, result }, { status });
  const fetcher: typeof fetch = (input, init) => {
    const url = new URL(String(input));
    const endpoint = `${url.pathname.replace(`/client/v4/accounts/${account}`, "")}${url.search}`;
    const method = init?.method ?? "GET";
    assert.equal(new Headers(init?.headers).get("authorization"), `Bearer ${token}`);
    calls.push({ method, endpoint, body: init?.body ? JSON.parse(String(init.body)) : undefined });
    if (state.denied.some((prefix) => endpoint.includes(prefix)))
      return Promise.resolve(
        reply(null, 403, [{ code: 10000, message: `Authentication error ${token}` }]),
      );
    if (endpoint === "/containers/applications") return Promise.resolve(reply(state.applications));
    if (endpoint === `/containers/applications/${applicationId}`)
      return Promise.resolve(
        reply({
          id: applicationId,
          account_id: account,
          name: proofContainerApplication,
          version: 7,
          active_rollout_id: "rollout-new",
          max_instances: 2,
          scheduling_policy: "default",
          created_at: "2026-10-04T07:55:00Z",
          configuration: {
            image: `registry.cloudflare.com/${account}/arcforges-cloud@sha256:${digest}`,
            instance_type: "lite",
            environment_variables: [{ name: "AF_CSRF_SECRET", value: "env-value-never-printed" }],
          },
          labels: [{ name: "owner", value: "label-value-never-printed" }],
          constraints: { tiers: [1, 2] },
          health: { instances: { active: 2, healthy: 1, failed: 0, starting: 0, scheduling: 1 } },
        }),
      );
    if (endpoint === `/containers/dash/applications/${applicationId}/instances?per_page=100`)
      return Promise.resolve(
        reply({
          instances: [
            {
              id: "instance-running",
              app_version: 7,
              location: "lhr",
              created_at: "2026-10-06T03:50:01Z",
              current_placement: { status: { health: "running", container_status: "running" } },
            },
            {
              id: "instance-stopping",
              app_version: 6,
              location: "ewr",
              created_at: "2026-10-06T01:00:00Z",
              current_placement: { status: { health: "stopping" } },
            },
            {
              id: "instance-placed",
              app_version: 7,
              location: "sin",
              created_at: "2026-10-06T03:51:00Z",
              current_placement: { status: { container_status: "placed" } },
            },
          ],
          durable_objects: [
            {
              id: "a".repeat(64),
              name: "hello",
              deployment_id: "instance-running",
              assigned_at: "2026-10-06T03:50:00Z",
            },
            { id: "b".repeat(64), name: "foundation", assigned_at: "2026-10-04T08:00:00Z" },
          ],
        }),
      );
    if (endpoint === `/containers/applications/${applicationId}/status`)
      return Promise.resolve(
        reply({
          instances: { running: 1, stopping: 1 },
          message: "free text that is never printed",
        }),
      );
    if (endpoint === `/containers/applications/${applicationId}/rollouts`)
      return Promise.resolve(
        reply([
          {
            id: "rollout-old",
            created_at: "2026-10-04T20:13:29Z",
            status: "completed",
            kind: "full_auto",
          },
          {
            id: "rollout-new",
            created_at: "2026-10-06T02:10:56Z",
            status: "progressing",
            target_version: 7,
          },
        ]),
      );
    if (endpoint === "/workers/observability/telemetry/query")
      return Promise.resolve(
        state.logs === 200
          ? reply({ events: { events: [{ $metadata: { message: "log line never printed" } }] } })
          : reply(null, state.logs, [{ code: 10000, message: `Authentication error ${token}` }]),
      );
    return Promise.resolve(reply(null, 404));
  };
  return { api: new CloudflareApi(account, token, fetcher), calls, fetcher };
}

const never = [
  token,
  account,
  "env-value-never-printed",
  "label-value-never-printed",
  "free text",
  "log line never printed",
  "AF_CSRF_SECRET",
];

test("the observation only reads, tells the instance models apart and prints no secret, account id, environment value or log line", async () => {
  const { api, calls } = fakeProvider();
  const lines = await observe(api, () => 1_800_000_000_000);
  const text = lines.join("\n");
  // Read-only: every call is a GET except the one dry Workers Logs question, which stores nothing.
  const writes = calls.filter((call) => call.method !== "GET");
  assert.deepEqual(
    writes.map((call) => call.endpoint),
    ["/workers/observability/telemetry/query"],
  );
  assert.equal((writes[0]?.body as { dry?: unknown } | undefined)?.dry, true);
  assert.deepEqual(
    calls.filter((call) => call.method === "GET").map((call) => call.endpoint),
    [
      "/containers/applications",
      `/containers/applications/${applicationId}`,
      `/containers/dash/applications/${applicationId}/instances?per_page=100`,
      `/containers/applications/${applicationId}/status`,
      `/containers/applications/${applicationId}/rollouts`,
    ],
  );
  // The summary: configured ceiling against the listed instances, by state, version and location.
  assert(
    text.includes(
      `configured: max_instances 2, instance_type lite, scheduling_policy default, version 7, image sha256:${digest}`,
    ),
    text,
  );
  assert(text.includes("listed instances: 3"), text);
  assert(text.includes("by state: provisioning 1, running 1, stopping 1"), text);
  assert(text.includes("by version: current 7 2, other 6 1"), text);
  assert(text.includes("by location: ewr 1, lhr 1, sin 1"), text);
  assert(text.includes("instances serving no Durable Object: 2"), text);
  assert(text.includes("foundation: instance none, state none"), text);
  assert(
    text.includes("hello: instance instance-running, state running, version 7, location lhr"),
    text,
  );
  assert(text.includes("instance-stopping: state stopping, version 6, location ewr"), text);
  assert(text.includes("Durable Object none"), text);
  // Provider fields come through the allowlist only; the newest rollout comes first.
  assert(text.includes("health.instances.scheduling = 1"), text);
  assert(text.includes("active_rollout_id = rollout-new"), text);
  assert(text.includes("instances.stopping = 1"), text);
  assert(text.includes("rollouts (newest 2 of 2)"), text);
  assert(text.indexOf("rollout-new") < text.indexOf("rollout-old"), text);
  assert(text.includes("INFO Workers Logs: the deployment token may not query them (http 403)"));
  for (const value of never) assert(!text.includes(value), `printed: ${value}`);

  const permitted = await observe(fakeProvider({ logs: 200 }).api);
  const allowed = permitted.join("\n");
  assert(allowed.includes("Workers Logs: the deployment token may query them"), allowed);
  for (const value of never) assert(!allowed.includes(value), `printed: ${value}`);
  const malformed = (await observe(fakeProvider({ logs: 400 }).api)).join("\n");
  assert(malformed.includes("the dry query was not answered (http 400); permission unknown"));
});

test("a missing application or a refused required read stops the observation; optional reads only report", async () => {
  await assert.rejects(observe(fakeProvider({ applications: [] }).api), /was not found once/u);
  const twice = fakeProvider({
    applications: [
      { id: applicationId, name: proofContainerApplication },
      { id: applicationId, name: proofContainerApplication },
    ],
  });
  await assert.rejects(observe(twice.api), /was not found once/u);
  for (const prefix of ["/containers/applications", "/containers/dash/"]) {
    const refused = fakeProvider({ denied: [prefix] });
    await assert.rejects(observe(refused.api), (error: Error) => {
      assert.match(
        error.message,
        /read failed \(http 403, 10000 Authentication error \[redacted\]\)/u,
      );
      assert(!error.message.includes(token) && !error.message.includes(account));
      return true;
    });
    assert(refused.calls.every((call) => call.method === "GET"));
  }
  const partial = fakeProvider({ denied: ["/status", "/rollouts"] });
  const text = (await observe(partial.api)).join("\n");
  assert.match(text, /INFO status not read \(http 403/u);
  assert.match(text, /INFO rollouts not read \(http 403/u);
  assert(!text.includes(token));
});

test("only allowlisted primitive fields are printed and unusual values are withheld", () => {
  const rows = observedFieldsOf(
    {
      name: "proof",
      id: "x-1",
      location: "lhr",
      note: "not allowlisted",
      status: "a,b;c",
      version: 3,
      nested: [{ state: "running", secret: "s" }],
      environment: { SECRET: "v" },
      environment_variables: [{ name: "AF_SECRET_NAME", value: "v" }],
      labels: [{ name: "label-name", value: "v" }],
      image: "registry.example/acct/image",
      region: `cache-${account}`,
    },
    account,
  );
  assert.deepEqual(rows, [
    { path: "id", value: "x-1" },
    { path: "location", value: "lhr" },
    { path: "name", value: "proof" },
    { path: "nested[0].state", value: "running" },
    { path: "status", value: "[withheld]" },
    { path: "version", value: "3" },
  ]);
});

test("the instance state follows Wrangler's derivation", () => {
  assert.equal(instanceState(undefined), "none");
  assert.equal(instanceState({}), "unknown");
  assert.equal(
    instanceState({ current_placement: { status: { container_status: "placed" } } }),
    "provisioning",
  );
  assert.equal(
    instanceState({
      current_placement: { status: { container_status: "running", health: "failed" } },
    }),
    "running",
  );
  assert.equal(
    instanceState({ current_placement: { status: { health: "stopping" } } }),
    "stopping",
  );
  assert.equal(
    instanceState({ current_placement: { status: { health: "Odd value!" } } }),
    "unknown",
  );
});

test("observe is a manual choice of the proof dispatch that reaches only the read-only script", async () => {
  const good = {
    GITHUB_ACTIONS: "true",
    GITHUB_REPOSITORY: "ArcForges/Cloud",
    GITHUB_REF: "refs/heads/main",
    GITHUB_EVENT_NAME: "workflow_dispatch",
    CLOUDFLARE_ACCOUNT_ID: account,
    CLOUDFLARE_API_TOKEN: token,
  };
  assert.deepEqual(requireContext(good, "observe"), { account, token });
  assert.throws(() => requireContext({ ...good, GITHUB_EVENT_NAME: "pull_request" }, "observe"));
  // An observation is held to main exactly like the other proof actions.
  for (const ref of ["refs/heads/task/cloud-71", "refs/pull/62/merge", "refs/tags/main"])
    assert.throws(
      () => requireContext({ ...good, GITHUB_REF: ref }, "observe"),
      /Only main may touch the proof environment/u,
    );
  assert.throws(() => requireContext(good, "delete"));

  const workflow = readFileSync(path.join(repository, ".github/workflows/ci.yml"), "utf8");
  assert.match(workflow, /options: \[none, access, provision, deploy, observe\]/u);
  const access =
    workflow.split(/^ {2}proof-access:\n/mu)[1]?.split(/^ {2}[a-z][a-z-]*:\n/mu)[0] ?? "";
  assert.match(access, /observe\) npm run observe:proof ;;/u);
  assert.match(access, /access\) npm run access:proof ;;/u);
  assert.match(access, /\*\) npm run provision:proof ;;/u);
  assert.equal((workflow.match(/observe:proof/gu) ?? []).length, 1, "only the access job runs it");
  const deploy =
    workflow.split(/^ {2}deploy-proof:\n/mu)[1]?.split(/^ {2}[a-z][a-z-]*:\n/mu)[0] ?? "";
  assert.match(deploy, /inputs\.proof == 'deploy'/u, "an observation never deploys");
  // A positive match alone would still pass a widened condition such as `|| inputs.proof == 'observe'`.
  assert.doesNotMatch(deploy, /observe/u, "the deployment job never names observe");
  const condition = deploy.split(/^ {4}needs:/mu)[0] ?? "";
  assert.match(condition, /^ {4}if: >-\n/mu);
  assert.doesNotMatch(
    condition,
    /\|\||inputs\.proof\s*!=/u,
    "the deployment job runs for proof == 'deploy' only",
  );
  const scripts = (
    JSON.parse(readFileSync(path.join(repository, "package.json"), "utf8")) as {
      scripts: Record<string, string>;
    }
  ).scripts;
  assert.equal(scripts["observe:proof"], "node eng/verification/proof-cloudflare.ts observe");

  // The script itself: with the dispatch context it reads and prints, and never provisions or deploys.
  const { calls, fetcher } = fakeProvider();
  const saved = { ...process.env };
  const originalFetch = globalThis.fetch;
  const originalLog = console.log;
  const printed: string[] = [];
  try {
    Object.assign(process.env, good);
    globalThis.fetch = fetcher;
    console.log = (line: unknown) => {
      printed.push(String(line));
    };
    await main("observe");
  } finally {
    console.log = originalLog;
    globalThis.fetch = originalFetch;
    for (const name of Object.keys(good)) {
      if (saved[name] === undefined) delete process.env[name];
      else process.env[name] = saved[name];
    }
  }
  assert(
    printed.some((line) =>
      line.startsWith(`Proof Container application ${proofContainerApplication}`),
    ),
  );
  assert.deepEqual(
    calls.filter((call) => call.method !== "GET").map((call) => call.endpoint),
    ["/workers/observability/telemetry/query"],
  );
  assert(
    !calls.some((call) =>
      /\/d1\/|\/r2\/|\/queues|\/tokens\/verify|\/workers\/scripts/u.test(call.endpoint),
    ),
  );
  for (const value of never) assert(!printed.join("\n").includes(value), `printed: ${value}`);
});
