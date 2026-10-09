// SPDX-License-Identifier: AGPL-3.0-only
// Cloudflare account access, resource provisioning, deployment and read-only observation of the isolated
// `proof` environment. It runs only in the manually dispatched jobs of .github/workflows/ci.yml on `main`,
// inside the `cloudflare` GitHub environment, with the existing deployment token. Output is sanitized: it
// names capabilities, resources and HTTP statuses, and the observation adds only allowlisted provider fields
// (names, provider ids, states, counts, versions, locations, times); never a token, a secret, an environment
// value or a log line. The proof secrets are generated here at deploy time and handed to Wrangler through a
// runner-local file; they are never printed, never committed and never leave the runner except into the
// proof Worker. No live service is called: the checks are provider metadata receipts, not runtime tests.
import assert from "node:assert/strict";
import { createHash, randomBytes } from "node:crypto";
import { mkdir, readFile, rm, writeFile } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";
import {
  buildProofConfig,
  generateSecrets,
  proofBucketName,
  proofDatabaseName,
  composeProofAssets,
  profileBundleAssetName,
  profileBundlePin,
  proofAssetsDirName,
  proofHostname,
  proofQueueNames,
  proofWorkerName,
  siteArchiveAssetName,
  siteArchivePin,
  stageProofAssets,
  verifyProfileBundle,
  verifySiteArchive,
  type CandidateConfig,
} from "./proof-deploy.ts";

const productionWorker = "arcforges-cloud";
const productionRoute = "arcforges.com/api/*";
const zoneName = "arcforges.com";

export interface ApiReply {
  status: number;
  success: boolean;
  /** Provider error codes and messages only; any token text is removed. */
  errors: string;
  result: unknown;
}

export class CloudflareApi {
  readonly account: string;
  private readonly token: string;
  private readonly fetcher: typeof fetch;

  constructor(account: string, token: string, fetcher: typeof fetch = fetch) {
    this.account = account;
    this.token = token;
    this.fetcher = fetcher;
  }

  private scrub(text: string): string {
    return this.token === "" ? text : text.split(this.token).join("[redacted]");
  }

  async request(method: string, endpoint: string, body?: unknown): Promise<ApiReply> {
    // Reads are retried a bounded number of times on transient failures; writes are never blindly
    // repeated (the callers re-read the state instead).
    const attempts = method === "GET" ? 3 : 1;
    let last: ApiReply = { status: 0, success: false, errors: "no response", result: null };
    for (let attempt = 1; attempt <= attempts; attempt++) {
      try {
        const response = await this.fetcher(`https://api.cloudflare.com/client/v4${endpoint}`, {
          method,
          headers: {
            authorization: `Bearer ${this.token}`,
            "content-type": "application/json",
          },
          body: body === undefined ? undefined : JSON.stringify(body),
          signal: AbortSignal.timeout(30_000),
        });
        let parsed: { success?: boolean; errors?: unknown; result?: unknown } = {};
        try {
          parsed = (await response.json()) as typeof parsed;
        } catch {
          // A non-JSON reply is reported by status only.
        }
        const errors = Array.isArray(parsed.errors)
          ? (parsed.errors as { code?: unknown; message?: unknown }[])
              .map((error) => `${String(error.code ?? "?")} ${String(error.message ?? "")}`.trim())
              .join("; ")
          : "";
        last = {
          status: response.status,
          success: response.ok && parsed.success !== false,
          errors: this.scrub(errors),
          result: parsed.result ?? null,
        };
        if (last.status < 500 && last.status !== 429) return last;
      } catch (error) {
        last = {
          status: 0,
          success: false,
          errors: this.scrub(error instanceof Error ? error.name : "network error"),
          result: null,
        };
      }
      if (attempt < attempts) await new Promise((resolve) => setTimeout(resolve, attempt * 2_000));
    }
    return last;
  }

  accountPath(rest: string): string {
    return `/accounts/${this.account}${rest}`;
  }
}

export interface Check {
  name: string;
  required: boolean;
  ok: boolean;
  detail: string;
}

function line(check: Check): string {
  return `${check.ok ? "PASS" : check.required ? "FAIL" : "INFO"} ${check.name}${check.detail ? ` (${check.detail})` : ""}`;
}

function describe(reply: ApiReply): string {
  return `http ${reply.status}${reply.errors ? `, ${reply.errors}` : ""}`;
}

async function listCheck(
  api: CloudflareApi,
  name: string,
  endpoint: string,
  required: boolean,
): Promise<Check> {
  const reply = await api.request("GET", endpoint);
  return { name, required, ok: reply.success, detail: reply.success ? "" : describe(reply) };
}

export async function findZoneId(api: CloudflareApi): Promise<string | null> {
  const reply = await api.request("GET", `/zones?name=${zoneName}`);
  const zones = Array.isArray(reply.result) ? (reply.result as { id?: string }[]) : [];
  return reply.success && zones.length === 1 ? (zones[0]?.id ?? null) : null;
}

/** Read probes of every permission the proof deployment needs. Names and statuses only. */
export async function probeAccess(api: CloudflareApi): Promise<Check[]> {
  const checks: Check[] = [];
  // Account tokens verify on the account endpoint, user tokens on the user endpoint.
  let verify = await api.request("GET", api.accountPath("/tokens/verify"));
  if (!verify.success) verify = await api.request("GET", "/user/tokens/verify");
  const status = (verify.result as { status?: string } | null)?.status;
  checks.push({
    name: "token verify",
    required: false,
    ok: verify.success && status === "active",
    detail: verify.success ? `status ${String(status)}` : describe(verify),
  });
  checks.push(
    await listCheck(api, "Workers Scripts read", api.accountPath("/workers/scripts"), true),
  );
  checks.push(await listCheck(api, "D1 read", api.accountPath("/d1/database?per_page=5"), true));
  checks.push(await listCheck(api, "R2 read", api.accountPath("/r2/buckets"), true));
  checks.push(await listCheck(api, "Queues read", api.accountPath("/queues?per_page=5"), true));
  const zoneId = await findZoneId(api);
  checks.push({
    name: `Zone read (${zoneName})`,
    required: true,
    ok: zoneId !== null,
    detail: zoneId === null ? "zone not visible to the token" : "",
  });
  if (zoneId !== null) {
    checks.push(
      await listCheck(api, "Workers Routes read", `/zones/${zoneId}/workers/routes`, false),
    );
    checks.push(
      await listCheck(
        api,
        `DNS read (${zoneName})`,
        `/zones/${zoneId}/dns_records?name=${proofHostname}`,
        false,
      ),
    );
  }
  checks.push(
    await listCheck(api, "Workers custom domains read", api.accountPath("/workers/domains"), false),
  );
  return checks;
}

export interface Provisioned {
  d1DatabaseId: string;
  actions: string[];
}

async function ensureD1(api: CloudflareApi, actions: string[]): Promise<string> {
  const find = async () => {
    const reply = await api.request(
      "GET",
      api.accountPath(`/d1/database?name=${encodeURIComponent(proofDatabaseName)}&per_page=100`),
    );
    assert(reply.success, `D1 list failed (${describe(reply)})`);
    const found = (reply.result as { uuid?: string; name?: string }[]).find(
      (entry) => entry.name === proofDatabaseName,
    );
    return found?.uuid;
  };
  let id = await find();
  if (id === undefined) {
    const created = await api.request("POST", api.accountPath("/d1/database"), {
      name: proofDatabaseName,
    });
    // Whatever the create answered, the listing decides (a lost reply may hide a success).
    id = await find();
    assert(id !== undefined, `D1 create failed (${describe(created)})`);
    actions.push(`D1 ${proofDatabaseName}: created`);
  } else actions.push(`D1 ${proofDatabaseName}: exists`);
  assert.match(id, /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/u);
  return id;
}

async function ensureBucket(api: CloudflareApi, actions: string[]): Promise<void> {
  const exists = async () =>
    (await api.request("GET", api.accountPath(`/r2/buckets/${proofBucketName}`))).success;
  if (await exists()) return void actions.push(`R2 ${proofBucketName}: exists`);
  const created = await api.request("POST", api.accountPath("/r2/buckets"), {
    name: proofBucketName,
  });
  assert(await exists(), `R2 create failed (${describe(created)})`);
  actions.push(`R2 ${proofBucketName}: created`);
}

async function ensureQueue(api: CloudflareApi, name: string, actions: string[]): Promise<void> {
  const exists = async () => {
    const reply = await api.request("GET", api.accountPath("/queues?per_page=100"));
    assert(reply.success, `Queues list failed (${describe(reply)})`);
    return (reply.result as { queue_name?: string }[]).some((entry) => entry.queue_name === name);
  };
  if (await exists()) return void actions.push(`Queue ${name}: exists`);
  const created = await api.request("POST", api.accountPath("/queues"), { queue_name: name });
  assert(await exists(), `Queue create failed (${describe(created)})`);
  actions.push(`Queue ${name}: created`);
}

/** Idempotent creation of exactly the reserved proof resources; nothing else is touched. */
export async function provision(api: CloudflareApi): Promise<Provisioned> {
  const actions: string[] = [];
  const d1DatabaseId = await ensureD1(api, actions);
  await ensureBucket(api, actions);
  for (const name of proofQueueNames) await ensureQueue(api, name, actions);
  return { d1DatabaseId, actions };
}

/**
 * Hard stop before the custom domain is attached. An existing DNS record for the proof hostname is
 * accepted only when the domain already serves the proof Worker (a redeploy); any other record, or a
 * DNS or domain lookup that cannot be read, stops the job so no existing record or service is taken
 * over. Wrangler's own refusal to override a record is a second guard, not the only one.
 */
export async function checkProofDomainFree(api: CloudflareApi): Promise<void> {
  const zoneId = await findZoneId(api);
  assert(
    zoneId !== null,
    `Zone ${zoneName} is not visible to the token; the domain is not attached.`,
  );
  const domains = await api.request(
    "GET",
    api.accountPath(`/workers/domains?hostname=${proofHostname}`),
  );
  assert(domains.success, `Workers domains lookup failed (${describe(domains)}); not attaching.`);
  const attached = (domains.result as { hostname?: string; service?: string }[] | null) ?? [];
  const entry = attached.find((item) => item.hostname === proofHostname);
  assert(
    entry === undefined || entry.service === proofWorkerName,
    `${proofHostname} already serves another Worker; not attaching.`,
  );
  const dns = await api.request("GET", `/zones/${zoneId}/dns_records?name=${proofHostname}`);
  assert(dns.success, `DNS lookup for ${proofHostname} failed (${describe(dns)}); not attaching.`);
  const records = Array.isArray(dns.result) ? (dns.result as unknown[]) : [];
  assert(
    records.length === 0 || entry?.service === proofWorkerName,
    `A DNS record for ${proofHostname} exists and is not the proof Worker's custom domain; not attaching.`,
  );
}

/** Provider receipts after the deployment: no request reaches the deployed service. */
export async function postDeployChecks(api: CloudflareApi): Promise<Check[]> {
  const checks: Check[] = [];
  const subdomain = await api.request(
    "GET",
    api.accountPath(`/workers/scripts/${proofWorkerName}/subdomain`),
  );
  const state = subdomain.result as { enabled?: boolean; previews_enabled?: boolean } | null;
  // An absent field is "not disabled": only an explicit false proves workers.dev is off, and preview
  // URLs must not be reported enabled.
  checks.push({
    name: "workers.dev and preview URLs disabled for the proof Worker",
    required: true,
    ok: subdomain.success && state?.enabled === false && state?.previews_enabled !== true,
    detail: subdomain.success
      ? `enabled=${String(state?.enabled)}, previews_enabled=${String(state?.previews_enabled)}`
      : describe(subdomain),
  });
  const domains = await api.request(
    "GET",
    api.accountPath(`/workers/domains?hostname=${proofHostname}`),
  );
  const attached = Array.isArray(domains.result)
    ? (domains.result as { hostname?: string; service?: string }[]).some(
        (entry) => entry.hostname === proofHostname && entry.service === proofWorkerName,
      )
    : false;
  checks.push({
    name: `custom domain ${proofHostname} serves ${proofWorkerName}`,
    required: true,
    ok: domains.success && attached,
    detail: domains.success ? "" : describe(domains),
  });
  const zoneId = await findZoneId(api);
  if (zoneId === null) {
    // Without the zone the production route cannot be proven intact: fail closed.
    checks.push({
      name: `zone ${zoneName} readable for the route receipts`,
      required: true,
      ok: false,
      detail: "zone not visible to the token",
    });
    return checks;
  }
  const routes = await api.request("GET", `/zones/${zoneId}/workers/routes`);
  const list = Array.isArray(routes.result)
    ? (routes.result as { pattern?: string; script?: string }[])
    : [];
  checks.push({
    name: `production route ${productionRoute} still serves ${productionWorker}`,
    required: true,
    ok:
      routes.success &&
      list.some((entry) => entry.pattern === productionRoute && entry.script === productionWorker),
    detail: routes.success ? "" : describe(routes),
  });
  checks.push({
    name: "no proof Worker route on the zone",
    required: true,
    ok: routes.success && !list.some((entry) => entry.script === proofWorkerName),
    detail: routes.success ? "" : describe(routes),
  });
  return checks;
}

// ------------------------------------------------------------------------------------------ read-only observation

/** The proof Container application Wrangler creates for env.proof (worker name, class name and environment). */
export const proofContainerApplication = "arcforges-cloud-proof-foundationcontainer-proof";
/** One page of instances; the proof application has two named instances, so a full page is reported as a limit. */
export const observedInstancesPerPage = 100;

/**
 * The only fields the observation prints. Everything else the provider returns (environment values, labels, keys,
 * image registry paths, messages, log lines) is never printed: names, provider ids, states, counts, versions,
 * locations, placement and rollout settings and times only.
 */
const observedFields = new Set([
  "id",
  "name",
  "version",
  "app_version",
  "state",
  "status",
  "health",
  "container_status",
  "location",
  "region",
  "regions",
  "cities",
  "tier",
  "tiers",
  "jurisdiction",
  "created_at",
  "updated_at",
  "last_updated_at",
  "last_change",
  "assigned_at",
  "started_at",
  "stopped_at",
  "deployment_id",
  "durable_object_id",
  "namespace_id",
  "max_instances",
  "min_instances",
  "instances",
  "instance_type",
  "vcpu",
  "memory_mib",
  "disk_mb",
  "scheduling_policy",
  "rollout_active_grace_period",
  "active_rollout_id",
  "rollout_step_percentage",
  "rollout_kind",
  "kind",
  "strategy",
  "step",
  "steps",
  "current_step",
  "progress",
  "percentage",
  "target_version",
  "healthy",
  "failed",
  "starting",
  "scheduling",
  "active",
  "assigned",
  "running",
  "stopping",
  "stopped",
  "placed",
  "provisioning",
  "unhealthy",
  "count",
  "total",
  "exit_code",
]);
/** Subtrees that are never read into the output, whatever field names they contain. */
const withheldSubtrees = new Set([
  "environment",
  "environment_variables",
  "env",
  "secrets",
  "labels",
  "ssh",
  "wrangler_ssh",
  "authorized_keys",
  "trusted_user_ca_keys",
  "command",
  "entrypoint",
  "dns",
  "network",
]);
/** A printed value is short and made of id, time, state and location characters only. */
const plainValue = /^[A-Za-z0-9 ._:+@/-]{0,120}$/u;
const plainState = /^[a-z_]{1,32}$/u;

export interface ObservedRow {
  path: string;
  value: string;
}

/** Flattens a provider object into its allowlisted primitive fields, in a stable order, never a value with the account. */
export function observedFieldsOf(value: unknown, account: string, prefix = ""): ObservedRow[] {
  const rows: ObservedRow[] = [];
  const visit = (node: unknown, path: string, key: string) => {
    if (Array.isArray(node)) {
      node.forEach((item, index) => {
        visit(item, `${path}[${index}]`, key);
      });
      return;
    }
    if (node !== null && typeof node === "object") {
      const record = node as Record<string, unknown>;
      for (const name of Object.keys(record).sort())
        if (!withheldSubtrees.has(name)) visit(record[name], path ? `${path}.${name}` : name, name);
      return;
    }
    if (!observedFields.has(key)) return;
    if (node !== null && !["string", "number", "boolean"].includes(typeof node)) return;
    const text = String(node);
    if (account !== "" && text.includes(account)) return;
    rows.push({ path, value: plainValue.test(text) ? text : "[withheld]" });
  };
  visit(value, prefix, "");
  return rows;
}

export interface ObservedInstance {
  id?: string;
  app_version?: number | string;
  location?: string;
  created_at?: string;
  current_placement?: { status?: { health?: string; container_status?: string } };
}
export interface ObservedDurableObject {
  id?: string;
  name?: string;
  deployment_id?: string;
  assigned_at?: string;
}

/** The instance state as Wrangler's `containers instances` derives it: the container status first, then the health. */
export function instanceState(instance: ObservedInstance | undefined): string {
  if (!instance) return "none";
  const status = instance.current_placement?.status;
  const raw = status?.container_status ?? status?.health;
  if (raw === undefined || !plainState.test(String(raw))) return "unknown";
  return raw === "placed" ? "provisioning" : String(raw);
}

function plain(value: unknown, fallback = "-"): string {
  if (value === undefined || value === null) return fallback;
  const text = String(value);
  return plainValue.test(text) ? text : "[withheld]";
}

/** "name 2, other 1": a stable count of values. */
function tally(values: string[]): string {
  const totals = new Map<string, number>();
  for (const value of values) totals.set(value, (totals.get(value) ?? 0) + 1);
  return (
    [...totals]
      .sort(([a], [b]) => a.localeCompare(b))
      .map(([value, total]) => `${value} ${total}`)
      .join(", ") || "none"
  );
}

function imageDigest(application: Record<string, unknown> | null): string {
  const image = (application?.configuration as { image?: unknown } | undefined)?.image;
  const digest =
    typeof image === "string" ? /@sha256:([0-9a-f]{64})$/u.exec(image)?.[1] : undefined;
  return digest ? `sha256:${digest}` : "unknown";
}

/**
 * The read-only observation of the proof Container application (manual dispatch `proof=observe`). It reads the
 * application, its status, every instance with the Durable Object it serves and the rollouts, and asks once, as a dry
 * run that stores nothing, whether the token may query Workers Logs; of that answer only the HTTP status is used. It
 * creates, changes and deletes nothing. The summary sets the configured ceiling against what the provider lists, by
 * state, version and location, so that a stopped or stopping instance still listed, a single usable placement and
 * instances left by an earlier rollout can be told apart; the allowlisted fields follow. The application and its
 * instances must be readable; the status, the rollouts and the logs question only report when they are not.
 */
export async function observe(api: CloudflareApi, now: () => number = Date.now): Promise<string[]> {
  const lines: string[] = [];
  const scrub = (text: string) => text.split(api.account).join("[account]");
  const listed = await api.request("GET", api.accountPath("/containers/applications"));
  assert(listed.success, `Container applications read failed (${scrub(describe(listed))})`);
  const applications = Array.isArray(listed.result)
    ? (listed.result as { id?: unknown; name?: unknown }[])
    : [];
  const found = applications.filter((entry) => entry.name === proofContainerApplication);
  assert.equal(found.length, 1, `The application ${proofContainerApplication} was not found once.`);
  const id = String(found[0]?.id ?? "");
  assert.match(
    id,
    /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/u,
    "Unexpected application id",
  );
  const base = api.accountPath(`/containers/applications/${id}`);
  const detail = await api.request("GET", base);
  assert(detail.success, `Container application read failed (${scrub(describe(detail))})`);
  const application = (detail.result ?? null) as Record<string, unknown> | null;
  const listing = await api.request(
    "GET",
    api.accountPath(
      `/containers/dash/applications/${id}/instances?per_page=${observedInstancesPerPage}`,
    ),
  );
  assert(listing.success, `Container instances read failed (${scrub(describe(listing))})`);
  const data = (listing.result ?? {}) as {
    instances?: ObservedInstance[];
    durable_objects?: ObservedDurableObject[];
  };
  const instances = Array.isArray(data.instances) ? data.instances : [];
  const durableObjects = Array.isArray(data.durable_objects) ? data.durable_objects : [];
  const status = await api.request("GET", `${base}/status`);
  const rollouts = await api.request("GET", `${base}/rollouts`);
  const to = now();
  const logs = await api.request(
    "POST",
    api.accountPath("/workers/observability/telemetry/query"),
    {
      queryId: "cloud-proof-observe",
      timeframe: { from: to - 3_600_000, to },
      view: "calculations",
      dry: true,
      limit: 1,
      parameters: {
        calculations: [{ operator: "count" }],
        filters: [
          { key: "$metadata.service", operation: "eq", type: "string", value: proofWorkerName },
        ],
      },
    },
  );

  const version = application?.version;
  const configuration = application?.configuration as { instance_type?: unknown } | undefined;
  const byId = new Map(instances.map((instance) => [instance.id, instance]));
  const serving = (instance: ObservedInstance) =>
    durableObjects.find(
      (entry) => entry.deployment_id !== undefined && entry.deployment_id === instance.id,
    );
  lines.push(`Proof Container application ${proofContainerApplication} (${plain(id)}):`);
  lines.push(
    `  configured: max_instances ${plain(application?.max_instances, "unknown")}, instance_type ${plain(
      configuration?.instance_type ?? application?.instance_type,
      "unknown",
    )}, scheduling_policy ${plain(application?.scheduling_policy, "unknown")}, version ${plain(
      version,
      "unknown",
    )}, image ${imageDigest(application)}`,
  );
  lines.push(
    `  listed instances: ${instances.length}${instances.length >= observedInstancesPerPage ? " (one full page; more may exist)" : ""}`,
  );
  lines.push(`  by state: ${tally(instances.map((instance) => instanceState(instance)))}`);
  lines.push(
    `  by version: ${tally(
      instances.map((instance) =>
        version !== undefined && String(instance.app_version) === String(version)
          ? `current ${plain(version)}`
          : `other ${plain(instance.app_version, "unknown")}`,
      ),
    )}`,
  );
  lines.push(
    `  by location: ${tally(instances.map((instance) => plain(instance.location, "unknown")))}`,
  );
  lines.push(
    `  instances serving no Durable Object: ${instances.filter((instance) => !serving(instance)).length}`,
  );
  lines.push("  Durable Objects:");
  for (const entry of [...durableObjects].sort((a, b) =>
    String(a.name ?? "").localeCompare(String(b.name ?? "")),
  )) {
    const instance = entry.deployment_id ? byId.get(entry.deployment_id) : undefined;
    lines.push(
      `    ${plain(entry.name, "unnamed")}: instance ${plain(instance?.id, "none")}, state ${instanceState(instance)}, version ${plain(
        instance?.app_version,
      )}, location ${plain(instance?.location)}, created ${plain(instance?.created_at)}, assigned ${plain(entry.assigned_at)}`,
    );
  }
  lines.push("  Instances:");
  for (const instance of instances)
    lines.push(
      `    ${plain(instance.id, "unknown")}: state ${instanceState(instance)}, version ${plain(
        instance.app_version,
      )}, location ${plain(instance.location)}, created ${plain(instance.created_at)}, Durable Object ${plain(
        serving(instance)?.name,
        "none",
      )}`,
    );
  const section = (title: string, value: unknown) => {
    lines.push(`  ${title}:`);
    for (const row of observedFieldsOf(value, api.account))
      lines.push(`    ${row.path} = ${row.value}`);
  };
  section("application fields", application);
  section("instance fields", { instances, durable_objects: durableObjects });
  if (status.success) section("status fields", status.result);
  else lines.push(`  INFO status not read (${scrub(describe(status))})`);
  if (rollouts.success) {
    const list = Array.isArray(rollouts.result)
      ? (rollouts.result as { created_at?: unknown }[])
      : [];
    const newest = [...list]
      .sort((a, b) => String(b.created_at ?? "").localeCompare(String(a.created_at ?? "")))
      .slice(0, 5);
    section(`rollouts (newest ${newest.length} of ${list.length})`, newest);
  } else lines.push(`  INFO rollouts not read (${scrub(describe(rollouts))})`);
  lines.push(
    logs.success
      ? "  Workers Logs: the deployment token may query them (dry query answered; nothing of it is printed)"
      : logs.status === 401 || logs.status === 403
        ? `  INFO Workers Logs: the deployment token may not query them (http ${logs.status})`
        : `  INFO Workers Logs: the dry query was not answered (http ${logs.status}); permission unknown`,
  );
  return lines.map(scrub);
}

export function report(title: string, checks: Check[]): void {
  console.log(`${title}:`);
  for (const check of checks) console.log(`  ${line(check)}`);
  const failed = checks.filter((check) => check.required && !check.ok);
  assert.equal(
    failed.length,
    0,
    `${failed.length} required check(s) failed: ${failed.map((check) => check.name).join(", ")}`,
  );
}

export function requireContext(
  environment: Record<string, string | undefined>,
  action: string,
): { account: string; token: string } {
  assert.equal(environment.GITHUB_ACTIONS, "true", "The proof environment is handled in CI only.");
  assert.equal(environment.GITHUB_REPOSITORY, "ArcForges/Cloud");
  assert.equal(
    environment.GITHUB_REF,
    "refs/heads/main",
    "Only main may touch the proof environment.",
  );
  assert.equal(
    environment.GITHUB_EVENT_NAME,
    "workflow_dispatch",
    "The proof environment is manual.",
  );
  assert(
    ["access", "provision", "deploy", "observe"].includes(action),
    "Use access, provision, deploy or observe.",
  );
  const account = environment.CLOUDFLARE_ACCOUNT_ID ?? "";
  assert.match(
    account,
    /^[0-9a-f]{32}$/u,
    "Set CLOUDFLARE_ACCOUNT_ID in the cloudflare environment.",
  );
  const token = environment.CLOUDFLARE_API_TOKEN ?? "";
  assert(token !== "", "Set the CLOUDFLARE_API_TOKEN environment secret.");
  return { account, token };
}

/** The gh arguments that download one pinned Web release asset into a directory. */
export function releaseDownloadArguments(
  pin: { repository: string; release: string },
  assetName: string,
  directory: string,
): string[] {
  return [
    "release",
    "download",
    pin.release,
    "--repo",
    pin.repository,
    "--pattern",
    assetName,
    "--dir",
    directory,
  ];
}

export interface StagedProofAssets {
  profileDigest: string;
  siteDigest: string;
  files: number;
  headersSha256: string;
}

/**
 * Verifies the two downloaded Web release assets against their pinned digests (the Blazor profile bundle and the C#
 * Site archive), composes them into the one proof tree and stages it under the root's artifacts. Nothing is staged
 * unless both verify.
 */
export async function verifyAndStageProofAssets(
  downloaded: { profile: Uint8Array; site: Uint8Array },
  root: string,
  pins: { profile: string; site: string } = {
    profile: profileBundlePin.digest,
    site: siteArchivePin.digest,
  },
): Promise<StagedProofAssets> {
  const profile = verifyProfileBundle(downloaded.profile, pins.profile);
  const site = verifySiteArchive(downloaded.site, pins.site);
  const assets = composeProofAssets(profile, site);
  const files = await stageProofAssets(assets, path.join(root, "artifacts", proofAssetsDirName));
  return {
    profileDigest: profile.digest,
    siteDigest: site.digest,
    files,
    headersSha256: createHash("sha256").update(assets.headers).digest("hex"),
  };
}

async function deploy(api: CloudflareApi, provisioned: Provisioned): Promise<void> {
  const { verifyCandidate } = await import("../../tooling/project.ts");
  const { candidateDir, readJson, root, run, wrangler, writeJson } =
    await import("../../tooling/process.ts");
  const candidate = await verifyCandidate();
  assert.equal(candidate.dirty, false, "Uncommitted local builds cannot deploy.");
  const current = await run(
    "gh",
    ["api", "repos/ArcForges/Cloud/git/ref/heads/main", "--jq", ".object.sha"],
    true,
  );
  assert.equal(candidate.revision, current, "A newer main commit exists; only it may deploy.");
  await run("docker", ["load", "--input", "artifacts/candidate/docker-image.tar"]);
  const imageId = await run(
    "docker",
    ["image", "inspect", candidate.image, "--format", "{{.Id}}"],
    true,
  );
  assert.equal(imageId, candidate.imageId, "Loaded image is not the sealed candidate image.");
  await run(process.execPath, [wrangler, "containers", "push", candidate.image]);
  const registryTag = `registry.cloudflare.com/${api.account}/${candidate.image}`;
  const digests = JSON.parse(
    await run(
      "docker",
      ["image", "inspect", registryTag, "--format", "{{json .RepoDigests}}"],
      true,
    ),
  ) as string[];
  const prefix = `registry.cloudflare.com/${api.account}/arcforges-cloud@sha256:`;
  const imageDigest = digests.find((value) => value.startsWith(prefix));
  assert(imageDigest, "Cloudflare registry did not return the pushed image digest.");

  // WEB.40 (CLOUD.85): the two immutable release assets of one Web release, the Blazor profile bundle and the C#
  // Site archive. Each is downloaded from its pinned release, verified against its pinned digest and composed into
  // the one proof tree. Nothing is rebuilt and no Web source is read; a mismatch stops the job before anything is
  // deployed.
  const releaseDir = path.join(root, "artifacts", "web-release");
  const profileAsset = profileBundleAssetName(profileBundlePin.digest);
  const siteAsset = siteArchiveAssetName(siteArchivePin.digest);
  await rm(releaseDir, { recursive: true, force: true });
  await run("gh", releaseDownloadArguments(profileBundlePin, profileAsset, releaseDir));
  await run("gh", releaseDownloadArguments(siteArchivePin, siteAsset, releaseDir));
  const staged = await verifyAndStageProofAssets(
    {
      profile: await readFile(path.join(releaseDir, profileAsset)),
      site: await readFile(path.join(releaseDir, siteAsset)),
    },
    root,
  );
  console.log(
    `Web ${profileBundlePin.release}: profile bundle ${staged.profileDigest} and Site ${staged.siteDigest} verified; ${staged.files} files staged as the proof assets.`,
  );

  await checkProofDomainFree(api);
  const config = buildProofConfig(
    await readJson<CandidateConfig>(path.join(candidateDir, "wrangler.json")),
    {
      account: api.account,
      imageDigest,
      revision: candidate.revision,
      databaseId: provisioned.d1DatabaseId,
      main: "./candidate/worker.js",
      migrationsDir: "../worker/proof-migrations",
    },
  );
  const configFile = path.join(root, "artifacts", "proof.wrangler.json");
  await writeJson(configFile, config);
  const common = ["--config", "artifacts/proof.wrangler.json", "--env", "proof"];
  // Migrations are a separate step, never part of Container startup.
  await run(process.execPath, [
    wrangler,
    "d1",
    "migrations",
    "apply",
    proofDatabaseName,
    "--remote",
    ...common,
  ]);
  // Fresh secrets travel in a runner-local file that Wrangler uploads with the version and that is
  // removed immediately; nothing prints them.
  const secretsDir = path.join(process.env.RUNNER_TEMP ?? path.join(root, "artifacts"), "proof");
  const secretsFile = path.join(secretsDir, `secrets-${randomBytes(8).toString("hex")}.json`);
  await mkdir(secretsDir, { recursive: true });
  try {
    await writeFile(secretsFile, JSON.stringify(generateSecrets()), { mode: 0o600 });
    await run(process.execPath, [
      wrangler,
      "deploy",
      ...common,
      "--no-bundle",
      "--containers-rollout",
      "immediate",
      "--tag",
      `${candidate.version}-proof`,
      "--secrets-file",
      secretsFile,
    ]);
  } finally {
    await rm(secretsFile, { force: true });
  }
  const receipts = await postDeployChecks(api);
  await writeJson(path.join(root, "artifacts", "proof-deployment.json"), {
    revision: candidate.revision,
    version: candidate.version,
    imageId: candidate.imageId,
    imageDigest,
    worker: proofWorkerName,
    hostname: proofHostname,
    baseUrl: `https://${proofHostname}`,
    d1DatabaseId: provisioned.d1DatabaseId,
    resources: provisioned.actions,
    profileBundle: {
      repository: profileBundlePin.repository,
      release: profileBundlePin.release,
      digest: staged.profileDigest,
    },
    siteArchive: {
      repository: siteArchivePin.repository,
      release: siteArchivePin.release,
      digest: staged.siteDigest,
    },
    proofAssets: { files: staged.files, headersSha256: staged.headersSha256 },
    receipts: receipts.map((check) => ({ name: check.name, ok: check.ok })),
    deployedAt: new Date().toISOString(),
  });
  report("Post-deployment provider receipts", receipts);
  console.log(
    `Proof environment deployed at https://${proofHostname}. This is deployment completion, not live acceptance evidence.`,
  );
}

export async function main(action: string): Promise<void> {
  const { account, token } = requireContext(process.env, action);
  const api = new CloudflareApi(account, token);
  if (action === "observe") {
    // Read-only: nothing is provisioned, deployed or changed, and no request reaches the deployed service.
    for (const line of await observe(api)) console.log(line);
    return;
  }
  report("Access", await probeAccess(api));
  if (action === "access") return;
  const provisioned = await provision(api);
  for (const entry of provisioned.actions) console.log(`  ${entry}`);
  if (action === "provision") return;
  await deploy(api, provisioned);
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url))
  await main(process.argv[2] ?? "");
