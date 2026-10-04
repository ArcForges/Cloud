// SPDX-License-Identifier: AGPL-3.0-only
// Cloudflare account access, resource provisioning and deployment of the isolated `proof` environment.
// It runs only in the manually dispatched jobs of .github/workflows/ci.yml on `main`, inside the
// `cloudflare` GitHub environment, with the existing deployment token. Output is sanitized: it names
// capabilities, resources and HTTP statuses, never a token, a secret or a response body. The proof
// secrets are generated here at deploy time and handed to Wrangler through a runner-local file; they
// are never printed, never committed and never leave the runner except into the proof Worker.
// No live service is called: the checks are provider metadata receipts, not runtime tests.
import assert from "node:assert/strict";
import { randomBytes } from "node:crypto";
import { mkdir, rm, writeFile } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";
import {
  buildProofConfig,
  generateSecrets,
  proofBucketName,
  proofDatabaseName,
  proofHostname,
  proofQueueNames,
  proofWorkerName,
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
  assert(["access", "provision", "deploy"].includes(action), "Use access, provision or deploy.");
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
  report("Access", await probeAccess(api));
  if (action === "access") return;
  const provisioned = await provision(api);
  for (const entry of provisioned.actions) console.log(`  ${entry}`);
  if (action === "provision") return;
  await deploy(api, provisioned);
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url))
  await main(process.argv[2] ?? "");
