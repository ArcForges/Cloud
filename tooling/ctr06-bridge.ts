// SPDX-License-Identifier: AGPL-3.0-only
// Pure verification used by the protected CTR06 bridge publisher. The caller
// supplies authenticated provider API results; no slot label is promotion proof.
import assert from "node:assert/strict";
import { createHash } from "node:crypto";

export const bridgeRevision = "8e5f6e26aa97b123d9f60b91f780364a094e74cd";
export const bridgeImageId =
  "sha256:9b90c26264806fda339cdcff44dcf987bccf702117b3cd3e81ed7248de9730f0";
export const bridgeReleaseSHA256 =
  "d9c52a13c54b073758866c9e02168cc1e527cca92257df259e97298a5aa2a466";

export interface BridgeContext {
  environment: "production" | "acceptance";
  databaseHost: string;
  databasePort: number;
  databaseName: string;
  databaseOid: number;
  ownerOid: number;
  legacyRole: string;
  legacyRoleOid: number;
  bridgeRole: string;
  bridgeRoleOid: number;
  bridgeLogin: string;
  bridgeLoginOid: number;
  nonce: string;
  workflowRevision: string;
  cloudAccount: string;
  workerName: string;
  workerVersion: string;
  containerApplication: string;
  registryImage: string;
}

/** Must match the verifier in center/internal/bridgeproof exactly. */
export function bridgeAudience(c: BridgeContext): string {
  assert(["production", "acceptance"].includes(c.environment));
  assert.match(c.databaseHost, /^[a-z0-9.-]{1,253}$/u);
  assert(Number.isInteger(c.databasePort) && c.databasePort > 0 && c.databasePort <= 65535);
  for (const name of [c.databaseName, c.legacyRole, c.bridgeRole, c.bridgeLogin, c.workerName])
    assert.match(name, /^[a-zA-Z_][a-zA-Z0-9_-]{0,62}$/u);
  for (const oid of [c.databaseOid, c.ownerOid, c.legacyRoleOid, c.bridgeRoleOid, c.bridgeLoginOid])
    assert(Number.isInteger(oid) && oid > 0 && oid <= 4294967295);
  assert.notEqual(c.bridgeRole, c.legacyRole);
  assert.notEqual(c.bridgeLogin, c.bridgeRole);
  assert.match(c.nonce, /^[a-f0-9]{64}$/u);
  assert.match(c.workflowRevision, /^[a-f0-9]{40}$/u);
  assert.match(c.cloudAccount, /^[a-f0-9]{32}$/u);
  assert.equal(
    c.workerName,
    c.environment === "production" ? "arcforges-cloud" : "arcforges-cloud-proof",
  );
  for (const id of [c.workerVersion, c.containerApplication])
    assert.match(id, /^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$/u);
  assert.match(
    c.registryImage,
    new RegExp(
      `^registry\\.cloudflare\\.com/${c.cloudAccount}/arcforges-cloud@sha256:[a-f0-9]{64}$`,
      "u",
    ),
  );
  assert.equal(
    c.registryImage,
    `registry.cloudflare.com/${c.cloudAccount}/arcforges-cloud@${bridgeImageId}`,
    "registry manifest differs from the sealed bridge",
  );
  const fields = [
    "ArcForges CTR06 protected promotion v1",
    c.environment,
    c.databaseHost,
    String(c.databasePort),
    c.databaseName,
    String(c.databaseOid),
    String(c.ownerOid),
    c.legacyRole,
    String(c.legacyRoleOid),
    c.bridgeRole,
    String(c.bridgeRoleOid),
    c.bridgeLogin,
    String(c.bridgeLoginOid),
    c.nonce,
    c.workflowRevision,
    bridgeRevision,
    bridgeImageId,
    bridgeReleaseSHA256,
    c.cloudAccount,
    c.workerName,
    c.workerVersion,
    c.containerApplication,
    c.registryImage,
  ];
  return `urn:arcforges:ctr06:${createHash("sha256").update(fields.join("\n")).digest("hex")}`;
}

type Binding = { name?: unknown; type?: unknown; class_name?: unknown; namespace_id?: unknown };
type WorkerVersion = { id?: unknown; resources?: { bindings?: Binding[] } };
type Deployment = { versions?: { version_id?: unknown; percentage?: unknown }[] };
type Application = {
  id?: unknown;
  account_id?: unknown;
  scheduling_policy?: unknown;
  durable_objects?: { namespace_id?: unknown };
  configuration?: { image?: unknown };
};
type ContainerVersion = { percentage?: unknown; configuration?: { image?: unknown } };
type ContainerInstance = {
  application_id?: unknown;
  image?: unknown;
  status?: { state?: unknown };
};

/**
 * The candidate's upload result supplies versionId; this validates a separate
 * provider read of that exact version and 100% traffic, links its DO namespace
 * to the exact application, and verifies every live/starting/stopping instance
 * and the provider's version distribution against the same immutable image.
 * No secret value is read, returned or compared.
 */
export function verifyBridgeProviderSnapshot(input: {
  account: string;
  environment: "production" | "acceptance";
  workerVersionId: string;
  registryImage: string;
  deployment: Deployment;
  workerVersion: WorkerVersion;
  application: Application;
  versions: ContainerVersion[];
  instances: ContainerInstance[];
}): { applicationId: string; versionId: string; image: string } {
  assert.match(input.account, /^[a-f0-9]{32}$/u);
  assert.match(
    input.workerVersionId,
    /^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$/u,
  );
  assert.match(
    input.registryImage,
    new RegExp(
      `^registry\\.cloudflare\\.com/${input.account}/arcforges-cloud@sha256:[a-f0-9]{64}$`,
      "u",
    ),
  );
  assert.equal(
    input.registryImage,
    `registry.cloudflare.com/${input.account}/arcforges-cloud@${bridgeImageId}`,
    "registry manifest differs from the sealed bridge",
  );
  const live = input.deployment.versions?.filter((v) => Number(v.percentage) > 0) ?? [];
  assert.equal(live.length, 1, "provider traffic is split or unknown");
  assert.equal(live[0]?.version_id, input.workerVersionId, "another Worker version is live");
  assert.equal(live[0]?.percentage, 100, "the bridge version does not serve 100%");
  assert.equal(input.workerVersion.id, input.workerVersionId, "provider returned another version");
  const bindings = input.workerVersion.resources?.bindings;
  assert(Array.isArray(bindings), "version bindings unavailable");
  const credential = bindings.filter(
    (b) => b.name === "ARCFORGES_CENTER_DATABASE_URL" && b.type === "secret_text",
  );
  assert.equal(credential.length, 1, "bridge version has no unique runtime secret binding");
  const container = bindings.filter(
    (b) => b.name === "CLOUD_CONTAINER" && b.type === "durable_object_namespace",
  );
  assert.equal(container.length, 1, "bridge version has no unique container binding");
  assert.equal(
    container[0]?.class_name,
    input.environment === "production" ? "CloudContainer" : "FoundationContainer",
  );
  const namespace = container[0]?.namespace_id;
  assert(
    typeof namespace === "string" && /^[a-f0-9]{32}$/u.test(namespace),
    "provider omitted the Durable Object namespace",
  );
  assert.equal(
    input.application.account_id,
    input.account,
    "another provider account owns the application",
  );
  assert.equal(
    input.application.scheduling_policy,
    "default",
    "unsupported container scheduling policy",
  );
  assert.equal(
    input.application.durable_objects?.namespace_id,
    namespace,
    "Worker and container namespaces differ",
  );
  assert.equal(
    input.application.configuration?.image,
    input.registryImage,
    "application image differs from the sealed upload",
  );
  const id = String(input.application.id ?? "");
  assert.match(id, /^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$/u);
  const active = input.versions.filter((v) => Number(v.percentage) > 0);
  assert.equal(active.length, 1, "container versions are split or absent");
  assert.equal(active[0]?.percentage, 100, "container version is not at 100%");
  assert.equal(
    active[0]?.configuration?.image,
    input.registryImage,
    "live container version uses another image",
  );
  for (const instance of input.instances) {
    assert.equal(instance.application_id, id, "provider listed an instance of another application");
    const state = instance.status?.state;
    assert(
      ["running", "provisioning", "stopping", "stopped", "failed", "inactive"].includes(
        String(state),
      ),
      "unknown container state",
    );
    if (state === "running" || state === "provisioning" || state === "stopping")
      assert.equal(
        instance.image,
        input.registryImage,
        "a live or stopping instance still uses an older image",
      );
  }
  return { applicationId: id, versionId: input.workerVersionId, image: input.registryImage };
}

const bridgeMembers = [
  "build-identity.json",
  "docker-image.tar",
  "worker.js",
  "wrangler.json",
  "legal-notices.json",
  "worker-meta.json",
  "proof-worker.js",
  "proof-worker-meta.json",
  "image-provenance.json",
  "arcforges-tool.tar",
];

/** After the pinned carrier is safely extracted, verify every sealed member. */
export async function verifyBridgeCarrier(
  directory: string,
): Promise<{ image: string; imageId: string; version: string }> {
  const { readdir, readFile } = await import("node:fs/promises");
  const path = await import("node:path");
  const { sha256 } = await import("./process.ts");
  assert(path.isAbsolute(directory));
  const entries = (await readdir(directory)).sort();
  assert.deepEqual(
    entries,
    [...bridgeMembers, "manifest.json"].sort(),
    "bridge carrier member set differs",
  );
  const manifest = JSON.parse(await readFile(path.join(directory, "manifest.json"), "utf8")) as {
    schema?: unknown;
    revision?: unknown;
    dirty?: unknown;
    version?: unknown;
    image?: unknown;
    imageId?: unknown;
    files?: Record<string, string>;
  };
  assert.equal(manifest.schema, 1);
  assert.equal(manifest.revision, bridgeRevision);
  assert.equal(manifest.dirty, false);
  assert.equal(manifest.version, "0.1.0-ci.615.1");
  assert.equal(manifest.image, "arcforges-cloud:ci.615.1");
  assert.equal(manifest.imageId, bridgeImageId);
  assert.deepEqual(
    Object.keys(manifest.files ?? {}).sort(),
    [...bridgeMembers].sort(),
    "bridge manifest member set differs",
  );
  for (const member of bridgeMembers) {
    const expected = manifest.files?.[member];
    assert(
      typeof expected === "string" && /^[a-f0-9]{64}$/u.test(expected),
      "invalid bridge member digest",
    );
    assert.equal(
      await sha256(path.join(directory, member)),
      expected,
      `bridge member changed: ${member}`,
    );
  }
  assert.equal(
    manifest.files?.["docker-image.tar"],
    "50d98d88fa84a0bc5f11a123ca5588848632fa11384ae49fc5ca4abd43523f72",
  );
  assert.equal(
    manifest.files?.["worker.js"],
    "4258a4ba977dbc9457f6ce7a307612c5802df5a2ca3a38849defb5dc4c01cf4f",
  );
  assert.equal(
    manifest.files?.["proof-worker.js"],
    "b4eb36509ffe1af337bbdb4f5423dce0fade787b88de60aa890cb5cd18d6d703",
  );
  const config = JSON.parse(await readFile(path.join(directory, "wrangler.json"), "utf8")) as {
    name?: unknown;
    main?: unknown;
    no_bundle?: unknown;
    vars?: Record<string, unknown>;
    containers?: { image?: unknown }[];
  };
  assert.equal(config.name, "arcforges-cloud");
  assert.equal(config.main, "./worker.js");
  assert.equal(config.no_bundle, true);
  assert.equal(config.vars?.SOURCE_REVISION, bridgeRevision);
  assert.equal(config.vars?.FLAGSHIP_SURFACES, "");
  assert.equal(config.containers?.[0]?.image, manifest.image);
  return {
    image: String(manifest.image),
    imageId: bridgeImageId,
    version: String(manifest.version),
  };
}

interface ProviderEnvelope {
  success?: unknown;
  result?: unknown;
  result_info?: { next_page_token?: unknown };
}
type ProviderGet = (path: string) => Promise<ProviderEnvelope>;

/** Fixed-origin authenticated transport. Provider bodies are never logged. */
export function cloudflareReader(account: string, token: string): ProviderGet {
  assert.match(account, /^[a-f0-9]{32}$/u);
  assert(token.length > 0, "Cloudflare provider credential is unavailable");
  return async (path) => {
    assert(path.startsWith("/") && !path.includes(".."));
    const url = `https://api.cloudflare.com/client/v4/accounts/${account}${path}`;
    try {
      const response = await fetch(url, {
        headers: { Authorization: `Bearer ${token}` },
        redirect: "error",
        signal: AbortSignal.timeout(15_000),
      });
      if (!response.ok) throw new Error("provider refused");
      const body = await response.text();
      if (body.length > 2_000_000) throw new Error("provider response too large");
      const parsed = JSON.parse(body) as ProviderEnvelope;
      if (parsed.success !== true) throw new Error("provider refused");
      return parsed;
    } catch {
      throw new Error("The bridge provider metadata could not be verified.");
    }
  };
}

/** Follow the provider's documented cursor, bounded and with no omitted page. */
async function providerPages(get: ProviderGet, path: string): Promise<unknown[]> {
  const all: unknown[] = [];
  let cursor = "";
  const seen = new Set<string>();
  for (let page = 0; page < 100; page++) {
    const query = new URLSearchParams({ per_page: "500" });
    if (cursor) query.set("page_token", cursor);
    const envelope = await get(`${path}?${query}`);
    assert(
      envelope.success === true && Array.isArray(envelope.result),
      "provider list unavailable",
    );
    all.push(...envelope.result);
    assert(
      envelope.result_info && typeof envelope.result_info === "object",
      "provider pagination metadata missing",
    );
    const next = envelope.result_info.next_page_token;
    if (next === undefined || next === null || next === "") return all;
    assert(
      typeof next === "string" && next.length <= 2048 && !seen.has(next),
      "provider cursor invalid",
    );
    seen.add(next);
    cursor = next;
  }
  throw new Error("provider pagination exceeded its bound");
}

/** Read and validate provider metadata after the exact upload returned its ID. */
export async function verifyLiveBridge(
  get: ProviderGet,
  deployment: Deployment,
  account: string,
  environment: "production" | "acceptance",
  workerVersionId: string,
  registryImage: string,
): Promise<{ applicationId: string; versionId: string; image: string }> {
  const worker = environment === "production" ? "arcforges-cloud" : "arcforges-cloud-proof";
  assert.match(workerVersionId, /^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$/u);
  const versionEnvelope = await get(`/workers/scripts/${worker}/versions/${workerVersionId}`);
  assert(
    versionEnvelope.success === true &&
      typeof versionEnvelope.result === "object" &&
      versionEnvelope.result !== null,
  );
  const workerVersion = versionEnvelope.result as WorkerVersion;
  const bindings = workerVersion.resources?.bindings;
  assert(Array.isArray(bindings), "provider did not return version bindings");
  const container = bindings.filter(
    (binding) => binding.name === "CLOUD_CONTAINER" && binding.type === "durable_object_namespace",
  );
  assert.equal(container.length, 1);
  const namespace = container[0]?.namespace_id;
  assert(typeof namespace === "string" && /^[a-f0-9]{32}$/u.test(namespace));
  const applications = (await providerPages(get, "/containers/applications")) as Application[];
  const selected = applications.filter(
    (application) => application.durable_objects?.namespace_id === namespace,
  );
  assert.equal(selected.length, 1, "container namespace is absent or ambiguous");
  const application = selected[0];
  assert(application, "provider returned no selected application");
  const applicationId = String(application.id ?? "");
  assert.match(applicationId, /^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$/u);
  const detail = await get(`/containers/applications/${applicationId}`);
  assert(detail.success === true && typeof detail.result === "object" && detail.result !== null);
  const versions = await get(`/containers/applications/${applicationId}/versions`);
  assert(versions.success === true && Array.isArray(versions.result));
  const instances = (await providerPages(
    get,
    `/containers/applications/${applicationId}/instances-v2`,
  )) as ContainerInstance[];
  return verifyBridgeProviderSnapshot({
    account,
    environment,
    workerVersionId,
    registryImage,
    deployment,
    workerVersion,
    application: detail.result as Application,
    versions: versions.result as ContainerVersion[],
    instances,
  });
}
