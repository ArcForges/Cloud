// SPDX-License-Identifier: AGPL-3.0-only
// The provisioning of the center's Cloudflare resources (AF-CTR-02): its R2 bucket with lifecycle rules and its queues. It is
// idempotent: a resource that exists is kept (its lifecycle rules are set to exactly the declared ones), a missing one is created,
// and nothing else is touched. The PostgreSQL part of provisioning (the database and the roles) belongs to the deployment's
// PostgreSQL step (tooling/postgres-deploy.ts): `admin ensure-database`, then `migrate`, which creates the runtime group role and
// reconciles its grants, and the rotation of the runtime credential at promotion. The acceptance environment is provisioned from
// the manually dispatched proof jobs; production is provisioned only by AF-PROD-01 with the owner's approval (Plan H-20), so the
// production target is refused here until that task changes this file in a reviewed change.
import assert from "node:assert/strict";

export type CenterTarget = "acceptance" | "production";

/** What the provisioning needs of the Cloudflare API client (eng/verification/proof-cloudflare.ts). */
export interface ProvisioningApi {
  readonly account: string;
  request(
    method: string,
    endpoint: string,
    body?: unknown,
  ): Promise<{ status: number; success: boolean; errors: string; result: unknown }>;
  accountPath(rest: string): string;
}

export interface LifecycleRule {
  id: string;
  enabled: boolean;
  conditions: { prefix: string };
  deleteObjectsTransition?: { condition: { type: "Age"; maxAge: number } };
  abortMultipartUploadsTransition?: { condition: { type: "Age"; maxAge: number } };
}

export interface CenterResources {
  bucket: string;
  lifecycle: LifecycleRule[];
  queues: string[];
}

const day = 24 * 60 * 60;

/**
 * The lifecycle of the center's bucket: consented support bundles expire after 30 days (ArcForges-Design data/cloud-store.md
 * section 4) and incomplete multipart uploads are aborted after one day; release artifacts and manifests do not expire.
 */
export const centerLifecycle: LifecycleRule[] = [
  {
    id: "support-bundles-30-days",
    enabled: true,
    conditions: { prefix: "support-bundles/" },
    deleteObjectsTransition: { condition: { type: "Age", maxAge: 30 * day } },
  },
  {
    id: "abort-incomplete-uploads",
    enabled: true,
    conditions: { prefix: "" },
    abortMultipartUploadsTransition: { condition: { type: "Age", maxAge: day } },
  },
];

/** The center's resources per target; the event queue is the outbox publisher's destination, with its dead-letter queue. */
export const centerResources: Record<CenterTarget, CenterResources> = {
  acceptance: {
    bucket: "arcforges-acceptance-center",
    lifecycle: centerLifecycle,
    queues: ["arcforges-acceptance-center-events", "arcforges-acceptance-center-events-dlq"],
  },
  production: {
    bucket: "arcforges-center",
    lifecycle: centerLifecycle,
    queues: ["arcforges-center-events", "arcforges-center-events-dlq"],
  },
};

function describe(reply: { status: number; errors: string }): string {
  return `http ${reply.status}${reply.errors ? `, ${reply.errors}` : ""}`;
}

async function ensureBucket(
  api: ProvisioningApi,
  resources: CenterResources,
  actions: string[],
): Promise<void> {
  const name = resources.bucket;
  const exists = async () =>
    (await api.request("GET", api.accountPath(`/r2/buckets/${name}`))).success;
  if (await exists()) actions.push(`R2 ${name}: exists`);
  else {
    const created = await api.request("POST", api.accountPath("/r2/buckets"), { name });
    // Whatever the create answered, the read decides (a lost reply may hide a success).
    assert(await exists(), `R2 create failed (${describe(created)})`);
    actions.push(`R2 ${name}: created`);
  }
  const lifecycle = await api.request("PUT", api.accountPath(`/r2/buckets/${name}/lifecycle`), {
    rules: resources.lifecycle,
  });
  assert(lifecycle.success, `R2 lifecycle update failed (${describe(lifecycle)})`);
  const read = await api.request("GET", api.accountPath(`/r2/buckets/${name}/lifecycle`));
  const rules = (read.result as { rules?: { id?: string }[] } | null)?.rules ?? [];
  assert(
    read.success &&
      resources.lifecycle.every((rule) => rules.some((entry) => entry.id === rule.id)),
    `R2 lifecycle rules of ${name} were not applied (${describe(read)})`,
  );
  actions.push(`R2 ${name}: lifecycle ${resources.lifecycle.map((rule) => rule.id).join(", ")}`);
}

async function ensureQueue(api: ProvisioningApi, name: string, actions: string[]): Promise<void> {
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

/** Idempotent creation of exactly the target's resources. Production is refused (AF-PROD-01 with the owner's approval only). */
export async function provisionCenter(
  api: ProvisioningApi,
  target: CenterTarget,
): Promise<string[]> {
  if (target === "production")
    throw new Error(
      "The center's production resources are provisioned only by AF-PROD-01 with the owner's approval (H-20); nothing was changed.",
    );
  const resources = centerResources[target];
  const actions: string[] = [];
  await ensureBucket(api, resources, actions);
  for (const queue of resources.queues) await ensureQueue(api, queue, actions);
  return actions;
}
