// SPDX-License-Identifier: AGPL-3.0-only
import assert from "node:assert/strict";
import { test } from "node:test";
import { bridgeAudience, verifyBridgeProviderSnapshot } from "../../tooling/ctr06-bridge.ts";
import { promoteCTR06Bridge } from "../../tooling/ctr06-publisher.ts";
import type { CenterRunner } from "../../tooling/postgres-deploy.ts";

const account = "c".repeat(32);
const version = "00000000-0000-4000-8000-000000000001";
const application = "00000000-0000-4000-8000-000000000002";
const namespace = "e".repeat(32);
const image = `registry.cloudflare.com/${account}/arcforges-cloud@sha256:9b90c26264806fda339cdcff44dcf987bccf702117b3cd3e81ed7248de9730f0`;

test("CTR06 audience binds the database, release, generation and provider", () => {
  const value = {
    environment: "production" as const,
    databaseHost: "ep-test.example.neon.tech",
    databasePort: 5432,
    databaseName: "center",
    clusterSystemIdentifier: "1234567890123456789",
    databaseOid: 123,
    ownerOid: 124,
    legacyRole: "center_runtime",
    legacyRoleOid: 125,
    bridgeRole: "center_ctr06",
    bridgeRoleOid: 126,
    bridgeLogin: "center_ctr06_a",
    bridgeLoginOid: 127,
    nonce: "a".repeat(64),
    workflowRevision: "b".repeat(40),
    cloudAccount: account,
    workerName: "arcforges-cloud",
    workerVersion: version,
    containerApplication: application,
    registryImage: image,
  };
  assert.equal(
    bridgeAudience(value),
    "urn:arcforges:ctr06:04a42f713b8e467ec3c4f3ee85325940393bc9e343bb5c0b4a8aaf25061bcd0b",
  );
  assert.notEqual(bridgeAudience({ ...value, nonce: "f".repeat(64) }), bridgeAudience(value));
  assert.notEqual(bridgeAudience({ ...value, databaseOid: 124 }), bridgeAudience(value));
  assert.notEqual(
    bridgeAudience({ ...value, clusterSystemIdentifier: "9876543210987654321" }),
    bridgeAudience(value),
  );
  assert.throws(() => bridgeAudience({ ...value, clusterSystemIdentifier: "" }));
  assert.notEqual(
    bridgeAudience({ ...value, workerVersion: "00000000-0000-4000-8000-000000000003" }),
    bridgeAudience(value),
  );
  assert.throws(() => bridgeAudience({ ...value, cloudAccount: "invalid" }));
});

test("CTR06 provider predicate requires exact version, secret binding, DO and completed image rollout", () => {
  const snapshot = {
    account,
    environment: "production" as const,
    workerVersionId: version,
    registryImage: image,
    deployment: { versions: [{ version_id: version, percentage: 100 }] },
    workerVersion: {
      id: version,
      resources: {
        bindings: [
          { name: "ARCFORGES_CENTER_DATABASE_URL", type: "secret_text" },
          {
            name: "CLOUD_CONTAINER",
            type: "durable_object_namespace",
            class_name: "CloudContainer",
            namespace_id: namespace,
          },
        ],
      },
    },
    application: {
      id: application,
      account_id: account,
      scheduling_policy: "default",
      durable_objects: { namespace_id: namespace },
      configuration: { image },
    },
    versions: [{ percentage: 100, configuration: { image } }],
    instances: [{ application_id: application, image, status: { state: "running" } }],
  };
  assert.deepEqual(verifyBridgeProviderSnapshot(snapshot), {
    applicationId: application,
    versionId: version,
    image,
  });
  const foreignImage = `registry.cloudflare.com/${account}/arcforges-cloud@sha256:${"f".repeat(64)}`;
  const otherBinding = snapshot.workerVersion.resources.bindings[1];
  assert.ok(otherBinding, "fixture must contain a non-container binding");
  const cases = [
    {
      ...snapshot,
      registryImage: foreignImage,
      application: { ...snapshot.application, configuration: { image: foreignImage } },
      versions: [{ percentage: 100, configuration: { image: foreignImage } }],
    },
    {
      ...snapshot,
      deployment: {
        versions: [
          { version_id: version, percentage: 99 },
          { version_id: "old", percentage: 1 },
        ],
      },
    },
    { ...snapshot, workerVersion: { id: "another", resources: snapshot.workerVersion.resources } },
    {
      ...snapshot,
      workerVersion: {
        id: version,
        resources: { bindings: [otherBinding] },
      },
    },
    {
      ...snapshot,
      application: { ...snapshot.application, durable_objects: { namespace_id: "f".repeat(32) } },
    },
    {
      ...snapshot,
      application: { ...snapshot.application, configuration: { image: "untrusted" } },
    },
    {
      ...snapshot,
      versions: [
        { percentage: 99, configuration: { image } },
        { percentage: 1, configuration: { image: "old" } },
      ],
    },
    {
      ...snapshot,
      instances: [{ application_id: application, image: "old", status: { state: "stopping" } }],
    },
    {
      ...snapshot,
      instances: [{ application_id: application, image, status: { state: "unknown" } }],
    },
  ];
  for (const bad of cases) assert.throws(() => verifyBridgeProviderSnapshot(bad));
});

test("CTR06 upload captures only one version ID from a sensitive child", async () => {
  const { runSensitive, proofProcessEnvironment } =
    await import("../../tooling/sensitive-process.ts");
  const env = proofProcessEnvironment(process.env);
  const output = await runSensitive(
    "upload",
    process.execPath,
    ["-e", `process.stdout.write('sensitive provider output\\nCurrent Version ID: ${version}\\n')`],
    env,
    "worker-version",
  );
  assert.equal(output, version);
  await assert.rejects(() =>
    runSensitive(
      "upload",
      process.execPath,
      [
        "-e",
        `process.stdout.write('Current Version ID: ${version}\\nCurrent Version ID: ${version}\\n')`,
      ],
      env,
      "worker-version",
    ),
  );
});

test("CTR06 live provider verification follows every cursor and rejects a late old instance", async () => {
  const { verifyLiveBridge } = await import("../../tooling/ctr06-bridge.ts");
  const deployment = { versions: [{ version_id: version, percentage: 100 }] };
  const worker = {
    id: version,
    resources: {
      bindings: [
        { name: "ARCFORGES_CENTER_DATABASE_URL", type: "secret_text" },
        {
          name: "CLOUD_CONTAINER",
          type: "durable_object_namespace",
          class_name: "CloudContainer",
          namespace_id: namespace,
        },
      ],
    },
  };
  const app = {
    id: application,
    account_id: account,
    scheduling_policy: "default",
    durable_objects: { namespace_id: namespace },
    configuration: { image },
  };
  let old = false;
  const requests: string[] = [];
  const get = async (path: string) => {
    requests.push(path);
    if (path.startsWith("/workers/scripts/")) return { success: true, result: worker };
    if (path.startsWith("/containers/applications?")) {
      if (!path.includes("page_token="))
        return { success: true, result: [], result_info: { next_page_token: "second" } };
      return { success: true, result: [app], result_info: {} };
    }
    if (path === `/containers/applications/${application}`) return { success: true, result: app };
    if (path === `/containers/applications/${application}/versions`)
      return { success: true, result: [{ percentage: 100, configuration: { image } }] };
    if (path.includes("/instances-v2?")) {
      if (!path.includes("page_token="))
        return { success: true, result: [], result_info: { next_page_token: "more" } };
      return {
        success: true,
        result: [
          { application_id: application, image: old ? "old" : image, status: { state: "running" } },
        ],
        result_info: {},
      };
    }
    throw new Error("unexpected provider route");
  };
  assert.deepEqual(await verifyLiveBridge(get, deployment, account, "production", version, image), {
    applicationId: application,
    versionId: version,
    image,
  });
  assert(requests.some((path) => path.includes("page_token=second")));
  assert(requests.some((path) => path.includes("page_token=more")));
  old = true;
  await assert.rejects(() =>
    verifyLiveBridge(get, deployment, account, "production", version, image),
  );
});

test("CTR06 bridge refuses a missing center runner before any provider work", async () => {
  await assert.rejects(
    () => promoteCTR06Bridge("production", "image", {}, undefined as unknown as CenterRunner),
    /sealed center runner is unavailable/u,
  );
});
