// SPDX-License-Identifier: AGPL-3.0-only
// This phase-1 negative requires the isolated-driver configuration and proves
// the actual publisher stops before the driver or owner-only provider transports.
// The pre-phase-1 real Go/PG/crypto integration remains in the fixed historical
// source fixture. This refusal is not upgrade or rollback acceptance.
// Run `npm run test:ctr06:publisher:driver` with its isolated fixture variables;
// missing configuration refuses instead of silently skipping.
import assert from "node:assert/strict";
import { copyFile, mkdir, rmdir, unlink } from "node:fs/promises";
import path from "node:path";
import { mock, test } from "node:test";
import type { CenterRunner } from "../../tooling/postgres-deploy.ts";

test(
  "phase 1 publisher refuses before the isolated driver or provider can be called",
  {},
  async () => {
    const driver = process.env.CTR06_TEST_DRIVER_URL;
    const authorization = process.env.CTR06_TEST_DRIVER_TOKEN;
    const archive = process.env.CTR06_TEST_BRIDGE_ARCHIVE;
    const database = process.env.CTR06_TEST_DATABASE_URL;
    const legacyRole = process.env.CTR06_TEST_LEGACY_ROLE;
    assert(
      driver && authorization && archive && database && legacyRole,
      "requires the isolated PostgreSQL Go test driver; see this test's invocation comment",
    );
    const stageCarrier = process.env.CTR06_TEST_STAGE_CARRIER === "1";
    const stagedDirectory = path.resolve("artifacts", "ctr06-linux");
    const stagedCarrier = path.join(stagedDirectory, "cloud-0.1.0-ci.615.1.tar.gz");
    let stagedDirectoryCreated = false;
    let stagedFileCreated = false;
    const revision = "b".repeat(40);
    const account = "c".repeat(32);
    const namespace = "e".repeat(32);
    const version = "00000000-0000-4000-8000-000000000001";
    const application = "00000000-0000-4000-8000-000000000002";
    const image = `registry.cloudflare.com/${account}/arcforges-cloud@sha256:9b90c26264806fda339cdcff44dcf987bccf702117b3cd3e81ed7248de9730f0`;
    const originalFetch = globalThis.fetch;
    let rpcCalls = 0;
    let fetchCalls = 0;
    const rpc = async (endpoint: string, value: unknown) => {
      rpcCalls++;
      const response = await originalFetch(driver + endpoint, {
        method: "POST",
        headers: { "Content-Type": "application/json", Authorization: `Bearer ${authorization}` },
        body: JSON.stringify(value),
      });
      if (!response.ok) throw new Error(`test driver ${endpoint} refused`);
      return (await response.json()) as Record<string, unknown>;
    };
    const realBridge = await import("../../tooling/ctr06-bridge.ts");
    const realSensitive = await import("../../tooling/sensitive-process.ts");
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
    const provider = async (path: string) => {
      if (path.startsWith("/workers/scripts/")) return { success: true, result: worker };
      if (path.startsWith("/containers/applications?"))
        return { success: true, result: [app], result_info: {} };
      if (path === `/containers/applications/${application}`) return { success: true, result: app };
      if (path.endsWith("/versions"))
        return { success: true, result: [{ percentage: 100, configuration: { image } }] };
      if (path.includes("/instances-v2?"))
        return {
          success: true,
          result: [{ application_id: application, image, status: { state: "running" } }],
          result_info: {},
        };
      throw new Error("unexpected mocked provider transport path");
    };
    mock.module("../../tooling/ctr06-bridge.ts", {
      namedExports: { ...realBridge, cloudflareReader: () => provider },
    });
    const center: CenterRunner = async (candidateImage, variables, command, options) =>
      await rpc("/center", {
        candidateImage,
        variables,
        command,
        directory: options?.secretsDirectory,
      });
    mock.module("../../tooling/sensitive-process.ts", {
      namedExports: {
        ...realSensitive,
        runSensitive: async (...args: Parameters<typeof realSensitive.runSensitive>) => {
          const [stage, command, argv] = args;
          if (command === "gh" && argv[0] === "api") return { object: { sha: revision } };
          if (command === "gh" && argv[0] === "release") {
            assert.equal(stageCarrier, false, "staged carrier should not trigger another download");
            const directory = argv[argv.indexOf("--dir") + 1];
            assert(typeof directory === "string");
            await copyFile(archive, `${directory}/cloud-0.1.0-ci.615.1.tar.gz`, 1);
            return undefined;
          }
          if (
            command === "docker" &&
            argv[0] === "image" &&
            String(argv[2]).startsWith("registry.cloudflare.com/")
          )
            return [image];
          if (command === process.execPath && argv.includes("containers") && argv.includes("push"))
            return undefined;
          if (
            command === process.execPath &&
            argv.includes("deploy") &&
            !argv.includes("deployments")
          ) {
            const file = argv[argv.indexOf("--secrets-file") + 1];
            assert(typeof file === "string");
            await rpc("/start-bridge", { secretFile: file });
            return version;
          }
          if (command === process.execPath && argv.includes("deployments"))
            return { versions: [{ version_id: version, percentage: 100 }] };
          return await realSensitive.runSensitive(stage, command, argv, args[3], args[4], args[5]);
        },
      },
    });
    globalThis.fetch = (async (input, init) => {
      fetchCalls++;
      const url = new URL(String(input));
      if (url.hostname === "pipelines.actions.githubusercontent.com") {
        const issued = await rpc("/oidc", { audience: url.searchParams.get("audience") });
        return new Response(JSON.stringify({ value: issued.token }), {
          status: 200,
          headers: { "content-type": "application/json" },
        });
      }
      return originalFetch(input, init);
    }) as typeof fetch;
    try {
      if (stageCarrier) {
        // Exclusive creation ensures this test never adopts or removes an
        // artifact belonging to another run.
        await mkdir(stagedDirectory, { mode: 0o700 });
        stagedDirectoryCreated = true;
        await copyFile(archive, stagedCarrier, 1);
        stagedFileCreated = true;
      }
      process.env.GITHUB_ACTIONS = "true";
      process.env.GITHUB_REPOSITORY = "ArcForges/Cloud";
      process.env.GITHUB_REF = "refs/heads/main";
      process.env.GITHUB_EVENT_NAME = "push";
      process.env.GITHUB_SHA = revision;
      process.env.CLOUDFLARE_ACCOUNT_ID = account;
      process.env.CLOUDFLARE_API_TOKEN = "synthetic-provider-credential";
      process.env.GH_TOKEN = "synthetic-github-credential";
      process.env.ACTIONS_ID_TOKEN_REQUEST_URL =
        "https://pipelines.actions.githubusercontent.com/test";
      process.env.ACTIONS_ID_TOKEN_REQUEST_TOKEN = "synthetic-oidc-credential";
      process.env.NEON_DATABASE_URL =
        "postgres://test:synthetic@ep-test-pooler.region.neon.tech/db?sslmode=require&channel_binding=require";
      const { promoteCTR06Bridge } = await import("../../tooling/ctr06-publisher.ts");
      await assert.rejects(
        () =>
          promoteCTR06Bridge(
            "production",
            "source-candidate",
            {
              ARCFORGES_CENTER_MODE: "self-hosted",
              ARCFORGES_CENTER_MIGRATION_DATABASE_URL: database,
              ARCFORGES_CENTER_RUNTIME_ROLE: legacyRole,
            },
            center,
          ),
        /security bridge successor is not yet bound/u,
      );
      assert.equal(rpcCalls, 0);
      assert.equal(fetchCalls, 0);
    } finally {
      if (stagedFileCreated) await unlink(stagedCarrier);
      if (stagedDirectoryCreated) await rmdir(stagedDirectory);
      globalThis.fetch = originalFetch;
      mock.restoreAll();
    }
  },
);
