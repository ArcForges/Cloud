// SPDX-License-Identifier: AGPL-3.0-only
// One protected schema-10 bridge handoff. Owner-only provider credentials are
// used solely by this process; the private URL and OIDC token never become an artifact.
import assert from "node:assert/strict";
import { constants as fsConstants } from "node:fs";
import { copyFile, mkdir, mkdtemp, readFile, rmdir, unlink, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { buildProofConfig, type CandidateConfig } from "../eng/verification/proof-deploy.ts";
import { isProofCommandKeyBinding } from "../worker/foundation/proof-command-key.ts";
import {
  bridgeAudience,
  bridgeImageId,
  cloudflareReader,
  verifyBridgeCarrier,
  verifyLiveBridge,
  type BridgeContext,
} from "./ctr06-bridge.ts";
import { neonRuntimeSecret, withNeonRuntimeSecret } from "./neon-runtime.ts";
import { center, type PostgresTarget } from "./postgres-deploy.ts";
import { root, wrangler } from "./process.ts";
import { proofProcessEnvironment, runSensitive } from "./sensitive-process.ts";

const bridgeDirectory = path.join(root, "artifacts", "ctr06-bridge");
const bridgeConfig = path.join(root, "artifacts", "ctr06-bridge.wrangler.json");
const releaseFile = "cloud-0.1.0-ci.615.1.tar.gz";
const members = [
  "manifest.json",
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

function ciContext(target: PostgresTarget): string {
  assert.equal(process.env.GITHUB_ACTIONS, "true");
  assert.equal(process.env.GITHUB_REPOSITORY, "ArcForges/Cloud");
  assert.equal(process.env.GITHUB_REF, "refs/heads/main");
  assert.equal(
    process.env.GITHUB_EVENT_NAME,
    target === "production" ? "push" : "workflow_dispatch",
  );
  const revision = process.env.GITHUB_SHA ?? "";
  assert.match(revision, /^[a-f0-9]{40}$/u);
  return revision;
}

async function requireMain(revision: string): Promise<void> {
  const result = (await runSensitive(
    "head",
    "gh",
    ["api", "repos/ArcForges/Cloud/git/ref/heads/main"],
    proofProcessEnvironment(process.env, ["GH_TOKEN"]),
    "json",
  )) as { object?: { sha?: unknown } };
  assert.equal(result.object?.sha, revision, "a newer main exists");
}

async function oidc(audience: string): Promise<string> {
  const request = process.env.ACTIONS_ID_TOKEN_REQUEST_URL ?? "";
  const credential = process.env.ACTIONS_ID_TOKEN_REQUEST_TOKEN ?? "";
  let url: URL;
  try {
    url = new URL(request);
  } catch {
    throw new Error("protected OIDC transport is unavailable");
  }
  assert(
    url.protocol === "https:" &&
      url.hostname.endsWith(".actions.githubusercontent.com") &&
      credential.length > 0,
  );
  url.searchParams.set("audience", audience);
  try {
    const response = await fetch(url, {
      headers: { Authorization: `Bearer ${credential}` },
      redirect: "error",
      signal: AbortSignal.timeout(15_000),
    });
    if (!response.ok) throw new Error("OIDC refused");
    const body = await response.text();
    if (body.length > 65536) throw new Error("OIDC response too large");
    const value = (JSON.parse(body) as { value?: unknown }).value;
    if (typeof value !== "string" || value.length > 32768)
      throw new Error("OIDC token unavailable");
    return value;
  } catch {
    throw new Error("The protected bridge OIDC proof could not be issued.");
  }
}

async function proofMetadata(
  get: ReturnType<typeof cloudflareReader>,
): Promise<{ databaseId: string; keyBinding: string }> {
  const d1 = await get("/d1/database?name=arcforges-proof-business&per_page=100");
  assert(d1.success === true && Array.isArray(d1.result));
  const databases = (d1.result as { name?: unknown; uuid?: unknown }[]).filter(
    (x) => x.name === "arcforges-proof-business",
  );
  assert.equal(databases.length, 1);
  const databaseId = String(databases[0]?.uuid ?? "");
  assert.match(databaseId, /^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$/u);
  const settings = await get("/workers/scripts/arcforges-cloud-proof/settings");
  const bindings = (
    settings.result as
      { bindings?: { name?: unknown; type?: unknown; text?: unknown }[] } | undefined
  )?.bindings;
  assert(settings.success === true && Array.isArray(bindings));
  const named = bindings.filter(
    (x) => x.name === "ARCFORGES_CENTER_PROOF_COMMAND_KEY_BINDING" && x.type === "plain_text",
  );
  assert.equal(named.length, 1);
  const keyBinding = named[0]?.text;
  assert(isProofCommandKeyBinding(keyBinding));
  assert.equal(bindings.filter((x) => x.name === keyBinding && x.type === "secret_text").length, 1);
  return { databaseId, keyBinding };
}

function privateUser(): string | undefined {
  return typeof process.getuid === "function" && typeof process.getgid === "function"
    ? `${process.getuid()}:${process.getgid()}`
    : undefined;
}

type Prepared = {
  databaseName: string;
  clusterSystemIdentifier: string;
  databaseOid: number;
  ownerOid: number;
  legacyRole: string;
  legacyRoleOid: number;
  bridgeRole: string;
  bridgeRoleOid: number;
  bridgeLogin: string;
  bridgeLoginOid: number;
  nonce: string;
  probe?: {
    connectsUnpooled?: boolean;
    connectedAsLoginRole?: boolean;
    cannotCreateTables?: boolean;
    cannotReadUngrantedTables?: boolean;
  };
};

/** Reuse a release carrier downloaded by the same guarded build when present.
 * The carrier is still verified by its pinned digest before any use.
 */
export async function copyStagedBridgeCarrier(
  staged: string,
  destination: string,
): Promise<boolean> {
  try {
    await copyFile(staged, destination, fsConstants.COPYFILE_EXCL);
    return true;
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === "ENOENT") return false;
    throw error;
  }
}

export async function withOwnedCleanup<T>(
  work: () => Promise<T>,
  cleanup: () => Promise<void>,
): Promise<T> {
  let result: T;
  try {
    result = await work();
  } catch (error) {
    try {
      await cleanup();
    } catch (cleanupError) {
      throw new AggregateError(
        [error, cleanupError],
        "Bridge promotion and owned cleanup both failed.",
      );
    }
    throw error;
  }
  await cleanup();
  return result;
}

/** The caller must already have verified and loaded the exact current candidate image. */
export async function promoteCTR06Bridge(
  target: PostgresTarget,
  candidateImage: string,
  variables: Record<string, string>,
): Promise<Record<string, unknown>> {
  const revision = ciContext(target);
  const account = process.env.CLOUDFLARE_ACCOUNT_ID ?? "";
  const apiToken = process.env.CLOUDFLARE_API_TOKEN ?? "";
  const get = cloudflareReader(account, apiToken);
  const providerEnv = proofProcessEnvironment(process.env, [
    "CLOUDFLARE_ACCOUNT_ID",
    "CLOUDFLARE_API_TOKEN",
  ]);
  providerEnv.NO_COLOR = "1";
  await requireMain(revision);
  const temp = await mkdtemp(path.join(os.tmpdir(), "arcforges-ctr06-bridge-"));
  let bridgeCreated = false,
    configCreated = false;
  return await withOwnedCleanup(
    async () => {
      // The durable carrier is pinned before parsing; extraction accepts only
      // bounded regular files and checks the OCI manifest, config and all layers.
      const carrier = path.join(temp, releaseFile);
      const staged = path.join(root, "artifacts", "ctr06-linux", releaseFile);
      if (!(await copyStagedBridgeCarrier(staged, carrier))) {
        await runSensitive(
          "candidate",
          "gh",
          [
            "release",
            "download",
            "cloud-0.1.0-ci.615.1",
            "--repo",
            "ArcForges/Cloud",
            "--pattern",
            releaseFile,
            "--dir",
            temp,
          ],
          proofProcessEnvironment(process.env, ["GH_TOKEN"]),
          "discard",
          { deadlineMs: 300_000 },
        );
      }
      await mkdir(bridgeDirectory, { mode: 0o700 });
      bridgeCreated = true;
      await runSensitive(
        "candidate",
        "python3",
        [
          path.join(root, "tooling", "ctr06_bridge_carrier.py"),
          path.join(temp, releaseFile),
          bridgeDirectory,
        ],
        proofProcessEnvironment(process.env),
        "discard",
        { deadlineMs: 300_000 },
      );
      const bridge = await verifyBridgeCarrier(bridgeDirectory);
      await runSensitive(
        "image",
        "docker",
        ["load", "--input", path.join(bridgeDirectory, "docker-image.tar")],
        proofProcessEnvironment(process.env),
        "discard",
        { deadlineMs: 300_000 },
      );
      const loaded = await runSensitive(
        "image",
        "docker",
        ["image", "inspect", bridge.image, "--format", "{{json .Id}}"],
        proofProcessEnvironment(process.env),
        "json",
      );
      assert.equal(loaded, bridgeImageId, "loaded bridge manifest differs");
      await runSensitive(
        "push",
        process.execPath,
        [wrangler, "containers", "push", bridge.image],
        providerEnv,
        "discard",
        { deadlineMs: 300_000 },
      );
      const registryTag = `registry.cloudflare.com/${account}/${bridge.image}`;
      const digests = await runSensitive(
        "image",
        "docker",
        ["image", "inspect", registryTag, "--format", "{{json .RepoDigests}}"],
        proofProcessEnvironment(process.env),
        "json",
      );
      const registryImage = `registry.cloudflare.com/${account}/arcforges-cloud@${bridgeImageId}`;
      assert(
        Array.isArray(digests) && digests.includes(registryImage),
        "provider registry manifest differs from the verified bridge",
      );

      const prepared = (await center(
        candidateImage,
        { ...variables, ARCFORGES_CENTER_RUNTIME_SECRET_FILE: "/secrets/runtime.json" },
        ["admin", "prepare-ctr06-bridge"],
        { secretsDirectory: temp, user: privateUser() },
      )) as Prepared;
      assert(
        prepared.probe?.connectsUnpooled === true &&
          prepared.probe?.connectedAsLoginRole === true &&
          prepared.probe?.cannotCreateTables === true &&
          prepared.probe?.cannotReadUngrantedTables === true,
      );
      const runtime = JSON.parse(await readFile(path.join(temp, "runtime.json"), "utf8")) as Record<
        string,
        string
      >;
      assert.deepEqual(Object.keys(runtime), ["ARCFORGES_CENTER_DATABASE_URL"]);
      assert(
        typeof runtime.ARCFORGES_CENTER_DATABASE_URL === "string" &&
          runtime.ARCFORGES_CENTER_DATABASE_URL.length > 0,
      );

      const base = JSON.parse(
        await readFile(path.join(bridgeDirectory, "wrangler.json"), "utf8"),
      ) as CandidateConfig & {
        vars: Record<string, string>;
        containers: { image: string }[];
        account_id?: string;
        no_bundle?: boolean;
      };
      let config: CandidateConfig;
      if (target === "acceptance") {
        const metadata = await proofMetadata(get);
        config = buildProofConfig(base, {
          account,
          imageDigest: registryImage,
          revision: "8e5f6e26aa97b123d9f60b91f780364a094e74cd",
          databaseId: metadata.databaseId,
          main: "./ctr06-bridge/proof-worker.js",
          buildIdentity: base.vars.BUILD_IDENTITY,
          migrationsDir: "../worker/proof-migrations",
          proofCommandKeyBinding: metadata.keyBinding,
        });
      } else {
        base.main = "./ctr06-bridge/worker.js";
        base.account_id = account;
        const container = base.containers[0];
        assert(container, "bridge configuration lacks a container");
        container.image = registryImage;
        config = base;
      }
      await writeFile(bridgeConfig, JSON.stringify(config), { mode: 0o600, flag: "wx" });
      configCreated = true;
      const configArgs = [
        "--config",
        bridgeConfig,
        "--env",
        target === "production" ? "" : "proof",
      ];
      const neon =
        target === "production"
          ? neonRuntimeSecret(base.vars.ARCFORGES_NEON_HELLO, process.env)
          : undefined;
      await requireMain(revision);
      let uploadId: unknown;
      await withNeonRuntimeSecret({ ...neon, ...runtime }, async (secretArgs) => {
        uploadId = await runSensitive(
          "upload",
          process.execPath,
          [
            wrangler,
            "deploy",
            ...configArgs,
            "--no-bundle",
            "--containers-rollout",
            "immediate",
            "--tag",
            target === "production" ? bridge.version : `${bridge.version}-acceptance`,
            "--message",
            "runtime-slot=a ctr06-bridge",
            ...secretArgs,
          ],
          providerEnv,
          "worker-version",
          { deadlineMs: 300_000 },
        );
      });
      assert(typeof uploadId === "string");
      // Deployment completion is not rollout completion. Read the actual live
      // version, namespace, image and every cursor page before attesting.
      const deadline = Date.now() + 240_000;
      let provider: { applicationId: string; versionId: string; image: string } | undefined;
      do {
        try {
          const status = (await runSensitive(
            "provider",
            process.execPath,
            [wrangler, "deployments", "status", "--json", ...configArgs],
            providerEnv,
            "json",
          )) as { versions?: { version_id?: unknown; percentage?: unknown }[] };
          provider = await verifyLiveBridge(get, status, account, target, uploadId, registryImage);
        } catch {
          if (Date.now() >= deadline)
            throw new Error("The provider did not establish the complete bridge rollout.");
          await new Promise((resolve) => setTimeout(resolve, 3000));
        }
      } while (provider === undefined);
      await requireMain(revision);
      let direct: URL;
      try {
        direct = new URL(variables.ARCFORGES_CENTER_MIGRATION_DATABASE_URL ?? "");
      } catch {
        throw new Error("The direct database endpoint is invalid.");
      }
      assert.equal(
        prepared.legacyRole,
        variables.ARCFORGES_CENTER_RUNTIME_ROLE,
        "the legacy group changed during preparation",
      );
      const expectedDatabase = variables.ARCFORGES_CENTER_DATABASE_NAME ?? direct.pathname.slice(1);
      assert.equal(
        prepared.databaseName,
        expectedDatabase,
        "the prepared database differs from the target",
      );
      const context: BridgeContext = {
        environment: target,
        databaseHost: direct.hostname.toLowerCase(),
        databasePort: Number(direct.port || "5432"),
        databaseName: prepared.databaseName,
        clusterSystemIdentifier: prepared.clusterSystemIdentifier,
        databaseOid: prepared.databaseOid,
        ownerOid: prepared.ownerOid,
        legacyRole: prepared.legacyRole,
        legacyRoleOid: prepared.legacyRoleOid,
        bridgeRole: prepared.bridgeRole,
        bridgeRoleOid: prepared.bridgeRoleOid,
        bridgeLogin: prepared.bridgeLogin,
        bridgeLoginOid: prepared.bridgeLoginOid,
        nonce: prepared.nonce,
        workflowRevision: revision,
        cloudAccount: account,
        workerName: target === "production" ? "arcforges-cloud" : "arcforges-cloud-proof",
        workerVersion: provider.versionId,
        containerApplication: provider.applicationId,
        registryImage: provider.image,
      };
      const token = await oidc(bridgeAudience(context));
      await writeFile(path.join(temp, "proof.json"), JSON.stringify({ context, token }), {
        mode: 0o600,
        flag: "wx",
      });
      return await center(
        candidateImage,
        {
          ...variables,
          ARCFORGES_CENTER_RUNTIME_ROLE: prepared.bridgeRole,
          ARCFORGES_CENTER_CTR06_PROOF_FILE: "/secrets/proof.json",
        },
        ["migrate"],
        { secretsDirectory: temp, user: privateUser() },
      );
    },
    async () => {
      // Only paths created by this call are removed; an unexpected entry causes
      // rmdir to fail rather than recursively deleting somebody else's work.
      for (const name of ["proof.json", "runtime.json", releaseFile]) {
        try {
          await unlink(path.join(temp, name));
        } catch (error) {
          if ((error as NodeJS.ErrnoException).code !== "ENOENT") throw error;
        }
      }
      await rmdir(temp);
      if (configCreated) await unlink(bridgeConfig);
      if (bridgeCreated) {
        for (const member of members) {
          try {
            await unlink(path.join(bridgeDirectory, member));
          } catch (error) {
            if ((error as NodeJS.ErrnoException).code !== "ENOENT") throw error;
          }
        }
        await rmdir(bridgeDirectory);
      }
    },
  );
}
