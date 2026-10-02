// SPDX-License-Identifier: AGPL-3.0-only
// Explicit local opt-in integration run: the real C# host process (point FOUNDATION_HOST_EXE at a
// Native AOT publish for the strongest evidence) against the real Worker modules running in workerd
// under Miniflare with LOCAL emulation of D1 (SQLite), R2, Durable Objects and Queues. It proves the
// cross-process protocol, plan, exact-value, guard, session, object and checkpoint/restart logic.
// It is NOT a Cloudflare provider result: no deployed D1, R2, Queue, Container or outbound-handler
// behavior is exercised. Never CI; it starts local processes and never reads credentials.
import assert from "node:assert/strict";
import { type ChildProcess, spawn } from "node:child_process";
import { createHash, randomBytes } from "node:crypto";
import { mkdir, readFile, writeFile } from "node:fs/promises";
import { createServer, type Server } from "node:http";
import net from "node:net";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { build } from "esbuild";
import { Miniflare, Response as MiniflareResponse, convertV4MiniflareOptions } from "miniflare";
import { manifestHash } from "../../worker/storage/plans.generated.ts";
import { runAll } from "./foundation-scenarios.ts";

const root = path.resolve(import.meta.dirname, "../..");
const hostPort = 8080;
const origin = "https://account.proof.arcforges.test";
const sleep = (ms: number) => new Promise((resolve) => setTimeout(resolve, ms));
const secret = () => randomBytes(32).toString("base64url");

function portFree(port: number): Promise<boolean> {
  return new Promise((resolve) => {
    const probe = net.connect(port, "127.0.0.1");
    probe.once("connect", () => {
      probe.destroy();
      resolve(false);
    });
    probe.once("error", () => resolve(true));
  });
}

function splitStatements(migration: string): string[] {
  return migration
    .split("\n")
    .filter((line) => !line.trimStart().startsWith("--"))
    .join("\n")
    .split(/;\s*\n/u)
    .map((statement) => statement.trim())
    .filter(Boolean);
}

async function waitForHealth(timeoutMs: number) {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    try {
      const response = await fetch(`http://127.0.0.1:${hostPort}/healthz`);
      if (response.ok) return;
    } catch {
      // still starting
    }
    await sleep(250);
  }
  throw new Error("The host did not become healthy.");
}

export async function main() {
  assert.notEqual(process.env.CI, "true", "The local integration run is opt-in, never CI.");
  const hostExe = process.env.FOUNDATION_HOST_EXE ?? "";
  assert(
    hostExe,
    "Set FOUNDATION_HOST_EXE to the host executable (a Native AOT publish is preferred).",
  );
  assert(await portFree(hostPort), `Port ${hostPort} is in use; the host listens on it.`);

  const outDirectory = path.join(root, "artifacts", "foundation-local");
  await mkdir(outDirectory, { recursive: true });
  const scriptPath = path.join(outDirectory, "worker.mjs");
  await build({
    entryPoints: [path.join(import.meta.dirname, "local-worker.ts")],
    outfile: scriptPath,
    bundle: true,
    format: "esm",
    target: "es2023",
    conditions: ["workerd", "worker", "browser"],
    external: ["cloudflare:workers"],
    logLevel: "error",
  });

  const keys = {
    c2w: secret(),
    w2c: secret(),
    csrf: secret(),
    operator: randomBytes(32).toString("base64url"),
  };
  let child: ChildProcess | undefined;
  let storageBase = "";
  let bridgeBase = "";
  let bridge: Server | undefined;
  const startHost = async () => {
    child = spawn(hostExe, [], {
      stdio: ["ignore", "ignore", "inherit"],
      windowsHide: true,
      env: {
        ...process.env,
        ARCFORGES_FOUNDATION_PROOF: "enabled",
        ARCFORGES_STORAGE_BASE_URL: bridgeBase,
        ARCFORGES_OBJECTS_BASE_URL: bridgeBase,
        AF_HMAC_C2W_KEY_ID: "c2w-1",
        AF_HMAC_C2W_SECRET: keys.c2w,
        AF_HMAC_W2C_KEY_ID: "w2c-1",
        AF_HMAC_W2C_SECRET: keys.w2c,
        AF_CSRF_SECRET: keys.csrf,
        AF_ALLOWED_ORIGIN: origin,
        AF_REALM_ID: "proof",
        AF_RECOVERY_GENERATION: "0",
      },
    });
    await waitForHealth(60_000);
  };
  const stopHost = async () => {
    const running = child;
    child = undefined;
    if (!running || running.exitCode !== null) return;
    running.kill();
    await new Promise((resolve) => running.once("exit", resolve));
  };
  let restarts = 0;
  const proxy = async (request: Request): Promise<Response> => {
    const url = new URL(request.url);
    if (url.pathname === "/__stop") {
      await stopHost();
      await startHost();
      restarts++;
      return new MiniflareResponse("restarted");
    }
    const body = ["GET", "HEAD"].includes(request.method)
      ? undefined
      : Buffer.from(await request.arrayBuffer());
    const reply = await fetch(`http://127.0.0.1:${hostPort}${url.pathname}${url.search}`, {
      method: request.method,
      headers: Object.fromEntries(request.headers),
      body,
      redirect: "manual",
    });
    return new MiniflareResponse(Buffer.from(await reply.arrayBuffer()), {
      status: reply.status,
      headers: Object.fromEntries(reply.headers),
    }) as unknown as Response;
  };

  const mf = new Miniflare(
    convertV4MiniflareOptions({
      modules: [{ type: "ESModule", path: scriptPath }],
      compatibilityDate: "2026-09-15",
      host: "127.0.0.1",
      port: 0,
      d1Databases: { DB: "proof-db" },
      r2Buckets: { OBJECTS: "proof-objects" },
      durableObjects: { JOB_COORDINATOR: "FoundationJobCoordinator" },
      queueProducers: { WAKE_QUEUE: "proof-wake" },
      queueConsumers: {
        "proof-wake": {
          maxBatchSize: 1,
          maxBatchTimeout: 1,
          maxRetries: 6,
          deadLetterQueue: "proof-wake-dlq",
        },
      },
      serviceBindings: { CONTAINER_SERVICE: proxy as never },
      bindings: {
        FOUNDATION_PROOF: "enabled",
        REALM_ID: "proof",
        RECOVERY_GENERATION: "0",
        ALLOWED_ORIGIN: origin,
        HMAC_C2W_KEY_ID: "c2w-1",
        HMAC_C2W_SECRET: keys.c2w,
        HMAC_W2C_KEY_ID: "w2c-1",
        HMAC_W2C_SECRET: keys.w2c,
        CSRF_SECRET: keys.csrf,
        PROOF_OPERATOR_TOKEN: keys.operator,
        SOURCE_REVISION: "local",
      },
    }),
  );
  try {
    const url = await mf.ready;
    storageBase = url.origin;
    // The host talks to the virtual hosts storage.internal and objects.internal in production; the
    // local bridge stands in for the outbound interception and only forwards those two route groups.
    bridge = createServer((incoming, outgoing) => {
      const target = incoming.url?.startsWith("/internal/storage/")
        ? `/__storage${incoming.url}`
        : incoming.url?.startsWith("/internal/objects/")
          ? `/__objects${incoming.url}`
          : undefined;
      if (!target) {
        outgoing.writeHead(404).end();
        return;
      }
      const chunks: Buffer[] = [];
      incoming.on("data", (chunk: Buffer) => chunks.push(chunk));
      incoming.on("end", async () => {
        try {
          const reply = await fetch(`${storageBase}${target}`, {
            method: incoming.method,
            headers: Object.fromEntries(
              Object.entries(incoming.headers).filter(([, value]) => typeof value === "string") as [
                string,
                string,
              ][],
            ),
            body: ["GET", "HEAD"].includes(incoming.method ?? "GET")
              ? undefined
              : Buffer.concat(chunks),
          });
          outgoing.writeHead(reply.status, Object.fromEntries(reply.headers));
          outgoing.end(Buffer.from(await reply.arrayBuffer()));
        } catch {
          outgoing.writeHead(502).end();
        }
      });
    });
    await new Promise<void>((resolve) => bridge?.listen(0, "127.0.0.1", resolve));
    bridgeBase = `http://127.0.0.1:${(bridge.address() as net.AddressInfo).port}`;
    const database = await mf.getD1Database("DB");
    const migration = await readFile(
      path.join(root, "worker/proof-migrations/0001_foundation_probe.sql"),
      "utf8",
    );
    await database.batch(
      splitStatements(migration).map((statement) => database.prepare(statement)),
    );
    await startHost();
    // Same-origin local access only; an unreachable host would fail the first scenario.
    const startedAt = new Date().toISOString();
    const evidence = await runAll(
      {
        baseUrl: storageBase,
        operatorToken: keys.operator,
        origin,
        pollIntervalMs: 500,
        jobTimeoutMs: 120_000,
      },
      manifestHash,
      { stopContainer: true },
    );
    const exe = await readFile(hostExe);
    const miniflareVersion = JSON.parse(
      await readFile(path.join(root, "node_modules/miniflare/package.json"), "utf8"),
    ) as { version: string };
    const report = {
      startedAt,
      finishedAt: new Date().toISOString(),
      kind: "local-emulation",
      emulated: "D1 (workerd SQLite), R2, Durable Object, Queue",
      notEmulated:
        "Cloudflare provider network path, Container, outbound handler interception, real D1/R2 limits",
      node: process.version,
      miniflare: miniflareVersion.version,
      platform: `${process.platform}-${process.arch}`,
      host: {
        kind: process.env.FOUNDATION_HOST_KIND ?? "unspecified",
        sha256: createHash("sha256").update(exe).digest("hex"),
        restarts,
      },
      manifestHash,
      evidence,
    };
    await writeFile(
      path.join(outDirectory, "foundation-local-evidence.json"),
      `${JSON.stringify(report, null, 2)}\n`,
    );
    console.log(
      `Local integration passed: ${evidence.map((item) => item.scenario).join(", ")} (host restarts: ${restarts})`,
    );
  } finally {
    await stopHost();
    bridge?.close();
    await mf.dispose();
  }
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url))
  await main();
