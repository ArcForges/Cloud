// SPDX-License-Identifier: AGPL-3.0-only
import assert from "node:assert/strict";
import { setTimeout as delay } from "node:timers/promises";
import { createHelloClient } from "@arcforges/api-client";
import { Code, ConnectError } from "@connectrpc/connect";

export async function waitForHealth(
  baseUrl: string,
  revision: string,
  worker: boolean,
  timeoutMs: number,
) {
  const deadline = Date.now() + timeoutMs;
  let last = "no response";
  while (Date.now() < deadline) {
    try {
      const response = await fetch(`${baseUrl}/healthz`, {
        signal: AbortSignal.timeout(20000),
        redirect: "error",
        cache: "no-store",
      });
      last = `HTTP ${response.status}`;
      if (response.ok) {
        const health = (await response.json()) as {
          service: string;
          revision: string;
          nativeAot: boolean;
        };
        last = JSON.stringify(health);
        if (
          health.service === "arcforges-cloud" &&
          health.revision === revision &&
          health.nativeAot === true &&
          (!worker || response.headers.get("x-arcforges-worker-revision") === revision)
        ) {
          return health;
        }
      }
    } catch (error) {
      last = error instanceof Error ? error.message : String(error);
    }
    console.log(`Waiting for the Native AOT container revision ${revision}: ${last}`);
    await delay(5000);
  }
  throw new Error(`Container readiness did not converge within ${timeoutMs / 1000}s: ${last}`);
}

export async function verifyProtocol(baseUrl: string, worker: boolean) {
  const client = createHelloClient({
    baseUrl,
    useBinaryFormat: true,
    fetch: (input, init) => fetch(input, { ...init, credentials: "omit", redirect: "error" }),
  });
  for (const name of ["ArcForges", "世界 👋"]) {
    const response = await client.sayHello({ name }, { timeoutMs: 20000 });
    assert.equal(response.message, `Hello, ${name}!`);
  }
  await assert.rejects(
    client.sayHello({ name: "" }, { timeoutMs: 20000 }),
    (error: unknown) => error instanceof ConnectError && error.code === Code.InvalidArgument,
  );
  await assert.rejects(
    client.sayHello({ name: "x".repeat(257) }, { timeoutMs: 20000 }),
    (error: unknown) => error instanceof ConnectError && error.code === Code.ResourceExhausted,
  );

  if (worker) {
    for (const [endpoint, method, expected] of [
      ["/unknown", "GET", 404],
      ["/arcforges.hello.v1.HelloService/SayHello", "GET", 405],
    ] as const) {
      const response = await fetch(baseUrl + endpoint, {
        method,
        redirect: "error",
        signal: AbortSignal.timeout(10000),
      });
      assert.equal(response.status, expected);
      await response.body?.cancel();
    }
    const unsupported = await fetch(`${baseUrl}/arcforges.hello.v1.HelloService/SayHello`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: "{}",
      signal: AbortSignal.timeout(10000),
      redirect: "error",
    });
    assert.equal(unsupported.status, 415);
    await unsupported.body?.cancel();
    const oversized = await fetch(`${baseUrl}/arcforges.hello.v1.HelloService/SayHello`, {
      method: "POST",
      headers: { "content-type": "application/grpc-web+proto" },
      body: new Uint8Array(4097),
      signal: AbortSignal.timeout(10000),
      redirect: "error",
    });
    assert.equal(oversized.status, 413);
    await oversized.body?.cancel();
  }
  return {
    transport: "binary gRPC-Web",
    publishedClient: "1.0.0-ci.25.1",
    greeting: true,
    unicode: true,
    invalidArgument: true,
    resourceExhausted: true,
    workerBoundary: worker,
  };
}
