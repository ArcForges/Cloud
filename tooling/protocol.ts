// SPDX-License-Identifier: AGPL-3.0-only
import assert from "node:assert/strict";
import path from "node:path";
import { setTimeout as delay } from "node:timers/promises";
import { createHelloClient } from "@arcforges/api-client";
import { Code, ConnectError } from "@connectrpc/connect";
import { readJson, root } from "./process.ts";

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
    // Exercise real router normalization using the published serializer, not handmade protobuf.
    for (const contentType of [
      "application/grpc-web",
      "Application/GRPC-Web+Proto; charset=utf-8",
    ]) {
      const normalized = createHelloClient({
        baseUrl,
        useBinaryFormat: true,
        fetch: (input, init) => {
          const headers = new Headers(init?.headers);
          headers.set("content-type", contentType);
          return fetch(input, { ...init, headers, redirect: "error" });
        },
      });
      assert.equal(
        (await normalized.sayHello({ name: "Content-Type" }, { timeoutMs: 5000 })).message,
        "Hello, Content-Type!",
      );
    }
    for (const [deadline, code] of [
      ["0m", Code.DeadlineExceeded],
      ["invalid", Code.InvalidArgument],
    ] as const) {
      const expired = createHelloClient({
        baseUrl,
        useBinaryFormat: true,
        fetch: (input, init) => {
          const headers = new Headers(init?.headers);
          headers.set("grpc-timeout", deadline);
          return fetch(input, { ...init, headers, redirect: "error" });
        },
      });
      await assert.rejects(
        expired.sayHello({ name: "Deadline" }, { timeoutMs: 5000 }),
        (error: unknown) => error instanceof ConnectError && error.code === code,
      );
    }
    for (const [endpoint, method, expected] of [
      ["/unknown", "GET", 404],
      ["/api/arcforges.hello.v1.HelloService/SayHello", "POST", 404],
      ["/arcforges.hello.v1.HelloService/SayHello", "GET", 405],
    ] as const) {
      const response = await fetch(baseUrl + endpoint, {
        method,
        redirect: "error",
        signal: AbortSignal.timeout(10000),
      });
      assert.equal(response.status, expected);
      await response.arrayBuffer();
    }
    const unsupported = await fetch(`${baseUrl}/arcforges.hello.v1.HelloService/SayHello`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: "{}",
      signal: AbortSignal.timeout(10000),
      redirect: "error",
    });
    assert.equal(unsupported.status, 415);
    await unsupported.arrayBuffer();
    const oversized = await fetch(`${baseUrl}/arcforges.hello.v1.HelloService/SayHello`, {
      method: "POST",
      headers: { "content-type": "application/grpc-web+proto" },
      body: new Uint8Array(4097),
      signal: AbortSignal.timeout(10000),
      redirect: "error",
    });
    assert.equal(oversized.status, 413);
    await oversized.arrayBuffer();
  }
  return {
    transport: "binary gRPC-Web",
    publishedClient: (
      await readJson<{ version: string }>(
        path.join(root, "node_modules/@arcforges/api-client/package.json"),
      )
    ).version,
    greeting: true,
    unicode: true,
    invalidArgument: true,
    resourceExhausted: true,
    workerBoundary: worker,
  };
}
