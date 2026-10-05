// SPDX-License-Identifier: AGPL-3.0-only
// The plan bridge is private: the public entry never reaches it, whatever a caller signs or claims, and the
// handler accepts only the Container's own direction of the private signature.
import assert from "node:assert/strict";
import test from "node:test";
import { serializeExecutePlanRequestJson } from "@arcforges/ai-internal";
import { fetchEntry, type WorkerEnv } from "../../worker/foundation/entry.ts";
import type { FoundationEnv } from "../../worker/foundation/types.ts";
import { base64UrlEncode, sha256Hex } from "../../worker/private/encoding.ts";
import { newNonce, sign } from "../../worker/private/signing.ts";
import type { D1Like } from "../../worker/storage/d1.ts";
import {
  executePlanPath,
  handleExecutePlan,
  type StorageEnv,
} from "../../worker/storage/handler.ts";
import { createSqliteD1 } from "./support/sqlite-d1.ts";
import { fixedNow, planRequest } from "./support/plan-calls.ts";

const c2w = new Uint8Array(32).fill(5);
const w2c = new Uint8Array(32).fill(2);
const call = planRequest("foundation.readiness", [[]]);
const body = () => serializeExecutePlanRequestJson(call);

/** A D1 that records every use: a refused request must leave it untouched. */
function spyDatabase() {
  const real = createSqliteD1();
  const calls: string[] = [];
  const db: D1Like = {
    prepare(sql) {
      calls.push(sql);
      return real.prepare(sql);
    },
    batch(statements) {
      calls.push("batch");
      return real.batch(statements);
    },
  };
  return { db, calls };
}
async function signedFor(
  url: string,
  key: { id: string; secret: Uint8Array },
  payload = body(),
  method = "POST",
) {
  const target = new URL(url);
  const headers = await sign(
    {
      method,
      pathAndQuery: target.pathname + target.search,
      bodySha256Hex: await sha256Hex(payload),
      requestId: call.requestId,
      time: String(Math.floor(fixedNow / 1000)),
      nonce: newNonce(),
    },
    key,
  );
  return new Request(target, {
    method,
    headers: { "content-type": "application/json", ...headers },
    body: payload as BodyInit,
  });
}
const environment = (db: D1Like, proof: boolean): WorkerEnv & Partial<FoundationEnv> =>
  ({
    SOURCE_REVISION: "0".repeat(40),
    ...(proof ? { FOUNDATION_PROOF: "enabled" } : {}),
    DB: db,
    RECOVERY_GENERATION: "0",
    HMAC_C2W_KEY_ID: "c2w-1",
    HMAC_C2W_SECRET: base64UrlEncode(c2w),
    HMAC_W2C_KEY_ID: "w2c-1",
    HMAC_W2C_SECRET: base64UrlEncode(w2c),
    CLOUD_CONTAINER: {
      getByName: () => ({
        fetch: () => {
          throw new Error("the Container must not be reached");
        },
      }),
    },
    HELLO_RATE_LIMITER: { limit: () => Promise.resolve({ success: true }) },
  }) as unknown as WorkerEnv & Partial<FoundationEnv>;

test("a correctly signed plan request is refused on every public path and runs no SQL", async () => {
  const targets = [
    `https://proof.arcforges.com${executePlanPath}`,
    `https://arcforges.com${executePlanPath}`,
    `https://arcforges.com/api${executePlanPath}`,
    `https://arcforges.com/api/internal/storage/v1/execute-plan`,
    `https://storage.internal${executePlanPath}`,
    `http://storage.internal${executePlanPath}`,
    `https://proof.arcforges.com/proof/v1${executePlanPath}`,
  ];
  for (const proof of [false, true])
    for (const target of targets) {
      const { db, calls } = spyDatabase();
      const response = await fetchEntry(
        await signedFor(target, { id: "c2w-1", secret: c2w }),
        environment(db, proof),
        { waitUntil: () => {} },
      );
      assert(response.status >= 400, `${target} proof=${String(proof)} -> ${response.status}`);
      assert.deepEqual(calls, [], `${target} must not reach D1`);
      assert.doesNotMatch(await response.text(), /manifestHash|foundation\.readiness|rows/u);
    }
});

test("the handler accepts only the Container's direction of the private signature", async () => {
  const url = `http://storage.internal${executePlanPath}`;
  const wrong: [string, { id: string; secret: Uint8Array }][] = [
    ["the Worker-to-Container secret under its own id", { id: "w2c-1", secret: w2c }],
    ["the Worker-to-Container secret under the Container's id", { id: "c2w-1", secret: w2c }],
    ["the Container's secret under the Worker's id", { id: "w2c-1", secret: c2w }],
    ["an unknown key id", { id: "c2w-0", secret: c2w }],
    ["a replaced secret", { id: "c2w-1", secret: new Uint8Array(32).fill(9) }],
  ];
  for (const [label, key] of wrong) {
    const { db, calls } = spyDatabase();
    const response = await handleExecutePlan(
      await signedFor(url, key),
      environment(db, true) as StorageEnv,
      () => fixedNow,
    );
    assert.equal(response.status, 401, label);
    assert.equal(await response.text(), "", `${label}: the refusal carries no detail`);
    assert.deepEqual(calls, [], `${label}: nothing ran`);
  }
  // The same request signed by the Container's own key is the only one that executes.
  const { db, calls } = spyDatabase();
  const accepted = await handleExecutePlan(
    await signedFor(url, { id: "c2w-1", secret: c2w }),
    environment(db, true) as StorageEnv,
    () => fixedNow,
  );
  assert.equal(accepted.status, 200);
  assert(calls.length > 0);
});

test("a signature cannot be moved to another path, body or method", async () => {
  const url = `http://storage.internal${executePlanPath}`;
  const key = { id: "c2w-1", secret: c2w };
  const original = await signedFor(url, key);
  const headers = Object.fromEntries(original.headers);
  const attempts: [string, Request][] = [
    [
      "another body",
      new Request(url, { method: "POST", headers, body: body().slice(0, -1) as BodyInit }),
    ],
    [
      "another path",
      new Request(`http://storage.internal/internal/storage/v1/execute-plan/x`, {
        method: "POST",
        headers,
        body: body() as BodyInit,
      }),
    ],
  ];
  for (const [label, request] of attempts) {
    const { db, calls } = spyDatabase();
    const response = await handleExecutePlan(
      request,
      environment(db, true) as StorageEnv,
      () => fixedNow,
    );
    assert([401, 404].includes(response.status), `${label} -> ${response.status}`);
    assert.deepEqual(calls, [], label);
  }
});
