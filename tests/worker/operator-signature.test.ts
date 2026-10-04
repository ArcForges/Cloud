// SPDX-License-Identifier: AGPL-3.0-only
// The signed operator surface of the deployed proof environment: the Worker holds only an Ed25519
// public key, the operator signs each request, and every other request is refused the same way.
import assert from "node:assert/strict";
import { generateKeyPairSync, type KeyObject } from "node:crypto";
import { mkdtempSync, readFileSync, statSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import test from "node:test";
import {
  initOperatorKey,
  loadOperatorKey,
  publicKeyText,
  signOperatorRequest,
} from "../../eng/verification/proof-operator.ts";
import { verifyOperatorSignature } from "../../worker/foundation/operator-signature.ts";
import { handleProof } from "../../worker/foundation/proof-routes.ts";
import type { FoundationEnv } from "../../worker/foundation/types.ts";
import { base64UrlEncode, sha256Hex } from "../../worker/private/encoding.ts";
import { createFakeR2 } from "./support/fake-r2.ts";

const now = 1_800_000_000;
const body = new TextEncoder().encode('{"hello":"world"}');
const key = generateKeyPairSync("ed25519").privateKey;
const otherKey = generateKeyPairSync("ed25519").privateKey;

async function check(
  authorization: string | null,
  overrides: {
    method?: string;
    host?: string;
    pathname?: string;
    body?: Uint8Array;
    publicKey?: string;
    at?: number;
  } = {},
) {
  return verifyOperatorSignature(
    authorization,
    {
      method: overrides.method ?? "POST",
      host: overrides.host ?? "proof.example",
      pathname: overrides.pathname ?? "/proof/v1/exact",
      bodySha256Hex: await sha256Hex(overrides.body ?? body),
    },
    overrides.publicKey ?? publicKeyText(key),
    overrides.at ?? now,
  );
}
const sign = (signer: KeyObject = key) =>
  signOperatorRequest(signer, "POST", "proof.example", "/proof/v1/exact", body, {
    nowSeconds: now,
  });

test("a fresh signature over the exact request verifies and every deviation is refused", async () => {
  const header = await sign();
  assert.match(header, /^AF-Operator t=\d{10},n=[A-Za-z0-9_-]{22},s=[A-Za-z0-9_-]{86}$/u);
  assert.equal(await check(header), true);
  // The signature binds method, path, body, time and the key.
  assert.equal(await check(header, { method: "GET" }), false);
  assert.equal(await check(header, { pathname: "/proof/v1/guard" }), false);
  assert.equal(await check(header, { host: "evil.example" }), false, "the host is bound");
  assert.equal(await check(header, { body: new TextEncoder().encode("{}") }), false);
  assert.equal(await check(header, { publicKey: publicKeyText(otherKey) }), false);
  assert.equal(await check(await sign(otherKey)), false);
  // A 60 second skew is accepted, one more second is not, in either direction.
  assert.equal(await check(header, { at: now + 60 }), true);
  assert.equal(await check(header, { at: now - 60 }), true);
  assert.equal(await check(header, { at: now + 61 }), false);
  assert.equal(await check(header, { at: now - 61 }), false);
  // A tampered time field no longer matches the signed text.
  assert.equal(await check(header.replace(/t=\d{10}/u, `t=${now + 1}`)), false);
  for (const bad of [
    null,
    "",
    "Bearer x",
    "AF-Operator",
    header.replace("AF-Operator", "af-operator"),
    `${header} `,
    header.replace(/s=[A-Za-z0-9_-]{86}/u, `s=${"A".repeat(86)}`),
    header.replace(/n=[A-Za-z0-9_-]{22}/u, "n=short"),
  ])
    assert.equal(await check(bad), false, String(bad));
  // A malformed or missing configured key refuses everything instead of throwing.
  for (const publicKey of ["", "short", base64UrlEncode(new Uint8Array(31)), "!".repeat(43)])
    assert.equal(await check(header, { publicKey }), false, publicKey);
});

const w2c = base64UrlEncode(new Uint8Array(32).fill(2));
function environment(overrides: Partial<FoundationEnv>) {
  const forwarded: { path: string }[] = [];
  const env: FoundationEnv = {
    FOUNDATION_PROOF: "enabled",
    DB: undefined as never,
    RECOVERY_GENERATION: "0",
    HMAC_W2C_KEY_ID: "w2c-1",
    HMAC_W2C_SECRET: w2c,
    OBJECTS: createFakeR2(),
    WAKE_QUEUE: { send: () => Promise.resolve() },
    JOB_COORDINATOR: undefined as never,
    CLOUD_CONTAINER: {
      getByName: () => ({
        fetch(request: Request) {
          forwarded.push({ path: new URL(request.url).pathname });
          return Promise.resolve(
            new Response('{"ready":true}', { headers: { "content-type": "application/json" } }),
          );
        },
      }),
    },
    ...overrides,
  };
  return { env, forwarded };
}

async function signedRequest(signer: KeyObject, pathname: string, payload: Uint8Array) {
  return new Request(`https://proof.example${pathname}`, {
    method: "POST",
    headers: {
      authorization: await signOperatorRequest(signer, "POST", "proof.example", pathname, payload, {
        nowSeconds: Math.floor(Date.now() / 1000),
      }),
      "content-type": "application/json",
    },
    body: payload as BodyInit,
  });
}
const bearer = (token: string, payload: Uint8Array) =>
  new Request("https://proof.example/proof/v1/readiness", {
    method: "POST",
    headers: { authorization: `Bearer ${token}`, "content-type": "application/json" },
    body: payload as BodyInit,
  });

test("the proof surface accepts only the configured operator key and refuses everything else with 401", async () => {
  const { env, forwarded } = environment({ PROOF_OPERATOR_VERIFIER: publicKeyText(key) });
  const payload = new TextEncoder().encode("{}");
  const ok = await handleProof(await signedRequest(key, "/proof/v1/readiness", payload), env);
  assert.equal(ok.status, 200);
  assert.deepEqual(forwarded, [{ path: "/internal/foundation/v1/readiness" }]);
  const before = forwarded.length;
  const signedForGuard = await signedRequest(key, "/proof/v1/guard", payload);
  const wrongPath = new Request("https://proof.example/proof/v1/readiness", {
    method: "POST",
    headers: {
      authorization: signedForGuard.headers.get("authorization") ?? "",
      "content-type": "application/json",
    },
    body: payload as BodyInit,
  });
  const refused = [
    await handleProof(await signedRequest(otherKey, "/proof/v1/readiness", payload), env),
    await handleProof(wrongPath, env),
    await handleProof(bearer("t".repeat(40), payload), env),
    await handleProof(
      new Request("https://proof.example/proof/v1/readiness", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: payload as BodyInit,
      }),
      env,
    ),
    await handleProof(
      await signedRequest(key, "/proof/v1/readiness", new Uint8Array(20_000).fill(32)),
      env,
    ),
  ];
  for (const response of refused) {
    assert.equal(response.status, 401);
    assert.equal(await response.text(), "", "refusals reveal nothing");
  }
  assert.equal(forwarded.length, before, "nothing reached the Container");
});

test("credentials are accepted only when configured, and none configured disables the surface", async () => {
  const token = "t".repeat(40);
  const payload = new TextEncoder().encode("{}");
  const bearerOnly = environment({ PROOF_OPERATOR_TOKEN: token });
  assert.equal(
    (await handleProof(await signedRequest(key, "/proof/v1/readiness", payload), bearerOnly.env))
      .status,
    401,
  );
  const both = environment({
    PROOF_OPERATOR_TOKEN: token,
    PROOF_OPERATOR_VERIFIER: publicKeyText(key),
  });
  assert.equal(
    (await handleProof(await signedRequest(key, "/proof/v1/readiness", payload), both.env)).status,
    200,
  );
  assert.equal((await handleProof(bearer(token, payload), both.env)).status, 200);
  const keyOnly = environment({ PROOF_OPERATOR_VERIFIER: publicKeyText(key) });
  assert.equal((await handleProof(bearer(token, payload), keyOnly.env)).status, 401);
  // A configured but too short bearer token is never accepted, even when the key enables the surface.
  const shortToken = environment({
    PROOF_OPERATOR_TOKEN: "short",
    PROOF_OPERATOR_VERIFIER: publicKeyText(key),
  });
  assert.equal((await handleProof(bearer("short", payload), shortToken.env)).status, 401);
  const shortOnly = environment({ PROOF_OPERATOR_TOKEN: "t".repeat(31) });
  assert.equal((await handleProof(bearer("t".repeat(31), payload), shortOnly.env)).status, 503);
  const none = environment({});
  assert.equal(
    (await handleProof(await signedRequest(key, "/proof/v1/readiness", payload), none.env)).status,
    503,
  );
});

test("the operator key file is created once, kept and never overwritten", () => {
  const dir = mkdtempSync(path.join(tmpdir(), "operator-key-"));
  const file = path.join(dir, "nested", "key.pem");
  const first = initOperatorKey(file);
  assert.match(first, /^[A-Za-z0-9_-]{43}$/u);
  assert.equal(initOperatorKey(file), first, "an existing key is kept");
  assert.equal(publicKeyText(loadOperatorKey(file)), first);
  assert(readFileSync(file, "utf8").startsWith("-----BEGIN PRIVATE KEY-----"));
  if (process.platform !== "win32") assert.equal(statSync(file).mode & 0o077, 0);
  assert.throws(() => loadOperatorKey(path.join(dir, "missing.pem")), /No operator key file/u);
});
