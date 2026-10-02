// SPDX-License-Identifier: AGPL-3.0-only
// Private request signing: independent cross-language vectors, negatives and strict encodings.
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import path from "node:path";
import test from "node:test";
import {
  base64UrlDecode,
  base64UrlEncode,
  hexDecode,
  hexEncode,
  sha256Hex,
} from "../../worker/private/encoding.ts";
import { loadKeys } from "../../worker/private/hmac-settings.ts";
import {
  newNonce,
  parseSecret,
  sign,
  signingText,
  verify,
  type SigningKey,
} from "../../worker/private/signing.ts";

interface VectorCase {
  name: string;
  method: string;
  pathAndQuery: string;
  body: string;
  declaredContentHash: string | null;
  time: string;
  nonce: string;
  requestId: string;
  signer: string;
  signature: string;
}
const vectors = JSON.parse(
  readFileSync(
    path.resolve(import.meta.dirname, "../ArcForges.Cloud.Tests/Vectors/private-signing.json"),
    "utf8",
  ),
) as { material: string; cases: VectorCase[] };
const key: SigningKey = {
  id: "c2w-1",
  secret: new Uint8Array(createHash("sha256").update(vectors.material).digest()),
};
const bodyHash = (value: VectorCase) =>
  value.declaredContentHash ?? createHash("sha256").update(value.body).digest("hex");
const parts = (value: VectorCase) => ({
  method: value.method,
  pathAndQuery: value.pathAndQuery,
  bodySha256Hex: bodyHash(value),
  requestId: value.requestId,
  time: value.time,
  nonce: value.nonce,
});
const headersOf = (value: VectorCase, overrides: Record<string, string> = {}) =>
  new Headers({
    "x-af-key-id": value.signer,
    "x-af-time": value.time,
    "x-af-nonce": value.nonce,
    "x-af-request-id": value.requestId,
    "x-af-signature": value.signature,
    ...overrides,
  });
const request = (value: VectorCase, overrides: Record<string, string> = {}) => ({
  method: value.method,
  pathAndQuery: value.pathAndQuery,
  bodySha256Hex: bodyHash(value),
  headers: headersOf(value, overrides),
});

test("signing text has LF separators and no trailing LF", () => {
  const first = vectors.cases[0] as VectorCase;
  const text = signingText(parts(first));
  assert.equal(text.split("\n").length, 6);
  assert(!text.endsWith("\n"));
  assert(!text.includes("\r"));
});

test("independently generated vectors verify and the signer reproduces them exactly", async () => {
  assert(vectors.cases.length >= 3);
  for (const value of vectors.cases) {
    const now = Number(value.time) + 5;
    assert.deepEqual(
      await verify(request(value), [key], now),
      { ok: true, keyId: "c2w-1", requestId: value.requestId },
      value.name,
    );
    const produced = await sign(parts(value), key);
    assert.equal(produced["x-af-signature"], value.signature, value.name);
  }
});

test("any altered signed element fails identically", async () => {
  const value = vectors.cases[0] as VectorCase;
  const now = Number(value.time);
  const altered = [
    { ...request(value), method: "PUT" },
    { ...request(value), pathAndQuery: `${value.pathAndQuery}x` },
    { ...request(value), bodySha256Hex: "0".repeat(64) },
    request(value, { "x-af-time": String(Number(value.time) + 1) }),
    request(value, { "x-af-nonce": "BBBBBBBBBBBBBBBBBBBBBB" }),
    request(value, { "x-af-request-id": "99999999-9999-4999-8999-999999999999" }),
    request(value, { "x-af-key-id": "c2w-2" }),
    request(value, { "x-af-signature": value.signature.slice(0, -1) }),
    request(value, { "x-af-signature": `${value.signature}A` }),
    request(value, {
      "x-af-signature": value.signature.replace(/^./u, value.signature.startsWith("A") ? "B" : "A"),
    }),
  ];
  for (const candidate of altered)
    assert.deepEqual(await verify(candidate, [key], now), { ok: false });
});

test("malformed headers and out-of-skew clocks are refused", async () => {
  const value = vectors.cases[0] as VectorCase;
  const now = Number(value.time);
  assert.equal((await verify(request(value), [key], now + 60)).ok, true);
  assert.equal((await verify(request(value), [key], now - 60)).ok, true);
  assert.equal((await verify(request(value), [key], now + 61)).ok, false);
  assert.equal((await verify(request(value), [key], now - 61)).ok, false);
  for (const [name, bad] of [
    ["x-af-key-id", ""],
    ["x-af-key-id", "-bad"],
    ["x-af-time", "01790000000"],
    ["x-af-time", "17.9"],
    ["x-af-nonce", "short"],
    ["x-af-nonce", "A".repeat(23)],
    ["x-af-request-id", value.requestId.replace(/^1/u, "A")],
    ["x-af-request-id", "not-a-uuid"],
    ["x-af-signature", ""],
    ["x-af-signature", `${value.signature}=`],
  ] as const)
    assert.deepEqual(
      await verify(request(value, { [name]: bad }), [key], now),
      { ok: false },
      `${name}=${bad}`,
    );
  const missing = request(value);
  missing.headers.delete("x-af-signature");
  assert.deepEqual(await verify(missing, [key], now), { ok: false });
  assert.deepEqual(await verify({ ...request(value), bodySha256Hex: "ABC" }, [key], now), {
    ok: false,
  });
});

test("a previous key still verifies during rotation and an unknown key never does", async () => {
  const value = vectors.cases[0] as VectorCase;
  const now = Number(value.time);
  const current: SigningKey = { id: "c2w-2", secret: new Uint8Array(32).fill(7) };
  assert.equal((await verify(request(value), [current, key], now)).ok, true);
  assert.equal((await verify(request(value), [current], now)).ok, false);
});

test("nonces are 128 random bits in strict base64url", () => {
  const first = newNonce();
  const second = newNonce();
  assert.match(first, /^[A-Za-z0-9_-]{22}$/u);
  assert.notEqual(first, second);
  assert.equal(base64UrlDecode(first)?.length, 16);
});

test("deployment secrets are exactly 256 bits of strict unpadded base64url", () => {
  const good = base64UrlEncode(new Uint8Array(32).fill(1));
  assert.equal(parseSecret(good)?.length, 32);
  for (const bad of [
    undefined,
    "",
    good.slice(1),
    `${good}A`,
    `${good}=`,
    good.replace(/^./u, "+"),
    "A".repeat(42),
  ])
    assert.equal(parseSecret(bad), null, String(bad));
});

test("base64url is strict and round-trips every length", () => {
  for (let length = 0; length < 70; length++) {
    const bytes = Uint8Array.from({ length }, (_, index) => (index * 37 + length) & 255);
    const text = base64UrlEncode(bytes);
    assert.equal(text, Buffer.from(bytes).toString("base64url"));
    assert.deepEqual(base64UrlDecode(text), bytes);
  }
  for (const bad of ["A", "AAAAA", "AB", "AAB", "A+A=", "A A A", "AA==", "=AAA", "ÄAAA"])
    assert.equal(base64UrlDecode(bad), null, bad);
  assert.deepEqual(hexDecode("00ff10"), Uint8Array.of(0, 255, 16));
  assert.equal(hexDecode("0"), null);
  assert.equal(hexDecode("0G"), null);
  assert.equal(hexDecode("0A"), null);
  assert.equal(hexEncode(Uint8Array.of(0, 255, 16)), "00ff10");
});

test("body hashes use lowercase hex SHA-256", async () => {
  assert.equal(
    await sha256Hex(new TextEncoder().encode("x")),
    createHash("sha256").update("x").digest("hex"),
  );
});

test("key loading requires the current key and refuses half-configured rotation", () => {
  const secret = base64UrlEncode(new Uint8Array(32).fill(9));
  const other = base64UrlEncode(new Uint8Array(32).fill(8));
  assert.equal(loadKeys({}, "C2W"), null);
  assert.equal(loadKeys({ HMAC_C2W_KEY_ID: "c2w-1" }, "C2W"), null);
  assert.equal(loadKeys({ HMAC_C2W_SECRET: secret }, "C2W"), null);
  assert.equal(loadKeys({ HMAC_C2W_KEY_ID: "c2w-1", HMAC_C2W_SECRET: "short" }, "C2W"), null);
  assert.equal(loadKeys({ HMAC_W2C_KEY_ID: "w2c-1", HMAC_W2C_SECRET: secret }, "C2W"), null);
  const single = loadKeys({ HMAC_C2W_KEY_ID: "c2w-1", HMAC_C2W_SECRET: secret }, "C2W");
  assert.equal(single?.current.id, "c2w-1");
  assert.equal(single?.previous, undefined);
  const rotated = loadKeys(
    {
      HMAC_C2W_KEY_ID: "c2w-2",
      HMAC_C2W_SECRET: secret,
      HMAC_C2W_PREVIOUS_KEY_ID: "c2w-1",
      HMAC_C2W_PREVIOUS_SECRET: other,
    },
    "C2W",
  );
  assert.equal(rotated?.previous?.id, "c2w-1");
  assert.equal(
    loadKeys(
      { HMAC_C2W_KEY_ID: "c2w-2", HMAC_C2W_SECRET: secret, HMAC_C2W_PREVIOUS_KEY_ID: "c2w-1" },
      "C2W",
    ),
    null,
  );
  assert.equal(
    loadKeys(
      {
        HMAC_C2W_KEY_ID: "c2w-2",
        HMAC_C2W_SECRET: secret,
        HMAC_C2W_PREVIOUS_KEY_ID: "c2w-1",
        HMAC_C2W_PREVIOUS_SECRET: "bad",
      },
      "C2W",
    ),
    null,
  );
  assert.equal(
    loadKeys(
      {
        HMAC_C2W_KEY_ID: "same",
        HMAC_C2W_SECRET: secret,
        HMAC_C2W_PREVIOUS_KEY_ID: "same",
        HMAC_C2W_PREVIOUS_SECRET: other,
      },
      "C2W",
    ),
    null,
  );
});
