// SPDX-License-Identifier: AGPL-3.0-only
// The private R2 facade: signature before bytes, server-verified hash, bounded parts and ranges.
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import test from "node:test";
import { base64UrlEncode } from "../../worker/private/encoding.ts";
import { newNonce, sign } from "../../worker/private/signing.ts";
import {
  handleObjects,
  maxPartBytes,
  parseRange,
  type ObjectsEnv,
} from "../../worker/foundation/objects.ts";
import { createFakeR2 } from "./support/fake-r2.ts";
import { fixedNow, uuid } from "./support/plan-calls.ts";

const secret = new Uint8Array(32).fill(3);
const emptyHash = createHash("sha256").update("").digest("hex");
const hex = (bytes: Uint8Array) => createHash("sha256").update(bytes).digest("hex");
const workspace = "22222222-2222-4222-8222-222222222222";
const resource = "33333333-3333-4333-8333-333333333333";
const now = () => fixedNow;

function environment(overrides: Partial<ObjectsEnv> = {}) {
  const OBJECTS = createFakeR2();
  const env: ObjectsEnv = {
    OBJECTS,
    REALM_ID: "proof",
    HMAC_C2W_KEY_ID: "c2w-1",
    HMAC_C2W_SECRET: base64UrlEncode(secret),
    ...overrides,
  };
  return { env, OBJECTS };
}

async function put(
  body: Uint8Array,
  options: { declared?: string; length?: string; time?: number; path?: string } = {},
) {
  const path = options.path ?? `/internal/objects/v1/probe/${workspace}/${resource}`;
  const declared = options.declared ?? hex(body);
  const headers = await sign(
    {
      method: "PUT",
      pathAndQuery: path,
      bodySha256Hex: declared,
      requestId: uuid(),
      time: String(options.time ?? Math.floor(fixedNow / 1000)),
      nonce: newNonce(),
    },
    { id: "c2w-1", secret },
  );
  return new Request(`http://objects.internal${path}`, {
    method: "PUT",
    headers: {
      ...headers,
      "x-af-content-sha256": declared,
      "content-length": options.length ?? String(body.length),
    },
    body: body as BodyInit,
  });
}
async function get(sha: string, range?: string, overrides: { time?: number; path?: string } = {}) {
  const path = overrides.path ?? `/internal/objects/v1/probe/${workspace}/${resource}/${sha}`;
  const headers = await sign(
    {
      method: "GET",
      pathAndQuery: path,
      bodySha256Hex: emptyHash,
      requestId: uuid(),
      time: String(overrides.time ?? Math.floor(fixedNow / 1000)),
      nonce: newNonce(),
    },
    { id: "c2w-1", secret },
  );
  return new Request(`http://objects.internal${path}`, {
    method: "GET",
    headers: range ? { ...headers, range } : { ...headers },
  });
}
const payload = Uint8Array.from({ length: 4096 }, (_, index) => (index * 31) & 255);

test("a signed put stores the object under a hash-bearing private key and a get returns it", async () => {
  const { env, OBJECTS } = environment();
  const created = await handleObjects(await put(payload), env, now);
  assert.equal(created.status, 201);
  assert.deepEqual(await created.json(), { sha256: hex(payload), size: 4096, existing: false });
  assert.deepEqual(
    [...OBJECTS.objects.keys()],
    [`realm/proof/workspace/${workspace}/diagnostic/${resource}/${hex(payload)}`],
  );
  const whole = await handleObjects(await get(hex(payload)), env, now);
  assert.equal(whole.status, 200);
  assert.equal(whole.headers.get("x-af-content-sha256"), hex(payload));
  assert.deepEqual(new Uint8Array(await whole.arrayBuffer()), payload);
  const ranged = await handleObjects(await get(hex(payload), "bytes=10-19"), env, now);
  assert.equal(ranged.status, 206);
  assert.equal(ranged.headers.get("content-range"), "bytes 10-19/4096");
  assert.equal(ranged.headers.get("x-af-content-sha256"), hex(payload));
  assert.deepEqual(new Uint8Array(await ranged.arrayBuffer()), payload.slice(10, 20));
});

test("bytes whose hash differs from the declared and signed hash are refused and never stored", async () => {
  const { env, OBJECTS } = environment();
  const other = hex(new Uint8Array([1, 2, 3]));
  const response = await handleObjects(await put(payload, { declared: other }), env, now);
  assert.equal(response.status, 422);
  assert.deepEqual(await response.json(), { error: "hash_mismatch" });
  assert.equal(OBJECTS.objects.size, 0);
});

test("a declared length that differs from the stored size removes the object", async () => {
  const { env, OBJECTS } = environment();
  const response = await handleObjects(await put(payload, { length: "4095" }), env, now);
  assert.equal(response.status, 422);
  assert.deepEqual(await response.json(), { error: "length_mismatch" });
  assert.equal(OBJECTS.objects.size, 0);
});

test("the same object is idempotent and never overwritten", async () => {
  const { env, OBJECTS } = environment();
  assert.equal((await handleObjects(await put(payload), env, now)).status, 201);
  const again = await handleObjects(await put(payload), env, now);
  assert.equal(again.status, 200);
  assert.deepEqual(await again.json(), { sha256: hex(payload), size: 4096, existing: true });
  assert.equal(OBJECTS.objects.size, 1);
});

test("authentication is checked before any byte is read", async () => {
  const { env, OBJECTS } = environment();
  const stale = await handleObjects(
    await put(payload, { time: Math.floor(fixedNow / 1000) + 61 }),
    env,
    now,
  );
  assert.equal(stale.status, 401);
  const wrongKey = await handleObjects(
    await put(payload),
    environment({ HMAC_C2W_SECRET: base64UrlEncode(new Uint8Array(32).fill(4)) }).env,
    now,
  );
  assert.equal(wrongKey.status, 401);
  // Signed over a different hash than the one declared in the header.
  const request = await put(payload);
  request.headers.set("x-af-content-sha256", hex(new Uint8Array([9])));
  assert.equal((await handleObjects(request, env, now)).status, 401);
  assert.equal(OBJECTS.puts, 0);
  assert.equal(
    (await handleObjects(await get(hex(payload), undefined, { time: 1 }), env, now)).status,
    401,
  );
});

test("size, length declaration and routing bounds", async () => {
  const { env } = environment();
  assert.equal(
    (await handleObjects(await put(payload, { length: String(maxPartBytes + 1) }), env, now))
      .status,
    413,
  );
  const missing = await put(payload);
  missing.headers.delete("content-length");
  assert.equal((await handleObjects(missing, env, now)).status, 411);
  for (const path of [
    `/internal/objects/v1/probe/not-a-uuid/${resource}`,
    `/internal/objects/v1/probe/${workspace}/${resource}/extra/segment`,
    "/internal/objects/v1/other",
    "/internal/storage/v1/execute-plan",
  ])
    assert.equal((await handleObjects(await put(payload, { path }), env, now)).status, 404, path);
  assert.equal((await handleObjects(await get("not-a-hash"), env, now)).status, 404);
  const wrongMethod = new Request(
    `http://objects.internal/internal/objects/v1/probe/${workspace}/${resource}`,
    { method: "DELETE" },
  );
  assert.equal((await handleObjects(wrongMethod, env, now)).status, 405);
  const wrongHost = new Request(
    `http://example.com/internal/objects/v1/probe/${workspace}/${resource}`,
    { method: "PUT" },
  );
  assert.equal((await handleObjects(wrongHost, env, now)).status, 404);
});

test("ranges are exact, inside the object and at most one part", async () => {
  assert.deepEqual(parseRange("bytes=0-0", 1), { start: 0, end: 0 });
  assert.deepEqual(parseRange("bytes=5-9", 10), { start: 5, end: 9 });
  for (const bad of [
    "bytes=5-",
    "bytes=-5",
    "bytes=0-1,3-4",
    "items=0-1",
    "bytes=a-b",
    "bytes=0-1 ",
  ])
    assert.equal(parseRange(bad, 10), null, bad);
  for (const unsatisfiable of ["bytes=5-4", "bytes=0-10", "bytes=10-10"])
    assert.equal(parseRange(unsatisfiable, 10), "unsatisfiable", unsatisfiable);
  assert.equal(parseRange(`bytes=0-${maxPartBytes}`, maxPartBytes + 5), "unsatisfiable");
  const { env } = environment();
  await handleObjects(await put(payload), env, now);
  const malformed = await handleObjects(await get(hex(payload), "bytes=1-"), env, now);
  assert.equal(malformed.status, 400);
  const beyond = await handleObjects(await get(hex(payload), "bytes=0-4096"), env, now);
  assert.equal(beyond.status, 416);
  assert.equal(beyond.headers.get("content-range"), "bytes */4096");
  assert.equal((await handleObjects(await get(hex(new Uint8Array([7]))), env, now)).status, 404);
});

test("missing realm or keys disable the facade instead of opening it", async () => {
  for (const broken of [
    { REALM_ID: undefined },
    { REALM_ID: "Bad Realm" },
    { HMAC_C2W_SECRET: undefined },
  ]) {
    const { env } = environment(broken);
    assert.equal(
      (await handleObjects(await put(payload), env, now)).status,
      503,
      JSON.stringify(broken),
    );
  }
});

test("bytes that differ from the declared hash are refused on an existing key too and the object is kept", async () => {
  // Real R2 evaluates the conditional write first and skips its own checksum when the key exists
  // (this fake does the same), so the facade must verify the bytes itself.
  const { env, OBJECTS } = environment();
  assert.equal((await handleObjects(await put(payload), env, now)).status, 201);
  const tampered = payload.slice();
  tampered[0] = (tampered[0] ?? 0) ^ 0xff;
  const response = await handleObjects(await put(tampered, { declared: hex(payload) }), env, now);
  assert.equal(response.status, 422);
  assert.deepEqual(await response.json(), { error: "hash_mismatch" });
  assert.equal(OBJECTS.objects.size, 1);
  const [stored] = [...OBJECTS.objects.values()];
  assert.deepEqual(stored?.bytes, payload, "the stored object is unchanged");
  // A body larger than the declared length is a length mismatch, not a stored object.
  const longer = new Uint8Array(payload.length + 1);
  const mismatch = await handleObjects(
    await put(longer, { declared: hex(longer), length: "4096" }),
    env,
    now,
  );
  assert.equal(mismatch.status, 422);
  assert.equal(OBJECTS.objects.size, 1);
});
