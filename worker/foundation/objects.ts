// SPDX-License-Identifier: AGPL-3.0-only
// The private `objects.internal` R2 facade (contracts 05 sections 6 and 9, reduced to the foundation
// probe): bounded signed PUT with a server-verified SHA-256 and signed range GET. There is no public
// URL, no presigned URL and the raw R2 key never leaves the Worker.
import { BodyTooLarge, jsonResponse, readBounded, refusal } from "../private/bounded-body.ts";
import { sha256Hex } from "../private/encoding.ts";
import { loadKeys, verificationKeys, type PrivateKeyEnv } from "../private/hmac-settings.ts";
import { verify } from "../private/signing.ts";
import type { R2Like } from "./types.ts";

export const objectsHost = "objects.internal";
export const maxPartBytes = 8 * 1024 * 1024;
const prefix = "/internal/objects/v1/probe/";
const uuid = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/u;
const hash = /^[0-9a-f]{64}$/u;
const emptyBodyHash = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
const realmPattern = /^[a-z0-9][a-z0-9-]{0,31}$/u;

export interface ObjectsEnv extends PrivateKeyEnv {
  OBJECTS: R2Like;
  REALM_ID?: string;
}

function objectKey(realm: string, workspace: string, resource: string, sha256: string) {
  return `realm/${realm}/workspace/${workspace}/diagnostic/${resource}/${sha256}`;
}

type Range = { start: number; end: number };
/** `bytes=a-b` with both ends present, inside the object and at most one part long. */
export function parseRange(header: string, size: number): Range | "unsatisfiable" | null {
  const match = /^bytes=(\d{1,12})-(\d{1,12})$/u.exec(header);
  if (!match) return null;
  const start = Number(match[1]);
  const end = Number(match[2]);
  if (start > end || end >= size || end - start + 1 > maxPartBytes) return "unsatisfiable";
  return { start, end };
}

export async function handleObjects(
  request: Request,
  env: ObjectsEnv,
  nowMs: () => number = Date.now,
): Promise<Response> {
  const url = new URL(request.url);
  if (url.hostname !== objectsHost || url.search !== "" || !url.pathname.startsWith(prefix))
    return refusal(404);
  const segments = url.pathname.slice(prefix.length).split("/");
  const [workspace = "", resource = "", sha256 = ""] = segments;
  const isPut = request.method === "PUT" && segments.length === 2;
  const isGet = request.method === "GET" && segments.length === 3;
  if (!uuid.test(workspace) || !uuid.test(resource)) return refusal(404);
  if (isGet && !hash.test(sha256)) return refusal(404);
  if (!isPut && !isGet) return refusal(segments.length === 2 || segments.length === 3 ? 405 : 404);
  const realm = env.REALM_ID ?? "";
  const keys = loadKeys(env, "C2W");
  if (!keys || !realmPattern.test(realm)) return refusal(503);

  if (isPut) {
    const declaredHash = request.headers.get("x-af-content-sha256") ?? "";
    const length = request.headers.get("content-length");
    // A byte transfer is signed over its declared hash, so the signature is checked before a byte is read.
    const verification = await verify(
      {
        method: "PUT",
        pathAndQuery: url.pathname,
        bodySha256Hex: hash.test(declaredHash) ? declaredHash : "",
        headers: request.headers,
      },
      verificationKeys(keys),
      Math.floor(nowMs() / 1000),
    );
    if (!verification.ok) return refusal(401);
    if (length === null || !/^[1-9][0-9]{0,8}$/u.test(length)) return refusal(411);
    const declaredLength = Number(length);
    if (declaredLength > maxPartBytes) return refusal(413);
    if (!request.body) return refusal(400);
    // The bytes are verified here, before any storage decision: R2 skips its own checksum when the
    // conditional write finds the key already present, so without this an existing key would answer
    // 200 to bytes that do not match the declared hash. The body is bounded by one part.
    let bytes: Uint8Array;
    try {
      bytes = await readBounded(request.body, maxPartBytes);
    } catch (error) {
      if (error instanceof BodyTooLarge) return refusal(413);
      throw error;
    }
    if (bytes.length !== declaredLength) return jsonResponse(422, { error: "length_mismatch" });
    if ((await sha256Hex(bytes)) !== declaredHash)
      return jsonResponse(422, { error: "hash_mismatch" });
    const key = objectKey(realm, workspace, resource, declaredHash);
    let stored: Awaited<ReturnType<R2Like["put"]>>;
    try {
      // R2 verifies the SHA-256 of the received bytes against the declared value as well.
      stored = await env.OBJECTS.put(key, bytes, {
        sha256: declaredHash,
        customMetadata: { sha256: declaredHash, length },
        onlyIf: { etagDoesNotMatch: "*" },
      });
    } catch (error) {
      const message = error instanceof Error ? error.message : "";
      return /checksum|digest|sha-?256|did not match/iu.test(message)
        ? jsonResponse(422, { error: "hash_mismatch" })
        : jsonResponse(503, { error: "unavailable" });
    }
    if (stored === null) {
      // The key embeds the content hash and the bytes were just verified against it, so an existing
      // object is the identical object.
      const existing = await env.OBJECTS.head(key);
      return existing?.size === declaredLength
        ? jsonResponse(200, { sha256: declaredHash, size: declaredLength, existing: true })
        : jsonResponse(409, { error: "conflict" });
    }
    if (stored.size !== declaredLength) {
      await env.OBJECTS.delete(key);
      return jsonResponse(422, { error: "length_mismatch" });
    }
    return jsonResponse(201, { sha256: declaredHash, size: stored.size, existing: false });
  }

  const verification = await verify(
    {
      method: "GET",
      pathAndQuery: url.pathname,
      bodySha256Hex: emptyBodyHash,
      headers: request.headers,
    },
    verificationKeys(keys),
    Math.floor(nowMs() / 1000),
  );
  if (!verification.ok) return refusal(401);
  const key = objectKey(realm, workspace, resource, sha256);
  const head = await env.OBJECTS.head(key);
  if (!head) return refusal(404);
  const rangeHeader = request.headers.get("range");
  let range: Range = { start: 0, end: head.size - 1 };
  if (rangeHeader !== null) {
    const parsed = parseRange(rangeHeader, head.size);
    if (parsed === null) return refusal(400);
    if (parsed === "unsatisfiable") {
      return new Response(null, {
        status: 416,
        headers: { "content-range": `bytes */${head.size}` },
      });
    }
    range = parsed;
  } else if (head.size > maxPartBytes) return refusal(413);
  const object = await env.OBJECTS.get(key, {
    range: { offset: range.start, length: range.end - range.start + 1 },
  });
  if (!object) return refusal(404);
  const headers = new Headers({
    "content-type": "application/octet-stream",
    "cache-control": "no-store",
    "accept-ranges": "bytes",
    "content-length": String(range.end - range.start + 1),
    // The stored whole-object hash, never recomputed from the returned range.
    "x-af-content-sha256": head.customMetadata?.sha256 ?? sha256,
    "x-content-type-options": "nosniff",
  });
  if (rangeHeader !== null)
    headers.set("content-range", `bytes ${range.start}-${range.end}/${head.size}`);
  return new Response(object.body, { status: rangeHeader !== null ? 206 : 200, headers });
}
