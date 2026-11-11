// SPDX-License-Identifier: AGPL-3.0-only
// Authentication of the authority collector is necessary but is not evidence of complete authority.
import assert from "node:assert/strict";
import { createHash, createPublicKey, verify, type JsonWebKey } from "node:crypto";
import { object, parseDocument } from "./provenance.ts";

const issuer = "https://token.actions.githubusercontent.com";
const jwksUrl = `${issuer}/.well-known/jwks`;
const audiencePrefix = "arcforges:ctr06:bootstrap-authority:v1:";
const collectorWorkflow =
  "ArcForges/Cloud/.github/workflows/ctr06-authority-collector.yml@refs/heads/main";
const repositoryId = "1372264358";
const ownerId = "279581753";
const maximumPayload = 1024 * 1024;
const maximumToken = 32 * 1024;
const maximumJwks = 128 * 1024;
const hex40 = /^[a-f0-9]{40}$/u;
const natural = /^[1-9][0-9]{0,14}$/u;
const knownClaims = new Set([
  "iss",
  "sub",
  "aud",
  "exp",
  "iat",
  "nbf",
  "jti",
  "ref",
  "sha",
  "repository",
  "repository_id",
  "repository_owner",
  "repository_owner_id",
  "enterprise",
  "enterprise_id",
  "run_id",
  "run_number",
  "run_attempt",
  "actor",
  "actor_id",
  "workflow",
  "workflow_ref",
  "workflow_sha",
  "head_ref",
  "base_ref",
  "event_name",
  "ref_type",
  "ref_protected",
  "environment",
  "environment_node_id",
  "job_workflow_ref",
  "job_workflow_sha",
  "repository_visibility",
  "runner_environment",
  "issuer_scope",
  "check_run_id",
]);

export type AuthenticatedWindow = Readonly<{
  issuedAt: number;
  notBefore: number;
  expiresAt: number;
}>;

export function requireFreshWindow(window: AuthenticatedWindow, nowSeconds: number): void {
  assert(Number.isSafeInteger(nowSeconds) && nowSeconds >= 0);
  assert(
    window.notBefore <= nowSeconds && nowSeconds < window.expiresAt,
    "Authenticated proof is not fresh",
  );
}

export type CollectorIdentity = {
  sourceSha: string;
  runId: string;
  runAttempt: string;
};

function base64url(segment: string): Buffer {
  assert(segment.length > 0 && /^[A-Za-z0-9_-]+$/u.test(segment), "Malformed JWT segment");
  const bytes = Buffer.from(segment, "base64url");
  assert.equal(bytes.toString("base64url"), segment, "Noncanonical JWT segment");
  return bytes;
}

function safeTime(value: unknown): number {
  assert(
    typeof value === "number" && Number.isSafeInteger(value) && value >= 0,
    "Invalid JWT time",
  );
  return value;
}

function collectKeys(input: Buffer): Map<string, JsonWebKey> {
  assert(input.length > 0 && input.length <= maximumJwks, "JWKS size invalid");
  const document = object(parseDocument(input), "keys");
  assert(Array.isArray(document.keys) && document.keys.length > 0 && document.keys.length <= 64);
  const keys = new Map<string, JsonWebKey>();
  const seen = new Set<string>();
  for (const value of document.keys) {
    const key = object(value);
    assert(typeof key.kid === "string" && /^[A-Za-z0-9._-]{1,128}$/u.test(key.kid));
    assert(!seen.has(key.kid), "Duplicate JWKS key id");
    seen.add(key.kid);
    if (key.kty !== "RSA" || key.use !== "sig" || key.alg !== "RS256") continue;
    assert(typeof key.n === "string" && typeof key.e === "string");
    const n = base64url(key.n);
    const e = base64url(key.e);
    assert(n.length >= 256 && n.length <= 1024 && e.length > 0 && e.length <= 8, "Unsafe RSA key");
    keys.set(key.kid, key as JsonWebKey);
  }
  return keys;
}

/**
 * Verifies cryptography and the fixed collector identity. Supplying keys here is a test seam;
 * production callers must use verifyCollectorIdentity, which obtains the fixed issuer's JWKS.
 * This result authenticates bytes and identity only; provider coverage and enforcement remain separate.
 */
export function verifyCollectorIdentityWithKeys(
  payload: Buffer,
  token: string,
  identity: CollectorIdentity,
  nowSeconds: number,
  jwks: Buffer,
): AuthenticatedWindow {
  assert(payload.length > 0 && payload.length <= maximumPayload, "Authority payload size invalid");
  assert(Buffer.byteLength(token, "utf8") <= maximumToken, "OIDC token too large");
  assert(
    hex40.test(identity.sourceSha) &&
      natural.test(identity.runId) &&
      natural.test(identity.runAttempt),
  );
  assert(Number.isSafeInteger(nowSeconds) && nowSeconds >= 0);
  const segments = token.split(".");
  assert.equal(segments.length, 3, "Malformed JWT");
  const [headerPart, claimPart, signaturePart] = segments;
  assert(headerPart && claimPart && signaturePart);
  const header = object(parseDocument(base64url(headerPart)));
  assert(
    Object.keys(header).every((key) => ["alg", "kid", "typ", "x5t"].includes(key)),
    "Unexpected JWT header",
  );
  assert.equal(header.alg, "RS256");
  assert(header.typ === undefined || header.typ === "JWT");
  assert(typeof header.kid === "string");
  const key = collectKeys(jwks).get(header.kid);
  assert(key, "Unknown collector signing key");
  const signature = base64url(signaturePart);
  assert(
    verify(
      "RSA-SHA256",
      Buffer.from(`${headerPart}.${claimPart}`),
      createPublicKey({ key, format: "jwk" }),
      signature,
    ),
    "Collector signature differs",
  );
  const claims = object(parseDocument(base64url(claimPart)));
  assert(
    Object.keys(claims).every((key) => knownClaims.has(key)),
    "Unsupported collector claim",
  );
  assert.equal(claims.iss, issuer);
  assert.equal(claims.aud, audiencePrefix + createHash("sha256").update(payload).digest("hex"));
  assert.equal(claims.sub, "repo:ArcForges/Cloud:ref:refs/heads/main");
  assert.equal(claims.repository, "ArcForges/Cloud");
  assert.equal(claims.repository_id, repositoryId);
  assert.equal(claims.repository_owner_id, ownerId);
  assert.equal(claims.ref, "refs/heads/main");
  assert.equal(claims.ref_protected, "true");
  assert.equal(claims.workflow_ref, collectorWorkflow);
  assert.equal(claims.workflow_sha, identity.sourceSha);
  assert.equal(claims.sha, identity.sourceSha);
  assert.equal(claims.event_name, "workflow_dispatch");
  assert.equal(claims.run_id, identity.runId);
  assert.equal(claims.run_attempt, identity.runAttempt);
  assert.equal(claims.runner_environment, "github-hosted");
  assert(typeof claims.jti === "string" && claims.jti.length >= 1 && claims.jti.length <= 256);
  const issued = safeTime(claims.iat);
  const notBefore = safeTime(claims.nbf);
  const expires = safeTime(claims.exp);
  assert(issued <= nowSeconds + 30 && notBefore <= nowSeconds && expires > nowSeconds);
  assert(expires > issued && expires - issued <= 300, "Collector token lifetime invalid");
  return Object.freeze({ issuedAt: issued, notBefore, expiresAt: expires });
}

/** Production authentication: neither the issuer nor its key source is configurable by the caller. */
export async function verifyCollectorIdentity(
  payload: Buffer,
  token: string,
  identity: CollectorIdentity,
  nowSeconds: number,
): Promise<AuthenticatedWindow> {
  const response = await fetch(jwksUrl, {
    redirect: "error",
    signal: AbortSignal.timeout(10_000),
    headers: { accept: "application/json" },
  });
  assert(response.ok, "Collector JWKS unavailable");
  const length = response.headers.get("content-length");
  if (length !== null) assert(/^[0-9]+$/u.test(length) && Number(length) <= maximumJwks);
  assert(response.body, "Collector JWKS body missing");
  const reader = response.body.getReader();
  const chunks: Buffer[] = [];
  let total = 0;
  try {
    while (true) {
      const next = await reader.read();
      if (next.done) break;
      total += next.value.byteLength;
      assert(total <= maximumJwks, "Collector JWKS too large");
      chunks.push(Buffer.from(next.value));
    }
  } finally {
    await reader.cancel().catch(() => undefined);
  }
  return verifyCollectorIdentityWithKeys(
    payload,
    token,
    identity,
    nowSeconds,
    Buffer.concat(chunks),
  );
}
