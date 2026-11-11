// SPDX-License-Identifier: AGPL-3.0-only
// This evaluates the supplied observations. It does not establish their source, completeness or enforcement.
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { object } from "./provenance.ts";

const idPattern = /^[A-Za-z0-9._:-]{1,128}$/u;
const relationshipKinds = new Set([
  "assume",
  "exchange",
  "delegate",
  "invoke",
  "credential",
  "inherit",
]);
const capabilityKinds = new Set([
  "metadata",
  "publication",
  "database",
  "rollout",
  "deployment",
  "activation",
  "unknown",
]);
const forbidden = new Set(["database", "rollout", "deployment", "activation", "unknown"]);

type Principal = { id: string; capabilities: string[] };
type Relationship = { id: string; kind: string; requires: string[]; grants: string };

function identity(value: unknown): string {
  assert(typeof value === "string" && idPattern.test(value), "Invalid authority identity");
  return value;
}
function stringArray(value: unknown, maximum: number): string[] {
  assert(Array.isArray(value) && value.length <= maximum);
  const result = value.map(identity);
  assert.equal(new Set(result).size, result.length, "Duplicate authority entry");
  return result;
}

/**
 * Recompute the least fixed point, including joint prerequisites, rather than accepting a claimed decision.
 * Inputs must separately come from complete authenticated authoritative provider observations. A successful
 * return is only a result for these inputs, never a production publication or complete-coverage assertion.
 */
export function evaluateObservedAuthority(input: unknown): { reachable: string[] } {
  const value = object(input, "principals relationships roots");
  assert(
    Array.isArray(value.principals) &&
      value.principals.length > 0 &&
      value.principals.length <= 4096,
  );
  assert(Array.isArray(value.relationships) && value.relationships.length <= 16384);
  const principals = new Map<string, Principal>();
  for (const raw of value.principals) {
    const item = object(raw, "id capabilities");
    const id = identity(item.id);
    assert(!principals.has(id), "Duplicate principal");
    const capabilities = stringArray(item.capabilities, 32);
    assert(
      capabilities.every((capability) => capabilityKinds.has(capability)),
      "Unsupported capability",
    );
    principals.set(id, { id, capabilities });
  }
  const roots = stringArray(value.roots, 4096);
  assert(roots.length > 0 && roots.every((id) => principals.has(id)), "Unknown or missing root");
  const relationships: Relationship[] = [];
  const seen = new Set<string>();
  for (const raw of value.relationships) {
    const item = object(raw, "id kind requires grants");
    const id = identity(item.id);
    assert(!seen.has(id), "Duplicate relationship");
    seen.add(id);
    const kind = identity(item.kind);
    assert(relationshipKinds.has(kind), "Unknown relationship semantics");
    const requires = stringArray(item.requires, 32);
    const grants = identity(item.grants);
    assert(
      requires.length > 0 && requires.every((id) => principals.has(id)) && principals.has(grants),
      "Incomplete relationship",
    );
    relationships.push({ id, kind, requires, grants });
  }
  const reachable = new Set(roots);
  let changed = true;
  while (changed) {
    changed = false;
    for (const relationship of relationships) {
      if (
        !reachable.has(relationship.grants) &&
        relationship.requires.every((id) => reachable.has(id))
      ) {
        reachable.add(relationship.grants);
        changed = true;
      }
    }
  }
  for (const id of reachable) {
    const principal = principals.get(id);
    assert(
      principal && !principal.capabilities.some((capability) => forbidden.has(capability)),
      "Observed path reaches forbidden or unknown authority",
    );
  }
  return { reachable: [...reachable].sort() };
}

/** Strict page-chain consistency only; authenticity and completeness against a trusted inventory are separate. */
export function checkObservedPageChain(input: unknown): { ids: string[]; revision: string } {
  assert(Array.isArray(input) && input.length > 0 && input.length <= 1000);
  let cursor: string | null = null;
  let revision: string | undefined;
  const ids = new Set<string>();
  const cursors = new Set<string>();
  for (const [index, raw] of input.entries()) {
    const page = object(raw, "cursor next revision ids");
    assert.equal(page.cursor, cursor, "Authority pagination cursor differs");
    if (cursor !== null) {
      assert(!cursors.has(cursor), "Repeated authority cursor");
      cursors.add(cursor);
    }
    const currentRevision = identity(page.revision);
    if (revision === undefined) revision = currentRevision;
    assert.equal(currentRevision, revision, "Authority source changed between pages");
    for (const id of stringArray(page.ids, 1000)) {
      assert(!ids.has(id), "Duplicate authority object");
      ids.add(id);
      assert(ids.size <= 16384, "Authority inventory too large");
    }
    assert(page.next === null || typeof page.next === "string");
    const next: string | null = page.next === null ? null : identity(page.next);
    assert(
      index === input.length - 1 ? next === null : next !== null,
      "Authority page chain incomplete",
    );
    cursor = next;
  }
  assert(revision !== undefined);
  return { ids: [...ids].sort(), revision };
}

/** The reviewed profile fixes identities and supported provider-specific observation/control formats.
 * Values supplied in a signed payload never choose their own profile or authenticate themselves. */
export type AuthoritySourceProfile = Readonly<{
  domain: string;
  namespace: string;
  provider: string;
  observationType: string;
  enforcementType: string;
}>;
export type LeaseSource = Readonly<{
  domain: string;
  namespace: string;
  provider: string;
  revision: string;
}>;
export type AuthorityLease = Readonly<{
  id: string;
  holder: string;
  fence: string;
  start: number;
  end: number;
  sources: readonly LeaseSource[];
}>;
const sha256Pattern = /^[a-f0-9]{64}$/u;
function safeTime(value: unknown): number {
  assert(
    typeof value === "number" && Number.isSafeInteger(value) && value >= 0,
    "Invalid authority time",
  );
  return value;
}
function opaqueReceipt(value: unknown): void {
  assert(
    typeof value === "string" &&
      value.length > 0 &&
      value.length <= 65536 &&
      /^[A-Za-z0-9_-]+$/u.test(value),
    "Invalid source proof encoding",
  );
  const bytes = Buffer.from(value, "base64url");
  assert(bytes.length > 0 && bytes.toString("base64url") === value, "Noncanonical source proof");
}
/** Exact canonical fields which a reviewed provider-specific adapter may authenticate. */
export function sourceObservationMessage(
  ref: LeaseSource,
  collectedAt: number,
  pagesDigest: string,
): Buffer {
  return Buffer.from(JSON.stringify({ ...ref, collectedAt, pagesDigest }));
}
export function sourceEnforcementMessage(
  ref: LeaseSource,
  lease: Pick<AuthorityLease, "id" | "holder" | "fence" | "start" | "end">,
): Buffer {
  return Buffer.from(
    JSON.stringify({
      ...ref,
      leaseId: lease.id,
      holder: lease.holder,
      fence: lease.fence,
      start: lease.start,
      end: lease.end,
    }),
  );
}
function sourceReference(value: unknown): LeaseSource {
  const ref = object(value, "domain namespace provider revision");
  return {
    domain: identity(ref.domain),
    namespace: identity(ref.namespace),
    provider: identity(ref.provider),
    revision: identity(ref.revision),
  };
}

/** Validate exact signed per-source evidence and the lease's complete source/revision/fence binding.
 * The reviewed source adapter must independently authenticate provider observation bytes, inventory
 * completeness and each enforcement receipt; matching strings, signatures and hashes alone do not. */
export function inspectSourceEvidence(
  rawLease: unknown,
  rawSources: unknown,
  at: number,
  holder: string,
  profiles: readonly AuthoritySourceProfile[],
): AuthorityLease {
  assert(Number.isSafeInteger(at) && at >= 0);
  assert(profiles.length > 0 && profiles.length <= 128);
  const profilesByDomain = new Map<string, AuthoritySourceProfile>();
  for (const profile of profiles) {
    for (const value of [
      profile.domain,
      profile.namespace,
      profile.provider,
      profile.observationType,
      profile.enforcementType,
    ])
      identity(value);
    assert(!profilesByDomain.has(profile.domain), "Duplicate reviewed authority source");
    profilesByDomain.set(profile.domain, profile);
  }
  const data = object(rawLease, "id holder fence start end sources");
  const id = identity(data.id);
  const fence = identity(data.fence);
  assert.equal(data.holder, holder, "Lease holder differs");
  const start = safeTime(data.start);
  const end = safeTime(data.end);
  assert(start <= at && at < end && end - start <= 300, "Lease outside observation interval");
  assert(
    Array.isArray(data.sources) && data.sources.length === profiles.length,
    "Lease source set incomplete",
  );
  const refs = new Map<string, LeaseSource>();
  for (const raw of data.sources) {
    const ref = sourceReference(raw);
    const profile = profilesByDomain.get(ref.domain);
    assert(profile && !refs.has(ref.domain), "Unexpected or duplicate lease source");
    assert.equal(ref.namespace, profile.namespace, "Lease namespace differs");
    assert.equal(ref.provider, profile.provider, "Lease provider differs");
    refs.set(ref.domain, ref);
  }
  assert(
    Array.isArray(rawSources) && rawSources.length === profiles.length,
    "Authority source domains incomplete",
  );
  const seen = new Set<string>();
  for (const raw of rawSources) {
    const source = object(
      raw,
      "domain namespace provider revision collectedAt observation pages enforcement",
    );
    const domain = identity(source.domain);
    const profile = profilesByDomain.get(domain);
    const ref = refs.get(domain);
    assert(profile && ref && !seen.has(domain), "Unexpected or duplicate authority source");
    seen.add(domain);
    assert.equal(source.namespace, ref.namespace, "Source namespace differs");
    assert.equal(source.provider, ref.provider, "Source provider differs");
    assert.equal(source.revision, ref.revision, "Source revision differs");
    const collected = safeTime(source.collectedAt);
    assert(
      start <= collected && collected <= at && at - collected <= 120,
      "Source observation is stale or outside lease",
    );
    const chain = checkObservedPageChain(source.pages);
    assert.equal(chain.revision, ref.revision, "Page revision differs from source");
    const observation = object(source.observation, "type provider revision digest attestation");
    assert.equal(observation.type, profile.observationType, "Unsupported observation control");
    assert.equal(observation.provider, ref.provider, "Observation identity differs");
    assert.equal(observation.revision, ref.revision, "Observation revision differs");
    assert(typeof observation.digest === "string" && sha256Pattern.test(observation.digest));
    assert.equal(
      observation.digest,
      createHash("sha256").update(JSON.stringify(source.pages)).digest("hex"),
      "Observation pages differ",
    );
    opaqueReceipt(observation.attestation);
    const enforcement = object(source.enforcement, "type leaseId fence revision receipt");
    assert.equal(enforcement.type, profile.enforcementType, "Unsupported enforcement control");
    assert.equal(enforcement.leaseId, id, "Enforcement lease differs");
    assert.equal(enforcement.fence, fence, "Enforcement fence differs");
    assert.equal(enforcement.revision, ref.revision, "Enforcement revision differs");
    opaqueReceipt(enforcement.receipt);
  }
  assert.equal(seen.size, profiles.length);
  return Object.freeze({
    id,
    holder,
    fence,
    start,
    end,
    sources: Object.freeze(
      [...refs.values()]
        .sort((a, b) => a.domain.localeCompare(b.domain))
        .map((ref) => Object.freeze(ref)),
    ),
  });
}
