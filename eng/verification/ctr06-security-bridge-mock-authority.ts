// SPDX-License-Identifier: AGPL-3.0-only
// ISOLATED TEST MODEL ONLY. This is not an accepted production trust model or evidence source.
// A signed mock graph does not prove that its external permission inventory is complete.
import assert from "node:assert/strict";
import { type KeyObject, verify } from "node:crypto";
import { parseDocument } from "../../tooling/provenance.ts";

const capabilityNames = [
  "metadata",
  "publication",
  "database",
  "rollout",
  "deployment",
  "activation",
  "unknown",
];
const delegationKinds = ["assume", "exchange", "delegate", "invoke", "credential"];
const edgeKinds = [...delegationKinds, "notification"];
const identity = /^[A-Za-z0-9._:-]{1,128}$/u;
function record(value: unknown, keys: string[]) {
  assert(value && typeof value === "object" && !Array.isArray(value));
  const result = value as Record<string, unknown>;
  assert.deepEqual(Object.keys(result).sort(), [...keys].sort());
  return result;
}
function number(value: unknown) {
  assert(typeof value === "number" && Number.isSafeInteger(value));
  return value;
}
function name(value: unknown) {
  assert(typeof value === "string" && identity.test(value));
  return value;
}

export type MockContext = {
  repository: string;
  ref: string;
  workflow: string;
  producerCommit: string;
  runId: string;
  runAttempt: number;
  sourceCommit: string;
  sourceTree: string;
  sourceArchiveSha256: string;
  nonce: string;
};

/** Verifies a test-key signature and evaluates the graph; it is never called by the live gate. */
export function inspectMockAuthority(
  payload: Buffer,
  signature: Buffer,
  publicKey: KeyObject,
  context: MockContext,
  now: number,
) {
  assert.equal(publicKey.type, "public");
  assert.equal(publicKey.asymmetricKeyType, "ed25519");
  assert.equal(signature.length, 64);
  assert(verify(null, payload, publicKey, signature), "Mock authority signature differs");
  const document = record(parseDocument(payload), [
    "schema",
    "issuer",
    "audience",
    "subject",
    "context",
    "issuedAt",
    "expiresAt",
    "principals",
    "edges",
  ]);
  assert.equal(document.schema, "arcforges.ctr06.mock-authority.v1");
  assert.equal(document.issuer, "test-only");
  assert.equal(document.audience, "test-only-security-bridge");
  assert.deepEqual(document.context, context, "Mock context differs");
  assert.match(context.nonce, /^[a-f0-9]{32}$/u);
  const issued = number(document.issuedAt);
  const expiry = number(document.expiresAt);
  assert(
    Number.isSafeInteger(now) &&
      issued <= now + 30 &&
      expiry > now &&
      expiry > issued &&
      expiry - issued <= 120,
    "Mock evidence is stale",
  );
  assert(
    Array.isArray(document.principals) &&
      document.principals.length > 0 &&
      document.principals.length <= 128,
  );
  assert(Array.isArray(document.edges) && document.edges.length <= 512);
  const nodes = new Map<string, string[]>();
  for (const item of document.principals) {
    const principal = record(item, ["id", "capabilities"]);
    const id = name(principal.id);
    assert(!nodes.has(id));
    assert(Array.isArray(principal.capabilities));
    const caps = principal.capabilities.map(name);
    assert(
      caps.every((cap) => capabilityNames.includes(cap)) && new Set(caps).size === caps.length,
    );
    nodes.set(id, caps);
  }
  const subject = name(document.subject);
  assert(nodes.has(subject));
  const adjacent = new Map<string, string[]>();
  const seenEdges = new Set<string>();
  for (const item of document.edges) {
    const edge = record(item, ["from", "to", "kind"]);
    const from = name(edge.from);
    const to = name(edge.to);
    const kind = name(edge.kind);
    assert(nodes.has(from) && nodes.has(to) && edgeKinds.includes(kind));
    const key = `${from}\0${kind}\0${to}`;
    assert(!seenEdges.has(key));
    seenEdges.add(key);
    if (delegationKinds.includes(kind)) adjacent.set(from, [...(adjacent.get(from) ?? []), to]);
  }
  const visited = new Set<string>();
  const pending = [subject];
  while (pending.length) {
    const id = pending.pop();
    assert(id);
    if (visited.has(id)) continue;
    visited.add(id);
    const caps = nodes.get(id);
    assert(caps);
    assert(
      caps.every((cap) => ["metadata", "publication"].includes(cap)),
      "Mock path reaches forbidden or unknown authority",
    );
    pending.push(...(adjacent.get(id) ?? []));
  }
  return {
    scope: "MOCKED isolated test model; external completeness NOT PROVEN",
    reachable: [...visited].sort(),
  };
}
