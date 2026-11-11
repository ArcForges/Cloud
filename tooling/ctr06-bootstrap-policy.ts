// SPDX-License-Identifier: AGPL-3.0-only
// This evaluates the supplied observations. It does not establish their source, completeness or enforcement.
import assert from "node:assert/strict";
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
