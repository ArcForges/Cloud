// SPDX-License-Identifier: AGPL-3.0-only
import assert from "node:assert/strict";
import { test } from "node:test";
import {
  checkObservedPageChain,
  evaluateObservedAuthority,
} from "../../tooling/ctr06-bootstrap-policy.ts";

test("observed authority follows transitive and jointly required identities", () => {
  const principals = [
    { id: "runner", capabilities: ["metadata", "publication"] },
    { id: "broker", capabilities: ["metadata"] },
    { id: "exchange", capabilities: [] },
    { id: "database-role", capabilities: ["database"] },
  ];
  const relationships = [
    { id: "joint", kind: "assume", requires: ["runner", "exchange"], grants: "database-role" },
  ];
  assert.deepEqual(
    evaluateObservedAuthority({ principals, relationships, roots: ["runner", "broker"] }),
    { reachable: ["broker", "runner"] },
  );
  relationships.push({ id: "token", kind: "exchange", requires: ["broker"], grants: "exchange" });
  assert.throws(
    () => evaluateObservedAuthority({ principals, relationships, roots: ["runner", "broker"] }),
    /forbidden/,
  );
  for (const kind of ["assume", "exchange", "delegate", "invoke", "credential", "inherit"]) {
    assert.throws(
      () =>
        evaluateObservedAuthority({
          principals,
          relationships: [{ id: "x", kind, requires: ["runner"], grants: "database-role" }],
          roots: ["runner"],
        }),
      /forbidden/,
    );
  }
});

test("unknown semantics, incomplete nodes, duplicate facts and reachable unknown capability fail", () => {
  const principals = [
    { id: "runner", capabilities: ["metadata"] },
    { id: "unknown-role", capabilities: ["unknown"] },
  ];
  assert.throws(
    () =>
      evaluateObservedAuthority({
        principals,
        roots: ["runner"],
        relationships: [
          { id: "x", kind: "notification", requires: ["runner"], grants: "unknown-role" },
        ],
      }),
    /Unknown relationship/,
  );
  assert.throws(
    () =>
      evaluateObservedAuthority({
        principals,
        roots: ["runner"],
        relationships: [{ id: "x", kind: "invoke", requires: ["runner"], grants: "unknown-role" }],
      }),
    /unknown authority/,
  );
  assert.throws(() =>
    evaluateObservedAuthority({ principals, roots: ["absent"], relationships: [] }),
  );
  assert.throws(() =>
    evaluateObservedAuthority({
      principals: [...principals, principals[0]],
      roots: ["runner"],
      relationships: [],
    }),
  );
  assert.throws(() =>
    evaluateObservedAuthority({
      principals,
      roots: ["runner"],
      relationships: [{ id: "x", kind: "invoke", requires: ["missing"], grants: "unknown-role" }],
    }),
  );
});

test("page-chain checks detect omitted, repeated or changed source observations", () => {
  const first = { cursor: null, next: "next", revision: "v1", ids: ["a"] };
  const second = { cursor: "next", next: null, revision: "v1", ids: ["b"] };
  assert.deepEqual(checkObservedPageChain([first, second]), { ids: ["a", "b"], revision: "v1" });
  assert.throws(() => checkObservedPageChain([first]));
  assert.throws(() => checkObservedPageChain([first, { ...second, revision: "v2" }]));
  assert.throws(() => checkObservedPageChain([first, { ...second, ids: ["a"] }]));
  assert.throws(() => checkObservedPageChain([first, { ...second, cursor: "wrong" }]));
  assert.throws(() =>
    checkObservedPageChain([
      { cursor: null, next: "a", revision: "v1", ids: [] },
      { cursor: "a", next: "a", revision: "v1", ids: [] },
      { cursor: "a", next: null, revision: "v1", ids: [] },
    ]),
  );
});
