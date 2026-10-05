// SPDX-License-Identifier: AGPL-3.0-only
// D1 FTS5 behaviour of the physical search schema: scope-first MATCH expressions can neither leave their workspace and product nor
// reach another column, whatever the user types, and the external-content index follows insert, update and delete. The same vector
// file pins the C# builder (tests/ArcForges.Cloud.Tests/Physical/Fts5QueryTests.cs). SQLite's FTS5 is the oracle; D1's FTS5 is the same
// engine, but its export, tokenizer build and limits are provider facts this does not prove.
import assert from "node:assert/strict";
import { readFileSync, readdirSync } from "node:fs";
import path from "node:path";
import { DatabaseSync } from "node:sqlite";
import test from "node:test";
import { migrationsDirectory } from "../../eng/verification/physical-schema.ts";

interface Doc {
  id: string;
  workspaceId: string;
  productId: string;
  title: string;
  body: string;
}
const vectors = JSON.parse(
  readFileSync(
    path.resolve(import.meta.dirname, "../ArcForges.Cloud.Tests/Vectors/physical-fts5.json"),
    "utf8",
  ),
) as {
  documents: Doc[];
  queries: {
    name: string;
    scopeWord: string;
    input: string;
    match: string;
    expectedIds: string[];
    prefix?: boolean;
  }[];
  refusals: { name: string; scopeWord: string; input: string }[];
};

function database(): DatabaseSync {
  const db = new DatabaseSync(":memory:");
  for (const file of readdirSync(migrationsDirectory)
    .filter((entry) => /^\d{4}_.+\.sql$/u.test(entry))
    .sort())
    db.exec(readFileSync(path.join(migrationsDirectory, file), "utf8"));
  db.exec("PRAGMA foreign_keys = OFF");
  return db;
}

function addDocument(db: DatabaseSync, doc: Doc): void {
  db.prepare(
    `INSERT INTO search_search_document (search_doc_id, workspace_id, product_id, source_kind, source_id, source_version, title, body, indexed_at, scope_key)
     VALUES (?, ?, ?, 'chat.message', ?, '{}', ?, ?, CAST('1790000000000000' AS INTEGER), ?)`,
  ).run(
    doc.id,
    doc.workspaceId,
    doc.productId,
    doc.id,
    doc.title,
    doc.body,
    `${doc.workspaceId.replaceAll("-", "")}x${doc.productId}`,
  );
}

function search(db: DatabaseSync, match: string): string[] {
  const rows = db
    .prepare(
      `SELECT d.search_doc_id AS id FROM search_search_document_fts f JOIN search_search_document d ON d.rowid = f.rowid WHERE search_search_document_fts MATCH ? ORDER BY d.search_doc_id`,
    )
    .all(match) as { id: string }[];
  return rows.map((row) => row.id);
}

test("a scope-first MATCH returns exactly the documents of its workspace and product and treats every operator as text", () => {
  const db = database();
  for (const doc of vectors.documents) addDocument(db, doc);
  for (const query of vectors.queries) {
    assert.deepEqual(search(db, query.match), query.expectedIds, query.name);
  }
});

test("the scope key is derived: a document cannot be stored under another scope than its workspace and product", () => {
  const db = database();
  const doc = vectors.documents[0] as Doc;
  assert.throws(
    () =>
      db
        .prepare(
          `INSERT INTO search_search_document (search_doc_id, workspace_id, product_id, source_kind, source_id, source_version, title, body, indexed_at, scope_key)
           VALUES (?, ?, 'arcscope', 'chat.message', ?, '{}', 'a', 'b', CAST('1' AS INTEGER), ?)`,
        )
        .run(doc.id, doc.workspaceId, doc.id, "ffffffffffffffffffffffffffffffffxarcscope"),
    /CHECK constraint failed: ck_search_search_document__scope_key__derived/u,
  );
});

test("the FTS5 index follows update and delete of the owning row through its triggers", () => {
  const db = database();
  for (const doc of vectors.documents) addDocument(db, doc);
  const scopeA = vectors.queries[0]?.match as string;
  assert.deepEqual(search(db, scopeA), vectors.queries[0]?.expectedIds);
  db.prepare(
    "UPDATE search_search_document SET title = 'renamed', body = 'nothing' WHERE search_doc_id = ?",
  ).run((vectors.documents[0] as Doc).id);
  assert.deepEqual(search(db, scopeA), [(vectors.documents[1] as Doc).id]);
  db.prepare("DELETE FROM search_search_document WHERE search_doc_id = ?").run(
    (vectors.documents[1] as Doc).id,
  );
  assert.deepEqual(search(db, scopeA), []);
  // The index and its content stay consistent.
  db.exec(
    "INSERT INTO search_search_document_fts (search_search_document_fts) VALUES ('integrity-check')",
  );
});

test("a MATCH without the scope filter is global: the filter is what the host builder always prepends", () => {
  const db = database();
  for (const doc of vectors.documents) addDocument(db, doc);
  const unscoped = search(db, '{title body} : ("hello")');
  const workspaces = new Set(
    (
      db
        .prepare(
          "SELECT workspace_id AS w FROM search_search_document WHERE search_doc_id IN (" +
            unscoped.map(() => "?").join(",") +
            ")",
        )
        .all(...unscoped) as { w: string }[]
    ).map((row) => row.w),
  );
  assert(
    workspaces.size > 1 || unscoped.length > 2,
    "an unscoped query crosses scopes, which is why the builder is the only way to form a query",
  );
});

test("the FTS5 virtual table lives in its own migration so that an export procedure can drop and rebuild exactly that part", () => {
  const files = readdirSync(migrationsDirectory).filter((entry) => /fts5\.sql$/u.test(entry));
  assert.equal(files.length, 1);
  const text = readFileSync(path.join(migrationsDirectory, files[0] as string), "utf8");
  assert.match(text, /CREATE VIRTUAL TABLE/u);
  for (const file of readdirSync(migrationsDirectory).filter(
    (entry) => entry.endsWith(".sql") && !/fts5\.sql$/u.test(entry),
  ))
    assert.doesNotMatch(
      readFileSync(path.join(migrationsDirectory, file), "utf8"),
      /CREATE VIRTUAL TABLE/u,
      file,
    );
});

test("the refusal vectors are documented for the host builder (the TypeScript side has no builder)", () => {
  assert(vectors.refusals.length >= 9);
});
