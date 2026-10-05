-- af-migration: module=search mode=expand
-- The D1 FTS5 virtual table and its index triggers (derived, rebuildable data; Design D1 profile section 8).
CREATE VIRTUAL TABLE "search_search_document_fts" USING fts5("scope_key", "title", "body", content='search_search_document', content_rowid='rowid', tokenize='unicode61 remove_diacritics 2');

CREATE TRIGGER "tr_search_search_document__fts_insert" AFTER INSERT ON "search_search_document"
BEGIN
  INSERT INTO "search_search_document_fts" (rowid, "scope_key", "title", "body") VALUES (new.rowid, new."scope_key", new."title", new."body");
END;

CREATE TRIGGER "tr_search_search_document__fts_delete" AFTER DELETE ON "search_search_document"
BEGIN
  INSERT INTO "search_search_document_fts" ("search_search_document_fts", rowid, "scope_key", "title", "body") VALUES ('delete', old.rowid, old."scope_key", old."title", old."body");
END;

CREATE TRIGGER "tr_search_search_document__fts_update" AFTER UPDATE ON "search_search_document"
BEGIN
  INSERT INTO "search_search_document_fts" ("search_search_document_fts", rowid, "scope_key", "title", "body") VALUES ('delete', old.rowid, old."scope_key", old."title", old."body");
  INSERT INTO "search_search_document_fts" (rowid, "scope_key", "title", "body") VALUES (new.rowid, new."scope_key", new."title", new."body");
END;
