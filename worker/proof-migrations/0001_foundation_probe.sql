-- PRF.07 foundation probe schema. It belongs to the isolated proof environment database only.
-- Product modules own their tables and numbered migrations under RES-cloud-d1-migrations; this
-- file creates no product table and is applied only by the explicit proof deployment step.
CREATE TABLE probe_schema (
  version INTEGER NOT NULL PRIMARY KEY CHECK (version = 1)
) STRICT;
INSERT INTO probe_schema (version) VALUES (1);

-- A false precondition violates this constraint and rolls the whole D1 batch back.
CREATE TABLE probe_guard (
  command_id TEXT NOT NULL PRIMARY KEY,
  allowed INTEGER NOT NULL CONSTRAINT af_guard_failed CHECK (allowed = 1)
) STRICT;

CREATE TABLE probe_exact (
  scope TEXT NOT NULL,
  id TEXT NOT NULL,
  signed_value INTEGER NOT NULL,
  unsigned_text TEXT NOT NULL CHECK (length(unsigned_text) BETWEEN 1 AND 20 AND unsigned_text NOT GLOB '*[^0-9]*'),
  decimal_text TEXT NOT NULL CHECK (length(decimal_text) BETWEEN 1 AND 64),
  payload BLOB,
  revision INTEGER NOT NULL CHECK (revision >= 1),
  PRIMARY KEY (scope, id)
) STRICT;

CREATE TABLE probe_account (
  scope TEXT NOT NULL,
  id TEXT NOT NULL,
  balance INTEGER NOT NULL CHECK (balance >= 0),
  revision INTEGER NOT NULL CHECK (revision >= 1),
  PRIMARY KEY (scope, id)
) STRICT;

CREATE TABLE probe_receipt (
  scope TEXT NOT NULL,
  command_id TEXT NOT NULL,
  request_hash TEXT NOT NULL,
  result_json TEXT NOT NULL CHECK (json_valid(result_json)),
  PRIMARY KEY (scope, command_id)
) STRICT;

CREATE TABLE probe_outbox (
  sequence INTEGER PRIMARY KEY AUTOINCREMENT,
  scope TEXT NOT NULL,
  command_id TEXT NOT NULL,
  event_key TEXT NOT NULL,
  payload_json TEXT NOT NULL CHECK (json_valid(payload_json)),
  UNIQUE (scope, command_id, event_key)
) STRICT;

CREATE TABLE probe_session (
  scope TEXT NOT NULL,
  session_id TEXT NOT NULL,
  handle_hash BLOB NOT NULL CHECK (length(handle_hash) = 32),
  user_id TEXT NOT NULL,
  device_id TEXT NOT NULL,
  workspace_ids_json TEXT NOT NULL CHECK (json_valid(workspace_ids_json)),
  recovery_generation INTEGER NOT NULL CHECK (recovery_generation >= 0),
  auth_epoch INTEGER NOT NULL CHECK (auth_epoch >= 0),
  created_at INTEGER NOT NULL,
  absolute_expires_at INTEGER NOT NULL,
  idle_expires_at INTEGER NOT NULL,
  last_seen_at INTEGER NOT NULL,
  revoked_at INTEGER,
  revoke_reason TEXT,
  PRIMARY KEY (scope, session_id),
  UNIQUE (scope, handle_hash)
) STRICT;

CREATE TABLE probe_job (
  scope TEXT NOT NULL,
  job_id TEXT NOT NULL,
  total INTEGER NOT NULL CHECK (total BETWEEN 1 AND 1000),
  cursor INTEGER NOT NULL CHECK (cursor >= 0 AND cursor <= total),
  fence INTEGER NOT NULL CHECK (fence >= 0),
  lease_owner TEXT,
  lease_until INTEGER,
  state TEXT NOT NULL CHECK (state IN ('running', 'complete')),
  checksum TEXT NOT NULL CHECK (length(checksum) BETWEEN 1 AND 20 AND checksum NOT GLOB '*[^0-9]*'),
  revision INTEGER NOT NULL CHECK (revision >= 1),
  PRIMARY KEY (scope, job_id)
) STRICT;

CREATE TABLE probe_job_item (
  scope TEXT NOT NULL,
  job_id TEXT NOT NULL,
  item_no INTEGER NOT NULL CHECK (item_no >= 0),
  amount INTEGER NOT NULL,
  PRIMARY KEY (scope, job_id, item_no),
  FOREIGN KEY (scope, job_id) REFERENCES probe_job (scope, job_id)
) STRICT;

-- Consumer inbox: duplicate Queue delivery cannot repeat a business effect.
CREATE TABLE probe_inbox (
  scope TEXT NOT NULL,
  consumer TEXT NOT NULL,
  event_id TEXT NOT NULL,
  generation INTEGER NOT NULL CHECK (generation >= 0),
  PRIMARY KEY (scope, consumer, event_id, generation)
) STRICT;
