-- af-migration: module=search mode=expand
-- Baseline physical schema of the search owner (generated from Physical/manifest/search.json; Design D1 profile section 2).
CREATE TABLE "search_cf_instance_inventory" (
  "kind" TEXT NOT NULL,
  "instance_id" TEXT NOT NULL,
  "recovery_generation" INTEGER NOT NULL,
  "workspace_id" TEXT NOT NULL CONSTRAINT "ck_search_cf_instance_inventory__workspace_id" CHECK (length("workspace_id") = 36 AND "workspace_id" GLOB '????????-????-????-????-????????????' AND "workspace_id" NOT GLOB '*[^0-9a-f-]*'),
  "owner_job_id" TEXT NOT NULL CONSTRAINT "ck_search_cf_instance_inventory__owner_job_id" CHECK (length("owner_job_id") = 36 AND "owner_job_id" GLOB '????????-????-????-????-????????????' AND "owner_job_id" NOT GLOB '*[^0-9a-f-]*'),
  "worker_version" TEXT NOT NULL,
  "deletion_receipt" TEXT,
  "updated_at" INTEGER NOT NULL,
  CONSTRAINT "pk_search_cf_instance_inventory" PRIMARY KEY ("kind", "instance_id", "recovery_generation")
) STRICT;

CREATE TABLE "search_inference_job" (
  "job_id" TEXT NOT NULL CONSTRAINT "ck_search_inference_job__job_id" CHECK (length("job_id") = 36 AND "job_id" GLOB '????????-????-????-????-????????????' AND "job_id" NOT GLOB '*[^0-9a-f-]*'),
  "workspace_id" TEXT NOT NULL CONSTRAINT "ck_search_inference_job__workspace_id" CHECK (length("workspace_id") = 36 AND "workspace_id" GLOB '????????-????-????-????-????????????' AND "workspace_id" NOT GLOB '*[^0-9a-f-]*'),
  "principal_id" TEXT NOT NULL CONSTRAINT "ck_search_inference_job__principal_id" CHECK (length("principal_id") = 36 AND "principal_id" GLOB '????????-????-????-????-????????????' AND "principal_id" NOT GLOB '*[^0-9a-f-]*'),
  "service_term_id" TEXT NOT NULL CONSTRAINT "ck_search_inference_job__service_term_id" CHECK (length("service_term_id") = 36 AND "service_term_id" GLOB '????????-????-????-????-????????????' AND "service_term_id" NOT GLOB '*[^0-9a-f-]*'),
  "purpose" INTEGER NOT NULL CONSTRAINT "ck_search_inference_job__purpose" CHECK ("purpose" IN (1, 2)),
  "input_hash" BLOB NOT NULL CONSTRAINT "ck_search_inference_job__input_hash" CHECK (length("input_hash") = 32),
  "source_manifest_ref" BLOB NOT NULL,
  "source_set_hash" BLOB NOT NULL CONSTRAINT "ck_search_inference_job__source_set_hash" CHECK (length("source_set_hash") = 32),
  "model_descriptor_id" TEXT NOT NULL CONSTRAINT "ck_search_inference_job__model_descriptor_id" CHECK (length("model_descriptor_id") = 36 AND "model_descriptor_id" GLOB '????????-????-????-????-????????????' AND "model_descriptor_id" NOT GLOB '*[^0-9a-f-]*'),
  "config_revision_id" TEXT NOT NULL CONSTRAINT "ck_search_inference_job__config_revision_id" CHECK (length("config_revision_id") = 36 AND "config_revision_id" GLOB '????????-????-????-????-????????????' AND "config_revision_id" NOT GLOB '*[^0-9a-f-]*'),
  "profile" TEXT NOT NULL,
  "state" INTEGER NOT NULL CONSTRAINT "ck_search_inference_job__state" CHECK ("state" IN (1, 2, 3, 4, 5, 6)),
  "reason" TEXT NOT NULL CONSTRAINT "ck_search_inference_job__reason" CHECK (length("reason") BETWEEN 1 AND 128 AND "reason" NOT GLOB '*[^A-Za-z0-9._:/-]*'),
  "rev" INTEGER NOT NULL CONSTRAINT "ck_search_inference_job__rev" CHECK ("rev" >= 0),
  "created_at" INTEGER NOT NULL,
  "updated_at" INTEGER NOT NULL,
  "deadline" INTEGER NOT NULL,
  "logical_request_id" TEXT NOT NULL CONSTRAINT "ck_search_inference_job__logical_request_id" CHECK (length("logical_request_id") = 36 AND "logical_request_id" GLOB '????????-????-????-????-????????????' AND "logical_request_id" NOT GLOB '*[^0-9a-f-]*'),
  "provider_attempt_id" TEXT CONSTRAINT "ck_search_inference_job__provider_attempt_id" CHECK (length("provider_attempt_id") = 36 AND "provider_attempt_id" GLOB '????????-????-????-????-????????????' AND "provider_attempt_id" NOT GLOB '*[^0-9a-f-]*'),
  "intent_receipt" TEXT NOT NULL CONSTRAINT "ck_search_inference_job__intent_receipt" CHECK (length("intent_receipt") = 36 AND "intent_receipt" GLOB '????????-????-????-????-????????????' AND "intent_receipt" NOT GLOB '*[^0-9a-f-]*'),
  "workflow_id" TEXT NOT NULL,
  "worker_version" TEXT,
  "recovery_generation" INTEGER NOT NULL,
  "lease_holder" TEXT,
  "lease_epoch" INTEGER NOT NULL,
  "lease_expires_at" INTEGER,
  "result_ref" TEXT CONSTRAINT "ck_search_inference_job__result_ref" CHECK (length("result_ref") = 36 AND "result_ref" GLOB '????????-????-????-????-????????????' AND "result_ref" NOT GLOB '*[^0-9a-f-]*'),
  "outcome_receipt" TEXT,
  "outcome_hash" BLOB CONSTRAINT "ck_search_inference_job__outcome_hash" CHECK (length("outcome_hash") = 32),
  "source_publication_ref" TEXT CONSTRAINT "ck_search_inference_job__source_publication_ref" CHECK (length("source_publication_ref") = 36 AND "source_publication_ref" GLOB '????????-????-????-????-????????????' AND "source_publication_ref" NOT GLOB '*[^0-9a-f-]*'),
  "cancellation_requested_at" INTEGER,
  "completed_at" INTEGER,
  CONSTRAINT "pk_search_inference_job" PRIMARY KEY ("job_id"),
  CONSTRAINT "ck_search_inference_job__succeeded_has_result" CHECK ("state" <> 4 OR ("result_ref" IS NOT NULL AND "outcome_hash" IS NOT NULL)),
  CONSTRAINT "ck_search_inference_job__unknown_no_completion" CHECK ("state" <> 3 OR ("result_ref" IS NULL AND "completed_at" IS NULL))
) STRICT;

CREATE UNIQUE INDEX "ux_search_inference_job__logical_request_id" ON "search_inference_job" ("logical_request_id");

CREATE UNIQUE INDEX "ux_search_inference_job__provider_attempt_id" ON "search_inference_job" ("provider_attempt_id");

CREATE TABLE "search_retrieval_chunk" (
  "chunk_id" TEXT NOT NULL CONSTRAINT "ck_search_retrieval_chunk__chunk_id" CHECK (length("chunk_id") = 36 AND "chunk_id" GLOB '????????-????-????-????-????????????' AND "chunk_id" NOT GLOB '*[^0-9a-f-]*'),
  "workspace_id" TEXT NOT NULL CONSTRAINT "ck_search_retrieval_chunk__workspace_id" CHECK (length("workspace_id") = 36 AND "workspace_id" GLOB '????????-????-????-????-????????????' AND "workspace_id" NOT GLOB '*[^0-9a-f-]*'),
  "product_id" TEXT NOT NULL CONSTRAINT "ck_search_retrieval_chunk__product_id" CHECK ("product_id" IN ('arcscope', 'companion')),
  "source_kind" TEXT NOT NULL CONSTRAINT "ck_search_retrieval_chunk__source_kind" CHECK (length("source_kind") BETWEEN 1 AND 128 AND "source_kind" NOT GLOB '*[^A-Za-z0-9._:/-]*'),
  "source_id" TEXT NOT NULL CONSTRAINT "ck_search_retrieval_chunk__source_id" CHECK (length("source_id") = 36 AND "source_id" GLOB '????????-????-????-????-????????????' AND "source_id" NOT GLOB '*[^0-9a-f-]*'),
  "source_version" TEXT NOT NULL CONSTRAINT "ck_search_retrieval_chunk__source_version" CHECK (json_valid("source_version")),
  "anchor_id" TEXT CONSTRAINT "ck_search_retrieval_chunk__anchor_id" CHECK (length("anchor_id") = 36 AND "anchor_id" GLOB '????????-????-????-????-????????????' AND "anchor_id" NOT GLOB '*[^0-9a-f-]*'),
  "chunk_ordinal" INTEGER NOT NULL CONSTRAINT "ck_search_retrieval_chunk__chunk_ordinal" CHECK ("chunk_ordinal" BETWEEN -2147483648 AND 2147483647),
  "text" TEXT NOT NULL,
  "embedding_model_id" TEXT NOT NULL,
  "embedded_at" INTEGER NOT NULL,
  CONSTRAINT "pk_search_retrieval_chunk" PRIMARY KEY ("chunk_id")
) STRICT;

CREATE INDEX "ix_search_retrieval_chunk__source_kind_source_id" ON "search_retrieval_chunk" ("source_kind", "source_id");

CREATE TABLE "search_search_document" (
  "search_doc_id" TEXT NOT NULL CONSTRAINT "ck_search_search_document__search_doc_id" CHECK (length("search_doc_id") = 36 AND "search_doc_id" GLOB '????????-????-????-????-????????????' AND "search_doc_id" NOT GLOB '*[^0-9a-f-]*'),
  "workspace_id" TEXT NOT NULL CONSTRAINT "ck_search_search_document__workspace_id" CHECK (length("workspace_id") = 36 AND "workspace_id" GLOB '????????-????-????-????-????????????' AND "workspace_id" NOT GLOB '*[^0-9a-f-]*'),
  "product_id" TEXT NOT NULL CONSTRAINT "ck_search_search_document__product_id" CHECK ("product_id" IN ('arcscope', 'companion')),
  "source_kind" TEXT NOT NULL CONSTRAINT "ck_search_search_document__source_kind" CHECK (length("source_kind") BETWEEN 1 AND 128 AND "source_kind" NOT GLOB '*[^A-Za-z0-9._:/-]*'),
  "source_id" TEXT NOT NULL CONSTRAINT "ck_search_search_document__source_id" CHECK (length("source_id") = 36 AND "source_id" GLOB '????????-????-????-????-????????????' AND "source_id" NOT GLOB '*[^0-9a-f-]*'),
  "source_version" TEXT NOT NULL CONSTRAINT "ck_search_search_document__source_version" CHECK (json_valid("source_version")),
  "title" TEXT NOT NULL,
  "body" TEXT NOT NULL,
  "indexed_at" INTEGER NOT NULL,
  "scope_key" TEXT NOT NULL CONSTRAINT "ck_search_search_document__scope_key__derived" CHECK ("scope_key" = replace("workspace_id", '-', '') || 'x' || "product_id"),
  CONSTRAINT "pk_search_search_document" PRIMARY KEY ("search_doc_id")
) STRICT;

CREATE UNIQUE INDEX "ux_search_search_document__workspace_id_product_id_source_kind_source_id" ON "search_search_document" ("workspace_id", "product_id", "source_kind", "source_id");
