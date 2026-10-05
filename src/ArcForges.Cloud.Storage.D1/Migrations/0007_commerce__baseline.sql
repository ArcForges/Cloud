-- af-migration: module=commerce mode=expand
-- Baseline physical schema of the commerce owner (generated from Physical/manifest/commerce.json; Design D1 profile section 2).
CREATE TABLE "commerce_attempt_usage" (
  "attempt_usage_id" TEXT NOT NULL CONSTRAINT "ck_commerce_attempt_usage__attempt_usage_id" CHECK (length("attempt_usage_id") = 36 AND "attempt_usage_id" GLOB '????????-????-????-????-????????????' AND "attempt_usage_id" NOT GLOB '*[^0-9a-f-]*'),
  "provider_attempt_id" TEXT NOT NULL CONSTRAINT "ck_commerce_attempt_usage__provider_attempt_id" CHECK (length("provider_attempt_id") = 36 AND "provider_attempt_id" GLOB '????????-????-????-????-????????????' AND "provider_attempt_id" NOT GLOB '*[^0-9a-f-]*'),
  "usage_revision" INTEGER NOT NULL CONSTRAINT "ck_commerce_attempt_usage__usage_revision" CHECK ("usage_revision" BETWEEN -2147483648 AND 2147483647),
  "category" TEXT NOT NULL,
  "quantity" INTEGER NOT NULL,
  "unit" TEXT NOT NULL,
  "recorded_at" INTEGER NOT NULL,
  CONSTRAINT "pk_commerce_attempt_usage" PRIMARY KEY ("attempt_usage_id"),
  CONSTRAINT "fk_commerce_attempt_usage__provider_attempt_id" FOREIGN KEY ("provider_attempt_id") REFERENCES "commerce_provider_attempt" ("provider_attempt_id") ON DELETE RESTRICT,
  CONSTRAINT "ck_commerce_attempt_usage__quantity_nonnegative" CHECK ("quantity" >= 0)
) STRICT;

CREATE UNIQUE INDEX "ux_commerce_attempt_usage__provider_attempt_id_usage_revision_category" ON "commerce_attempt_usage" ("provider_attempt_id", "usage_revision", "category");

CREATE TABLE "commerce_billing_account" (
  "billing_account_id" TEXT NOT NULL CONSTRAINT "ck_commerce_billing_account__billing_account_id" CHECK (length("billing_account_id") = 36 AND "billing_account_id" GLOB '????????-????-????-????-????????????' AND "billing_account_id" NOT GLOB '*[^0-9a-f-]*'),
  "owner_user_id" TEXT NOT NULL CONSTRAINT "ck_commerce_billing_account__owner_user_id" CHECK (length("owner_user_id") = 36 AND "owner_user_id" GLOB '????????-????-????-????-????????????' AND "owner_user_id" NOT GLOB '*[^0-9a-f-]*'),
  "created_at" INTEGER NOT NULL,
  "rev" INTEGER NOT NULL CONSTRAINT "ck_commerce_billing_account__rev" CHECK ("rev" >= 0),
  CONSTRAINT "pk_commerce_billing_account" PRIMARY KEY ("billing_account_id")
) STRICT;

CREATE TABLE "commerce_checkout_attempt" (
  "attempt_id" TEXT NOT NULL CONSTRAINT "ck_commerce_checkout_attempt__attempt_id" CHECK (length("attempt_id") = 36 AND "attempt_id" GLOB '????????-????-????-????-????????????' AND "attempt_id" NOT GLOB '*[^0-9a-f-]*'),
  "intent_id" TEXT NOT NULL CONSTRAINT "ck_commerce_checkout_attempt__intent_id" CHECK (length("intent_id") = 36 AND "intent_id" GLOB '????????-????-????-????-????????????' AND "intent_id" NOT GLOB '*[^0-9a-f-]*'),
  "billing_account_id" TEXT NOT NULL CONSTRAINT "ck_commerce_checkout_attempt__billing_account_id" CHECK (length("billing_account_id") = 36 AND "billing_account_id" GLOB '????????-????-????-????-????????????' AND "billing_account_id" NOT GLOB '*[^0-9a-f-]*'),
  "workspace_id" TEXT NOT NULL CONSTRAINT "ck_commerce_checkout_attempt__workspace_id" CHECK (length("workspace_id") = 36 AND "workspace_id" GLOB '????????-????-????-????-????????????' AND "workspace_id" NOT GLOB '*[^0-9a-f-]*'),
  "offer_id" TEXT NOT NULL CONSTRAINT "ck_commerce_checkout_attempt__offer_id" CHECK (length("offer_id") = 36 AND "offer_id" GLOB '????????-????-????-????-????????????' AND "offer_id" NOT GLOB '*[^0-9a-f-]*'),
  "price_version_id" TEXT NOT NULL CONSTRAINT "ck_commerce_checkout_attempt__price_version_id" CHECK (length("price_version_id") = 36 AND "price_version_id" GLOB '????????-????-????-????-????????????' AND "price_version_id" NOT GLOB '*[^0-9a-f-]*'),
  "provider" TEXT NOT NULL,
  "external_session_ref" TEXT,
  "state" INTEGER NOT NULL CONSTRAINT "ck_commerce_checkout_attempt__state" CHECK ("state" IN (1, 2, 3, 4, 5, 6)),
  "request_hash" BLOB NOT NULL CONSTRAINT "ck_commerce_checkout_attempt__request_hash" CHECK (length("request_hash") = 32),
  "created_at" INTEGER NOT NULL,
  "expires_at" INTEGER NOT NULL,
  "rev" INTEGER NOT NULL CONSTRAINT "ck_commerce_checkout_attempt__rev" CHECK ("rev" >= 0),
  CONSTRAINT "pk_commerce_checkout_attempt" PRIMARY KEY ("attempt_id"),
  CONSTRAINT "fk_commerce_checkout_attempt__intent_id" FOREIGN KEY ("intent_id") REFERENCES "commerce_purchase_intent" ("purchase_intent_id") ON DELETE RESTRICT,
  CONSTRAINT "fk_commerce_checkout_attempt__billing_account_id" FOREIGN KEY ("billing_account_id") REFERENCES "commerce_billing_account" ("billing_account_id") ON DELETE RESTRICT,
  CONSTRAINT "fk_commerce_checkout_attempt__workspace_id" FOREIGN KEY ("workspace_id") REFERENCES "workspace_workspace" ("workspace_id") ON DELETE RESTRICT,
  CONSTRAINT "fk_commerce_checkout_attempt__offer_id" FOREIGN KEY ("offer_id") REFERENCES "commerce_offer" ("offer_id") ON DELETE RESTRICT,
  CONSTRAINT "fk_commerce_checkout_attempt__price_version_id" FOREIGN KEY ("price_version_id") REFERENCES "commerce_price_version" ("price_version_id") ON DELETE RESTRICT
) STRICT;

CREATE UNIQUE INDEX "ux_commerce_checkout_attempt__provider_external_session_ref" ON "commerce_checkout_attempt" ("provider", "external_session_ref");

CREATE INDEX "ix_commerce_checkout_attempt__intent_id_created_at" ON "commerce_checkout_attempt" ("intent_id", "created_at");

CREATE UNIQUE INDEX "ux_commerce_checkout_attempt__intent_id" ON "commerce_checkout_attempt" ("intent_id") WHERE "state" NOT IN (4, 5, 6);

CREATE TABLE "commerce_compensation_adjustment" (
  "adjustment_id" TEXT NOT NULL CONSTRAINT "ck_commerce_compensation_adjustment__adjustment_id" CHECK (length("adjustment_id") = 36 AND "adjustment_id" GLOB '????????-????-????-????-????????????' AND "adjustment_id" NOT GLOB '*[^0-9a-f-]*'),
  "workspace_id" TEXT NOT NULL CONSTRAINT "ck_commerce_compensation_adjustment__workspace_id" CHECK (length("workspace_id") = 36 AND "workspace_id" GLOB '????????-????-????-????-????????????' AND "workspace_id" NOT GLOB '*[^0-9a-f-]*'),
  "source_lot_id" TEXT NOT NULL CONSTRAINT "ck_commerce_compensation_adjustment__source_lot_id" CHECK (length("source_lot_id") = 36 AND "source_lot_id" GLOB '????????-????-????-????-????????????' AND "source_lot_id" NOT GLOB '*[^0-9a-f-]*'),
  "new_lot_id" TEXT CONSTRAINT "ck_commerce_compensation_adjustment__new_lot_id" CHECK (length("new_lot_id") = 36 AND "new_lot_id" GLOB '????????-????-????-????-????????????' AND "new_lot_id" NOT GLOB '*[^0-9a-f-]*'),
  "delta_micro" INTEGER NOT NULL,
  "proposal_id" TEXT NOT NULL CONSTRAINT "ck_commerce_compensation_adjustment__proposal_id" CHECK (length("proposal_id") = 36 AND "proposal_id" GLOB '????????-????-????-????-????????????' AND "proposal_id" NOT GLOB '*[^0-9a-f-]*'),
  "created_at" INTEGER NOT NULL,
  "command_id" TEXT NOT NULL CONSTRAINT "ck_commerce_compensation_adjustment__command_id" CHECK (length("command_id") = 36 AND "command_id" GLOB '????????-????-????-????-????????????' AND "command_id" NOT GLOB '*[^0-9a-f-]*'),
  CONSTRAINT "pk_commerce_compensation_adjustment" PRIMARY KEY ("adjustment_id"),
  CONSTRAINT "fk_commerce_compensation_adjustment__workspace_id" FOREIGN KEY ("workspace_id") REFERENCES "workspace_workspace" ("workspace_id") ON DELETE RESTRICT,
  CONSTRAINT "fk_commerce_compensation_adjustment__source_lot_id" FOREIGN KEY ("source_lot_id") REFERENCES "commerce_credit_lot" ("credit_lot_id") ON DELETE RESTRICT,
  CONSTRAINT "fk_commerce_compensation_adjustment__new_lot_id" FOREIGN KEY ("new_lot_id") REFERENCES "commerce_credit_lot" ("credit_lot_id") ON DELETE RESTRICT,
  CONSTRAINT "fk_commerce_compensation_adjustment__proposal_id" FOREIGN KEY ("proposal_id") REFERENCES "audit_operator_proposal" ("proposal_id") ON DELETE RESTRICT,
  CONSTRAINT "ck_commerce_compensation_adjustment__delta_nonzero" CHECK ("delta_micro" <> 0),
  CONSTRAINT "ck_commerce_compensation_adjustment__new_lot_iff_positive" CHECK (("delta_micro" > 0) = ("new_lot_id" IS NOT NULL))
) STRICT;

CREATE UNIQUE INDEX "ux_commerce_compensation_adjustment__proposal_id" ON "commerce_compensation_adjustment" ("proposal_id");

CREATE UNIQUE INDEX "ux_commerce_compensation_adjustment__command_id" ON "commerce_compensation_adjustment" ("command_id");

CREATE TRIGGER "tr_commerce_compensation_adjustment__immutable_update" BEFORE UPDATE ON "commerce_compensation_adjustment"
BEGIN
  SELECT RAISE(ABORT, 'CHECK constraint failed: af_immutable_commerce_compensation_adjustment');
END;

CREATE TRIGGER "tr_commerce_compensation_adjustment__immutable_delete" BEFORE DELETE ON "commerce_compensation_adjustment"
BEGIN
  SELECT RAISE(ABORT, 'CHECK constraint failed: af_immutable_commerce_compensation_adjustment');
END;

CREATE TABLE "commerce_credit_lot" (
  "credit_lot_id" TEXT NOT NULL CONSTRAINT "ck_commerce_credit_lot__credit_lot_id" CHECK (length("credit_lot_id") = 36 AND "credit_lot_id" GLOB '????????-????-????-????-????????????' AND "credit_lot_id" NOT GLOB '*[^0-9a-f-]*'),
  "workspace_id" TEXT NOT NULL CONSTRAINT "ck_commerce_credit_lot__workspace_id" CHECK (length("workspace_id") = 36 AND "workspace_id" GLOB '????????-????-????-????-????????????' AND "workspace_id" NOT GLOB '*[^0-9a-f-]*'),
  "lot_class" INTEGER NOT NULL CONSTRAINT "ck_commerce_credit_lot__lot_class" CHECK ("lot_class" IN (1, 2)),
  "original_micro" INTEGER NOT NULL,
  "remaining_micro" INTEGER NOT NULL,
  "held_micro" INTEGER NOT NULL,
  "expires_at" INTEGER,
  "refund_hold" INTEGER NOT NULL CONSTRAINT "ck_commerce_credit_lot__refund_hold" CHECK ("refund_hold" IN (0, 1)),
  "source_ref" TEXT,
  "created_at" INTEGER NOT NULL,
  "rev" INTEGER NOT NULL CONSTRAINT "ck_commerce_credit_lot__rev" CHECK ("rev" >= 0),
  CONSTRAINT "pk_commerce_credit_lot" PRIMARY KEY ("credit_lot_id"),
  CONSTRAINT "fk_commerce_credit_lot__workspace_id" FOREIGN KEY ("workspace_id") REFERENCES "workspace_workspace" ("workspace_id") ON DELETE RESTRICT,
  CONSTRAINT "ck_commerce_credit_lot__balances_nonnegative" CHECK ("remaining_micro" >= 0 AND "held_micro" >= 0 AND "held_micro" <= "remaining_micro"),
  CONSTRAINT "ck_commerce_credit_lot__purchased_never_expires" CHECK ("lot_class" <> 1 OR "expires_at" IS NULL),
  CONSTRAINT "ck_commerce_credit_lot__compensation_expires" CHECK ("lot_class" <> 2 OR "expires_at" IS NOT NULL)
) STRICT;

CREATE INDEX "ix_commerce_credit_lot__workspace_id_lot_class_refund_hold_expires_at_created_at" ON "commerce_credit_lot" ("workspace_id", "lot_class", "refund_hold", "expires_at", "created_at");

CREATE TABLE "commerce_credit_transaction" (
  "transaction_id" TEXT NOT NULL CONSTRAINT "ck_commerce_credit_transaction__transaction_id" CHECK (length("transaction_id") = 36 AND "transaction_id" GLOB '????????-????-????-????-????????????' AND "transaction_id" NOT GLOB '*[^0-9a-f-]*'),
  "workspace_id" TEXT NOT NULL CONSTRAINT "ck_commerce_credit_transaction__workspace_id" CHECK (length("workspace_id") = 36 AND "workspace_id" GLOB '????????-????-????-????-????????????' AND "workspace_id" NOT GLOB '*[^0-9a-f-]*'),
  "credit_lot_id" TEXT NOT NULL CONSTRAINT "ck_commerce_credit_transaction__credit_lot_id" CHECK (length("credit_lot_id") = 36 AND "credit_lot_id" GLOB '????????-????-????-????-????????????' AND "credit_lot_id" NOT GLOB '*[^0-9a-f-]*'),
  "reservation_id" TEXT CONSTRAINT "ck_commerce_credit_transaction__reservation_id" CHECK (length("reservation_id") = 36 AND "reservation_id" GLOB '????????-????-????-????-????????????' AND "reservation_id" NOT GLOB '*[^0-9a-f-]*'),
  "logical_request_id" TEXT CONSTRAINT "ck_commerce_credit_transaction__logical_request_id" CHECK (length("logical_request_id") = 36 AND "logical_request_id" GLOB '????????-????-????-????-????????????' AND "logical_request_id" NOT GLOB '*[^0-9a-f-]*'),
  "kind" INTEGER NOT NULL CONSTRAINT "ck_commerce_credit_transaction__kind" CHECK ("kind" IN (1, 2, 3, 4, 5, 6)),
  "amount_micro" INTEGER NOT NULL,
  "reason" TEXT NOT NULL CONSTRAINT "ck_commerce_credit_transaction__reason" CHECK (length("reason") BETWEEN 1 AND 128 AND "reason" NOT GLOB '*[^A-Za-z0-9._:/-]*'),
  "command_id" TEXT NOT NULL CONSTRAINT "ck_commerce_credit_transaction__command_id" CHECK (length("command_id") = 36 AND "command_id" GLOB '????????-????-????-????-????????????' AND "command_id" NOT GLOB '*[^0-9a-f-]*'),
  "movement_ordinal" INTEGER NOT NULL CONSTRAINT "ck_commerce_credit_transaction__movement_ordinal" CHECK ("movement_ordinal" BETWEEN -2147483648 AND 2147483647),
  "created_at" INTEGER NOT NULL,
  CONSTRAINT "pk_commerce_credit_transaction" PRIMARY KEY ("transaction_id"),
  CONSTRAINT "fk_commerce_credit_transaction__workspace_id" FOREIGN KEY ("workspace_id") REFERENCES "workspace_workspace" ("workspace_id") ON DELETE RESTRICT,
  CONSTRAINT "fk_commerce_credit_transaction__credit_lot_id" FOREIGN KEY ("credit_lot_id") REFERENCES "commerce_credit_lot" ("credit_lot_id") ON DELETE RESTRICT
) STRICT;

CREATE UNIQUE INDEX "ux_commerce_credit_transaction__command_id_movement_ordinal" ON "commerce_credit_transaction" ("command_id", "movement_ordinal");

CREATE INDEX "ix_commerce_credit_transaction__credit_lot_id_created_at" ON "commerce_credit_transaction" ("credit_lot_id", "created_at");

CREATE TRIGGER "tr_commerce_credit_transaction__immutable_update" BEFORE UPDATE ON "commerce_credit_transaction"
BEGIN
  SELECT RAISE(ABORT, 'CHECK constraint failed: af_immutable_commerce_credit_transaction');
END;

CREATE TRIGGER "tr_commerce_credit_transaction__immutable_delete" BEFORE DELETE ON "commerce_credit_transaction"
BEGIN
  SELECT RAISE(ABORT, 'CHECK constraint failed: af_immutable_commerce_credit_transaction');
END;

CREATE TABLE "commerce_customer_settlement" (
  "settlement_id" TEXT NOT NULL CONSTRAINT "ck_commerce_customer_settlement__settlement_id" CHECK (length("settlement_id") = 36 AND "settlement_id" GLOB '????????-????-????-????-????????????' AND "settlement_id" NOT GLOB '*[^0-9a-f-]*'),
  "logical_request_id" TEXT NOT NULL CONSTRAINT "ck_commerce_customer_settlement__logical_request_id" CHECK (length("logical_request_id") = 36 AND "logical_request_id" GLOB '????????-????-????-????-????????????' AND "logical_request_id" NOT GLOB '*[^0-9a-f-]*'),
  "reservation_id" TEXT NOT NULL CONSTRAINT "ck_commerce_customer_settlement__reservation_id" CHECK (length("reservation_id") = 36 AND "reservation_id" GLOB '????????-????-????-????-????????????' AND "reservation_id" NOT GLOB '*[^0-9a-f-]*'),
  "debit_capacity_micro" INTEGER NOT NULL,
  "debit_compensation_micro" INTEGER NOT NULL,
  "debit_purchased_micro" INTEGER NOT NULL,
  "released_micro" INTEGER NOT NULL,
  "rounding_mode" TEXT NOT NULL,
  "settled_at" INTEGER NOT NULL,
  "adjusts_settlement_id" TEXT CONSTRAINT "ck_commerce_customer_settlement__adjusts_settlement_id" CHECK (length("adjusts_settlement_id") = 36 AND "adjusts_settlement_id" GLOB '????????-????-????-????-????????????' AND "adjusts_settlement_id" NOT GLOB '*[^0-9a-f-]*'),
  CONSTRAINT "pk_commerce_customer_settlement" PRIMARY KEY ("settlement_id"),
  CONSTRAINT "fk_commerce_customer_settlement__logical_request_id" FOREIGN KEY ("logical_request_id") REFERENCES "commerce_logical_ai_request" ("logical_request_id") ON DELETE RESTRICT,
  CONSTRAINT "fk_commerce_customer_settlement__reservation_id" FOREIGN KEY ("reservation_id") REFERENCES "entitlement_capacity_reservation" ("reservation_id") ON DELETE RESTRICT
) STRICT;

CREATE UNIQUE INDEX "ux_commerce_customer_settlement__logical_request_id" ON "commerce_customer_settlement" ("logical_request_id") WHERE "adjusts_settlement_id" IS NULL;

CREATE TRIGGER "tr_commerce_customer_settlement__immutable_update" BEFORE UPDATE ON "commerce_customer_settlement"
BEGIN
  SELECT RAISE(ABORT, 'CHECK constraint failed: af_immutable_commerce_customer_settlement');
END;

CREATE TABLE "commerce_ledger_entry" (
  "ledger_entry_id" TEXT NOT NULL CONSTRAINT "ck_commerce_ledger_entry__ledger_entry_id" CHECK (length("ledger_entry_id") = 36 AND "ledger_entry_id" GLOB '????????-????-????-????-????????????' AND "ledger_entry_id" NOT GLOB '*[^0-9a-f-]*'),
  "ledger" INTEGER NOT NULL CONSTRAINT "ck_commerce_ledger_entry__ledger" CHECK ("ledger" IN (1, 2, 3)),
  "workspace_id" TEXT CONSTRAINT "ck_commerce_ledger_entry__workspace_id" CHECK (length("workspace_id") = 36 AND "workspace_id" GLOB '????????-????-????-????-????????????' AND "workspace_id" NOT GLOB '*[^0-9a-f-]*'),
  "amount_micro" INTEGER,
  "amount_money" TEXT CONSTRAINT "ck_commerce_ledger_entry__amount_money" CHECK (length("amount_money") BETWEEN 1 AND 30 AND "amount_money" NOT GLOB '*[^0-9.-]*' AND "amount_money" NOT GLOB '*.*.*' AND "amount_money" NOT GLOB '*-*-*' AND "amount_money" NOT GLOB '*[0-9.]-*' AND "amount_money" NOT GLOB '.*' AND "amount_money" NOT GLOB '*.' AND "amount_money" NOT GLOB '-.*' AND "amount_money" NOT GLOB '-' AND "amount_money" NOT GLOB '0[0-9]*' AND "amount_money" NOT GLOB '-0[0-9]*' AND "amount_money" <> '-0' AND "amount_money" NOT GLOB '*.*0' AND (instr("amount_money", '.') = 0 OR length("amount_money") - instr("amount_money", '.') <= 9) AND length(replace(replace("amount_money", '-', ''), '.', '')) <= 28),
  "currency" TEXT CONSTRAINT "ck_commerce_ledger_entry__currency" CHECK (length("currency") = 3 AND "currency" NOT GLOB '*[^A-Z]*'),
  "occurred_at" INTEGER NOT NULL,
  "reference_kind" TEXT NOT NULL,
  "reference_id" TEXT NOT NULL CONSTRAINT "ck_commerce_ledger_entry__reference_id" CHECK (length("reference_id") = 36 AND "reference_id" GLOB '????????-????-????-????-????????????' AND "reference_id" NOT GLOB '*[^0-9a-f-]*'),
  "created_at" INTEGER NOT NULL,
  CONSTRAINT "pk_commerce_ledger_entry" PRIMARY KEY ("ledger_entry_id"),
  CONSTRAINT "ck_commerce_ledger_entry__customer_credit_units" CHECK ("ledger" <> 2 OR ("amount_micro" IS NOT NULL AND "amount_money" IS NULL AND "currency" IS NULL)),
  CONSTRAINT "ck_commerce_ledger_entry__money_ledger_units" CHECK ("ledger" NOT IN (1, 3) OR ("amount_money" IS NOT NULL AND "currency" IS NOT NULL AND "amount_micro" IS NULL))
) STRICT;

CREATE INDEX "ix_commerce_ledger_entry__ledger_occurred_at" ON "commerce_ledger_entry" ("ledger", "occurred_at");

CREATE INDEX "ix_commerce_ledger_entry__ledger_workspace_id_occurred_at" ON "commerce_ledger_entry" ("ledger", "workspace_id", "occurred_at");

CREATE TRIGGER "tr_commerce_ledger_entry__immutable_update" BEFORE UPDATE ON "commerce_ledger_entry"
BEGIN
  SELECT RAISE(ABORT, 'CHECK constraint failed: af_immutable_commerce_ledger_entry');
END;

CREATE TRIGGER "tr_commerce_ledger_entry__immutable_delete" BEFORE DELETE ON "commerce_ledger_entry"
BEGIN
  SELECT RAISE(ABORT, 'CHECK constraint failed: af_immutable_commerce_ledger_entry');
END;

CREATE TABLE "commerce_logical_ai_request" (
  "logical_request_id" TEXT NOT NULL CONSTRAINT "ck_commerce_logical_ai_request__logical_request_id" CHECK (length("logical_request_id") = 36 AND "logical_request_id" GLOB '????????-????-????-????-????????????' AND "logical_request_id" NOT GLOB '*[^0-9a-f-]*'),
  "workspace_id" TEXT CONSTRAINT "ck_commerce_logical_ai_request__workspace_id" CHECK (length("workspace_id") = 36 AND "workspace_id" GLOB '????????-????-????-????-????????????' AND "workspace_id" NOT GLOB '*[^0-9a-f-]*'),
  "service_term_id" TEXT CONSTRAINT "ck_commerce_logical_ai_request__service_term_id" CHECK (length("service_term_id") = 36 AND "service_term_id" GLOB '????????-????-????-????-????????????' AND "service_term_id" NOT GLOB '*[^0-9a-f-]*'),
  "operator_job_ref" TEXT CONSTRAINT "ck_commerce_logical_ai_request__operator_job_ref" CHECK (length("operator_job_ref") = 36 AND "operator_job_ref" GLOB '????????-????-????-????-????????????' AND "operator_job_ref" NOT GLOB '*[^0-9a-f-]*'),
  "run_id" TEXT CONSTRAINT "ck_commerce_logical_ai_request__run_id" CHECK (length("run_id") = 36 AND "run_id" GLOB '????????-????-????-????-????????????' AND "run_id" NOT GLOB '*[^0-9a-f-]*'),
  "step_id" TEXT CONSTRAINT "ck_commerce_logical_ai_request__step_id" CHECK (length("step_id") = 36 AND "step_id" GLOB '????????-????-????-????-????????????' AND "step_id" NOT GLOB '*[^0-9a-f-]*'),
  "attempt_id" TEXT CONSTRAINT "ck_commerce_logical_ai_request__attempt_id" CHECK (length("attempt_id") = 36 AND "attempt_id" GLOB '????????-????-????-????-????????????' AND "attempt_id" NOT GLOB '*[^0-9a-f-]*'),
  "beneficiary" INTEGER NOT NULL CONSTRAINT "ck_commerce_logical_ai_request__beneficiary" CHECK ("beneficiary" IN (1, 2, 3, 4, 5, 6)),
  "tariff_version_id" TEXT CONSTRAINT "ck_commerce_logical_ai_request__tariff_version_id" CHECK (length("tariff_version_id") = 36 AND "tariff_version_id" GLOB '????????-????-????-????-????????????' AND "tariff_version_id" NOT GLOB '*[^0-9a-f-]*'),
  "config_revision_id" TEXT NOT NULL CONSTRAINT "ck_commerce_logical_ai_request__config_revision_id" CHECK (length("config_revision_id") = 36 AND "config_revision_id" GLOB '????????-????-????-????-????????????' AND "config_revision_id" NOT GLOB '*[^0-9a-f-]*'),
  "state" INTEGER NOT NULL CONSTRAINT "ck_commerce_logical_ai_request__state" CHECK ("state" IN (1, 2, 3, 4, 5, 6, 7, 8)),
  "created_at" INTEGER NOT NULL,
  "settled_at" INTEGER,
  CONSTRAINT "pk_commerce_logical_ai_request" PRIMARY KEY ("logical_request_id")
) STRICT;

CREATE INDEX "ix_commerce_logical_ai_request__workspace_id_created_at" ON "commerce_logical_ai_request" ("workspace_id", "created_at");

CREATE INDEX "ix_commerce_logical_ai_request__state_created_at" ON "commerce_logical_ai_request" ("state", "created_at");

CREATE TABLE "commerce_offer" (
  "offer_id" TEXT NOT NULL CONSTRAINT "ck_commerce_offer__offer_id" CHECK (length("offer_id") = 36 AND "offer_id" GLOB '????????-????-????-????-????????????' AND "offer_id" NOT GLOB '*[^0-9a-f-]*'),
  "kind" INTEGER NOT NULL CONSTRAINT "ck_commerce_offer__kind" CHECK ("kind" IN (1, 2, 3, 4)),
  "name" TEXT NOT NULL,
  "scope" TEXT NOT NULL,
  "active" INTEGER NOT NULL CONSTRAINT "ck_commerce_offer__active" CHECK ("active" IN (0, 1)),
  "term_profile" TEXT NOT NULL,
  "created_at" INTEGER NOT NULL,
  "rev" INTEGER NOT NULL CONSTRAINT "ck_commerce_offer__rev" CHECK ("rev" >= 0),
  CONSTRAINT "pk_commerce_offer" PRIMARY KEY ("offer_id")
) STRICT;

CREATE TABLE "commerce_order" (
  "order_id" TEXT NOT NULL CONSTRAINT "ck_commerce_order__order_id" CHECK (length("order_id") = 36 AND "order_id" GLOB '????????-????-????-????-????????????' AND "order_id" NOT GLOB '*[^0-9a-f-]*'),
  "purchase_intent_id" TEXT NOT NULL CONSTRAINT "ck_commerce_order__purchase_intent_id" CHECK (length("purchase_intent_id") = 36 AND "purchase_intent_id" GLOB '????????-????-????-????-????????????' AND "purchase_intent_id" NOT GLOB '*[^0-9a-f-]*'),
  "billing_account_id" TEXT NOT NULL CONSTRAINT "ck_commerce_order__billing_account_id" CHECK (length("billing_account_id") = 36 AND "billing_account_id" GLOB '????????-????-????-????-????????????' AND "billing_account_id" NOT GLOB '*[^0-9a-f-]*'),
  "workspace_id" TEXT NOT NULL CONSTRAINT "ck_commerce_order__workspace_id" CHECK (length("workspace_id") = 36 AND "workspace_id" GLOB '????????-????-????-????-????????????' AND "workspace_id" NOT GLOB '*[^0-9a-f-]*'),
  "offer_id" TEXT NOT NULL CONSTRAINT "ck_commerce_order__offer_id" CHECK (length("offer_id") = 36 AND "offer_id" GLOB '????????-????-????-????-????????????' AND "offer_id" NOT GLOB '*[^0-9a-f-]*'),
  "price_version_id" TEXT NOT NULL CONSTRAINT "ck_commerce_order__price_version_id" CHECK (length("price_version_id") = 36 AND "price_version_id" GLOB '????????-????-????-????-????????????' AND "price_version_id" NOT GLOB '*[^0-9a-f-]*'),
  "amount" TEXT NOT NULL CONSTRAINT "ck_commerce_order__amount" CHECK (length("amount") BETWEEN 1 AND 30 AND "amount" NOT GLOB '*[^0-9.-]*' AND "amount" NOT GLOB '*.*.*' AND "amount" NOT GLOB '*-*-*' AND "amount" NOT GLOB '*[0-9.]-*' AND "amount" NOT GLOB '.*' AND "amount" NOT GLOB '*.' AND "amount" NOT GLOB '-.*' AND "amount" NOT GLOB '-' AND "amount" NOT GLOB '0[0-9]*' AND "amount" NOT GLOB '-0[0-9]*' AND "amount" <> '-0' AND "amount" NOT GLOB '*.*0' AND (instr("amount", '.') = 0 OR length("amount") - instr("amount", '.') <= 9) AND length(replace(replace("amount", '-', ''), '.', '')) <= 28),
  "amount_currency" TEXT NOT NULL CONSTRAINT "ck_commerce_order__amount_currency" CHECK (length("amount_currency") = 3 AND "amount_currency" NOT GLOB '*[^A-Z]*'),
  "state" INTEGER NOT NULL CONSTRAINT "ck_commerce_order__state" CHECK ("state" IN (1, 2, 3)),
  "created_at" INTEGER NOT NULL,
  "completed_at" INTEGER,
  "rev" INTEGER NOT NULL CONSTRAINT "ck_commerce_order__rev" CHECK ("rev" >= 0),
  CONSTRAINT "pk_commerce_order" PRIMARY KEY ("order_id"),
  CONSTRAINT "fk_commerce_order__purchase_intent_id" FOREIGN KEY ("purchase_intent_id") REFERENCES "commerce_purchase_intent" ("purchase_intent_id") ON DELETE RESTRICT,
  CONSTRAINT "fk_commerce_order__billing_account_id" FOREIGN KEY ("billing_account_id") REFERENCES "commerce_billing_account" ("billing_account_id") ON DELETE RESTRICT,
  CONSTRAINT "fk_commerce_order__workspace_id" FOREIGN KEY ("workspace_id") REFERENCES "workspace_workspace" ("workspace_id") ON DELETE RESTRICT,
  CONSTRAINT "fk_commerce_order__offer_id" FOREIGN KEY ("offer_id") REFERENCES "commerce_offer" ("offer_id") ON DELETE RESTRICT,
  CONSTRAINT "fk_commerce_order__price_version_id" FOREIGN KEY ("price_version_id") REFERENCES "commerce_price_version" ("price_version_id") ON DELETE RESTRICT
) STRICT;

CREATE UNIQUE INDEX "ux_commerce_order__purchase_intent_id" ON "commerce_order" ("purchase_intent_id");

CREATE TRIGGER "tr_commerce_order__limited_update" BEFORE UPDATE ON "commerce_order"
WHEN (OLD."order_id" IS NOT NEW."order_id" OR OLD."purchase_intent_id" IS NOT NEW."purchase_intent_id" OR OLD."billing_account_id" IS NOT NEW."billing_account_id" OR OLD."workspace_id" IS NOT NEW."workspace_id" OR OLD."offer_id" IS NOT NEW."offer_id" OR OLD."price_version_id" IS NOT NEW."price_version_id" OR OLD."amount" IS NOT NEW."amount" OR OLD."amount_currency" IS NOT NEW."amount_currency" OR OLD."created_at" IS NOT NEW."created_at") OR NOT (OLD."state" = 1)
BEGIN
  SELECT RAISE(ABORT, 'CHECK constraint failed: af_immutable_commerce_order');
END;

CREATE TABLE "commerce_payment" (
  "payment_id" TEXT NOT NULL CONSTRAINT "ck_commerce_payment__payment_id" CHECK (length("payment_id") = 36 AND "payment_id" GLOB '????????-????-????-????-????????????' AND "payment_id" NOT GLOB '*[^0-9a-f-]*'),
  "order_id" TEXT NOT NULL CONSTRAINT "ck_commerce_payment__order_id" CHECK (length("order_id") = 36 AND "order_id" GLOB '????????-????-????-????-????????????' AND "order_id" NOT GLOB '*[^0-9a-f-]*'),
  "provider" TEXT NOT NULL,
  "provider_payment_ref" TEXT NOT NULL,
  "amount" TEXT NOT NULL CONSTRAINT "ck_commerce_payment__amount" CHECK (length("amount") BETWEEN 1 AND 30 AND "amount" NOT GLOB '*[^0-9.-]*' AND "amount" NOT GLOB '*.*.*' AND "amount" NOT GLOB '*-*-*' AND "amount" NOT GLOB '*[0-9.]-*' AND "amount" NOT GLOB '.*' AND "amount" NOT GLOB '*.' AND "amount" NOT GLOB '-.*' AND "amount" NOT GLOB '-' AND "amount" NOT GLOB '0[0-9]*' AND "amount" NOT GLOB '-0[0-9]*' AND "amount" <> '-0' AND "amount" NOT GLOB '*.*0' AND (instr("amount", '.') = 0 OR length("amount") - instr("amount", '.') <= 9) AND length(replace(replace("amount", '-', ''), '.', '')) <= 28),
  "amount_currency" TEXT NOT NULL CONSTRAINT "ck_commerce_payment__amount_currency" CHECK (length("amount_currency") = 3 AND "amount_currency" NOT GLOB '*[^A-Z]*'),
  "state" INTEGER NOT NULL CONSTRAINT "ck_commerce_payment__state" CHECK ("state" IN (1, 2, 3, 4)),
  "provider_event_id" TEXT NOT NULL CONSTRAINT "ck_commerce_payment__provider_event_id" CHECK (length("provider_event_id") = 36 AND "provider_event_id" GLOB '????????-????-????-????-????????????' AND "provider_event_id" NOT GLOB '*[^0-9a-f-]*'),
  "created_at" INTEGER NOT NULL,
  "captured_at" INTEGER,
  "rev" INTEGER NOT NULL CONSTRAINT "ck_commerce_payment__rev" CHECK ("rev" >= 0),
  CONSTRAINT "pk_commerce_payment" PRIMARY KEY ("payment_id"),
  CONSTRAINT "fk_commerce_payment__order_id" FOREIGN KEY ("order_id") REFERENCES "commerce_order" ("order_id") ON DELETE RESTRICT,
  CONSTRAINT "fk_commerce_payment__provider_event_id" FOREIGN KEY ("provider_event_id") REFERENCES "commerce_provider_event" ("provider_event_id") ON DELETE RESTRICT
) STRICT;

CREATE UNIQUE INDEX "ux_commerce_payment__provider_provider_payment_ref" ON "commerce_payment" ("provider", "provider_payment_ref");

CREATE TABLE "commerce_price_version" (
  "price_version_id" TEXT NOT NULL CONSTRAINT "ck_commerce_price_version__price_version_id" CHECK (length("price_version_id") = 36 AND "price_version_id" GLOB '????????-????-????-????-????????????' AND "price_version_id" NOT GLOB '*[^0-9a-f-]*'),
  "offer_id" TEXT NOT NULL CONSTRAINT "ck_commerce_price_version__offer_id" CHECK (length("offer_id") = 36 AND "offer_id" GLOB '????????-????-????-????-????????????' AND "offer_id" NOT GLOB '*[^0-9a-f-]*'),
  "version" INTEGER NOT NULL,
  "amount" TEXT NOT NULL CONSTRAINT "ck_commerce_price_version__amount" CHECK (length("amount") BETWEEN 1 AND 30 AND "amount" NOT GLOB '*[^0-9.-]*' AND "amount" NOT GLOB '*.*.*' AND "amount" NOT GLOB '*-*-*' AND "amount" NOT GLOB '*[0-9.]-*' AND "amount" NOT GLOB '.*' AND "amount" NOT GLOB '*.' AND "amount" NOT GLOB '-.*' AND "amount" NOT GLOB '-' AND "amount" NOT GLOB '0[0-9]*' AND "amount" NOT GLOB '-0[0-9]*' AND "amount" <> '-0' AND "amount" NOT GLOB '*.*0' AND (instr("amount", '.') = 0 OR length("amount") - instr("amount", '.') <= 9) AND length(replace(replace("amount", '-', ''), '.', '')) <= 28),
  "amount_currency" TEXT NOT NULL CONSTRAINT "ck_commerce_price_version__amount_currency" CHECK (length("amount_currency") = 3 AND "amount_currency" NOT GLOB '*[^A-Z]*'),
  "tax_category" TEXT NOT NULL,
  "starts_at" INTEGER NOT NULL,
  "ends_at" INTEGER,
  "config_revision_id" TEXT NOT NULL CONSTRAINT "ck_commerce_price_version__config_revision_id" CHECK (length("config_revision_id") = 36 AND "config_revision_id" GLOB '????????-????-????-????-????????????' AND "config_revision_id" NOT GLOB '*[^0-9a-f-]*'),
  CONSTRAINT "pk_commerce_price_version" PRIMARY KEY ("price_version_id"),
  CONSTRAINT "fk_commerce_price_version__offer_id" FOREIGN KEY ("offer_id") REFERENCES "commerce_offer" ("offer_id") ON DELETE RESTRICT
) STRICT;

CREATE UNIQUE INDEX "ux_commerce_price_version__offer_id_version" ON "commerce_price_version" ("offer_id", "version");

CREATE INDEX "ix_commerce_price_version__offer_id_starts_at" ON "commerce_price_version" ("offer_id", "starts_at");

CREATE TRIGGER "tr_commerce_price_version__immutable_update" BEFORE UPDATE ON "commerce_price_version"
BEGIN
  SELECT RAISE(ABORT, 'CHECK constraint failed: af_immutable_commerce_price_version');
END;

CREATE TABLE "commerce_provider_attempt" (
  "provider_attempt_id" TEXT NOT NULL CONSTRAINT "ck_commerce_provider_attempt__provider_attempt_id" CHECK (length("provider_attempt_id") = 36 AND "provider_attempt_id" GLOB '????????-????-????-????-????????????' AND "provider_attempt_id" NOT GLOB '*[^0-9a-f-]*'),
  "logical_request_id" TEXT NOT NULL CONSTRAINT "ck_commerce_provider_attempt__logical_request_id" CHECK (length("logical_request_id") = 36 AND "logical_request_id" GLOB '????????-????-????-????-????????????' AND "logical_request_id" NOT GLOB '*[^0-9a-f-]*'),
  "attempt_ordinal" INTEGER NOT NULL CONSTRAINT "ck_commerce_provider_attempt__attempt_ordinal" CHECK ("attempt_ordinal" BETWEEN -2147483648 AND 2147483647),
  "provider_request_ref" TEXT,
  "client_dispatch_key" TEXT NOT NULL CONSTRAINT "ck_commerce_provider_attempt__client_dispatch_key" CHECK (length("client_dispatch_key") = 36 AND "client_dispatch_key" GLOB '????????-????-????-????-????????????' AND "client_dispatch_key" NOT GLOB '*[^0-9a-f-]*'),
  "dispatch_state" INTEGER NOT NULL CONSTRAINT "ck_commerce_provider_attempt__dispatch_state" CHECK ("dispatch_state" IN (1, 2, 3, 4)),
  "intent_committed_at" INTEGER NOT NULL,
  "owner_fence" INTEGER NOT NULL,
  "funding_class" INTEGER NOT NULL CONSTRAINT "ck_commerce_provider_attempt__funding_class" CHECK ("funding_class" IN (1, 2, 3)),
  "model_descriptor_id" TEXT NOT NULL CONSTRAINT "ck_commerce_provider_attempt__model_descriptor_id" CHECK (length("model_descriptor_id") = 36 AND "model_descriptor_id" GLOB '????????-????-????-????-????????????' AND "model_descriptor_id" NOT GLOB '*[^0-9a-f-]*'),
  "supplier_price_version_id" TEXT NOT NULL CONSTRAINT "ck_commerce_provider_attempt__supplier_price_version_id" CHECK (length("supplier_price_version_id") = 36 AND "supplier_price_version_id" GLOB '????????-????-????-????-????????????' AND "supplier_price_version_id" NOT GLOB '*[^0-9a-f-]*'),
  "route" TEXT NOT NULL,
  "processing_tier" TEXT NOT NULL,
  "context_tier" TEXT NOT NULL,
  "region_tier" TEXT NOT NULL,
  "dispatched_at" INTEGER,
  "completed_at" INTEGER,
  "usage_source" INTEGER NOT NULL CONSTRAINT "ck_commerce_provider_attempt__usage_source" CHECK ("usage_source" IN (1, 2, 3, 4)),
  "completeness" INTEGER NOT NULL CONSTRAINT "ck_commerce_provider_attempt__completeness" CHECK ("completeness" IN (1, 2, 3, 4)),
  "outcome" INTEGER CONSTRAINT "ck_commerce_provider_attempt__outcome" CHECK ("outcome" IN (1, 2, 3, 4, 5)),
  "output_commit_ref" TEXT CONSTRAINT "ck_commerce_provider_attempt__output_commit_ref" CHECK (length("output_commit_ref") = 36 AND "output_commit_ref" GLOB '????????-????-????-????-????????????' AND "output_commit_ref" NOT GLOB '*[^0-9a-f-]*'),
  CONSTRAINT "pk_commerce_provider_attempt" PRIMARY KEY ("provider_attempt_id"),
  CONSTRAINT "fk_commerce_provider_attempt__logical_request_id" FOREIGN KEY ("logical_request_id") REFERENCES "commerce_logical_ai_request" ("logical_request_id") ON DELETE RESTRICT
) STRICT;

CREATE UNIQUE INDEX "ux_commerce_provider_attempt__logical_request_id_attempt_ordinal" ON "commerce_provider_attempt" ("logical_request_id", "attempt_ordinal");

CREATE UNIQUE INDEX "ux_commerce_provider_attempt__client_dispatch_key" ON "commerce_provider_attempt" ("client_dispatch_key");

CREATE TRIGGER "tr_commerce_provider_attempt__monotonic_owner_fence" BEFORE UPDATE OF "owner_fence" ON "commerce_provider_attempt"
WHEN NEW."owner_fence" < OLD."owner_fence"
BEGIN
  SELECT RAISE(ABORT, 'CHECK constraint failed: af_monotonic_commerce_provider_attempt_owner_fence');
END;

CREATE TABLE "commerce_provider_customer" (
  "billing_account_id" TEXT NOT NULL CONSTRAINT "ck_commerce_provider_customer__billing_account_id" CHECK (length("billing_account_id") = 36 AND "billing_account_id" GLOB '????????-????-????-????-????????????' AND "billing_account_id" NOT GLOB '*[^0-9a-f-]*'),
  "provider" TEXT NOT NULL,
  "external_customer_ref" TEXT NOT NULL,
  CONSTRAINT "pk_commerce_provider_customer" PRIMARY KEY ("billing_account_id", "provider")
) STRICT;

CREATE UNIQUE INDEX "ux_commerce_provider_customer__provider_external_customer_ref" ON "commerce_provider_customer" ("provider", "external_customer_ref");

CREATE TABLE "commerce_provider_event" (
  "provider_event_id" TEXT NOT NULL CONSTRAINT "ck_commerce_provider_event__provider_event_id" CHECK (length("provider_event_id") = 36 AND "provider_event_id" GLOB '????????-????-????-????-????????????' AND "provider_event_id" NOT GLOB '*[^0-9a-f-]*'),
  "provider" TEXT NOT NULL,
  "external_event_id" TEXT NOT NULL,
  "event_type" TEXT NOT NULL,
  "raw_payload" TEXT NOT NULL CONSTRAINT "ck_commerce_provider_event__raw_payload" CHECK (json_valid("raw_payload")),
  "signature_verified" INTEGER NOT NULL CONSTRAINT "ck_commerce_provider_event__signature_verified" CHECK ("signature_verified" IN (0, 1)),
  "received_at" INTEGER NOT NULL,
  "processing_state" INTEGER NOT NULL CONSTRAINT "ck_commerce_provider_event__processing_state" CHECK ("processing_state" IN (1, 2, 3)),
  "retry_count" INTEGER NOT NULL CONSTRAINT "ck_commerce_provider_event__retry_count" CHECK ("retry_count" BETWEEN -2147483648 AND 2147483647),
  "quarantine_reason" TEXT,
  CONSTRAINT "pk_commerce_provider_event" PRIMARY KEY ("provider_event_id"),
  CONSTRAINT "ck_commerce_provider_event__unverified_never_processed" CHECK ("processing_state" <> 2 OR "signature_verified" = 1)
) STRICT;

CREATE UNIQUE INDEX "ux_commerce_provider_event__provider_event_type_external_event_id" ON "commerce_provider_event" ("provider", "event_type", "external_event_id");

CREATE INDEX "ix_commerce_provider_event__processing_state_received_at" ON "commerce_provider_event" ("processing_state", "received_at");

CREATE TABLE "commerce_purchase_intent" (
  "purchase_intent_id" TEXT NOT NULL CONSTRAINT "ck_commerce_purchase_intent__purchase_intent_id" CHECK (length("purchase_intent_id") = 36 AND "purchase_intent_id" GLOB '????????-????-????-????-????????????' AND "purchase_intent_id" NOT GLOB '*[^0-9a-f-]*'),
  "billing_account_id" TEXT NOT NULL CONSTRAINT "ck_commerce_purchase_intent__billing_account_id" CHECK (length("billing_account_id") = 36 AND "billing_account_id" GLOB '????????-????-????-????-????????????' AND "billing_account_id" NOT GLOB '*[^0-9a-f-]*'),
  "workspace_id" TEXT NOT NULL CONSTRAINT "ck_commerce_purchase_intent__workspace_id" CHECK (length("workspace_id") = 36 AND "workspace_id" GLOB '????????-????-????-????-????????????' AND "workspace_id" NOT GLOB '*[^0-9a-f-]*'),
  "offer_id" TEXT NOT NULL CONSTRAINT "ck_commerce_purchase_intent__offer_id" CHECK (length("offer_id") = 36 AND "offer_id" GLOB '????????-????-????-????-????????????' AND "offer_id" NOT GLOB '*[^0-9a-f-]*'),
  "price_version_id" TEXT NOT NULL CONSTRAINT "ck_commerce_purchase_intent__price_version_id" CHECK (length("price_version_id") = 36 AND "price_version_id" GLOB '????????-????-????-????-????????????' AND "price_version_id" NOT GLOB '*[^0-9a-f-]*'),
  "state" INTEGER NOT NULL CONSTRAINT "ck_commerce_purchase_intent__state" CHECK ("state" IN (1, 2, 3, 4, 5)),
  "created_at" INTEGER NOT NULL,
  "expires_at" INTEGER NOT NULL,
  CONSTRAINT "pk_commerce_purchase_intent" PRIMARY KEY ("purchase_intent_id"),
  CONSTRAINT "fk_commerce_purchase_intent__billing_account_id" FOREIGN KEY ("billing_account_id") REFERENCES "commerce_billing_account" ("billing_account_id") ON DELETE RESTRICT
) STRICT;

CREATE INDEX "ix_commerce_purchase_intent__state_expires_at" ON "commerce_purchase_intent" ("state", "expires_at");

CREATE TABLE "commerce_refund" (
  "refund_id" TEXT NOT NULL CONSTRAINT "ck_commerce_refund__refund_id" CHECK (length("refund_id") = 36 AND "refund_id" GLOB '????????-????-????-????-????????????' AND "refund_id" NOT GLOB '*[^0-9a-f-]*'),
  "payment_id" TEXT NOT NULL CONSTRAINT "ck_commerce_refund__payment_id" CHECK (length("payment_id") = 36 AND "payment_id" GLOB '????????-????-????-????-????????????' AND "payment_id" NOT GLOB '*[^0-9a-f-]*'),
  "workspace_id" TEXT NOT NULL CONSTRAINT "ck_commerce_refund__workspace_id" CHECK (length("workspace_id") = 36 AND "workspace_id" GLOB '????????-????-????-????-????????????' AND "workspace_id" NOT GLOB '*[^0-9a-f-]*'),
  "reason" TEXT NOT NULL,
  "amount" TEXT CONSTRAINT "ck_commerce_refund__amount" CHECK (length("amount") BETWEEN 1 AND 30 AND "amount" NOT GLOB '*[^0-9.-]*' AND "amount" NOT GLOB '*.*.*' AND "amount" NOT GLOB '*-*-*' AND "amount" NOT GLOB '*[0-9.]-*' AND "amount" NOT GLOB '.*' AND "amount" NOT GLOB '*.' AND "amount" NOT GLOB '-.*' AND "amount" NOT GLOB '-' AND "amount" NOT GLOB '0[0-9]*' AND "amount" NOT GLOB '-0[0-9]*' AND "amount" <> '-0' AND "amount" NOT GLOB '*.*0' AND (instr("amount", '.') = 0 OR length("amount") - instr("amount", '.') <= 9) AND length(replace(replace("amount", '-', ''), '.', '')) <= 28),
  "amount_currency" TEXT CONSTRAINT "ck_commerce_refund__amount_currency" CHECK (length("amount_currency") = 3 AND "amount_currency" NOT GLOB '*[^A-Z]*'),
  "state" INTEGER NOT NULL CONSTRAINT "ck_commerce_refund__state" CHECK ("state" IN (1, 2, 3, 4, 5, 6, 7)),
  "decision_proposal_id" TEXT CONSTRAINT "ck_commerce_refund__decision_proposal_id" CHECK (length("decision_proposal_id") = 36 AND "decision_proposal_id" GLOB '????????-????-????-????-????????????' AND "decision_proposal_id" NOT GLOB '*[^0-9a-f-]*'),
  "provider_refund_ref" TEXT,
  "provider_event_id" TEXT CONSTRAINT "ck_commerce_refund__provider_event_id" CHECK (length("provider_event_id") = 36 AND "provider_event_id" GLOB '????????-????-????-????-????????????' AND "provider_event_id" NOT GLOB '*[^0-9a-f-]*'),
  "created_at" INTEGER NOT NULL,
  "updated_at" INTEGER NOT NULL,
  "rev" INTEGER NOT NULL CONSTRAINT "ck_commerce_refund__rev" CHECK ("rev" >= 0),
  CONSTRAINT "pk_commerce_refund" PRIMARY KEY ("refund_id"),
  CONSTRAINT "fk_commerce_refund__payment_id" FOREIGN KEY ("payment_id") REFERENCES "commerce_payment" ("payment_id") ON DELETE RESTRICT,
  CONSTRAINT "fk_commerce_refund__workspace_id" FOREIGN KEY ("workspace_id") REFERENCES "workspace_workspace" ("workspace_id") ON DELETE RESTRICT,
  CONSTRAINT "fk_commerce_refund__decision_proposal_id" FOREIGN KEY ("decision_proposal_id") REFERENCES "audit_operator_proposal" ("proposal_id") ON DELETE RESTRICT,
  CONSTRAINT "ck_commerce_refund__both_or_none_amount" CHECK (("amount" IS NULL AND "amount_currency" IS NULL) OR ("amount" IS NOT NULL AND "amount_currency" IS NOT NULL))
) STRICT;

CREATE UNIQUE INDEX "ux_commerce_refund__payment_id_provider_refund_ref" ON "commerce_refund" ("payment_id", "provider_refund_ref");

CREATE INDEX "ix_commerce_refund__workspace_id_created_at" ON "commerce_refund" ("workspace_id", "created_at");

CREATE TABLE "commerce_spend_budget" (
  "scope_kind" TEXT NOT NULL,
  "scope_id" TEXT NOT NULL,
  "period_key" TEXT NOT NULL,
  "unit" TEXT NOT NULL,
  "limit" TEXT NOT NULL CONSTRAINT "ck_commerce_spend_budget__limit" CHECK (length("limit") BETWEEN 1 AND 30 AND "limit" NOT GLOB '*[^0-9.-]*' AND "limit" NOT GLOB '*.*.*' AND "limit" NOT GLOB '*-*-*' AND "limit" NOT GLOB '*[0-9.]-*' AND "limit" NOT GLOB '.*' AND "limit" NOT GLOB '*.' AND "limit" NOT GLOB '-.*' AND "limit" NOT GLOB '-' AND "limit" NOT GLOB '0[0-9]*' AND "limit" NOT GLOB '-0[0-9]*' AND "limit" <> '-0' AND "limit" NOT GLOB '*.*0' AND (instr("limit", '.') = 0 OR length("limit") - instr("limit", '.') <= 9) AND length(replace(replace("limit", '-', ''), '.', '')) <= 28),
  "used" TEXT NOT NULL CONSTRAINT "ck_commerce_spend_budget__used" CHECK (length("used") BETWEEN 1 AND 30 AND "used" NOT GLOB '*[^0-9.-]*' AND "used" NOT GLOB '*.*.*' AND "used" NOT GLOB '*-*-*' AND "used" NOT GLOB '*[0-9.]-*' AND "used" NOT GLOB '.*' AND "used" NOT GLOB '*.' AND "used" NOT GLOB '-.*' AND "used" NOT GLOB '-' AND "used" NOT GLOB '0[0-9]*' AND "used" NOT GLOB '-0[0-9]*' AND "used" <> '-0' AND "used" NOT GLOB '*.*0' AND (instr("used", '.') = 0 OR length("used") - instr("used", '.') <= 9) AND length(replace(replace("used", '-', ''), '.', '')) <= 28),
  "held" TEXT NOT NULL CONSTRAINT "ck_commerce_spend_budget__held" CHECK (length("held") BETWEEN 1 AND 30 AND "held" NOT GLOB '*[^0-9.-]*' AND "held" NOT GLOB '*.*.*' AND "held" NOT GLOB '*-*-*' AND "held" NOT GLOB '*[0-9.]-*' AND "held" NOT GLOB '.*' AND "held" NOT GLOB '*.' AND "held" NOT GLOB '-.*' AND "held" NOT GLOB '-' AND "held" NOT GLOB '0[0-9]*' AND "held" NOT GLOB '-0[0-9]*' AND "held" <> '-0' AND "held" NOT GLOB '*.*0' AND (instr("held", '.') = 0 OR length("held") - instr("held", '.') <= 9) AND length(replace(replace("held", '-', ''), '.', '')) <= 28),
  "rev" INTEGER NOT NULL CONSTRAINT "ck_commerce_spend_budget__rev" CHECK ("rev" >= 0),
  "period_ends_at" INTEGER,
  CONSTRAINT "pk_commerce_spend_budget" PRIMARY KEY ("scope_kind", "scope_id", "period_key", "unit"),
  CONSTRAINT "ck_commerce_spend_budget__nonnegative" CHECK ("limit" NOT GLOB '-*' AND "used" NOT GLOB '-*' AND "held" NOT GLOB '-*')
) STRICT;

CREATE TABLE "commerce_spend_reservation" (
  "reservation_id" TEXT NOT NULL CONSTRAINT "ck_commerce_spend_reservation__reservation_id" CHECK (length("reservation_id") = 36 AND "reservation_id" GLOB '????????-????-????-????-????????????' AND "reservation_id" NOT GLOB '*[^0-9a-f-]*'),
  "provider_attempt_id" TEXT CONSTRAINT "ck_commerce_spend_reservation__provider_attempt_id" CHECK (length("provider_attempt_id") = 36 AND "provider_attempt_id" GLOB '????????-????-????-????-????????????' AND "provider_attempt_id" NOT GLOB '*[^0-9a-f-]*'),
  "logical_request_id" TEXT CONSTRAINT "ck_commerce_spend_reservation__logical_request_id" CHECK (length("logical_request_id") = 36 AND "logical_request_id" GLOB '????????-????-????-????-????????????' AND "logical_request_id" NOT GLOB '*[^0-9a-f-]*'),
  "scope_kind" TEXT NOT NULL,
  "scope_id" TEXT NOT NULL,
  "period_key" TEXT NOT NULL,
  "unit" TEXT NOT NULL,
  "bound" TEXT NOT NULL CONSTRAINT "ck_commerce_spend_reservation__bound" CHECK (length("bound") BETWEEN 1 AND 30 AND "bound" NOT GLOB '*[^0-9.-]*' AND "bound" NOT GLOB '*.*.*' AND "bound" NOT GLOB '*-*-*' AND "bound" NOT GLOB '*[0-9.]-*' AND "bound" NOT GLOB '.*' AND "bound" NOT GLOB '*.' AND "bound" NOT GLOB '-.*' AND "bound" NOT GLOB '-' AND "bound" NOT GLOB '0[0-9]*' AND "bound" NOT GLOB '-0[0-9]*' AND "bound" <> '-0' AND "bound" NOT GLOB '*.*0' AND (instr("bound", '.') = 0 OR length("bound") - instr("bound", '.') <= 9) AND length(replace(replace("bound", '-', ''), '.', '')) <= 28),
  "used" TEXT NOT NULL CONSTRAINT "ck_commerce_spend_reservation__used" CHECK (length("used") BETWEEN 1 AND 30 AND "used" NOT GLOB '*[^0-9.-]*' AND "used" NOT GLOB '*.*.*' AND "used" NOT GLOB '*-*-*' AND "used" NOT GLOB '*[0-9.]-*' AND "used" NOT GLOB '.*' AND "used" NOT GLOB '*.' AND "used" NOT GLOB '-.*' AND "used" NOT GLOB '-' AND "used" NOT GLOB '0[0-9]*' AND "used" NOT GLOB '-0[0-9]*' AND "used" <> '-0' AND "used" NOT GLOB '*.*0' AND (instr("used", '.') = 0 OR length("used") - instr("used", '.') <= 9) AND length(replace(replace("used", '-', ''), '.', '')) <= 28),
  "state" INTEGER NOT NULL CONSTRAINT "ck_commerce_spend_reservation__state" CHECK ("state" IN (1, 2, 3, 4)),
  "lease_expires_at" INTEGER,
  "reconcile_at" INTEGER,
  "reconciliation_ref" TEXT CONSTRAINT "ck_commerce_spend_reservation__reconciliation_ref" CHECK (length("reconciliation_ref") = 36 AND "reconciliation_ref" GLOB '????????-????-????-????-????????????' AND "reconciliation_ref" NOT GLOB '*[^0-9a-f-]*'),
  "rev" INTEGER NOT NULL CONSTRAINT "ck_commerce_spend_reservation__rev" CHECK ("rev" >= 0),
  CONSTRAINT "pk_commerce_spend_reservation" PRIMARY KEY ("reservation_id"),
  CONSTRAINT "fk_commerce_spend_reservation__scope_kind_scope_id_period_key_unit" FOREIGN KEY ("scope_kind", "scope_id", "period_key", "unit") REFERENCES "commerce_spend_budget" ("scope_kind", "scope_id", "period_key", "unit") ON DELETE RESTRICT,
  CONSTRAINT "ck_commerce_spend_reservation__exactly_one_request_identity" CHECK (("provider_attempt_id" IS NULL) <> ("logical_request_id" IS NULL))
) STRICT;

CREATE UNIQUE INDEX "ux_commerce_spend_reservation__provider_attempt_id_scope_kind_scope_id_period_key_unit" ON "commerce_spend_reservation" ("provider_attempt_id", "scope_kind", "scope_id", "period_key", "unit");

CREATE UNIQUE INDEX "ux_commerce_spend_reservation__logical_request_id_scope_kind_scope_id_period_key_unit" ON "commerce_spend_reservation" ("logical_request_id", "scope_kind", "scope_id", "period_key", "unit");

CREATE TABLE "commerce_subscription" (
  "subscription_id" TEXT NOT NULL CONSTRAINT "ck_commerce_subscription__subscription_id" CHECK (length("subscription_id") = 36 AND "subscription_id" GLOB '????????-????-????-????-????????????' AND "subscription_id" NOT GLOB '*[^0-9a-f-]*'),
  "billing_account_id" TEXT NOT NULL CONSTRAINT "ck_commerce_subscription__billing_account_id" CHECK (length("billing_account_id") = 36 AND "billing_account_id" GLOB '????????-????-????-????-????????????' AND "billing_account_id" NOT GLOB '*[^0-9a-f-]*'),
  "workspace_id" TEXT NOT NULL CONSTRAINT "ck_commerce_subscription__workspace_id" CHECK (length("workspace_id") = 36 AND "workspace_id" GLOB '????????-????-????-????-????????????' AND "workspace_id" NOT GLOB '*[^0-9a-f-]*'),
  "offer_id" TEXT NOT NULL CONSTRAINT "ck_commerce_subscription__offer_id" CHECK (length("offer_id") = 36 AND "offer_id" GLOB '????????-????-????-????-????????????' AND "offer_id" NOT GLOB '*[^0-9a-f-]*'),
  "price_version_id" TEXT NOT NULL CONSTRAINT "ck_commerce_subscription__price_version_id" CHECK (length("price_version_id") = 36 AND "price_version_id" GLOB '????????-????-????-????-????????????' AND "price_version_id" NOT GLOB '*[^0-9a-f-]*'),
  "state" INTEGER NOT NULL CONSTRAINT "ck_commerce_subscription__state" CHECK ("state" IN (1, 2, 3, 4, 5, 6)),
  "paid_through" INTEGER NOT NULL,
  "cancel_at_period_end" INTEGER NOT NULL CONSTRAINT "ck_commerce_subscription__cancel_at_period_end" CHECK ("cancel_at_period_end" IN (0, 1)),
  "external_subscription_ref" TEXT,
  "rev" INTEGER NOT NULL CONSTRAINT "ck_commerce_subscription__rev" CHECK ("rev" >= 0),
  CONSTRAINT "pk_commerce_subscription" PRIMARY KEY ("subscription_id")
) STRICT;

CREATE INDEX "ix_commerce_subscription__state_paid_through" ON "commerce_subscription" ("state", "paid_through");

CREATE TABLE "commerce_supplier_cost_entry" (
  "supplier_cost_id" TEXT NOT NULL CONSTRAINT "ck_commerce_supplier_cost_entry__supplier_cost_id" CHECK (length("supplier_cost_id") = 36 AND "supplier_cost_id" GLOB '????????-????-????-????-????????????' AND "supplier_cost_id" NOT GLOB '*[^0-9a-f-]*'),
  "provider_attempt_id" TEXT NOT NULL CONSTRAINT "ck_commerce_supplier_cost_entry__provider_attempt_id" CHECK (length("provider_attempt_id") = 36 AND "provider_attempt_id" GLOB '????????-????-????-????-????????????' AND "provider_attempt_id" NOT GLOB '*[^0-9a-f-]*'),
  "currency" TEXT NOT NULL CONSTRAINT "ck_commerce_supplier_cost_entry__currency" CHECK (length("currency") = 3 AND "currency" NOT GLOB '*[^A-Z]*'),
  "amount" TEXT NOT NULL CONSTRAINT "ck_commerce_supplier_cost_entry__amount" CHECK (length("amount") BETWEEN 1 AND 30 AND "amount" NOT GLOB '*[^0-9.-]*' AND "amount" NOT GLOB '*.*.*' AND "amount" NOT GLOB '*-*-*' AND "amount" NOT GLOB '*[0-9.]-*' AND "amount" NOT GLOB '.*' AND "amount" NOT GLOB '*.' AND "amount" NOT GLOB '-.*' AND "amount" NOT GLOB '-' AND "amount" NOT GLOB '0[0-9]*' AND "amount" NOT GLOB '-0[0-9]*' AND "amount" <> '-0' AND "amount" NOT GLOB '*.*0' AND (instr("amount", '.') = 0 OR length("amount") - instr("amount", '.') <= 9) AND length(replace(replace("amount", '-', ''), '.', '')) <= 28),
  "basis" INTEGER NOT NULL CONSTRAINT "ck_commerce_supplier_cost_entry__basis" CHECK ("basis" IN (1, 2, 3)),
  "unresolved" INTEGER NOT NULL CONSTRAINT "ck_commerce_supplier_cost_entry__unresolved" CHECK ("unresolved" IN (0, 1)),
  "adjusts_cost_id" TEXT CONSTRAINT "ck_commerce_supplier_cost_entry__adjusts_cost_id" CHECK (length("adjusts_cost_id") = 36 AND "adjusts_cost_id" GLOB '????????-????-????-????-????????????' AND "adjusts_cost_id" NOT GLOB '*[^0-9a-f-]*'),
  CONSTRAINT "pk_commerce_supplier_cost_entry" PRIMARY KEY ("supplier_cost_id"),
  CONSTRAINT "fk_commerce_supplier_cost_entry__provider_attempt_id" FOREIGN KEY ("provider_attempt_id") REFERENCES "commerce_provider_attempt" ("provider_attempt_id") ON DELETE RESTRICT,
  CONSTRAINT "fk_commerce_supplier_cost_entry__adjusts_cost_id" FOREIGN KEY ("adjusts_cost_id") REFERENCES "commerce_supplier_cost_entry" ("supplier_cost_id") ON DELETE RESTRICT
) STRICT;

CREATE INDEX "ix_commerce_supplier_cost_entry__basis_unresolved" ON "commerce_supplier_cost_entry" ("basis", "unresolved");

CREATE TRIGGER "tr_commerce_supplier_cost_entry__immutable_update" BEFORE UPDATE ON "commerce_supplier_cost_entry"
BEGIN
  SELECT RAISE(ABORT, 'CHECK constraint failed: af_immutable_commerce_supplier_cost_entry');
END;

CREATE TRIGGER "tr_commerce_supplier_cost_entry__immutable_delete" BEFORE DELETE ON "commerce_supplier_cost_entry"
BEGIN
  SELECT RAISE(ABORT, 'CHECK constraint failed: af_immutable_commerce_supplier_cost_entry');
END;
