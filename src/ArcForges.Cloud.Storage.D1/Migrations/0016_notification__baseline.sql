-- af-migration: module=notification mode=expand
-- Baseline physical schema of the notification owner (generated from Physical/manifest/notification.json; Design D1 profile section 2).
CREATE TABLE "notification_delivery" (
  "delivery_id" TEXT NOT NULL CONSTRAINT "ck_notification_delivery__delivery_id" CHECK (length("delivery_id") = 36 AND "delivery_id" GLOB '????????-????-????-????-????????????' AND "delivery_id" NOT GLOB '*[^0-9a-f-]*'),
  "user_id" TEXT NOT NULL CONSTRAINT "ck_notification_delivery__user_id" CHECK (length("user_id") = 36 AND "user_id" GLOB '????????-????-????-????-????????????' AND "user_id" NOT GLOB '*[^0-9a-f-]*'),
  "template_version" TEXT NOT NULL,
  "purpose" TEXT NOT NULL,
  "recipient_hash" TEXT NOT NULL,
  "recipient_secret_ref" TEXT NOT NULL,
  "state" INTEGER NOT NULL CONSTRAINT "ck_notification_delivery__state" CHECK ("state" IN (1, 2, 3, 4, 5, 6, 7, 8, 9)),
  "challenge_ref" TEXT CONSTRAINT "ck_notification_delivery__challenge_ref" CHECK (length("challenge_ref") = 36 AND "challenge_ref" GLOB '????????-????-????-????-????????????' AND "challenge_ref" NOT GLOB '*[^0-9a-f-]*'),
  "security_epoch" INTEGER NOT NULL,
  "current_attempt_id" TEXT CONSTRAINT "ck_notification_delivery__current_attempt_id" CHECK (length("current_attempt_id") = 36 AND "current_attempt_id" GLOB '????????-????-????-????-????????????' AND "current_attempt_id" NOT GLOB '*[^0-9a-f-]*'),
  "created_at" INTEGER NOT NULL,
  "expires_at" INTEGER NOT NULL,
  "rev" INTEGER NOT NULL CONSTRAINT "ck_notification_delivery__rev" CHECK ("rev" >= 0),
  CONSTRAINT "pk_notification_delivery" PRIMARY KEY ("delivery_id"),
  CONSTRAINT "fk_notification_delivery__user_id" FOREIGN KEY ("user_id") REFERENCES "identity_user" ("user_id") ON DELETE RESTRICT
) STRICT;

CREATE INDEX "ix_notification_delivery__state_expires_at" ON "notification_delivery" ("state", "expires_at");

CREATE TABLE "notification_delivery_attempt" (
  "attempt_id" TEXT NOT NULL CONSTRAINT "ck_notification_delivery_attempt__attempt_id" CHECK (length("attempt_id") = 36 AND "attempt_id" GLOB '????????-????-????-????-????????????' AND "attempt_id" NOT GLOB '*[^0-9a-f-]*'),
  "delivery_id" TEXT NOT NULL CONSTRAINT "ck_notification_delivery_attempt__delivery_id" CHECK (length("delivery_id") = 36 AND "delivery_id" GLOB '????????-????-????-????-????????????' AND "delivery_id" NOT GLOB '*[^0-9a-f-]*'),
  "provider" INTEGER NOT NULL CONSTRAINT "ck_notification_delivery_attempt__provider" CHECK ("provider" IN (1, 2)),
  "dispatch_state" INTEGER NOT NULL CONSTRAINT "ck_notification_delivery_attempt__dispatch_state" CHECK ("dispatch_state" IN (1, 2, 3, 4, 5)),
  "request_hash" BLOB NOT NULL CONSTRAINT "ck_notification_delivery_attempt__request_hash" CHECK (length("request_hash") = 32),
  "provider_message_id" TEXT,
  "accepted_at" INTEGER,
  "outcome" TEXT CONSTRAINT "ck_notification_delivery_attempt__outcome" CHECK (length("outcome") BETWEEN 1 AND 128 AND "outcome" NOT GLOB '*[^A-Za-z0-9._:/-]*'),
  "reconciled_at" INTEGER,
  CONSTRAINT "pk_notification_delivery_attempt" PRIMARY KEY ("attempt_id"),
  CONSTRAINT "fk_notification_delivery_attempt__delivery_id" FOREIGN KEY ("delivery_id") REFERENCES "notification_delivery" ("delivery_id") ON DELETE RESTRICT
) STRICT;

CREATE UNIQUE INDEX "ux_notification_delivery_attempt__provider_provider_message_id" ON "notification_delivery_attempt" ("provider", "provider_message_id");

CREATE INDEX "ix_notification_delivery_attempt__dispatch_state_reconciled_at" ON "notification_delivery_attempt" ("dispatch_state", "reconciled_at");

CREATE TABLE "notification_notification" (
  "notification_id" TEXT NOT NULL CONSTRAINT "ck_notification_notification__notification_id" CHECK (length("notification_id") = 36 AND "notification_id" GLOB '????????-????-????-????-????????????' AND "notification_id" NOT GLOB '*[^0-9a-f-]*'),
  "workspace_id" TEXT NOT NULL CONSTRAINT "ck_notification_notification__workspace_id" CHECK (length("workspace_id") = 36 AND "workspace_id" GLOB '????????-????-????-????-????????????' AND "workspace_id" NOT GLOB '*[^0-9a-f-]*'),
  "user_id" TEXT NOT NULL CONSTRAINT "ck_notification_notification__user_id" CHECK (length("user_id") = 36 AND "user_id" GLOB '????????-????-????-????-????????????' AND "user_id" NOT GLOB '*[^0-9a-f-]*'),
  "product_id" TEXT CONSTRAINT "ck_notification_notification__product_id" CHECK ("product_id" IN ('arcscope', 'companion')),
  "kind" TEXT NOT NULL CONSTRAINT "ck_notification_notification__kind" CHECK (length("kind") BETWEEN 1 AND 128 AND "kind" NOT GLOB '*[^A-Za-z0-9._:/-]*'),
  "owner_ref_kind" TEXT NOT NULL CONSTRAINT "ck_notification_notification__owner_ref_kind" CHECK (length("owner_ref_kind") BETWEEN 1 AND 128 AND "owner_ref_kind" NOT GLOB '*[^A-Za-z0-9._:/-]*'),
  "owner_ref_id" TEXT NOT NULL CONSTRAINT "ck_notification_notification__owner_ref_id" CHECK (length("owner_ref_id") = 36 AND "owner_ref_id" GLOB '????????-????-????-????-????????????' AND "owner_ref_id" NOT GLOB '*[^0-9a-f-]*'),
  "durability" INTEGER NOT NULL CONSTRAINT "ck_notification_notification__durability" CHECK ("durability" IN (1, 2)),
  "created_at" INTEGER NOT NULL,
  "expires_at" INTEGER,
  "resolved_at" INTEGER,
  "rev" INTEGER NOT NULL CONSTRAINT "ck_notification_notification__rev" CHECK ("rev" >= 0),
  CONSTRAINT "pk_notification_notification" PRIMARY KEY ("notification_id")
) STRICT;

CREATE INDEX "ix_notification_notification__workspace_id_durability_resolved_at" ON "notification_notification" ("workspace_id", "durability", "resolved_at");

CREATE TABLE "notification_provider_event" (
  "provider" TEXT NOT NULL,
  "event_id" TEXT NOT NULL,
  "delivery_id" TEXT NOT NULL CONSTRAINT "ck_notification_provider_event__delivery_id" CHECK (length("delivery_id") = 36 AND "delivery_id" GLOB '????????-????-????-????-????????????' AND "delivery_id" NOT GLOB '*[^0-9a-f-]*'),
  "attempt_id" TEXT NOT NULL CONSTRAINT "ck_notification_provider_event__attempt_id" CHECK (length("attempt_id") = 36 AND "attempt_id" GLOB '????????-????-????-????-????????????' AND "attempt_id" NOT GLOB '*[^0-9a-f-]*'),
  "body_hash" BLOB NOT NULL CONSTRAINT "ck_notification_provider_event__body_hash" CHECK (length("body_hash") = 32),
  "kind" TEXT NOT NULL CONSTRAINT "ck_notification_provider_event__kind" CHECK (length("kind") BETWEEN 1 AND 128 AND "kind" NOT GLOB '*[^A-Za-z0-9._:/-]*'),
  "received_at" INTEGER NOT NULL,
  "applied_at" INTEGER,
  CONSTRAINT "pk_notification_provider_event" PRIMARY KEY ("provider", "event_id")
) STRICT;

CREATE TABLE "notification_push_delivery" (
  "delivery_id" TEXT NOT NULL CONSTRAINT "ck_notification_push_delivery__delivery_id" CHECK (length("delivery_id") = 36 AND "delivery_id" GLOB '????????-????-????-????-????????????' AND "delivery_id" NOT GLOB '*[^0-9a-f-]*'),
  "notification_id" TEXT NOT NULL CONSTRAINT "ck_notification_push_delivery__notification_id" CHECK (length("notification_id") = 36 AND "notification_id" GLOB '????????-????-????-????-????????????' AND "notification_id" NOT GLOB '*[^0-9a-f-]*'),
  "registration_id" TEXT NOT NULL CONSTRAINT "ck_notification_push_delivery__registration_id" CHECK (length("registration_id") = 36 AND "registration_id" GLOB '????????-????-????-????-????????????' AND "registration_id" NOT GLOB '*[^0-9a-f-]*'),
  "registration_revision" INTEGER NOT NULL,
  "recovery_generation" INTEGER NOT NULL,
  "state" INTEGER NOT NULL CONSTRAINT "ck_notification_push_delivery__state" CHECK ("state" IN (1, 2, 3, 4, 5, 6)),
  "expires_at" INTEGER NOT NULL,
  "next_attempt_at" INTEGER NOT NULL,
  "created_at" INTEGER NOT NULL,
  "attempt_count" INTEGER NOT NULL,
  "lease_fence" INTEGER NOT NULL,
  "provider_message_id" TEXT,
  "last_reason" TEXT CONSTRAINT "ck_notification_push_delivery__last_reason" CHECK (length("last_reason") BETWEEN 1 AND 128 AND "last_reason" NOT GLOB '*[^A-Za-z0-9._:/-]*'),
  "completed_at" INTEGER,
  CONSTRAINT "pk_notification_push_delivery" PRIMARY KEY ("delivery_id")
) STRICT;

CREATE UNIQUE INDEX "ux_notification_push_delivery__notification_id_registration_id_registration_revision_recovery_generation" ON "notification_push_delivery" ("notification_id", "registration_id", "registration_revision", "recovery_generation");

CREATE TRIGGER "tr_notification_push_delivery__monotonic_lease_fence" BEFORE UPDATE OF "lease_fence" ON "notification_push_delivery"
WHEN NEW."lease_fence" < OLD."lease_fence"
BEGIN
  SELECT RAISE(ABORT, 'CHECK constraint failed: af_monotonic_notification_push_delivery_lease_fence');
END;

CREATE TABLE "notification_push_registration" (
  "registration_id" TEXT NOT NULL CONSTRAINT "ck_notification_push_registration__registration_id" CHECK (length("registration_id") = 36 AND "registration_id" GLOB '????????-????-????-????-????????????' AND "registration_id" NOT GLOB '*[^0-9a-f-]*'),
  "device_id" TEXT NOT NULL CONSTRAINT "ck_notification_push_registration__device_id" CHECK (length("device_id") = 36 AND "device_id" GLOB '????????-????-????-????-????????????' AND "device_id" NOT GLOB '*[^0-9a-f-]*'),
  "installation_id" TEXT NOT NULL CONSTRAINT "ck_notification_push_registration__installation_id" CHECK (length("installation_id") = 36 AND "installation_id" GLOB '????????-????-????-????-????????????' AND "installation_id" NOT GLOB '*[^0-9a-f-]*'),
  "registration_revision" INTEGER NOT NULL,
  "encrypted_token" TEXT NOT NULL,
  "token_hash" TEXT NOT NULL,
  "recovery_generation" INTEGER NOT NULL,
  "updated_at" INTEGER NOT NULL,
  CONSTRAINT "pk_notification_push_registration" PRIMARY KEY ("registration_id")
) STRICT;

CREATE UNIQUE INDEX "ux_notification_push_registration__device_id_installation_id" ON "notification_push_registration" ("device_id", "installation_id");

CREATE TRIGGER "tr_notification_push_registration__monotonic_registration_revision" BEFORE UPDATE OF "registration_revision" ON "notification_push_registration"
WHEN NEW."registration_revision" < OLD."registration_revision"
BEGIN
  SELECT RAISE(ABORT, 'CHECK constraint failed: af_monotonic_notification_push_registration_registration_revision');
END;

CREATE TABLE "notification_suppression" (
  "recipient_hash" TEXT NOT NULL,
  "stream" INTEGER NOT NULL CONSTRAINT "ck_notification_suppression__stream" CHECK ("stream" IN (1, 2)),
  "reason" INTEGER NOT NULL CONSTRAINT "ck_notification_suppression__reason" CHECK ("reason" IN (1, 2, 3)),
  "provider_event_id" TEXT,
  "created_at" INTEGER NOT NULL,
  "cleared_at" INTEGER,
  "rev" INTEGER NOT NULL CONSTRAINT "ck_notification_suppression__rev" CHECK ("rev" >= 0),
  CONSTRAINT "pk_notification_suppression" PRIMARY KEY ("recipient_hash", "stream")
) STRICT;
