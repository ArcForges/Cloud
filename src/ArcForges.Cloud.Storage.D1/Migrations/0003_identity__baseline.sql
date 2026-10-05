-- af-migration: module=identity mode=expand
-- Baseline physical schema of the identity owner (generated from Physical/manifest/identity.json; Design D1 profile section 2).
CREATE TABLE "identity_api_token" (
  "token_id" TEXT NOT NULL CONSTRAINT "ck_identity_api_token__token_id" CHECK (length("token_id") = 36 AND "token_id" GLOB '????????-????-????-????-????????????' AND "token_id" NOT GLOB '*[^0-9a-f-]*'),
  "user_id" TEXT NOT NULL CONSTRAINT "ck_identity_api_token__user_id" CHECK (length("user_id") = 36 AND "user_id" GLOB '????????-????-????-????-????????????' AND "user_id" NOT GLOB '*[^0-9a-f-]*'),
  "workspace_id" TEXT NOT NULL CONSTRAINT "ck_identity_api_token__workspace_id" CHECK (length("workspace_id") = 36 AND "workspace_id" GLOB '????????-????-????-????-????????????' AND "workspace_id" NOT GLOB '*[^0-9a-f-]*'),
  "secret_hash" BLOB NOT NULL CONSTRAINT "ck_identity_api_token__secret_hash" CHECK (length("secret_hash") = 32),
  "name" TEXT NOT NULL,
  "scopes" TEXT NOT NULL CONSTRAINT "ck_identity_api_token__scopes" CHECK (CASE WHEN json_valid("scopes") THEN json_type("scopes") = 'array' ELSE 0 END),
  "created_at" INTEGER NOT NULL,
  "expires_at" INTEGER NOT NULL,
  "last_used_at" INTEGER,
  "revoked_at" INTEGER,
  "rev" INTEGER NOT NULL CONSTRAINT "ck_identity_api_token__rev" CHECK ("rev" >= 0),
  "auth_epoch" INTEGER NOT NULL,
  "recovery_generation" INTEGER NOT NULL,
  CONSTRAINT "pk_identity_api_token" PRIMARY KEY ("token_id"),
  CONSTRAINT "fk_identity_api_token__user_id" FOREIGN KEY ("user_id") REFERENCES "identity_user" ("user_id") ON DELETE RESTRICT,
  CONSTRAINT "fk_identity_api_token__workspace_id" FOREIGN KEY ("workspace_id") REFERENCES "workspace_workspace" ("workspace_id") ON DELETE RESTRICT
) STRICT;

CREATE UNIQUE INDEX "ux_identity_api_token__secret_hash" ON "identity_api_token" ("secret_hash");

CREATE INDEX "ix_identity_api_token__user_id_revoked_at" ON "identity_api_token" ("user_id", "revoked_at");

CREATE TABLE "identity_auth_identity" (
  "auth_identity_id" TEXT NOT NULL CONSTRAINT "ck_identity_auth_identity__auth_identity_id" CHECK (length("auth_identity_id") = 36 AND "auth_identity_id" GLOB '????????-????-????-????-????????????' AND "auth_identity_id" NOT GLOB '*[^0-9a-f-]*'),
  "user_id" TEXT NOT NULL CONSTRAINT "ck_identity_auth_identity__user_id" CHECK (length("user_id") = 36 AND "user_id" GLOB '????????-????-????-????-????????????' AND "user_id" NOT GLOB '*[^0-9a-f-]*'),
  "method" INTEGER NOT NULL CONSTRAINT "ck_identity_auth_identity__method" CHECK ("method" IN (1, 2, 3, 4)),
  "subject" TEXT NOT NULL,
  "public_key" BLOB,
  "user_handle" BLOB,
  "backup_eligible" INTEGER CONSTRAINT "ck_identity_auth_identity__backup_eligible" CHECK ("backup_eligible" IN (0, 1)),
  "backup_state" INTEGER CONSTRAINT "ck_identity_auth_identity__backup_state" CHECK ("backup_state" IN (0, 1)),
  "transports" TEXT CONSTRAINT "ck_identity_auth_identity__transports" CHECK (json_valid("transports")),
  "sign_count" INTEGER,
  "label" TEXT,
  "created_at" INTEGER NOT NULL,
  "last_used_at" INTEGER,
  "revoked_at" INTEGER,
  "realm_id" TEXT NOT NULL CONSTRAINT "ck_identity_auth_identity__realm_id" CHECK (length("realm_id") = 36 AND "realm_id" GLOB '????????-????-????-????-????????????' AND "realm_id" NOT GLOB '*[^0-9a-f-]*'),
  "provider_id" TEXT NOT NULL,
  "password_hash" TEXT,
  "rev" INTEGER NOT NULL CONSTRAINT "ck_identity_auth_identity__rev" CHECK ("rev" >= 0),
  CONSTRAINT "pk_identity_auth_identity" PRIMARY KEY ("auth_identity_id"),
  CONSTRAINT "fk_identity_auth_identity__user_id" FOREIGN KEY ("user_id") REFERENCES "identity_user" ("user_id") ON DELETE RESTRICT,
  CONSTRAINT "ck_identity_auth_identity__backup_state_requires_backup_eligible" CHECK ("backup_state" IS NULL OR "backup_eligible" IS NOT NULL),
  CONSTRAINT "ck_identity_auth_identity__passkey_requires_user_handle" CHECK ("method" <> 1 OR "user_handle" IS NOT NULL),
  CONSTRAINT "ck_identity_auth_identity__password_hash_only_for_password" CHECK ("method" = 3 OR "password_hash" IS NULL)
) STRICT;

CREATE UNIQUE INDEX "ux_identity_auth_identity__realm_id_provider_id_subject" ON "identity_auth_identity" ("realm_id", "provider_id", "subject");

CREATE INDEX "ix_identity_auth_identity__user_id_revoked_at" ON "identity_auth_identity" ("user_id", "revoked_at");

CREATE TABLE "identity_browser_auth_flow" (
  "flow_id" TEXT NOT NULL CONSTRAINT "ck_identity_browser_auth_flow__flow_id" CHECK (length("flow_id") = 36 AND "flow_id" GLOB '????????-????-????-????-????????????' AND "flow_id" NOT GLOB '*[^0-9a-f-]*'),
  "binding_hash" TEXT NOT NULL,
  "origin" TEXT NOT NULL,
  "method" INTEGER NOT NULL CONSTRAINT "ck_identity_browser_auth_flow__method" CHECK ("method" IN (1, 2)),
  "purpose" INTEGER NOT NULL CONSTRAINT "ck_identity_browser_auth_flow__purpose" CHECK ("purpose" IN (1, 2, 3, 4, 5)),
  "challenge" TEXT NOT NULL CONSTRAINT "ck_identity_browser_auth_flow__challenge" CHECK (json_valid("challenge")),
  "created_at" INTEGER NOT NULL,
  "expires_at" INTEGER NOT NULL,
  "attempts" INTEGER NOT NULL CONSTRAINT "ck_identity_browser_auth_flow__attempts" CHECK ("attempts" BETWEEN -2147483648 AND 2147483647),
  "max_attempts" INTEGER NOT NULL CONSTRAINT "ck_identity_browser_auth_flow__max_attempts" CHECK ("max_attempts" BETWEEN -2147483648 AND 2147483647),
  "consumed_at" INTEGER,
  "csrf_hash" TEXT NOT NULL,
  CONSTRAINT "pk_identity_browser_auth_flow" PRIMARY KEY ("flow_id"),
  CONSTRAINT "ck_identity_browser_auth_flow__purpose_authentication_recovery_enrollment" CHECK ("purpose" IN (1, 2, 4)),
  CONSTRAINT "ck_identity_browser_auth_flow__attempts_within_bound" CHECK ("attempts" >= 0 AND "attempts" <= "max_attempts")
) STRICT;

CREATE INDEX "ix_identity_browser_auth_flow__expires_at" ON "identity_browser_auth_flow" ("expires_at");

CREATE TRIGGER "tr_identity_browser_auth_flow__limited_update" BEFORE UPDATE ON "identity_browser_auth_flow"
WHEN NOT (OLD."consumed_at" IS NULL)
BEGIN
  SELECT RAISE(ABORT, 'CHECK constraint failed: af_immutable_identity_browser_auth_flow');
END;

CREATE TABLE "identity_email_address" (
  "email_id" TEXT NOT NULL CONSTRAINT "ck_identity_email_address__email_id" CHECK (length("email_id") = 36 AND "email_id" GLOB '????????-????-????-????-????????????' AND "email_id" NOT GLOB '*[^0-9a-f-]*'),
  "user_id" TEXT NOT NULL CONSTRAINT "ck_identity_email_address__user_id" CHECK (length("user_id") = 36 AND "user_id" GLOB '????????-????-????-????-????????????' AND "user_id" NOT GLOB '*[^0-9a-f-]*'),
  "address_normalised" TEXT NOT NULL,
  "verified_at" INTEGER,
  "purpose" INTEGER NOT NULL CONSTRAINT "ck_identity_email_address__purpose" CHECK ("purpose" IN (1, 2, 3)),
  CONSTRAINT "pk_identity_email_address" PRIMARY KEY ("email_id"),
  CONSTRAINT "fk_identity_email_address__user_id" FOREIGN KEY ("user_id") REFERENCES "identity_user" ("user_id") ON DELETE CASCADE
) STRICT;

CREATE UNIQUE INDEX "ux_identity_email_address__address_normalised_purpose" ON "identity_email_address" ("address_normalised", "purpose") WHERE "verified_at" IS NOT NULL;

CREATE TABLE "identity_native_authorization" (
  "flow_id" TEXT NOT NULL CONSTRAINT "ck_identity_native_authorization__flow_id" CHECK (length("flow_id") = 36 AND "flow_id" GLOB '????????-????-????-????-????????????' AND "flow_id" NOT GLOB '*[^0-9a-f-]*'),
  "realm_id" TEXT NOT NULL CONSTRAINT "ck_identity_native_authorization__realm_id" CHECK (length("realm_id") = 36 AND "realm_id" GLOB '????????-????-????-????-????????????' AND "realm_id" NOT GLOB '*[^0-9a-f-]*'),
  "installation_id" TEXT NOT NULL CONSTRAINT "ck_identity_native_authorization__installation_id" CHECK (length("installation_id") = 36 AND "installation_id" GLOB '????????-????-????-????-????????????' AND "installation_id" NOT GLOB '*[^0-9a-f-]*'),
  "client_id" TEXT NOT NULL,
  "redirect_uri" TEXT NOT NULL,
  "state_hash" TEXT NOT NULL,
  "pkce_challenge" TEXT NOT NULL,
  "code_hash" TEXT,
  "user_id" TEXT CONSTRAINT "ck_identity_native_authorization__user_id" CHECK (length("user_id") = 36 AND "user_id" GLOB '????????-????-????-????-????????????' AND "user_id" NOT GLOB '*[^0-9a-f-]*'),
  "session_id" TEXT CONSTRAINT "ck_identity_native_authorization__session_id" CHECK (length("session_id") = 36 AND "session_id" GLOB '????????-????-????-????-????????????' AND "session_id" NOT GLOB '*[^0-9a-f-]*'),
  "created_at" INTEGER NOT NULL,
  "expires_at" INTEGER NOT NULL,
  "code_expires_at" INTEGER,
  "consumed_at" INTEGER,
  "attempt_count" INTEGER NOT NULL CONSTRAINT "ck_identity_native_authorization__attempt_count" CHECK ("attempt_count" BETWEEN -2147483648 AND 2147483647),
  "rev" INTEGER NOT NULL CONSTRAINT "ck_identity_native_authorization__rev" CHECK ("rev" >= 0),
  CONSTRAINT "pk_identity_native_authorization" PRIMARY KEY ("flow_id"),
  CONSTRAINT "ck_identity_native_authorization__attempt_count_range" CHECK ("attempt_count" BETWEEN 0 AND 5)
) STRICT;

CREATE UNIQUE INDEX "ux_identity_native_authorization__code_hash" ON "identity_native_authorization" ("code_hash");

CREATE TABLE "identity_operator_access" (
  "provider_id" TEXT NOT NULL,
  "subject" TEXT NOT NULL,
  "role" TEXT NOT NULL,
  "granted_by" TEXT NOT NULL,
  "expires_at" INTEGER,
  "revoked_at" INTEGER,
  "rev" INTEGER NOT NULL CONSTRAINT "ck_identity_operator_access__rev" CHECK ("rev" >= 0),
  CONSTRAINT "pk_identity_operator_access" PRIMARY KEY ("provider_id", "subject", "role")
) STRICT;

CREATE TABLE "identity_operator_action" (
  "action_id" TEXT NOT NULL CONSTRAINT "ck_identity_operator_action__action_id" CHECK (length("action_id") = 36 AND "action_id" GLOB '????????-????-????-????-????????????' AND "action_id" NOT GLOB '*[^0-9a-f-]*'),
  "proposer" TEXT NOT NULL,
  "approver" TEXT,
  "operation_id" TEXT NOT NULL,
  "proposal_hash" TEXT NOT NULL,
  "evidence_ref" TEXT NOT NULL,
  "state" TEXT NOT NULL,
  "expires_at" INTEGER NOT NULL,
  "created_at" INTEGER NOT NULL,
  "consumed_at" INTEGER,
  "rev" INTEGER NOT NULL CONSTRAINT "ck_identity_operator_action__rev" CHECK ("rev" >= 0),
  CONSTRAINT "pk_identity_operator_action" PRIMARY KEY ("action_id")
) STRICT;

CREATE TABLE "identity_operator_session" (
  "session_id" TEXT NOT NULL CONSTRAINT "ck_identity_operator_session__session_id" CHECK (length("session_id") = 36 AND "session_id" GLOB '????????-????-????-????-????????????' AND "session_id" NOT GLOB '*[^0-9a-f-]*'),
  "provider_id" TEXT NOT NULL,
  "subject" TEXT NOT NULL,
  "tenant_id" TEXT NOT NULL,
  "handle_hash" TEXT NOT NULL,
  "issued_at" INTEGER NOT NULL,
  "expires_at" INTEGER NOT NULL,
  "revoked_at" INTEGER,
  "auth_epoch" INTEGER NOT NULL,
  "recovery_generation" INTEGER NOT NULL,
  CONSTRAINT "pk_identity_operator_session" PRIMARY KEY ("session_id")
) STRICT;

CREATE UNIQUE INDEX "ux_identity_operator_session__handle_hash" ON "identity_operator_session" ("handle_hash");

CREATE TABLE "identity_recovery_code" (
  "code_hash" BLOB NOT NULL CONSTRAINT "ck_identity_recovery_code__code_hash" CHECK (length("code_hash") = 32),
  "set_id" TEXT NOT NULL CONSTRAINT "ck_identity_recovery_code__set_id" CHECK (length("set_id") = 36 AND "set_id" GLOB '????????-????-????-????-????????????' AND "set_id" NOT GLOB '*[^0-9a-f-]*'),
  "user_id" TEXT NOT NULL CONSTRAINT "ck_identity_recovery_code__user_id" CHECK (length("user_id") = 36 AND "user_id" GLOB '????????-????-????-????-????????????' AND "user_id" NOT GLOB '*[^0-9a-f-]*'),
  "issued_at" INTEGER NOT NULL,
  "consumed_at" INTEGER,
  "invalidated_at" INTEGER,
  CONSTRAINT "pk_identity_recovery_code" PRIMARY KEY ("code_hash")
) STRICT;

CREATE INDEX "ix_identity_recovery_code__user_id_set_id" ON "identity_recovery_code" ("user_id", "set_id");

CREATE TABLE "identity_recovery_flow" (
  "flow_id" TEXT NOT NULL CONSTRAINT "ck_identity_recovery_flow__flow_id" CHECK (length("flow_id") = 36 AND "flow_id" GLOB '????????-????-????-????-????????????' AND "flow_id" NOT GLOB '*[^0-9a-f-]*'),
  "realm_id" TEXT NOT NULL CONSTRAINT "ck_identity_recovery_flow__realm_id" CHECK (length("realm_id") = 36 AND "realm_id" GLOB '????????-????-????-????-????????????' AND "realm_id" NOT GLOB '*[^0-9a-f-]*'),
  "user_id" TEXT CONSTRAINT "ck_identity_recovery_flow__user_id" CHECK (length("user_id") = 36 AND "user_id" GLOB '????????-????-????-????-????????????' AND "user_id" NOT GLOB '*[^0-9a-f-]*'),
  "method" INTEGER NOT NULL CONSTRAINT "ck_identity_recovery_flow__method" CHECK ("method" IN (1, 2, 3, 4)),
  "proof_hash" BLOB NOT NULL CONSTRAINT "ck_identity_recovery_flow__proof_hash" CHECK (length("proof_hash") = 32),
  "replacement_challenge" BLOB,
  "state" INTEGER NOT NULL CONSTRAINT "ck_identity_recovery_flow__state" CHECK ("state" IN (1, 2, 3, 4, 5)),
  "attempt_count" INTEGER NOT NULL CONSTRAINT "ck_identity_recovery_flow__attempt_count" CHECK ("attempt_count" BETWEEN -2147483648 AND 2147483647),
  "rate_limit_key" TEXT NOT NULL,
  "created_at" INTEGER NOT NULL,
  "expires_at" INTEGER NOT NULL,
  "completed_at" INTEGER,
  "auth_epoch" INTEGER NOT NULL,
  "recovery_generation" INTEGER NOT NULL,
  "rev" INTEGER NOT NULL CONSTRAINT "ck_identity_recovery_flow__rev" CHECK ("rev" >= 0),
  CONSTRAINT "pk_identity_recovery_flow" PRIMARY KEY ("flow_id"),
  CONSTRAINT "ck_identity_recovery_flow__attempt_count_range" CHECK ("attempt_count" BETWEEN 0 AND 5)
) STRICT;

CREATE INDEX "ix_identity_recovery_flow__expires_at" ON "identity_recovery_flow" ("expires_at");

CREATE TABLE "identity_security_flow" (
  "flow_id" TEXT NOT NULL CONSTRAINT "ck_identity_security_flow__flow_id" CHECK (length("flow_id") = 36 AND "flow_id" GLOB '????????-????-????-????-????????????' AND "flow_id" NOT GLOB '*[^0-9a-f-]*'),
  "kind" TEXT NOT NULL CONSTRAINT "ck_identity_security_flow__kind" CHECK (length("kind") BETWEEN 1 AND 128 AND "kind" NOT GLOB '*[^A-Za-z0-9._:/-]*'),
  "purpose" TEXT NOT NULL CONSTRAINT "ck_identity_security_flow__purpose" CHECK (length("purpose") BETWEEN 1 AND 128 AND "purpose" NOT GLOB '*[^A-Za-z0-9._:/-]*'),
  "provider" TEXT,
  "user_id" TEXT CONSTRAINT "ck_identity_security_flow__user_id" CHECK (length("user_id") = 36 AND "user_id" GLOB '????????-????-????-????-????????????' AND "user_id" NOT GLOB '*[^0-9a-f-]*'),
  "installation_id" TEXT CONSTRAINT "ck_identity_security_flow__installation_id" CHECK (length("installation_id") = 36 AND "installation_id" GLOB '????????-????-????-????-????????????' AND "installation_id" NOT GLOB '*[^0-9a-f-]*'),
  "device_id" TEXT CONSTRAINT "ck_identity_security_flow__device_id" CHECK (length("device_id") = 36 AND "device_id" GLOB '????????-????-????-????-????????????' AND "device_id" NOT GLOB '*[^0-9a-f-]*'),
  "origin" TEXT,
  "proof_hash" BLOB NOT NULL CONSTRAINT "ck_identity_security_flow__proof_hash" CHECK (length("proof_hash") = 32),
  "target_payload_hash" BLOB NOT NULL CONSTRAINT "ck_identity_security_flow__target_payload_hash" CHECK (length("target_payload_hash") = 32),
  "expires_at" INTEGER NOT NULL,
  "attempts" INTEGER NOT NULL CONSTRAINT "ck_identity_security_flow__attempts" CHECK ("attempts" BETWEEN -2147483648 AND 2147483647),
  "consumed_at" INTEGER,
  "payload_proto" BLOB NOT NULL,
  CONSTRAINT "pk_identity_security_flow" PRIMARY KEY ("flow_id")
) STRICT;

CREATE TABLE "identity_session" (
  "session_id" TEXT NOT NULL CONSTRAINT "ck_identity_session__session_id" CHECK (length("session_id") = 36 AND "session_id" GLOB '????????-????-????-????-????????????' AND "session_id" NOT GLOB '*[^0-9a-f-]*'),
  "user_id" TEXT NOT NULL CONSTRAINT "ck_identity_session__user_id" CHECK (length("user_id") = 36 AND "user_id" GLOB '????????-????-????-????-????????????' AND "user_id" NOT GLOB '*[^0-9a-f-]*'),
  "device_id" TEXT NOT NULL CONSTRAINT "ck_identity_session__device_id" CHECK (length("device_id") = 36 AND "device_id" GLOB '????????-????-????-????-????????????' AND "device_id" NOT GLOB '*[^0-9a-f-]*'),
  "installation_id" TEXT NOT NULL CONSTRAINT "ck_identity_session__installation_id" CHECK (length("installation_id") = 36 AND "installation_id" GLOB '????????-????-????-????-????????????' AND "installation_id" NOT GLOB '*[^0-9a-f-]*'),
  "issued_at" INTEGER NOT NULL,
  "expires_at" INTEGER NOT NULL,
  "revoked_at" INTEGER,
  "credential_kind" INTEGER NOT NULL CONSTRAINT "ck_identity_session__credential_kind" CHECK ("credential_kind" IN (1, 2)),
  "refresh_token_hash" TEXT,
  "browser_handle_hash" TEXT,
  "browser_origin" TEXT,
  "idle_expires_at" INTEGER,
  "last_activity_at" INTEGER,
  "session_policy_version" TEXT NOT NULL,
  "refresh_generation" INTEGER CONSTRAINT "ck_identity_session__refresh_generation" CHECK ("refresh_generation" BETWEEN -2147483648 AND 2147483647),
  "step_up_at" INTEGER,
  "step_up_classes" TEXT NOT NULL CONSTRAINT "ck_identity_session__step_up_classes" CHECK (CASE WHEN json_valid("step_up_classes") THEN json_type("step_up_classes") = 'array' ELSE 0 END),
  "access_token_hash" TEXT,
  "access_expires_at" INTEGER,
  "csrf_hash" TEXT,
  "purpose" INTEGER NOT NULL CONSTRAINT "ck_identity_session__purpose" CHECK ("purpose" IN (1, 2, 3, 4, 5)),
  "auth_epoch" INTEGER NOT NULL,
  "recovery_generation" INTEGER NOT NULL,
  "rev" INTEGER NOT NULL,
  "family_id" TEXT CONSTRAINT "ck_identity_session__family_id" CHECK (length("family_id") = 36 AND "family_id" GLOB '????????-????-????-????-????????????' AND "family_id" NOT GLOB '*[^0-9a-f-]*'),
  "product_id" TEXT NOT NULL CONSTRAINT "ck_identity_session__product_id" CHECK ("product_id" IN ('arcscope', 'companion')),
  CONSTRAINT "pk_identity_session" PRIMARY KEY ("session_id"),
  CONSTRAINT "fk_identity_session__user_id" FOREIGN KEY ("user_id") REFERENCES "identity_user" ("user_id") ON DELETE CASCADE,
  CONSTRAINT "fk_identity_session__device_id" FOREIGN KEY ("device_id") REFERENCES "device_device" ("device_id") ON DELETE RESTRICT,
  CONSTRAINT "ck_identity_session__native_bearer_credential_shape" CHECK ("credential_kind" <> 1 OR ("refresh_token_hash" IS NOT NULL AND "refresh_generation" IS NOT NULL AND "browser_handle_hash" IS NULL AND "browser_origin" IS NULL AND "idle_expires_at" IS NULL)),
  CONSTRAINT "ck_identity_session__browser_cookie_credential_shape" CHECK ("credential_kind" <> 2 OR ("browser_handle_hash" IS NOT NULL AND "browser_origin" IS NOT NULL AND "idle_expires_at" IS NOT NULL AND "csrf_hash" IS NOT NULL AND "refresh_token_hash" IS NULL AND "refresh_generation" IS NULL AND "family_id" IS NULL AND "access_token_hash" IS NULL)),
  CONSTRAINT "ck_identity_session__refresh_hash_requires_family" CHECK ("refresh_token_hash" IS NULL OR "family_id" IS NOT NULL),
  CONSTRAINT "ck_identity_session__access_hash_requires_access_expiry" CHECK ("access_token_hash" IS NULL OR "access_expires_at" IS NOT NULL),
  CONSTRAINT "ck_identity_session__idle_expiry_not_after_absolute" CHECK ("idle_expires_at" IS NULL OR "idle_expires_at" <= "expires_at")
) STRICT;

CREATE INDEX "ix_identity_session__user_id_revoked_at_expires_at" ON "identity_session" ("user_id", "revoked_at", "expires_at");

CREATE INDEX "ix_identity_session__device_id" ON "identity_session" ("device_id");

CREATE UNIQUE INDEX "ux_identity_session__refresh_token_hash" ON "identity_session" ("refresh_token_hash") WHERE "refresh_token_hash" IS NOT NULL;

CREATE UNIQUE INDEX "ux_identity_session__browser_handle_hash" ON "identity_session" ("browser_handle_hash") WHERE "browser_handle_hash" IS NOT NULL;

CREATE UNIQUE INDEX "ux_identity_session__access_token_hash" ON "identity_session" ("access_token_hash") WHERE "access_token_hash" IS NOT NULL;

CREATE INDEX "ix_identity_session__browser_origin_idle_expires_at" ON "identity_session" ("browser_origin", "idle_expires_at");

CREATE TABLE "identity_spent_refresh" (
  "token_hash" BLOB NOT NULL CONSTRAINT "ck_identity_spent_refresh__token_hash" CHECK (length("token_hash") = 32),
  "session_id" TEXT NOT NULL CONSTRAINT "ck_identity_spent_refresh__session_id" CHECK (length("session_id") = 36 AND "session_id" GLOB '????????-????-????-????-????????????' AND "session_id" NOT GLOB '*[^0-9a-f-]*'),
  "family_id" TEXT NOT NULL CONSTRAINT "ck_identity_spent_refresh__family_id" CHECK (length("family_id") = 36 AND "family_id" GLOB '????????-????-????-????-????????????' AND "family_id" NOT GLOB '*[^0-9a-f-]*'),
  "generation" INTEGER NOT NULL,
  "consumed_at" INTEGER NOT NULL,
  "family_expires_at" INTEGER NOT NULL,
  CONSTRAINT "pk_identity_spent_refresh" PRIMARY KEY ("token_hash"),
  CONSTRAINT "fk_identity_spent_refresh__session_id" FOREIGN KEY ("session_id") REFERENCES "identity_session" ("session_id") ON DELETE RESTRICT
) STRICT;

CREATE UNIQUE INDEX "ux_identity_spent_refresh__family_id_generation" ON "identity_spent_refresh" ("family_id", "generation");

CREATE TABLE "identity_step_up_challenge" (
  "challenge_id" TEXT NOT NULL CONSTRAINT "ck_identity_step_up_challenge__challenge_id" CHECK (length("challenge_id") = 36 AND "challenge_id" GLOB '????????-????-????-????-????????????' AND "challenge_id" NOT GLOB '*[^0-9a-f-]*'),
  "user_id" TEXT NOT NULL CONSTRAINT "ck_identity_step_up_challenge__user_id" CHECK (length("user_id") = 36 AND "user_id" GLOB '????????-????-????-????-????????????' AND "user_id" NOT GLOB '*[^0-9a-f-]*'),
  "session_id" TEXT NOT NULL CONSTRAINT "ck_identity_step_up_challenge__session_id" CHECK (length("session_id") = 36 AND "session_id" GLOB '????????-????-????-????-????????????' AND "session_id" NOT GLOB '*[^0-9a-f-]*'),
  "operation_class" TEXT NOT NULL,
  "target_hash" TEXT NOT NULL,
  "method" TEXT NOT NULL,
  "proof_hash" BLOB NOT NULL CONSTRAINT "ck_identity_step_up_challenge__proof_hash" CHECK (length("proof_hash") = 32),
  "state" INTEGER NOT NULL CONSTRAINT "ck_identity_step_up_challenge__state" CHECK ("state" IN (1, 2, 3, 4, 5)),
  "attempt_count" INTEGER NOT NULL CONSTRAINT "ck_identity_step_up_challenge__attempt_count" CHECK ("attempt_count" BETWEEN -2147483648 AND 2147483647),
  "created_at" INTEGER NOT NULL,
  "expires_at" INTEGER NOT NULL,
  "consumed_at" INTEGER,
  "auth_epoch" INTEGER NOT NULL,
  "recovery_generation" INTEGER NOT NULL,
  "rev" INTEGER NOT NULL CONSTRAINT "ck_identity_step_up_challenge__rev" CHECK ("rev" >= 0),
  CONSTRAINT "pk_identity_step_up_challenge" PRIMARY KEY ("challenge_id"),
  CONSTRAINT "fk_identity_step_up_challenge__user_id" FOREIGN KEY ("user_id") REFERENCES "identity_user" ("user_id") ON DELETE RESTRICT,
  CONSTRAINT "fk_identity_step_up_challenge__session_id" FOREIGN KEY ("session_id") REFERENCES "identity_session" ("session_id") ON DELETE RESTRICT,
  CONSTRAINT "ck_identity_step_up_challenge__attempt_count_range" CHECK ("attempt_count" BETWEEN 0 AND 5)
) STRICT;

CREATE INDEX "ix_identity_step_up_challenge__session_id_expires_at" ON "identity_step_up_challenge" ("session_id", "expires_at");

CREATE TABLE "identity_user" (
  "user_id" TEXT NOT NULL CONSTRAINT "ck_identity_user__user_id" CHECK (length("user_id") = 36 AND "user_id" GLOB '????????-????-????-????-????????????' AND "user_id" NOT GLOB '*[^0-9a-f-]*'),
  "realm_id" TEXT NOT NULL CONSTRAINT "ck_identity_user__realm_id" CHECK (length("realm_id") = 36 AND "realm_id" GLOB '????????-????-????-????-????????????' AND "realm_id" NOT GLOB '*[^0-9a-f-]*'),
  "display_name" TEXT NOT NULL,
  "state" INTEGER NOT NULL CONSTRAINT "ck_identity_user__state" CHECK ("state" IN (1, 2, 3, 4, 5)),
  "created_at" INTEGER NOT NULL,
  "deletion_requested_at" INTEGER,
  "rev" INTEGER NOT NULL CONSTRAINT "ck_identity_user__rev" CHECK ("rev" >= 0),
  CONSTRAINT "pk_identity_user" PRIMARY KEY ("user_id")
) STRICT;

CREATE INDEX "ix_identity_user__realm_id_state" ON "identity_user" ("realm_id", "state");
