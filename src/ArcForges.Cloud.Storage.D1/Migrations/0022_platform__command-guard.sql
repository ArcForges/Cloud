-- af-migration: module=platform mode=expand
-- The guard rows of a guarded D1 batch (Design D1 profile section 4, "Shared family plans and the guard table"; model 01 platform.command_guard).
CREATE TABLE "platform_command_guard" (
  "command_id" TEXT NOT NULL CONSTRAINT "ck_platform_command_guard__command_id" CHECK (length("command_id") = 36 AND "command_id" GLOB '????????-????-????-????-????????????' AND "command_id" NOT GLOB '*[^0-9a-f-]*'),
  "guard_key" TEXT NOT NULL CONSTRAINT "ck_platform_command_guard__guard_key" CHECK (length("guard_key") BETWEEN 1 AND 128 AND "guard_key" NOT GLOB '*[^A-Za-z0-9._:/-]*'),
  "allowed" INTEGER NOT NULL CONSTRAINT "ck_platform_command_guard__allowed" CHECK ("allowed" IN (0, 1)),
  CONSTRAINT "pk_platform_command_guard" PRIMARY KEY ("command_id", "guard_key"),
  CONSTRAINT "ck_platform_command_guard__af_guard_failed" CHECK ("allowed" = 1)
) STRICT;

CREATE TRIGGER "tr_platform_command_guard__immutable_update" BEFORE UPDATE ON "platform_command_guard"
BEGIN
  SELECT RAISE(ABORT, 'CHECK constraint failed: af_immutable_platform_command_guard');
END;
