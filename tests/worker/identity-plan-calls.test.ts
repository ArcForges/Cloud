// SPDX-License-Identifier: AGPL-3.0-only
// The shared vector of the identity plan calls (CLOUD.11). `tests/ArcForges.Cloud.Tests/Vectors/identity-plan-calls.json` holds a
// fixed sequence of commits (inputs) and the exact plan arguments each must produce. This test builds the arguments with the TypeScript
// builders and runs the whole sequence on the real migrations; the C# IdentityStatementTests build the same arguments from the same
// inputs with the module's own builders and compare them, so two independent implementations agree on every placeholder.
// Regenerate the file with IDENTITY_VECTORS_UPDATE=1 after a reviewed plan change.
import assert from "node:assert/strict";
import { readFileSync, writeFileSync } from "node:fs";
import path from "node:path";
import test from "node:test";
import type { D1Scalar } from "@arcforges/ai-internal";
import { base64UrlEncode } from "../../worker/private/encoding.ts";
import {
  addArguments,
  count,
  enrollArguments,
  enrollmentPlan,
  openIdentityD1,
  relabelArguments,
  renameArguments,
  revokeArguments,
  rows,
  runPlan,
  type AddInputs,
  type CredentialInput,
  type EnrollInputs,
  type RelabelInputs,
  type RenameInputs,
  type RevokeInputs,
  type TailInputs,
} from "./support/identity-support.ts";
import { repositoryRoot } from "./support/sqlite-d1.ts";

const vectorPath = path.join(
  repositoryRoot,
  "tests/ArcForges.Cloud.Tests/Vectors/identity-plan-calls.json",
);

const realm = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa";
const id = (n: number) => `00000000-0000-4000-8000-${n.toString(16).padStart(12, "0")}`;
const now = 1_790_000_000_123_456;
const tail = (n: number, at = now): TailInputs => ({
  command: id(0x1000 + n),
  now: at,
  outbox: id(0x2000 + n),
  correlation: id(0x3000 + n),
  causation: n % 2 === 0 ? id(0x4000 + n) : null,
  schema: 23,
});
const bytes = (...values: number[]) => base64UrlEncode(Uint8Array.from(values));

const ada = id(1);
const adaWorkspace = id(2);
const adaEmail: CredentialInput = {
  credentialId: id(3),
  user: ada,
  realm,
  provider: "official-email",
  method: 2,
  subject: "ada@example.test",
  label: null,
  passkey: null,
  password: null,
  createdAt: now,
};
const adaPassword: CredentialInput = {
  ...adaEmail,
  credentialId: id(4),
  provider: "self-host-password",
  method: 3,
  subject: "ada",
  label: "Café ключ 😀",
  password: "verifier-example",
  createdAt: now + 1_000_000,
};
const adaOidc: CredentialInput = {
  ...adaEmail,
  credentialId: id(5),
  provider: "corp-oidc",
  method: 4,
  subject: "https://issuer.example.test|sub-42",
  label: "Corporate sign-in",
  createdAt: now + 2_000_000,
};
const bob = id(10);
const bobPasskey: CredentialInput = {
  credentialId: id(12),
  user: bob,
  realm,
  provider: "official-passkey",
  method: 1,
  subject: "cred-id-AQIDBA",
  label: "Phone",
  passkey: {
    publicKey: bytes(1, 2, 3, 250, 251, 252),
    userHandle: bytes(9, 8, 7, 6),
    backupEligible: true,
    backupState: false,
    transports: '["internal","hybrid"]',
    signCount: 0,
  },
  password: null,
  createdAt: now + 3_000_000,
};

interface Step {
  name: string;
  op: "enroll" | "add" | "relabel" | "rename" | "revoke";
  scope: string;
  input: EnrollInputs | AddInputs | RelabelInputs | RenameInputs | RevokeInputs;
}

const steps: Step[] = [
  {
    name: "enroll an email user",
    op: "enroll",
    scope: adaWorkspace,
    input: {
      ...tail(1),
      realm,
      user: ada,
      workspace: adaWorkspace,
      credential: adaEmail,
      displayName: "Ada Lovelace",
      workspaceName: "Personal",
      region: "Automatic",
    } satisfies EnrollInputs,
  },
  {
    name: "enroll a passkey user",
    op: "enroll",
    scope: id(11),
    input: {
      ...tail(2, now + 3_000_000),
      realm,
      user: bob,
      workspace: id(11),
      credential: bobPasskey,
      displayName: "Bob",
      workspaceName: "Personal",
      region: "Automatic",
    } satisfies EnrollInputs,
  },
  {
    name: "link a password credential",
    op: "add",
    scope: adaWorkspace,
    input: {
      ...tail(3, now + 1_000_000),
      realm,
      user: ada,
      scope: adaWorkspace,
      expectedUserRevision: 1,
      credential: adaPassword,
    } satisfies AddInputs,
  },
  {
    name: "link an oidc credential",
    op: "add",
    scope: adaWorkspace,
    input: {
      ...tail(4, now + 2_000_000),
      realm,
      user: ada,
      scope: adaWorkspace,
      expectedUserRevision: 2,
      credential: adaOidc,
    } satisfies AddInputs,
  },
  {
    name: "relabel a credential",
    op: "relabel",
    scope: adaWorkspace,
    input: {
      ...tail(5),
      realm,
      user: ada,
      scope: adaWorkspace,
      target: adaPassword.credentialId,
      expectedCredentialRevision: 1,
      label: "Home server",
    } satisfies RelabelInputs,
  },
  {
    name: "clear a credential label",
    op: "relabel",
    scope: adaWorkspace,
    input: {
      ...tail(6),
      realm,
      user: ada,
      scope: adaWorkspace,
      target: adaPassword.credentialId,
      expectedCredentialRevision: 2,
      label: null,
    } satisfies RelabelInputs,
  },
  {
    name: "rename the user",
    op: "rename",
    scope: adaWorkspace,
    input: {
      ...tail(7),
      realm,
      user: ada,
      scope: adaWorkspace,
      expectedUserRevision: 3,
      displayName: "Ada King, Countess of Lovelace",
    } satisfies RenameInputs,
  },
  {
    name: "revoke the first credential",
    op: "revoke",
    scope: adaWorkspace,
    input: {
      ...tail(8, now + 9_000_000),
      realm,
      user: ada,
      scope: adaWorkspace,
      target: adaEmail.credentialId,
      expectedCredentialRevision: 1,
      expectedUserRevision: 4,
      at: now + 9_000_000,
    } satisfies RevokeInputs,
  },
];

function build(step: Step): D1Scalar[][] {
  switch (step.op) {
    case "enroll":
      return enrollArguments(step.input as EnrollInputs);
    case "add":
      return addArguments(step.input as AddInputs);
    case "relabel":
      return relabelArguments(step.input as RelabelInputs);
    case "rename":
      return renameArguments(step.input as RenameInputs);
    case "revoke":
      return revokeArguments(step.input as RevokeInputs);
  }
}

const planIds: Record<Step["op"], string> = {
  enroll: enrollmentPlan,
  add: "identity.credential-add",
  relabel: "identity.credential-relabel",
  rename: "identity.user-rename",
  revoke: "identity.credential-revoke",
};

function document() {
  return {
    schemaVersion: 1,
    note: "Generated by tests/worker/identity-plan-calls.test.ts (IDENTITY_VECTORS_UPDATE=1). Inputs are fixed; expected is the exact argument list of each plan call in placeholder order, tail and guard release included.",
    steps: steps.map((step) => ({
      name: step.name,
      op: step.op,
      plan: planIds[step.op],
      scope: step.scope,
      input: step.input,
      expected: build(step),
    })),
  };
}

test("the vector file equals what the builders produce for its inputs", () => {
  if (process.env["IDENTITY_VECTORS_UPDATE"] === "1")
    writeFileSync(vectorPath, `${JSON.stringify(document(), null, 2)}\n`);
  const stored = JSON.parse(readFileSync(vectorPath, "utf8")) as unknown;
  assert.deepEqual(stored, JSON.parse(JSON.stringify(document())));
});

test("the whole vector sequence commits on the real migrations, one receipt and one change record per step", async () => {
  const db = openIdentityD1();
  for (const step of steps) {
    const outcome = await runPlan(db, planIds[step.op], build(step), step.scope);
    assert.equal(outcome.ok, true, step.name);
  }
  assert.equal(count(db, "platform_command"), steps.length);
  assert.equal(count(db, "platform_change_archive"), steps.length);
  assert.equal(count(db, "platform_outbox"), 8, "every step publishes exactly one event");
  assert.equal(count(db, "platform_command_guard"), 0);
  // The final state: Ada keeps two usable credentials of the three, her workspace is untouched, her display name is the renamed one.
  assert.deepEqual(
    rows(db, `SELECT display_name, CAST(rev AS TEXT) FROM identity_user WHERE user_id = '${ada}'`),
    [["Ada King, Countess of Lovelace", "5"]],
  );
  assert.equal(count(db, "identity_auth_identity", `user_id = '${ada}' AND revoked_at IS NULL`), 2);
  assert.equal(count(db, "workspace_workspace", `owner_user_id = '${ada}' AND rev = 1`), 1);
  assert.deepEqual(
    rows(
      db,
      `SELECT hex(public_key), hex(user_handle), backup_eligible, backup_state, transports, sign_count FROM identity_auth_identity WHERE auth_identity_id = '${bobPasskey.credentialId}'`,
    ),
    [["010203FAFBFC", "09080706", 1, 0, '["internal","hybrid"]', 0]],
  );
});
