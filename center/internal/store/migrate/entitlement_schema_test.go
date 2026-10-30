// SPDX-License-Identifier: AGPL-3.0-only

package migrate

import (
	"context"
	"errors"
	"io/fs"
	"strings"
	"testing"
	"testing/fstest"

	"github.com/jackc/pgx/v5/pgconn"

	"github.com/ArcForges/Cloud/center/internal/pgtest"
	"github.com/ArcForges/Cloud/center/internal/schema"
)

// migration0003SHA256 pins the applied form of 0003_entitlement.sql: a migration that has been applied is immutable (the runner
// refuses a changed one), so this value only changes before the migration is merged. The successor provenance record
// center-runtime-r20 pins the same file by its hash.
const migration0003SHA256 = "8eaca09b91e57abc9514c70ced246f965b31f9a2bf898fdb9dabadb2bd7c3f9d"

// schemasAndGrantsAt are the schemas and the runtime role's grants as the build at a migration version has them: 0003 adds the
// entitlement schema and, in the identity schema, the operator table.
func schemasAndGrantsAt(version int) ([]string, []schema.Grant) {
	if version >= 3 {
		return schema.Schemas, schema.RuntimeGrants
	}
	var schemas []string
	for _, name := range schema.Schemas {
		if name != "entitlement" {
			schemas = append(schemas, name)
		}
	}
	var grants []schema.Grant
	for _, grant := range schema.RuntimeGrants {
		if grant.Schema != "entitlement" && !(grant.Schema == "identity" && grant.Table == "operator") {
			grants = append(grants, grant)
		}
	}
	return schemas, grants
}

// TestMigration0003LandsWholeOverVersion2 rehearses the production step of 0003 as TestMigration0002LandsWholeOverVersion1 does for
// 0002: a database at version 2 (production's state after part A), owned by a migration role that is not a superuser, receives 0003
// from the center's own runner. 0003 runs in one transaction: a copy of it that fails at its last statement leaves the database at
// version 2 with nothing of 0003, so a failed deployment leaves the running revision's store as it was; the real 0003 then lands, its
// checksum is the pinned one, and the runtime role holds exactly the declared grants on its tables.
func TestMigration0003LandsWholeOverVersion2(t *testing.T) {
	build := centerBuild(t)
	if len(build) < 3 || build[2].Name != "0003_entitlement.sql" {
		t.Fatalf("the build has no 0003 as its third migration: %d migrations", len(build))
	}
	if build[2].SHA256 != migration0003SHA256 {
		t.Fatalf("0003_entitlement.sql has the checksum %s, pinned %s", build[2].SHA256, migration0003SHA256)
	}
	ctx := context.Background()
	schemas2, grants2 := schemasAndGrantsAt(2)
	for _, failing := range []bool{true, false} {
		url, name := pgtest.Database(t)
		conn := pgtest.Connect(t, url)
		if second, err := apply(t, url, build[:2], Options{Runner: "test", RuntimeRole: name + "_runtime", Schemas: schemas2, Grants: grants2}); err != nil || second.Version != 2 {
			t.Fatalf("version 2: %+v %v", second, err)
		}
		options := Options{Runner: "test", RuntimeRole: name + "_runtime"}
		if failing {
			broken := fstest.MapFS{}
			entries, err := fs.ReadDir(schema.Migrations(), ".")
			if err != nil {
				t.Fatal(err)
			}
			for _, entry := range entries {
				data, err := fs.ReadFile(schema.Migrations(), entry.Name())
				if err != nil {
					t.Fatal(err)
				}
				if entry.Name() == "0003_entitlement.sql" {
					data = append(data, []byte("\nSELECT 1 / 0;\n")...)
				}
				broken[entry.Name()] = &fstest.MapFile{Data: data}
			}
			failingBuild, err := Load(broken)
			if err != nil {
				t.Fatal(err)
			}
			_, err = apply(t, url, failingBuild, options)
			var failure *Failure
			if !errors.As(err, &failure) || failure.Name != "0003_entitlement.sql" || failure.SQLState != "22012" {
				t.Fatalf("the failing 0003: %v", err)
			}
			status, err := Inspect(ctx, conn, build)
			var objects string
			if err == nil {
				err = conn.QueryRow(ctx, `SELECT coalesce(string_agg(name, ', ' ORDER BY name), '') FROM (
    SELECT 'schema ' || nspname AS name FROM pg_namespace WHERE nspname = 'entitlement'
    UNION ALL SELECT 'table identity.operator' FROM pg_class WHERE relname = 'operator' AND relnamespace = 'identity'::regnamespace
    UNION ALL SELECT 'function ' || n.nspname || '.' || p.proname FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace
        WHERE (n.nspname = 'entitlement') OR (n.nspname = 'identity' AND p.proname = 'operator_only_revokes')) found`).Scan(&objects)
			}
			if err != nil || status.Version != 2 || status.State != StatePending || len(status.Pending) != 1 || objects != "" {
				t.Fatalf("after the failed 0003: %+v objects=%q %v", status, objects, err)
			}
			continue
		}
		result, err := apply(t, url, build, options)
		if err != nil || result.Version != 3 || len(result.Ran) != 1 || result.Ran[0].Name != "0003_entitlement.sql" ||
			result.Ran[0].SHA256 != migration0003SHA256 || result.Grants != "reconciled" || result.State != StateCurrent {
			t.Fatalf("0003 over version 2: %+v %v", result, err)
		}
		t.Logf("0003 applied over version 2 by a non-superuser owner in %d ms, sha256 %s", result.Ran[0].DurationMS, result.Ran[0].SHA256)
		privilege := func(table, kind string) bool {
			var has bool
			if err := conn.QueryRow(ctx, "SELECT has_table_privilege($1, $2, $3)", name+"_runtime", table, kind).Scan(&has); err != nil {
				t.Fatal(err)
			}
			return has
		}
		for table, want := range map[string]string{
			"entitlement.grant": "SI", "entitlement.revocation": "SI", "entitlement.service_term": "SI", "entitlement.definitions_activation": "SI",
			"entitlement.snapshot": "SIU", "entitlement.revision": "SIU", "entitlement.service_term_action": "S", "entitlement.account_status_fact": "S",
			"entitlement.feature_release": "S", "identity.operator": "S",
		} {
			for letter, kind := range map[string]string{"S": "SELECT", "I": "INSERT", "U": "UPDATE"} {
				if got := privilege(table, kind); got != strings.Contains(want, letter) {
					t.Errorf("the runtime role's %s on %s is %v, declared %q", kind, table, got, want)
				}
			}
			if privilege(table, "DELETE") || privilege(table, "TRUNCATE") {
				t.Errorf("the runtime role may delete from %s", table)
			}
		}
	}
}

// TestTheEntitlementStoreConstraints holds migration 0003 to its invariants with the migration role, independently of the code that
// writes the rows: the shape of every grant kind, the reason a privileged source needs, the same-account foreign keys, the idempotency
// indexes, the append-only triggers, the one-step revision and the operator row that only ever revokes. Each refused case names the
// constraint that must refuse it, and the rows it builds on exist before it runs.
func TestTheEntitlementStoreConstraints(t *testing.T) {
	url, name := pgtest.Database(t)
	if _, err := apply(t, url, centerBuild(t), Options{Runner: "test", RuntimeRole: name + "_runtime"}); err != nil {
		t.Fatal(err)
	}
	conn := pgtest.Connect(t, url)
	ctx := context.Background()
	must := func(t *testing.T, statement string) {
		t.Helper()
		if _, err := conn.Exec(ctx, statement); err != nil {
			t.Fatalf("%s: %v", statement, err)
		}
	}
	const (
		user   = "00000000-0000-4000-8000-000000000001"
		other  = "00000000-0000-4000-8000-000000000002"
		grant  = "00000000-0000-4000-8000-0000000000a1"
		term   = "00000000-0000-4000-8000-0000000000b1"
		termB  = "00000000-0000-4000-8000-0000000000b2"
		action = "00000000-0000-4000-8000-0000000000c1"
	)
	must(t, "INSERT INTO identity.user (user_id, display_name, state, passkey_user_handle, created_at, rev) VALUES ('"+user+"', 'Owner', 1, decode(repeat('01', 32), 'hex'), now(), 1)")
	must(t, "INSERT INTO identity.user (user_id, display_name, state, passkey_user_handle, created_at, rev) VALUES ('"+other+"', 'Other', 1, decode(repeat('02', 32), 'hex'), now(), 1)")
	insertGrant := func(id, account, kind, subject, value, source, ref, reason string) string {
		return "INSERT INTO entitlement.grant (grant_id, account_id, kind, subject, value, source, source_ref, effective_from, issued_by_actor, created_at, reason) VALUES (" +
			id + ", '" + account + "', " + kind + ", '" + subject + "', '" + value + "'::jsonb, " + source + ", " + ref + ", now(), 'commerce', now(), " + reason + ")"
	}
	must(t, insertGrant("'"+grant+"'", user, "1", "center.nodes", "{}", "5", "'ticket-1'", "'goodwill'"))
	must(t, insertGrant("gen_random_uuid()", user, "2", "q.bytes", `{"limit":100000000000000,"priority":9223372036854775807}`, "1", "'sub-1'", "NULL"))
	must(t, insertGrant("gen_random_uuid()", user, "3", "ai.capacity", `{"capacityPlanRef":"plan-basic","priority":0}`, "1", "'sub-2'", "NULL"))
	must(t, "INSERT INTO entitlement.service_term (term_id, account_id, kind, period_ref, starts_at, ends_at, authorized_at, created_at) VALUES ('"+term+"', '"+user+"', 3, 'ticket-1', now(), now() + interval '30 days', now(), now())")
	must(t, "INSERT INTO entitlement.service_term (term_id, account_id, kind, period_ref, starts_at, ends_at, authorized_at, created_at) VALUES ('"+termB+"', '"+other+"', 3, 'ticket-2', now(), now() + interval '30 days', now(), now())")
	must(t, "INSERT INTO entitlement.revision (account_id, rev, updated_at) VALUES ('"+user+"', 1, now())")
	must(t, "INSERT INTO entitlement.service_term_action (action_id, account_id, term_id, kind, effective_at, recorded_at, source_ref) VALUES ('"+action+"', '"+user+"', '"+term+"', 2, now(), now(), 'revoke-1')")
	must(t, "INSERT INTO entitlement.account_status_fact (status_fact_id, account_id, recorded_at, status, auto_renew, purchase_pending, source_ref) VALUES (gen_random_uuid(), '"+user+"', now(), 1, true, false, 'status-1')")
	must(t, "INSERT INTO entitlement.feature_release (feature_key, released_at) VALUES ('center.nodes', now())")
	must(t, "INSERT INTO entitlement.definitions_activation (account_id, activated_at, definitions_version) VALUES ('"+user+"', now(), 'dev-1')")
	must(t, "INSERT INTO entitlement.revocation (revocation_id, account_id, grant_id, reason_code, effective_from, issued_by_actor, created_at) VALUES (gen_random_uuid(), '"+user+"', '"+grant+"', 'refund', now(), 'operator', now())")
	must(t, "INSERT INTO identity.operator (operator_id, user_id, granted_at, expires_at, granted_by, reason) VALUES ('00000000-0000-4000-8000-0000000000d1', '"+user+"', now(), now() + interval '30 days', 'operator:cli', 'owner')")

	type refusal struct{ statement, constraint string }
	refused := map[string]refusal{
		"a capability grant with a payload":           {insertGrant("gen_random_uuid()", user, "1", "x.y", `{"limit":1}`, "1", "'r1'", "NULL"), "grant_value_shape"},
		"a quota grant without a priority":            {insertGrant("gen_random_uuid()", user, "2", "q.x", `{"limit":1}`, "1", "'r2'", "NULL"), "grant_value_shape"},
		"a quota grant above the bound":               {insertGrant("gen_random_uuid()", user, "2", "q.x", `{"limit":100000000000001,"priority":0}`, "1", "'r3'", "NULL"), "grant_value_shape"},
		"a negative quota priority":                   {insertGrant("gen_random_uuid()", user, "2", "q.x", `{"limit":1,"priority":-1}`, "1", "'r4'", "NULL"), "grant_value_shape"},
		"a quota payload with a stranger":             {insertGrant("gen_random_uuid()", user, "2", "q.x", `{"limit":1,"priority":0,"extra":1}`, "1", "'r5'", "NULL"), "grant_value_shape"},
		"an allowance without a plan reference":       {insertGrant("gen_random_uuid()", user, "3", "al.x", `{"priority":0}`, "1", "'r6'", "NULL"), "grant_value_shape"},
		"an allowance plan reference with a slash":    {insertGrant("gen_random_uuid()", user, "3", "al.x", `{"capacityPlanRef":"a/b","priority":0}`, "1", "'r7'", "NULL"), "grant_value_shape"},
		"a grant payload that is not an object":       {insertGrant("gen_random_uuid()", user, "1", "x.y", `[]`, "1", "'r8'", "NULL"), "grant_value_shape"},
		"an unknown grant kind":                       {insertGrant("gen_random_uuid()", user, "4", "x.y", `{}`, "1", "'r9'", "NULL"), "grant_kind"},
		"an unknown grant source":                     {insertGrant("gen_random_uuid()", user, "1", "x.y", `{}`, "8", "'r10'", "NULL"), "grant_source"},
		"an administrative grant without a reason":    {insertGrant("gen_random_uuid()", user, "1", "x.y", `{}`, "5", "'r11'", "NULL"), "grant_reason_required_for_operator_sources"},
		"a compensation grant without a reason":       {insertGrant("gen_random_uuid()", user, "1", "x.y", `{}`, "7", "'r12'", "NULL"), "grant_reason_required_for_operator_sources"},
		"a subscription grant with a reason":          {insertGrant("gen_random_uuid()", user, "1", "x.y", `{}`, "1", "'r13'", "'why'"), "grant_reason_required_for_operator_sources"},
		"a reason with a control character":           {insertGrant("gen_random_uuid()", user, "1", "x.y", `{}`, "5", "'r14'", `e'a\nb'`), "grant_reason_shape"},
		"a reason of 513 characters":                  {insertGrant("gen_random_uuid()", user, "1", "x.y", `{}`, "5", "'r15'", "repeat('x', 513)"), "grant_reason_shape"},
		"a subject in capitals":                       {insertGrant("gen_random_uuid()", user, "1", "Center.Nodes", `{}`, "1", "'r16'", "NULL"), "grant_subject"},
		"a source reference with a slash":             {insertGrant("gen_random_uuid()", user, "1", "x.y", `{}`, "1", "'a/b'", "NULL"), "grant_source_ref"},
		"a grant that ends before it starts":          {"INSERT INTO entitlement.grant (grant_id, account_id, kind, subject, value, source, source_ref, effective_from, effective_until, issued_by_actor, created_at) VALUES (gen_random_uuid(), '" + user + "', 1, 'x.y', '{}', 1, 'r17', now(), now() - interval '1 day', 'c', now())", "grant_window"},
		"a replayed source reference":                 {insertGrant("gen_random_uuid()", user, "1", "x.y", `{}`, "5", "'ticket-1'", "'again'"), "grant_source_ref_once"},
		"a grant of an unknown account":               {insertGrant("gen_random_uuid()", "00000000-0000-4000-8000-0000000000ff", "1", "x.y", `{}`, "1", "'r18'", "NULL"), "grant_account"},
		"a revocation of another account's grant":     {"INSERT INTO entitlement.revocation (revocation_id, account_id, grant_id, reason_code, effective_from, issued_by_actor, created_at) VALUES (gen_random_uuid(), '" + other + "', '" + grant + "', 'refund', now(), 'op', now())", "revocation_grant"},
		"a revocation reason code in capitals":        {"INSERT INTO entitlement.revocation (revocation_id, account_id, grant_id, reason_code, effective_from, issued_by_actor, created_at) VALUES (gen_random_uuid(), '" + user + "', '" + grant + "', 'Refund', now(), 'op', now())", "revocation_reason_code"},
		"a term that ends before it starts":           {"INSERT INTO entitlement.service_term (term_id, account_id, kind, period_ref, starts_at, ends_at, authorized_at, created_at) VALUES (gen_random_uuid(), '" + user + "', 3, 'p1', now(), now() - interval '1 day', now(), now())", "service_term_ends_after_starts"},
		"a subscription term without its reference":   {"INSERT INTO entitlement.service_term (term_id, account_id, kind, period_ref, starts_at, ends_at, authorized_at, created_at) VALUES (gen_random_uuid(), '" + user + "', 1, 'p2', now(), now() + interval '1 day', now(), now())", "service_term_subscription_ref"},
		"a compensation term with a subscription":     {"INSERT INTO entitlement.service_term (term_id, account_id, kind, subscription_ref, period_ref, starts_at, ends_at, authorized_at, created_at) VALUES (gen_random_uuid(), '" + user + "', 3, 's', 'p3', now(), now() + interval '1 day', now(), now())", "service_term_subscription_ref"},
		"a grace that ends before the term":           {"INSERT INTO entitlement.service_term (term_id, account_id, kind, period_ref, starts_at, ends_at, grace_ends_at, authorized_at, created_at) VALUES (gen_random_uuid(), '" + user + "', 3, 'p4', now(), now() + interval '2 days', now() + interval '1 day', now(), now())", "service_term_grace"},
		"a period created twice":                      {"INSERT INTO entitlement.service_term (term_id, account_id, kind, period_ref, starts_at, ends_at, authorized_at, created_at) VALUES (gen_random_uuid(), '" + user + "', 3, 'ticket-1', now(), now() + interval '1 day', now(), now())", "service_term_period"},
		"a term action on another account's term":     {"INSERT INTO entitlement.service_term_action (action_id, account_id, term_id, kind, effective_at, recorded_at, source_ref) VALUES (gen_random_uuid(), '" + user + "', '" + termB + "', 2, now(), now(), 'revoke-2')", "service_term_action_term"},
		"a supersede without its replacement":         {"INSERT INTO entitlement.service_term_action (action_id, account_id, term_id, kind, effective_at, recorded_at, source_ref) VALUES (gen_random_uuid(), '" + user + "', '" + term + "', 1, now(), now(), 'sup-1')", "service_term_action_replacement_matches_kind"},
		"a revoke with a replacement":                 {"INSERT INTO entitlement.service_term_action (action_id, account_id, term_id, kind, effective_at, recorded_at, source_ref, replacement_term_id) VALUES (gen_random_uuid(), '" + user + "', '" + term + "', 2, now(), now(), 'rev-2', '" + term + "')", "service_term_action_replacement_matches_kind"},
		"a term action reference used twice":          {"INSERT INTO entitlement.service_term_action (action_id, account_id, term_id, kind, effective_at, recorded_at, source_ref) VALUES (gen_random_uuid(), '" + user + "', '" + term + "', 2, now(), now(), 'revoke-1')", "service_term_action_source_ref"},
		"an unknown account status":                   {"INSERT INTO entitlement.account_status_fact (status_fact_id, account_id, recorded_at, status, auto_renew, purchase_pending, source_ref) VALUES (gen_random_uuid(), '" + user + "', now(), 4, true, false, 'status-2')", "account_status_fact_status"},
		"a status reference used twice":               {"INSERT INTO entitlement.account_status_fact (status_fact_id, account_id, recorded_at, status, auto_renew, purchase_pending, source_ref) VALUES (gen_random_uuid(), '" + user + "', now(), 1, true, false, 'status-1')", "account_status_fact_source_ref"},
		"a feature released twice":                    {"INSERT INTO entitlement.feature_release (feature_key, released_at) VALUES ('center.nodes', now())", "feature_release_pkey"},
		"a feature key in capitals":                   {"INSERT INTO entitlement.feature_release (feature_key, released_at) VALUES ('Center.Nodes', now())", "feature_release_key"},
		"two activations at one instant":              {"INSERT INTO entitlement.definitions_activation (account_id, activated_at, definitions_version) SELECT account_id, activated_at, 'dev-2' FROM entitlement.definitions_activation", "definitions_activation_pkey"},
		"a snapshot with a version below zero":        {"INSERT INTO entitlement.snapshot (account_id, entitlement_version, computed_at, definitions_version, content) VALUES ('" + other + "', -1, now(), 'dev-1', 'defs=dev-1\n')", "snapshot_version"},
		"a snapshot valid until before it was made":   {"INSERT INTO entitlement.snapshot (account_id, entitlement_version, computed_at, valid_until, definitions_version, content) VALUES ('" + other + "', 0, now(), now() - interval '1 day', 'dev-1', 'defs=dev-1\n')", "snapshot_validity"},
		"a snapshot that is not canonical text":       {"INSERT INTO entitlement.snapshot (account_id, entitlement_version, computed_at, definitions_version, content) VALUES ('" + other + "', 0, now(), 'dev-1', 'nothing')", "snapshot_content"},
		"a revision of zero":                          {"INSERT INTO entitlement.revision (account_id, rev, updated_at) VALUES ('" + other + "', 0, now())", "revision_rev"},
		"an operator that expires before it is given": {"INSERT INTO identity.operator (operator_id, user_id, granted_at, expires_at, granted_by, reason) VALUES (gen_random_uuid(), '" + other + "', now(), now() - interval '1 day', 'operator:cli', 'r')", "operator_expiry"},
		"an operator for more than 400 days":          {"INSERT INTO identity.operator (operator_id, user_id, granted_at, expires_at, granted_by, reason) VALUES (gen_random_uuid(), '" + other + "', now(), now() + interval '401 days', 'operator:cli', 'r')", "operator_expiry"},
		"an operator without a reason":                {"INSERT INTO identity.operator (operator_id, user_id, granted_at, expires_at, granted_by, reason) VALUES (gen_random_uuid(), '" + other + "', now(), now() + interval '1 day', 'operator:cli', '')", "operator_reason"},
		"an operator of an unknown account":           {"INSERT INTO identity.operator (operator_id, user_id, granted_at, expires_at, granted_by, reason) VALUES (gen_random_uuid(), '00000000-0000-4000-8000-0000000000fe', now(), now() + interval '1 day', 'operator:cli', 'r')", "operator_user"},
	}
	for label, item := range refused {
		t.Run(label, func(t *testing.T) {
			tx, err := conn.Begin(ctx)
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = tx.Rollback(ctx) }()
			_, err = tx.Exec(ctx, item.statement)
			var pgError *pgconn.PgError
			if !errors.As(err, &pgError) || !strings.HasPrefix(pgError.Code, "23") || pgError.ConstraintName != item.constraint {
				t.Fatalf("not refused by %s (%v): %s", item.constraint, err, item.statement)
			}
		})
	}

	// Every record table is append-only (the trigger refuses even the migration role), and the derived tables are not.
	for _, statement := range []string{
		"UPDATE entitlement.grant SET reason = 'edited' WHERE grant_id = '" + grant + "'",
		"DELETE FROM entitlement.grant WHERE grant_id = '" + grant + "'",
		"UPDATE entitlement.revocation SET reason_code = 'x' WHERE account_id = '" + user + "'",
		"DELETE FROM entitlement.revocation WHERE account_id = '" + user + "'",
		"UPDATE entitlement.service_term SET ends_at = ends_at + interval '1 day' WHERE term_id = '" + term + "'",
		"DELETE FROM entitlement.service_term WHERE term_id = '" + term + "'",
		"UPDATE entitlement.service_term_action SET effective_at = now() WHERE action_id = '" + action + "'",
		"DELETE FROM entitlement.service_term_action WHERE action_id = '" + action + "'",
		"UPDATE entitlement.account_status_fact SET status = 3 WHERE account_id = '" + user + "'",
		"DELETE FROM entitlement.account_status_fact WHERE account_id = '" + user + "'",
		"UPDATE entitlement.feature_release SET released_at = now() WHERE feature_key = 'center.nodes'",
		"DELETE FROM entitlement.feature_release WHERE feature_key = 'center.nodes'",
		"UPDATE entitlement.definitions_activation SET definitions_version = 'dev-9' WHERE account_id = '" + user + "'",
		"DELETE FROM entitlement.definitions_activation WHERE account_id = '" + user + "'",
		"DELETE FROM identity.operator WHERE user_id = '" + user + "'",
		"DELETE FROM entitlement.revision WHERE account_id = '" + user + "'",
	} {
		if _, err := conn.Exec(ctx, statement); !pgtest.IsCode(err, "23514") {
			t.Errorf("an append-only record changed (%v): %s", err, statement)
		}
	}
	// A revision advances by exactly one.
	if _, err := conn.Exec(ctx, "UPDATE entitlement.revision SET rev = 3, updated_at = now() WHERE account_id = '"+user+"'"); !pgtest.IsCode(err, "23514") {
		t.Errorf("a revision skipped a step: %v", err)
	}
	must(t, "UPDATE entitlement.revision SET rev = 2, updated_at = now() WHERE account_id = '"+user+"'")
	// The snapshot is derived: it is rewritten in place.
	must(t, "INSERT INTO entitlement.snapshot (account_id, entitlement_version, computed_at, definitions_version, content) VALUES ('"+user+"', 0, now(), 'dev-1', 'defs=dev-1\n')")
	must(t, "UPDATE entitlement.snapshot SET entitlement_version = 1, computed_at = now() + interval '1 second' WHERE account_id = '"+user+"'")
	// An operator row is revoked once and changes in no other way.
	if _, err := conn.Exec(ctx, "UPDATE identity.operator SET expires_at = expires_at + interval '1 day' WHERE user_id = '"+user+"'"); !pgtest.IsCode(err, "23514") {
		t.Errorf("an operator row was extended: %v", err)
	}
	must(t, "UPDATE identity.operator SET revoked_at = now() WHERE user_id = '"+user+"'")
	if _, err := conn.Exec(ctx, "UPDATE identity.operator SET revoked_at = now() WHERE user_id = '"+user+"'"); !pgtest.IsCode(err, "23514") {
		t.Errorf("an operator row was revoked twice: %v", err)
	}
}

// TestEveryEntitlementForeignKeyHasAnIndex holds migration 0003 to the index decision of 0002 (E8): the first referencing column of
// every foreign key of the entitlement schema, and of identity.operator, leads an index.
func TestEveryEntitlementForeignKeyHasAnIndex(t *testing.T) {
	url, name := pgtest.Database(t)
	if _, err := apply(t, url, centerBuild(t), Options{Runner: "test", RuntimeRole: name + "_runtime"}); err != nil {
		t.Fatal(err)
	}
	rows, err := pgtest.Connect(t, url).Query(context.Background(), `SELECT c.conname
FROM pg_constraint c JOIN pg_namespace n ON n.oid = c.connamespace
WHERE c.contype = 'f' AND (n.nspname = 'entitlement' OR c.conname = 'operator_user')
    AND NOT EXISTS (SELECT 1 FROM pg_index i WHERE i.indrelid = c.conrelid AND i.indkey[0] = c.conkey[1])
ORDER BY 1`)
	if err != nil {
		t.Fatal(err)
	}
	var missing []string
	for rows.Next() {
		var constraint string
		if err = rows.Scan(&constraint); err != nil {
			t.Fatal(err)
		}
		missing = append(missing, constraint)
	}
	if err = rows.Err(); err != nil || len(missing) > 0 {
		t.Fatalf("foreign keys without a leading index: %v %v", missing, err)
	}
}
