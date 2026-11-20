// SPDX-License-Identifier: AGPL-3.0-only

package migrate

import (
	"context"
	"errors"
	"slices"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/ArcForges/Cloud/center/internal/pgtest"
	"github.com/ArcForges/Cloud/center/internal/platform"
)

var originalHostedTables = []string{
	"entitlement.grant",
	"entitlement.revocation",
	"entitlement.service_term",
	"entitlement.service_term_action",
	"entitlement.snapshot",
	"entitlement.revision",
}

type hostedProjectionFixture struct {
	account, clippedGrant, unboundedGrant, clippedTerm platform.ID
	at                                                 time.Time
	original                                           []ctr06BackupTable
}

func seedHostedProjection(t *testing.T, owner *pgx.Conn, account platform.ID) hostedProjectionFixture {
	t.Helper()
	ctx := context.Background()
	f := hostedProjectionFixture{
		account: account, clippedGrant: platform.NewID(), unboundedGrant: platform.NewID(), clippedTerm: platform.NewID(),
	}
	if err := owner.QueryRow(ctx, "SELECT statement_timestamp()").Scan(&f.at); err != nil {
		t.Fatal(Sanitize("capture entitlement test clock", err))
	}
	revokedGrant := platform.NewID()
	if _, err := owner.Exec(ctx, `INSERT INTO entitlement.grant
        (grant_id, account_id, kind, subject, value, source, source_ref, effective_from, effective_until, issued_by_actor, created_at)
        VALUES ($2,$1,1,'center.nodes','{}',1,'fixture:nodes',$5::timestamptz-interval '2 hours',$5+interval '2 hours','fixture:provider',$5-interval '1 hour'),
               ($3,$1,1,'remote.control','{}',1,'fixture:control',$5-interval '1 hour',NULL,'fixture:provider',$5-interval '2 hours'),
               ($4,$1,1,'remote.view','{}',1,'fixture:view-revoked',$5-interval '2 hours',$5+interval '2 hours','fixture:provider',$5-interval '1 hour'),
               (gen_random_uuid(),$1,1,'center.execute','{}',1,'fixture:legacy',$5-interval '2 hours',$5+interval '2 hours','fixture:provider',$5-interval '1 hour'),
               (gen_random_uuid(),$1,1,'remote.view','{}',1,'fixture:not-yet-recorded',$5-interval '2 hours',$5+interval '2 hours','fixture:provider',$5+interval '1 hour')`,
		account, f.clippedGrant, f.unboundedGrant, revokedGrant, f.at); err != nil {
		t.Fatal(Sanitize("seed original subscription grants", err))
	}
	if _, err := owner.Exec(ctx, `INSERT INTO entitlement.revocation
        (revocation_id, account_id, grant_id, reason_code, effective_from, issued_by_actor, created_at)
        VALUES (gen_random_uuid(),$1,$2,'fixture-shortening',$4::timestamptz+interval '30 minutes','fixture:provider',$4-interval '1 minute'),
               (gen_random_uuid(),$1,$3,'fixture-revoked',$4-interval '10 minutes','fixture:provider',$4-interval '11 minutes')`,
		account, f.clippedGrant, revokedGrant, f.at); err != nil {
		t.Fatal(Sanitize("seed original grant revocations", err))
	}
	supersededTerm := platform.NewID()
	if _, err := owner.Exec(ctx, `INSERT INTO entitlement.service_term
        (term_id, account_id, kind, subscription_ref, period_ref, starts_at, ends_at, grace_ends_at, authorized_at, created_at)
        VALUES ($2,$1,1,'fixture:subscription','fixture:current',$4::timestamptz-interval '2 hours',$4+interval '3 hours',$4+interval '4 hours',$4-interval '15 minutes',$4-interval '45 minutes'),
               ($3,$1,1,'fixture:subscription','fixture:superseded',$4-interval '3 hours',$4+interval '2 hours',NULL,$4-interval '2 hours',$4-interval '2 hours'),
               (gen_random_uuid(),$1,1,'fixture:grace','fixture:grace-only',$4-interval '2 hours',$4-interval '30 minutes',$4+interval '1 hour',$4-interval '1 hour',$4-interval '1 hour'),
               (gen_random_uuid(),$1,3,NULL,'fixture:compensation',$4-interval '2 hours',$4+interval '2 hours',NULL,$4-interval '1 hour',$4-interval '1 hour')`,
		account, f.clippedTerm, supersededTerm, f.at); err != nil {
		t.Fatal(Sanitize("seed original service terms", err))
	}
	if _, err := owner.Exec(ctx, `INSERT INTO entitlement.service_term_action
        (action_id, account_id, term_id, kind, effective_at, recorded_at, source_ref, replacement_term_id)
        VALUES (gen_random_uuid(),$1,$2,2,$4::timestamptz+interval '45 minutes',$4-interval '1 minute','fixture:future-term-end',NULL),
               (gen_random_uuid(),$1,$3,1,$4-interval '15 minutes',$4-interval '16 minutes','fixture:original-supersession',$2)`,
		account, f.clippedTerm, supersededTerm, f.at); err != nil {
		t.Fatal(Sanitize("seed original service term actions", err))
	}
	original, err := ctr06SnapshotData(ctx, owner, originalHostedTables)
	if err != nil {
		t.Fatal(err)
	}
	f.original = original
	return f
}

func (f hostedProjectionFixture) check(t *testing.T, owner *pgx.Conn, runtime string) {
	t.Helper()
	ctx := context.Background()
	original, err := ctr06SnapshotData(ctx, owner, originalHostedTables)
	if err != nil || !slices.Equal(original, f.original) {
		t.Fatalf("original grants, terms, actions, snapshot or revision changed: %v", err)
	}

	var total, matching int
	err = owner.QueryRow(ctx, `SELECT count(*), count(*) FILTER (WHERE migration_version=15
        AND definition_version='hosted-v2' AND account_id=$1 AND (
        (source_kind='grant' AND source_id=$2 AND source_grant_id=$2 AND source_term_id IS NULL AND capability_key='center.nodes'
            AND source_from=$5::timestamptz-interval '2 hours' AND source_until=$5+interval '2 hours'
            AND valid_from=$5-interval '1 hour' AND valid_until=$5+interval '30 minutes')
        OR (source_kind='grant' AND source_id=$3 AND capability_key='remote.control' AND source_until IS NULL AND valid_until IS NULL)
        OR (source_kind='term' AND source_id=$4 AND source_grant_id IS NULL AND source_term_id=$4 AND capability_key IS NULL
            AND source_from=$5-interval '2 hours' AND source_until=$5+interval '3 hours' AND source_grace_until=$5+interval '4 hours'
            AND valid_from=$5-interval '15 minutes' AND valid_until=$5+interval '45 minutes')))
        FROM entitlement.hosted_projection_migration`,
		f.account, f.clippedGrant, f.unboundedGrant, f.clippedTerm, f.at).Scan(&total, &matching)
	if err != nil || total != 3 || matching != total {
		t.Fatalf("qualified original-reference facts: total=%d matching=%d error=%v", total, matching, Sanitize("read hosted projection", err))
	}
	var access bool
	if err := owner.QueryRow(ctx, `SELECT has_table_privilege($1,'entitlement.hosted_projection_migration',
        'SELECT,INSERT,UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER')`, runtime).Scan(&access); err != nil || access {
		t.Fatalf("migration-only facts writable or readable by the runtime role: %v", Sanitize("check hosted projection privileges", err))
	}
}

func TestHostedEntitlementProjectionAppendPreservesSchema14(t *testing.T) {
	ctx := context.Background()
	url, name := pgtest.Database(t)
	owner := pgtest.Connect(t, url)
	runtime := name + "_runtime"
	options := Options{Runner: "isolated-hosted-projection", RuntimeRole: runtime}
	build := centerBuild(t)
	if len(build) < 15 || build[14].Name != "0015_hosted_entitlement_projection.sql" {
		t.Fatal("the build is missing the canonical schema15 append")
	}
	if result, err := Apply(ctx, owner, build[:14], options); err != nil || result.Version != 14 {
		t.Fatalf("prepare schema14: %v", err)
	}
	prior, exists, err := ReadApplied(ctx, owner)
	if err != nil || !exists || len(prior) != 14 {
		t.Fatalf("read schema14 migration history: %v", err)
	}

	fixture := seedHostedProjection(t, owner, seedNamespaceFixture(t, owner).account)
	result, err := Apply(ctx, owner, build[:15], options)
	if err != nil || result.Version != 15 || len(result.Ran) != 1 || result.Ran[0].Name != build[14].Name {
		t.Fatalf("append schema15: %v", err)
	}
	if !slices.Equal(prior, result.Applied[:14]) {
		t.Fatal("schema15 rewrote applied migration history")
	}
	if version, err := CheckCompatible(ctx, owner, build[:14]); err != nil || version != 15 {
		t.Fatalf("schema14 build cannot read the expanded schema15: %v", err)
	}
	fixture.check(t, owner, runtime)
	if result, err := Apply(ctx, owner, build[:15], options); err != nil || len(result.Ran) != 0 {
		t.Fatalf("repeat canonical schema15 migration: %v", err)
	}

	for _, sql := range []string{
		"UPDATE entitlement.hosted_projection_migration SET definition_version='rewritten'",
		"DELETE FROM entitlement.hosted_projection_migration",
	} {
		var refusal *pgconn.PgError
		if _, err := owner.Exec(ctx, sql); !errors.As(err, &refusal) || refusal.Code != "23514" {
			t.Fatalf("altering historical projection facts: %v", Sanitize("check append-only hosted facts", err))
		}
	}
	fixture.check(t, owner, runtime)
}
