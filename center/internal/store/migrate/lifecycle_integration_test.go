// SPDX-License-Identifier: AGPL-3.0-only

package migrate

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"testing"

	"github.com/ArcForges/Cloud/center/internal/pgtest"
	"github.com/ArcForges/Cloud/center/internal/platform"
	"github.com/ArcForges/Cloud/center/internal/store"
	"github.com/jackc/pgx/v5"
)

type lifecycleAuthority struct {
	account, low, current, proved, pending platform.ID
}

// These are explicitly supplied historical database facts, not fabricated
// successful recovery/passkey ceremonies. The migration must retain their
// snapshots and derive the account floor under the real writer barrier.
func seedLifecycleAuthority(t *testing.T, owner *pgx.Conn) lifecycleAuthority {
	t.Helper()
	f := seedNamespaceFixture(t, owner)
	a := lifecycleAuthority{f.account, platform.NewID(), platform.NewID(), platform.NewID(), platform.NewID()}
	device, installation := platform.NewID(), platform.NewID()
	ctx := context.Background()
	statements := []struct {
		sql  string
		args []any
	}{
		{`INSERT INTO device.device(device_id,user_id,display_name,platform,trust_level,remote_enabled,first_seen_at,last_seen_at,rev)
 VALUES($1,$2,'Migration browser',6,1,false,now(),now(),1)`, []any{device, a.account}},
		{`INSERT INTO device.installation(installation_id,device_id,user_id,product_id,app_version,platform,client_installation_id,installed_at,last_active_at,rev)
 VALUES($1,$2,$3,'arcforges-web','web','web',$4,now(),now(),1)`, []any{installation, device, a.account, platform.NewID()}},
		{`INSERT INTO identity.session(session_id,user_id,device_id,installation_id,credential_kind,scope,product_id,purpose,auth_method,authenticated_at,
 issued_at,expires_at,idle_expires_at,last_activity_at,browser_handle_hash,browser_origin,auth_epoch,recovery_generation,session_policy_version,rev)
 VALUES($1,$2,$3,$4,2,1,'arcforges-web',1,1,now(),now(),now()+interval '12 hours',now()+interval '30 minutes',now(),sha256(convert_to(($1::uuid)::text,'UTF8')),
 'https://center.example',2,1,'v1',1),($5,$2,$3,$4,2,1,'arcforges-web',1,1,now(),now(),now()+interval '12 hours',now()+interval '30 minutes',now(),sha256(convert_to(($5::uuid)::text,'UTF8')),
 'https://center.example',7,4,'v1',1)`, []any{a.low, a.account, device, installation, a.current}},
		{`INSERT INTO identity.step_up_challenge(challenge_id,user_id,session_id,operation_id,target_hash,method,challenge,state,attempt_count,
 created_at,expires_at,proved_at,auth_epoch,recovery_generation,rev)
 VALUES($1,$2,$3,'identity.removeAuthIdentity',sha256('supplied intent'),1,sha256('supplied challenge'),2,0,now(),now()+interval '5 minutes',now(),7,4,1),
 ($4,$2,$3,'identity.removeAuthIdentity',sha256('pending intent'),1,sha256('pending challenge'),1,0,now(),now()+interval '5 minutes',NULL,7,4,1)`, []any{a.proved, a.account, a.current, a.pending}},
	}
	for _, statement := range statements {
		if _, err := owner.Exec(ctx, statement.sql, statement.args...); err != nil {
			t.Fatal(store.Sanitize("seed historical authority facts", err))
		}
	}
	return a
}

func TestLifecycleFiniteTransitionsRetainHistoryAndFenceSchema12(t *testing.T) {
	for _, version := range []int{10, 11, 12} {
		t.Run(strconv.Itoa(version), func(t *testing.T) {
			ctx := context.Background()
			url, name := pgtest.Database(t)
			owner := pgtest.Connect(t, url)
			group := name + "_runtime"
			build := centerBuild(t)
			if _, err := Apply(ctx, owner, build[:version], Options{Runner: "actual-lifecycle-predecessor", RuntimeRole: group}); err != nil {
				t.Fatal(err)
			}
			if version < 12 {
				dir := t.TempDir()
				result, err := ApplyManagement(ctx, owner, build, Options{Runner: "actual-finite-management12", RuntimeRole: group}, managementConfig(url, name, group), filepath.Join(dir, "source.dump"), filepath.Join(dir, "source.json"))
				if err != nil || result.Version != 12 {
					t.Fatalf("finite predecessor phase: %v", err)
				}
				group = result.RuntimeRole
			}
			a := seedLifecycleAuthority(t, owner)
			var oldReceipt string
			if err := owner.QueryRow(ctx, "SELECT encode(sha256(convert_to(to_jsonb(c)::text,'UTF8')),'hex') FROM management.cutover_receipt c WHERE target_schema=12").Scan(&oldReceipt); err != nil {
				t.Fatal("schema12 receipt unavailable")
			}
			if _, err := Apply(ctx, owner, build, Options{Runner: "naked-append13", RuntimeRole: group}); !errors.Is(err, ErrLifecycleTransitionRequired) {
				t.Fatalf("ordinary append revived old schema12 writer: %v", err)
			}
			dir := t.TempDir()
			result, err := ApplyLifecycle(ctx, owner, build, Options{Runner: "actual-finite-lifecycle13", RuntimeRole: group}, managementConfig(url, name, group), filepath.Join(dir, "source.dump"), filepath.Join(dir, "source.json"))
			if err != nil || result.Version != 13 || result.RuntimeRole == group || len(result.Ran) != 1 || result.Grants != "reconciled" {
				t.Fatalf("finite lifecycle transition: %v", err)
			}
			var auth, recovery, lowAuth, lowRecovery int64
			var lowRevoked, currentRevoked, oldWriter, ownerFunction bool
			var receipt string
			var receipts int
			err = owner.QueryRow(ctx, `SELECT a.auth_epoch,a.recovery_generation,l.auth_epoch,l.recovery_generation,l.revoked_at IS NOT NULL,c.revoked_at IS NOT NULL,
 EXISTS(SELECT 1 FROM pg_class t JOIN pg_namespace n ON n.oid=t.relnamespace WHERE n.nspname=ANY($4::text[]) AND t.relkind='r'
 AND has_table_privilege($5,t.oid,'INSERT,UPDATE,DELETE,TRUNCATE')),
 has_function_privilege($6,'identity.finish_account_deletion(uuid,timestamptz)','EXECUTE'),
 (SELECT encode(sha256(convert_to(to_jsonb(r)::text,'UTF8')),'hex') FROM management.cutover_receipt r WHERE target_schema=12),
 (SELECT count(*) FROM management.cutover_receipt)
 FROM identity.account_security_state a,identity.session l,identity.session c WHERE a.user_id=$1 AND l.session_id=$2 AND c.session_id=$3`,
				a.account, a.low, a.current, []string{"platform", "audit", "fleet", "identity", "device", "entitlement", "management"}, group, result.RuntimeRole).
				Scan(&auth, &recovery, &lowAuth, &lowRecovery, &lowRevoked, &currentRevoked, &oldWriter, &ownerFunction, &receipt, &receipts)
			if err != nil || auth != 7 || recovery != 4 || lowAuth != 2 || lowRecovery != 1 || !lowRevoked || currentRevoked || oldWriter || ownerFunction || receipt != oldReceipt || receipts != 2 {
				t.Fatalf("schema12 authority or historical receipt survived incorrectly: %v", store.Sanitize("inspect lifecycle transition", err))
			}
			status, err := Inspect(ctx, owner, build[:13])
			if err != nil || status.State != StateCurrent || status.RuntimeRole != result.RuntimeRole {
				t.Fatalf("actual schema13 admission: %v", err)
			}
		})
	}
}

func TestLifecycleRefusesOpenWriterAndManagementOnlyPrivilegePath(t *testing.T) {
	for _, mode := range []string{"open-session", "management-writer"} {
		t.Run(mode, func(t *testing.T) {
			ctx := context.Background()
			url, name := pgtest.Database(t)
			owner := pgtest.Connect(t, url)
			group := name + "_runtime"
			build := centerBuild(t)
			if _, err := Apply(ctx, owner, build[:12], Options{Runner: "actual-schema12", RuntimeRole: group}); err != nil {
				t.Fatal(err)
			}
			if mode == "open-session" {
				_, active := managementRuntime(t, owner, url, group)
				defer active.Close(ctx)
			} else {
				outsider := pgx.Identifier{name + "_outsider"}.Sanitize()
				if _, err := owner.Exec(ctx, "CREATE ROLE "+outsider+" NOLOGIN; GRANT USAGE ON SCHEMA management TO "+outsider+"; GRANT UPDATE ON management.remote_operation TO "+outsider); err != nil {
					t.Fatal(store.Sanitize("prepare actual writer path", err))
				}
			}
			dir := t.TempDir()
			_, err := ApplyLifecycle(ctx, owner, build, Options{Runner: "actual-writer-refusal", RuntimeRole: group}, managementConfig(url, name, group), filepath.Join(dir, "source.dump"), filepath.Join(dir, "source.json"))
			if !errors.Is(err, ErrManagementTransitionRequired) {
				t.Fatalf("unfenced schema12 writer was admitted: %v", err)
			}
			var version int
			if err := owner.QueryRow(ctx, "SELECT max(version) FROM platform.schema_migration").Scan(&version); err != nil || version != 12 {
				t.Fatal("writer refusal changed the source schema")
			}
			if _, err := os.Stat(filepath.Join(dir, "source.dump")); err != nil {
				t.Fatal("writer refusal lost its real backup")
			}
		})
	}
}

func TestLifecycleSQLFaultRollsBackNewGeneration(t *testing.T) {
	ctx := context.Background()
	url, name := pgtest.Database(t)
	owner := pgtest.Connect(t, url)
	group := name + "_runtime"
	build := centerBuild(t)
	if _, err := Apply(ctx, owner, build[:12], Options{Runner: "actual-schema12", RuntimeRole: group}); err != nil {
		t.Fatal(err)
	}
	fault := append([]Migration(nil), build...)
	fault[12].SQL += "\nSELECT 1/0;\n"
	digest := sha256.Sum256([]byte(fault[12].SQL))
	fault[12].SHA256 = hex.EncodeToString(digest[:])
	dir := t.TempDir()
	if _, err := ApplyLifecycle(ctx, owner, fault, Options{Runner: "actual-lifecycle-sql-fault", RuntimeRole: group}, managementConfig(url, name, group), filepath.Join(dir, "source.dump"), filepath.Join(dir, "source.json")); err == nil {
		t.Fatal("injected SQL fault was reported as success")
	}
	status, err := Inspect(ctx, owner, build[:12])
	var stateExists bool
	if err != nil || status.Version != 12 || status.RuntimeRole != group || owner.QueryRow(ctx, "SELECT to_regclass('identity.account_security_state') IS NOT NULL").Scan(&stateExists) != nil || stateExists {
		t.Fatal("failed schema13 transaction retained new authority or a moved runtime floor")
	}
}

func TestRemoteObservationAppendKeepsTheQualifiedSchema13Authority(t *testing.T) {
	ctx := context.Background()
	url, name := pgtest.Database(t)
	owner := pgtest.Connect(t, url)
	group := name + "_runtime"
	build := centerBuild(t)
	const next = "0014_management_remote_observations.sql"
	if len(build) < 14 || build[13].Name != next {
		t.Fatal("the remote-observation migration is missing")
	}
	before, err := Apply(ctx, owner, build[:13], Options{Runner: "remote-observation-predecessor", RuntimeRole: group})
	if err != nil || before.State != StateCurrent || before.Version != 13 {
		t.Fatalf("apply the exact schema13 predecessor: %v", err)
	}

	receiptDigest := func() string {
		t.Helper()
		var digest string
		if err := owner.QueryRow(ctx, `SELECT encode(sha256(convert_to(
jsonb_agg(to_jsonb(c) ORDER BY c.target_schema)::text,'UTF8')),'hex') FROM management.cutover_receipt c`).Scan(&digest); err != nil {
			t.Fatal(store.Sanitize("read the qualified cutover receipts", err))
		}
		return digest
	}
	original := receiptDigest()
	pending, err := Inspect(ctx, owner, build)
	if err != nil || pending.State != StatePending || pending.RuntimeRole != group || !slices.Equal(pending.Pending, []string{next}) {
		t.Fatalf("inspect the preserved schema13 authority with one pending append: %v", err)
	}
	if _, err := Apply(ctx, owner, build, Options{Runner: "wrong-runtime", RuntimeRole: "center03_other_runtime"}); err == nil {
		t.Fatal("a mismatched runtime generation admitted the append")
	}

	result, err := Apply(ctx, owner, build, Options{Runner: "remote-observation-append", RuntimeRole: group})
	if err != nil || result.State != StateCurrent || result.Version != 14 || result.RuntimeRole != group ||
		result.Grants != "reconciled" || len(result.Ran) != 1 || result.Ran[0].Name != next || result.Ran[0].SHA256 != build[13].SHA256 {
		t.Fatalf("ordinary append did not retain the qualified runtime: %+v %v", result, err)
	}
	if !slices.EqualFunc(before.Applied, result.Applied[:13], func(old, current Applied) bool {
		return old.Version == current.Version && old.Name == current.Name && old.SHA256 == current.SHA256 &&
			old.AppliedAt.Equal(current.AppliedAt) && old.AppliedBy == current.AppliedBy
	}) || receiptDigest() != original {
		t.Fatal("the append changed an applied migration or a qualified cutover receipt")
	}
}
