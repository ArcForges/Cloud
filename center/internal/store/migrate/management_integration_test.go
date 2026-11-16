// SPDX-License-Identifier: AGPL-3.0-only

package migrate

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/ArcForges/Cloud/center/internal/config"
	"github.com/ArcForges/Cloud/center/internal/management"
	"github.com/ArcForges/Cloud/center/internal/pgtest"
	"github.com/ArcForges/Cloud/center/internal/platform"
	"github.com/ArcForges/Cloud/center/internal/store"
	"github.com/jackc/pgx/v5"
)

func managementRuntime(t *testing.T, owner *pgx.Conn, url, group string) (*management.Store, *pgx.Conn) {
	t.Helper()
	ctx := context.Background()
	password := pgtest.Secret()
	login := group + "_a"
	if _, err := owner.Exec(ctx, "ALTER ROLE "+pgx.Identifier{login}.Sanitize()+" LOGIN PASSWORD '"+password+"'; GRANT "+pgx.Identifier{group}.Sanitize()+" TO "+pgx.Identifier{login}.Sanitize()); err != nil {
		t.Fatal(store.Sanitize("enable isolated runtime credential", err))
	}
	runtimeURL := pgtest.WithUser(t, url, login, password)
	return management.New(store.New(pgtest.Pool(t, runtimeURL, 4))), pgtest.Connect(t, runtimeURL)
}

func TestManagementOpenOldWriterAndMembershipPathRefuse(t *testing.T) {
	for _, mode := range []string{"open-session", "noinherit-membership"} {
		t.Run(mode, func(t *testing.T) {
			ctx := context.Background()
			url, name := pgtest.Database(t)
			owner := pgtest.Connect(t, url)
			group := name + "_runtime"
			build := centerBuild(t)
			if _, err := Apply(ctx, owner, build[:11], Options{Runner: "isolated-schema11-fixture", RuntimeRole: group}); err != nil {
				t.Fatal(err)
			}
			var writer *pgx.Conn
			if mode == "open-session" {
				password := pgtest.Secret()
				login := group + "_a"
				if _, err := owner.Exec(ctx, "ALTER ROLE "+pgx.Identifier{login}.Sanitize()+" LOGIN PASSWORD '"+password+"'; GRANT "+pgx.Identifier{group}.Sanitize()+" TO "+pgx.Identifier{login}.Sanitize()); err != nil {
					t.Fatal(store.Sanitize("enable isolated old writer", err))
				}
				writer = pgtest.Connect(t, pgtest.WithUser(t, url, login, password))
			} else {
				extra := name + "_outsider"
				if _, err := owner.Exec(ctx, "CREATE ROLE "+pgx.Identifier{extra}.Sanitize()+" NOLOGIN NOINHERIT; GRANT "+pgx.Identifier{group}.Sanitize()+" TO "+pgx.Identifier{extra}.Sanitize()+" WITH INHERIT FALSE"); err != nil {
					t.Fatal(store.Sanitize("create isolated membership path", err))
				}
			}
			dir := t.TempDir()
			result, err := ApplyManagement(ctx, owner, build, Options{Runner: "isolated-native-fixture", RuntimeRole: group}, managementConfig(url, name, group), filepath.Join(dir, "source.dump"), filepath.Join(dir, "source.json"))
			if !errors.Is(err, ErrManagementTransitionRequired) || result.Version == 12 {
				t.Fatalf("unsafe writer was not refused: %v", err)
			}
			var version int
			var write bool
			if err := owner.QueryRow(ctx, "SELECT (SELECT max(version) FROM platform.schema_migration),has_table_privilege($1,'fleet.routed_call','INSERT')", group).Scan(&version, &write); err != nil || version != 11 || !write {
				t.Fatal("failed transition changed old role or schema")
			}
			if _, err := os.Stat(filepath.Join(dir, "source.dump")); err != nil {
				t.Fatal("failed transition lost its verified backup")
			}
			if writer != nil {
				if err := writer.Close(ctx); err != nil {
					t.Fatal("old writer did not close")
				}
			}
		})
	}
}

func TestManagementMigrationFaultRollsBackFloorRolesAndSchema(t *testing.T) {
	ctx := context.Background()
	url, name := pgtest.Database(t)
	owner := pgtest.Connect(t, url)
	group := name + "_runtime"
	build := centerBuild(t)
	if _, err := Apply(ctx, owner, build[:11], Options{Runner: "isolated-schema11-fixture", RuntimeRole: group}); err != nil {
		t.Fatal(err)
	}
	f := seedNamespaceFixture(t, owner)
	if err := insertNamespace(ctx, owner, f, platform.NewID(), false, 1, 1, false); err != nil {
		t.Fatal(store.Sanitize("seed unresolved historical input", err))
	}
	fault := append([]Migration(nil), build...)
	fault[11].SQL += "\nSELECT 1/0;\n"
	digest := sha256.Sum256([]byte(fault[11].SQL))
	fault[11].SHA256 = hex.EncodeToString(digest[:])
	dir := t.TempDir()
	_, err := ApplyManagement(ctx, owner, fault, Options{Runner: "isolated-injected-SQL-fault", RuntimeRole: group}, managementConfig(url, name, group), filepath.Join(dir, "source.dump"), filepath.Join(dir, "source.json"))
	var failure *Failure
	if !errors.As(err, &failure) || failure.SQLState != "22012" {
		t.Fatalf("expected actual PostgreSQL transaction fault: %v", err)
	}
	var version, identities, roles int
	var noManagement bool
	var role string
	if err := owner.QueryRow(ctx, `SELECT (SELECT max(version) FROM platform.schema_migration),(SELECT count(*) FROM fleet.routed_call),
 (SELECT count(*) FROM pg_roles WHERE rolname LIKE $1),to_regnamespace('management') IS NULL,
 (SELECT runtime_role::text FROM platform.ctr06_runtime_floor)`, name+"%_v2_%").Scan(&version, &identities, &roles, &noManagement, &role); err != nil || version != 11 || identities != 1 || roles != 0 || !noManagement || role != group {
		t.Fatal("failed SQL did not roll back the floor, roles, schema and retained identity together")
	}
	if _, err := os.Stat(filepath.Join(dir, "source.dump")); err != nil {
		t.Fatal("fault recovery lost the source backup")
	}
}

func managementConfig(url, name, group string) config.Migration {
	return config.Migration{Mode: config.SelfHosted, URL: url, Database: name, RuntimeRole: group}
}

func TestManagementFreshStorageAndSQLGuards(t *testing.T) {
	ctx := context.Background()
	url, name := pgtest.Database(t)
	owner := pgtest.Connect(t, url)
	group := name + "_runtime"
	build := centerBuild(t)
	result, err := Apply(ctx, owner, build, Options{Runner: "isolated-native-fixture", RuntimeRole: group})
	if err != nil || result.Version != 12 || result.State != StateCurrent {
		t.Fatalf("fresh management migration: %v", err)
	}
	if repeated, err := Apply(ctx, owner, build, Options{Runner: "isolated-native-fixture", RuntimeRole: group}); err != nil || repeated.Version != 12 || repeated.State != StateCurrent || len(repeated.Ran) != 0 || repeated.Grants != "reconciled" {
		t.Fatalf("schema12 repeat and exact grants: %v", err)
	}
	f := seedNamespaceFixture(t, owner)
	channel, holder := platform.NewID(), platform.NewID()
	protocol := platform.NewID()
	for _, statement := range []struct {
		sql  string
		args []any
	}{
		{`UPDATE fleet.node SET online_since=now(),connection_id=$1 WHERE enrollment_id=$2`, []any{channel, f.enrollment}},
		{`INSERT INTO management.node_protocol(enrollment_id,node_id,account_id,protocol_major,protocol_epoch,initialized_at,rev) VALUES($1,$2,$3,2,$4,now(),1)`, []any{f.enrollment, f.node, f.account, protocol}},
		{`INSERT INTO fleet.hub_lease(singleton,holder,fence,acquired_at,renewed_at,expires_at) VALUES(true,$1,1,now(),now(),now()+interval '5 minutes')`, []any{holder}},
	} {
		if _, err := owner.Exec(ctx, statement.sql, statement.args...); err != nil {
			t.Fatal(store.Sanitize("seed management metadata", err))
		}
	}
	runtime, sqlRuntime := managementRuntime(t, owner, url, group)
	identity := management.Identity{Account: f.account, Command: platform.NewID(), Enrollment: f.enrollment, Node: f.node, OwnerEpoch: [16]byte(platform.NewID()), IntentSHA256: sha256.Sum256([]byte("supplied canonical intent digest")), Method: "RunService.Start", CreatedAt: time.Now().UTC(), ReplayUntil: time.Now().Add(time.Hour).UTC()}
	lease := management.Lease{Holder: holder, ChannelEpoch: channel, Fence: 1}
	_, inserted, err := runtime.Reserve(ctx, identity, lease)
	if err != nil || !inserted {
		t.Fatalf("reservation: inserted=%v err=%v", inserted, err)
	}
	_, inserted, err = runtime.Reserve(ctx, identity, lease)
	if err != nil || inserted {
		t.Fatalf("exact join: inserted=%v err=%v", inserted, err)
	}
	conflict := identity
	conflict.OwnerEpoch = [16]byte(platform.NewID())
	if _, _, err := runtime.Reserve(ctx, conflict, lease); !errors.Is(err, management.ErrIdentityConflict) {
		t.Fatalf("owner epoch rebind: %v", err)
	}
	for _, statement := range []string{
		"UPDATE management.command_identity SET method='RunService.Stop'",
		"DELETE FROM management.command_identity",
		"INSERT INTO management.method_catalogue VALUES('RunService.WriteTerminal','run',2)",
		"SELECT * FROM management.cutover_receipt",
	} {
		if _, err := sqlRuntime.Exec(ctx, statement); err == nil {
			t.Fatal("runtime privilege boundary accepted an unauthorized statement")
		}
	}
	// These are supplied reconciliation observations on real SQL, not signed
	// Node results or evidence that an external Run happened.
	if _, err := sqlRuntime.Exec(ctx, `UPDATE management.remote_operation SET state=7,may_have_delivered=true,delivery_count=1,effect=3,updated_at=clock_timestamp()`); err != nil {
		t.Fatal(store.Sanitize("record supplied unknown observation", err))
	}
	for _, statement := range []string{
		"UPDATE management.remote_operation SET may_have_delivered=false",
		"UPDATE management.remote_operation SET delivery_count=0",
		"UPDATE management.remote_operation SET final_at=clock_timestamp()",
		"UPDATE management.remote_operation SET request_sha256=sha256('other')",
	} {
		if _, err := sqlRuntime.Exec(ctx, statement); err == nil {
			t.Fatal("a monotonic or unknown-outcome SQL guard was bypassed")
		}
	}
	if _, err := sqlRuntime.Exec(ctx, `UPDATE management.remote_operation SET state=3,effect=2,result_sha256=sha256('supplied result identity'),final_at=clock_timestamp(),updated_at=clock_timestamp()`); err != nil {
		t.Fatal(store.Sanitize("record supplied known observation", err))
	}
	if _, err := sqlRuntime.Exec(ctx, "UPDATE management.remote_operation SET result_sha256=sha256('replacement')"); err == nil {
		t.Fatal("known final result was replaced")
	}
	other := identity
	other.Command = platform.NewID()
	other.Method = "RunService.Stop"
	if _, inserted, err := runtime.Reserve(ctx, other, lease); err != nil || !inserted {
		t.Fatalf("second command: %v", err)
	}
	firstPage, next, err := runtime.List(ctx, f.account, "", 1)
	if err != nil || len(firstPage) != 1 || next == "" {
		t.Fatalf("bounded page: count=%d next=%v err=%v", len(firstPage), next != "", err)
	}
	secondPage, end, err := runtime.List(ctx, f.account, next, 1)
	if err != nil || len(secondPage) != 1 || end != "" || firstPage[0].Command == secondPage[0].Command {
		t.Fatal("keyset continuation lost its boundary")
	}
	if _, err := runtime.Inspect(ctx, platform.NewID(), identity.Command); !errors.Is(err, pgx.ErrNoRows) {
		t.Fatal("another account read the command")
	}
	terminal := identity
	terminal.Command = platform.NewID()
	terminal.Method = "RunService.WriteTerminal"
	if _, _, err := runtime.Reserve(ctx, terminal, lease); err == nil {
		t.Fatal("terminal input entered the durable mutation catalogue")
	}
	if _, err := owner.Exec(ctx, "UPDATE management.node_protocol SET revoked_at=clock_timestamp(),rev=rev+1"); err != nil {
		t.Fatal(store.Sanitize("revoke fixture protocol", err))
	}
	if _, err := owner.Exec(ctx, "UPDATE management.node_protocol SET revoked_at=NULL,rev=rev+1"); err == nil {
		t.Fatal("revoked protocol reactivated")
	}
	other.Command = platform.NewID()
	if _, _, err := runtime.Reserve(ctx, other, lease); !errors.Is(err, management.ErrLease) {
		t.Fatalf("revoked protocol admission: %v", err)
	}
}

func TestManagementSchema10RemainsUnqualifiedWithoutEffects(t *testing.T) {
	ctx := context.Background()
	url, name := pgtest.Database(t)
	owner := pgtest.Connect(t, url)
	group := name + "_runtime"
	build := centerBuild(t)
	if _, err := Apply(ctx, owner, build[:10], Options{Runner: "isolated-schema10-fixture", RuntimeRole: group}); err != nil {
		t.Fatal(err)
	}
	f := seedNamespaceFixture(t, owner)
	if err := insertNamespace(ctx, owner, f, platform.NewID(), false, 1, 1, false); err != nil {
		t.Fatal(store.Sanitize("seed retained schema10 identity", err))
	}
	dir := t.TempDir()
	archive, meta := filepath.Join(dir, "source.dump"), filepath.Join(dir, "source.json")
	result, err := ApplyManagement(ctx, owner, build, Options{Runner: "isolated-native-fixture", RuntimeRole: group}, managementConfig(url, name, group), archive, meta)
	if !errors.Is(err, ErrManagementSuccessorUnqualified) || result.State != StateRefused {
		t.Fatalf("unqualified successor boundary: %v", err)
	}
	if _, err := os.Stat(archive); !os.IsNotExist(err) {
		t.Fatal("unqualified path started a backup")
	}
	var version, count int
	var floor bool
	if err := owner.QueryRow(ctx, "SELECT (SELECT max(version) FROM platform.schema_migration),(SELECT count(*) FROM fleet.routed_call),to_regclass('platform.ctr06_runtime_floor') IS NOT NULL").Scan(&version, &count, &floor); err != nil || version != 10 || count != 1 || floor {
		t.Fatal("unqualified transition changed schema or retained identity")
	}
}

func TestManagementValid11PreservesLegacyUnknownAndFencesItsWriters(t *testing.T) {
	ctx := context.Background()
	url, name := pgtest.Database(t)
	owner := pgtest.Connect(t, url)
	group := name + "_runtime"
	build := centerBuild(t)
	if _, err := Apply(ctx, owner, build[:11], Options{Runner: "isolated-schema11-fixture", RuntimeRole: group}); err != nil {
		t.Fatal(err)
	}
	f := seedNamespaceFixture(t, owner)
	task, file := platform.NewID(), platform.NewID()
	if err := insertNamespace(ctx, owner, f, task, false, 1, 1, false); err != nil {
		t.Fatal(store.Sanitize("seed retained task identity", err))
	}
	if err := insertNamespace(ctx, owner, f, file, true, 10, 1, false); err != nil {
		t.Fatal(store.Sanitize("seed retained file identity", err))
	}
	if _, err := owner.Exec(ctx, "UPDATE fleet.routed_file_call SET state=7,delivered=true,updated_at=clock_timestamp()"); err != nil {
		t.Fatal(store.Sanitize("seed delivered unknown input", err))
	}
	if _, err := Apply(ctx, owner, build, Options{Runner: "isolated-native-fixture", RuntimeRole: group}); !errors.Is(err, ErrManagementTransitionRequired) {
		t.Fatalf("naked 0012 was admitted: %v", err)
	}
	dir := t.TempDir()
	result, err := ApplyManagement(ctx, owner, build, Options{Runner: "isolated-native-fixture", RuntimeRole: group}, managementConfig(url, name, group), filepath.Join(dir, "source.dump"), filepath.Join(dir, "source.json"))
	if err != nil || result.Version != 12 || result.RuntimeRole == group {
		t.Fatalf("schema11 finite maintenance: %v", err)
	}
	var identities, unknown int
	var oldWrite bool
	if err := owner.QueryRow(ctx, "SELECT (SELECT count(*) FROM management.command_identity WHERE namespace IN(1,2)),(SELECT count(*) FROM management.legacy_outcome WHERE may_have_delivered),has_table_privilege($1,'fleet.routed_call','INSERT')", group).Scan(&identities, &unknown, &oldWrite); err != nil || identities != 2 || unknown != 2 || oldWrite {
		t.Fatal("legacy identity/uncertainty or old-writer fence differs")
	}
	runtime, _ := managementRuntime(t, owner, url, result.RuntimeRole)
	i := management.Identity{Account: f.account, Command: task, Enrollment: f.enrollment, Node: f.node, OwnerEpoch: [16]byte(platform.NewID()), Method: "RunService.Start", CreatedAt: time.Now(), ReplayUntil: time.Now().Add(time.Hour)}
	if _, _, err := runtime.Reserve(ctx, i, management.Lease{}); !errors.Is(err, management.ErrLegacyCommand) {
		t.Fatalf("legacy tombstone became executable: %v", err)
	}
	if err := insertNamespace(ctx, owner, f, platform.NewID(), false, 1, 1, false); err == nil {
		t.Fatal("old routing accepted new work after expansion")
	}
	// Restore the actual schema11 backup produced before this transition.
	// This preserves the original floor protocol instead of copying source READY.
	metadataPath := filepath.Join(dir, "source.json")
	raw, err := os.ReadFile(metadataPath)
	if err != nil {
		t.Fatal("schema11 backup metadata unavailable")
	}
	metadataDigest := ctr06SHA(raw)
	meta, err := ctr06ReadMetadata(metadataPath, metadataDigest)
	if err != nil {
		t.Fatal(err)
	}
	target := name + "_r11"
	targetRole := target + "_runtime"
	t.Cleanup(func() { pgtest.Drop(t, target) })
	targetURL := pgtest.WithDatabase(t, url, target)
	cfg := config.Migration{Mode: config.SelfHosted, URL: targetURL, Maintenance: url, Database: target, RuntimeRole: targetRole}
	if restored, err := RestoreLogical(ctx, cfg, filepath.Join(dir, "source.dump"), meta.ArchiveSHA256, metadataPath, metadataDigest, "isolated-schema11-restore"); err != nil || restored.SchemaVersion != 11 || restored.RestoreReceipt == "" {
		t.Fatalf("original schema11 backup restore: %v", err)
	}
	copyOwner := pgtest.Connect(t, targetURL)
	newDir := t.TempDir()
	copyResult, err := ApplyManagement(ctx, copyOwner, build, Options{Runner: "isolated-restored11-transition", RuntimeRole: targetRole}, cfg, filepath.Join(newDir, "restored.dump"), filepath.Join(newDir, "restored.json"))
	if err != nil || copyResult.Version != 12 {
		t.Fatalf("restored11 forward transition: %v", err)
	}
	var retained int
	if err := copyOwner.QueryRow(ctx, "SELECT count(*) FROM management.legacy_outcome WHERE may_have_delivered").Scan(&retained); err != nil || retained != 2 {
		t.Fatal("schema11 restore/transition lost uncertain legacy identities")
	}
}
