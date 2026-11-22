// SPDX-License-Identifier: AGPL-3.0-only

package migrate

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"testing"
	"time"

	"github.com/ArcForges/Cloud/center/internal/config"
	"github.com/ArcForges/Cloud/center/internal/pgtest"
	"github.com/ArcForges/Cloud/center/internal/platform"
	"github.com/ArcForges/Cloud/center/internal/schema"
	"github.com/ArcForges/Cloud/center/internal/store"
	"github.com/jackc/pgx/v5"
)

func TestContractionInventoryForBackup(t *testing.T) {
	captureBackupInventory(t, schema.ContractionVersion, "ARCFORGES_MIG02_INVENTORY_DIR")
}

func TestContractionFreshRuntimeUsesTheContractedReader(t *testing.T) {
	ctx := context.Background()
	url, name := pgtest.Database(t)
	owner := pgtest.Connect(t, url)
	group := name + "_runtime"
	build := centerBuild(t)
	options := Options{Runner: "isolated-fresh-contraction", RuntimeRole: group}
	result, err := Apply(ctx, owner, build, options)
	if err != nil || result.Version != schema.ContractionVersion || result.State != StateCurrent ||
		result.RuntimeRole != group || len(result.Ran) != schema.ContractionVersion || result.Grants != "reconciled" {
		t.Fatalf("fresh contracted schema: %v", err)
	}
	assertContractedSchema(t, ctx, owner)
	_, runtime := managementRuntime(t, owner, url, group)
	assertContractedReader(t, ctx, runtime, build)
	if repeated, err := Apply(ctx, owner, build, options); err != nil || repeated.Version != result.Version || len(repeated.Ran) != 0 {
		t.Fatalf("reapply current history and grants: %v", err)
	}
	refused, err := PrepareContraction(ctx, owner, build, options, managementConfig(url, name, group))
	if !errors.Is(err, ErrRefused) || refused.State != StateRefused || refused.Version != schema.ContractionVersion ||
		!reflect.DeepEqual(refused.Applied, result.Applied) || len(refused.Ran) != 0 {
		t.Fatalf("schema preparation attempted to revisit a contracted database: %+v %v", refused, err)
	}
}

func TestPrepareContractionRefusesIneligibleAuthorityAndResumesAfterKnownPartialProgress(t *testing.T) {
	ctx := t.Context()
	url, name := pgtest.Database(t)
	owner := pgtest.Connect(t, url)
	group := name + "_runtime"
	build := centerBuild(t)
	options := Options{Runner: "isolated-preparation", RuntimeRole: group}
	cfg := managementConfig(url, name, group)
	assertRefused := func(role string, version int) {
		t.Helper()
		selected := options
		selected.RuntimeRole = role
		source := cfg
		source.RuntimeRole = role
		result, err := PrepareContraction(ctx, owner, build, selected, source)
		if !errors.Is(err, ErrRefused) || result.State != StateRefused || result.Version != version || len(result.Ran) != 0 {
			t.Fatalf("unsafe schema preparation was not refused at schema %d: %+v %v", version, result, err)
		}
	}
	assertRefused(group, 0)
	if _, exists, err := ReadApplied(ctx, owner); err != nil || exists {
		t.Fatalf("preparation initialized an empty database: exists=%t %v", exists, err)
	}
	original, err := Apply(ctx, owner, build[:13], options)
	if err != nil || original.Version != 13 {
		t.Fatalf("prepare the real schema13 source: %+v %v", original, err)
	}
	assertRefused(name+"_obsolete", 13)

	foreign := pgx.Identifier{name + "_foreign"}.Sanitize()
	if _, err := owner.Exec(ctx, "CREATE ROLE "+foreign); err != nil {
		t.Fatal(store.Sanitize("create the isolated historical reader", err))
	}
	if _, err := owner.Exec(ctx, "GRANT CONNECT ON DATABASE "+pgx.Identifier{name}.Sanitize()+" TO "+foreign+
		"; GRANT SELECT ON TABLE fleet.routed_call TO "+foreign); err != nil {
		t.Fatal(store.Sanitize("grant the isolated historical reader access", err))
	}
	assertRefused(group, 13)
	if _, err := owner.Exec(ctx, "REVOKE SELECT ON TABLE fleet.routed_call FROM "+foreign+
		"; REVOKE CONNECT ON DATABASE "+pgx.Identifier{name}.Sanitize()+" FROM "+foreign); err != nil {
		t.Fatal(store.Sanitize("revoke the isolated historical reader access", err))
	}
	if applied := contractionHistory(t, ctx, owner); !reflect.DeepEqual(applied, original.Applied) {
		t.Fatal("an ineligible preparation changed the applied ledger")
	}

	faulty := append([]Migration(nil), build...)
	faulty[14].SQL += "\nSELECT 1 / 0;\n"
	partial, err := PrepareContraction(ctx, owner, faulty, options, cfg)
	var fault *Failure
	if !errors.As(err, &fault) || fault.Version != 15 || fault.SQLState != "22012" ||
		partial.State != StateMaintenance || partial.Version != 14 || len(partial.Applied) != 14 || partial.Grants != "" ||
		len(partial.Ran) != 1 || partial.Ran[0].Version != 14 ||
		!reflect.DeepEqual(partial.Applied[:13], original.Applied) {
		t.Fatalf("the real failed additive step lost the last committed checkpoint: %+v %v", partial, err)
	}
	complete, err := PrepareContraction(ctx, owner, build, options, cfg)
	if err != nil || complete.State != StateCurrent || complete.Version != 16 || complete.BuildVersion != 16 ||
		complete.RuntimeRole != group || complete.Grants != "reconciled" || len(complete.Ran) != 2 || len(complete.Applied) != 16 ||
		!reflect.DeepEqual(complete.Applied[:14], partial.Applied) {
		t.Fatalf("resuming after a known partial preparation did not keep the same history: %+v %v", complete, err)
	}
	replayed, err := PrepareContraction(ctx, owner, build, options, cfg)
	if err != nil || replayed.State != StateCurrent || replayed.Version != 16 || replayed.RuntimeRole != group ||
		replayed.Grants != "reconciled" || len(replayed.Ran) != 0 || !reflect.DeepEqual(replayed.Applied, complete.Applied) {
		t.Fatalf("replay changed the prepared migration ledger or runtime generation: %+v %v", replayed, err)
	}
}

func TestContractionRuntimeReaderRefusesCopiedDatabaseAuthority(t *testing.T) {
	ctx := t.Context()
	url, name := pgtest.Database(t)
	owner := pgtest.Connect(t, url)
	group := name + "_runtime"
	build := centerBuild(t)
	if _, err := Apply(ctx, owner, build, Options{Runner: "isolated-contracted-copy", RuntimeRole: group}); err != nil {
		t.Fatal(err)
	}
	_, runtime := managementRuntime(t, owner, url, group)
	assertContractedReader(t, ctx, runtime, build)
	ownerName := owner.Config().User
	cloneConfig := runtime.Config()
	cloneConfig.Database = name + "_copied"
	if err := runtime.Close(ctx); err != nil {
		t.Fatal(store.Sanitize("close the original runtime fixture", err))
	}
	if err := owner.Close(ctx); err != nil {
		t.Fatal(store.Sanitize("close the original owner fixture", err))
	}
	admin := pgtest.Admin(t)
	clone := pgx.Identifier{cloneConfig.Database}.Sanitize()
	if _, err := admin.Exec(ctx, "CREATE DATABASE "+clone+" TEMPLATE "+pgx.Identifier{name}.Sanitize()+
		" OWNER "+pgx.Identifier{ownerName}.Sanitize()); err != nil {
		t.Fatal(store.Sanitize("copy the isolated database as a template", err))
	}
	t.Cleanup(func() { pgtest.Drop(t, cloneConfig.Database) })
	if _, err := admin.Exec(ctx, "GRANT CONNECT ON DATABASE "+clone+" TO "+pgx.Identifier{group}.Sanitize()); err != nil {
		t.Fatal(store.Sanitize("make the copied runtime connection possible", err))
	}
	copiedRuntime, err := pgx.ConnectConfig(ctx, cloneConfig)
	if err != nil {
		t.Fatal(store.Sanitize("connect to the isolated copy with the original fixture login", err))
	}
	defer copiedRuntime.Close(context.Background())
	var count int
	if err := copiedRuntime.QueryRow(ctx, "SELECT count(*) FROM platform.runtime_schema_history").Scan(&count); err != nil || count != 0 {
		t.Fatal("unadmitted copied database exposed migration history as current")
	}
	if _, err := CheckCompatible(ctx, copiedRuntime, build); !errors.Is(err, ErrIncompatible) {
		t.Fatalf("runtime accepted a checkpoint belonging to the original database: %v", err)
	}
}

func TestContractionFromSchema10And11RetainsOriginalIdentitiesAndRestores(t *testing.T) {
	for _, version := range []int{10, 11} {
		t.Run(strconv.Itoa(version), func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
			defer cancel()
			url, name := pgtest.Database(t)
			owner := pgtest.Connect(t, url)
			group := name + "_runtime"
			build := centerBuild(t)
			if _, err := Apply(ctx, owner, build[:version], Options{Runner: "isolated-actual-predecessor", RuntimeRole: group}); err != nil {
				t.Fatal(err)
			}
			initial := contractionHistory(t, ctx, owner)
			fixture := seedNamespaceFixture(t, owner)
			command := platform.NewID()
			insertContractionTask(t, ctx, owner, fixture, command, 8)
			var file platform.ID
			var mobileFlow platform.ID
			if version == 11 {
				file = platform.NewID()
				if err := insertNamespace(ctx, owner, fixture, file, true, 17, 1, false); err != nil {
					t.Fatal(store.Sanitize("insert original file identity", err))
				}
				if _, err := owner.Exec(ctx, "UPDATE fleet.routed_file_call SET state=8 WHERE account_id=$1 AND command_id=$2", fixture.account, file); err != nil {
					t.Fatal(store.Sanitize("settle original file as not delivered", err))
				}
				mobileFlow = platform.NewID()
				if _, err := owner.Exec(ctx, `INSERT INTO identity.mobile_authorization
 (flow_id,state,client_id,redirect_uri,code_challenge,client_state,installation_id,platform,app_version,created_at,expires_at,rev)
 VALUES($1,1,'arcforges.android','https://center.example/app/callback',repeat('A',43),repeat('A',16),
 gen_random_uuid(),'android-15','2.0',now(),now()+interval '5 minutes',1)`, mobileFlow); err != nil {
					t.Fatal(store.Sanitize("seed original mobile authorization", err))
				}
			}
			managementDir := t.TempDir()
			management, err := ApplyManagement(ctx, owner, build, Options{Runner: "isolated-legacy-expansion", RuntimeRole: group},
				managementConfig(url, name, group), filepath.Join(managementDir, "source.dump"), filepath.Join(managementDir, "source.json"))
			if err != nil || management.Version != 12 || !reflect.DeepEqual(initial, management.Applied[:version]) {
				t.Fatalf("expand actual schema%d without changing its applied history: %v", version, err)
			}
			group = management.RuntimeRole
			early, err := PrepareContraction(ctx, owner, build, Options{Runner: "isolated-contraction-predecessor", RuntimeRole: group},
				managementConfig(url, name, group))
			if !errors.Is(err, ErrRefused) || early.State != StateRefused || early.Version != 12 ||
				!reflect.DeepEqual(early.Applied, management.Applied) || len(early.Ran) != 0 {
				t.Fatalf("contraction preparation skipped the schema13 lifecycle admission: %+v %v", early, err)
			}
			lifecycleDir := t.TempDir()
			lifecycle, err := ApplyLifecycle(ctx, owner, build, Options{Runner: "isolated-lifecycle-expansion", RuntimeRole: group},
				managementConfig(url, name, group), filepath.Join(lifecycleDir, "source.dump"), filepath.Join(lifecycleDir, "source.json"))
			if err != nil || lifecycle.Version != 13 || lifecycle.RuntimeRole == group {
				t.Fatalf("install actual lifecycle transition: %v", err)
			}
			group = lifecycle.RuntimeRole
			predecessor := schema.ContractionVersion - 1
			prepared, err := PrepareContraction(ctx, owner, build, Options{Runner: "isolated-contraction-predecessor", RuntimeRole: group},
				managementConfig(url, name, group))
			if err != nil || prepared.State != StateCurrent || prepared.Version != predecessor || prepared.RuntimeRole != group ||
				prepared.Grants != "reconciled" || len(prepared.Ran) != 3 || len(prepared.Applied) != predecessor ||
				!reflect.DeepEqual(prepared.Applied[:13], lifecycle.Applied) {
				t.Fatalf("prepare the historical schema%d lineage through schema16: %+v %v", version, prepared, err)
			}
			before := contractionHistory(t, ctx, owner)
			assertContractedTombstone(t, ctx, owner, fixture, command, 1)

			options := Options{Runner: "isolated-verified-contraction", RuntimeRole: group}
			if _, err := Apply(ctx, owner, build, options); !errors.Is(err, ErrContractionRequired) {
				t.Fatalf("ordinary apply did not require verified contraction admission: %v", err)
			}
			assertContractionCheckpoint(t, ctx, owner, before, group)

			witness := contractionRestoreDestination(t, url, name, "_witness")
			archive, metadata := contractionBackupPaths(t)
			result, err := ApplyContraction(ctx, owner, build, options, managementConfig(url, name, group), witness, archive, metadata)
			if err != nil || result.Version != schema.ContractionVersion || result.RuntimeRole == group ||
				len(result.Ran) != 1 || !reflect.DeepEqual(before, result.Applied[:predecessor]) {
				t.Fatalf("contract verified schema%d lineage: %v", version, err)
			}
			assertContractedSchema(t, ctx, owner)
			assertContractedTombstone(t, ctx, owner, fixture, command, 1)
			if version == 11 {
				assertContractedTombstone(t, ctx, owner, fixture, file, 2)
				original := pgtest.Connect(t, witness.URL)
				var retained bool
				if err := original.QueryRow(ctx, "SELECT state=1 FROM identity.mobile_authorization WHERE flow_id=$1", mobileFlow).Scan(&retained); err != nil || !retained {
					t.Fatal("the isolated rollback witness lost the original mobile authorization identity")
				}
			}
			var backup, restore bool
			if err := owner.QueryRow(ctx, `SELECT octet_length(backup_manifest_sha256)=32, octet_length(contraction_restore_sha256)=32
 FROM management.cutover_receipt WHERE source_schema=$1 AND target_schema=$2 AND phase=4`, predecessor, schema.ContractionVersion).Scan(&backup, &restore); err != nil || !backup || !restore {
				t.Fatal("contracted source has no exact predecessor backup and isolated restore binding")
			}
			_, runtime := managementRuntime(t, owner, url, result.RuntimeRole)
			assertContractedReader(t, ctx, runtime, build)

			afterArchive, afterMetadata := contractionBackupPaths(t)
			captured, err := CaptureLogical(ctx, managementConfig(url, name, result.RuntimeRole), afterArchive, afterMetadata)
			if err != nil || captured.SchemaVersion != schema.ContractionVersion {
				t.Fatalf("capture contracted source: %v", err)
			}
			destination := contractionRestoreDestination(t, url, name, "_restored")
			restored, err := RestoreLogical(ctx, destination, afterArchive, captured.ArchiveSHA256, afterMetadata, captured.MetadataSHA256, "isolated-contracted-restore")
			if err != nil || restored.SchemaVersion != schema.ContractionVersion || restored.RestoreReceipt == "" ||
				restored.SourceBackupSHA256 != captured.ArchiveSHA256 || restored.RuntimeRole == result.RuntimeRole {
				t.Fatalf("restore contracted backup in its own generation: %v", err)
			}
			target := pgtest.Connect(t, destination.URL)
			assertContractedSchema(t, ctx, target)
			assertContractedTombstone(t, ctx, target, fixture, command, 1)
			if version == 11 {
				assertContractedTombstone(t, ctx, target, fixture, file, 2)
			}
			if got := contractionHistory(t, ctx, target); !reflect.DeepEqual(result.Applied, got) {
				t.Fatal("contracted backup restore changed applied migration history")
			}
			status, err := Inspect(ctx, target, build)
			if err != nil || status.State != StateCurrent || status.RestoreReceipt != restored.RestoreReceipt {
				t.Fatalf("restored contracted admission is incomplete: %v", err)
			}
			_, restoredRuntime := managementRuntime(t, target, destination.URL, destination.RuntimeRole)
			assertContractedReader(t, ctx, restoredRuntime, build)
		})
	}
}

func TestContractionRefusesUnresolvedReceiptsAndLiveHub(t *testing.T) {
	for _, mode := range []string{"accepted", "unknown", "active-hub"} {
		t.Run(mode, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
			defer cancel()
			url, name := pgtest.Database(t)
			owner := pgtest.Connect(t, url)
			build := centerBuild(t)
			group := name + "_runtime"
			options := Options{Runner: "isolated-unsafe-contraction", RuntimeRole: group}
			if mode == "active-hub" {
				if _, err := Apply(ctx, owner, build[:schema.ContractionVersion-1], options); err != nil {
					t.Fatal(err)
				}
				if _, err := owner.Exec(ctx, `INSERT INTO fleet.hub_lease(singleton,holder,fence,acquired_at,renewed_at,expires_at)
 VALUES(true,$1,1,now(),now(),now()+interval '5 minutes')`, platform.NewID()); err != nil {
					t.Fatal(store.Sanitize("seed live isolated hub lease", err))
				}
			} else {
				if _, err := Apply(ctx, owner, build[:11], options); err != nil {
					t.Fatal(err)
				}
				fixture := seedNamespaceFixture(t, owner)
				state := int16(1)
				if mode == "unknown" {
					state = 7
				}
				insertContractionTask(t, ctx, owner, fixture, platform.NewID(), state)
				archive, metadata := contractionBackupPaths(t)
				management, err := ApplyManagement(ctx, owner, build, options, managementConfig(url, name, group), archive, metadata)
				if err != nil || management.Version != 12 {
					t.Fatalf("expand unresolved predecessor: %v", err)
				}
				group = management.RuntimeRole
				options.RuntimeRole = group
				archive, metadata = contractionBackupPaths(t)
				lifecycle, err := ApplyLifecycle(ctx, owner, build, options, managementConfig(url, name, group), archive, metadata)
				if err != nil || lifecycle.Version != 13 {
					t.Fatalf("expand unresolved lifecycle schema: %v", err)
				}
				group = lifecycle.RuntimeRole
				options.RuntimeRole = group
				if _, err := Apply(ctx, owner, build[:schema.ContractionVersion-1], options); err != nil {
					t.Fatal(err)
				}
			}
			before := contractionHistory(t, ctx, owner)
			witness := contractionRestoreDestination(t, url, name, "_witness")
			archive, metadata := contractionBackupPaths(t)
			_, err := ApplyContraction(ctx, owner, build, options, managementConfig(url, name, group), witness, archive, metadata)
			var failure *Failure
			if (!errors.As(err, &failure) || failure.SQLState != "55000") && !errors.Is(err, ErrContractionRequired) {
				t.Fatalf("contraction did not refuse %s at its effect boundary: %v", mode, err)
			}
			assertContractionCheckpoint(t, ctx, owner, before, group)
		})
	}
}

func TestContractionSQLFaultKeepsRollbackCheckpoint(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	url, name := pgtest.Database(t)
	owner := pgtest.Connect(t, url)
	group := name + "_runtime"
	build := centerBuild(t)
	options := Options{Runner: "isolated-contraction-SQL-fault", RuntimeRole: group}
	predecessor := schema.ContractionVersion - 1
	if _, err := Apply(ctx, owner, build[:predecessor], options); err != nil {
		t.Fatal(err)
	}
	before := contractionHistory(t, ctx, owner)
	fault := append([]Migration(nil), build...)
	fault[predecessor].SQL += "\nSELECT 1/0;\n"
	digest := sha256.Sum256([]byte(fault[predecessor].SQL))
	fault[predecessor].SHA256 = hex.EncodeToString(digest[:])
	witness := contractionRestoreDestination(t, url, name, "_witness")
	archive, metadata := contractionBackupPaths(t)
	_, err := ApplyContraction(ctx, owner, fault, options, managementConfig(url, name, group), witness, archive, metadata)
	var failure *Failure
	if !errors.As(err, &failure) || failure.SQLState != "22012" {
		t.Fatalf("expected PostgreSQL transaction failure after the drop statements: %v", err)
	}
	assertContractionCheckpoint(t, ctx, owner, before, group)
	for _, path := range []string{archive, metadata} {
		if info, err := os.Stat(path); err != nil || info.Size() == 0 {
			t.Fatal("the verified rollback backup was lost after the SQL fault")
		}
	}
}

func TestContractionCommitClassification(t *testing.T) {
	migration := Migration{Version: schema.ContractionVersion, Name: contractionName}
	if contractionCommitUnknown(migration, false, io.EOF) ||
		contractionCommitUnknown(migration, true, pgx.ErrTxCommitRollback) ||
		contractionCommitUnknown(migration, true, nil) ||
		contractionCommitUnknown(Migration{Version: 16}, true, io.EOF) {
		t.Fatal("known outcomes or earlier migration behavior changed")
	}
	if !contractionCommitUnknown(migration, true, io.EOF) {
		t.Fatal("a lost contraction COMMIT response was treated as a known rollback")
	}
}

func TestContractionReportsCommittedSchemaWhenGrantReconcileFails(t *testing.T) {
	ctx := t.Context()
	url, name := pgtest.Database(t)
	owner := pgtest.Connect(t, url)
	group := name + "_runtime"
	build := centerBuild(t)
	_, grants := schema.AtVersion(schema.ContractionVersion)
	grants = append(grants, schema.Grant{Schema: "platform", Table: "missing_grant_target", Privileges: []schema.Privilege{schema.Select}})
	result, err := Apply(ctx, owner, build, Options{Runner: "isolated-contraction-grant-fault", RuntimeRole: group, Grants: grants})
	if !errors.Is(err, ErrContractionFollowupRequired) || result.State != StateMaintenance ||
		result.Version != schema.ContractionVersion || len(result.Ran) != schema.ContractionVersion ||
		result.Ran[len(result.Ran)-1].Version != schema.ContractionVersion {
		t.Fatalf("a committed contraction with failed grants was treated as a rollback: %v", err)
	}
	status, err := Inspect(ctx, owner, build)
	if err != nil || status.State != StateCurrent || status.Version != schema.ContractionVersion {
		t.Fatalf("committed contraction could not be independently inspected: %v", err)
	}
	recovered, err := Apply(ctx, owner, build, Options{Runner: "recover-isolated-verified-grants", RuntimeRole: group})
	if err != nil || recovered.State != StateCurrent || len(recovered.Ran) != 0 || recovered.Grants != "reconciled" {
		t.Fatalf("known commit could not complete its grants without applying a second time: %v", err)
	}
}

func TestContractionRefusesForeignRetiredRelationReader(t *testing.T) {
	for _, mode := range []string{"column-grant", "set-role"} {
		t.Run(mode, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
			defer cancel()
			url, name := pgtest.Database(t)
			owner := pgtest.Connect(t, url)
			group := name + "_runtime"
			build := centerBuild(t)
			options := Options{Runner: "isolated-foreign-reader-contraction", RuntimeRole: group}
			if _, err := Apply(ctx, owner, build[:schema.ContractionVersion-1], options); err != nil {
				t.Fatal(err)
			}
			roleName := name + "_retired_reader"
			role := pgx.Identifier{roleName}.Sanitize()
			admin := pgtest.Admin(t)
			if _, err := admin.Exec(ctx, "CREATE ROLE "+role+" NOLOGIN"); err != nil {
				t.Fatal(store.Sanitize("create isolated foreign reader", err))
			}
			if _, err := owner.Exec(ctx, "GRANT CONNECT ON DATABASE "+pgx.Identifier{name}.Sanitize()+" TO "+role); err != nil {
				t.Fatal(store.Sanitize("give the fixture reader access to its database", err))
			}
			if mode == "column-grant" {
				if _, err := owner.Exec(ctx, "GRANT USAGE ON SCHEMA fleet TO "+role+
					"; GRANT SELECT (command_id) ON fleet.routed_call TO "+role); err != nil {
					t.Fatal(store.Sanitize("set up isolated foreign column reader", err))
				}
			} else {
				if _, err := admin.Exec(ctx, "GRANT pg_read_all_data TO "+role+" WITH INHERIT FALSE, SET TRUE"); err != nil {
					t.Fatal(store.Sanitize("set up isolated assumable reader", err))
				}
				var inherited, canAssume bool
				if err := owner.QueryRow(ctx, "SELECT has_table_privilege($1,'fleet.routed_call','SELECT'), pg_has_role($1,'pg_read_all_data','SET')",
					roleName).Scan(&inherited, &canAssume); err != nil || inherited || !canAssume {
					t.Fatal("assumable reader must gain access only through SET ROLE")
				}
			}
			before := contractionHistory(t, ctx, owner)
			witness := contractionRestoreDestination(t, url, name, "_witness")
			archive, metadata := contractionBackupPaths(t)
			_, err := ApplyContraction(ctx, owner, build, options, managementConfig(url, name, group), witness, archive, metadata)
			if !errors.Is(err, ErrContractionRequired) {
				t.Fatalf("contraction did not refuse the foreign legacy relation reader: %v", err)
			}
			assertContractionCheckpoint(t, ctx, owner, before, group)
		})
	}
}

func insertContractionTask(t *testing.T, ctx context.Context, conn *pgx.Conn, fixture namespaceFixture, command platform.ID, state int16) {
	t.Helper()
	if err := insertNamespace(ctx, conn, fixture, command, false, 1, 1, false); err != nil {
		t.Fatal(store.Sanitize("seed original routed Task", err))
	}
	if state != 1 {
		if _, err := conn.Exec(ctx, "UPDATE fleet.routed_call SET state=$3::smallint,delivered=($3::smallint=7) WHERE account_id=$1 AND command_id=$2",
			fixture.account, command, state); err != nil {
			t.Fatal(store.Sanitize("set original routed Task outcome", err))
		}
	}
}

func contractionHistory(t *testing.T, ctx context.Context, conn *pgx.Conn) []Applied {
	t.Helper()
	applied, exists, err := ReadApplied(ctx, conn)
	if err != nil || !exists {
		t.Fatal("the original applied history is unavailable")
	}
	return applied
}

func contractionBackupPaths(t *testing.T) (string, string) {
	t.Helper()
	dir := t.TempDir()
	return filepath.Join(dir, "source.dump"), filepath.Join(dir, "source.json")
}

func contractionRestoreDestination(t *testing.T, url, name, suffix string) config.Migration {
	t.Helper()
	target := name + suffix
	t.Cleanup(func() { pgtest.Drop(t, target) })
	cfg := managementConfig(pgtest.WithDatabase(t, url, target), target, target+"_runtime")
	cfg.Maintenance = url
	return cfg
}

func assertContractedReader(t *testing.T, ctx context.Context, runtime *pgx.Conn, build []Migration) {
	t.Helper()
	version, err := CheckCompatible(ctx, runtime, build)
	if err != nil || version != schema.ContractionVersion {
		t.Fatalf("contracted runtime reader failed: %v", err)
	}
	if _, err := CheckCompatible(ctx, runtime, build[:schema.ContractionVersion-1]); !errors.Is(err, ErrIncompatible) {
		t.Fatalf("former runtime reader was not refused: %v", err)
	}
	if _, err := runtime.Exec(ctx, "SELECT version FROM platform.schema_migration"); !pgtest.IsCode(err, "42501") {
		t.Fatal("runtime can query the owner-only historical migration ledger")
	}
}

func assertContractedSchema(t *testing.T, ctx context.Context, conn *pgx.Conn) {
	t.Helper()
	var retired, shared bool
	err := conn.QueryRow(ctx, `SELECT to_regclass('fleet.routed_call') IS NULL AND to_regclass('fleet.routed_file_call') IS NULL
 AND to_regclass('fleet.routed_file_target') IS NULL AND to_regclass('fleet.routed_command_id') IS NULL
 AND to_regclass('fleet.refusal_code') IS NULL AND to_regclass('identity.mobile_authorization') IS NULL,
 to_regclass('fleet.hub_lease') IS NOT NULL AND to_regclass('identity.session') IS NOT NULL
 AND to_regclass('management.command_identity') IS NOT NULL AND to_regclass('management.legacy_outcome') IS NOT NULL
 AND to_regclass('platform.runtime_schema_history') IS NOT NULL`).Scan(&retired, &shared)
	if err != nil || !retired || !shared {
		t.Fatal("contracted schema differs from the retired/shared object boundary")
	}
}

func assertContractedTombstone(t *testing.T, ctx context.Context, conn *pgx.Conn, fixture namespaceFixture, command platform.ID, wantNamespace int) {
	t.Helper()
	var namespace, state int
	var ownerEpochAbsent, notDelivered, digestPresent bool
	err := conn.QueryRow(ctx, `SELECT i.namespace,o.legacy_state,i.node_owner_epoch IS NULL,NOT o.may_have_delivered,
 octet_length(o.source_row_sha256)=32 FROM management.command_identity i
 JOIN management.legacy_outcome o USING(account_id,command_id)
 WHERE i.account_id=$1 AND i.command_id=$2 AND i.enrollment_id=$3 AND i.node_id=$4`,
		fixture.account, command, fixture.enrollment, fixture.node).Scan(&namespace, &state, &ownerEpochAbsent, &notDelivered, &digestPresent)
	if err != nil || namespace != wantNamespace || state != 8 || !ownerEpochAbsent || !notDelivered || !digestPresent {
		t.Fatal("the original command ID and non-executable outcome did not survive")
	}
}

func assertContractionCheckpoint(t *testing.T, ctx context.Context, conn *pgx.Conn, before []Applied, oldRole string) {
	t.Helper()
	if after := contractionHistory(t, ctx, conn); !reflect.DeepEqual(before, after) {
		t.Fatal("refusal changed the predecessor migration ledger")
	}
	var intact bool
	err := conn.QueryRow(ctx, `SELECT to_regclass('fleet.routed_call') IS NOT NULL AND to_regclass('fleet.routed_file_call') IS NOT NULL
 AND to_regclass('identity.mobile_authorization') IS NOT NULL AND to_regclass('platform.runtime_schema_history') IS NULL
 AND has_table_privilege($1,'platform.schema_migration','SELECT')
 AND EXISTS(SELECT 1 FROM platform.ctr06_runtime_floor WHERE runtime_role=$1)
 AND NOT EXISTS(SELECT 1 FROM management.cutover_receipt WHERE target_schema=$2)`, oldRole, schema.ContractionVersion).Scan(&intact)
	if err != nil || !intact {
		t.Fatal("refusal changed original relations, writer generation, or admission")
	}
}
