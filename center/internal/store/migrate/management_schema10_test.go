// SPDX-License-Identifier: AGPL-3.0-only

package migrate

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/ArcForges/Cloud/center/internal/bridgeproof"
	"github.com/ArcForges/Cloud/center/internal/pgtest"
	"github.com/ArcForges/Cloud/center/internal/platform"
	"github.com/ArcForges/Cloud/center/internal/store"
)

func TestManagementSchema10FiniteMaintenancePreservesHistory(t *testing.T) {
	ctx := context.Background()
	url, name := pgtest.Database(t)
	owner := pgtest.Connect(t, url)
	group := name + "_runtime"
	build := centerBuild(t)
	if _, err := Apply(ctx, owner, build[:10], Options{Runner: "actual-schema10-fixture", RuntimeRole: group}); err != nil {
		t.Fatal(err)
	}
	f := seedNamespaceFixture(t, owner)
	if err := insertNamespace(ctx, owner, f, platform.NewID(), false, 1, 1, false); err != nil {
		t.Fatal(store.Sanitize("seed retained schema10 input", err))
	}
	before, _, err := ReadApplied(ctx, owner)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	result, err := ApplyManagement(ctx, owner, build, Options{Runner: "isolated-finite-maintenance-fixture", RuntimeRole: group}, managementConfig(url, name, group), filepath.Join(dir, "source.dump"), filepath.Join(dir, "source.json"))
	if err != nil || result.Version != 12 || result.RuntimeRole == group || len(result.Ran) != 2 {
		t.Fatalf("finite schema10 transition: %v", err)
	}
	after, _, err := ReadApplied(ctx, owner)
	if err != nil || len(after) != 12 || !reflect.DeepEqual(before, after[:10]) {
		t.Fatal("applied schema10 history changed")
	}
	var source int
	var legacy, revision, image string
	var oldWrite bool
	var count int
	if err := owner.QueryRow(ctx, `SELECT (SELECT source_schema FROM management.cutover_receipt),f.legacy_role::text,f.bridge_revision,f.bridge_image_id,
 has_table_privilege($1,'fleet.routed_call','INSERT'),(SELECT count(*) FROM management.legacy_outcome WHERE may_have_delivered)
 FROM platform.ctr06_runtime_floor f`, group).Scan(&source, &legacy, &revision, &image, &oldWrite, &count); err != nil || source != 10 || legacy != group || oldWrite || count != 1 {
		t.Fatal("finite floor or retained uncertainty differs")
	}
	if revision == bridgeproof.BridgeRevision || !strings.HasPrefix(revision, "afv2-maintenance/") || !strings.HasPrefix(image, "native-sha256:") {
		t.Fatal("new floor claimed the obsolete bridge or a published image")
	}
	if !errors.Is(RequireCTR06SecurityBridge(), ErrCTR06SecurityBridgeUnbound) {
		t.Fatal("historical public bridge was re-enabled")
	}
}

func TestManagementSchema10LaterFaultKeepsCommittedFloorAndCanResume(t *testing.T) {
	ctx := context.Background()
	url, name := pgtest.Database(t)
	owner := pgtest.Connect(t, url)
	group := name + "_runtime"
	build := centerBuild(t)
	if _, err := Apply(ctx, owner, build[:10], Options{Runner: "actual-schema10-fixture", RuntimeRole: group}); err != nil {
		t.Fatal(err)
	}
	f := seedNamespaceFixture(t, owner)
	if err := insertNamespace(ctx, owner, f, platform.NewID(), false, 1, 1, false); err != nil {
		t.Fatal(store.Sanitize("seed retained schema10 input", err))
	}
	fault := append([]Migration(nil), build...)
	fault[11].SQL += "\nSELECT 1/0;\n"
	digest := sha256.Sum256([]byte(fault[11].SQL))
	fault[11].SHA256 = hex.EncodeToString(digest[:])
	dir := t.TempDir()
	result, err := ApplyManagement(ctx, owner, fault, Options{Runner: "isolated-later-SQL-fault", RuntimeRole: group}, managementConfig(url, name, group), filepath.Join(dir, "source.dump"), filepath.Join(dir, "source.json"))
	var failure *Failure
	if !errors.As(err, &failure) || failure.SQLState != "22012" || result.Version != 11 || result.State != StatePending {
		t.Fatalf("later fault did not report committed floor: %+v %v", result, err)
	}
	floor, err := InspectCTR06RuntimeFloor(ctx, owner)
	if err != nil || floor == group {
		t.Fatal("committed floor was lost or old authority re-enabled")
	}
	var oldWrite bool
	if owner.QueryRow(ctx, "SELECT has_table_privilege($1,'fleet.routed_call','INSERT')", group).Scan(&oldWrite) != nil || oldWrite {
		t.Fatal("old writer regained privileges after 0012 fault")
	}
	newDir := t.TempDir()
	completed, err := ApplyManagement(ctx, owner, build, Options{Runner: "isolated-maintenance-resume", RuntimeRole: floor}, managementConfig(url, name, floor), filepath.Join(newDir, "resume.dump"), filepath.Join(newDir, "resume.json"))
	if err != nil || completed.Version != 12 {
		t.Fatalf("forward recovery from checked11 floor: %v", err)
	}
}

func TestManagementSchema10BackupRestoresIntoANewTargetGeneration(t *testing.T) {
	ctx := context.Background()
	url, name := pgtest.Database(t)
	owner := pgtest.Connect(t, url)
	group := name + "_runtime"
	build := centerBuild(t)
	if _, err := Apply(ctx, owner, build[:10], Options{Runner: "actual-schema10-restore-source", RuntimeRole: group}); err != nil {
		t.Fatal(err)
	}
	f := seedNamespaceFixture(t, owner)
	command := platform.NewID()
	if err := insertNamespace(ctx, owner, f, command, false, 1, 1, false); err != nil {
		t.Fatal(store.Sanitize("seed supplied schema10 uncertainty", err))
	}
	if _, err := owner.Exec(ctx, `INSERT INTO platform.runtime_credential(slot,login_role,rotated_at,rotated_by) VALUES('a',$1,now(),'historical input fixture')`, group+"_a"); err != nil {
		t.Fatal(store.Sanitize("seed supplied credential selection history", err))
	}
	dir := t.TempDir()
	archive, metadata := filepath.Join(dir, "source.dump"), filepath.Join(dir, "source.json")
	captured, err := CaptureLogical(ctx, managementConfig(url, name, group), archive, metadata)
	if err != nil || captured.SchemaVersion != 10 {
		t.Fatalf("capture real schema10 snapshot: %v", err)
	}
	target := name + "_restored"
	t.Cleanup(func() { pgtest.Drop(t, target) })
	role := target + "_runtime"
	cfg := managementConfig(pgtest.WithDatabase(t, url, target), target, role)
	cfg.Maintenance = url
	restored, err := RestoreLogical(ctx, cfg, archive, captured.ArchiveSHA256, metadata, captured.MetadataSHA256, "actual-schema10-restore-target")
	if err != nil || restored.SchemaVersion != 12 || restored.RestoreReceipt == "" {
		t.Fatalf("restore real schema10 archive into V2: %v", err)
	}
	destination := pgtest.Connect(t, cfg.URL)
	status, err := Inspect(ctx, destination, build)
	if err != nil || status.State != StateCurrent || status.RuntimeRole != role || status.RestoreReceipt != restored.RestoreReceipt {
		t.Fatalf("target-specific restore status: %v", err)
	}
	var source, unknown, history, current int
	var bound, noLegacy, sourceWritesTarget, sourceStillWrites bool
	if err := destination.QueryRow(ctx, `SELECT
 (SELECT source_schema FROM management.cutover_receipt),
 (SELECT count(*) FROM management.legacy_outcome WHERE account_id=$1 AND command_id=$2 AND may_have_delivered),
 (SELECT count(*) FROM platform.ctr06_legacy_runtime_credential WHERE login_role=$3||'_a'),
 (SELECT count(*) FROM platform.runtime_credential),
 EXISTS(SELECT 1 FROM platform.ctr06_runtime_floor f JOIN platform.ctr06_restore_admission a USING(singleton),pg_database d
 WHERE d.datname=current_database() AND f.database_oid=d.oid AND f.runtime_role=$4 AND a.kind='restore' AND a.state='READY' AND a.receipt_sha256=$5),
 (SELECT legacy_role IS NULL AND legacy_role_oid IS NULL FROM platform.ctr06_runtime_floor),
 has_table_privilege($3,'fleet.routed_call','INSERT')`, f.account, command, group, role, restored.RestoreReceipt).Scan(&source, &unknown, &history, &current, &bound, &noLegacy, &sourceWritesTarget); err != nil || source != 10 || unknown != 1 || history != 1 || current != 0 || !bound || !noLegacy || sourceWritesTarget {
		t.Fatal("restored target copied source authority or lost retained facts")
	}
	if owner.QueryRow(ctx, "SELECT has_table_privilege($1,'fleet.routed_call','INSERT')", group).Scan(&sourceStillWrites) != nil || !sourceStillWrites {
		t.Fatal("restoring an independent target altered the source's role generation")
	}
	runtime, _ := managementRuntime(t, destination, cfg.URL, role)
	retained, err := runtime.Inspect(ctx, f.account, command)
	if err != nil || retained.Namespace != 1 || !retained.MayHaveDelivered {
		t.Fatalf("historical uncertainty not inspectable as a non-executable tombstone: %v", err)
	}
}

func TestManagementSchema10RestoreFailureKeepsQuarantineAndCannotBeAdopted(t *testing.T) {
	ctx := context.Background()
	url, name := pgtest.Database(t)
	owner := pgtest.Connect(t, url)
	group := name + "_runtime"
	build := centerBuild(t)
	if _, err := Apply(ctx, owner, build[:10], Options{Runner: "actual-schema10-rejected-history-source", RuntimeRole: group}); err != nil {
		t.Fatal(err)
	}
	// Supplied inconsistent old selection history is not a credential or a fake
	// producer proof. Its exact bytes remain in the preserved failed target.
	if _, err := owner.Exec(ctx, `INSERT INTO platform.runtime_credential(slot,login_role,rotated_at,rotated_by) VALUES('a','unknown_generation_a',now(),'historical inconsistent input')`); err != nil {
		t.Fatal(store.Sanitize("seed inconsistent historical selection", err))
	}
	dir := t.TempDir()
	archive, metadata := filepath.Join(dir, "source.dump"), filepath.Join(dir, "source.json")
	captured, err := CaptureLogical(ctx, managementConfig(url, name, group), archive, metadata)
	if err != nil {
		t.Fatal(err)
	}
	target := name + "_failed"
	t.Cleanup(func() { pgtest.Drop(t, target) })
	cfg := managementConfig(pgtest.WithDatabase(t, url, target), target, target+"_runtime")
	cfg.Maintenance = url
	if _, err := RestoreLogical(ctx, cfg, archive, captured.ArchiveSHA256, metadata, captured.MetadataSHA256, "actual-schema10-rejected-history-target"); err == nil || !strings.Contains(err.Error(), "UNKNOWN and quarantined") {
		t.Fatalf("failed expansion did not preserve unknown quarantine: %v", err)
	}
	destination := pgtest.Connect(t, cfg.URL)
	var version, history int
	var marker string
	var occupied bool
	if err := destination.QueryRow(ctx, `SELECT (SELECT max(version) FROM platform.schema_migration),
 (SELECT count(*) FROM platform.runtime_credential WHERE login_role='unknown_generation_a'),
 coalesce(shobj_description(d.oid,'pg_database'),''),EXISTS(SELECT 1 FROM pg_roles WHERE rolname=$1)
 FROM pg_database d WHERE d.datname=current_database()`, cfg.RuntimeRole).Scan(&version, &history, &marker, &occupied); err != nil || version != 10 || history != 1 || marker != ctr06RestoreIsolationMarker || occupied {
		t.Fatal("failed expansion leaked a floor/role or discarded the source snapshot")
	}
	if _, err := Apply(ctx, destination, build, Options{Runner: "ordinary-cannot-adopt", RuntimeRole: cfg.RuntimeRole}); !errors.Is(err, ErrCTR06RetirementUnproven) {
		t.Fatalf("ordinary migration adopted a failed quarantined target: %v", err)
	}
	if _, err := RestoreLogical(ctx, cfg, archive, captured.ArchiveSHA256, metadata, captured.MetadataSHA256, "another-invocation-cannot-adopt"); err == nil {
		t.Fatal("a new invocation adopted an earlier target by name")
	}
}
