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
