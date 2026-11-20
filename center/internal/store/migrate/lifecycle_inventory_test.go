// SPDX-License-Identifier: AGPL-3.0-only

package migrate

import (
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/ArcForges/Cloud/center/internal/pgtest"
)

func TestLifecycleInventoryForBackup(t *testing.T) {
	captureBackupInventory(t, 13, "ARCFORGES_ID01_INVENTORY_DIR")
}

func TestRemoteObservationInventoryForBackup(t *testing.T) {
	captureBackupInventory(t, 14, "ARCFORGES_CENTER03_INVENTORY_DIR")
}

func TestHostedEntitlementInventoryForBackup(t *testing.T) {
	captureBackupInventory(t, 15, "ARCFORGES_HOST01_INVENTORY_DIR")
}

func TestHostedCommerceInventoryForBackup(t *testing.T) {
	captureBackupInventory(t, 16, "ARCFORGES_HOST02_INVENTORY_DIR")
}

func captureBackupInventory(t *testing.T, version int, evidenceRoot string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	url, name := pgtest.Database(t)
	owner := pgtest.Connect(t, url)
	if _, err := Apply(ctx, owner, centerBuild(t)[:version], Options{Runner: "isolated-inventory-fixture", RuntimeRole: name + "_runtime"}); err != nil {
		t.Fatal(err)
	}
	if _, err := owner.Exec(ctx, "SET search_path=pg_catalog; SET TIME ZONE 'UTC'"); err != nil {
		t.Fatal("inventory session settings failed")
	}
	catalogue, err := ctr06CatalogueSHA(ctx, owner)
	if err != nil {
		t.Fatal(err)
	}
	base := os.Getenv(evidenceRoot)
	if base == "" {
		base = t.TempDir()
	} else if !filepath.IsAbs(base) {
		t.Fatal("inventory output root must be absolute")
	}
	schemaName := fmt.Sprintf("schema%d", version)
	dir, err := os.MkdirTemp(base, "lifecycle-"+schemaName+"-")
	if err != nil {
		t.Fatal("private inventory output unavailable")
	}
	dump, err := ctr06NativeTool("pg_dump")
	if err != nil {
		t.Fatal(err)
	}
	restore, err := ctr06NativeTool("pg_restore")
	if err != nil {
		t.Fatal(err)
	}
	env, err := restorePGEnvironment(url)
	if err != nil {
		t.Fatal(err)
	}
	archive, err := os.OpenFile(filepath.Join(dir, "source.dump"), os.O_RDWR|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		t.Fatal("private inventory archive unavailable")
	}
	defer archive.Close()
	cmd := exec.CommandContext(ctx, dump, "--format=custom")
	cmd.Env = env
	cmd.Stdout = archive
	cmd.Stderr = io.Discard
	if err := cmd.Run(); err != nil {
		t.Fatal("native inventory dump failed")
	}
	if archive.Sync() != nil {
		t.Fatal("inventory dump sync failed")
	}
	raw, err := runRestoreTool(ctx, restore, env, archive, "--list")
	if err != nil {
		t.Fatal(err)
	}
	var inventory []string
	for _, line := range strings.Split(string(raw), "\n") {
		if line == "" || strings.HasPrefix(line, ";") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 7 {
			t.Fatal("ambiguous native object inventory")
		}
		if fields[3] == "ACL" {
			continue
		}
		inventory = append(inventory, strings.Join(fields[3:len(fields)-1], " "))
	}
	sort.Strings(inventory)
	canonical := strings.Join(inventory, "\n") + "\n"
	if os.WriteFile(filepath.Join(dir, schemaName+"-inventory.txt"), []byte(canonical), 0o600) != nil || os.WriteFile(filepath.Join(dir, schemaName+"-catalogue-sha256.txt"), []byte(catalogue+"\n"), 0o600) != nil {
		t.Fatal("inventory evidence write failed")
	}
	t.Logf("Schema%d native facts: catalogue=%s inventorySHA256=%s objects=%d output=%s", version, catalogue, ctr06SHA([]byte(canonical)), len(inventory), dir)
	qualifiedInventory, qualifiedCatalogue, err := backupDefinition(version)
	if err != nil {
		t.Fatal(err)
	}
	if err := ctr06ArchiveInventoryFor(raw, qualifiedInventory, nil); err != nil {
		t.Fatal(err)
	}
	if catalogue != qualifiedCatalogue || canonical != qualifiedInventory {
		t.Fatalf("schema%d native catalogue or inventory changed from its archive qualification", version)
	}
}
