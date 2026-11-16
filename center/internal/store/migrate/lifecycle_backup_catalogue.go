// SPDX-License-Identifier: AGPL-3.0-only

package migrate

import (
	_ "embed"
	"errors"

	"github.com/ArcForges/Cloud/center/internal/schema"
)

// The closed schema13 inventory and definition fingerprint were captured from
// the real PostgreSQL18.7 canonical fresh migration on H-22 at source
// cba8a20b887e266ffe9f359770dc9ec6573f5d3f. The native artifact contains 381
// non-ACL objects (inventory SHA256 0f26a23b7e39b4b4f9ab8f859e647f822e6e39eac41c1383028d484121972578).
// This is a source oracle, not an archive's claim or a passed restore receipt.
//
//go:embed lifecycle_schema13_inventory.txt
var lifecycleSchema13Inventory string

const lifecycleSchema13CatalogueSHA = "5fb4f156d72ed7040d839e76d82028ffb3e769a085e319bf501fbe18871ff30b"

const lifecycleSchema13MigrationSHA = "9936d566131f26aa470bf63494f0167391a76c0824b2a57c99ef01f4dcde5d4e"

func lifecycleBackupDefinition() (string, string, error) {
	build, err := Load(schema.Migrations())
	if err != nil || len(build) < 13 || build[12].SHA256 != lifecycleSchema13MigrationSHA {
		return "", "", errors.New("schema13 backup catalogue qualification does not match this migration build")
	}
	return lifecycleSchema13Inventory, lifecycleSchema13CatalogueSHA, nil
}
