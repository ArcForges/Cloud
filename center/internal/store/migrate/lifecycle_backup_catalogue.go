// SPDX-License-Identifier: AGPL-3.0-only

package migrate

import (
	_ "embed"
	"errors"

	"github.com/ArcForges/Cloud/center/internal/schema"
)

// The closed schema13 inventory and definition fingerprint were captured from
// the real PostgreSQL18.7 canonical fresh migration on H-22 at source
// e62dac9b80bc40e4d364cddff39efce370f9609a. The native artifact contains 382
// non-ACL objects (inventory SHA256 4f3eea6a132861d604ff1a94cf53aa320eef9e6bdec546e0ce43be677fa5531e).
// This is a source oracle, not an archive's claim or a passed restore receipt.
//
//go:embed lifecycle_schema13_inventory.txt
var lifecycleSchema13Inventory string

const lifecycleSchema13CatalogueSHA = "ba0db874e2abf564139893cd5009c14873d9e57ea54a1d381d9e2318fbbb1530"

const lifecycleSchema13MigrationSHA = "1014d5163065ff585e51bc7ef901c44a10356f53f3597c3be122017d41bde946"

func lifecycleBackupDefinition() (string, string, error) {
	build, err := Load(schema.Migrations())
	if err != nil || len(build) < 13 || build[12].SHA256 != lifecycleSchema13MigrationSHA {
		return "", "", errors.New("schema13 backup catalogue qualification does not match this migration build")
	}
	return lifecycleSchema13Inventory, lifecycleSchema13CatalogueSHA, nil
}
