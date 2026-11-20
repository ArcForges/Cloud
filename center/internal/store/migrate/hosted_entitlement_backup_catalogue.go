// SPDX-License-Identifier: AGPL-3.0-only

package migrate

import (
	"errors"
	"slices"
	"strings"

	"github.com/ArcForges/Cloud/center/internal/schema"
)

const hostedEntitlementSchema15MigrationSHA = "277581578fdac6293e470dc31e11e19100623ac3bcb902e3ccc98dbe5a437d2c"

// Native PostgreSQL 18.7 on H-22 at a260d1a40ce90403e98e4765c52ed8b7c0ae58fc
// retained all 382 schema14 entries and added six. The 388-entry inventory
// has SHA256 3fa39f5c851367e7046a4e34e56a8cb0b4c2154e9b6a830ac07881d2d985b6d8.
const hostedEntitlementSchema15CatalogueSHA = "80ac40cf787937de93d659c32619d98e1d6e6896e24fcc4285dcfbb16def1ae8"

const hostedEntitlementSchema15InventoryDelta = `CONSTRAINT entitlement hosted_projection_migration hosted_projection_migration_pkey
FK CONSTRAINT entitlement hosted_projection_migration hosted_projection_grant
FK CONSTRAINT entitlement hosted_projection_migration hosted_projection_term
TABLE DATA entitlement hosted_projection_migration
TABLE entitlement hosted_projection_migration
TRIGGER entitlement hosted_projection_migration hosted_projection_append_only`

func hostedEntitlementBackupDefinition() (string, string, error) {
	previous, _, err := remoteObservationBackupDefinition()
	if err != nil {
		return "", "", err
	}
	build, err := Load(schema.Migrations())
	if err != nil || len(build) < 15 || build[14].Name != "0015_hosted_entitlement_projection.sql" ||
		build[14].SHA256 != hostedEntitlementSchema15MigrationSHA {
		return "", "", errors.New("schema15 backup catalogue qualification does not match this migration build")
	}
	objects := strings.Split(strings.TrimSuffix(previous, "\n")+"\n"+hostedEntitlementSchema15InventoryDelta, "\n")
	slices.Sort(objects)
	return strings.Join(objects, "\n") + "\n", hostedEntitlementSchema15CatalogueSHA, nil
}
