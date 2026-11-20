// SPDX-License-Identifier: AGPL-3.0-only

package migrate

import (
	"errors"
	"slices"
	"strings"

	"github.com/ArcForges/Cloud/center/internal/schema"
)

const hostedEntitlementSchema15MigrationSHA = "6df860b8742148511bf8678a637e157e3deb6fa167cbfe21c30670b33aca471c"

// Native PostgreSQL 18.7 on H-22 at c7c72a8de489da7e4950e6b1f106922c30ec24bf
// retained all 382 schema14 entries and added eight, including both source
// indexes. The 390-entry inventory has SHA256
// 25e7640a458214184796aa72244c7edf25eee10066ecbfb48fc3144ceec1fcd3.
const hostedEntitlementSchema15CatalogueSHA = "9e07e0dbb53ec581f6193d2351d80a3d62408f2ed3eaadeb39355fbb36f8e68e"

const hostedEntitlementSchema15InventoryDelta = `CONSTRAINT entitlement hosted_projection_migration hosted_projection_migration_pkey
FK CONSTRAINT entitlement hosted_projection_migration hosted_projection_grant
FK CONSTRAINT entitlement hosted_projection_migration hosted_projection_term
INDEX entitlement hosted_projection_source_grant
INDEX entitlement hosted_projection_source_term
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
