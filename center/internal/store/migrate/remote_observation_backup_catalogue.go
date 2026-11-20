// SPDX-License-Identifier: AGPL-3.0-only

package migrate

import (
	"errors"

	"github.com/ArcForges/Cloud/center/internal/schema"
)

// The native PostgreSQL 18.7 qualification on H-22 from source
// 9132ca6824c1f7633173fc723a13bf72f334226a found the same 382 inventory
// entries as schema13 and a distinct catalogue fingerprint for schema14.
const remoteObservationSchema14CatalogueSHA = "3d4391ad1ed26799407c5dbced06019f44d019ad75219eb76023e0ba10e7b15e"

const remoteObservationSchema14MigrationSHA = "30b42ab4ff2513fdf7c94b21d7fa70f6352fd775d8872ad2eb1407130446f7d0"

func remoteObservationBackupDefinition() (string, string, error) {
	inventory, _, err := lifecycleBackupDefinition()
	if err != nil {
		return "", "", err
	}
	build, err := Load(schema.Migrations())
	if err != nil || len(build) < 14 || build[13].Name != "0014_management_remote_observations.sql" ||
		build[13].SHA256 != remoteObservationSchema14MigrationSHA {
		return "", "", errors.New("schema14 backup catalogue qualification does not match this migration build")
	}
	return inventory, remoteObservationSchema14CatalogueSHA, nil
}
