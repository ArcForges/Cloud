// SPDX-License-Identifier: AGPL-3.0-only

package migrate

import (
	"errors"
	"slices"
	"strings"

	"github.com/ArcForges/Cloud/center/internal/schema"
)

const hostedCommerceSchema16MigrationSHA = "92de4d5b3b4e352e64a442304ea3d6de7fb4316d09d5a2f26bfeee209b4c8b85"
const hostedCommerceSchema16CatalogueSHA = ""
const hostedCommerceSchema16InventoryDelta = ""

func hostedCommerceBackupDefinition() (string, string, error) {
	previous, _, err := hostedEntitlementBackupDefinition()
	if err != nil {
		return "", "", err
	}
	build, err := Load(schema.Migrations())
	if err != nil || len(build) < 16 || build[15].Name != "0016_hosted_web_commerce.sql" ||
		build[15].SHA256 != hostedCommerceSchema16MigrationSHA || len(hostedCommerceSchema16CatalogueSHA) != 64 {
		return "", "", errors.New("schema16 backup catalogue qualification does not match this migration build")
	}
	objects := strings.Split(strings.TrimSuffix(previous, "\n")+"\n"+hostedCommerceSchema16InventoryDelta, "\n")
	slices.Sort(objects)
	return strings.Join(objects, "\n") + "\n", hostedCommerceSchema16CatalogueSHA, nil
}
