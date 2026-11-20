// SPDX-License-Identifier: AGPL-3.0-only

package migrate

import (
	"errors"
	"slices"
	"strings"

	"github.com/ArcForges/Cloud/center/internal/schema"
)

const hostedCommerceSchema16MigrationSHA = "71c2c998610787a596f00e121532c74b7480c5d3de383b07efe442f992305d5c"
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
