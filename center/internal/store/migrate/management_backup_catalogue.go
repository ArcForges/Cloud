// SPDX-License-Identifier: AGPL-3.0-only

package migrate

import _ "embed"

// The closed schema12 object inventory and definition fingerprint were captured
// from the real PostgreSQL18.7 canonical fresh migration on H-22 at source
// c0d9a62cdb200f43d291f362a11a80983f4c7089. This is a source oracle, not a
// source archive's claim and not proof that any restore has passed.
//
//go:embed management_schema12_inventory.txt
var managementSchema12Inventory string

const managementSchema12CatalogueSHA = "813ca9708dcfcf7ef79a3aeed2ef0c5b7cfb5703ca11819f305b9e6fd0f91501"

const managementSchema12MigrationSHA = "69c5496cb533c1b5edd56aaab3cce65c04608874ad29646b84df72d8321d85e5"
