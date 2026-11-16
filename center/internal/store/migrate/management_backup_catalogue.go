// SPDX-License-Identifier: AGPL-3.0-only

package migrate

import _ "embed"

// The closed schema12 object inventory and definition fingerprint were captured
// from the real PostgreSQL18.7 canonical fresh migration on H-22 at source
// 0aba947d44086350e9fcaca2c9cf0f400ee42912. This is a source oracle, not a
// source archive's claim and not proof that any restore has passed.
//
//go:embed management_schema12_inventory.txt
var managementSchema12Inventory string

const managementSchema12CatalogueSHA = "034aa62eb4aba1396197a096e89b8aad9fa6ff6a904fafdbacda026f2386938c"

const managementSchema12MigrationSHA = "485661afcadbd485d83c660e39c163f7519b7e34a0a67e004203867f363670b3"
