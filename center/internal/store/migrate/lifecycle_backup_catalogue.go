// SPDX-License-Identifier: AGPL-3.0-only

package migrate

import "errors"

// Schema13 admission is deliberately closed until its native PostgreSQL18
// inventory and catalogue have been captured and independently reviewed.
// TestLifecycleInventoryForBackup produces candidate facts; an archive's own
// claimed inventory is never a substitute for the checked-in source oracle.
func lifecycleBackupDefinition() (string, string, error) {
	return "", "", errors.New("schema13 native backup catalogue has not been qualified")
}
