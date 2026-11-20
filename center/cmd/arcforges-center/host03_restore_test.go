// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"context"
	"path/filepath"
	"strings"
	"time"

	"github.com/ArcForges/Cloud/center/internal/pgtest"
	"github.com/ArcForges/Cloud/center/internal/platform"
	"github.com/ArcForges/Cloud/center/internal/store/migrate"
)

func (f *host03Fixture) restore(source host03Database, first host03Enrollment) host03Database {
	f.t.Helper()
	archive, metadata := filepath.Join(f.root, "source.pgdmp"), filepath.Join(f.root, "source-metadata.json")
	source.migrationURL = pgtest.WithDatabase(f.t, source.migrationURL, source.name)
	captured := f.command(source, "admin", "backup-logical", "--archive", archive, "--metadata", metadata)
	archiveSHA, metadataSHA := host03FileDigest(f.t, archive), host03FileDigest(f.t, metadata)
	if captured["archiveSha256"] != archiveSHA || captured["metadataSha256"] != metadataSHA {
		f.t.Fatal("the protected backup receipt did not bind the exact produced archive and metadata")
	}
	targetName := source.name + "_restored"
	target := host03Database{name: targetName, runtimeRole: targetName + "_rt",
		migrationURL: source.migrationURL, archiveSHA: archiveSHA, metadataSHA: metadataSHA}
	if migrate.ValidRoleName(target.runtimeRole) != nil {
		f.t.Fatal("the fixture did not generate a target runtime group name within the admitted bounds")
	}
	f.t.Cleanup(func() { pgtest.Drop(f.t, target.name) })
	restored := f.command(target, "admin", "restore-logical-backup", "--archive", archive, "--sha256", archiveSHA,
		"--metadata", metadata, "--metadata-sha256", metadataSHA)
	target.restoreReceipt, _ = restored["restoreReceipt"].(string)
	if restored["database"] != target.name || restored["runtimeRole"] != target.runtimeRole || restored["sourceBackupSha256"] != archiveSHA ||
		restored["schemaVersion"] != captured["schemaVersion"] || !host03Hex(target.restoreReceipt, 32) {
		f.t.Fatal("the exact logical restore did not produce a separate admitted database receipt")
	}
	target.migrationURL = pgtest.WithDatabase(f.t, target.migrationURL, target.name)
	status := f.command(target, "migrate", "status")
	if status["state"] != "current" || status["restoreReceipt"] != target.restoreReceipt {
		f.t.Fatal("read-only migrate status did not independently recover the admitted target receipt")
	}
	db := pgtest.Connect(f.t, target.migrationURL)
	ctx, cancel := context.WithTimeout(f.t.Context(), 6*time.Second)
	defer cancel()
	var revoked, disconnected bool
	if err := db.QueryRow(ctx, `SELECT p.revoked_at IS NOT NULL,n.connection_id IS NULL
FROM management.node_protocol p JOIN fleet.node n USING (enrollment_id) WHERE p.enrollment_id=$1 AND p.node_id=$2`,
		first.enrollment, first.node).Scan(&revoked, &disconnected); err != nil || !revoked || !disconnected {
		f.t.Fatal("the restored database retained source enrollment history but failed to revoke source protocol or live connection authority")
	}
	return f.rotate(target)
}

// The tool emits its existing classifications to stderr. Record only fixed
// labels for known phases so archive paths, SQL text and credentials cannot
// cross from command stderr to shared fixture output.
func host03RestoreDiagnostic(stderr string) string {
	for _, known := range []struct{ text, phase string }{
		{"restore configuration was refused", "configuration_refused"},
		{"runtime role name", "role_name_refused"},
		{"distinct maintenance database", "maintenance_endpoint_refused"},
		{"unsupported backup schema", "schema_refused"},
		{"backup metadata", "metadata_refused"},
		{"required PostgreSQL backup tool", "native_tool_unavailable"},
		{"private restore workspace", "private_workspace_unavailable"},
		{"backup inventory", "archive_inventory_mismatch"},
		{"archive history or sequence assertions", "archive_assertion_mismatch"},
		{"archive is corrupt or unreadable", "archive_unreadable"},
		{"maintenance database could not be reached", "maintenance_database_unavailable"},
		{"destination or a runtime role already exists", "target_already_exists"},
		{"migration owner has unknown members", "target_migration_role_shared"},
		{"destination ACL is not isolated", "target_acl_not_isolated"},
		{"destination could not be", "target_creation_or_connection_unconfirmed"},
		{"fresh destination admission outcome", "target_fresh_admission_uncertain"},
		{"restore child did not complete", "native_restore_child_uncertain"},
		{"the restored security schema", "restored_security_mismatch"},
		{"destination has an unknown writer", "target_writer_or_connection_unconfirmed"},
		{"restored table data does not match", "restored_snapshot_mismatch"},
		{"restored catalogue", "restored_catalogue_mismatch"},
		{"restored migration history", "restored_history_mismatch"},
		{"restored sequence", "restored_sequence_mismatch"},
		{"verified restore could not commit readiness", "restore_admission_uncertain"},
		{"restore readiness committed", "restore_admission_recheck_unconfirmed"},
	} {
		if strings.Contains(stderr, known.text) {
			return known.phase
		}
	}
	return "unclassified"
}

func (f *host03Fixture) protocol(db host03Database, value *host03Enrollment) platform.ID {
	f.t.Helper()
	conn := pgtest.Connect(f.t, pgtest.WithDatabase(f.t, db.migrationURL, db.name))
	ctx, cancel := context.WithTimeout(f.t.Context(), 6*time.Second)
	defer cancel()
	var protocol, node platform.ID
	if err := conn.QueryRow(ctx, `SELECT p.protocol_epoch,p.node_id
FROM management.node_protocol p JOIN fleet.node n USING (enrollment_id)
WHERE p.enrollment_id=$1 AND p.protocol_major=2 AND p.revoked_at IS NULL AND n.connection_id IS NOT NULL`,
		value.enrollment).Scan(&protocol, &node); err != nil || node == (platform.ID{}) || protocol == (platform.ID{}) {
		f.t.Fatal("the actual online V2 connection did not have its exact PostgreSQL enrollment and protocol")
	}
	if value.node != (platform.ID{}) && node != value.node {
		f.t.Fatal("the durable enrollment changed native Node identity")
	}
	value.node = node
	return protocol
}
