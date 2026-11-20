// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"context"
	"path/filepath"
	"time"

	"github.com/ArcForges/Cloud/center/internal/pgtest"
	"github.com/ArcForges/Cloud/center/internal/platform"
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
	target := host03Database{name: source.name + "_restored", runtimeRole: source.name + "_restored_runtime",
		migrationURL: source.migrationURL, archiveSHA: archiveSHA, metadataSHA: metadataSHA}
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
