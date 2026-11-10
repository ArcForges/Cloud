// SPDX-License-Identifier: AGPL-3.0-only

package migrate

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"regexp"
	"strings"
	"time"

	"github.com/ArcForges/Cloud/center/internal/config"
	"github.com/ArcForges/Cloud/center/internal/schema"
	"github.com/jackc/pgx/v5"
)

// BackupCaptureReport contains no row, credential or snapshot contents. The
// archive and sidecar are privileged administrator-owned inputs to recovery.
type BackupCaptureReport struct {
	ArchiveSHA256  string `json:"archiveSha256"`
	ArchiveLength  int64  `json:"archiveLength"`
	MetadataSHA256 string `json:"metadataSha256"`
	SchemaVersion  int    `json:"schemaVersion"`
}

func ctr06NativeTool(name string) (string, error) {
	path, err := exec.LookPath(name)
	if err != nil {
		return "", errors.New("a required PostgreSQL backup tool is unavailable")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	command := exec.CommandContext(ctx, path, "--version")
	command.Env = []string{}
	for _, key := range []string{"PATH", "SYSTEMROOT", "WINDIR", "HOME", "TMPDIR", "TEMP", "TMP"} {
		if value := os.Getenv(key); value != "" {
			command.Env = append(command.Env, key+"="+value)
		}
	}
	output, err := command.Output()
	version := regexp.MustCompile(`^` + regexp.QuoteMeta(name) + ` \(PostgreSQL\) 18[.][0-9]+([^\n]*)\n?$`)
	if err != nil || !version.Match(output) {
		return "", errors.New("the PostgreSQL backup tool version is unsupported")
	}
	return path, nil
}

// captureFile creates a new administrator-selected object; a partial output is
// deliberately retained rather than adopting, overwriting or deleting a path.
func captureFile(path string, content io.Reader) error {
	if !filepath.IsAbs(path) {
		return errors.New("backup output paths must be absolute")
	}
	file, syncParent, release, err := openCaptureFile(path)
	if err != nil {
		return errors.New("backup output already exists or could not be created")
	}
	defer release()
	defer file.Close()
	if _, err := io.Copy(file, content); err != nil {
		return errors.New("backup output is incomplete; preserve it for investigation")
	}
	if err := file.Sync(); err != nil {
		return errors.New("backup output could not be synchronized; preserve it for investigation")
	}
	opened, err := file.Stat()
	if err != nil {
		return errors.New("backup output identity could not be checked")
	}
	named, err := os.Lstat(path)
	if err != nil || !opened.Mode().IsRegular() || !named.Mode().IsRegular() || !os.SameFile(opened, named) {
		return errors.New("backup output identity changed; preserve it for investigation")
	}
	if syncParent != nil {
		if err := syncParent(); err != nil {
			return errors.New("backup output directory could not be synchronized; preserve it for investigation")
		}
	}
	return nil
}

// CaptureLogical produces a complete custom-format archive from the exact
// exported snapshot also used to collect the content assertions. SHARE locks
// drain table writers while this snapshot and sequence states are checked.
// The source owner and its local OS account are the trusted administrator.
func CaptureLogical(ctx context.Context, cfg config.Migration, archivePath, metadataPath string) (report BackupCaptureReport, finalErr error) {
	if !filepath.IsAbs(archivePath) || !filepath.IsAbs(metadataPath) || filepath.Clean(archivePath) == filepath.Clean(metadataPath) {
		return report, errors.New("distinct absolute archive and metadata output paths are required")
	}
	dump, err := ctr06NativeTool("pg_dump")
	if err != nil {
		return report, err
	}
	restore, err := ctr06NativeTool("pg_restore")
	if err != nil {
		return report, err
	}
	work, cleanup, err := restoreScratch()
	if err != nil {
		return report, errors.New("a private backup workspace is unavailable")
	}
	defer func() {
		if err := cleanup(); err != nil {
			finalErr = errors.Join(finalErr, errors.New("private backup workspace cleanup failed"))
		}
	}()
	conn, err := restoreConnect(ctx, cfg.URL)
	if err != nil {
		return report, errors.New("the source database could not be reached")
	}
	defer conn.Close(context.Background())
	tx, err := conn.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.RepeatableRead})
	if err != nil {
		return report, errors.New("the source snapshot could not be started")
	}
	defer tx.Rollback(context.Background())
	if _, err := tx.Exec(ctx, "SET LOCAL search_path=pg_catalog; SET LOCAL TIME ZONE 'UTC'"); err != nil {
		return report, errors.New("the source snapshot settings could not be established")
	}
	build, err := Load(schema.Migrations())
	if err != nil || len(build) != 11 {
		return report, errors.New("the supported migration catalogue is unavailable")
	}
	applied, exists, err := ReadApplied(ctx, tx)
	if err != nil || !exists || len(applied) != 11 {
		return report, errors.New("only a supported complete 0011 source can be captured")
	}
	comparison := Compare(build, applied)
	if len(comparison.Pending) != 0 || len(comparison.Problems) != 0 {
		return report, errors.New("the source migration history is incompatible")
	}
	sourceRole, _, err := readyCTR06Admission(ctx, tx, cfg.RuntimeRole)
	if err != nil {
		return report, errors.New("the source runtime floor or admission is untrusted")
	}
	var sourceCluster string
	var serverVersion int
	if err := tx.QueryRow(ctx, "SELECT system_identifier::text,current_setting('server_version_num')::int FROM pg_catalog.pg_control_system()").Scan(&sourceCluster, &serverVersion); err != nil || !ctr06ClusterID.MatchString(sourceCluster) || serverVersion/10000 != TestedMajor {
		return report, errors.New("the source cluster identity or PostgreSQL major is unsupported")
	}
	tables, err := ctr06RequiredTables()
	if err != nil {
		return report, err
	}
	quoted := make([]string, 0, len(tables))
	for _, table := range tables {
		parts := strings.Split(table, ".")
		if len(parts) != 2 {
			return report, errors.New("the supported table inventory is invalid")
		}
		quoted = append(quoted, pgx.Identifier{parts[0], parts[1]}.Sanitize())
	}
	if _, err := tx.Exec(ctx, "LOCK TABLE "+strings.Join(quoted, ",")+" IN SHARE MODE"); err != nil {
		return report, errors.New("source writers could not be drained for a complete backup")
	}
	if checkedRole, _, err := readyCTR06Admission(ctx, tx, sourceRole); err != nil || checkedRole != sourceRole {
		return report, errors.New("the source admission changed during backup preparation")
	}
	var malformedHistory bool
	if err := tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM platform.runtime_credential
 WHERE login_role<>$1::text||'_'||slot OR slot NOT IN ('a','b'))`, sourceRole).Scan(&malformedHistory); err != nil || malformedHistory {
		return report, errors.New("the source credential history does not belong to its checked generation")
	}
	var snapshot string
	if err := tx.QueryRow(ctx, "SELECT pg_catalog.pg_export_snapshot()").Scan(&snapshot); err != nil || !ctr06SnapshotID.MatchString(snapshot) {
		return report, errors.New("the source snapshot could not be exported")
	}
	if err := ctr06CheckSchemaOwnership(ctx, tx); err != nil {
		return report, err
	}
	catalogue, err := ctr06CatalogueSHA(ctx, tx)
	if err != nil || catalogue != ctr06Schema11CatalogueSHA {
		return report, errors.New("the source schema definitions are not the supported catalogue")
	}
	data, err := ctr06SnapshotData(ctx, tx, tables)
	if err != nil {
		return report, err
	}
	objects, err := ctr06SnapshotLargeObjects(ctx, tx)
	if err != nil {
		return report, err
	}
	sequences, err := ctr06SnapshotSequences(ctx, tx)
	if err != nil {
		return report, err
	}
	childEnv, err := restorePGEnvironment(cfg.URL)
	if err != nil {
		return report, err
	}
	archive, err := os.OpenFile(filepath.Join(work, "archive"), os.O_RDWR|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return report, errors.New("the private backup could not be created")
	}
	defer archive.Close()
	command := exec.CommandContext(ctx, dump, "--format=custom", "--snapshot="+snapshot)
	command.WaitDelay = 5 * time.Second
	command.Env, command.Stdout, command.Stderr = childEnv, archive, io.Discard
	if err := command.Run(); err != nil {
		return report, errors.New("the full snapshot backup did not complete")
	}
	if err := archive.Sync(); err != nil {
		return report, errors.New("the private backup could not be synchronized")
	}
	afterSequences, err := ctr06SnapshotSequences(ctx, tx)
	if err != nil || !reflect.DeepEqual(sequences, afterSequences) {
		return report, errors.New("source sequence state changed during capture")
	}
	raw, err := runRestoreTool(ctx, restore, childEnv, archive, "--list")
	if err != nil {
		return report, err
	}
	if err := ctr06ArchiveInventory(raw, objects); err != nil {
		return report, err
	}
	if _, err := restoreList(raw, schema.Schemas); err != nil {
		return report, err
	}
	archiveSequence, err := ctr06ArchiveFacts(ctx, restore, childEnv, archive, build)
	if err != nil || !reflect.DeepEqual(sequences, archiveSequence) {
		return report, errors.New("the backup history or sequence state does not match the source")
	}
	if err := ctr06ArchiveIntegrity(ctx, restore, childEnv, archive); err != nil {
		return report, err
	}
	info, err := archive.Stat()
	if err != nil || info.Size() <= 0 {
		return report, errors.New("the private backup is incomplete")
	}
	if _, err := archive.Seek(0, io.SeekStart); err != nil {
		return report, errors.New("the private backup cannot be read")
	}
	digester := sha256.New()
	if _, err := io.Copy(digester, archive); err != nil {
		return report, errors.New("the private backup cannot be hashed")
	}
	migrations := make([]ctr06BackupMigration, 0, len(applied))
	for _, migration := range applied {
		migrations = append(migrations, ctr06BackupMigration{Version: migration.Version, Name: migration.Name, SHA256: migration.SHA256})
	}
	meta := ctr06BackupMetadata{Version: ctr06BackupMetadataVersion, Procedure: "checked-full-pg-dump-exported-snapshot-v1",
		ArchiveLength: info.Size(), ArchiveSHA256: hex.EncodeToString(digester.Sum(nil)), ArchiveTOCSHA256: ctr06SHA(raw),
		SourceCluster: sourceCluster, SourceSnapshot: snapshot, SourceRuntimeRole: sourceRole, SourceServerMajor: serverVersion / 10000, SourceSchemaVersion: 11,
		SourceMigrations: migrations, SourceCatalogueSHA256: catalogue, Tables: data, Sequences: sequences, LargeObjects: objects}
	if err := ctr06ValidateMetadata(meta, build); err != nil {
		return report, err
	}
	encoded, err := json.MarshalIndent(meta, "", "  ")
	if err != nil || len(encoded) > ctr06BackupMetadataMax {
		return report, errors.New("backup metadata could not be encoded")
	}
	encoded = append(encoded, '\n')
	if _, err := archive.Seek(0, io.SeekStart); err != nil {
		return report, errors.New("the private backup cannot be read")
	}
	if err := captureFile(archivePath, archive); err != nil {
		return report, err
	}
	if err := captureFile(metadataPath, strings.NewReader(string(encoded))); err != nil {
		return report, err
	}
	return BackupCaptureReport{ArchiveSHA256: meta.ArchiveSHA256, ArchiveLength: meta.ArchiveLength,
		MetadataSHA256: ctr06SHA(encoded), SchemaVersion: 11}, nil
}
