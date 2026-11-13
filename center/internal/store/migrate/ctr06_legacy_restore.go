// SPDX-License-Identifier: AGPL-3.0-only

package migrate

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"reflect"
	"strings"
	"time"

	"github.com/ArcForges/Cloud/center/internal/bridgeproof"
	"github.com/ArcForges/Cloud/center/internal/config"
	"github.com/ArcForges/Cloud/center/internal/schema"
	"github.com/jackc/pgx/v5"
)

// The delivered CTR05 baseline and the compatible bridge have byte-identical
// 0001–0010 migrations. A source claim is provenance, not promotion proof;
// the archive itself must still pass every supported history and data check.
const ctr06DeliveredCTR05Revision = "ffc03636ca0c7049fddf5fad733d0f98c53c3a6d"

// LegacyProvenance is a privileged administrator's documented assertion of
// the known full-dump procedure and custody, not a database or promotion
// authority. Original snapshot identifiers and source row counts remain
// explicitly unrecorded; the manager observes only archive and target facts.
type LegacyProvenance struct {
	Version           string `json:"version"`
	ArchiveLength     int64  `json:"archiveLength"`
	ArchiveSHA256     string `json:"archiveSha256"`
	SourceSchema      int    `json:"sourceSchema"`
	SourceRevision    string `json:"sourceRevision"`
	SourceRuntimeRole string `json:"sourceRuntimeRole"`
	DumpProcedure     string `json:"dumpProcedure"`
	DumpMajor         int    `json:"dumpMajor"`
	AttestedBy        string `json:"attestedBy"`
	CustodyEvidence   string `json:"custodyEvidence"`
}

func ctr06ReadLegacyProvenance(path, digest, archiveSHA, role string) (LegacyProvenance, error) {
	var provenance LegacyProvenance
	if !filepath.IsAbs(path) || !restoreDigest.MatchString(digest) {
		return provenance, errors.New("an absolute legacy provenance path and digest are required")
	}
	file, err := os.Open(path)
	if err != nil {
		return provenance, errors.New("legacy provenance is unavailable")
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Size() <= 0 || info.Size() > ctr06BackupMetadataMax {
		return provenance, errors.New("legacy provenance is not a bounded regular file")
	}
	data, err := io.ReadAll(io.LimitReader(file, ctr06BackupMetadataMax+1))
	if err != nil || int64(len(data)) != info.Size() || ctr06SHA(data) != digest {
		return provenance, errors.New("legacy provenance does not match its expected digest")
	}
	if err := ctr06UniqueJSON(data); err != nil {
		return provenance, errors.New("legacy provenance is ambiguous")
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&provenance); err != nil || decoder.Decode(new(any)) != io.EOF {
		return LegacyProvenance{}, errors.New("legacy provenance is malformed")
	}
	administrator, err := user.Current()
	if err != nil || administrator.Username == "" || provenance.AttestedBy != administrator.Username ||
		provenance.Version != "arcforges-legacy-full-dump-provenance-v1" ||
		provenance.ArchiveLength <= 0 || provenance.ArchiveSHA256 != archiveSHA || !restoreDigest.MatchString(archiveSHA) ||
		provenance.SourceSchema != 10 || (provenance.SourceRevision != bridgeproof.BridgeRevision && provenance.SourceRevision != ctr06DeliveredCTR05Revision) ||
		provenance.SourceRuntimeRole != role || ValidRoleName(role) != nil || provenance.DumpMajor != TestedMajor ||
		provenance.DumpProcedure != "pg_dump --format=custom, unfiltered full database" ||
		len(strings.TrimSpace(provenance.CustodyEvidence)) < 32 || len(provenance.CustodyEvidence) > 4096 {
		return LegacyProvenance{}, errors.New("legacy full-dump provenance or authenticated administrator attestation is insufficient")
	}
	return provenance, nil
}

// CTR06RestoreIssuer issues only the temporary bridge credential for the
// supplied in-process role identities. It is not a readiness or migration
// predicate: the manager independently runs and stops the verified server,
// checks the database graph, and makes the 0011 retirement decision itself.
type CTR06RestoreIssuer func(context.Context, *pgx.Conn, []Migration, PreparedBridgeRoles) (string, error)

type LegacyRestoreReport struct {
	RestoreReport
	SourceSnapshot      string `json:"sourceSnapshot"`
	SourceRowCounts     string `json:"sourceRowCounts"`
	ArchiveObservation  string `json:"archiveObservation"`
	LegacyProvenanceSHA string `json:"legacyProvenanceSha256"`
}

func RestoreLegacy(ctx context.Context, cfg config.Migration, archivePath, expected, provenancePath, provenanceDigest, runner string, issuer CTR06RestoreIssuer) (report LegacyRestoreReport, finalErr error) {
	if err := RequireCTR06SecurityBridge(); err != nil {
		return report, err
	}
	archiveCommitted, admissionReady := false, false
	defer func() {
		if finalErr != nil && archiveCommitted && !admissionReady {
			finalErr = fmt.Errorf("the legacy archive transaction committed; destination admission outcome UNKNOWN; preserve and inspect it: %w", finalErr)
		}
	}()
	if cfg.Mode != config.SelfHosted || cfg.CTR06BridgeExecutable == "" || cfg.CTR06ProofFile != "" || issuer == nil {
		return report, errors.New("legacy recovery requires the verified self-hosted bridge manager")
	}
	if err := ValidRoleName(cfg.RuntimeRole); err != nil {
		return report, err
	}
	maintenanceURL, err := url.Parse(cfg.Maintenance)
	if err != nil || strings.TrimPrefix(maintenanceURL.Path, "/") == cfg.Database {
		return report, errors.New("a distinct maintenance database and fresh destination are required")
	}
	provenance, err := ctr06ReadLegacyProvenance(provenancePath, provenanceDigest, expected, cfg.RuntimeRole)
	if err != nil {
		return report, err
	}
	build, err := Load(schema.Migrations())
	if err != nil || len(build) != 11 || build[9].Name != "0010_fleet_routed_call.sql" || build[10].Name != "0011_fleet_routed_files.sql" {
		return report, errors.New("the supported migration build is unavailable")
	}
	bridge, err := openLocalBridge(cfg.CTR06BridgeExecutable)
	if err != nil {
		return report, errors.New("the verified native legacy bridge is unavailable")
	}
	defer bridge.close()
	tool, err := ctr06NativeTool("pg_restore")
	if err != nil {
		return report, err
	}
	work, cleanup, err := restoreScratch()
	if err != nil {
		return report, errors.New("a private legacy restore workspace is unavailable")
	}
	defer func() {
		if err := cleanup(); err != nil {
			finalErr = errors.Join(finalErr, errors.New("private legacy restore workspace cleanup failed"))
		}
	}()
	archive, err := copyRestoreBackup(archivePath, expected, work)
	if err != nil {
		return report, err
	}
	defer archive.Close()
	info, err := archive.Stat()
	if err != nil || info.Size() != provenance.ArchiveLength {
		return report, errors.New("legacy archive length differs from its provenance")
	}
	env, err := restorePGEnvironment(cfg.URL)
	if err != nil {
		return report, err
	}
	raw, err := runRestoreTool(ctx, tool, env, archive, "--list")
	if err != nil {
		return report, err
	}
	objects, blobListing, err := ctr06LegacyBlobEntries(raw)
	if err != nil {
		return report, err
	}
	if err := ctr06ArchiveInventoryFor(raw, ctr06Schema10Inventory, objects); err != nil {
		return report, err
	}
	sequences, err := ctr06ArchiveFacts(ctx, tool, env, archive, build[:10])
	if err != nil {
		return report, err
	}
	if err := ctr06ArchiveIntegrity(ctx, tool, env, archive); err != nil {
		return report, err
	}
	tables, err := ctr06LegacyArchiveTables(ctx, tool, env, archive)
	if err != nil {
		return report, err
	}
	listPath := filepath.Join(work, "restore-list")
	if err := os.WriteFile(listPath, blobListing, 0o600); err != nil {
		return report, errors.New("the private large-object observation list could not be written")
	}
	objects, err = ctr06LegacyArchiveLargeObjects(ctx, tool, env, archive, listPath, objects)
	if err != nil {
		return report, err
	}
	// No destination or role exists until all evidence and archive checks above
	// have succeeded. On any later failure resources remain for inspection.
	conn, err := createRestoreTarget(ctx, cfg)
	if err != nil {
		return report, err
	}
	defer conn.Close(context.Background())
	var owner string
	if err := conn.QueryRow(ctx, "SELECT current_user").Scan(&owner); err != nil || owner == "" {
		return report, errors.New("the destination owner is unavailable")
	}
	if _, err := runRestoreTool(ctx, tool, env, archive, "--single-transaction", "--exit-on-error", "--no-owner", "--no-acl", "--role="+owner, "--dbname="+cfg.Database); err != nil {
		return report, ctr06RestoreChildFailure(conn, "isolated")
	}
	archiveCommitted = true
	if _, err := conn.Exec(ctx, "SET search_path=pg_catalog; SET TIME ZONE 'UTC'"); err != nil {
		return report, errors.New("the legacy target inspection settings are unavailable")
	}
	applied, exists, err := ReadApplied(ctx, conn)
	if err != nil || !exists || len(applied) != 10 {
		return report, errors.New("the restored legacy history is incomplete")
	}
	comparison := Compare(build[:10], applied)
	if len(comparison.Problems) != 0 || len(comparison.Pending) != 0 {
		return report, errors.New("the restored legacy history is incompatible")
	}
	if err := ctr06CheckSchemaOwnership(ctx, conn); err != nil {
		return report, err
	}
	catalogue, err := ctr06CatalogueSHA(ctx, conn)
	if err != nil || catalogue != ctr06Schema10CatalogueSHA {
		return report, errors.New("the restored legacy catalogue differs from the supported schema")
	}
	if err := ctr06VerifyLegacyTables(ctx, conn, tables); err != nil {
		return report, err
	}
	actualSequences, err := ctr06SnapshotSequences(ctx, conn)
	if err != nil || !reflect.DeepEqual(sequences, actualSequences) {
		return report, errors.New("the restored legacy sequence differs from the archive")
	}
	actualObjects, err := ctr06SnapshotLargeObjects(ctx, conn)
	if err != nil || !reflect.DeepEqual(objects, actualObjects) {
		return report, errors.New("the restored legacy large objects differ from the archive")
	}
	roles, err := reserveLegacyRestoreRoles(ctx, conn, cfg.RuntimeRole)
	if err != nil {
		return report, err
	}
	if err := checkLegacyRestoreIsolation(ctx, conn, cfg.RuntimeRole, roles); err != nil {
		return report, err
	}
	// The old privileged tool is used only against this isolated schema-10
	// destination, with the exact already-opened verified bridge object.
	legacy := exec.CommandContext(ctx, bridge.path, "migrate")
	legacy.ExtraFiles = bridge.extraFiles
	legacy.Env = []string{config.EnvMode + "=self-hosted", config.EnvMigrationDatabaseURL + "=" + cfg.URL, config.EnvRuntimeRole + "=" + cfg.RuntimeRole}
	if value := os.Getenv("SystemRoot"); value != "" {
		legacy.Env = append(legacy.Env, "SystemRoot="+value)
	}
	legacy.Stdout, legacy.Stderr = io.Discard, io.Discard
	legacy.WaitDelay = 5 * time.Second
	if err := legacy.Run(); err != nil {
		return report, errors.New("verified legacy administration failed; preserve the isolated destination")
	}
	if err := checkLegacyRestoreIsolation(ctx, conn, cfg.RuntimeRole, roles); err != nil {
		return report, err
	}
	capability, err := newRestoreCapability(ctx, conn, expected, provenanceDigest)
	if err != nil {
		return report, errors.New("the legacy destination recovery identity could not be established")
	}
	defer capability.destroy()
	options := Options{Runner: runner, RuntimeRole: cfg.RuntimeRole, LockTimeout: cfg.LockTimeout, localRestore: capability}
	result, err := applySelfHostedCTR06(ctx, conn, build, options, bridge, func(ctx context.Context, roles PreparedBridgeRoles) (string, error) {
		return issuer(ctx, conn, build, roles)
	})
	if err != nil || result.State != StateCurrent || result.Version != 11 || result.Grants != "" {
		return report, errors.New("legacy bridge promotion or atomic 0011 quarantine did not complete; target outcome UNKNOWN; preserve it")
	}
	finalRole := result.RuntimeRole
	if err := checkRestoreIsolation(ctx, conn, finalRole); err != nil {
		return report, err
	}
	floor, _, err := restoreSecuritySnapshot(ctx, conn)
	if err != nil {
		return report, err
	}
	verification, err := json.Marshal(struct {
		TOCSHA256 string                   `json:"tocSha256"`
		Tables    []ctr06ArchiveTable      `json:"archiveTables"`
		Sequences []ctr06BackupSequence    `json:"archiveSequences"`
		Objects   []ctr06BackupLargeObject `json:"archiveLargeObjects"`
	}{ctr06SHA(raw), tables, sequences, objects})
	if err != nil {
		return report, errors.New("legacy archive observations could not be bound")
	}
	receipt, err := finalizeCTR06Restore(ctx, conn, finalRole, cfg.RuntimeRole, ctr06SHA(verification), capability)
	if err != nil {
		return report, errors.New("legacy recovery readiness outcome UNKNOWN; inspect the target receipt")
	}
	admissionReady = true
	status, err := Inspect(ctx, conn, build)
	if err != nil || status.State != StateCurrent || len(status.Pending) != 0 || status.RuntimeRole != finalRole || status.RestoreReceipt != receipt {
		return report, errors.New("legacy readiness committed but could not be confirmed; inspect the receipt")
	}
	options.localRestore, options.RuntimeRole = nil, finalRole
	reconciled, err := Apply(ctx, conn, build, options)
	if err != nil || reconciled.State != StateCurrent || len(reconciled.Ran) != 0 || reconciled.Grants != "reconciled" {
		return report, errors.New("legacy readiness committed but grants could not be reconciled; inspect the receipt")
	}
	if err := checkRestoreIsolation(ctx, conn, finalRole); err != nil {
		return report, err
	}
	return LegacyRestoreReport{RestoreReport: RestoreReport{Database: cfg.Database, RuntimeRole: finalRole,
		SourceBackupSHA256: expected, TargetFloorSHA256: ctr06SHA([]byte(floor)), SchemaVersion: 11, RestoreReceipt: receipt},
		SourceSnapshot: "not-recorded", SourceRowCounts: "not-recorded", ArchiveObservation: "archive-copy-and-target-verified", LegacyProvenanceSHA: provenanceDigest}, nil
}

// These roles are created, identified and linked in the same call, never
// adopted by name. They are passwordless NOLOGIN placeholders for the old
// archive's slot history; no recovered credential can log in as them.
func reserveLegacyRestoreRoles(ctx context.Context, conn *pgx.Conn, group string) ([]uint32, error) {
	roles := []string{group, group + "_a", group + "_b"}
	oids := make([]uint32, len(roles))
	err := pgx.BeginFunc(ctx, conn, func(tx pgx.Tx) error {
		for _, role := range roles {
			if _, err := tx.Exec(ctx, "CREATE ROLE "+pgx.Identifier{role}.Sanitize()+" NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS"); err != nil {
				return errors.New("a legacy restore role is occupied or cannot be reserved")
			}
		}
		for _, role := range roles[1:] {
			if _, err := tx.Exec(ctx, "GRANT "+pgx.Identifier{group}.Sanitize()+" TO "+pgx.Identifier{role}.Sanitize()); err != nil {
				return errors.New("legacy placeholder membership could not be established")
			}
		}
		for i, role := range roles {
			if err := tx.QueryRow(ctx, "SELECT oid FROM pg_roles WHERE rolname=$1", role).Scan(&oids[i]); err != nil || oids[i] == 0 {
				return errors.New("a legacy restore role identity is unavailable")
			}
		}
		return nil
	})
	return oids, err
}

func checkLegacyRestoreIsolation(ctx context.Context, conn *pgx.Conn, group string, oids []uint32) error {
	if len(oids) != 3 {
		return errors.New("legacy restore role identities are incomplete")
	}
	for i, role := range []string{group, group + "_a", group + "_b"} {
		if err := RequirePlainRole(ctx, conn, role, false); err != nil {
			return errors.New("a legacy restore role is not a passwordless disabled placeholder")
		}
		var same bool
		if err := conn.QueryRow(ctx, "SELECT EXISTS(SELECT 1 FROM pg_roles WHERE oid=$1::oid AND rolname=$2)", oids[i], role).Scan(&same); err != nil || !same {
			return errors.New("a legacy restore role identity changed")
		}
	}
	var unsafe bool
	err := conn.QueryRow(ctx, `WITH RECURSIVE reach(actor,memberof) AS (
 SELECT oid,oid FROM pg_roles UNION SELECT reach.actor,m.roleid FROM reach JOIN pg_auth_members m ON m.member=reach.memberof
), owner AS (SELECT oid FROM pg_roles WHERE rolname=current_user)
SELECT EXISTS(SELECT 1 FROM platform.runtime_credential WHERE login_role<>$1::text||'_'||slot OR slot NOT IN ('a','b'))
 OR NOT pg_has_role($3::oid,$2::oid,'MEMBER') OR NOT pg_has_role($4::oid,$2::oid,'MEMBER')
 OR EXISTS(SELECT 1 FROM pg_auth_members m,owner WHERE m.roleid=ANY($5::oid[]) AND m.member<>owner.oid AND NOT m.member=ANY($5::oid[]))
 OR EXISTS(SELECT 1 FROM pg_auth_members m WHERE m.member=ANY($5::oid[]) AND NOT (m.member IN ($3::oid,$4::oid) AND m.roleid=$2::oid))
 OR EXISTS(SELECT 1 FROM pg_stat_activity a JOIN pg_roles r ON r.oid=a.usesysid
   WHERE a.datname=current_database() AND a.pid<>pg_backend_pid() AND NOT r.rolsuper)
 OR EXISTS(SELECT 1 FROM pg_database d,aclexplode(coalesce(d.datacl,acldefault('d',d.datdba))) a
   WHERE d.datname=current_database() AND a.grantee=0 AND a.privilege_type IN ('CONNECT','TEMPORARY'))
 OR EXISTS(SELECT 1 FROM pg_roles actor JOIN reach r ON r.actor=actor.oid JOIN pg_roles reachable ON reachable.oid=r.memberof,owner
   WHERE actor.oid<>owner.oid AND NOT actor.oid=ANY($5::oid[]) AND NOT actor.rolsuper AND actor.rolname !~ '^pg_'
   AND (reachable.oid=owner.oid OR reachable.rolsuper OR
        has_table_privilege(reachable.oid,'fleet.routed_call','INSERT,UPDATE,DELETE,TRUNCATE') OR
        has_table_privilege(reachable.oid,'fleet.hub_lease','INSERT,UPDATE,DELETE,TRUNCATE')))`,
		group, oids[0], oids[1], oids[2], oids).Scan(&unsafe)
	if err != nil || unsafe {
		return errors.New("the legacy destination has an unknown writer, connection, role path or history")
	}
	return nil
}
