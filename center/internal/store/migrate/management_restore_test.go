// SPDX-License-Identifier: AGPL-3.0-only

package migrate

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"testing"
	"time"

	"github.com/ArcForges/Cloud/center/internal/config"
	"github.com/ArcForges/Cloud/center/internal/management"
	"github.com/ArcForges/Cloud/center/internal/pgtest"
	"github.com/ArcForges/Cloud/center/internal/platform"
	"github.com/ArcForges/Cloud/center/internal/store"
)

func TestManagementBackupRestoreRetainsUnknownAndRenewsTargetAdmission(t *testing.T) {
	testManagementBackupRestore(t, 12)
}

func TestLifecycleBackupRestoreRevokesAuthorityAndRetainsUnknown(t *testing.T) {
	testManagementBackupRestore(t, 13)
}

func TestRemoteObservationBackupRestoreRetainsIdentityAndUncertainty(t *testing.T) {
	testManagementBackupRestore(t, 14)
}

func TestHostedEntitlementBackupRestoreRetainsOriginalProjection(t *testing.T) {
	testManagementBackupRestore(t, 15)
}

func TestHostedCommerceBackupRestoreRetainsProviderEvidence(t *testing.T) {
	testManagementBackupRestore(t, 16)
}

func testManagementBackupRestore(t *testing.T, version int) {
	t.Helper()
	ctx := context.Background()
	url, name := pgtest.Database(t)
	owner := pgtest.Connect(t, url)
	group := name + "_runtime"
	build := managementBuild(t)
	if version >= 13 {
		build = centerBuild(t)[:version]
	}
	var hosted hostedProjectionFixture
	if version == 15 {
		if _, err := Apply(ctx, owner, build[:14], Options{Runner: "isolated-schema14-projection-source", RuntimeRole: group}); err != nil {
			t.Fatal(err)
		}
		hosted = seedHostedProjection(t, owner, seedNamespaceFixture(t, owner).account)
	}
	if _, err := Apply(ctx, owner, build, Options{Runner: "isolated-schema12-backup-source", RuntimeRole: group}); err != nil {
		t.Fatal(err)
	}
	if version == 15 {
		hosted.check(t, owner, group)
	}
	var commerceAccount platform.ID
	var commerceEvidence []ctr06BackupTable
	commerceTables := []string{
		"commerce.provider_environment", "commerce.customer", "commerce.purchase", "commerce.checkout",
		"commerce.subscription", "commerce.renewal", "commerce.provider_event", "commerce.settled_period", "commerce.billing_entry",
	}
	if version == 16 {
		commerceAccount = seedNamespaceFixture(t, owner).account
		seedHostedCommerceFacts(t, owner, commerceAccount)
		seedQueuedCommerceEvent(t, owner)
		checkCommercePending(t, owner, commerceAccount, true)
		var err error
		commerceEvidence, err = ctr06SnapshotData(ctx, owner, commerceTables)
		if err != nil {
			t.Fatal(err)
		}
	}
	var authority lifecycleAuthority
	var export, recovery, deletion platform.ID
	if version >= 13 {
		authority = seedLifecycleAuthority(t, owner)
		export, recovery, deletion = platform.NewID(), platform.NewID(), platform.NewID()
		// Supplied source facts exercise restore preservation, not the business
		// acceptance of a recovery, export or deletion ceremony.
		// Confirmed/completed source facts include their retained command/proof
		// reference IDs and confirmation instant; this fixture executes no proof
		// ceremony and makes no claim that a provider or export actually ran.
		if _, err := owner.Exec(ctx, `UPDATE identity.account_security_state SET auth_epoch=7,recovery_generation=4,rev=rev+1,changed_at=clock_timestamp() WHERE user_id=$1`, authority.account); err != nil {
			t.Fatal(store.Sanitize("seed current account authority", err))
		}
		if _, err := owner.Exec(ctx, `INSERT INTO identity.lifecycle_operation(operation_id,user_id,kind,state,plan_rev,intent_sha256,auth_epoch,recovery_generation,created_at,expires_at,finished_at,rev,export_artifact_id,export_sha256,export_bytes,command_id,proof_id,confirmed_at)
 VALUES($2,$1,3,4,1,sha256('supplied export intent'),7,4,now(),now()+interval '1 hour',now(),1,gen_random_uuid(),sha256('supplied export digest'),123,gen_random_uuid(),gen_random_uuid(),now()),
 ($3,$1,1,2,1,sha256('supplied recovery intent'),7,4,now(),now()+interval '1 hour',NULL,1,NULL,NULL,NULL,gen_random_uuid(),gen_random_uuid(),now()),
 ($4,$1,2,2,1,sha256('supplied deletion intent'),7,4,now(),now()+interval '1 hour',NULL,1,NULL,NULL,NULL,gen_random_uuid(),gen_random_uuid(),now());`, authority.account, export, recovery, deletion); err != nil {
			t.Fatal(store.Sanitize("seed source lifecycle facts", err))
		}
	}
	f := seedNamespaceFixture(t, owner)
	channel, holder, protocol := platform.NewID(), platform.NewID(), platform.NewID()
	if _, err := owner.Exec(ctx, `UPDATE fleet.node SET online_since=now(),connection_id=$1 WHERE enrollment_id=$2`, channel, f.enrollment); err != nil {
		t.Fatal(store.Sanitize("seed fixture channel identity", err))
	}
	if _, err := owner.Exec(ctx, `INSERT INTO management.node_protocol(enrollment_id,node_id,account_id,protocol_major,protocol_epoch,initialized_at,rev) VALUES($1,$2,$3,2,$4,now(),1)`, f.enrollment, f.node, f.account, protocol); err != nil {
		t.Fatal(store.Sanitize("seed fixture protocol identity", err))
	}
	if _, err := owner.Exec(ctx, `INSERT INTO fleet.hub_lease(singleton,holder,fence,acquired_at,renewed_at,expires_at) VALUES(true,$1,1,now(),now(),now()+interval '5 minutes')`, holder); err != nil {
		t.Fatal(store.Sanitize("seed fixture hub lease", err))
	}
	runtime, sqlRuntime := managementRuntime(t, owner, url, group)
	identity := management.Identity{Account: f.account, Command: platform.NewID(), Enrollment: f.enrollment, Node: f.node, OwnerEpoch: [16]byte(platform.NewID()), IntentSHA256: sha256.Sum256([]byte("supplied unresolved operation identity")), Method: "RunService.Start", CreatedAt: time.Now().UTC(), ReplayUntil: time.Now().Add(time.Hour).UTC()}
	lease := management.Lease{Holder: holder, ChannelEpoch: channel, Fence: 1}
	if version >= 14 {
		identity.Actor, identity.Grant, identity.GrantRevision = platform.NewID(), platform.NewID(), 4
		lease.ProtocolEpoch = protocol
	}
	reserved, inserted, err := runtime.Reserve(ctx, identity, lease)
	if err != nil || !inserted {
		t.Fatalf("reserve input fixture: %v", err)
	}
	if version >= 14 {
		if _, won, err := runtime.MarkPossiblyDelivered(ctx, identity, lease, reserved); err != nil || !won {
			t.Fatalf("claim the original routing observation: %v", err)
		}
		if receipt, err := runtime.MarkUnknown(ctx, identity, lease); err != nil || receipt.State != management.StateUnknown {
			t.Fatalf("retain uncertainty after the original claim: %v", err)
		}
	} else if _, err := sqlRuntime.Exec(ctx, `UPDATE management.remote_operation SET state=7,may_have_delivered=true,effect=3,delivery_count=1,updated_at=clock_timestamp()`); err != nil {
		t.Fatal(store.Sanitize("record supplied unknown fixture", err))
	}
	dir := t.TempDir()
	archive, metadata := filepath.Join(dir, "source.dump"), filepath.Join(dir, "source.json")
	captured, err := CaptureLogical(ctx, managementConfig(url, name, group), archive, metadata)
	if err != nil || captured.SchemaVersion != version {
		t.Fatalf("schema%d real snapshot: %v", version, err)
	}
	var sourceAdmission string
	cutoverVersion := min(version, 13)
	if err := owner.QueryRow(ctx, "SELECT encode(database_identity_sha256,'hex') FROM management.cutover_receipt WHERE target_schema=$1", cutoverVersion).Scan(&sourceAdmission); err != nil {
		t.Fatal("source admission unavailable")
	}
	target := name + "_restored"
	targetRole := target + "_runtime"
	t.Cleanup(func() { pgtest.Drop(t, target) })
	cfg := config.Migration{Mode: config.SelfHosted, URL: pgtest.WithDatabase(t, url, target), Maintenance: url, Database: target, RuntimeRole: targetRole}
	restored, err := RestoreLogical(ctx, cfg, archive, captured.ArchiveSHA256, metadata, captured.MetadataSHA256, "isolated-schema12-restore-target")
	if err != nil || restored.SchemaVersion != version || restored.RestoreReceipt == "" || restored.SourceBackupSHA256 != captured.ArchiveSHA256 {
		t.Fatalf("schema%d real restore: %v", version, err)
	}
	destination := pgtest.Connect(t, cfg.URL)
	if version == 15 {
		hosted.check(t, destination, targetRole)
	}
	if version == 16 {
		actual, err := ctr06SnapshotData(ctx, destination, commerceTables)
		if err != nil || !slices.Equal(actual, commerceEvidence) {
			t.Fatalf("restored commerce identities or facts changed: %v", err)
		}
	}
	status, err := Inspect(ctx, destination, build)
	if err != nil || status.State != StateCurrent || status.RuntimeRole != targetRole {
		t.Fatalf("target-specific admission: %v", err)
	}
	var targetAdmission string
	var readyCount, revoked int
	var channelAbsent bool
	if err := destination.QueryRow(ctx, `SELECT (SELECT count(*) FROM management.cutover_receipt),
 (SELECT encode(database_identity_sha256,'hex') FROM management.cutover_receipt WHERE target_schema=$2),
 (SELECT count(*) FROM management.node_protocol WHERE revoked_at IS NOT NULL),
 (SELECT connection_id IS NULL FROM fleet.node WHERE enrollment_id=$1)`, f.enrollment, cutoverVersion).Scan(&readyCount, &targetAdmission, &revoked, &channelAbsent); err != nil || readyCount != cutoverVersion-11 || targetAdmission == sourceAdmission || revoked != 1 || !channelAbsent {
		t.Fatal("source ready/channel authority survived as target authority")
	}
	if version >= 13 {
		var auth, generation, oldAuth, oldGeneration int64
		var revokedSession, provedConsumed, pendingDenied, retainedExport bool
		var exportState, recoveryState, deletionState int
		err := destination.QueryRow(ctx, `SELECT a.auth_epoch,a.recovery_generation,s.auth_epoch,s.recovery_generation,s.revoked_at IS NOT NULL,
 (SELECT state=3 AND proved_at IS NOT NULL AND consumed_at IS NOT NULL FROM identity.step_up_challenge WHERE challenge_id=$3),
 (SELECT state=5 FROM identity.step_up_challenge WHERE challenge_id=$4),
 (SELECT state FROM identity.lifecycle_operation WHERE operation_id=$5),
 (SELECT export_sha256=sha256('supplied export digest') AND export_bytes=123 FROM identity.lifecycle_operation WHERE operation_id=$5),
 (SELECT state FROM identity.lifecycle_operation WHERE operation_id=$6),
 (SELECT state FROM identity.lifecycle_operation WHERE operation_id=$7)
 FROM identity.account_security_state a,identity.session s WHERE a.user_id=$1 AND s.session_id=$2`,
			authority.account, authority.current, authority.proved, authority.pending, export, recovery, deletion).
			Scan(&auth, &generation, &oldAuth, &oldGeneration, &revokedSession, &provedConsumed, &pendingDenied, &exportState, &retainedExport, &recoveryState, &deletionState)
		if err != nil || auth != 8 || generation != 5 || oldAuth != 7 || oldGeneration != 4 || !revokedSession || !provedConsumed || !pendingDenied || exportState != 7 || !retainedExport || recoveryState != 7 || deletionState != 2 {
			t.Fatalf("restored account/lifecycle authority or evidence differs: %v", store.Sanitize("inspect restored lifecycle facts", err))
		}
	}
	restoredRuntime, restoredSQL := managementRuntime(t, destination, cfg.URL, targetRole)
	if version == 16 {
		checkCommercePending(t, restoredSQL, commerceAccount, true)
	}
	retained, inserted, err := restoredRuntime.Reserve(ctx, identity, lease)
	if err != nil || inserted || retained.State != 7 || !retained.MayHaveDelivered || retained.Effect == nil || *retained.Effect != 3 {
		t.Fatalf("unknown identity was forgotten or re-executed: inserted=%v err=%v", inserted, err)
	}
	if version >= 14 {
		authority := management.Authority{
			Account: identity.Account, Actor: identity.Actor, Enrollment: identity.Enrollment,
			Node: identity.Node, Grant: identity.Grant, GrantRevision: identity.GrantRevision,
		}
		original, observed, err := restoredRuntime.InspectOriginal(ctx, authority, identity.Command)
		if err != nil || original.OwnerEpoch != identity.OwnerEpoch || original.IntentSHA256 != identity.IntentSHA256 ||
			observed.State != management.StateUnknown || !observed.MayHaveDelivered || observed.DeliveryCount != 1 ||
			observed.FinalAt != nil || observed.Reason != "operation_unknown" {
			t.Fatalf("the original scope or uncertain observation changed across the archive restore: %v", err)
		}
	}
	newCommand := identity
	newCommand.Command = platform.NewID()
	if _, _, err := restoredRuntime.Reserve(ctx, newCommand, lease); !errors.Is(err, management.ErrLease) {
		t.Fatalf("old protocol admitted fresh work: %v", err)
	}
	conflict := identity
	conflict.OwnerEpoch = [16]byte(platform.NewID())
	if _, _, err := restoredRuntime.Reserve(ctx, conflict, lease); !errors.Is(err, management.ErrIdentityConflict) {
		t.Fatal("restore silently rebound the Node owner epoch")
	}
}

func TestManagementIncompleteBackupRefusesBeforeCreatingADestination(t *testing.T) {
	ctx := context.Background()
	url, name := pgtest.Database(t)
	owner := pgtest.Connect(t, url)
	group := name + "_runtime"
	if _, err := Apply(ctx, owner, managementBuild(t), Options{Runner: "isolated-schema12-negative-source", RuntimeRole: group}); err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	archive, metadata := filepath.Join(dir, "source.dump"), filepath.Join(dir, "source.json")
	captured, err := CaptureLogical(ctx, managementConfig(url, name, group), archive, metadata)
	if err != nil {
		t.Fatal(err)
	}
	meta, err := ctr06ReadMetadata(metadata, captured.MetadataSHA256)
	if err != nil {
		t.Fatal(err)
	}
	for _, mode := range []string{"missing-table", "changed-checksum", "self-asserted-catalogue"} {
		t.Run(mode, func(t *testing.T) {
			bad := meta
			switch mode {
			case "missing-table":
				bad.Tables = append([]ctr06BackupTable(nil), meta.Tables[:len(meta.Tables)-1]...)
			case "changed-checksum":
				bad.SourceMigrations = append([]ctr06BackupMigration(nil), meta.SourceMigrations...)
				bad.SourceMigrations[0].SHA256 = ctr06SHA([]byte("changed applied migration"))
			case "self-asserted-catalogue":
				bad.SourceCatalogueSHA256 = ctr06SHA([]byte("unreviewed source catalogue"))
			}
			raw, err := json.Marshal(bad)
			if err != nil {
				t.Fatal("negative metadata encoding failed")
			}
			path := filepath.Join(dir, mode+".json")
			if os.WriteFile(path, raw, 0o600) != nil {
				t.Fatal("negative fixture write failed")
			}
			target := pgtest.Name(name + "_negative")
			t.Cleanup(func() { pgtest.Drop(t, target) })
			cfg := config.Migration{Mode: config.SelfHosted, URL: pgtest.WithDatabase(t, url, target), Maintenance: url, Database: target, RuntimeRole: target + "_rt"}
			if _, err := RestoreLogical(ctx, cfg, archive, captured.ArchiveSHA256, path, ctr06SHA(raw), "isolated-negative-restore"); err == nil {
				t.Fatal("incomplete backup was accepted despite a valid outer digest")
			}
			var exists bool
			if err := owner.QueryRow(ctx, "SELECT EXISTS(SELECT 1 FROM pg_database WHERE datname=$1)", target).Scan(&exists); err != nil || exists {
				t.Fatal("refused backup created a destination")
			}
		})
	}
}
