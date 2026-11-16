// SPDX-License-Identifier: AGPL-3.0-only

package migrate

import (
	"context"
	"crypto/sha256"
	"errors"
	"testing"
	"time"

	"github.com/ArcForges/Cloud/center/internal/management"
	"github.com/ArcForges/Cloud/center/internal/pgtest"
	"github.com/ArcForges/Cloud/center/internal/platform"
	"github.com/ArcForges/Cloud/center/internal/store"
)

func TestManagementRevokedProtocolAllowsOnlyDefiniteReconciliation(t *testing.T) {
	ctx := context.Background()
	url, name := pgtest.Database(t)
	owner := pgtest.Connect(t, url)
	group := name + "_runtime"
	if _, err := Apply(ctx, owner, centerBuild(t), Options{Runner: "isolated-reconciliation-fixture", RuntimeRole: group}); err != nil {
		t.Fatal(err)
	}
	f := seedNamespaceFixture(t, owner)
	channel, holder := platform.NewID(), platform.NewID()
	if _, err := owner.Exec(ctx, `UPDATE fleet.node SET online_since=now(),connection_id=$1 WHERE enrollment_id=$2`, channel, f.enrollment); err != nil {
		t.Fatal(store.Sanitize("seed fixture channel", err))
	}
	if _, err := owner.Exec(ctx, `INSERT INTO management.node_protocol(enrollment_id,node_id,account_id,protocol_major,protocol_epoch,initialized_at,rev) VALUES($1,$2,$3,2,$4,now(),1)`, f.enrollment, f.node, f.account, platform.NewID()); err != nil {
		t.Fatal(store.Sanitize("seed fixture protocol", err))
	}
	if _, err := owner.Exec(ctx, `INSERT INTO fleet.hub_lease(singleton,holder,fence,acquired_at,renewed_at,expires_at) VALUES(true,$1,1,now(),now(),now()+interval '5 minutes')`, holder); err != nil {
		t.Fatal(store.Sanitize("seed fixture lease", err))
	}
	runtime, sqlRuntime := managementRuntime(t, owner, url, group)
	identity := management.Identity{Account: f.account, Command: platform.NewID(), Enrollment: f.enrollment, Node: f.node, OwnerEpoch: [16]byte(platform.NewID()), IntentSHA256: sha256.Sum256([]byte("supplied canonical identity")), Method: "RunService.Start", CreatedAt: time.Now().UTC(), ReplayUntil: time.Now().Add(time.Hour).UTC()}
	lease := management.Lease{Holder: holder, ChannelEpoch: channel, Fence: 1}
	if _, inserted, err := runtime.Reserve(ctx, identity, lease); err != nil || !inserted {
		t.Fatalf("original reservation: %v", err)
	}
	if _, err := sqlRuntime.Exec(ctx, `UPDATE management.remote_operation SET state=7,effect=3,may_have_delivered=true,delivery_count=1,updated_at=clock_timestamp()`); err != nil {
		t.Fatal(store.Sanitize("record supplied unknown observation", err))
	}
	if _, err := owner.Exec(ctx, `UPDATE management.node_protocol SET revoked_at=clock_timestamp(),rev=rev+1`); err != nil {
		t.Fatal(store.Sanitize("revoke fixture protocol", err))
	}
	fresh := identity
	fresh.Command = platform.NewID()
	if _, _, err := runtime.Reserve(ctx, fresh, lease); !errors.Is(err, management.ErrLease) {
		t.Fatalf("revoked protocol admitted new identity: %v", err)
	}
	for _, statement := range []string{
		`UPDATE management.remote_operation SET delivery_count=delivery_count+1`,
		`UPDATE management.remote_operation SET channel_epoch=gen_random_uuid()`,
		`UPDATE management.remote_operation SET state=4,effect=1,final_at=clock_timestamp(),updated_at=clock_timestamp()`,
		`UPDATE management.remote_operation SET state=3,effect=2,result_sha256=sha256('supplied observation'),final_at=clock_timestamp(),updated_at=clock_timestamp(),channel_epoch=gen_random_uuid()`,
		`UPDATE management.remote_operation SET state=3,effect=2,result_sha256=sha256('supplied observation'),final_at=clock_timestamp(),updated_at=clock_timestamp(),node_owner_epoch=decode(repeat('ff',16),'hex')`,
	} {
		if _, err := sqlRuntime.Exec(ctx, statement); err == nil {
			t.Fatal("revocation allowed redelivery, rebind or unverified definitive identity")
		}
	}
	if _, err := owner.Exec(ctx, `UPDATE fleet.hub_lease SET holder=$1,fence=fence+1,acquired_at=clock_timestamp(),renewed_at=clock_timestamp(),expires_at=clock_timestamp()+interval '5 minutes'`, platform.NewID()); err != nil {
		t.Fatal(store.Sanitize("advance actual hub lease", err))
	}
	if _, err := sqlRuntime.Exec(ctx, `UPDATE management.remote_operation SET state=3,effect=2,result_sha256=sha256('supplied observation'),final_at=clock_timestamp(),updated_at=clock_timestamp()`); err == nil {
		t.Fatal("a stale hub settled the operation")
	}
	// This is a supplied definite reconciliation observation, not a mock Node
	// signature or a claim that an external Run succeeded. Real SQL must retain
	// the original identity and must not demand new delivery authority to settle.
	if _, err := sqlRuntime.Exec(ctx, `UPDATE management.remote_operation SET state=3,effect=2,result_sha256=sha256('supplied observation'),final_at=clock_timestamp(),updated_at=clock_timestamp(),hub_fence=2`); err != nil {
		t.Fatal(store.Sanitize("reconcile original uncertain identity", err))
	}
	retained, inserted, err := runtime.Reserve(ctx, identity, lease)
	if err != nil || inserted || retained.State != 3 || retained.DeliveryCount != 1 {
		t.Fatalf("reconciliation changed execution identity or delivery: %v", err)
	}
	if _, err := sqlRuntime.Exec(ctx, `UPDATE management.remote_operation SET state=4,effect=1,result_sha256=sha256('replacement')`); err == nil {
		t.Fatal("final reconciliation was overwritten")
	}
}
