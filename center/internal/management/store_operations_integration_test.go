// SPDX-License-Identifier: AGPL-3.0-only

package management_test

import (
	"context"
	"crypto/sha256"
	"errors"
	"testing"
	"time"

	"github.com/ArcForges/Cloud/center/internal/management"
	"github.com/ArcForges/Cloud/center/internal/pgtest"
	"github.com/ArcForges/Cloud/center/internal/platform"
	"github.com/ArcForges/Cloud/center/internal/schema"
	"github.com/ArcForges/Cloud/center/internal/store"
	"github.com/ArcForges/Cloud/center/internal/store/migrate"
	"github.com/jackc/pgx/v5"
)

func TestRemoteOperationRetainsOriginalAuthorityAndSendClaim(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	url, name := pgtest.Database(t)
	owner := pgtest.Connect(t, url)
	group := name + "_runtime"
	build, err := migrate.Load(schema.Migrations())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := migrate.Apply(ctx, owner, build, migrate.Options{Runner: "isolated management operation fixture", RuntimeRole: group}); err != nil {
		t.Fatal(err)
	}
	exec := func(label, sql string, args ...any) {
		t.Helper()
		if _, err := owner.Exec(ctx, sql, args...); err != nil {
			t.Fatal(store.Sanitize(label, err))
		}
	}

	account, device, installation := platform.NewID(), platform.NewID(), platform.NewID()
	enrollment, node := platform.NewID(), platform.NewID()
	exec("seed owner", `INSERT INTO identity.user(user_id,display_name,state,passkey_user_handle,created_at,rev)
	VALUES($1,'Owner',1,sha256(convert_to($2,'UTF8')),now(),1)`, account, account.String())
	exec("seed device", `INSERT INTO device.device(device_id,user_id,display_name,platform,trust_level,remote_enabled,first_seen_at,last_seen_at,rev)
	VALUES($1,$2,'test node',3,1,false,now(),now(),1)`, device, account)
	exec("seed installation", `INSERT INTO device.installation(installation_id,device_id,user_id,product_id,app_version,platform,installed_at,last_active_at,rev)
	VALUES($1,$2,$3,'arcforges-node','0.1.0','linux',now(),now(),1)`, installation, device, account)
	lease := management.Lease{Holder: platform.NewID(), Fence: 1, ChannelEpoch: platform.NewID(), ProtocolEpoch: platform.NewID()}
	exec("seed Node", `INSERT INTO fleet.node(enrollment_id,node_id,user_id,device_id,installation_id,display_name,os,arch,version,
	enrolled_at,last_seen_at,rev,online_since,connection_id)
	VALUES($1,$2,$3,$4,$5,'test node',2,1,'0.1.0',now(),now(),1,now(),$6)`,
		enrollment, node, account, device, installation, lease.ChannelEpoch)
	exec("seed protocol", `INSERT INTO management.node_protocol(enrollment_id,node_id,account_id,protocol_major,protocol_epoch,initialized_at,rev)
	VALUES($1,$2,$3,2,$4,now(),1)`, enrollment, node, account, lease.ProtocolEpoch)
	exec("seed hub", `INSERT INTO fleet.hub_lease(singleton,holder,fence,acquired_at,renewed_at,expires_at)
	VALUES(true,$1,$2,now(),now(),now()+interval '5 minutes')`, lease.Holder, lease.Fence)
	login, password := group+"_a", pgtest.Secret()
	exec("enable fixture runtime", "ALTER ROLE "+pgx.Identifier{login}.Sanitize()+" LOGIN PASSWORD '"+password+"'; GRANT "+
		pgx.Identifier{group}.Sanitize()+" TO "+pgx.Identifier{login}.Sanitize())
	runtime := management.New(store.New(pgtest.Pool(t, pgtest.WithUser(t, url, login, password), 4)))

	scope := management.Authority{Account: account, Actor: platform.NewID(), Enrollment: enrollment, Node: node, Grant: platform.NewID(), GrantRevision: 9}
	makeIdentity := func(method string) management.Identity {
		now := time.Now().UTC()
		return management.Identity{Account: account, Command: platform.NewID(), Enrollment: enrollment, Node: node,
			Actor: scope.Actor, Grant: scope.Grant, GrantRevision: scope.GrantRevision, OwnerEpoch: [16]byte(platform.NewID()),
			IntentSHA256: sha256.Sum256([]byte("fixture canonical intent " + method)), Method: method,
			CreatedAt: now, ReplayUntil: now.Add(time.Hour)}
	}
	reserve := func(i management.Identity) {
		t.Helper()
		r, fresh, e := runtime.Reserve(ctx, i, lease)
		if e != nil || !fresh || r.State != management.StateAccepted || r.DeliveryCount != 0 || r.MayHaveDelivered {
			t.Fatalf("reserve: receipt=%+v fresh=%t error=%v", r, fresh, e)
		}
	}
	start := makeIdentity("RunService.Start")
	stop := makeIdentity("RunService.Stop")
	unattempted := makeIdentity("RunService.Start")
	reserve(start)
	reserve(stop)
	reserve(unattempted)

	wrongScope := scope
	wrongScope.Actor = platform.NewID()
	if _, _, err := runtime.InspectOriginal(ctx, wrongScope, start.Command); !errors.Is(err, pgx.ErrNoRows) {
		t.Fatalf("foreign actor read retained identity: %v", err)
	}
	wrongScope = scope
	wrongScope.GrantRevision++
	if _, _, err := runtime.InspectOriginal(ctx, wrongScope, start.Command); !errors.Is(err, pgx.ErrNoRows) {
		t.Fatalf("replaced grant read retained identity: %v", err)
	}
	legacyShape := makeIdentity("RunService.Start")
	legacyShape.Actor, legacyShape.Grant, legacyShape.GrantRevision = platform.ID{}, platform.ID{}, 0
	reserve(legacyShape)
	if _, _, err := runtime.InspectOriginal(ctx, scope, legacyShape.Command); !errors.Is(err, pgx.ErrNoRows) {
		t.Fatalf("unassociated record supplied authority: %v", err)
	}
	if _, claimed, err := runtime.MarkPossiblyDelivered(ctx, legacyShape, lease); claimed || !errors.Is(err, management.ErrIdentityConflict) {
		t.Fatalf("unassociated operation claimed delivery: %t %v", claimed, err)
	}

	wrongProtocol := lease
	wrongProtocol.ProtocolEpoch = platform.NewID()
	if _, claimed, err := runtime.MarkPossiblyDelivered(ctx, start, wrongProtocol); claimed || !errors.Is(err, management.ErrLease) {
		t.Fatalf("foreign protocol claimed delivery: %t %v", claimed, err)
	}
	type claim struct {
		ok  bool
		err error
	}
	claims := make(chan claim, 4)
	for range cap(claims) {
		go func() {
			_, ok, err := runtime.MarkPossiblyDelivered(ctx, start, lease)
			claims <- claim{ok: ok, err: err}
		}()
	}
	claimed := 0
	for range cap(claims) {
		c := <-claims
		if c.err != nil {
			t.Fatal(c.err)
		}
		if c.ok {
			claimed++
		}
	}
	if claimed != 1 {
		t.Fatalf("send claim winners: %d", claimed)
	}
	if _, err := runtime.MarkNotDelivered(ctx, start, lease); !errors.Is(err, management.ErrTransition) {
		t.Fatalf("possible delivery regressed to no effect: %v", err)
	}
	if _, fresh, err := runtime.Reserve(ctx, start, lease); fresh || err != nil {
		t.Fatalf("exact replay became a new admission: %t %v", fresh, err)
	}

	if _, ok, err := runtime.MarkPossiblyDelivered(ctx, stop, lease); !ok || err != nil {
		t.Fatalf("Stop send claim: %t %v", ok, err)
	}
	run := platform.NewID()
	stopObservation := management.Observation{State: management.StateSucceeded, Effect: management.EffectDidNotHappen,
		ResultSHA256: sha256.Sum256([]byte("verified fixture no-op Stop")), ResultKind: "run", ResultID: &run}
	r, err := runtime.RecordResult(ctx, stop, lease, stopObservation)
	if err != nil || r.State != management.StateSucceeded || r.Effect == nil || *r.Effect != management.EffectDidNotHappen ||
		r.FinalAt == nil || r.ResultID == nil || *r.ResultID != run {
		t.Fatalf("no-op Stop settlement: receipt=%+v error=%v", r, err)
	}
	if _, err := runtime.RecordResult(ctx, start, lease, stopObservation); !errors.Is(err, management.ErrTransition) {
		t.Fatalf("Start accepted no-effect success: %v", err)
	}

	exec("clear fixture channel", `UPDATE fleet.node SET connection_id=NULL,online_since=NULL WHERE enrollment_id=$1`, enrollment)
	r, err = runtime.MarkNotDelivered(ctx, unattempted, lease)
	if err != nil || r.State != management.StateNotDelivered || r.MayHaveDelivered || r.DeliveryCount != 0 {
		t.Fatalf("prove absent send claim after disconnect: receipt=%+v error=%v", r, err)
	}
	r, err = runtime.MarkUnknown(ctx, start, lease)
	if err != nil || r.State != management.StateUnknown || !r.MayHaveDelivered || r.DeliveryCount != 1 || r.FinalAt != nil {
		t.Fatalf("retain disconnect uncertainty: receipt=%+v error=%v", r, err)
	}

	next := management.Lease{Holder: platform.NewID(), Fence: 2, ChannelEpoch: platform.NewID(), ProtocolEpoch: lease.ProtocolEpoch}
	exec("rotate fixture hub", `UPDATE fleet.hub_lease SET holder=$1,fence=$2,acquired_at=clock_timestamp(),
	renewed_at=clock_timestamp(),expires_at=clock_timestamp()+interval '5 minutes' WHERE singleton`, next.Holder, next.Fence)
	exec("publish fixture connection", `UPDATE fleet.node SET connection_id=$1,online_since=clock_timestamp()
	WHERE enrollment_id=$2`, next.ChannelEpoch, enrollment)
	got, r, err := runtime.InspectOriginal(ctx, scope, start.Command)
	if err != nil || got.OwnerEpoch != start.OwnerEpoch || got.Command != start.Command || got.Actor != scope.Actor ||
		got.Grant != scope.Grant || got.GrantRevision != scope.GrantRevision || got.IntentSHA256 != start.IntentSHA256 ||
		r.State != management.StateUnknown {
		t.Fatalf("inspect exact original association: error=%v", err)
	}
	observation := management.Observation{State: management.StateSucceeded, Effect: management.EffectHappened,
		ResultSHA256: sha256.Sum256([]byte("verified fixture Start")), ResultKind: "run", ResultID: &run}
	for _, stale := range []management.Lease{lease, next} {
		if _, err := runtime.RecordResult(ctx, got, stale, observation); !errors.Is(err, management.ErrLease) {
			t.Fatalf("direct result used a stale or substituted send fence: %v", err)
		}
	}
	forged := got
	forged.OwnerEpoch = [16]byte(platform.NewID())
	if _, err := runtime.ReconcileResult(ctx, forged, next, observation); !errors.Is(err, management.ErrIdentityConflict) {
		t.Fatalf("reconciled a changed owner epoch: %v", err)
	}
	r, err = runtime.ReconcileResult(ctx, got, next, observation)
	if err != nil || r.State != management.StateSucceeded || r.DeliveryCount != 1 || r.FinalAt == nil {
		t.Fatalf("reconcile exact original operation: receipt=%+v error=%v", r, err)
	}
	if _, ok, err := runtime.MarkPossiblyDelivered(ctx, got, next); ok || err != nil {
		t.Fatalf("reconciled command claimed a second send: %t %v", ok, err)
	}
	changedResult := observation
	changedResult.ResultSHA256 = sha256.Sum256([]byte("different fixture result"))
	if _, err := runtime.ReconcileResult(ctx, got, next, changedResult); !errors.Is(err, management.ErrTransition) {
		t.Fatalf("terminal result changed: %v", err)
	}
	// Only this exact identity has durable proof of no previous claim.
	if _, ok, err := runtime.MarkPossiblyDelivered(ctx, unattempted, next); !ok || err != nil {
		t.Fatalf("explicit proved no-effect retry: %t %v", ok, err)
	}
}
