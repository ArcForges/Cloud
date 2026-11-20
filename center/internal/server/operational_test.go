// SPDX-License-Identifier: AGPL-3.0-only

package server

import (
	"bytes"
	"crypto/sha256"
	"log/slog"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/ArcForges/Cloud/center/internal/commerce"
	"github.com/ArcForges/Cloud/center/internal/commerce/paddle"
	"github.com/ArcForges/Cloud/center/internal/config"
	"github.com/ArcForges/Cloud/center/internal/dbtest"
	"github.com/ArcForges/Cloud/center/internal/management"
	"github.com/ArcForges/Cloud/center/internal/observe"
	"github.com/ArcForges/Cloud/center/internal/platform"
)

func TestOperationalPulseTracksListenerReservations(t *testing.T) {
	raw, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	listener := listen(raw, 1, 1)
	t.Cleanup(func() { _ = listener.Close() })
	center := &Center{Metrics: observe.NewMetrics(), httpSlots: listener.slots}
	accept := func() *slotConn {
		t.Helper()
		peer, err := net.DialTimeout("tcp", listener.Addr().String(), 2*time.Second)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = peer.Close() })
		connection, err := listener.Accept()
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = connection.Close() })
		return connection.(*slotConn)
	}
	expect := func(requests, nodes int64) {
		t.Helper()
		pulse := center.operationalPulse(t.Context())
		if pulse.HTTPRequests != (observe.Capacity{Active: requests, Limit: 1}) ||
			pulse.HTTPNodes != (observe.Capacity{Active: nodes, Limit: 1}) {
			t.Fatalf("listener pulse: requests=%+v nodes=%+v", pulse.HTTPRequests, pulse.HTTPNodes)
		}
	}
	expect(0, 0)
	first := accept()
	expect(1, 0)
	if !first.toNode() {
		t.Fatal("available node slot was refused")
	}
	expect(0, 1)
	second := accept()
	if second.toNode() {
		t.Fatal("upgraded past the node slot limit")
	}
	first.toRequest() // The failed-handshake fallback keeps its node slot while the request pool is full.
	expect(1, 1)
	_ = second.Close()
	first.toRequest()
	expect(1, 0)
	_ = first.Close()
	_ = first.Close()
	if first.toNode() {
		t.Fatal("closed connection reacquired a slot")
	}
	expect(0, 0)
}

func TestOperationalPulseSamplesDurableRecordsWithRuntimePrivileges(t *testing.T) {
	db := dbtest.New(t)
	now := time.Now().UTC().Truncate(time.Microsecond)
	ctx := t.Context()
	if err := commerce.CheckEnvironment(ctx, db.Runtime, paddle.Sandbox, true); err != nil {
		t.Fatal(err)
	}
	_, err := db.Migration.Exec(ctx, `WITH sample AS (
		SELECT 'evt_fixture_due' AS event_ref, 1 AS state,
		       $1::timestamptz - interval '10 minutes' AS received_at,
		       $1::timestamptz - interval '1 minute' AS next_check_at, NULL::timestamptz AS processed_at
		UNION ALL SELECT 'evt_fixture_retry', 3, $1-interval '20 minutes', $1, NULL
		UNION ALL SELECT 'evt_fixture_future', 3, $1-interval '1 hour', $1+interval '1 minute', NULL
		UNION ALL SELECT 'evt_fixture_review', 3, $1-interval '1 hour', NULL, NULL
		UNION ALL SELECT 'evt_fixture_terminal', 4, $1-interval '2 hours', NULL, $1
	)
	INSERT INTO commerce.provider_event (provider,environment,event_ref,payload_sha256,semantic_sha256,event_kind,
		resource_ref,occurred_at,state,verified_at,received_at,next_check_at,processed_at)
	SELECT 1,2,event_ref,sha256('digest'::bytea),sha256('meaning'::bytea),'transaction.completed',
	       'txn_fixture_private_reference',received_at,state,received_at,received_at,next_check_at,processed_at
	FROM sample`, now)
	if err != nil {
		t.Fatal(err)
	}
	center := &Center{Store: db.Runtime}
	if due := center.pendingPulse(ctx, now, billingDue, now); due != (observe.QueuePulse{
		State: observe.SourceReady, Count: 2, OldestSeconds: 1200,
	}) {
		t.Fatalf("due pulse with one pending and one due retry: %+v", due)
	}
	if _, err := db.Migration.Exec(ctx, `INSERT INTO commerce.provider_event
		(provider,environment,event_ref,payload_sha256,semantic_sha256,event_kind,resource_ref,
		occurred_at,state,verified_at,received_at,next_check_at,processed_at)
		SELECT provider,environment,event_ref || '_' || n::text,payload_sha256,semantic_sha256,event_kind,resource_ref,
		       occurred_at,state,verified_at,received_at,next_check_at,processed_at
		FROM commerce.provider_event,generate_series(1,$1::integer) AS generated(n)
		WHERE event_ref='evt_fixture_due'`, pulseRowLimit+4); err != nil {
		t.Fatal(err)
	}
	if due := center.pendingPulse(ctx, now, billingDue, now); due != (observe.QueuePulse{
		State: observe.SourceReady, Count: pulseRowLimit, OldestSeconds: 600, Truncated: true,
	}) {
		t.Fatalf("due pulse: %+v", due)
	}
	if review := center.pendingPulse(ctx, now, billingReview); review != (observe.QueuePulse{
		State: observe.SourceReady, Count: 1, OldestSeconds: 3600,
	}) {
		t.Fatalf("review pulse: %+v", review)
	}
	if unknown := center.pendingPulse(ctx, now, remoteUnknown, management.StateUnknown); unknown != (observe.QueuePulse{State: observe.SourceReady}) {
		t.Fatalf("empty remote uncertainty pulse: %+v", unknown)
	}
	if unavailable := center.pendingPulse(ctx, now, "SELECT count(*) FROM commerce.unavailable_fixture LIMIT $1"); unavailable.State != observe.SourceUnavailable {
		t.Fatalf("failing pending source: %+v", unavailable)
	}
}

func TestOperationalPulseCountsTheDurableUnknownTransition(t *testing.T) {
	db := dbtest.New(t)
	node, _, enrolled := enrollNode(t, db)
	ctx := t.Context()
	now := time.Now().UTC()
	lease := management.Lease{Holder: platform.NewID(), Fence: 1, ChannelEpoch: platform.NewID(), ProtocolEpoch: platform.NewID()}
	var account platform.ID
	if err := db.Migration.QueryRow(ctx, `UPDATE fleet.node SET online_since=$2,connection_id=$3
		WHERE enrollment_id=$1 RETURNING user_id`, enrolled.EnrollmentID, now, lease.ChannelEpoch).Scan(&account); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Migration.Exec(ctx, `INSERT INTO management.node_protocol
		(enrollment_id,node_id,account_id,protocol_major,protocol_epoch,initialized_at,rev)
		VALUES ($1,$2,$3,2,$4,$5,1)`, enrolled.EnrollmentID, node.ID, account, lease.ProtocolEpoch, now); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Migration.Exec(ctx, `INSERT INTO fleet.hub_lease(singleton,holder,fence,acquired_at,renewed_at,expires_at)
		VALUES (true,$1,$2,$3,$3,$3::timestamptz+interval '5 minutes')`, lease.Holder, lease.Fence, now); err != nil {
		t.Fatal(err)
	}
	operations := management.New(db.Runtime)
	identity := management.Identity{Account: account, Command: platform.NewID(), Enrollment: enrolled.EnrollmentID, Node: node.ID,
		Actor: platform.NewID(), Grant: platform.NewID(), GrantRevision: 1, OwnerEpoch: [16]byte(platform.NewID()),
		IntentSHA256: sha256.Sum256([]byte("fixture unknown intent")), Method: "RunService.Start",
		CreatedAt: now, ReplayUntil: now.Add(time.Hour)}
	reservation, fresh, err := operations.Reserve(ctx, identity, lease)
	if err != nil || !fresh {
		t.Fatalf("reserve operation: fresh=%t err=%v", fresh, err)
	}
	if _, claimed, err := operations.MarkPossiblyDelivered(ctx, identity, lease, reservation); err != nil || !claimed {
		t.Fatalf("claim possible delivery: claimed=%t err=%v", claimed, err)
	}
	unknown, err := operations.MarkUnknown(ctx, identity, lease)
	if err != nil || unknown.State != management.StateUnknown {
		t.Fatalf("durable unknown: state=%d err=%v", unknown.State, err)
	}
	center := &Center{Store: db.Runtime}
	pulse := center.pendingPulse(ctx, unknown.UpdatedAt.Add(time.Minute), remoteUnknown, management.StateUnknown)
	if pulse != (observe.QueuePulse{State: observe.SourceReady, Count: 1, OldestSeconds: 60}) {
		t.Fatalf("unknown after admitted possible delivery: %+v", pulse)
	}
}

func TestOperationalPulseDistinguishesRestoreIsolationFromReachability(t *testing.T) {
	db := dbtest.New(t)
	settings := testConfig(config.SelfHosted)
	settings.Database = db.Runtime.Pool().Config()
	center, err := New(settings, slog.New(slog.DiscardHandler), Options{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(center.Close)
	ctx := t.Context()
	ready := center.operationalPulse(ctx)
	if ready.RuntimeDatabase != observe.SourceReady || ready.SchemaAdmission != observe.SourceReady ||
		ready.RemoteUnknown.State != observe.SourceReady || ready.BillingDue.State != observe.SourceDisabled {
		t.Fatalf("ready pulse: %+v", ready)
	}
	if _, err := db.Migration.Exec(ctx, "COMMENT ON DATABASE "+pgx.Identifier{db.Name}.Sanitize()+
		" IS 'arcforges-ctr06-restore-quarantine-v1'"); err != nil {
		t.Fatal(err)
	}
	center.pulse.next = time.Time{}
	blocked := center.operationalPulse(ctx)
	if blocked.RuntimeDatabase != observe.SourceReady || blocked.SchemaAdmission != observe.SourceUnavailable ||
		blocked.RemoteUnknown.State != observe.SourceUnavailable {
		t.Fatalf("isolated restore pulse: %+v", blocked)
	}
	var metrics bytes.Buffer
	if err := blocked.WritePrometheus(&metrics); err != nil {
		t.Fatal(err)
	}
	if body := metrics.String(); !strings.Contains(body, `arcforges_center_store_ready{check="schema_admission"} 0`) ||
		!strings.Contains(body, `arcforges_center_pending_available{queue="remote_unknown"} 0`) ||
		strings.Contains(body, `arcforges_center_pending_items{queue="remote_unknown"}`) ||
		strings.Contains(body, `queue="billing_due"`) || strings.Contains(body, db.Name) {
		t.Fatalf("isolated metrics contain a stale count or private value:\n%s", body)
	}
}
