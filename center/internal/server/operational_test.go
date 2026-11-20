// SPDX-License-Identifier: AGPL-3.0-only

package server

import (
	"bytes"
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
		SELECT 'evt_fixture_due_' || n::text AS event_ref, 1 AS state,
		       $1::timestamptz - interval '10 minutes' AS received_at,
		       $1::timestamptz - interval '1 minute' AS next_check_at, NULL::timestamptz AS processed_at
		FROM generate_series(1,$2::integer)
		UNION ALL SELECT 'evt_fixture_future', 3, $1-interval '1 hour', $1+interval '1 minute', NULL
		UNION ALL SELECT 'evt_fixture_review', 3, $1-interval '1 hour', NULL, NULL
		UNION ALL SELECT 'evt_fixture_terminal', 4, $1-interval '2 hours', NULL, $1
	)
	INSERT INTO commerce.provider_event (provider,environment,event_ref,payload_sha256,semantic_sha256,event_kind,
		resource_ref,occurred_at,state,verified_at,received_at,next_check_at,processed_at)
	SELECT 1,2,event_ref,sha256('digest'::bytea),sha256('meaning'::bytea),'transaction.completed',
	       'txn_fixture_private_reference',received_at,state,received_at,received_at,next_check_at,processed_at
	FROM sample`, now, pulseRowLimit+4)
	if err != nil {
		t.Fatal(err)
	}
	center := &Center{Store: db.Runtime}
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
