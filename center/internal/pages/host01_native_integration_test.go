// SPDX-License-Identifier: AGPL-3.0-only

package pages_test

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"slices"
	"testing"
	"time"

	"connectrpc.com/connect/v2"
	"connectrpc.com/connect/v2/connecthttp"
	fleetv1 "github.com/ArcForges/Contracts/go/arcforges/fleet/v1"
	"github.com/ArcForges/Contracts/go/arcforges/fleet/v1/fleetv1connect"
	foundation "github.com/ArcForges/Contracts/go/arcforges/foundation/v1"
	publicapi "github.com/ArcForges/Contracts/go/arcforges/publicapi/v1"
	"github.com/ArcForges/Contracts/go/arcforges/publicapi/v1/publicapiv1connect"
	v2 "github.com/ArcForges/Contracts/go/arcforges/sandbox/v2"
	"github.com/ArcForges/Contracts/go/arcforges/sandbox/v2/sandboxv2connect"
	"google.golang.org/protobuf/proto"

	"github.com/ArcForges/Cloud/center/internal/config"
	"github.com/ArcForges/Cloud/center/internal/entitlement"
	"github.com/ArcForges/Cloud/center/internal/feature"
	"github.com/ArcForges/Cloud/center/internal/ingress"
	"github.com/ArcForges/Cloud/center/internal/platform"
	"github.com/ArcForges/Cloud/center/internal/routes"
)

const host01Required = "ARCFORGES_HOST01_E2E_REQUIRED"

// TestHost01InstalledEntitlement exercises the same independently verified
// installed Node through two real Go Centers on disposable loopback HTTPS
// and PostgreSQL. The official case uses the test harness's hosted mode and
// explicitly labeled provider facts. The Node selects the fixture origin as
// self_hosted through its unchanged local API; the shipping pin is untouched.
func TestHost01InstalledEntitlement(t *testing.T) {
	t.Run("self-hosted", func(t *testing.T) {
		run := startHost01InstalledNode(t, false)
		requireHost01Status(t, run, true, feature.ReasonSelfHostedDefault)
		finishCenter02InstalledNode(t, run, func(center02Owner, platform.ID) {
			if run.harness.count("SELECT count(*) FROM entitlement.grant") != 0 ||
				run.harness.count("SELECT count(*) FROM entitlement.service_term") != 0 {
				t.Fatal("self-hosted enrollment and replacement needed hosted entitlement records")
			}
			requireHost01Status(t, run, true, feature.ReasonSelfHostedDefault)
			t.Log("self-hosted enrollment and reconnect served local HTTPS without an official plan or credential")
		})
	})

	t.Run("official-lapse", func(t *testing.T) {
		run := startHost01InstalledNode(t, true)
		requireHost01Status(t, run, false, feature.ReasonNoEntitlement)
		term := seedHost01ProviderFacts(t, run)
		active := requireHost01Status(t, run, true, feature.ReasonEntitled)
		finishCenter02InstalledNode(t, run, func(reported center02Owner, connection platform.ID) {
			var target center03Target
			if qualifyCenter03Peer(t, run, reported, &target) != connection {
				t.Fatal("the Run's exact signed replacement connection changed before the expiry scenario")
			}
			end := scheduleHost01ProviderEnd(t, run, term)
			timer := time.NewTimer(time.Until(end))
			defer timer.Stop()
			select {
			case <-timer.C:
			case <-run.done:
				t.Fatal("the installed child exited before actual hosted term expiry")
			case <-run.ctx.Done():
				t.Fatal("the official fixture did not reach its real expiry boundary")
			}
			expired := requireHost01Status(t, run, false, feature.ReasonSubscriptionExpired)
			if expired.GetVersion() <= active.GetVersion() {
				t.Fatal("the expired resolver snapshot did not supersede the active version")
			}
			requireHost01ReadDenied(t, run, target)
			requireHost01LapseClose(t, run, target, connection, end)
			t.Log("the official Center refused new access and closed the original signed connection before the listener shutdown")
		})
	})
}

func startHost01InstalledNode(t *testing.T, hosted bool) *center02NativeRun {
	t.Helper()
	options := settings{surfaces: "identity,pages,fleet,relay,nodes", relay: true, hosted: hosted,
		policy: `{"stepUpPerAccountLimit":1000,"signInFailuresAccountLimit":1000,"signInPerPrefixLimit":1000,"channelLapseRecheck":"1m"}`}
	if hosted {
		options.nativeHandler = host01LoopbackIngress
	}
	run := startInstalledCenterNode(t, host01Required, "ArcForges.ClosedLoop.Tests.CloudLinkCenterControlTests", options, func(h *harness) {
		if hosted && h.center.Config.Mode != config.OfficialHosted ||
			!hosted && (h.center.Config.Mode != config.SelfHosted || h.center.Config.Plan != config.PlanNone) {
			t.Fatal("the startup fixture selected the wrong Center service mode")
		}
		h.clock.mu.Lock()
		h.clock.tick = func() {
			h.clock.mu.Lock()
			h.clock.now = time.Now().UTC()
			h.clock.mu.Unlock()
		}
		h.clock.mu.Unlock()
		if hosted {
			requireHost01IngressBoundary(t, h)
		}
	})
	run.ownerBrowser.bootstrapState()
	return run
}

// The real official Center requires the client address normally supplied
// by its edge. The private TLS fixture derives that one field from its
// accepted socket and passes the actual request to the unchanged ingress.
func host01LoopbackIngress(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		peer, err := netip.ParseAddrPort(r.RemoteAddr)
		if err != nil || !peer.Addr().IsLoopback() {
			http.Error(w, "the hosted fixture requires a loopback peer", http.StatusBadRequest)
			return
		}
		forwarded := r.Clone(r.Context())
		forwarded.Header.Set(config.ClientIPHeader, peer.Addr().Unmap().String())
		forwarded.Header.Del(config.ClientCountryHeader)
		forwarded.Header.Del(config.ClientASNHeader)
		next.ServeHTTP(w, forwarded)
	})
}

func requireHost01IngressBoundary(t *testing.T, h *harness) {
	t.Helper()
	const procedure = fleetv1connect.NodeEnrollmentServiceStartDeviceAuthorizationProcedure
	// Omit the node on purpose. The unwrapped official ingress should
	// stop at the missing edge address. The fixture HTTPS route should
	// proceed to the actual device method's typed node validation.
	request := &fleetv1.NodeEnrollmentServiceStartDeviceAuthorizationRequest{Meta: center03Meta(false, nil)}
	payload, err := proto.Marshal(request)
	if err != nil {
		t.Fatal(err)
	}
	raw := httptest.NewRequest(http.MethodPost, h.origin+procedure, bytes.NewReader(ingress.Frame(payload)))
	// httptest preserves its absolute input as RequestURI. Match the
	// origin-form request target that the native HTTPS client sends.
	raw.RequestURI = raw.URL.RequestURI()
	raw.RemoteAddr = "127.0.0.1:1"
	raw.Header.Set("Content-Type", "application/grpc-web+proto")
	refusal := httptest.NewRecorder()
	h.center.Public().ServeHTTP(refusal, raw)
	if denial := ingress.ReasonInvalidRequest; refusal.Code != http.StatusOK ||
		!bytes.Equal(refusal.Body.Bytes(), ingress.TrailerFrame(denial.Status, denial.Code, true)) {
		t.Fatalf("the official ingress without its address did not return the expected transport refusal (HTTP %d)", refusal.Code)
	}

	client := connect.NewClient(connecthttp.NewTransport(h.http, h.url, connecthttp.WithGRPCWeb()))
	var reply fleetv1.NodeEnrollmentServiceStartDeviceAuthorizationResponse
	if err = client.CallUnary(t.Context(), connect.Spec{Procedure: procedure, StreamType: connect.StreamTypeUnary}, request, &reply); err != nil {
		t.Fatalf("the native loopback ingress did not reach typed device validation: %s", connect.CodeOf(err))
	}
	failure := reply.GetError()
	if reply.GetValue() != nil || failure.GetCategory() != foundation.ErrorCategory_ERROR_CATEGORY_VALIDATION ||
		failure.GetCode() != "invalid_argument" || failure.GetEffect() != foundation.EffectCertainty_EFFECT_CERTAINTY_DID_NOT_HAPPEN {
		t.Fatalf("the official device method returned an unexpected result: %s/%s", failure.GetCategory(), failure.GetCode())
	}
	t.Log("the same device request hit the official missing-address transport refusal directly and reached real typed validation over the fixture TLS listener")
}

// The isolated provider fact is an actual service interval and ordinary
// typed subscription capability grants. There is no provider call or sale.
func seedHost01ProviderFacts(t *testing.T, run *center02NativeRun) platform.ID {
	t.Helper()
	start := time.Now().UTC().Truncate(time.Microsecond)
	term := platform.NewID()
	_, err := run.harness.migration.Exec(run.ctx, `INSERT INTO entitlement.service_term
		(term_id, account_id, kind, subscription_ref, period_ref, starts_at, ends_at, authorized_at, created_at)
		VALUES ($1,$2,1,'host01-fixture-subscription','host01-fixture-initial',$3,$4,$3,$3)`,
		term, run.owner.id, start, start.Add(4*time.Minute))
	if err != nil {
		t.Fatalf("append the scoped provider service fact: %v", err)
	}
	for _, key := range []feature.Key{feature.CenterNodes, feature.RemoteView, feature.RemoteControl} {
		reference := "host01-fixture-subscription-" + string(key)
		if _, _, err := run.harness.center.Entitlements.IssueGrant(run.ctx, entitlement.IssueGrantRequest{
			AccountID: run.owner.id.String(), Kind: entitlement.KindCapability, Subject: string(key),
			Value: entitlement.CapabilityValue{}, Source: entitlement.SourceSubscription, SourceRef: &reference,
			EffectiveFrom: entitlement.FromTime(start), IssuedByActor: "commerce",
		}); err != nil {
			t.Fatalf("admit the scoped provider capability %s: %v", key, err)
		}
	}
	return term
}

func scheduleHost01ProviderEnd(t *testing.T, run *center02NativeRun, previous platform.ID) time.Time {
	t.Helper()
	start := time.Now().UTC().Truncate(time.Microsecond)
	end := start.Add(5 * time.Second)
	replacement := platform.NewID()
	tx, err := run.harness.migration.Begin(run.ctx)
	if err != nil {
		t.Fatalf("begin the fixture provider correction: %v", err)
	}
	defer func() { _ = tx.Rollback(run.ctx) }()
	if _, err = tx.Exec(run.ctx, `INSERT INTO entitlement.service_term
		(term_id, account_id, kind, subscription_ref, period_ref, starts_at, ends_at, authorized_at, created_at)
		VALUES ($1,$2,1,'host01-fixture-subscription','host01-fixture-correction',$3,$4,$3,$3)`,
		replacement, run.owner.id, start, end); err != nil {
		t.Fatalf("append the replacement provider fact: %v", err)
	}
	if _, err = tx.Exec(run.ctx, `INSERT INTO entitlement.service_term_action
		(action_id,account_id,term_id,kind,effective_at,recorded_at,source_ref,replacement_term_id)
		VALUES ($1,$2,$3,1,$4,$4,'host01-fixture-correction',$5)`,
		platform.NewID(), run.owner.id, previous, start, replacement); err != nil {
		t.Fatalf("append the provider term supersession: %v", err)
	}
	if err = tx.Commit(run.ctx); err != nil {
		t.Fatalf("commit the fixture provider correction: %v", err)
	}
	// The provider fixture writes facts directly, so publish their projection
	// through the real resolver before testing its wall-clock expiry.
	snapshot, err := run.harness.center.Entitlements.Refresh(run.ctx, run.owner.id.String())
	if err != nil {
		t.Fatalf("refresh the replacement provider facts: %v", err)
	}
	if snapshot.ValidUntil == nil || *snapshot.ValidUntil != entitlement.FromTime(end) {
		t.Fatalf("the refreshed provider projection did not expire at %s", end.Format(time.RFC3339Nano))
	}
	for _, key := range []feature.Key{feature.CenterNodes, feature.RemoteView, feature.RemoteControl} {
		entry, ok := snapshot.Capability(string(key))
		if !ok || !entry.Granted {
			t.Fatalf("the replacement term did not preserve active access for %s before expiry", key)
		}
	}
	if !time.Now().Before(end) {
		t.Fatal("the replacement service term elapsed before the fixture could observe its valid interval")
	}
	t.Logf("the fixture appended a real time-bounded provider term ending at %s", end.Format(time.RFC3339Nano))
	return end
}

type host01StatusTransport struct{ browser *browser }

func (c host01StatusTransport) Do(req *http.Request) (*http.Response, error) {
	req.Header.Set("Origin", c.browser.h.origin)
	req.Header.Set("User-Agent", c.browser.userAgent)
	req.Header.Set(config.ClientIPHeader, "203.0.113.10")
	req.Header.Set(ingress.CSRFHeader, c.browser.csrf)
	req.AddCookie(&http.Cookie{Name: routes.PageCookieName, Value: c.browser.cookie})
	return c.browser.h.http.Do(req)
}

func requireHost01Status(t *testing.T, run *center02NativeRun, allowed bool, reason feature.Reason) *publicapi.EntitlementSnapshot {
	t.Helper()
	client := connect.NewClient(connecthttp.NewTransport(host01StatusTransport{run.ownerBrowser}, run.harness.url, connecthttp.WithGRPCWeb()))
	request := &publicapi.EntitlementServiceGetSnapshotRequest{Meta: center03Meta(false, nil)}
	var reply publicapi.EntitlementServiceGetSnapshotResponse
	if err := client.CallUnary(run.ctx, connect.Spec{Procedure: publicapiv1connect.EntitlementServiceGetSnapshotProcedure,
		StreamType: connect.StreamTypeUnary}, request, &reply); err != nil {
		t.Fatalf("read the authenticated entitlement snapshot: %s", connect.CodeOf(err))
	}
	snapshot := reply.GetValue().GetSnapshot()
	if reply.GetError() != nil || snapshot == nil || !proto.Equal(reply.GetMeta().GetCorrelationId(), request.GetMeta().GetCorrelationId()) {
		t.Fatalf("the authenticated entitlement snapshot returned %s without a correlated value", reply.GetError().GetCode())
	}
	want := map[string]bool{"center.nodes": true, "remote.view": true, "remote.control": true}
	for _, entry := range snapshot.GetCapabilities() {
		key := entry.GetCapability()
		if !want[key] || entry.GetAllowed() != allowed || !slices.Equal(entry.GetReasons(), []string{string(reason)}) {
			t.Fatalf("unexpected hosted availability for %s: %t %v", key, entry.GetAllowed(), entry.GetReasons())
		}
		delete(want, key)
	}
	if len(want) != 0 || len(snapshot.GetQuotas()) != 0 {
		t.Fatal("the entitlement snapshot omitted service keys or exposed an obsolete quota")
	}
	return snapshot
}

func requireHost01ReadDenied(t *testing.T, run *center02NativeRun, target center03Target) {
	t.Helper()
	// This fixture ID is never a local grant. The Center must refuse before
	// forwarding a V2 read or consulting any local Sandbox grant.
	target.grant, target.revision = platform.NewID(), 1
	request := &v2.ResourceServiceGetBudgetRequest{Meta: center03Meta(false, nil), ScopeKind: proto.String("sandbox"),
		ScopeId: center03ID(platform.NewID())}
	var reply v2.ResourceServiceGetBudgetResponse
	if err := center03Unary(run.ownerBrowser, target, sandboxv2connect.ResourceServiceGetBudgetProcedure, request, &reply, nil); err != nil {
		t.Fatalf("the lapsed authenticated V2 read returned transport status %s", connect.CodeOf(err))
	}
	failure := reply.GetError()
	if reply.GetValue() != nil || failure.GetCategory() != foundation.ErrorCategory_ERROR_CATEGORY_ENTITLEMENT ||
		failure.GetDetails().GetState().GetReason() != string(feature.ReasonSubscriptionExpired) ||
		!proto.Equal(reply.GetMeta().GetCorrelationId(), request.GetMeta().GetCorrelationId()) {
		t.Fatalf("the expired V2 read did not return the correlated entitlement refusal: %s/%s", failure.GetCategory(), failure.GetCode())
	}
	center03Denied(t, failure, "hosted_access_required")
}

func requireHost01LapseClose(t *testing.T, run *center02NativeRun, target center03Target, connection platform.ID, end time.Time) {
	t.Helper()
	ctx, cancel := context.WithTimeout(run.ctx, 55*time.Second)
	defer cancel()
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()
	var protocol platform.ID
	err := run.harness.migration.QueryRow(ctx, `SELECT protocol_epoch FROM management.node_protocol
		WHERE account_id=$1 AND node_id=$2 AND enrollment_id=$3 AND revoked_at IS NULL`,
		run.owner.id, target.node, target.enrollment).Scan(&protocol)
	if err != nil {
		t.Fatalf("read the exact enrolled protocol epoch after term expiry: %v", err)
	}
	for {
		var closed, lapsing, readmission bool
		err := run.harness.migration.QueryRow(ctx, `
WITH original AS (
	SELECT correlation_id, actor_ref FROM audit.audit_event
	WHERE event_type = 'fleet.channel.closed' AND reason = 'hosted_access_required' AND target_kind = 'node'
		AND target_id = $1 AND occurred_at >= $2
		AND convert_from(payload, 'UTF8')::jsonb ->> 'connectionId' = $3
		AND convert_from(payload, 'UTF8')::jsonb ->> 'code' = '4403'
), refusals AS (
	SELECT g.correlation_id, o.correlation_id AS original_id FROM audit.audit_event AS g JOIN original AS o USING (actor_ref)
	WHERE g.event_type = 'access.gated' AND g.reason = $4 AND g.target_kind = 'operation'
		AND g.target_id = $5 AND g.occurred_at >= $2
)
SELECT EXISTS (SELECT FROM original),
	EXISTS (SELECT FROM refusals WHERE correlation_id = original_id),
	EXISTS (SELECT FROM refusals WHERE correlation_id IS NOT NULL AND correlation_id IS DISTINCT FROM original_id)`,
			target.enrollment.String(), end, connection.String(), string(feature.ReasonSubscriptionExpired),
			routes.NodeChannelV2ID).Scan(&closed, &lapsing, &readmission)
		if err != nil {
			t.Fatalf("read authoritative hosted lapse and upgrade evidence: %v", err)
		}
		if closed && lapsing && readmission {
			if _, online := run.harness.center.Hub.V2Presence(run.owner.id, target.enrollment, target.node, protocol); online {
				t.Fatal("a channel was present for the exact paid enrollment after the recorded lapse and refused readmission")
			}
			return
		}
		select {
		case <-ticker.C:
		case <-run.done:
			t.Fatalf("the installed child exited before exact lapse proof: close=%t lapse=%t readmission=%t", closed, lapsing, readmission)
		case <-ctx.Done():
			t.Fatalf("timed out waiting for exact lapse proof: close=%t lapse=%t readmission=%t", closed, lapsing, readmission)
		}
	}
}
