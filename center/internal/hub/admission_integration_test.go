// SPDX-License-Identifier: AGPL-3.0-only

package hub_test

import (
	"bytes"
	"context"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/ArcForges/Cloud/center/internal/config"
	"github.com/ArcForges/Cloud/center/internal/entitlement"
	"github.com/ArcForges/Cloud/center/internal/nodetest"
	"github.com/ArcForges/Cloud/center/internal/platform"
	"github.com/ArcForges/Cloud/center/internal/session"
	"github.com/ArcForges/Cloud/center/internal/store"
)

// TestUpgradeAdmission is E1-2 (CTR5-HUB-02, PN-3): only a GET upgrade of version 13 with exactly the route's subprotocol, no query
// and no body reaches the credential check; each refusal is an HTTP answer with its closed reason in ArcForges-Refusal and the JSON
// ArcError, and none appends access.authorized.
func TestUpgradeAdmission(t *testing.T) {
	h := newHarness(t, settings{})
	node := h.enroll()
	upgrade := func(method, path string, header http.Header, body []byte) *http.Response {
		t.Helper()
		request, err := http.NewRequest(method, h.url+path, bytes.NewReader(body))
		if err != nil {
			t.Fatal(err)
		}
		if body == nil {
			request.Body, request.ContentLength = http.NoBody, 0
		}
		request.Header = http.Header{"Upgrade": {"websocket"}, "Connection": {"Upgrade"}, "Sec-Websocket-Version": {"13"},
			"Sec-Websocket-Key": {"dGhlIHNhbXBsZSBub25jZQ=="}, "Sec-Websocket-Protocol": {nodetest.ChannelSubprotocol},
			"Authorization": {"Bearer " + node.access}, config.ClientIPHeader: {"198.51.100.7"}}
		for name, values := range header {
			if values == nil {
				request.Header.Del(name)
				continue
			}
			request.Header[name] = values
		}
		response, err := http.DefaultClient.Do(request)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = response.Body.Close() })
		return response
	}
	cases := []struct {
		name   string
		method string
		path   string
		header http.Header
		body   []byte
		status int
		reason string
	}{
		{"a POST", http.MethodPost, "/fleet/v1/node", nil, []byte("x"), 405, "VALIDATION/invalid_argument"},
		{"a query", http.MethodGet, "/fleet/v1/node?x=1", nil, nil, 400, "VALIDATION/invalid_argument"},
		{"a body", http.MethodGet, "/fleet/v1/node", nil, []byte("x"), 400, "VALIDATION/invalid_argument"},
		{"no upgrade", http.MethodGet, "/fleet/v1/node", http.Header{"Upgrade": nil}, nil, 400, "VALIDATION/invalid_argument"},
		{"no connection upgrade", http.MethodGet, "/fleet/v1/node", http.Header{"Connection": {"keep-alive"}}, nil, 400, "VALIDATION/invalid_argument"},
		{"another version", http.MethodGet, "/fleet/v1/node", http.Header{"Sec-Websocket-Version": {"8"}}, nil, 400, "VALIDATION/invalid_argument"},
		{"no key", http.MethodGet, "/fleet/v1/node", http.Header{"Sec-Websocket-Key": nil}, nil, 400, "VALIDATION/invalid_argument"},
		{"no subprotocol", http.MethodGet, "/fleet/v1/node", http.Header{"Sec-Websocket-Protocol": nil}, nil, 400, "VALIDATION/invalid_argument"},
		{"another subprotocol", http.MethodGet, "/fleet/v1/node", http.Header{"Sec-Websocket-Protocol": {"chat"}}, nil, 400, "VALIDATION/invalid_argument"},
		{"an extra subprotocol", http.MethodGet, "/fleet/v1/node", http.Header{"Sec-Websocket-Protocol": {nodetest.ChannelSubprotocol + ", chat"}}, nil, 400,
			"VALIDATION/invalid_argument"},
		{"a trailing slash", http.MethodGet, "/fleet/v1/node/", nil, nil, 404, ""},
	}
	for _, item := range cases {
		response := upgrade(item.method, item.path, item.header, item.body)
		if response.StatusCode != item.status || response.Header.Get("ArcForges-Refusal") != item.reason {
			t.Errorf("%s: %d %q", item.name, response.StatusCode, response.Header.Get("ArcForges-Refusal"))
		}
		if item.reason != "" && response.Header.Get("Content-Type") != "application/json" {
			t.Errorf("%s: the refusal has no JSON ArcError", item.name)
		}
	}
	if n := h.audits("access.authorized"); n != 0 {
		t.Fatalf("a refused upgrade was authorized: %d", n)
	}
	// The well-formed upgrade is admitted (control).
	if response := upgrade(http.MethodGet, "/fleet/v1/node", nil, nil); response.StatusCode != http.StatusSwitchingProtocols {
		t.Fatalf("the well-formed upgrade: %d %q", response.StatusCode, response.Header.Get("ArcForges-Refusal"))
	}
}

// TestUpgradeRefusesUnknownRevokedExpiredAndAccountTokens is E1-3 (CTR5-HUB-02, PN-3, PN-4, SEC-22): the credential is checked before
// the upgrade, and each failure says which in its header: an unknown token is unauthenticated, an expired one token_expired (the node
// refreshes), a revoked one credential_revoked (it signs in again), an account session is permission_denied (the AGENT row admits the
// node scope only), and a cookie never authenticates the route (a cookie-only upgrade is unauthenticated: no cross-site hijacking).
func TestUpgradeRefusesUnknownRevokedExpiredAndAccountTokens(t *testing.T) {
	h := newHarness(t, settings{})
	expired, revoked := h.enroll(), h.enroll()
	h.db.Exec("UPDATE identity.session SET access_expires_at = now() - interval '1 second' WHERE installation_id = '" + expired.result.InstallationID.String() + "'")
	h.db.Exec("UPDATE identity.session SET revoked_at = now(), revoke_reason = 6 WHERE installation_id = '" + revoked.result.InstallationID.String() + "'")
	account := h.db.Account(1)
	for name, item := range map[string]struct {
		bearer string
		header http.Header
		status int
		reason string
	}{
		"no credential":    {"", nil, 401, "AUTHENTICATION/unauthenticated"},
		"an unknown token": {session.AccessPrefix + strings.Repeat("A", 43), nil, 401, "AUTHENTICATION/unauthenticated"},
		"an expired token": {expired.access, nil, 401, "AUTHENTICATION/token_expired"},
		"a revoked token":  {revoked.access, nil, 401, "AUTHENTICATION/credential_revoked"},
		"a cookie only": {"", http.Header{"Cookie": {"__Host-af_session=" + strings.Repeat("A", 43)}, "Origin": {"https://center.example.test"}}, 401,
			"AUTHENTICATION/unauthenticated"},
	} {
		channel, err := h.dial(item.bearer, item.header)
		got := refusalOf(t, channel, err)
		if got.status != item.status || got.reason != item.reason || got.body["code"] == nil {
			t.Errorf("%s: %+v", name, got)
		}
	}
	// An account session's native bearer: the row admits the node scope only.
	issued := h.issueAccount(account)
	channel, err := h.dial(issued, nil)
	if got := refusalOf(t, channel, err); got.status != 403 || got.reason != "AUTHORIZATION/permission_denied" {
		t.Errorf("an account session: %+v", got)
	}
	if n := h.audits("access.refused"); n != 1 {
		t.Errorf("the account session's refusal is audited once: %d", n)
	}
}

// issueAccount issues a native account session on a new desktop device and returns its access token.
func (h *harness) issueAccount(user platform.ID) string {
	h.t.Helper()
	ids := h.db
	device, installation := platform.NewID(), platform.NewID()
	ids.Exec("INSERT INTO device.device (device_id, user_id, display_name, platform, trust_level, remote_enabled, first_seen_at, last_seen_at, rev) VALUES ('" +
		device.String() + "', '" + user.String() + "', 'desktop', 1, 1, false, now(), now(), 1)")
	ids.Exec("INSERT INTO device.installation (installation_id, device_id, user_id, product_id, app_version, platform, installed_at, last_active_at, rev) VALUES ('" +
		installation.String() + "', '" + device.String() + "', '" + user.String() + "', 'arcforges-mobile', '1.0.0', 'android', now(), now(), 1)")
	var issued session.Native
	if err := h.db.Runtime.InTx(context.Background(), "issue", store.TxOptions{}, func(ctx context.Context, tx pgx.Tx) error {
		var err error
		issued, err = session.IssueNative(ctx, tx, h.policy, session.Grant{UserID: user, DeviceID: device, InstallationID: installation, Scope: session.ScopeAccount,
			Product: "arcforges-mobile", Purpose: session.PurposeAuthenticate, AuthMethod: 1, AuthenticatedAt: time.Now()}, time.Now())
		return err
	}); err != nil {
		h.t.Fatal(err)
	}
	h.secrets = append(h.secrets, issued.AccessToken, issued.RefreshToken)
	return issued.AccessToken
}

// TestTheChannelIsGatedInBothModes is E1-4 (bullet 9, the center half; CTR5-SUR-05): the channel's row is gated by center.nodes after
// authentication, the controls and access.authorized. A self-hosted center admits it by its built-in default and refuses it once the
// operator disables the key; an official hosted center without a plan configuration (production) refuses it, audited access.gated.
// The refusal is ENTITLEMENT/feature_not_entitled, 403, before any upgrade.
func TestTheChannelIsGatedInBothModes(t *testing.T) {
	for name, item := range map[string]struct {
		options  settings
		admitted bool
	}{
		"self-hosted default":                                        {settings{}, true},
		"self-hosted with center.nodes off":                          {settings{disabled: "center.nodes"}, false},
		"official hosted without a catalogue":                        {settings{mode: config.OfficialHosted}, false},
		"official hosted with the development fixtures and no grant": {settings{mode: config.OfficialHosted, plan: config.PlanDevelopmentFixtures}, false},
		"official hosted with the development fixtures and a grant":  {settings{mode: config.OfficialHosted, plan: config.PlanDevelopmentFixtures}, true},
	} {
		t.Run(name, func(t *testing.T) {
			h := newHarness(t, item.options)
			node := h.enroll()
			if item.options.mode == config.OfficialHosted && item.admitted {
				h.grant(node.user, "center.nodes")
			}
			channel, err := h.dial(node.access, nil)
			if item.admitted {
				if err != nil {
					t.Fatalf("refused: %v", err)
				}
				_ = channel.WS.CloseNow()
				return
			}
			got := refusalOf(t, channel, err)
			if got.status != 403 || got.reason != "ENTITLEMENT/feature_not_entitled" {
				t.Fatalf("%+v", got)
			}
			if h.audits("access.authorized") != 1 || h.audits("access.gated") != 1 {
				t.Fatalf("authorized %d, gated %d", h.audits("access.authorized"), h.audits("access.gated"))
			}
		})
	}
}

// TestTheChannelsUpgradeRateIsBoundedPerNodeAndPerAccount replaces E1-5 (Q21: no connected-node cap; the upgrade-rate buckets of E0):
// a node's upgrades beyond its bucket are refused RESOURCE/rate_limited, 429 with Retry-After, before access.authorized; another node
// of the account is not affected until the account's bucket is spent too.
func TestTheChannelsUpgradeRateIsBoundedPerNodeAndPerAccount(t *testing.T) {
	h := newHarness(t, settings{policy: `{"channelUpgradeNodeLimit": 2, "channelUpgradeAccountLimit": 3}`})
	first := h.enroll()
	second := h.enrollIn(first.user)
	for range 2 {
		channel, err := h.dial(first.access, nil)
		if err != nil {
			t.Fatalf("an upgrade within the node's bucket: %v", err)
		}
		_ = channel.WS.CloseNow()
	}
	authorized := h.audits("access.authorized")
	channel, err := h.dial(first.access, nil)
	got := refusalOf(t, channel, err)
	if got.status != 429 || got.reason != "RESOURCE/rate_limited" || got.retry == "" {
		t.Fatalf("the node's third upgrade: %+v", got)
	}
	if limit, _ := got.body["details"].(map[string]any)["limit"].(map[string]any); limit["limitName"] != "channel_upgrades_per_node" {
		t.Errorf("the limit: %v", got.body)
	}
	if h.audits("access.authorized") != authorized {
		t.Error("a refused upgrade was authorized")
	}
	// The account's bucket: three upgrades in all (the refused one counted in it), so the other node's first is refused.
	channel, err = h.dial(second.access, nil)
	if got = refusalOf(t, channel, err); got.status != 429 {
		t.Fatalf("the account's fourth upgrade: %+v", got)
	}
}

// TestAHubWithoutTheLeaseAdmitsNoChannel (PB-5): a process whose hub does not hold the hub lease (another process does) answers the
// upgrade RESOURCE/overloaded, 503 with Retry-After, before any credential is read.
func TestAHubWithoutTheLeaseAdmitsNoChannel(t *testing.T) {
	h := newHarness(t, settings{})
	node := h.enroll()
	// Another process takes the lease over: this hub's renewal then fails.
	h.db.Exec("UPDATE fleet.hub_lease SET holder = gen_random_uuid(), fence = fence + 1, acquired_at = now(), renewed_at = now(), expires_at = now() + interval '1 hour'")
	if !eventually(t, 5*time.Second, func() bool { _, held := h.center.Hub.Lease().Fence(); return !held }) {
		t.Fatal("the hub did not notice that it lost the lease")
	}
	channel, err := h.dial(node.access, nil)
	if got := refusalOf(t, channel, err); got.status != 503 || got.reason != "RESOURCE/overloaded" || got.retry == "" {
		t.Fatalf("%+v", got)
	}
	if h.audits("access.authorized") != 0 {
		t.Fatal("the upgrade reached the authorizer")
	}
}

// TestADisabledRelaySurfaceIsNotServed: without the relay surface the route is 404 with the reason not_activated, before anything else.
func TestADisabledRelaySurfaceIsNotServed(t *testing.T) {
	h := newHarness(t, settings{surfaces: "identity,pages,fleet"})
	node := h.enroll()
	channel, err := h.dial(node.access, nil)
	if got := refusalOf(t, channel, err); got.status != 404 || got.reason != "STATE/not_activated" {
		t.Fatalf("%+v", got)
	}
	if h.center.Hub != nil {
		t.Fatal("a hub was composed without the relay surface")
	}
}

// TestARevokedNodeRowAdmitsNoChannel (C0 E-14): a live credential whose installation has no live node row is unauthenticated.
func TestARevokedNodeRowAdmitsNoChannel(t *testing.T) {
	h := newHarness(t, settings{})
	node := h.enroll()
	h.db.Exec("UPDATE fleet.node SET revoked_at = now(), revoke_reason = 1, rev = rev + 1 WHERE enrollment_id = '" + node.result.EnrollmentID.String() + "'")
	channel, err := h.dial(node.access, nil)
	if got := refusalOf(t, channel, err); got.status != 401 || got.reason != "AUTHENTICATION/unauthenticated" {
		t.Fatalf("%+v", got)
	}
}

// grant gives an account features through the operator grant (the operations page's domain call; the step-up evidence it consumes is
// stubbed), as an operator seeded in the store.
func (h *harness) grant(account platform.ID, features ...string) {
	h.t.Helper()
	operator := h.db.Account(1)
	h.db.Exec("INSERT INTO identity.operator (operator_id, user_id, granted_at, expires_at, granted_by, reason) VALUES (gen_random_uuid(), '" + operator.String() +
		"', now() - interval '1 day', now() + interval '30 days', 'operator:cli', 'test operator')")
	op := entitlement.NewOperator(h.center.Store, h.center.Entitlements, h.center.FeatureConfiguration.OperatorGrants, nil)
	if _, err := op.Grant(context.Background(), entitlement.GrantCall{Caller: entitlement.OperatorCaller{UserID: operator, Scope: "account"}, CommandID: platform.NewID(),
		Request: entitlement.OperatorRequest{Account: account.String(), Features: features, Reason: "the node channel's test", SourceRef: "ticket-1",
			ExpiresAt: entitlement.FromTime(time.Now().Add(10 * 24 * time.Hour))},
		Consume: func(context.Context, pgx.Tx, [32]byte, time.Time) error { return nil }}); err != nil {
		h.t.Fatal(err)
	}
}
