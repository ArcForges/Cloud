// SPDX-License-Identifier: AGPL-3.0-only

package hub_test

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"testing"
	"time"

	fleetv1 "github.com/ArcForges/Contracts/go/arcforges/fleet/v1"
	"github.com/ArcForges/Contracts/go/arcforges/fleet/v1/fleetv1connect"
	foundationv1 "github.com/ArcForges/Contracts/go/arcforges/foundation/v1"
	nodev1 "github.com/ArcForges/Contracts/go/arcforges/node/v1"
	relayv1 "github.com/ArcForges/Contracts/go/arcforges/relay/v1"
	"github.com/jackc/pgx/v5"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"

	"github.com/ArcForges/Cloud/center/internal/access"
	"github.com/ArcForges/Cloud/center/internal/config"
	"github.com/ArcForges/Cloud/center/internal/dbtest"
	"github.com/ArcForges/Cloud/center/internal/fleet"
	"github.com/ArcForges/Cloud/center/internal/hub"
	"github.com/ArcForges/Cloud/center/internal/identity"
	"github.com/ArcForges/Cloud/center/internal/nodetest"
	"github.com/ArcForges/Cloud/center/internal/platform"
	"github.com/ArcForges/Cloud/center/internal/routes"
	"github.com/ArcForges/Cloud/center/internal/session"
	"github.com/ArcForges/Cloud/center/internal/store"
)

// The node registry of FleetService on the nodes surface (AF-CTR-05 part E2a; Plan CTR5-API-01..04, CTR5-CALL-02, PB-1, C-N6, Q20,
// Q25; decisions B-4; EVIDENCE: REAL PostgreSQL, the composed center with its real ingress, session verifier, authorizer, relay
// verification and cascade, the real WebSocket server; MOCKED: the nodes, nodetest with software keys, and the step-up ceremony, whose
// proved challenge is seeded as identityapi's tests do).

// registryHarness is a center with the nodes surface; its channels answer no heartbeat while a test posts, so the deadline is long.
func registryHarness(t *testing.T) *harness {
	t.Helper()
	return newHarness(t, settings{surfaces: "identity,pages,fleet,relay,nodes",
		tune: func(s *hub.Settings) { s.Heartbeat, s.HeartbeatDeadline = time.Second, 30*time.Second }})
}

const fleetService = "/arcforges.fleet.v1.FleetService/"

// accountSession issues a native session of a scope (account or mobile.limited) for an account on a new device.
func (h *harness) accountSession(user platform.ID, scope session.Scope) session.Native {
	h.t.Helper()
	device, installation := platform.NewID(), platform.NewID()
	h.db.Exec("INSERT INTO device.device (device_id, user_id, display_name, platform, trust_level, remote_enabled, first_seen_at, last_seen_at, rev) VALUES ('" +
		device.String() + "', '" + user.String() + "', 'phone', 4, 1, false, now(), now(), 1)")
	h.db.Exec("INSERT INTO device.installation (installation_id, device_id, user_id, product_id, app_version, platform, installed_at, last_active_at, rev) VALUES ('" +
		installation.String() + "', '" + device.String() + "', '" + user.String() + "', 'arcforges-mobile', '1.0.0', 'android', now(), now(), 1)")
	var issued session.Native
	if err := h.db.Runtime.InTx(context.Background(), "issue", store.TxOptions{}, func(ctx context.Context, tx pgx.Tx) error {
		var err error
		issued, err = session.IssueNative(ctx, tx, h.policy, session.Grant{UserID: user, DeviceID: device, InstallationID: installation, Scope: scope,
			Product: "arcforges-mobile", Purpose: session.PurposeAuthenticate, AuthMethod: 1, AuthenticatedAt: time.Now()}, time.Now())
		return err
	}); err != nil {
		h.t.Fatal(err)
	}
	h.secrets = append(h.secrets, issued.AccessToken, issued.RefreshToken)
	return issued
}

// rpc posts a request and decodes the reply into response.
func (h *harness) rpc(path string, request proto.Message, bearer string, response proto.Message) {
	h.t.Helper()
	reply, err := nodetest.Client{URL: h.url, ClientIPHeader: config.ClientIPHeader}.Post(path, request, bearer)
	if err != nil {
		h.t.Fatal(err)
	}
	if _, err = nodetest.Decode(reply, response); err != nil {
		h.t.Fatalf("%s: %v", path, err)
	}
}

// writes is everything a refused registry call could have written: audit events, rate-limit counts, receipts, consumed challenges and
// node, device and session revisions.
func (h *harness) writes() int {
	return h.count(`SELECT (SELECT count(*) FROM audit.audit_event) + (SELECT coalesce(sum(count), 0) FROM platform.rate_limit) +
    (SELECT count(*) FROM platform.command_receipt) + (SELECT coalesce(sum(rev), 0) FROM identity.step_up_challenge) + (SELECT coalesce(sum(rev), 0) FROM fleet.node) +
    (SELECT coalesce(sum(rev), 0) FROM device.device) + (SELECT coalesce(sum(rev), 0) FROM identity.session)`)
}

func errorKey(value *foundationv1.ArcError) string {
	if value == nil {
		return ""
	}
	return strings.TrimPrefix(value.GetCategory().String(), "ERROR_CATEGORY_") + "/" + value.GetCode()
}

func idValue(id platform.ID) *foundationv1.Id {
	return &foundationv1.Id{Value: append([]byte(nil), id[:]...)}
}

func commandMeta() *foundationv1.RequestMeta {
	return &foundationv1.RequestMeta{CommandId: idValue(platform.NewID())}
}

func (h *harness) listNodes(bearer string, request *fleetv1.FleetServiceListNodesRequest) *fleetv1.FleetServiceListNodesResponse {
	h.t.Helper()
	if request == nil {
		request = &fleetv1.FleetServiceListNodesRequest{Meta: &foundationv1.RequestMeta{}}
	}
	response := &fleetv1.FleetServiceListNodesResponse{}
	h.rpc(fleetv1connect.FleetServiceListNodesProcedure, request, bearer, response)
	return response
}

func (h *harness) getNode(bearer string, request *fleetv1.FleetServiceGetNodeRequest) *fleetv1.FleetServiceGetNodeResponse {
	h.t.Helper()
	response := &fleetv1.FleetServiceGetNodeResponse{}
	h.rpc(fleetv1connect.FleetServiceGetNodeProcedure, request, bearer, response)
	return response
}

func (h *harness) renameNode(bearer string, meta *foundationv1.RequestMeta, nodeID platform.ID, name *string) *fleetv1.FleetServiceRenameNodeResponse {
	h.t.Helper()
	response := &fleetv1.FleetServiceRenameNodeResponse{}
	h.rpc(fleetv1connect.FleetServiceRenameNodeProcedure, &fleetv1.FleetServiceRenameNodeRequest{Meta: meta, NodeId: idValue(nodeID), Name: name}, bearer, response)
	return response
}

func (h *harness) revokeNode(bearer string, meta *foundationv1.RequestMeta, nodeID platform.ID) *fleetv1.FleetServiceRevokeNodeResponse {
	h.t.Helper()
	response := &fleetv1.FleetServiceRevokeNodeResponse{}
	h.rpc(fleetv1connect.FleetServiceRevokeNodeProcedure, &fleetv1.FleetServiceRevokeNodeRequest{Meta: meta, NodeId: idValue(nodeID)}, bearer, response)
	return response
}

// relayedCaller is the routed caller a relaying node states for its own local caller.
func relayedCaller(node *enrolled, origin nodev1.Origin) *fleetv1.RoutedCaller {
	return &fleetv1.RoutedCaller{Kind: fleetv1.CallerKind_CALLER_KIND_NODE_RELAY.Enum(), RelayingNodeId: idValue(node.node.ID), LocalOrigin: origin.Enum()}
}

// sign gives a registry request the relay assertion of its node over a nonce of the node's channel: the digest is SHA-256 of the
// request as transmitted without relay_assertion (the request is marshalled before the assertion is set, and the assertion's field
// comes last on the wire).
func sign(t *testing.T, node *enrolled, channel *nodetest.Channel, request proto.Message, method relayv1.RoutedMethod, target *platform.ID,
	origin nodev1.Origin, set func([]byte)) {
	t.Helper()
	data, err := proto.Marshal(request)
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(data)
	assertion := node.node.Assertion(publicBaseURL, nodetest.Relay{InstallationID: node.result.InstallationID, LocalOrigin: origin, LocalSession: platform.NewID(),
		Method: method, RequestSHA256: digest[:], Target: target, Nonce: nonceOf(t, channel)})
	encoded, err := proto.Marshal(assertion)
	if err != nil {
		t.Fatal(err)
	}
	set(encoded)
}

// TestTheRegistryRowsAreTheServedMethods (E2-1, E2-22; Plan CTR5-API-01 and AF-CTR-06): the nodes surface serves the four
// registry methods, six routed task methods and twelve routed file/workspace methods, each with its operation row. Every other
// FleetService method remains UNIMPLEMENTED; with the surface off all served methods refuse before reading a credential.
func TestTheRegistryRowsAreTheServedMethods(t *testing.T) {
	expected := []string{
		"ListNodes", "GetNode", "RenameNode", "RevokeNode",
		"SubmitNodeTask", "GetNodeTask", "ListNodeTasks", "WaitNodeTask", "ReadNodeTaskOutput", "CancelNodeTask",
		"ReadNodeFile", "WriteNodeFile", "EditNodeFile", "SearchNodeFiles", "ListNodeDirectory", "PlanNodeRemoval",
		"ExecuteNodeRemoval", "GetNodeFileOperation", "RegisterNodeWorkspace", "UnregisterNodeWorkspace", "ListNodeWorkspaces", "GetNodeWorkspace",
	}
	served := map[string]bool{}
	for _, method := range routes.NodesMethods() {
		if served[method.Path] {
			t.Errorf("duplicate served method %s", method.Path)
		}
		served[method.Path] = true
		if _, ok := access.Lookup(method.Path); !ok {
			t.Errorf("%s has no row", method.Path)
		}
	}
	if len(served) != len(expected) {
		t.Fatalf("%d served, want exactly %d registry/task/file/workspace methods", len(served), len(expected))
	}
	for _, name := range expected {
		if !served[fleetService+name] {
			t.Errorf("missing served method %s", name)
		}
	}
	h := registryHarness(t)
	user := h.db.Account(1)
	bearer := h.accountSession(user, session.ScopeAccount).AccessToken
	methods := fleetv1.File_arcforges_fleet_v1_fleet_proto.Services().ByName("FleetService").Methods()
	unserved := 0
	for index := range methods.Len() {
		path := fleetService + string(methods.Get(index).Name())
		if served[path] {
			continue
		}
		unserved++
		reply, err := nodetest.Client{URL: h.url, ClientIPHeader: config.ClientIPHeader}.Post(path, &fleetv1.FleetServiceListNodesRequest{Meta: &foundationv1.RequestMeta{}},
			bearer)
		if err != nil || reply.Status != "12" {
			t.Errorf("%s answers %q %q %v", path, reply.Status, reply.Message, err)
		}
	}
	if unserved != 9 {
		t.Fatalf("%d unserved FleetService methods, CTR5-API-01 lists 9", unserved)
	}
	if methods.ByName(protoreflect.Name("SendNodeCommand")) == nil {
		t.Fatal("the descriptor has no SendNodeCommand")
	}
	off := newHarness(t, settings{})
	for path := range served {
		response := &fleetv1.FleetServiceListNodesResponse{}
		off.rpc(path, &fleetv1.FleetServiceListNodesRequest{Meta: &foundationv1.RequestMeta{}}, "", response)
		if errorKey(response.GetError()) != "STATE/not_activated" || response.GetError().GetDetails().GetState().GetReason() != "nodes" {
			t.Errorf("%s with the nodes surface off: %v", path, response.GetError())
		}
	}
}

// TestTheRegistryListsTheAccountsLiveNodes is E2-16 (CTR5-API-02): ListNodes answers the account's live enrollments, oldest first, each
// with its presence (ONLINE while its channel is open in this process, OFFLINE after, NEVER_CONNECTED before), its device, version, the
// end of its live credential (absent once it expired) and its reported name; another account's node, an unknown node and a revoked node
// are the same STATE/not_found
// for GetNode, and a revoked node is no longer listed.
func TestTheRegistryListsTheAccountsLiveNodes(t *testing.T) {
	h := registryHarness(t)
	user := h.db.Account(1)
	first, second := h.enrollIn(user), h.enrollIn(user)
	foreign := h.enroll()
	channel := h.connect(first)
	bearer := h.accountSession(user, session.ScopeAccount).AccessToken
	stored := func(node *enrolled) string {
		var version string
		if err := h.db.Migration.QueryRow(context.Background(), "SELECT version FROM fleet.node WHERE node_id = $1", node.node.ID).Scan(&version); err != nil {
			t.Fatal(err)
		}
		return version
	}
	nodes := h.listNodes(bearer, nil).GetValue().GetNodes()
	if len(nodes) != 2 || !proto.Equal(nodes[0].GetNodeId(), idValue(first.node.ID)) || !proto.Equal(nodes[1].GetNodeId(), idValue(second.node.ID)) {
		t.Fatalf("the account's nodes: %v", nodes)
	}
	for index, node := range []*enrolled{first, second} {
		got := nodes[index]
		want := fleetv1.NodeOnlineState_NODE_ONLINE_STATE_NEVER_CONNECTED
		if index == 0 {
			want = fleetv1.NodeOnlineState_NODE_ONLINE_STATE_ONLINE
		}
		if got.GetOnline() != want || got.GetName() != node.node.Name || got.GetReportedName() != node.node.Name || got.GetVersion() != stored(node) ||
			!proto.Equal(got.GetDeviceId(), idValue(node.result.DeviceID)) || got.GetCredentialExpiresAt() == nil || got.GetLastSeenAt() == nil ||
			got.GetEnrolledAt() == nil || got.GetSummary() != nil || len(got.GetHostNodeId().GetValue()) != 0 {
			t.Errorf("node %d: %v", index, got)
		}
	}
	_ = channel.WS.CloseNow()
	if !eventually(t, 5*time.Second, func() bool {
		return h.listNodes(bearer, nil).GetValue().GetNodes()[0].GetOnline() == fleetv1.NodeOnlineState_NODE_ONLINE_STATE_OFFLINE
	}) {
		t.Fatal("a node whose channel closed is OFFLINE")
	}
	if got := h.getNode(bearer, &fleetv1.FleetServiceGetNodeRequest{Meta: &foundationv1.RequestMeta{}, NodeId: idValue(first.node.ID)}).GetValue(); !proto.Equal(
		got.GetNode().GetNodeId(), idValue(first.node.ID)) || len(got.GetRecentCommands()) != 0 {
		t.Fatalf("GetNode: %v", got)
	}
	// A credential that ended without a revocation is no live credential (review B N-3): credential_expires_at is absent.
	h.db.Exec("UPDATE identity.session SET expires_at = issued_at + interval '1 millisecond', refresh_expires_at = issued_at + interval '1 millisecond' " +
		"WHERE installation_id = '" + second.result.InstallationID.String() + "'")
	if listed := h.listNodes(bearer, nil).GetValue().GetNodes()[1]; listed.GetCredentialExpiresAt() != nil {
		t.Fatalf("an expired credential: %v", listed)
	}
	h.db.Exec("UPDATE fleet.node SET revoked_at = now(), revoke_reason = 1 WHERE node_id = '" + second.node.ID.String() + "'")
	var replies []string
	for _, nodeID := range []platform.ID{foreign.node.ID, platform.NewID(), second.node.ID} {
		failure := h.getNode(bearer, &fleetv1.FleetServiceGetNodeRequest{Meta: &foundationv1.RequestMeta{}, NodeId: idValue(nodeID)}).GetError()
		replies = append(replies, errorKey(failure)+" "+failure.GetDetails().GetState().GetResource().GetKind())
	}
	if replies[0] != "STATE/not_found node" || replies[1] != replies[0] || replies[2] != replies[0] {
		t.Fatalf("another account's, an unknown and a revoked node: %v", replies)
	}
	if nodes = h.listNodes(bearer, nil).GetValue().GetNodes(); len(nodes) != 1 {
		t.Fatalf("a revoked node is listed: %v", nodes)
	}
}

// TestATokenWithoutTheNodeKeyReadsNothing (C-N6; Design 11 T-19 "a token without the node key cannot relay"; decisions B-4): a node
// credential reads the registry only with a relay assertion the authorizer verified. Without one ListNodes and GetNode are refused
// AUTHENTICATION/unauthenticated (relay_assertion missing), and so is a caller without an assertion; a valid assertion of the node's
// own key over a nonce of its channel admits the read once (a replay is nonce_reused); an assertion for another target, another origin
// or a changed request field is request_mismatch; another node's credential presenting it is signature_invalid. No refusal and no read
// writes anything.
func TestATokenWithoutTheNodeKeyReadsNothing(t *testing.T) {
	h := registryHarness(t)
	user := h.db.Account(1)
	node, other := h.enrollIn(user), h.enrollIn(user)
	channel := h.connect(node)
	before := h.writes()
	refusal := func(failure *foundationv1.ArcError) string {
		return errorKey(failure) + " " + failure.GetDetails().GetState().GetState() + " " + failure.GetDetails().GetState().GetReason()
	}
	const missing = "AUTHENTICATION/unauthenticated relay_assertion missing"
	if got := refusal(h.listNodes(node.access, nil).GetError()); got != missing {
		t.Errorf("ListNodes with a bearer token alone: %s", got)
	}
	if got := refusal(h.getNode(node.access, &fleetv1.FleetServiceGetNodeRequest{Meta: &foundationv1.RequestMeta{}, NodeId: idValue(node.node.ID)}).GetError()); got != missing {
		t.Errorf("GetNode with a bearer token alone: %s", got)
	}
	if got := refusal(h.listNodes(node.access, &fleetv1.FleetServiceListNodesRequest{Meta: &foundationv1.RequestMeta{},
		Caller: relayedCaller(node, nodev1.Origin_ORIGIN_HUMAN)}).GetError()); got != missing {
		t.Errorf("a caller without an assertion: %s", got)
	}
	// A valid assertion admits the read once.
	list := &fleetv1.FleetServiceListNodesRequest{Meta: &foundationv1.RequestMeta{}, Caller: relayedCaller(node, nodev1.Origin_ORIGIN_SCRIPT)}
	sign(t, node, channel, list, hub.MethodListNodes, nil, nodev1.Origin_ORIGIN_SCRIPT, func(data []byte) { list.RelayAssertion = data })
	if nodes := h.listNodes(node.access, list).GetValue().GetNodes(); len(nodes) != 2 {
		t.Fatalf("a relayed ListNodes: %v", h.listNodes(node.access, list))
	}
	if got := refusal(h.listNodes(node.access, list).GetError()); got != "AUTHENTICATION/unauthenticated relay_assertion nonce_reused" {
		t.Errorf("a replayed assertion: %s", got)
	}
	get := &fleetv1.FleetServiceGetNodeRequest{Meta: &foundationv1.RequestMeta{}, NodeId: idValue(other.node.ID), Caller: relayedCaller(node, nodev1.Origin_ORIGIN_HUMAN)}
	target := other.node.ID
	sign(t, node, channel, get, hub.MethodGetNode, &target, nodev1.Origin_ORIGIN_HUMAN, func(data []byte) { get.RelayAssertion = data })
	if got := h.getNode(node.access, get).GetValue().GetNode(); !proto.Equal(got.GetNodeId(), idValue(other.node.ID)) {
		t.Fatalf("a relayed GetNode of another node of the account: %v", got)
	}
	mismatches := map[string]func() proto.Message{
		"another target": func() proto.Message {
			request := &fleetv1.FleetServiceGetNodeRequest{Meta: &foundationv1.RequestMeta{}, NodeId: idValue(other.node.ID), Caller: relayedCaller(node, nodev1.Origin_ORIGIN_HUMAN)}
			own := node.node.ID
			sign(t, node, channel, request, hub.MethodGetNode, &own, nodev1.Origin_ORIGIN_HUMAN, func(data []byte) { request.RelayAssertion = data })
			return request
		},
		"another origin": func() proto.Message {
			request := &fleetv1.FleetServiceListNodesRequest{Meta: &foundationv1.RequestMeta{}, Caller: relayedCaller(node, nodev1.Origin_ORIGIN_HUMAN)}
			sign(t, node, channel, request, hub.MethodListNodes, nil, nodev1.Origin_ORIGIN_AGENT, func(data []byte) { request.RelayAssertion = data })
			return request
		},
		"a field changed after signing": func() proto.Message {
			request := &fleetv1.FleetServiceListNodesRequest{Meta: &foundationv1.RequestMeta{}, Caller: relayedCaller(node, nodev1.Origin_ORIGIN_HUMAN)}
			sign(t, node, channel, request, hub.MethodListNodes, nil, nodev1.Origin_ORIGIN_HUMAN, func(data []byte) { request.RelayAssertion = data })
			request.Meta = &foundationv1.RequestMeta{CommandId: idValue(platform.NewID())}
			return request
		},
	}
	for name, build := range mismatches {
		request := build()
		var failure *foundationv1.ArcError
		switch typed := request.(type) {
		case *fleetv1.FleetServiceListNodesRequest:
			failure = h.listNodes(node.access, typed).GetError()
		case *fleetv1.FleetServiceGetNodeRequest:
			failure = h.getNode(node.access, typed).GetError()
		}
		if got := refusal(failure); got != "AUTHENTICATION/unauthenticated relay_assertion request_mismatch" {
			t.Errorf("%s: %s", name, got)
		}
	}
	stolen := &fleetv1.FleetServiceListNodesRequest{Meta: &foundationv1.RequestMeta{}, Caller: relayedCaller(node, nodev1.Origin_ORIGIN_HUMAN)}
	sign(t, node, channel, stolen, hub.MethodListNodes, nil, nodev1.Origin_ORIGIN_HUMAN, func(data []byte) { stolen.RelayAssertion = data })
	if got := refusal(h.listNodes(other.access, stolen).GetError()); got != "AUTHENTICATION/unauthenticated relay_assertion signature_invalid" {
		t.Errorf("another node's credential with this node's assertion: %s", got)
	}
	if after := h.writes(); after != before {
		t.Fatalf("the registry's relayed reads and refusals wrote %d rows or revisions", after-before)
	}
}

// TestAPersonSessionCannotSendANodeRelayCaller is E2-19's person half (Plan CTR5-SUR-03, SEC-10): an account session whose request
// names a NODE_RELAY caller or carries a relay assertion is refused AUTHORIZATION/permission_denied (the principal) and audited
// access.refused; an automation credential is refused the same way (an AGENT that is no relayed caller); a routed caller of another kind
// is VALIDATION/invalid_argument (caller.kind), refused before authorization and not audited.
func TestAPersonSessionCannotSendANodeRelayCaller(t *testing.T) {
	h := registryHarness(t)
	user := h.db.Account(1)
	node := h.enrollIn(user)
	bearer := h.accountSession(user, session.ScopeAccount).AccessToken
	automation := h.accountSession(user, session.ScopeAutomation).AccessToken
	for name, c := range map[string]struct {
		bearer  string
		request *fleetv1.FleetServiceListNodesRequest
	}{
		"a NODE_RELAY caller":      {bearer, &fleetv1.FleetServiceListNodesRequest{Meta: &foundationv1.RequestMeta{}, Caller: relayedCaller(node, nodev1.Origin_ORIGIN_HUMAN)}},
		"an assertion":             {bearer, &fleetv1.FleetServiceListNodesRequest{Meta: &foundationv1.RequestMeta{}, RelayAssertion: []byte{1}}},
		"an automation credential": {automation, nil},
	} {
		before := h.audits(access.AuditRefused)
		failure := h.listNodes(c.bearer, c.request).GetError()
		if errorKey(failure) != "AUTHORIZATION/permission_denied" || failure.GetDetails().GetState().GetReason() != "fleet.listNodes" ||
			h.audits(access.AuditRefused) != before+1 {
			t.Errorf("%s: %v", name, failure)
		}
	}
	other := relayedCaller(node, nodev1.Origin_ORIGIN_HUMAN)
	other.Kind = fleetv1.CallerKind_CALLER_KIND_ACCOUNT_SESSION.Enum()
	before := h.audits(access.AuditRefused)
	failure := h.listNodes(bearer, &fleetv1.FleetServiceListNodesRequest{Meta: &foundationv1.RequestMeta{}, Caller: other}).GetError()
	if errorKey(failure) != "VALIDATION/invalid_argument" || failure.GetDetails().GetState().GetReason() != "caller.kind: not_admitted" ||
		h.audits(access.AuditRefused) != before {
		t.Errorf("a routed caller of another kind: %v", failure)
	}
}

// TestAMobileLimitedSessionReadsTheRegistryButUpgradesToChangeIt (T-19, PB-1): a mobile.limited session lists and reads the nodes;
// RenameNode and RevokeNode answer it AUTHENTICATION/step_up_required (retry the same command after the upgrade) without writing
// anything.
func TestAMobileLimitedSessionReadsTheRegistryButUpgradesToChangeIt(t *testing.T) {
	h := registryHarness(t)
	user := h.db.Account(1)
	node := h.enrollIn(user)
	limited := h.accountSession(user, session.ScopeMobileLimited).AccessToken
	before := h.writes()
	if nodes := h.listNodes(limited, nil).GetValue().GetNodes(); len(nodes) != 1 {
		t.Fatalf("a mobile.limited ListNodes: %v", nodes)
	}
	name := "Renamed"
	for path, failure := range map[string]*foundationv1.ArcError{
		"RenameNode": h.renameNode(limited, commandMeta(), node.node.ID, &name).GetError(),
		"RevokeNode": h.revokeNode(limited, commandMeta(), node.node.ID).GetError(),
	} {
		if errorKey(failure) != "AUTHENTICATION/step_up_required" || failure.GetRetry().GetMode() != foundationv1.RetryMode_RETRY_MODE_SAME_COMMAND {
			t.Errorf("%s: %v", path, failure)
		}
	}
	if after := h.writes(); after != before {
		t.Fatalf("a mobile.limited session wrote %d rows or revisions", after-before)
	}
}

// TestRenameNodeKeepsTheReportedNameAndTheNodeAdoptsIt is E2-17 (CTR5-API-03, Q25): RenameNode gives the node and its device the
// account's name under a receipt (a replay answers the same node; another name under the same command is command_id_reused) and audits
// fleet.node.renamed without the name; the node's later report keeps its own name as reported_name and changes neither the node's nor the
// device's name; the node receives the account's name at its next accepted channel (ChannelAccepted.node_name). A name outside the node
// name rule is VALIDATION/invalid_argument.
func TestRenameNodeKeepsTheReportedNameAndTheNodeAdoptsIt(t *testing.T) {
	h := registryHarness(t)
	user := h.db.Account(1)
	node := h.enrollIn(user)
	bearer := h.accountSession(user, session.ScopeAccount).AccessToken
	name := "Build server"
	meta := commandMeta()
	renamed := h.renameNode(bearer, meta, node.node.ID, &name).GetValue().GetNode()
	if renamed.GetName() != name || renamed.GetReportedName() != node.node.Name {
		t.Fatalf("the renamed node: %v", renamed)
	}
	if replay := h.renameNode(bearer, meta, node.node.ID, &name).GetValue().GetNode(); !proto.Equal(replay, renamed) {
		t.Fatalf("a replay: %v", replay)
	}
	other := "Another"
	if failure := h.renameNode(bearer, meta, node.node.ID, &other).GetError(); errorKey(failure) != "CONFLICT/command_id_reused" {
		t.Fatalf("another name under the same command: %v", failure)
	}
	deviceName := func() string {
		var value string
		if err := h.db.Migration.QueryRow(context.Background(), "SELECT display_name FROM device.device WHERE device_id = $1", node.result.DeviceID).Scan(&value); err != nil {
			t.Fatal(err)
		}
		return value
	}
	if deviceName() != name || h.audits("fleet.node.renamed") != 1 || h.count("SELECT count(*) FROM audit.audit_event WHERE convert_from(payload, 'UTF8') LIKE '%Build server%'") != 0 {
		t.Fatal("the device takes the name and the audit carries none")
	}
	info := node.node.Info()
	info.Name = proto.String("box-2")
	report := &fleetv1.NodeEnrollmentServiceReportNodeInfoResponse{}
	h.rpc("/arcforges.fleet.v1.NodeEnrollmentService/ReportNodeInfo", &fleetv1.NodeEnrollmentServiceReportNodeInfoRequest{Meta: commandMeta(), Node: info}, node.access,
		report)
	if report.GetError() != nil {
		t.Fatalf("the node's report: %v", report.GetError())
	}
	listed := h.listNodes(bearer, nil).GetValue().GetNodes()[0]
	if listed.GetName() != name || listed.GetReportedName() != "box-2" || deviceName() != name {
		t.Fatalf("after the node's report: %v, device %q", listed, deviceName())
	}
	channel, err := h.dial(node.access, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = channel.WS.CloseNow() })
	ctx, cancel := background()
	defer cancel()
	if err = channel.Hello(ctx, node.node, node.result.InstallationID, publicBaseURL); err != nil {
		t.Fatal(err)
	}
	accepted, err := channel.Accept(ctx)
	if err != nil || accepted.GetNodeName() != name {
		t.Fatalf("ChannelAccepted.node_name: %v %v", accepted, err)
	}
	for value, reason := range map[string]string{"": "pattern", strings.Repeat("n", 65): "length", "build\nbox": "pattern"} {
		failure := h.renameNode(bearer, commandMeta(), node.node.ID, &value).GetError()
		if errorKey(failure) != "VALIDATION/invalid_argument" || failure.GetDetails().GetState().GetReason() != "name: "+reason {
			t.Errorf("the name %q: %v", value, failure)
		}
	}
	if failure := h.renameNode(bearer, commandMeta(), node.node.ID, nil).GetError(); errorKey(failure) != "VALIDATION/invalid_argument" {
		t.Errorf("no name: %v", failure)
	}
}

// TestRevokeNodeNeedsEvidenceBoundToTheNode is E2-18 (CTR5-API-04, the node target kind): RevokeNode without step-up evidence, or with
// evidence bound to another node, is AUTHENTICATION/step_up_required and writes nothing; with evidence of class fleet.revokeNode bound
// to the node it revokes the node's device with the cascade (the channel closes 4401, the node is no longer listed) and audits
// device.revoked; a replay of the command answers the same receipt, and a new command for the revoked node is STATE/not_found.
func TestRevokeNodeNeedsEvidenceBoundToTheNode(t *testing.T) {
	h := registryHarness(t)
	user := h.db.Account(1)
	node, other := h.enrollIn(user), h.enrollIn(user)
	closed := answer(h.connect(node))
	issued := h.accountSession(user, session.ScopeAccount)
	proved := dbtest.Session{ID: issued.SessionID, User: user}
	target := func(nodeID platform.ID) []byte {
		value, err := hex.DecodeString(identity.TargetHash("fleet.revokeNode", user, nodeID))
		if err != nil {
			t.Fatal(err)
		}
		return value
	}
	before := h.writes()
	meta := commandMeta()
	if failure := h.revokeNode(issued.AccessToken, meta, node.node.ID).GetError(); errorKey(failure) != "AUTHENTICATION/step_up_required" {
		t.Fatalf("without evidence: %v", failure)
	}
	h.db.ProveStepUp(proved, "fleet.revokeNode", target(other.node.ID), time.Now())
	after := h.writes()
	if failure := h.revokeNode(issued.AccessToken, meta, node.node.ID).GetError(); errorKey(failure) != "AUTHENTICATION/step_up_required" {
		t.Fatalf("with evidence for another node: %v", failure)
	}
	if h.writes() != after || after-before != 1 {
		t.Fatalf("a refused revocation wrote: %d, %d", h.writes()-after, after-before)
	}
	h.db.ProveStepUp(proved, "fleet.revokeNode", target(node.node.ID), time.Now())
	receipt := h.revokeNode(issued.AccessToken, meta, node.node.ID).GetValue().GetReceipt()
	if receipt == nil || !proto.Equal(receipt.GetCommandId(), meta.GetCommandId()) || receipt.GetResultRevision() == nil {
		t.Fatalf("the revocation: %v", receipt)
	}
	if got := closedWithin(t, closed, 5*time.Second); got.Code != hub.CloseCredential {
		t.Fatalf("the revoked node's channel: %+v", got)
	}
	if replay := h.revokeNode(issued.AccessToken, meta, node.node.ID).GetValue().GetReceipt(); !proto.Equal(replay, receipt) {
		t.Fatalf("a replay: %v", replay)
	}
	h.db.ProveStepUp(proved, "fleet.revokeNode", target(node.node.ID), time.Now())
	if failure := h.revokeNode(issued.AccessToken, commandMeta(), node.node.ID).GetError(); errorKey(failure) != "STATE/not_found" {
		t.Fatalf("a new revocation of a revoked node: %v", failure)
	}
	nodes := h.listNodes(issued.AccessToken, nil).GetValue().GetNodes()
	if len(nodes) != 1 || !proto.Equal(nodes[0].GetNodeId(), idValue(other.node.ID)) || h.audits("device.revoked") != 1 {
		t.Fatalf("after the revocation: %v, %d device.revoked", nodes, h.audits("device.revoked"))
	}
	if failure := h.getNode(issued.AccessToken, &fleetv1.FleetServiceGetNodeRequest{Meta: &foundationv1.RequestMeta{}, NodeId: idValue(node.node.ID)}).GetError(); errorKey(
		failure) != "STATE/not_found" {
		t.Fatalf("GetNode of the revoked node: %v", failure)
	}
}

// TestAForeignNodeIsNotFoundAndWritesNothing (CTR5-SEC-17; review B B-3): RenameNode and RevokeNode of another account's node are
// STATE/not_found at the ownership stage, before any receipt, evidence or audit is written, even when the caller holds step-up evidence
// for that node ID; the owner's node is untouched.
func TestAForeignNodeIsNotFoundAndWritesNothing(t *testing.T) {
	h := registryHarness(t)
	owner, stranger := h.db.Account(1), h.db.Account(1)
	node := h.enrollIn(owner)
	issued := h.accountSession(stranger, session.ScopeAccount)
	target, err := hex.DecodeString(identity.TargetHash("fleet.revokeNode", stranger, node.node.ID))
	if err != nil {
		t.Fatal(err)
	}
	h.db.ProveStepUp(dbtest.Session{ID: issued.SessionID, User: stranger}, "fleet.revokeNode", target, time.Now())
	before, receipts := h.writes(), h.count("SELECT count(*) FROM platform.command_receipt")
	name := "Taken"
	if failure := h.renameNode(issued.AccessToken, commandMeta(), node.node.ID, &name).GetError(); errorKey(failure) != "STATE/not_found" {
		t.Fatalf("RenameNode of another account's node: %v", failure)
	}
	if failure := h.revokeNode(issued.AccessToken, commandMeta(), node.node.ID).GetError(); errorKey(failure) != "STATE/not_found" {
		t.Fatalf("RevokeNode of another account's node: %v", failure)
	}
	if after := h.writes(); after != before || h.count("SELECT count(*) FROM platform.command_receipt") != receipts {
		t.Fatalf("a foreign node's refusals wrote %d rows or revisions", after-before)
	}
	bearer := h.accountSession(owner, session.ScopeAccount).AccessToken
	if nodes := h.listNodes(bearer, nil).GetValue().GetNodes(); len(nodes) != 1 || nodes[0].GetName() != node.node.Name {
		t.Fatalf("the owner's node: %v", nodes)
	}
}

// enrollNode enrolls a given node (its ID and key) in an account through fleet.Enroll.
func (h *harness) enrollNode(user platform.ID, node *nodetest.Node) *enrolled {
	h.t.Helper()
	approver := h.db.Session(user, 1)
	info, err := fleet.ParseNodeInfo(node.Info())
	if err != nil {
		h.t.Fatal(err)
	}
	var result fleet.Enrolled
	if err = h.db.Runtime.InTx(context.Background(), "enroll", store.TxOptions{}, func(ctx context.Context, tx pgx.Tx) error {
		var err error
		result, err = fleet.Enroll(ctx, tx, h.policy, fleet.EnrollRequest{UserID: user, Approver: fleet.Approver{SessionID: approver.ID, AuthMethod: 1,
			AuthenticatedAt: time.Now().Add(-time.Minute)}, NodeID: node.ID, Node: info, PublicKey: node.PublicKey, Flow: fleet.FlowDevice}, time.Now())
		return err
	}); err != nil {
		h.t.Fatal(err)
	}
	h.secrets = append(h.secrets, result.Session.AccessToken, result.Session.RefreshToken)
	return &enrolled{node: node, user: user, result: result, access: result.Session.AccessToken}
}

// TestAReplayAfterTheNodeIsEnrolledElsewhereAnswersItsReceipt (review A B-4): account A renames, then revokes its node; the same node
// ID is then enrolled under account B. A's replays of both commands still answer their receipts (A's own enrollment is the owner of its
// receipted writes), a new command of A for the node is STATE/not_found, and B reads its node.
func TestAReplayAfterTheNodeIsEnrolledElsewhereAnswersItsReceipt(t *testing.T) {
	h := registryHarness(t)
	first, second := h.db.Account(1), h.db.Account(1)
	node := h.enrollIn(first)
	issued := h.accountSession(first, session.ScopeAccount)
	name := "Build server"
	renameMeta, revokeMeta := commandMeta(), commandMeta()
	renamed := h.renameNode(issued.AccessToken, renameMeta, node.node.ID, &name).GetValue().GetNode()
	target, err := hex.DecodeString(identity.TargetHash("fleet.revokeNode", first, node.node.ID))
	if err != nil {
		t.Fatal(err)
	}
	h.db.ProveStepUp(dbtest.Session{ID: issued.SessionID, User: first}, "fleet.revokeNode", target, time.Now())
	receipt := h.revokeNode(issued.AccessToken, revokeMeta, node.node.ID).GetValue().GetReceipt()
	if renamed == nil || receipt == nil {
		t.Fatalf("the commands: %v %v", renamed, receipt)
	}
	again, err := nodetest.New()
	if err != nil {
		t.Fatal(err)
	}
	again.ID = node.node.ID
	elsewhere := h.enrollNode(second, again)
	if replay := h.revokeNode(issued.AccessToken, revokeMeta, node.node.ID).GetValue().GetReceipt(); !proto.Equal(replay, receipt) {
		t.Fatalf("A's replayed revocation: %v", h.revokeNode(issued.AccessToken, revokeMeta, node.node.ID))
	}
	if replay := h.renameNode(issued.AccessToken, renameMeta, node.node.ID, &name).GetValue().GetNode(); !proto.Equal(replay, renamed) {
		t.Fatalf("A's replayed rename: %v", replay)
	}
	if failure := h.renameNode(issued.AccessToken, commandMeta(), node.node.ID, &name).GetError(); errorKey(failure) != "STATE/not_found" {
		t.Fatalf("A's new rename of the node: %v", failure)
	}
	bearer := h.accountSession(second, session.ScopeAccount).AccessToken
	if got := h.getNode(bearer, &fleetv1.FleetServiceGetNodeRequest{Meta: &foundationv1.RequestMeta{}, NodeId: idValue(node.node.ID)}).GetValue().GetNode(); !proto.Equal(
		got.GetDeviceId(), idValue(elsewhere.result.DeviceID)) || got.GetName() != again.Name {
		t.Fatalf("B's node: %v", got)
	}
}

// TestARenameOfAnEarlierRowKeepsTheReportedName (review B B-1): a node row from before 0009 has no reported_name; renaming it keeps the
// name the node reported as reported_name (in the rename's own UPDATE), and the node's next report of that name changes nothing (no
// fleet.node.info_reported).
func TestARenameOfAnEarlierRowKeepsTheReportedName(t *testing.T) {
	h := registryHarness(t)
	user := h.db.Account(1)
	node := h.enrollIn(user)
	h.db.Exec("UPDATE fleet.node SET reported_name = NULL WHERE node_id = '" + node.node.ID.String() + "'")
	bearer := h.accountSession(user, session.ScopeAccount).AccessToken
	if listed := h.listNodes(bearer, nil).GetValue().GetNodes()[0]; listed.GetReportedName() != node.node.Name {
		t.Fatalf("an earlier row's reported name: %v", listed)
	}
	name := "Account name"
	renamed := h.renameNode(bearer, commandMeta(), node.node.ID, &name).GetValue().GetNode()
	if renamed.GetName() != name || renamed.GetReportedName() != node.node.Name {
		t.Fatalf("the renamed earlier row: %v", renamed)
	}
	reports := h.audits("fleet.node.info_reported")
	report := &fleetv1.NodeEnrollmentServiceReportNodeInfoResponse{}
	h.rpc("/arcforges.fleet.v1.NodeEnrollmentService/ReportNodeInfo", &fleetv1.NodeEnrollmentServiceReportNodeInfoRequest{Meta: commandMeta(), Node: node.node.Info()},
		node.access, report)
	listed := h.listNodes(bearer, nil).GetValue().GetNodes()[0]
	if report.GetError() != nil || h.audits("fleet.node.info_reported") != reports || listed.GetName() != name || listed.GetReportedName() != node.node.Name {
		t.Fatalf("the node's next report: %v, %d reports audited, %v", report.GetError(), h.audits("fleet.node.info_reported")-reports, listed)
	}
}
