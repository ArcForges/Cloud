// SPDX-License-Identifier: AGPL-3.0-only

package fleet

import (
	"context"
	"encoding/hex"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/ArcForges/Cloud/center/internal/arc"
	"github.com/ArcForges/Cloud/center/internal/dbtest"
	"github.com/ArcForges/Cloud/center/internal/identity"
	"github.com/ArcForges/Cloud/center/internal/nodetest"
	"github.com/ArcForges/Cloud/center/internal/oneuse"
	"github.com/ArcForges/Cloud/center/internal/platform"
	"github.com/ArcForges/Cloud/center/internal/store"
)

// EVIDENCE: REAL PostgreSQL, the real fleet service (no transport) and the real Enroll; the node is MOCKED (center/internal/nodetest,
// a software ES256 key that builds the poll proof as the node does); the approving accounts, their browser sessions and their step-up
// evidence are SEEDED (dbtest). The served path with a real passkey step-up and the command receipt is fleetapi's
// TestDeviceCodeEndToEnd. The clock is the test clock the service and the seeded evidence share; the rate-limit windows follow it.

// authorization is a node's device-code sign-in in progress.
type authorization struct {
	node    *nodetest.Node
	started Started
}

// wide opens the entry budgets (the budget tests narrow them again).
func (s *signIns) wide() {
	s.policy.DeviceEntryPerAccount.Limit, s.policy.DeviceEntryPerPrefix.Limit, s.policy.NodePollPerPrefix.Limit = 10_000, 10_000, 10_000
	s.renew()
}

func (s *signIns) start(node *nodetest.Node) (*authorization, error) {
	s.t.Helper()
	in, err := ParseStart(node.StartRequest())
	if err != nil {
		s.t.Fatal(err)
	}
	started, err := s.service.Start(context.Background(), s.from, in)
	if err != nil {
		return nil, err
	}
	return &authorization{node: node, started: started}, nil
}

func (s *signIns) mustStart(node *nodetest.Node) *authorization {
	s.t.Helper()
	a, err := s.start(node)
	if err != nil {
		s.t.Fatal(err)
	}
	return a
}

// lookup is one entry of LookupDeviceCode by an account from the rig's address.
func (s *signIns) lookup(user platform.ID, session dbtest.Session, code string) (DeviceView, error) {
	return s.lookupFrom(s.from, user, session, code)
}

func (s *signIns) lookupFrom(from Request, user platform.ID, session dbtest.Session, code string) (DeviceView, error) {
	account := accountOf(user, session, s.clock.Now())
	entry, err := s.service.ReserveEntry(context.Background(), from, account, "lookup")
	if err != nil {
		return DeviceView{}, err
	}
	return s.service.Lookup(context.Background(), from, account, entry, code)
}

// decide is one entry of ApproveDeviceCode, as fleetapi runs it without the receipt: the decision count, the reservation, the decision
// in one transaction without retries, and the settlement.
func (s *signIns) decide(user platform.ID, session dbtest.Session, code string, approve bool) error {
	account := accountOf(user, session, s.clock.Now())
	if err := s.service.TakeDecision(context.Background(), s.from, account); err != nil {
		return err
	}
	entry, err := s.service.ReserveEntry(context.Background(), s.from, account, "device_decide")
	if err != nil {
		return err
	}
	err = s.db.Runtime.InTx(context.Background(), "decide a device code", store.TxOptions{Attempts: 1}, func(ctx context.Context, tx pgx.Tx) error {
		return s.service.DecideDevice(ctx, tx, s.from, account, entry, code, approve, approve, nil, s.clock.Now())
	})
	s.service.Settle(context.Background(), s.from, entry, err, "device_decide")
	return err
}

// proveCode seeds an account session's proved step-up for the approval of a user code.
func (s *signIns) proveCode(user platform.ID, session dbtest.Session, code string) {
	s.t.Helper()
	target, err := hex.DecodeString(identity.TextTargetHash(ClassApproveDeviceCode, user, code))
	if err != nil {
		s.t.Fatal(err)
	}
	s.db.ProveStepUp(session, ClassApproveDeviceCode, target, s.clock.Now())
}

// approveCode looks a code up and approves it by an account with seeded evidence.
func (s *signIns) approveCode(user platform.ID, session dbtest.Session, a *authorization) {
	s.t.Helper()
	if _, err := s.lookup(user, session, a.started.UserCode); err != nil {
		s.t.Fatal(err)
	}
	s.proveCode(user, session, a.started.UserCode)
	if err := s.decide(user, session, a.started.UserCode, true); err != nil {
		s.t.Fatal(err)
	}
}

// poll is the node's poll with its proof.
func (s *signIns) poll(a *authorization) (Polled, error) {
	return s.pollWith(a, a.started.DeviceCode, a.node.PollProof(audience, a.started.DeviceCode))
}

func (s *signIns) pollWith(a *authorization, deviceCode string, proof []byte) (Polled, error) {
	return s.service.Poll(context.Background(), s.from, PollRequest{DeviceCode: deviceCode, Proof: proof})
}

func (s *signIns) authorizationState(a *authorization) int16 {
	return int16(s.count("SELECT state FROM fleet.device_authorization WHERE authorization_id = $1", a.started.AuthorizationID))
}

// authorizationSnapshot is everything a refused entry or poll could change: the row, the live sessions, the node rows, the audit chain.
func (s *signIns) authorizationSnapshot(a *authorization) string {
	s.t.Helper()
	var row string
	if err := s.db.Migration.QueryRow(context.Background(), `SELECT to_jsonb(d)::text || (SELECT count(*) FROM identity.session WHERE revoked_at IS NULL)::text ||
(SELECT count(*) FROM fleet.node)::text || (SELECT count(*) FROM audit.audit_event)::text FROM fleet.device_authorization d WHERE authorization_id = $1`,
		a.started.AuthorizationID).Scan(&row); err != nil {
		s.t.Fatal(err)
	}
	return row
}

// available is the entries an account has left, read from a wrong entry's refusal of an unknown code (which itself costs one).
func limitOf(err error) (string, int64, int64) {
	refusal, ok := err.(*arc.Refusal)
	if !ok || refusal.Limit == nil {
		return "", -1, -1
	}
	available := int64(-1)
	if refusal.Limit.Available != nil {
		available = *refusal.Limit.Available
	}
	return refusal.Limit.Name, refusal.Limit.Maximum, available
}

// unknownCode is a well-formed user code that names no authorization.
const unknownCode = "BBBBBBBB"

// TestDeviceCodeSignInEnrollsTheNode (E2-2, domain level): Start, the review, the approval, the poll; the authorization is COMPLETED
// with its results, the credential is a node session of the approving account bound to a new device and installation holding the
// node key, the codes are stored only as digests, and the events are the approval and one fleet.node.enrolled of the device flow, the
// last event.
func TestDeviceCodeSignInEnrollsTheNode(t *testing.T) {
	s := newSignIns(t)
	node := s.newNode()
	a := s.mustStart(node)
	started := a.started
	if len(started.DeviceCode) != 43 || len(started.UserCode) != 8 || started.Interval != 5*time.Second ||
		!started.ExpiresAt.Equal(s.clock.Now().Add(600*time.Second)) || started.VerificationURI != nodetest.DerivedVerificationURI(audience) ||
		started.VerificationURIComplete != nodetest.DerivedVerificationURIComplete(audience, started.UserCode) ||
		started.VerificationURIComplete != audience+"/activate#code="+started.UserCode[:4]+"-"+started.UserCode[4:] {
		t.Fatalf("started %+v", started)
	}
	if polled, err := s.poll(a); err != nil || polled.State != AuthorizationPending || polled.Interval != 5*time.Second {
		t.Fatalf("the first poll: %+v %s", polled, key(err))
	}
	view, err := s.lookup(s.user, s.approver, started.UserCode)
	if err != nil || view.NodeID != node.ID || view.Name != "buildbox" || view.Version != "0.1.0-dev" || string(view.PublicKey) != string(node.PublicKey) {
		t.Fatalf("the review: %+v %s", view, key(err))
	}
	s.proveCode(s.user, s.approver, started.UserCode)
	if err = s.decide(s.user, s.approver, started.UserCode, true); err != nil {
		t.Fatal(err)
	}
	s.clock.advance(5 * time.Second)
	polled, err := s.poll(a)
	if err != nil || polled.State != AuthorizationApproved || polled.Completed == nil || polled.Completed.Account.ID != s.user {
		t.Fatalf("the delivering poll: %+v %s", polled, key(err))
	}
	enrolled := polled.Completed.Enrolled
	if s.count(`SELECT count(*) FROM identity.session WHERE session_id = $1 AND scope = 3 AND user_id = $2 AND installation_id = $3 AND product_id = 'arcforges-node'
AND auth_method = 1 AND revoked_at IS NULL`, enrolled.Session.SessionID, s.user, enrolled.InstallationID) != 1 {
		t.Fatal("no node session of the account")
	}
	if s.count(`SELECT count(*) FROM fleet.device_authorization WHERE authorization_id = $1 AND state = 6 AND session_id = $2 AND enrollment_id = $3
AND completed_at IS NOT NULL AND last_poll_at = completed_at AND lookups = 1 AND viewed_by = $4 AND user_id = $4 AND reused_at IS NULL`, started.AuthorizationID,
		enrolled.Session.SessionID, enrolled.EnrollmentID, s.user) != 1 {
		t.Fatal("the authorization is not COMPLETED with its results")
	}
	if s.count("SELECT count(*) FROM device.installation WHERE installation_id = $1 AND public_key = $2", enrolled.InstallationID, node.PublicKey) != 1 {
		t.Fatal("the installation does not hold the node key")
	}
	if s.count(`SELECT count(*) FROM fleet.device_authorization d WHERE strpos(to_jsonb(d)::text, $1) > 0 OR strpos(to_jsonb(d)::text, $2) > 0`,
		started.DeviceCode, started.UserCode) != 0 {
		t.Fatal("a code is stored in clear")
	}
	if s.count("SELECT count(*) FROM audit.audit_event WHERE event_type = 'fleet.device_authorization.approved' AND target_id = $1", started.AuthorizationID.String()) != 1 ||
		s.count(`SELECT count(*) FROM audit.audit_event WHERE sequence = (SELECT max(sequence) FROM audit.audit_event) AND event_type = 'fleet.node.enrolled'
AND convert_from(payload, 'UTF8')::jsonb->>'flow' = 'device'`) != 1 {
		t.Fatal("the audit events are missing")
	}
}

// TestStartRefusesAHeldKey (C0: "A node_public_key that an installation holds or held is refused before approval"): a key held by a
// live installation and by a revoked one is CONFLICT/already_exists node_key / already_registered, and nothing is written.
func TestStartRefusesAHeldKey(t *testing.T) {
	s := newSignIns(t)
	live := s.newNode()
	s.mustEnroll(s.request(live.ID, live.PublicKey))
	revoked := s.newNode()
	enrolled := s.mustEnroll(s.request(revoked.ID, revoked.PublicKey))
	if err := s.revokeDevice(enrolled.DeviceID); err != nil {
		t.Fatal(err)
	}
	for _, node := range []*nodetest.Node{live, revoked} {
		if _, err := s.start(node); key(err) != "CONFLICT/already_exists node_key/already_registered" {
			t.Fatalf("a held key: %s", key(err))
		}
	}
	if s.count("SELECT count(*) FROM fleet.device_authorization") != 0 {
		t.Fatal("a refused Start wrote an authorization")
	}
}

// TestStartSupersedesOnlyPendingAuthorizationsOfTheSameKey (Q21): a newer Start of the node ID with the same key expires its PENDING
// authorizations; one with another key, an APPROVED one and a browser flow of the node are left alone.
func TestStartSupersedesOnlyPendingAuthorizationsOfTheSameKey(t *testing.T) {
	s := newSignIns(t)
	node := s.newNode()
	first := s.mustStart(node)
	approved := s.mustStart(s.newNode())
	s.approveCode(s.user, s.approver, approved)
	flow := s.mustBegin(node)
	other := *node
	other.PublicKey = s.newNode().PublicKey
	if _, err := s.start(&other); err != nil {
		t.Fatal(err)
	}
	if s.authorizationState(first) != AuthorizationPending {
		t.Fatal("a Start with another key superseded the node's authorization")
	}
	second := s.mustStart(node)
	if s.authorizationState(first) != AuthorizationExpired || s.authorizationState(second) != AuthorizationPending ||
		s.authorizationState(approved) != AuthorizationApproved || s.state(flow) != FlowPending {
		t.Fatalf("states %d %d %d %d", s.authorizationState(first), s.authorizationState(second), s.authorizationState(approved), s.state(flow))
	}
}

// TestStartCountsTheBucketsOfBegin: Start and Begin share node_flow_prefix and node_flow_node.
func TestStartCountsTheBucketsOfBegin(t *testing.T) {
	s := newSignIns(t)
	s.policy.NodeFlowPerNode.Limit = 2
	s.renew()
	node := s.newNode()
	s.mustBegin(node)
	s.mustStart(node)
	if _, err := s.start(node); key(err) != "RESOURCE/rate_limited" {
		t.Fatalf("the third flow of a node ID: %s", key(err))
	}
	if name, _, _ := limitOf(func() error { _, err := s.start(node); return err }()); name != "node_flow_node" {
		t.Fatalf("the refusal names %q", name)
	}
}

// TestLiveUserCodeCollisionRetries (DEV-01): a drawn code that a PENDING or an APPROVED authorization holds is drawn again; five
// collisions are RESOURCE/overloaded with nothing inserted. The code source is replaced by the test (the package's unexported field).
func TestLiveUserCodeCollisionRetries(t *testing.T) {
	s := newSignIns(t)
	pending := s.mustStart(s.newNode())
	approved := s.mustStart(s.newNode())
	s.approveCode(s.user, s.approver, approved)
	denied := s.mustStart(s.newNode())
	if _, err := s.lookup(s.user, s.approver, denied.started.UserCode); err != nil {
		t.Fatal(err)
	}
	if err := s.decide(s.user, s.approver, denied.started.UserCode, false); err != nil {
		t.Fatal(err)
	}
	draws := []string{pending.started.UserCode, approved.started.UserCode, denied.started.UserCode}
	var mu sync.Mutex
	s.service.userCodes = func() string {
		mu.Lock()
		defer mu.Unlock()
		code := draws[0]
		draws = draws[1:]
		return code
	}
	a := s.mustStart(s.newNode())
	if a.started.UserCode != denied.started.UserCode || len(draws) != 0 {
		t.Fatalf("drawn %s, %d left", a.started.UserCode, len(draws))
	}
	s.service.userCodes = func() string { return pending.started.UserCode }
	before := s.count("SELECT count(*) FROM fleet.device_authorization")
	if _, err := s.start(s.newNode()); key(err) != "RESOURCE/overloaded" || s.count("SELECT count(*) FROM fleet.device_authorization") != before {
		t.Fatalf("five collisions: %s", key(err))
	}
}

// TestPollIntervalAndSlowDown (DEV-03, P(iii), OQ-7): the first poll is never early; a poll less than the interval less 500 ms after
// the previous one is SLOW_DOWN, the interval grows by 5 seconds up to 60 seconds and stays there (0004's CHECK holds), the poll is
// recorded and nothing else happens (an approved authorization is not delivered); a poll at the interval is answered by the state;
// expiry is told before SLOW_DOWN.
func TestPollIntervalAndSlowDown(t *testing.T) {
	s := newSignIns(t)
	a := s.mustStart(s.newNode())
	if polled, err := s.poll(a); err != nil || polled.State != AuthorizationPending {
		t.Fatalf("the first poll at once: %+v %s", polled, key(err))
	}
	s.approveCode(s.user, s.approver, a)
	want := 5 * time.Second
	for range 13 {
		s.clock.advance(2 * time.Second)
		polled, err := s.poll(a)
		want = min(want+5*time.Second, 60*time.Second)
		if err != nil || polled.State != AuthorizationSlowDown || polled.Interval != want ||
			s.count("SELECT interval_ms FROM fleet.device_authorization WHERE authorization_id = $1", a.started.AuthorizationID) != int(want.Milliseconds()) {
			t.Fatalf("an early poll: %+v %s, want %s", polled, key(err), want)
		}
	}
	if s.authorizationState(a) != AuthorizationApproved {
		t.Fatal("SLOW_DOWN delivered or changed the state")
	}
	s.clock.advance(59 * time.Second)
	if polled, err := s.poll(a); err != nil || polled.State != AuthorizationSlowDown {
		t.Fatalf("59 seconds into a 60-second interval: %+v %s", polled, key(err))
	}
	s.clock.advance(59*time.Second + 600*time.Millisecond)
	if polled, err := s.poll(a); err != nil || polled.State != AuthorizationApproved || polled.Completed == nil {
		t.Fatalf("a poll at the interval less 400 ms: %+v %s", polled, key(err))
	}
	b := s.mustStart(s.newNode())
	if _, err := s.poll(b); err != nil {
		t.Fatal(err)
	}
	s.clock.advance(600 * time.Second)
	if polled, err := s.poll(b); err != nil || polled.State != AuthorizationExpired || s.authorizationState(b) != AuthorizationExpired {
		t.Fatalf("a poll after the expiry: %+v %s", polled, key(err))
	}
	if polled, err := s.poll(b); err != nil || polled.State != AuthorizationExpired {
		t.Fatalf("an early poll of an expired authorization: %+v %s", polled, key(err))
	}
}

// TestPollRateLimit (DEV-03, cloud-5): the seventh proved poll of one authorization within 10 seconds is RESOURCE/rate_limited
// (node_poll_authorization) and writes nothing; the bucket is counted before SLOW_DOWN decides, so early polls count in it.
func TestPollRateLimit(t *testing.T) {
	s := newSignIns(t)
	a := s.mustStart(s.newNode())
	for i := range 6 {
		if _, err := s.poll(a); err != nil {
			t.Fatalf("poll %d: %s", i+1, key(err))
		}
	}
	_, err := s.poll(a)
	if name, maximum, _ := limitOf(err); key(err) != "RESOURCE/rate_limited" || name != "node_poll_authorization" || maximum != 6 {
		t.Fatalf("the seventh poll: %s %s", key(err), name)
	}
	if s.count("SELECT count(*) FROM audit.audit_event WHERE event_type = 'identity.rate_limited' AND reason = 'node_poll_authorization'") != 1 {
		t.Fatal("the first refusal of the window is not audited")
	}
	if s.count("SELECT rev FROM fleet.device_authorization WHERE authorization_id = $1", a.started.AuthorizationID) != 7 {
		t.Fatal("the refused poll wrote the authorization")
	}
	s.clock.advance(10 * time.Second)
	if _, err = s.poll(a); err != nil {
		t.Fatalf("the next window: %s", key(err))
	}
}

// TestUnknownDeviceCodePollsDoNotStopAValidPoll (protocol-8): polls that name nothing, and polls whose proof fails, fill the client
// prefix's failure bucket and are then refused; a proved poll from the same prefix never waits on it.
func TestUnknownDeviceCodePollsDoNotStopAValidPoll(t *testing.T) {
	s := newSignIns(t)
	s.policy.NodePollPerPrefix.Limit = 5
	s.renew()
	a := s.mustStart(s.newNode())
	junk, _ := oneuse.NewCode()
	for i := range 3 {
		if _, err := s.pollWith(a, junk, a.node.PollProof(audience, junk)); key(err) != "STATE/not_found device_authorization/not_found" {
			t.Fatalf("unknown poll %d: %s", i, key(err))
		}
	}
	if _, err := s.pollWith(a, "not a code", a.node.PollProof(audience, "x")); key(err) != "STATE/not_found device_authorization/not_found" {
		t.Fatalf("a malformed code: %s", key(err))
	}
	if _, err := s.pollWith(a, a.started.DeviceCode, a.node.PollProof(audience+"/other", a.started.DeviceCode)); key(err) != "AUTHENTICATION/unauthenticated" {
		t.Fatalf("a bad proof: %s", key(err))
	}
	if _, err := s.pollWith(a, junk, a.node.PollProof(audience, junk)); key(err) != "RESOURCE/rate_limited" {
		t.Fatalf("the full bucket: %s", key(err))
	}
	if polled, err := s.poll(a); err != nil || polled.State != AuthorizationPending {
		t.Fatalf("the proved poll from the same prefix: %+v %s", polled, key(err))
	}
	other := s.mustStart(s.newNode())
	if _, err := s.pollWith(other, other.started.DeviceCode, other.node.PollProof(audience+"/x", other.started.DeviceCode)); key(err) != "RESOURCE/rate_limited" {
		t.Fatalf("a bad proof once the bucket is full: %s", key(err))
	}
}

// TestPollWithABadKeyProof (P(v), protocol-19 item 4, OQ-2): a proof over another device code, by another node ID, by another key,
// for another center URL (same host other path, other host), of the browser sign-in's purpose, a high-S proof and r = 0 are
// AUTHENTICATION/unauthenticated in every state, and nothing of the authorization, the sessions, the nodes or the audit changes (an
// APPROVED authorization stays APPROVED and is delivered afterwards).
func TestPollWithABadKeyProof(t *testing.T) {
	s := newSignIns(t)
	s.wide()
	pending := s.mustStart(s.newNode())
	approved := s.mustStart(s.newNode())
	s.approveCode(s.user, s.approver, approved)
	denied := s.mustStart(s.newNode())
	if _, err := s.lookup(s.user, s.approver, denied.started.UserCode); err != nil {
		t.Fatal(err)
	}
	if err := s.decide(s.user, s.approver, denied.started.UserCode, false); err != nil {
		t.Fatal(err)
	}
	completed := s.mustStart(s.newNode())
	s.approveCode(s.user, s.approver, completed)
	s.clock.advance(5 * time.Second)
	if _, err := s.poll(completed); err != nil {
		t.Fatal(err)
	}
	for _, a := range []*authorization{pending, approved, denied, completed} {
		code := a.started.DeviceCode
		stranger := s.newNode()
		impostor := *a.node
		impostor.ID = stranger.ID
		thief := *a.node
		thief.Key = stranger.Key
		zero := a.node.PollProof(audience, code)
		copy(zero[:32], make([]byte, 32))
		for name, proof := range map[string][]byte{
			"other device code": a.node.PollProof(audience, completed.started.DeviceCode+"x"),
			"other node ID":     impostor.PollProof(audience, code),
			"other key":         thief.PollProof(audience, code),
			"other path":        a.node.PollProof("https://center.example.test/other", code),
			"other host":        a.node.PollProof("https://other.example.test/api", code),
			"purpose 0x01":      a.node.Sign(0x01, audience, []byte(code)),
			"high-S":            a.node.SignMessage(nodetest.ProofMessage(0x02, audience, a.node.ID, []byte(code)), false),
			"r = 0":             zero,
		} {
			before := s.authorizationSnapshot(a)
			if _, err := s.pollWith(a, code, proof); key(err) != "AUTHENTICATION/unauthenticated" || s.authorizationSnapshot(a) != before {
				t.Fatalf("state %d, %s: %s", s.authorizationState(a), name, key(err))
			}
		}
	}
	s.clock.advance(5 * time.Second)
	if polled, err := s.poll(approved); err != nil || polled.State != AuthorizationApproved || polled.Completed == nil {
		t.Fatalf("the approved authorization after the bad proofs: %+v %s", polled, key(err))
	}
}

// TestDeviceCodeSecondPollRevokesCredentials (SEC-03, DEV-08): the first poll after delivery records the reuse once, revokes the
// delivered credential family (reason 8) and answers COMPLETED without credentials, audited once; later polls answer COMPLETED and
// write nothing.
func TestDeviceCodeSecondPollRevokesCredentials(t *testing.T) {
	s := newSignIns(t)
	a := s.mustStart(s.newNode())
	s.approveCode(s.user, s.approver, a)
	s.clock.advance(5 * time.Second)
	delivered, err := s.poll(a)
	if err != nil || delivered.Completed == nil {
		t.Fatal(key(err))
	}
	s.clock.advance(5 * time.Second)
	polled, err := s.poll(a)
	if err != nil || polled.State != AuthorizationCompleted || polled.Completed != nil {
		t.Fatalf("the second poll: %+v %s", polled, key(err))
	}
	if s.count("SELECT count(*) FROM identity.session WHERE session_id = $1 AND revoke_reason = 8", delivered.Completed.Enrolled.Session.SessionID) != 1 ||
		s.count("SELECT count(*) FROM fleet.device_authorization WHERE authorization_id = $1 AND reused_at IS NOT NULL AND state = 6", a.started.AuthorizationID) != 1 ||
		s.count("SELECT count(*) FROM audit.audit_event WHERE event_type = 'fleet.device_authorization.code_reused'") != 1 {
		t.Fatal("the reuse is not recorded and revoked once")
	}
	before := s.authorizationSnapshot(a)
	s.clock.advance(5 * time.Second)
	if polled, err = s.poll(a); err != nil || polled.State != AuthorizationCompleted || s.authorizationSnapshot(a) != before {
		t.Fatalf("a later poll: %+v %s", polled, key(err))
	}
}

// TestAnApprovedAuthorizationNotPolledExpires (DEV-09): an approval that no poll collects within the 600 seconds ends EXPIRED at the
// next poll; nothing was issued, so nothing is revoked; Lookup and the approver's decisions answer STATE/expired.
func TestAnApprovedAuthorizationNotPolledExpires(t *testing.T) {
	s := newSignIns(t)
	a := s.mustStart(s.newNode())
	s.approveCode(s.user, s.approver, a)
	s.clock.advance(600 * time.Second)
	if err := s.decide(s.user, s.approver, a.started.UserCode, false); key(err) != "STATE/expired" {
		t.Fatalf("a denial after the expiry: %s", key(err))
	}
	if _, err := s.lookup(s.user, s.approver, a.started.UserCode); key(err) != "STATE/expired" {
		t.Fatalf("a lookup after the expiry: %s", key(err))
	}
	if polled, err := s.poll(a); err != nil || polled.State != AuthorizationExpired || s.authorizationState(a) != AuthorizationExpired ||
		s.count("SELECT count(*) FROM identity.session WHERE scope = 3") != 0 {
		t.Fatalf("the poll: %+v %s", polled, key(err))
	}
}

// TestAPollEnrollRefusalLeavesTheAuthorizationApproved (d.1): a node ID live under another account is CONFLICT/already_exists node at
// the delivering poll; the transaction rolls back, the authorization stays APPROVED with nothing of the enrollment, and the identical
// retry answers the same rule.
func TestAPollEnrollRefusalLeavesTheAuthorizationApproved(t *testing.T) {
	s := newSignIns(t)
	node := s.newNode()
	other, otherSession := s.account(1)
	request := s.request(node.ID, nodeKey(t))
	request.UserID, request.Approver.SessionID = other, otherSession.ID
	s.mustEnroll(request)
	a := s.mustStart(node)
	s.approveCode(s.user, s.approver, a)
	for range 2 {
		s.clock.advance(5 * time.Second)
		before := s.authorizationSnapshot(a)
		if _, err := s.poll(a); key(err) != "CONFLICT/already_exists node/already_exists" {
			t.Fatalf("the delivering poll: %s", key(err))
		}
		if s.authorizationState(a) != AuthorizationApproved || s.authorizationSnapshot(a) != before {
			t.Fatal("a refused enrollment changed the authorization")
		}
	}
}

// TestDeviceApprovalDoesNotOutliveRevocationOfTheApproverSession (SEC-24, d.1): an approving session revoked by its account (2), with all
// sessions (3), with its device (5) or by an operator (6) lapses the approval at the delivering poll: EXPIRED, audited, no node; a
// sign-out (1) does not.
func TestDeviceApprovalDoesNotOutliveRevocationOfTheApproverSession(t *testing.T) {
	for reason, lapses := range map[int16]bool{1: false, 2: true, 3: true, 5: true, 6: true} {
		s := newSignIns(t)
		a := s.mustStart(s.newNode())
		s.approveCode(s.user, s.approver, a)
		s.db.Exec(fmt.Sprintf("UPDATE identity.session SET revoked_at = now(), revoke_reason = %d, rev = rev + 1 WHERE session_id = '%s'", reason, s.approver.ID))
		s.clock.advance(5 * time.Second)
		polled, err := s.poll(a)
		switch {
		case lapses && (err != nil || polled.State != AuthorizationExpired || s.authorizationState(a) != AuthorizationExpired ||
			s.count("SELECT count(*) FROM device.installation WHERE product_id = 'arcforges-node'") != 0 ||
			s.count("SELECT count(*) FROM audit.audit_event WHERE event_type = 'fleet.device_authorization.approval_lapsed'") != 1):
			t.Fatalf("reason %d: %+v %s", reason, polled, key(err))
		case !lapses && (err != nil || polled.State != AuthorizationApproved || s.authorizationState(a) != AuthorizationCompleted):
			t.Fatalf("reason %d: %+v %s", reason, polled, key(err))
		}
	}
}

// TestCodesOfOneFlowKindNeverWorkInTheOther (SEC-11, E2-5): a device code is no browser sign-in code and a browser code no device code;
// a flow ID is no user code; a Complete proof (purpose 0x01) is refused at Poll and a Poll proof (0x02) at Complete.
func TestCodesOfOneFlowKindNeverWorkInTheOther(t *testing.T) {
	s := newSignIns(t)
	s.wide()
	node := s.newNode()
	a := s.mustStart(node)
	s.approveCode(s.user, s.approver, a)
	f := s.mustBegin(s.newNode())
	s.approve(f)
	if _, err := s.completeWith(f, a.started.DeviceCode, f.signIn.Verifier, f.node.CompleteProof(audience, f.id, a.started.DeviceCode)); key(err) != "AUTHENTICATION/unauthenticated" {
		t.Fatalf("a device code at Complete: %s", key(err))
	}
	if _, err := s.completeWith(f, f.code, f.signIn.Verifier, f.node.Sign(0x02, audience, []byte(f.code))); key(err) != "AUTHENTICATION/unauthenticated" {
		t.Fatalf("a poll proof at Complete: %s", key(err))
	}
	if _, err := s.pollWith(a, f.code, node.PollProof(audience, f.code)); key(err) != "STATE/not_found device_authorization/not_found" {
		t.Fatalf("a browser code at Poll: %s", key(err))
	}
	s.clock.advance(5 * time.Second)
	if _, err := s.pollWith(a, a.started.DeviceCode, node.Sign(0x01, audience, append(f.id[:], a.started.DeviceCode...))); key(err) != "AUTHENTICATION/unauthenticated" {
		t.Fatalf("a complete proof at Poll: %s", key(err))
	}
}

// TestATerminalAuthorizationIsNeverWritten (cloud-10 item 4): 0004's trigger refuses every change of a DENIED or EXPIRED
// authorization, and every change of a COMPLETED one except recording the reuse once; APPROVED to COMPLETED is a permitted change.
func TestATerminalAuthorizationIsNeverWritten(t *testing.T) {
	s := newSignIns(t)
	s.wide()
	ctx := context.Background()
	denied := s.mustStart(s.newNode())
	if _, err := s.lookup(s.user, s.approver, denied.started.UserCode); err != nil {
		t.Fatal(err)
	}
	if err := s.decide(s.user, s.approver, denied.started.UserCode, false); err != nil {
		t.Fatal(err)
	}
	expired := s.mustStart(s.newNode())
	s.clock.advance(600 * time.Second)
	if _, err := s.poll(expired); err != nil || s.authorizationState(expired) != AuthorizationExpired {
		t.Fatalf("the expiry: %s", key(err))
	}
	for _, final := range []*authorization{denied, expired} {
		for _, statement := range []string{"UPDATE fleet.device_authorization SET last_poll_at = now(), rev = rev + 1 WHERE authorization_id = $1",
			"UPDATE fleet.device_authorization SET state = 1, rev = rev + 1 WHERE authorization_id = $1",
			"UPDATE fleet.device_authorization SET reused_at = now(), rev = rev + 1 WHERE authorization_id = $1"} {
			if _, err := s.db.Runtime.Pool().Exec(ctx, statement, final.started.AuthorizationID); err == nil {
				t.Fatalf("a final authorization (state %d) took %s", s.authorizationState(final), statement)
			}
		}
	}
	a := s.mustStart(s.newNode())
	s.approveCode(s.user, s.approver, a)
	s.clock.advance(5 * time.Second)
	if _, err := s.poll(a); err != nil {
		t.Fatal(err)
	}
	update := func(statement string) error {
		_, err := s.db.Runtime.Pool().Exec(ctx, statement, a.started.AuthorizationID)
		return err
	}
	for _, statement := range []string{"UPDATE fleet.device_authorization SET last_poll_at = now(), rev = rev + 1 WHERE authorization_id = $1",
		"UPDATE fleet.device_authorization SET interval_ms = 10000, rev = rev + 1 WHERE authorization_id = $1",
		"UPDATE fleet.device_authorization SET state = 4, rev = rev + 1 WHERE authorization_id = $1"} {
		if update(statement) == nil {
			t.Fatalf("a COMPLETED authorization took %s", statement)
		}
	}
	if err := update("UPDATE fleet.device_authorization SET reused_at = now(), rev = rev + 1 WHERE authorization_id = $1"); err != nil {
		t.Fatalf("the reuse: %v", err)
	}
	if update("UPDATE fleet.device_authorization SET reused_at = now() + interval '1 second', rev = rev + 1 WHERE authorization_id = $1") == nil {
		t.Fatal("the reuse was recorded twice")
	}
}
