// SPDX-License-Identifier: AGPL-3.0-only

package fleet

import (
	"context"
	"encoding/hex"
	"fmt"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/ArcForges/Cloud/center/internal/dbtest"
	"github.com/ArcForges/Cloud/center/internal/device"
	"github.com/ArcForges/Cloud/center/internal/identity"
	"github.com/ArcForges/Cloud/center/internal/nodetest"
	"github.com/ArcForges/Cloud/center/internal/oneuse"
	"github.com/ArcForges/Cloud/center/internal/platform"
	"github.com/ArcForges/Cloud/center/internal/store"
)

// EVIDENCE: REAL PostgreSQL, the real fleet service (no transport) and the real Enroll; the node is MOCKED (center/internal/nodetest,
// a software ES256 key that builds the proof as the node does); the approving account, its browser session and its step-up evidence
// are SEEDED (dbtest: the proved challenge is inserted as the identity surface would have stored it; the served path with a real
// passkey step-up is fleetapi's TestBrowserSignInEndToEnd).

// clock is a test clock the sign-in service and the seeded evidence share.
type clock struct {
	mu  sync.Mutex
	now time.Time
}

func newClock() *clock { return &clock{now: time.Now().UTC().Truncate(time.Microsecond)} }

func (c *clock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *clock) advance(by time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now = c.now.Add(by)
}

// signIns is a rig with a sign-in service on its own clock.
type signIns struct {
	*rig
	clock   *clock
	service *Service
	from    Request
}

// newSignIns is a rig whose Begin and decision buckets are wide (the tests of the buckets narrow them), and whose sign-in transactions
// run without retries, so a deadlock fails a race test.
func newSignIns(t *testing.T) *signIns {
	t.Helper()
	r := newRig(t)
	r.policy.NodeFlowPerPrefix.Limit, r.policy.NodeFlowPerNode.Limit, r.policy.NodeApprovePerAccount.Limit = 10_000, 10_000, 10_000
	s := &signIns{rig: r, clock: newClock(), from: Request{ClientIP: netip.MustParseAddr("203.0.113.9")}}
	s.renew()
	return s
}

// renew builds the sign-in service again after a policy change.
func (s *signIns) renew() {
	s.service = New(Options{DB: s.db.Runtime, Policy: s.policy, Clock: s.clock.Now, PublicBaseURL: audience, SignInAttempts: 1})
}

// revokeDevice revokes a device as DeviceService.Revoke does under its evidence path (the account lock first), without retries.
func (s *signIns) revokeDevice(deviceID platform.ID) error {
	return s.db.Runtime.InTx(context.Background(), "revoke the node's device", store.TxOptions{Attempts: 1}, func(ctx context.Context, tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, "SELECT 1 FROM identity.user WHERE user_id = $1 FOR UPDATE", s.user); err != nil {
			return err
		}
		_, err := device.Revoke(ctx, tx, s.user, deviceID, device.RevokedByOwner, []device.Participant{NodeParticipant{}}, time.Now())
		return err
	})
}

// accountOf is an approving account's caller (its browser session at epochs zero, as dbtest seeds it).
func accountOf(user platform.ID, session dbtest.Session, at time.Time) Account {
	return Account{Caller: identity.Caller{UserID: user, SessionID: session.ID, DeviceID: session.DeviceID, Scope: "account", Browser: true},
		AuthMethod: 1, AuthenticatedAt: at.Add(-time.Minute)}
}

// flow is a node's browser sign-in in progress.
type flow struct {
	node   *nodetest.Node
	signIn nodetest.SignIn
	id     platform.ID
	url    string
	code   string
}

func (s *signIns) newNode() *nodetest.Node {
	s.t.Helper()
	node, err := nodetest.New()
	if err != nil {
		s.t.Fatal(err)
	}
	return node
}

// begin starts a flow for a node.
func (s *signIns) begin(node *nodetest.Node) (*flow, error) {
	s.t.Helper()
	signIn := nodetest.NewSignIn()
	in, err := ParseBegin(node.BeginRequest(signIn))
	if err != nil {
		s.t.Fatal(err)
	}
	begun, err := s.service.Begin(context.Background(), s.from, in)
	if err != nil {
		return nil, err
	}
	return &flow{node: node, signIn: signIn, id: begun.FlowID, url: begun.AuthorizeURL}, nil
}

func (s *signIns) mustBegin(node *nodetest.Node) *flow {
	s.t.Helper()
	f, err := s.begin(node)
	if err != nil {
		s.t.Fatal(err)
	}
	return f
}

// prove seeds the account session's proved step-up for the approval of a flow.
func (s *signIns) prove(user platform.ID, session dbtest.Session, flowID platform.ID) {
	s.t.Helper()
	target, err := hex.DecodeString(identity.TargetHash(ClassApproveNodeSignIn, user, flowID))
	if err != nil {
		s.t.Fatal(err)
	}
	s.db.ProveStepUp(session, ClassApproveNodeSignIn, target, s.clock.Now())
}

// review records the rig account's review of a flow.
func (s *signIns) review(user platform.ID, session dbtest.Session, f *flow) (FlowView, error) {
	return s.service.Review(context.Background(), accountOf(user, session, s.clock.Now()), f.id)
}

// approve reviews and approves a flow by the rig's account with seeded evidence and keeps the code the loopback receives.
func (s *signIns) approve(f *flow) {
	s.t.Helper()
	s.approveBy(s.user, s.approver, f)
}

func (s *signIns) approveBy(user platform.ID, session dbtest.Session, f *flow) {
	s.t.Helper()
	if _, err := s.review(user, session, f); err != nil {
		s.t.Fatal(err)
	}
	s.prove(user, session, f.id)
	decision, err := s.service.Decide(context.Background(), s.from, accountOf(user, session, s.clock.Now()), f.id, true, true)
	if err != nil {
		s.t.Fatal(err)
	}
	if f.code, err = f.signIn.LoopbackCode(decision.RedirectURL); err != nil {
		s.t.Fatal(err)
	}
}

// complete presents the flow's code with the node's verifier and proof.
func (s *signIns) complete(f *flow) (Completed, error) {
	return s.completeWith(f, f.code, f.signIn.Verifier, f.node.CompleteProof(audience, f.id, f.code))
}

func (s *signIns) completeWith(f *flow, code, verifier string, proof []byte) (Completed, error) {
	return s.service.Complete(context.Background(), s.from, CompleteRequest{FlowID: f.id, Code: code, Verifier: verifier, Proof: proof})
}

func (s *signIns) state(f *flow) int16 {
	return int16(s.count("SELECT state FROM fleet.node_sign_in WHERE flow_id = $1", f.id))
}

// snapshot is everything a presentation could change: the flow row, the sessions, the node rows and the audit chain.
func (s *signIns) snapshot(f *flow) string {
	s.t.Helper()
	var row string
	if err := s.db.Migration.QueryRow(context.Background(), `SELECT to_jsonb(f)::text || (SELECT count(*) FROM identity.session WHERE revoked_at IS NULL)::text ||
(SELECT count(*) FROM fleet.node)::text || (SELECT count(*) FROM audit.audit_event)::text FROM fleet.node_sign_in f WHERE flow_id = $1`, f.id).Scan(&row); err != nil {
		s.t.Fatal(err)
	}
	return row
}

// TestBrowserSignInEnrollsTheNode (E1-6, domain level): Begin, review, approval, completion; the credential is a node session of the
// approving account bound to the node's new device and installation, the flow COMPLETED with its results, the code stored only as a
// digest, and one fleet.node.enrolled of the pkce flow.
func TestBrowserSignInEnrollsTheNode(t *testing.T) {
	s := newSignIns(t)
	node := s.newNode()
	f := s.mustBegin(node)
	if f.url != nodetest.DerivedAuthorizeURL(audience, f.id[:]) || f.url != audience+"/connect#flow="+f.id.String() {
		t.Fatalf("authorize URL %q", f.url)
	}
	s.approve(f)
	completed, err := s.complete(f)
	if err != nil {
		t.Fatal(err)
	}
	enrolled := completed.Enrolled
	if completed.Account.ID != s.user || completed.Account.DisplayName != "Test" || completed.Account.EmailMasked != "" || enrolled.Reenrolled || enrolled.KeyVersion != 1 {
		t.Fatalf("completed %+v", completed)
	}
	if s.count(`SELECT count(*) FROM identity.session WHERE session_id = $1 AND scope = 3 AND user_id = $2 AND installation_id = $3 AND product_id = 'arcforges-node'
AND auth_method = 1 AND revoked_at IS NULL`, enrolled.Session.SessionID, s.user, enrolled.InstallationID) != 1 {
		t.Fatal("no node session of the account")
	}
	if s.count(`SELECT count(*) FROM fleet.node_sign_in WHERE flow_id = $1 AND state = 3 AND session_id = $2 AND enrollment_id = $3 AND code_redeemed_at IS NOT NULL
AND completed_at IS NOT NULL AND code_hash IS NOT NULL`, f.id, enrolled.Session.SessionID, enrolled.EnrollmentID) != 1 {
		t.Fatal("the flow is not COMPLETED with its results")
	}
	if s.count("SELECT count(*) FROM device.installation WHERE installation_id = $1 AND public_key = $2", enrolled.InstallationID, node.PublicKey) != 1 {
		t.Fatal("the installation does not hold the node key")
	}
	if s.count("SELECT count(*) FROM fleet.node_sign_in WHERE flow_id = $1 AND position(convert_to($2, 'UTF8') in code_hash) > 0", f.id, f.code) != 0 {
		t.Fatal("the code is stored")
	}
	if s.count("SELECT count(*) FROM audit.audit_event WHERE event_type = 'fleet.node.enrolled' AND convert_from(payload, 'UTF8')::jsonb->>'flow' = 'pkce'") != 1 ||
		s.count("SELECT count(*) FROM audit.audit_event WHERE event_type = 'fleet.node_sign_in.approved' AND target_id = $1", f.id.String()) != 1 {
		t.Fatal("the audit events are missing")
	}
	// The audit chain head is the last write: fleet.node.enrolled is the last event and the flow row was written before it.
	if s.count("SELECT count(*) FROM audit.audit_event WHERE sequence = (SELECT max(sequence) FROM audit.audit_event) AND event_type = 'fleet.node.enrolled'") != 1 {
		t.Fatal("fleet.node.enrolled is not the last event")
	}
}

// TestBeginRefusesAHeldKey (C0: "A node_public_key that an installation holds or held is refused before approval"): a key held by a
// live installation, by the node's own signed-out installation and by a revoked one is CONFLICT/already_exists node_key /
// already_registered, and nothing is written.
func TestBeginRefusesAHeldKey(t *testing.T) {
	s := newSignIns(t)
	node := s.newNode()
	f := s.mustBegin(node)
	s.approve(f)
	completed, err := s.complete(f)
	if err != nil {
		t.Fatal(err)
	}
	flows := s.count("SELECT count(*) FROM fleet.node_sign_in")
	if _, err = s.begin(node); key(err) != "CONFLICT/already_exists node_key/already_registered" {
		t.Fatalf("a live holder: %s", key(err))
	}
	s.db.Exec("UPDATE identity.session SET revoked_at = now(), revoke_reason = 1, rev = rev + 1 WHERE session_id = '" + completed.Enrolled.Session.SessionID.String() + "'")
	if _, err = s.begin(node); key(err) != "CONFLICT/already_exists node_key/already_registered" {
		t.Fatalf("the node's own signed-out installation: %s", key(err))
	}
	s.db.Exec("UPDATE device.installation SET revoked_at = now(), rev = rev + 1 WHERE installation_id = '" + completed.Enrolled.InstallationID.String() + "'")
	if _, err = s.begin(node); key(err) != "CONFLICT/already_exists node_key/already_registered" {
		t.Fatalf("a revoked holder: %s", key(err))
	}
	if s.count("SELECT count(*) FROM fleet.node_sign_in") != flows {
		t.Fatal("a refused Begin wrote a flow")
	}
}

// TestBeginSupersedesOnlyPendingFlowsOfTheSameKey (Q21): a newer Begin of the node ID with the same key expires the node's PENDING
// flows; a Begin of the same node ID with another key (a party that knows only the node ID) leaves them alone, and an APPROVED flow
// is never superseded.
func TestBeginSupersedesOnlyPendingFlowsOfTheSameKey(t *testing.T) {
	s := newSignIns(t)
	node := s.newNode()
	first := s.mustBegin(node)
	approved := s.mustBegin(node)
	s.approve(approved)
	squatter := s.newNode()
	squatter.ID = node.ID
	s.mustBegin(squatter)
	if s.state(first) != FlowExpired {
		// The second Begin of the same key superseded the first.
		t.Fatalf("the first flow is %d", s.state(first))
	}
	third := s.mustBegin(node)
	s.mustBegin(squatter)
	if s.state(approved) != FlowApproved || s.state(third) != FlowPending {
		t.Fatalf("approved %d, third %d", s.state(approved), s.state(third))
	}
	s.mustBegin(node)
	if s.state(third) != FlowExpired {
		t.Fatalf("the same key did not supersede: %d", s.state(third))
	}
}

// TestBeginStoresTheCanonicalVersion (cloud-11): the flow keeps the version without build metadata.
func TestBeginStoresTheCanonicalVersion(t *testing.T) {
	s := newSignIns(t)
	node := s.newNode()
	node.Version = "0.1.0-dev+590dcff"
	f := s.mustBegin(node)
	if s.count("SELECT count(*) FROM fleet.node_sign_in WHERE flow_id = $1 AND version = '0.1.0-dev' AND state = 1", f.id) != 1 {
		t.Fatal("the flow does not store the canonical version")
	}
}

// TestBeginCountsItsBuckets (E1-15): the client prefix's and the node ID's buckets refuse past their limits with RESOURCE/rate_limited
// and the refused Begin writes no flow.
func TestBeginCountsItsBuckets(t *testing.T) {
	s := newSignIns(t)
	s.policy.NodeFlowPerNode.Limit, s.policy.NodeFlowPerPrefix.Limit = 3, 10
	s.renew()
	node := s.newNode()
	for range 3 {
		s.mustBegin(node)
	}
	if _, err := s.begin(node); key(err) != "RESOURCE/rate_limited" {
		t.Fatalf("the fourth Begin of one node ID: %s", key(err))
	}
	other := s.newNode()
	for range 6 {
		s.mustBegin(other)
		other = s.newNode()
	}
	if _, err := s.begin(other); key(err) != "RESOURCE/rate_limited" {
		t.Fatalf("the eleventh Begin of one network: %s", key(err))
	}
	if s.count("SELECT count(*) FROM fleet.node_sign_in") != 9 || s.count("SELECT count(*) FROM audit.audit_event WHERE event_type = 'identity.rate_limited'") != 2 {
		t.Fatalf("%d flows", s.count("SELECT count(*) FROM fleet.node_sign_in"))
	}
}

// TestApprovalRules (E1-7, FLW-04 as the C0 comments state it).
func TestApprovalRules(t *testing.T) {
	s := newSignIns(t)
	ctx := context.Background()
	decide := func(user platform.ID, session dbtest.Session, f *flow, approve bool) error {
		_, err := s.service.Decide(ctx, s.from, accountOf(user, session, s.clock.Now()), f.id, approve, approve)
		return err
	}
	other, otherSession := s.account(1)

	// Not reviewed at all; reviewed by another account last (the latest review wins).
	f := s.mustBegin(s.newNode())
	s.prove(s.user, s.approver, f.id)
	if err := decide(s.user, s.approver, f, true); key(err) != "STATE/invalid_state node_sign_in/not_reviewed" {
		t.Fatalf("unreviewed: %s", key(err))
	}
	if _, err := s.review(s.user, s.approver, f); err != nil {
		t.Fatal(err)
	}
	if _, err := s.review(other, otherSession, f); err != nil {
		t.Fatal(err)
	}
	if err := decide(s.user, s.approver, f, true); key(err) != "STATE/invalid_state node_sign_in/not_reviewed" {
		t.Fatalf("a displaced reviewer: %s", key(err))
	}
	// A review older than the window (N-3: SEEDED, the flow lifetime never lets the API produce one).
	if _, err := s.review(s.user, s.approver, f); err != nil {
		t.Fatal(err)
	}
	s.db.Exec("UPDATE fleet.node_sign_in SET viewed_at = viewed_at - interval '11 minutes', created_at = created_at - interval '11 minutes' WHERE flow_id = '" + f.id.String() + "'")
	if err := decide(s.user, s.approver, f, true); key(err) != "STATE/invalid_state node_sign_in/not_reviewed" {
		t.Fatalf("a review 11 minutes old: %s", key(err))
	}
	s.db.Exec("UPDATE fleet.node_sign_in SET viewed_at = viewed_at + interval '2 minutes' WHERE flow_id = '" + f.id.String() + "'")
	if err := decide(s.user, s.approver, f, true); err != nil {
		t.Fatalf("a review 9 minutes old: %s", key(err))
	}

	// Evidence: none, another class, another flow, reused.
	g := s.mustBegin(s.newNode())
	if _, err := s.review(s.user, s.approver, g); err != nil {
		t.Fatal(err)
	}
	if err := decide(s.user, s.approver, g, true); key(err) != "AUTHENTICATION/step_up_required" {
		t.Fatalf("no evidence: %s", key(err))
	}
	wrongClass, _ := hex.DecodeString(identity.TargetHash("device.revoke", s.user, g.id))
	s.db.ProveStepUp(s.approver, "device.revoke", wrongClass, s.clock.Now())
	s.prove(s.user, s.approver, f.id) // evidence for another flow
	if err := decide(s.user, s.approver, g, true); key(err) != "AUTHENTICATION/step_up_required" {
		t.Fatalf("evidence of another class or flow: %s", key(err))
	}
	if s.state(g) != FlowPending {
		t.Fatal("a refused approval changed the flow")
	}
	// A denial needs no evidence.
	if err := decide(s.user, s.approver, g, false); err != nil || s.state(g) != FlowDenied {
		t.Fatalf("deny: %s %d", key(err), s.state(g))
	}
	if err := decide(s.user, s.approver, g, true); key(err) != "STATE/invalid_state node_sign_in/denied" {
		t.Fatalf("a denied flow: %s", key(err))
	}
	// Another account's decided flow looks unknown (N-1); TestForeignFlowsLookUnknownAlsoAfterTheirExpiry pins it past the expiry.
	if err := decide(other, otherSession, g, false); key(err) != "STATE/not_found node_sign_in/not_found" {
		t.Fatalf("another account's flow: %s", key(err))
	}
	if _, err := s.review(other, otherSession, g); key(err) != "STATE/not_found node_sign_in/not_found" {
		t.Fatalf("another account's review: %s", key(err))
	}

	// A repeat approval by the approving account replaces the code; the old one no longer matches.
	h := s.mustBegin(s.newNode())
	s.approve(h)
	oldCode := h.code
	s.prove(s.user, s.approver, h.id)
	decision, err := s.service.Decide(ctx, s.from, accountOf(s.user, s.approver, s.clock.Now()), h.id, true, true)
	if err != nil {
		t.Fatal(err)
	}
	if h.code, err = h.signIn.LoopbackCode(decision.RedirectURL); err != nil || h.code == oldCode {
		t.Fatalf("reissue: %v", err)
	}
	if s.count("SELECT count(*) FROM audit.audit_event WHERE event_type = 'fleet.node_sign_in.code_reissued' AND target_id = $1", h.id.String()) != 1 {
		t.Fatal("the reissue is not audited")
	}
	if _, err = s.completeWith(h, oldCode, h.signIn.Verifier, h.node.CompleteProof(audience, h.id, oldCode)); key(err) != "AUTHENTICATION/unauthenticated" {
		t.Fatalf("the replaced code: %s", key(err))
	}
	// Another account cannot decide an APPROVED flow (it looks unknown); its approver may deny it.
	if err = decide(other, otherSession, h, false); key(err) != "STATE/not_found node_sign_in/not_found" {
		t.Fatalf("another account on an approved flow: %s", key(err))
	}
	if err = decide(s.user, s.approver, h, false); err != nil || s.state(h) != FlowDenied {
		t.Fatalf("the approver denies its approval: %s", key(err))
	}
	if _, err = s.complete(h); key(err) != "AUTHENTICATION/unauthenticated" {
		t.Fatalf("a denied approval's code: %s", key(err))
	}

	// Expired; the cap.
	e := s.mustBegin(s.newNode())
	if _, err = s.review(s.user, s.approver, e); err != nil {
		t.Fatal(err)
	}
	s.clock.advance(FlowLifetime)
	if err = decide(s.user, s.approver, e, false); key(err) != "STATE/expired" {
		t.Fatalf("an expired flow: %s", key(err))
	}
	if _, err = s.review(s.user, s.approver, e); key(err) != "STATE/expired" {
		t.Fatalf("an expired review: %s", key(err))
	}
	s.policy.MaxNodesPerAccount = 1
	s.renew()
	s.mustEnroll(s.request(platform.NewID(), nodeKey(t)))
	c := s.mustBegin(s.newNode())
	if _, err = s.review(s.user, s.approver, c); err != nil {
		t.Fatal(err)
	}
	s.prove(s.user, s.approver, c.id)
	if err = decide(s.user, s.approver, c, true); key(err) != "RESOURCE/quota_exceeded" {
		t.Fatalf("the cap: %s", key(err))
	}
}

// TestDecisionsAreCounted (E1-15): node_approve_account counts approvals and denials per account.
func TestDecisionsAreCounted(t *testing.T) {
	s := newSignIns(t)
	s.policy.NodeApprovePerAccount.Limit = 2
	s.renew()
	for range 2 {
		f := s.mustBegin(s.newNode())
		if _, err := s.review(s.user, s.approver, f); err != nil {
			t.Fatal(err)
		}
		if _, err := s.service.Decide(context.Background(), s.from, accountOf(s.user, s.approver, s.clock.Now()), f.id, false, false); err != nil {
			t.Fatal(err)
		}
	}
	f := s.mustBegin(s.newNode())
	if _, err := s.service.Decide(context.Background(), s.from, accountOf(s.user, s.approver, s.clock.Now()), f.id, false, false); key(err) != "RESOURCE/rate_limited" {
		t.Fatalf("a third decision: %s", key(err))
	}
}

// TestCompleteWithoutTheCodeNeverChangesAFlow (protocol-1, B-1): a caller that holds only the flow ID, presenting junk, gets the same
// reply for a PENDING, APPROVED, COMPLETED, DENIED, REVOKED, superseded (EXPIRED) and lapsed (EXPIRED) flow inside their expiry, and
// nothing changes: the flow row, the sessions, the nodes and the audit chain.
func TestCompleteWithoutTheCodeNeverChangesAFlow(t *testing.T) {
	s := newSignIns(t)
	pending := s.mustBegin(s.newNode())
	approved := s.mustBegin(s.newNode())
	s.approve(approved)
	completedFlow := s.mustBegin(s.newNode())
	s.approve(completedFlow)
	if _, err := s.complete(completedFlow); err != nil {
		t.Fatal(err)
	}
	denied := s.mustBegin(s.newNode())
	if _, err := s.review(s.user, s.approver, denied); err != nil {
		t.Fatal(err)
	}
	if _, err := s.service.Decide(context.Background(), s.from, accountOf(s.user, s.approver, s.clock.Now()), denied.id, false, false); err != nil {
		t.Fatal(err)
	}
	revoked := s.mustBegin(s.newNode())
	s.approve(revoked)
	if _, err := s.completeWith(revoked, revoked.code, revoked.signIn.Verifier, revoked.node.CompleteProof("https://other.example.test", revoked.id, revoked.code)); key(err) != "AUTHENTICATION/unauthenticated" {
		t.Fatal(key(err))
	}
	supersededNode := s.newNode()
	superseded := s.mustBegin(supersededNode)
	s.mustBegin(supersededNode)
	lapsed := s.mustBegin(s.newNode())
	s.approve(lapsed)
	s.db.Exec("UPDATE identity.session SET auth_epoch = auth_epoch + 1, rev = rev + 1 WHERE session_id = '" + s.approver.ID.String() + "'")
	if _, err := s.complete(lapsed); key(err) != "STATE/expired" || s.state(lapsed) != FlowExpired {
		t.Fatalf("lapse: %s", key(err))
	}
	states := map[*flow]int16{pending: FlowPending, approved: FlowApproved, completedFlow: FlowCompleted, denied: FlowDenied, revoked: FlowRevoked,
		superseded: FlowExpired, lapsed: FlowExpired}
	junk, _ := oneuse.NewCode()
	network := byte(0)
	for f, state := range states {
		network++
		s.from = Request{ClientIP: netip.AddrFrom4([4]byte{198, 51, network, 1})}
		if s.state(f) != state {
			t.Fatalf("flow in state %d, want %d", s.state(f), state)
		}
		before := s.snapshot(f)
		for _, code := range []string{junk, "", "not a code", f.code + "x"} {
			if _, err := s.completeWith(f, code, f.signIn.Verifier, f.node.CompleteProof(audience, f.id, code)); key(err) != "AUTHENTICATION/unauthenticated" {
				t.Fatalf("state %d, code %q: %s", state, code, key(err))
			}
		}
		if after := s.snapshot(f); after != before {
			t.Fatalf("state %d changed:\n%s\n%s", state, before, after)
		}
	}
}

// TestJunkCompletesDoNotBurnAnApprovedFlow (protocol-1): junk presentations from many networks while the flow is PENDING and again
// while it is APPROVED leave it usable; the node's own Complete then succeeds.
func TestJunkCompletesDoNotBurnAnApprovedFlow(t *testing.T) {
	s := newSignIns(t)
	f := s.mustBegin(s.newNode())
	junk := func() {
		for i := range 25 {
			request := Request{ClientIP: netip.AddrFrom4([4]byte{198, 18, byte(i), 1})}
			code, _ := oneuse.NewCode()
			if _, err := s.service.Complete(context.Background(), request, CompleteRequest{FlowID: f.id, Code: code, Verifier: f.signIn.Verifier,
				Proof: f.node.CompleteProof(audience, f.id, code)}); key(err) != "AUTHENTICATION/unauthenticated" {
				t.Fatalf("junk: %s", key(err))
			}
		}
	}
	junk()
	s.approve(f)
	junk()
	if _, err := s.complete(f); err != nil {
		t.Fatalf("the node's Complete after junk: %s", key(err))
	}
}

// TestAMatchingCodeNeverWaitsOnTheCompleteBucket (OQ-1, E1-15): junk from the node's own network fills the failure bucket, so further
// junk is RESOURCE/rate_limited, and the node's matching code still completes; unknown flows count too.
func TestAMatchingCodeNeverWaitsOnTheCompleteBucket(t *testing.T) {
	s := newSignIns(t)
	f := s.mustBegin(s.newNode())
	s.approve(f)
	limited := 0
	for range 40 {
		code, _ := oneuse.NewCode()
		_, err := s.completeWith(f, code, f.signIn.Verifier, f.node.CompleteProof(audience, f.id, code))
		switch key(err) {
		case "RESOURCE/rate_limited":
			limited++
		case "AUTHENTICATION/unauthenticated":
		default:
			t.Fatalf("junk: %s", key(err))
		}
	}
	if limited != 10 {
		t.Fatalf("%d of 40 junk presentations were limited", limited)
	}
	if _, err := s.service.Complete(context.Background(), s.from, CompleteRequest{FlowID: platform.NewID(), Code: f.code, Verifier: f.signIn.Verifier,
		Proof: f.node.CompleteProof(audience, f.id, f.code)}); key(err) != "RESOURCE/rate_limited" {
		t.Fatalf("an unknown flow while the bucket is full: %s", key(err))
	}
	if _, err := s.complete(f); err != nil {
		t.Fatalf("the matching code: %s", key(err))
	}
	if s.count("SELECT count(*) FROM audit.audit_event WHERE event_type = 'identity.rate_limited' AND reason = 'node_complete_prefix'") != 1 {
		t.Fatal("the full bucket is not audited once")
	}
}

// TestCompleteNodeSignInCodeReuseRevokesFlowAndFamily (SEC-01, FLW-08): the correct code presented again after the completion revokes
// the flow and the credential family it delivered (reason 8), audited once; later presentations answer code_reused only.
func TestCompleteNodeSignInCodeReuseRevokesFlowAndFamily(t *testing.T) {
	s := newSignIns(t)
	f := s.mustBegin(s.newNode())
	s.approve(f)
	completed, err := s.complete(f)
	if err != nil {
		t.Fatal(err)
	}
	for range 3 {
		if _, err = s.complete(f); key(err) != "CONFLICT/code_reused" {
			t.Fatalf("reuse: %s", key(err))
		}
	}
	if s.state(f) != FlowRevoked || s.count("SELECT count(*) FROM identity.session WHERE session_id = $1 AND revoke_reason = 8", completed.Enrolled.Session.SessionID) != 1 ||
		s.count("SELECT count(*) FROM audit.audit_event WHERE event_type = 'fleet.node_sign_in.code_reused'") != 1 {
		t.Fatal("the reuse did not revoke the flow and the family once")
	}
	// The node row stays live: the node signs in again with a new key.
	if s.count("SELECT count(*) FROM fleet.node WHERE enrollment_id = $1 AND revoked_at IS NULL", completed.Enrolled.EnrollmentID) != 1 {
		t.Fatal("the reuse revoked the node row")
	}
}

// TestConcurrentCompletesEnrollOnce (E1-14, SEC-01, cloud-2 item 7, N-6): two presentations of the correct code race; exactly one
// enrollment happens, the loser takes the reuse path (code_reused) and revokes the winner's family; a racer with a wrong verifier
// never makes a second enrollment either.
func TestConcurrentCompletesEnrollOnce(t *testing.T) {
	s := newSignIns(t)
	s.watchDeadlocks(t)
	for round := range rounds {
		f := s.mustBegin(s.newNode())
		s.approve(f)
		results := make([]string, 3)
		var start, done sync.WaitGroup
		start.Add(1)
		for i := range results {
			done.Add(1)
			go func() {
				defer done.Done()
				start.Wait()
				verifier := f.signIn.Verifier
				if i == 2 {
					verifier = nodetest.NewSignIn().Verifier
				}
				_, err := s.completeWith(f, f.code, verifier, f.node.CompleteProof(audience, f.id, f.code))
				results[i] = key(err)
				if deadlocked(err) {
					results[i] = "deadlock"
				}
			}()
		}
		start.Done()
		done.Wait()
		enrolled := s.count("SELECT count(*) FROM fleet.node_sign_in WHERE flow_id = $1 AND enrollment_id IS NOT NULL", f.id)
		live := s.count(`SELECT count(*) FROM identity.session s JOIN fleet.node_sign_in f ON f.session_id = s.session_id WHERE f.flow_id = $1 AND s.revoked_at IS NULL`, f.id)
		winners := 0
		for _, result := range results[:2] {
			if result == "" {
				winners++
			}
		}
		// Every racer presents the correct code, so every round ends REVOKED. With a winner, both others take the reuse path
		// (the wrong-verifier racer too, whose failure marker finds the flow COMPLETED: N-6) and the winner's family is revoked.
		// Without one, the wrong verifier locked first (the failure marker) and the two correct presentations are reuses of a
		// REVOKED flow.
		ok := s.state(f) == FlowRevoked && live == 0
		switch winners {
		case 1:
			reused := 0
			for _, result := range results {
				if result == "CONFLICT/code_reused" {
					reused++
				}
			}
			ok = ok && enrolled == 1 && reused == 2
		case 0:
			ok = ok && enrolled == 0 && results[0] == "CONFLICT/code_reused" && results[1] == "CONFLICT/code_reused" && results[2] == "AUTHENTICATION/unauthenticated"
		default:
			ok = false
		}
		if !ok {
			t.Fatalf("round %d: %v, %d enrolled, %d live, state %d", round, results, enrolled, live, s.state(f))
		}
	}
}

// TestPKCEWrongVerifierRevokesTheFlow (SEC-02, RFC 7636 4.6): the correct code with a wrong verifier, or with a node key proof for
// another center (a relay: protocol-4) or of a high s, revokes the flow, redeems its code and answers unauthenticated like any failed
// proof; the right verifier afterwards cannot complete it.
func TestPKCEWrongVerifierRevokesTheFlow(t *testing.T) {
	s := newSignIns(t)
	for name, present := range map[string]func(f *flow) (Completed, error){
		"verifier": func(f *flow) (Completed, error) {
			return s.completeWith(f, f.code, nodetest.NewSignIn().Verifier, f.node.CompleteProof(audience, f.id, f.code))
		},
		"another center": func(f *flow) (Completed, error) {
			return s.completeWith(f, f.code, f.signIn.Verifier, f.node.CompleteProof("https://relay.example.test/api", f.id, f.code))
		},
		"high s": func(f *flow) (Completed, error) {
			return s.completeWith(f, f.code, f.signIn.Verifier, f.node.SignMessage(ProofMessage(ProofComplete, audience, f.node.ID, CompleteBinding(f.id, f.code)), false))
		},
		"another key": func(f *flow) (Completed, error) {
			return s.completeWith(f, f.code, f.signIn.Verifier, s.newNode().CompleteProof(audience, f.id, f.code))
		},
	} {
		f := s.mustBegin(s.newNode())
		s.approve(f)
		if _, err := present(f); key(err) != "AUTHENTICATION/unauthenticated" {
			t.Fatalf("%s: %s", name, key(err))
		}
		if s.count("SELECT count(*) FROM fleet.node_sign_in WHERE flow_id = $1 AND state = 6 AND code_redeemed_at IS NOT NULL AND session_id IS NULL", f.id) != 1 {
			t.Fatalf("%s: the flow is not revoked", name)
		}
		if _, err := s.complete(f); key(err) != "CONFLICT/code_reused" {
			t.Fatalf("%s: the right proof afterwards: %s", name, key(err))
		}
	}
	if s.count("SELECT count(*) FROM audit.audit_event WHERE event_type = 'fleet.node_sign_in.verifier_failed'") != 4 || s.count("SELECT count(*) FROM fleet.node") != 0 {
		t.Fatal("the failures are not audited or a node was enrolled")
	}
}

// TestACorrectCodeAfterItsLifetimeLeavesTheFlowApproved (C0: "a correct code presented after its lifetime consumes nothing and
// leaves the flow APPROVED"); the approving account approves again for a fresh code, which completes.
func TestACorrectCodeAfterItsLifetimeLeavesTheFlowApproved(t *testing.T) {
	s := newSignIns(t)
	f := s.mustBegin(s.newNode())
	s.approve(f)
	s.clock.advance(s.policy.NodeCodeLifetime)
	before := s.snapshot(f)
	if _, err := s.complete(f); key(err) != "STATE/expired" {
		t.Fatalf("an expired code: %s", key(err))
	}
	if s.snapshot(f) != before || s.state(f) != FlowApproved {
		t.Fatal("an expired code changed the flow")
	}
	s.approve(f)
	if _, err := s.complete(f); err != nil {
		t.Fatalf("the fresh code: %s", key(err))
	}
}

// TestAnEnrollRefusalLeavesTheFlowApproved (OQ-2): a node ID live in another account answers CONFLICT/already_exists (node), and the
// flow stays APPROVED with its code unredeemed, so the identical retry answers the same rule.
func TestAnEnrollRefusalLeavesTheFlowApproved(t *testing.T) {
	s := newSignIns(t)
	node := s.newNode()
	other, otherSession := s.account(1)
	request := s.request(node.ID, nodeKey(t))
	request.UserID, request.Approver.SessionID = other, otherSession.ID
	s.mustEnroll(request)
	f := s.mustBegin(node)
	s.approve(f)
	for range 2 {
		if _, err := s.complete(f); key(err) != "CONFLICT/already_exists node/already_exists" {
			t.Fatalf("another account's node ID: %s", key(err))
		}
	}
	if s.count("SELECT count(*) FROM fleet.node_sign_in WHERE flow_id = $1 AND state = 2 AND code_redeemed_at IS NULL", f.id) != 1 {
		t.Fatal("the refusal changed the flow")
	}
}

// TestApprovalDoesNotOutliveRevocationOfTheApproverSession (SEC-24, protocol-6): the approving session revoked by another session of
// the account (reason 2) or with its device (reason 5) lapses the approval: the flow ends EXPIRED, audited, STATE/expired, nothing of
// the enrollment remains; a sign-out of the approving session (reason 1) and its expiry do not.
func TestApprovalDoesNotOutliveRevocationOfTheApproverSession(t *testing.T) {
	for reason, lapses := range map[int16]bool{1: false, 2: true, 3: true, 5: true, 6: true} {
		s := newSignIns(t)
		f := s.mustBegin(s.newNode())
		s.approve(f)
		s.db.Exec(fmt.Sprintf("UPDATE identity.session SET revoked_at = now(), revoke_reason = %d, rev = rev + 1 WHERE session_id = '%s'", reason, s.approver.ID))
		_, err := s.complete(f)
		switch {
		case lapses && (key(err) != "STATE/expired" || s.state(f) != FlowExpired || s.count("SELECT count(*) FROM device.installation WHERE product_id = 'arcforges-node'") != 0 ||
			s.count("SELECT count(*) FROM audit.audit_event WHERE event_type = 'fleet.node_sign_in.approval_lapsed'") != 1):
			t.Fatalf("reason %d: %s, state %d", reason, key(err), s.state(f))
		case !lapses && (err != nil || s.state(f) != FlowCompleted):
			t.Fatalf("reason %d: %s", reason, key(err))
		}
	}
}

// TestApproverEpochsAndAccountStateLapseTheApproval (SEC-24): a credential removal (the authentication epoch moves), a recovery
// generation move (SQL bump, labelled: no recovery path exists yet) and a suspended account (SQL) lapse the approval.
func TestApproverEpochsAndAccountStateLapseTheApproval(t *testing.T) {
	for name, statement := range map[string]string{
		"epoch":    "UPDATE identity.session SET auth_epoch = auth_epoch + 1, rev = rev + 1 WHERE user_id = '%s'",
		"recovery": "UPDATE identity.session SET recovery_generation = recovery_generation + 1, rev = rev + 1 WHERE user_id = '%s'",
		"suspend":  "UPDATE identity.user SET state = 3, rev = rev + 1 WHERE user_id = '%s'",
	} {
		s := newSignIns(t)
		f := s.mustBegin(s.newNode())
		s.approve(f)
		s.db.Exec(fmt.Sprintf(statement, s.user))
		if _, err := s.complete(f); key(err) != "STATE/expired" || s.state(f) != FlowExpired {
			t.Fatalf("%s: %s", name, key(err))
		}
		// B-1: the matching code on the EXPIRED flow is told the expiry (only the holder of the code learns it); nothing changes.
		before := s.snapshot(f)
		if _, err := s.complete(f); key(err) != "STATE/expired" || s.snapshot(f) != before {
			t.Fatalf("%s: the matching code on the expired flow: %s", name, key(err))
		}
	}
}

// TestCompleteTakesItsLocksInTheGlobalOrder (cloud-1, E1-14): a held flow row makes the completion wait holding nothing; a held
// account row makes it wait holding the flow row (Enroll's order follows: TestEnrollTakesItsLocksInTheGlobalOrder).
func TestCompleteTakesItsLocksInTheGlobalOrder(t *testing.T) {
	s := newSignIns(t)
	s.watchDeadlocks(t)
	f := s.mustBegin(s.newNode())
	s.approve(f)
	release := s.hold(t, "SELECT 1 FROM identity.user WHERE user_id = $1 FOR UPDATE", s.user)
	done := make(chan error, 1)
	go func() { _, err := s.complete(f); done <- err }()
	s.waitBlocked(t)
	if s.free(t, "SELECT 1 FROM fleet.node_sign_in WHERE flow_id = $1", f.id) {
		t.Fatal("the completion waits for the account without holding the flow row")
	}
	release(false)
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	g := s.mustBegin(s.newNode())
	s.approve(g)
	release = s.hold(t, "SELECT 1 FROM fleet.node_sign_in WHERE flow_id = $1 FOR UPDATE", g.id)
	go func() { _, err := s.complete(g); done <- err }()
	s.waitBlocked(t)
	if !s.free(t, "SELECT 1 FROM identity.user WHERE user_id = $1", s.user) {
		t.Fatal("the completion took the account before the flow row")
	}
	release(false)
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

// TestApproveTakesTheFlowBeforeTheAccount (cloud-1): an approval waits for a held flow row holding nothing, and for a held account
// row holding the flow row.
func TestApproveTakesTheFlowBeforeTheAccount(t *testing.T) {
	s := newSignIns(t)
	s.watchDeadlocks(t)
	f := s.mustBegin(s.newNode())
	if _, err := s.review(s.user, s.approver, f); err != nil {
		t.Fatal(err)
	}
	s.prove(s.user, s.approver, f.id)
	approve := func(done chan<- error) {
		_, err := s.service.Decide(context.Background(), s.from, accountOf(s.user, s.approver, s.clock.Now()), f.id, true, true)
		done <- err
	}
	done := make(chan error, 1)
	release := s.hold(t, "SELECT 1 FROM fleet.node_sign_in WHERE flow_id = $1 FOR UPDATE", f.id)
	go approve(done)
	s.waitBlocked(t)
	if !s.free(t, "SELECT 1 FROM identity.user WHERE user_id = $1", s.user) {
		t.Fatal("the approval took the account before the flow row")
	}
	release(false)
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	g := s.mustBegin(s.newNode())
	if _, err := s.review(s.user, s.approver, g); err != nil {
		t.Fatal(err)
	}
	s.prove(s.user, s.approver, g.id)
	f = g
	release = s.hold(t, "SELECT 1 FROM identity.user WHERE user_id = $1 FOR UPDATE", s.user)
	go approve(done)
	s.waitBlocked(t)
	if s.free(t, "SELECT 1 FROM fleet.node_sign_in WHERE flow_id = $1", g.id) {
		t.Fatal("the approval waits for the account without holding the flow row")
	}
	release(false)
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

// TestRevokeDuringCompleteLeavesNoLiveSession (E1-14, E1a checkpoint): a re-enrolling completion races DeviceService.Revoke of the
// node's device (through identity.RevokeDevice under its evidence path, which locks the account first); there is never a deadlock,
// and no live node session remains on a revoked device.
func TestRevokeDuringCompleteLeavesNoLiveSession(t *testing.T) {
	s := newSignIns(t)
	s.watchDeadlocks(t)
	node := s.newNode()
	for round := range rounds / 2 {
		// The node signs in again in place with a new key (a sign-in after a sign-out replaces the key).
		replacement := s.newNode()
		replacement.ID = node.ID
		node = replacement
		f := s.mustBegin(node)
		s.approve(f)
		var deviceID platform.ID
		live := s.count("SELECT count(*) FROM fleet.node WHERE node_id = $1 AND revoked_at IS NULL", node.ID) == 1
		if live {
			if err := s.db.Migration.QueryRow(context.Background(), "SELECT device_id FROM fleet.node WHERE node_id = $1 AND revoked_at IS NULL", node.ID).Scan(&deviceID); err != nil {
				t.Fatal(err)
			}
		}
		var start, done sync.WaitGroup
		start.Add(1)
		done.Add(2)
		var completeErr, revokeErr error
		go func() { defer done.Done(); start.Wait(); _, completeErr = s.complete(f) }()
		go func() {
			defer done.Done()
			start.Wait()
			if live {
				revokeErr = s.revokeDevice(deviceID)
			}
		}()
		start.Done()
		done.Wait()
		if deadlocked(completeErr) || deadlocked(revokeErr) {
			t.Fatalf("round %d: deadlock: %v %v", round, completeErr, revokeErr)
		}
		if s.count(`SELECT count(*) FROM identity.session s JOIN device.device d ON d.device_id = s.device_id WHERE s.scope = 3 AND s.revoked_at IS NULL AND
d.revoked_at IS NOT NULL`) != 0 {
			t.Fatalf("round %d: a live node session on a revoked device", round)
		}
	}
}

// TestACodeReplacedByReapprovalIsNotRedeemedByAnEarlierProof (cloud-2 item 2): a presentation verified against the code it read
// before the lock is decided again under the lock; a code replaced meanwhile (a repeat approval) is a mismatch, nothing is redeemed
// and the flow stays APPROVED.
func TestACodeReplacedByReapprovalIsNotRedeemedByAnEarlierProof(t *testing.T) {
	s := newSignIns(t)
	f := s.mustBegin(s.newNode())
	s.approve(f)
	ctx := context.Background()
	holder, err := s.db.Runtime.Pool().Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = holder.Rollback(ctx) }()
	if _, err = holder.Exec(ctx, "SELECT 1 FROM fleet.node_sign_in WHERE flow_id = $1 FOR UPDATE", f.id); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { _, err := s.complete(f); done <- err }()
	s.waitBlocked(t)
	_, replacement := oneuse.NewCode()
	if _, err = holder.Exec(ctx, "UPDATE fleet.node_sign_in SET code_hash = $2, rev = rev + 1 WHERE flow_id = $1", f.id, replacement[:]); err != nil {
		t.Fatal(err)
	}
	if err = holder.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	if err = <-done; key(err) != "AUTHENTICATION/unauthenticated" {
		t.Fatalf("the replaced code: %s", key(err))
	}
	if s.count("SELECT count(*) FROM fleet.node_sign_in WHERE flow_id = $1 AND state = 2 AND code_redeemed_at IS NULL", f.id) != 1 || s.count("SELECT count(*) FROM fleet.node") != 0 {
		t.Fatal("the replaced code was redeemed")
	}
}

// TestAFailureMarkerThatFindsTheFlowCompletedRevokesTheFamily (N-6, B5): the correct presentation holds the flow row and waits for
// the account (held by a third transaction); a presentation of the same code with a wrong verifier is verified as a failure outside
// any transaction and waits for the flow row; the account is released, the completion commits, and the failure marker, deciding
// under the lock, finds the flow COMPLETED and takes the reuse path: CONFLICT/code_reused, the flow REVOKED, the winner's family
// revoked with reason 8, one code_reused audit.
func TestAFailureMarkerThatFindsTheFlowCompletedRevokesTheFamily(t *testing.T) {
	s := newSignIns(t)
	s.watchDeadlocks(t)
	f := s.mustBegin(s.newNode())
	s.approve(f)
	release := s.hold(t, "SELECT 1 FROM identity.user WHERE user_id = $1 FOR UPDATE", s.user)
	completed, marked := make(chan error, 1), make(chan error, 1)
	go func() { _, err := s.complete(f); completed <- err }()
	s.waitBlocked(t)
	go func() {
		_, err := s.completeWith(f, f.code, nodetest.NewSignIn().Verifier, f.node.CompleteProof(audience, f.id, f.code))
		marked <- err
	}()
	deadline := time.Now().Add(5 * time.Second)
	for s.count(`SELECT count(DISTINCT l.pid) FROM pg_locks l JOIN pg_stat_activity a ON a.pid = l.pid
WHERE NOT l.granted AND a.datname = current_database()`) < 2 {
		if time.Now().After(deadline) {
			t.Fatal("the failure marker never waited for the flow row")
		}
		time.Sleep(5 * time.Millisecond)
	}
	release(false)
	if err := <-completed; err != nil {
		t.Fatalf("the completion: %s", key(err))
	}
	if err := <-marked; key(err) != "CONFLICT/code_reused" {
		t.Fatalf("the failure marker on a completed flow: %s", key(err))
	}
	if s.state(f) != FlowRevoked || s.count(`SELECT count(*) FROM identity.session s JOIN fleet.node_sign_in f ON f.session_id = s.session_id
WHERE f.flow_id = $1 AND s.revoke_reason = 8`, f.id) != 1 || s.count("SELECT count(*) FROM audit.audit_event WHERE event_type = 'fleet.node_sign_in.code_reused'") != 1 ||
		s.count("SELECT count(*) FROM audit.audit_event WHERE event_type = 'fleet.node_sign_in.verifier_failed'") != 0 {
		t.Fatalf("the reuse path was not taken: state %d", s.state(f))
	}
}

// TestForeignFlowsLookUnknownAlsoAfterTheirExpiry (N-1, B2): a flow another account approved is STATE/not_found to this account's
// review and decision also after the flow's expiry (the foreign check comes before the expiry check), while the approving account
// itself is told STATE/expired.
func TestForeignFlowsLookUnknownAlsoAfterTheirExpiry(t *testing.T) {
	s := newSignIns(t)
	other, otherSession := s.account(1)
	f := s.mustBegin(s.newNode())
	s.approve(f)
	s.clock.advance(FlowLifetime)
	if _, err := s.review(other, otherSession, f); key(err) != "STATE/not_found node_sign_in/not_found" {
		t.Fatalf("another account's review of an expired flow: %s", key(err))
	}
	if _, err := s.service.Decide(context.Background(), s.from, accountOf(other, otherSession, s.clock.Now()), f.id, false, false); key(err) != "STATE/not_found node_sign_in/not_found" {
		t.Fatalf("another account's decision on an expired flow: %s", key(err))
	}
	if _, err := s.review(s.user, s.approver, f); key(err) != "STATE/expired" {
		t.Fatalf("the approving account's review of its expired flow: %s", key(err))
	}
	if _, err := s.service.Decide(context.Background(), s.from, accountOf(s.user, s.approver, s.clock.Now()), f.id, false, false); key(err) != "STATE/expired" {
		t.Fatalf("the approving account's decision on its expired flow: %s", key(err))
	}
}

// TestTheCorrectCodeLoserRevokesTheWinner (C-1, FLW-08, cloud-2 item 7; the twin of
// TestAFailureMarkerThatFindsTheFlowCompletedRevokesTheFamily, with no wrong-verifier racer): the correct presentation holds the
// flow row and waits for the account (held by a third transaction); a second presentation of the same correct code, also pre-read
// APPROVED with both proofs good, waits for the flow row; the account is released, the winner completes, and the loser, deciding
// under the lock, finds the flow COMPLETED and takes the reuse path: CONFLICT/code_reused, the flow REVOKED, the winner's family
// revoked with reason 8, one code_reused audit.
func TestTheCorrectCodeLoserRevokesTheWinner(t *testing.T) {
	s := newSignIns(t)
	s.watchDeadlocks(t)
	f := s.mustBegin(s.newNode())
	s.approve(f)
	release := s.hold(t, "SELECT 1 FROM identity.user WHERE user_id = $1 FOR UPDATE", s.user)
	won, lost := make(chan error, 1), make(chan error, 1)
	go func() { _, err := s.complete(f); won <- err }()
	s.waitBlocked(t)
	go func() { _, err := s.complete(f); lost <- err }()
	deadline := time.Now().Add(5 * time.Second)
	for s.count(`SELECT count(DISTINCT l.pid) FROM pg_locks l JOIN pg_stat_activity a ON a.pid = l.pid
WHERE NOT l.granted AND a.datname = current_database()`) < 2 {
		if time.Now().After(deadline) {
			t.Fatal("the second presentation never waited for the flow row")
		}
		time.Sleep(5 * time.Millisecond)
	}
	release(false)
	if err := <-won; err != nil {
		t.Fatalf("the winner: %s", key(err))
	}
	if err := <-lost; key(err) != "CONFLICT/code_reused" {
		t.Fatalf("the loser: %s", key(err))
	}
	live := s.count(`SELECT count(*) FROM identity.session s JOIN fleet.node_sign_in f ON f.session_id = s.session_id WHERE f.flow_id = $1 AND s.revoked_at IS NULL`, f.id)
	if s.state(f) != FlowRevoked || live != 0 || s.count(`SELECT count(*) FROM identity.session s JOIN fleet.node_sign_in f ON f.session_id = s.session_id
WHERE f.flow_id = $1 AND s.revoke_reason = 8`, f.id) != 1 || s.count("SELECT count(*) FROM audit.audit_event WHERE event_type = 'fleet.node_sign_in.code_reused'") != 1 {
		t.Fatalf("the loser did not revoke the winner: state %d, %d live", s.state(f), live)
	}
}
