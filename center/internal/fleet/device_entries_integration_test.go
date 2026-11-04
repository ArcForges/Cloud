// SPDX-License-Identifier: AGPL-3.0-only

package fleet

import (
	"encoding/hex"
	"fmt"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/ArcForges/Cloud/center/internal/identity"
	"github.com/ArcForges/Cloud/center/internal/platform"
)

// EVIDENCE: as device_integration_test.go: REAL PostgreSQL and the real fleet service; the accounts, sessions and evidence SEEDED; the
// node MOCKED. These tests pin the user-code entry budgets (Q8 as merged in the C0 comments, the F7 resolution of e2-decisions.md),
// the review, the step-up binding and the decision rules of ApproveDeviceCode.

// TestSixthWrongUserCodeIsRateLimited (Q8, CTR4-SEC-04): each wrong entry of an account is VALIDATION/code_invalid naming
// device_entry_account with the window's cap and the entries left (4, 3, 2, 1, 0); once the budget is spent every entry, a right one
// too, is RESOURCE/rate_limited with retry_at the window's end, and nothing is read or written.
func TestSixthWrongUserCodeIsRateLimited(t *testing.T) {
	s := newSignIns(t)
	a := s.mustStart(s.newNode())
	for left := int64(4); left >= 0; left-- {
		_, err := s.lookup(s.user, s.approver, unknownCode)
		if name, maximum, available := limitOf(err); key(err) != "VALIDATION/code_invalid" || name != "device_entry_account" || maximum != 5 || available != left {
			t.Fatalf("a wrong entry with %d left: %s %s %d %d", left, key(err), name, maximum, available)
		}
	}
	before := s.authorizationSnapshot(a)
	_, err := s.lookup(s.user, s.approver, a.started.UserCode)
	name, _, _ := limitOf(err)
	if key(err) != "RESOURCE/rate_limited" || name != "device_entry_account" || s.authorizationSnapshot(a) != before {
		t.Fatalf("the right code after the budget: %s %s", key(err), name)
	}
	if err = s.decide(s.user, s.approver, a.started.UserCode, false); key(err) != "RESOURCE/rate_limited" {
		t.Fatalf("a decision after the budget: %s", key(err))
	}
	if s.count("SELECT count(*) FROM audit.audit_event WHERE event_type = 'identity.rate_limited' AND reason = 'device_entry_account'") != 1 {
		t.Fatal("the wrong entry that spent the budget is not audited once")
	}
	s.clock.advance(15 * time.Minute)
	if _, err = s.lookup(s.user, s.approver, unknownCode); key(err) != "VALIDATION/code_invalid" {
		t.Fatalf("the next window: %s", key(err))
	}
}

// TestARightLookupGivesBothReservationsBack (C0: "a right lookup gives both back"): four wrong entries and five right ones leave one
// entry, and the network bucket, which counts the same entries, holds four.
func TestARightLookupGivesBothReservationsBack(t *testing.T) {
	s := newSignIns(t)
	a := s.mustStart(s.newNode())
	for range 4 {
		if _, err := s.lookup(s.user, s.approver, unknownCode); key(err) != "VALIDATION/code_invalid" {
			t.Fatal(key(err))
		}
		if _, err := s.lookup(s.user, s.approver, a.started.UserCode); err != nil {
			t.Fatal(key(err))
		}
	}
	if _, _, available := limitOf(func() error { _, err := s.lookup(s.user, s.approver, unknownCode); return err }()); available != 0 {
		t.Fatalf("after four wrong entries and four right ones the fifth wrong entry leaves %d", available)
	}
	other, otherSession := s.account(1)
	if _, _, available := limitOf(func() error { _, err := s.lookup(other, otherSession, unknownCode); return err }()); available != 4 {
		t.Fatalf("another account on the network: %d left", available)
	}
	// The network's bucket holds the six wrong entries of the two accounts and none of the right ones.
	if s.count("SELECT count FROM platform.rate_limit WHERE bucket_hash = $1", hashOf(s.service.bucket("device_entry_prefix", "203.0.113.0/24"))) != 6 {
		t.Fatal("the network bucket does not hold exactly the wrong entries")
	}
}

// TestTheNetworkRefusalGivesTheAccountReservationBack (protocol-9 residual): when the network's budget is spent, an entry is
// rate_limited naming device_entry_prefix, and the account's unit it reserved first is given back.
func TestTheNetworkRefusalGivesTheAccountReservationBack(t *testing.T) {
	s := newSignIns(t)
	s.policy.DeviceEntryPerPrefix.Limit = 2
	s.renew()
	other, otherSession := s.account(1)
	for range 2 {
		if _, err := s.lookup(other, otherSession, unknownCode); key(err) != "VALIDATION/code_invalid" {
			t.Fatal(key(err))
		}
	}
	for range 3 {
		_, err := s.lookup(s.user, s.approver, unknownCode)
		if name, _, _ := limitOf(err); key(err) != "RESOURCE/rate_limited" || name != "device_entry_prefix" {
			t.Fatalf("the spent network: %s %s", key(err), name)
		}
	}
	elsewhere := Request{ClientIP: netip.MustParseAddr("198.51.100.4")}
	if _, _, available := limitOf(func() error { _, err := s.lookupFrom(elsewhere, s.user, s.approver, unknownCode); return err }()); available != 4 {
		t.Fatalf("the account's budget after three network refusals: %d left", available)
	}
}

// TestExpiredOtherStateAndUnreviewedEntriesCountAgainstTheBudget (F7, decided in e2-decisions.md): an entry naming an expired code
// (STATE/expired), a code in another state (STATE/invalid_state: a lookup of a code this account denied, a second approval of its
// APPROVED code), the decision of a code this account did not review, also one another account reviewed (STATE/invalid_state
// not_reviewed: the deliberate override of protocol-9 corrected fix item 3), and a code another account decided
// (VALIDATION/code_invalid) each keep the account's unit, with the exact refusal; a step-up refusal of a reviewed code gives it back.
// The account's budget is 7 here, so the six kept units and one more wrong entry spend it exactly.
func TestExpiredOtherStateAndUnreviewedEntriesCountAgainstTheBudget(t *testing.T) {
	s := newSignIns(t)
	s.policy.DeviceEntryPerAccount.Limit = 7
	s.renew()
	other, otherSession := s.account(1)
	expired := s.mustStart(s.newNode())
	approvedByOther := s.mustStart(s.newNode())
	s.approveCode(other, otherSession, approvedByOther)
	reviewedByOther := s.mustStart(s.newNode())
	if _, err := s.lookup(other, otherSession, reviewedByOther.started.UserCode); err != nil {
		t.Fatal(err)
	}
	unreviewed := s.mustStart(s.newNode())
	approvedByMe := s.mustStart(s.newNode())
	s.approveCode(s.user, s.approver, approvedByMe)
	deniedByMe := s.mustStart(s.newNode())
	if _, err := s.lookup(s.user, s.approver, deniedByMe.started.UserCode); err != nil {
		t.Fatal(err)
	}
	if err := s.decide(s.user, s.approver, deniedByMe.started.UserCode, false); err != nil {
		t.Fatal(err)
	}
	mine := s.mustStart(s.newNode())
	if _, err := s.lookup(s.user, s.approver, mine.started.UserCode); err != nil {
		t.Fatal(err)
	}
	if err := s.decide(s.user, s.approver, mine.started.UserCode, true); key(err) != "AUTHENTICATION/step_up_required" {
		t.Fatalf("an approval without evidence: %s", key(err))
	}
	s.db.Exec(fmt.Sprintf("UPDATE fleet.device_authorization SET expires_at = created_at + interval '1 microsecond', rev = rev + 1 WHERE authorization_id = '%s'",
		expired.started.AuthorizationID))
	s.clock.advance(time.Second)
	for _, entry := range []struct {
		name, want string
		enter      func() error
	}{
		{"expired", "STATE/expired", func() error { _, err := s.lookup(s.user, s.approver, expired.started.UserCode); return err }},
		{"decided elsewhere", "VALIDATION/code_invalid", func() error { _, err := s.lookup(s.user, s.approver, approvedByOther.started.UserCode); return err }},
		{"reviewed elsewhere", "STATE/invalid_state device_authorization/not_reviewed", func() error {
			return s.decide(s.user, s.approver, reviewedByOther.started.UserCode, false)
		}},
		{"never reviewed", "STATE/invalid_state device_authorization/not_reviewed", func() error {
			return s.decide(s.user, s.approver, unreviewed.started.UserCode, false)
		}},
		{"denied by me, looked up", "STATE/invalid_state device_authorization/denied", func() error {
			_, err := s.lookup(s.user, s.approver, deniedByMe.started.UserCode)
			return err
		}},
		{"approved by me, approved again", "STATE/invalid_state device_authorization/approved", func() error {
			return s.decide(s.user, s.approver, approvedByMe.started.UserCode, true)
		}},
	} {
		before := s.entryCount(s.user)
		err := entry.enter()
		if after := s.entryCount(s.user); key(err) != entry.want || after != before+1 {
			t.Fatalf("%s: %s, the account's count %d -> %d", entry.name, key(err), before, after)
		}
	}
	if s.count(`SELECT count(*) FROM fleet.device_authorization WHERE authorization_id = ANY($1::uuid[]) AND state = 1`,
		[]string{reviewedByOther.started.AuthorizationID.String(), unreviewed.started.AuthorizationID.String(), mine.started.AuthorizationID.String()}) != 3 {
		t.Fatal("a refused decision changed an authorization")
	}
	if s.authorizationState(approvedByMe) != AuthorizationApproved || s.authorizationState(deniedByMe) != AuthorizationDenied {
		t.Fatal("a refused entry changed this account's own authorizations")
	}
	// Six kept units and none for the step-up refusal: the seventh wrong entry leaves 0.
	if _, _, available := limitOf(func() error { _, err := s.lookup(s.user, s.approver, unknownCode); return err }()); available != 0 {
		t.Fatalf("the seventh wrong entry leaves %d", available)
	}
}

// TestTheSixthLookupOfALiveCodeIsRefusedAndTheAuthorizationStaysPending (C0 Q8): five lookups of one live code are admitted (also the
// same account's again); the sixth and later are VALIDATION/code_invalid naming device_code_lookups with available 0, nothing is
// written, the authorization stays PENDING (the node keeps polling PENDING), and an approval by an account whose review was displaced
// is not_reviewed. The fifth lookup is audited once.
func TestTheSixthLookupOfALiveCodeIsRefusedAndTheAuthorizationStaysPending(t *testing.T) {
	s := newSignIns(t)
	s.wide()
	a := s.mustStart(s.newNode())
	if _, err := s.lookup(s.user, s.approver, a.started.UserCode); err != nil {
		t.Fatal(err)
	}
	other, otherSession := s.account(1)
	for range 4 {
		if _, err := s.lookup(other, otherSession, a.started.UserCode); err != nil {
			t.Fatal(err)
		}
	}
	before := s.authorizationSnapshot(a)
	for i := range 2 {
		_, err := s.lookup(s.user, s.approver, a.started.UserCode)
		if name, maximum, available := limitOf(err); key(err) != "VALIDATION/code_invalid" || name != "device_code_lookups" || maximum != 5 || available != 0 {
			t.Fatalf("lookup %d: %s %s %d %d", 6+i, key(err), name, maximum, available)
		}
	}
	if s.authorizationSnapshot(a) != before || s.authorizationState(a) != AuthorizationPending ||
		s.count("SELECT count(*) FROM audit.audit_event WHERE event_type = 'fleet.device_authorization.lookups_exhausted'") != 1 {
		t.Fatal("a refused lookup wrote, or the exhaustion is not audited once")
	}
	s.proveCode(s.user, s.approver, a.started.UserCode)
	if err := s.decide(s.user, s.approver, a.started.UserCode, true); key(err) != "STATE/invalid_state device_authorization/not_reviewed" {
		t.Fatalf("the displaced reviewer's approval: %s", key(err))
	}
	if polled, err := s.poll(a); err != nil || polled.State != AuthorizationPending {
		t.Fatalf("the node's poll: %+v %s", polled, key(err))
	}
	s.proveCode(other, otherSession, a.started.UserCode)
	if err := s.decide(other, otherSession, a.started.UserCode, true); err != nil {
		t.Fatalf("the last reviewer's approval: %s", key(err))
	}
}

// TestConcurrentWrongCodesNeverPassTheAccountBudget (the F9 pattern): twenty concurrent wrong entries of one account are five
// code_invalid and fifteen rate_limited.
func TestConcurrentWrongCodesNeverPassTheAccountBudget(t *testing.T) {
	s := newSignIns(t)
	results := make(chan string, 20)
	var start sync.WaitGroup
	start.Add(1)
	for range 20 {
		go func() {
			start.Wait()
			_, err := s.lookup(s.user, s.approver, unknownCode)
			results <- key(err)
		}()
	}
	start.Done()
	counts := map[string]int{}
	for range 20 {
		counts[<-results]++
	}
	if counts["VALIDATION/code_invalid"] != 5 || counts["RESOURCE/rate_limited"] != 15 {
		t.Fatalf("concurrent wrong entries: %v", counts)
	}
}

// TestConcurrentLookupsNeverPassFiveLookups: ten accounts looking one live code up at once get five reviews and five
// device_code_lookups refusals; the row counts five.
func TestConcurrentLookupsNeverPassFiveLookups(t *testing.T) {
	s := newSignIns(t)
	s.wide()
	a := s.mustStart(s.newNode())
	results := make(chan string, 10)
	var start sync.WaitGroup
	start.Add(1)
	for range 10 {
		user, session := s.account(1)
		go func() {
			start.Wait()
			_, err := s.lookup(user, session, a.started.UserCode)
			name, _, _ := limitOf(err)
			results <- key(err) + name
		}()
	}
	start.Done()
	counts := map[string]int{}
	for range 10 {
		counts[<-results]++
	}
	if counts[""] != 5 || counts["VALIDATION/code_invaliddevice_code_lookups"] != 5 ||
		s.count("SELECT lookups FROM fleet.device_authorization WHERE authorization_id = $1", a.started.AuthorizationID) != 5 {
		t.Fatalf("concurrent lookups: %v", counts)
	}
}

// TestDeviceApprovalRules (DEV-07, C0): the review within 10 minutes (SQL-seeded review times: with the 600-second lifetime the window
// cannot bind otherwise), the step-up bound to the normalized user code (another code, another class, the hyphenated or lower-case
// text, the authorization ID as target and another account's evidence are step_up_required), the denial without evidence, the
// approver's denial of an APPROVED authorization, the approval of an APPROVED one (invalid_state approved), a code another account
// decided (code_invalid, also after its expiry), the node cap (quota_exceeded) and the decisions' audit.
func TestDeviceApprovalRules(t *testing.T) {
	s := newSignIns(t)
	s.wide()
	other, otherSession := s.account(1)
	a := s.mustStart(s.newNode())
	code := a.started.UserCode
	if _, err := s.lookup(s.user, s.approver, code); err != nil {
		t.Fatal(err)
	}
	s.db.Exec(fmt.Sprintf("UPDATE fleet.device_authorization SET viewed_at = viewed_at - interval '10 minutes 1 second', rev = rev + 1 WHERE authorization_id = '%s'",
		a.started.AuthorizationID))
	if err := s.decide(s.user, s.approver, code, false); key(err) != "STATE/invalid_state device_authorization/not_reviewed" {
		t.Fatalf("a review older than 10 minutes: %s", key(err))
	}
	if _, err := s.lookup(s.user, s.approver, code); err != nil {
		t.Fatal(err)
	}
	for name, target := range map[string]string{
		"another code": identity.TextTargetHash(ClassApproveDeviceCode, s.user, unknownCode),
		"hyphenated":   identity.TextTargetHash(ClassApproveDeviceCode, s.user, code[:4]+"-"+code[4:]),
		"lower case":   identity.TextTargetHash(ClassApproveDeviceCode, s.user, lower(code)),
		"the ID":       identity.TargetHash(ClassApproveDeviceCode, s.user, a.started.AuthorizationID),
		"another user": identity.TextTargetHash(ClassApproveDeviceCode, other, code),
	} {
		raw, err := hex.DecodeString(target)
		if err != nil {
			t.Fatal(err)
		}
		s.db.ProveStepUp(s.approver, ClassApproveDeviceCode, raw, s.clock.Now())
		if err = s.decide(s.user, s.approver, code, true); key(err) != "AUTHENTICATION/step_up_required" {
			t.Fatalf("evidence for %s: %s", name, key(err))
		}
	}
	raw, err := hex.DecodeString(identity.TextTargetHash(ClassApproveNodeSignIn, s.user, code))
	if err != nil {
		t.Fatal(err)
	}
	s.db.ProveStepUp(s.approver, ClassApproveNodeSignIn, raw, s.clock.Now())
	if err = s.decide(s.user, s.approver, code, true); key(err) != "AUTHENTICATION/step_up_required" {
		t.Fatalf("evidence of another class: %s", key(err))
	}
	s.proveCode(s.user, s.approver, code)
	if err = s.decide(s.user, s.approver, code, true); err != nil {
		t.Fatal(err)
	}
	if err = s.decide(s.user, s.approver, code, true); key(err) != "STATE/invalid_state device_authorization/approved" {
		t.Fatalf("approving an APPROVED authorization: %s", key(err))
	}
	if err = s.decide(other, otherSession, code, false); key(err) != "VALIDATION/code_invalid" {
		t.Fatalf("another account's denial of an approved code: %s", key(err))
	}
	if err = s.decide(s.user, s.approver, code, false); err != nil || s.authorizationState(a) != AuthorizationDenied {
		t.Fatalf("the approver's denial of its APPROVED authorization: %s", key(err))
	}
	if s.count(`SELECT count(*) FROM audit.audit_event WHERE event_type = 'fleet.device_authorization.denied' AND target_id = $1
AND convert_from(payload, 'UTF8')::jsonb->>'from' = 'approved'`, a.started.AuthorizationID.String()) != 1 {
		t.Fatal("the denial of the approval is not audited")
	}
	if s.count("SELECT count(*) FROM identity.step_up_challenge WHERE state = 2") != 6 {
		t.Fatal("a refused approval consumed evidence")
	}
	// A code another account decided looks unknown, also after its expiry (E1b N-1 for the device flow).
	b := s.mustStart(s.newNode())
	s.approveCode(other, otherSession, b)
	s.clock.advance(601 * time.Second)
	if _, err = s.lookup(s.user, s.approver, b.started.UserCode); key(err) != "VALIDATION/code_invalid" {
		t.Fatalf("an expired code another account decided: %s", key(err))
	}
	// The node cap: an approval that would add a node past maxNodesPerAccount is quota_exceeded, and both reservations are given back
	// (OQ-3: the code is right and reviewed): the account's and the network's counts are those before the decision.
	s.policy.MaxNodesPerAccount = 1
	s.renew()
	s.mustEnroll(s.request(s.newNode().ID, nodeKey(t)))
	c := s.mustStart(s.newNode())
	if _, err = s.lookup(s.user, s.approver, c.started.UserCode); err != nil {
		t.Fatal(err)
	}
	s.proveCode(s.user, s.approver, c.started.UserCode)
	accountBefore, networkBefore := s.entryCount(s.user), s.networkCount()
	if err = s.decide(s.user, s.approver, c.started.UserCode, true); key(err) != "RESOURCE/quota_exceeded" || s.authorizationState(c) != AuthorizationPending {
		t.Fatalf("the cap: %s", key(err))
	}
	if s.entryCount(s.user) != accountBefore || s.networkCount() != networkBefore {
		t.Fatalf("the cap's refusal kept units: account %d -> %d, network %d -> %d", accountBefore, s.entryCount(s.user), networkBefore, s.networkCount())
	}
}

func lower(code string) string {
	out := []byte(code)
	for i, c := range out {
		out[i] = c + ('a' - 'A')
	}
	return string(out)
}

// entryCount is the count of an account's device_entry_account bucket; networkCount that of the rig's network in device_entry_prefix.
func (s *signIns) entryCount(user platform.ID) int {
	return s.count("SELECT coalesce(sum(count), 0) FROM platform.rate_limit WHERE bucket_hash = $1", hashOf(s.service.bucket("device_entry_account", "account:"+user.String())))
}

func (s *signIns) networkCount() int {
	return s.count("SELECT coalesce(sum(count), 0) FROM platform.rate_limit WHERE bucket_hash = $1", hashOf(s.service.bucket("device_entry_prefix", "203.0.113.0/24")))
}

// hashOf is the stored key of a bucket.
func hashOf(bucket interface{ Hash() [32]byte }) []byte {
	hash := bucket.Hash()
	return hash[:]
}
