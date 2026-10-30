// SPDX-License-Identifier: AGPL-3.0-only

package identityapi_test

import (
	"context"
	"encoding/base64"
	"testing"
	"time"

	foundationv1 "github.com/ArcForges/Contracts/go/arcforges/foundation/v1"
	publicapiv1 "github.com/ArcForges/Contracts/go/arcforges/publicapi/v1"
	"github.com/jackc/pgx/v5"
	"google.golang.org/protobuf/proto"

	"github.com/ArcForges/Cloud/center/internal/config"
	"github.com/ArcForges/Cloud/center/internal/identity"
	"github.com/ArcForges/Cloud/center/internal/identity/passkey/virtual"
	"github.com/ArcForges/Cloud/center/internal/platform"
)

// The routed A1b items of A2 (A-1, the double fault of not_verified, command_id_reused through B4's second lookup and an attempt
// that is never settled) drive CompletePasskeyRegistration's duplicate handling with the harness's adjustable clock.

// registrationFixture is an account with a begun registration: a command that completes it, and the flow behind it.
type registrationFixture struct {
	who      account
	from     caller
	flowID   platform.ID
	complete func(alter func(*publicapiv1.IdentityServiceCompletePasskeyRegistrationRequest)) registrationAnswer
	subject  string
}

func beginRegistration(t *testing.T, h *harness) registrationFixture {
	t.Helper()
	who := h.seedAccount(1, "")
	from := bearer(h.signIn(who, newClaim(t), caller{}).GetAccessToken())
	h.stepUp(who, from, identity.ClassBeginRegistration, who.id)
	challenge := rpc(h, beginRegisterPath, &publicapiv1.IdentityServiceBeginPasskeyRegistrationRequest{Meta: meta(), DisplayName: proto.String("Key")}, from,
		&publicapiv1.IdentityServiceBeginPasskeyRegistrationResponse{}).GetValue().GetChallenge()
	creation, _ := virtual.New(rpID, origin).Create(challenge.GetChallenge(), who.handle)
	request := &publicapiv1.IdentityServiceCompletePasskeyRegistrationRequest{Meta: command(), FlowId: challenge.GetFlowId(), Credential: creationOf(creation)}
	return registrationFixture{who: who, from: from, flowID: idFrom(challenge.GetFlowId()), subject: base64.RawURLEncoding.EncodeToString(creation.CredentialID),
		complete: func(alter func(*publicapiv1.IdentityServiceCompletePasskeyRegistrationRequest)) registrationAnswer {
			sent := proto.Clone(request).(*publicapiv1.IdentityServiceCompletePasskeyRegistrationRequest)
			if alter != nil {
				alter(sent)
			}
			return rpc(h, completeRegisterPath, sent, from, &publicapiv1.IdentityServiceCompletePasskeyRegistrationResponse{})
		}}
}

// TestADuplicateAfterTheFlowsExpiryWhileTheFirstRunsIsBusy (A-1): the first completion took its attempt before the flow expired and
// is still in its success transaction when the flow expires; a duplicate of the same command that arrives then is told the store is
// busy (RESOURCE/overloaded, AFTER_TIME), never the final STATE/expired of a command that then commits, and the retry replays the
// receipt. The first execution is parked on the account's row, the clock moves past the flow's lifetime.
func TestADuplicateAfterTheFlowsExpiryWhileTheFirstRunsIsBusy(t *testing.T) {
	h := newHarness(t, settings{policy: writePolicy})
	fixture := beginRegistration(t, h)
	lock := h.holding("SELECT 1 FROM identity.user WHERE user_id = $1 FOR UPDATE", fixture.who.id)
	first := make(chan registrationAnswer, 1)
	go func() { first <- fixture.complete(nil) }()
	if !lock.waitFor(1) {
		t.Fatal("the first completion never reached the account's row")
	}
	h.clock.Advance(config.DefaultIdentityPolicy().PasskeyFlowLifetime + time.Second)
	duplicate := fixture.complete(nil).GetError()
	if failure(duplicate) != "RESOURCE/overloaded" || duplicate.GetRetry().GetMode() != foundationv1.RetryMode_RETRY_MODE_AFTER_TIME {
		t.Fatalf("the duplicate after the flow's expiry while the first runs: %v", duplicate)
	}
	lock.release(false)
	answer := <-first
	if answer.GetError() != nil {
		t.Fatalf("the first completion: %s", failure(answer.GetError()))
	}
	replay := fixture.complete(nil)
	if replay.GetError() != nil || !proto.Equal(replay.GetValue(), answer.GetValue()) || h.receipts() != 1 ||
		h.count("SELECT count(*) FROM identity.auth_identity WHERE subject = $1", fixture.subject) != 1 {
		t.Fatalf("the replay after the first committed: %v", replay)
	}
	h.verifyAudit()
}

// TestAnAttemptNeverSettledTurnsExpiredAfterTheGrace (A-1, the critic's second probe): an attempt that is never settled (the process
// stopped between taking it and settling it) answers RESOURCE/overloaded while a running completion could still hold it, until the
// flow's expiry plus identity.RunningGrace, and STATE/expired from then on, final and with nothing stored. The attempt is taken by
// SQL.
func TestAnAttemptNeverSettledTurnsExpiredAfterTheGrace(t *testing.T) {
	h := newHarness(t, settings{policy: writePolicy})
	fixture := beginRegistration(t, h)
	taken, err := h.migration.Exec(context.Background(),
		"UPDATE identity.auth_flow SET attempts = max_attempts WHERE flow_id = $1 AND consumed_at IS NULL AND outcome IS NULL", fixture.flowID)
	if err != nil || taken.RowsAffected() != 1 {
		t.Fatalf("the attempt was not taken: %v", err)
	}
	lifetime := config.DefaultIdentityPolicy().PasskeyFlowLifetime
	for _, step := range []struct {
		advance time.Duration
		want    string
		retry   foundationv1.RetryMode
	}{
		{lifetime - time.Minute, "RESOURCE/overloaded", foundationv1.RetryMode_RETRY_MODE_AFTER_TIME},
		{time.Minute + time.Second, "RESOURCE/overloaded", foundationv1.RetryMode_RETRY_MODE_AFTER_TIME},
		{identity.RunningGrace - 2*time.Second, "RESOURCE/overloaded", foundationv1.RetryMode_RETRY_MODE_AFTER_TIME},
		{2 * time.Second, "STATE/expired", foundationv1.RetryMode_RETRY_MODE_NEVER},
	} {
		h.clock.Advance(step.advance)
		refusal := fixture.complete(nil).GetError()
		if failure(refusal) != step.want || refusal.GetRetry().GetMode() != step.retry {
			t.Fatalf("after %s more: %v, want %s", step.advance, refusal, step.want)
		}
	}
	if h.receipts() != 0 || h.count("SELECT count(*) FROM identity.auth_identity WHERE subject = $1", fixture.subject) != 0 {
		t.Fatal("an unsettled attempt stored something")
	}
	h.verifyAudit()
}

// TestAnAttemptNeverTakenIsExpiredAtOnceAfterTheFlowsExpiry (a1b-1): a registration that is begun, never completed and completed
// after the flow's expiry is STATE/expired with RETRY_MODE_NEVER from the first second on, inside the running grace as well as after
// it: no attempt was ever taken, so no running completion could hold it, and it is not RESOURCE/overloaded for the grace's 15
// seconds. Nothing is stored.
func TestAnAttemptNeverTakenIsExpiredAtOnceAfterTheFlowsExpiry(t *testing.T) {
	h := newHarness(t, settings{policy: writePolicy})
	fixture := beginRegistration(t, h)
	h.clock.Advance(config.DefaultIdentityPolicy().PasskeyFlowLifetime)
	for _, step := range []time.Duration{time.Second, 4 * time.Second, identity.RunningGrace - 6*time.Second, 2 * time.Second} {
		h.clock.Advance(step)
		refusal := fixture.complete(nil).GetError()
		if failure(refusal) != "STATE/expired" || refusal.GetRetry().GetMode() != foundationv1.RetryMode_RETRY_MODE_NEVER {
			t.Fatalf("a flow never attempted, past its expiry by %s: %v, want STATE/expired with RETRY_MODE_NEVER", step, refusal)
		}
	}
	if h.receipts() != 0 || h.count("SELECT attempts FROM identity.auth_flow WHERE flow_id = $1", fixture.flowID) != 0 {
		t.Fatal("a refusal after the expiry stored a receipt or took an attempt")
	}
	h.verifyAudit()
}

// TestADuplicateMeetingTheFlowExhaustedByARefusalAnswersTheReceipt (a1b-2): a registration whose first execution commits a final
// stored refusal (CONFLICT/already_exists: the credential ID belongs to another account) and then exhausts the flow leaves the flow
// answering STATE/expired. A duplicate whose first receipt lookup ran before that receipt committed and whose attempt runs after the
// exhaust meets exactly that; it looks again and answers the refusal the receipt holds, never its own final STATE/expired. The
// duplicate is parked at its attempt by a statement trigger on identity.auth_flow that blocks its first updating statement on an
// advisory lock the test holds.
func TestADuplicateMeetingTheFlowExhaustedByARefusalAnswersTheReceipt(t *testing.T) {
	h := newHarness(t, settings{policy: writePolicy})
	fixture := beginRegistration(t, h)
	other := h.seedAccount(1, "")
	if _, err := h.migration.Exec(context.Background(), `INSERT INTO identity.auth_identity (auth_identity_id, user_id, method, provider_id, subject, public_key,
    user_handle, sign_count, backup_eligible, backup_state, transports, aaguid, attestation_format, created_at, rev)
SELECT $1, user_id, 1, 'passkey', $2, public_key, user_handle, 0, false, false, '{}', aaguid, 'none', now(), 1
FROM identity.auth_identity WHERE user_id = $3 AND method = 1`, platform.NewID(), fixture.subject, other.id); err != nil {
		t.Fatal(err)
	}
	h.exec(
		"CREATE SCHEMA testfault",
		`CREATE FUNCTION testfault.park() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN
  IF pg_try_advisory_xact_lock(7001) THEN PERFORM pg_advisory_xact_lock(7002); END IF;
  RETURN NULL; END; $$`,
		"CREATE TRIGGER test_park BEFORE UPDATE ON identity.auth_flow FOR EACH STATEMENT EXECUTE FUNCTION testfault.park()")
	gate := h.holding("SELECT pg_advisory_xact_lock(7002)")
	duplicates := make(chan registrationAnswer, 1)
	go func() { duplicates <- fixture.complete(nil) }()
	if !gate.waitFor(1) {
		t.Fatal("the duplicate never reached its attempt")
	}
	first := fixture.complete(nil)
	gate.release(false)
	second := <-duplicates
	expect(t, "the first execution", first.GetError(), "CONFLICT/already_exists")
	if h.refusalsKept("CONFLICT/already_exists") != 1 || h.count("SELECT count(*) FROM identity.auth_flow WHERE flow_id = $1 AND outcome IS NOT NULL", fixture.flowID) != 1 {
		t.Fatal("the first execution did not keep its refusal and end the flow")
	}
	if failure(second.GetError()) != "CONFLICT/already_exists" {
		t.Fatalf("the duplicate parked before the receipt and running after the exhaust: %q (%v), want CONFLICT/already_exists", failure(second.GetError()), second.GetError())
	}
	if replay := fixture.complete(nil); !proto.Equal(replay.GetError().GetDetails(), first.GetError().GetDetails()) || failure(replay.GetError()) != "CONFLICT/already_exists" {
		t.Fatalf("the replay: %v", replay)
	}
	h.verifyAudit()
}

// TestAVerificationFailureIsAnsweredWhenTheSecondLookupWouldFail (the double fault of not_verified): a creation that does not verify
// is a refusal no committed first execution causes (a duplicate never verifies: the first execution took the flow's only attempt),
// so it runs no second receipt lookup and a failing lookup cannot replace it with RESOURCE/overloaded, after which the retry
// would find the flow ended (STATE/expired) and the reason lost. The receipt table is locked from after the first lookup until the
// verification failed.
func TestAVerificationFailureIsAnsweredWhenTheSecondLookupWouldFail(t *testing.T) {
	h := newHarness(t, settings{policy: writePolicy})
	fixture := beginRegistration(t, h)
	receipts, err := pgx.ConnectConfig(context.Background(), h.migration.Config())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = receipts.Close(context.Background()) })
	// A creation made for another challenge never verifies; every send of this command carries the same one.
	wrong, _ := virtual.New(rpID, origin).Create(randomBytes(t, 32), fixture.who.handle)
	alter := func(request *publicapiv1.IdentityServiceCompletePasskeyRegistrationRequest) {
		request.Credential = creationOf(wrong)
	}
	flow := h.holding("SELECT 1 FROM identity.auth_flow WHERE flow_id = $1 FOR UPDATE", fixture.flowID)
	answers := make(chan registrationAnswer, 1)
	go func() { answers <- fixture.complete(alter) }()
	if !flow.waitFor(1) {
		t.Fatal("the completion never reached the flow's row")
	}
	locked, err := receipts.Begin(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if _, err = locked.Exec(context.Background(), "LOCK TABLE platform.command_receipt IN ACCESS EXCLUSIVE MODE"); err != nil {
		t.Fatal(err)
	}
	flow.release(false)
	answer := <-answers
	if err = locked.Rollback(context.Background()); err != nil {
		t.Fatal(err)
	}
	refusal := answer.GetError()
	if failure(refusal) != "VALIDATION/invalid_argument" || refusal.GetDetails().GetState().GetReason() != "credential: not_verified" {
		t.Fatalf("the creation that does not verify, with the receipt table locked: %v", refusal)
	}
	if h.receipts() != 0 {
		t.Fatal("a refusal stored a receipt")
	}
	// The flow ended with the refusal, so the identical retry meets an ended flow: the documented STATE/expired.
	expect(t, "the identical retry", fixture.complete(alter).GetError(), "STATE/expired")
	h.verifyAudit()
}

// TestADuplicateWithAnotherPayloadIsACommandIDReusedAfterTheFirstCommitted (the critic's first probe): a duplicate whose receipt
// lookup runs before the first execution committed and whose attempt runs after it finds the flow consumed; its second receipt
// lookup meets the first's receipt, whose request is another one, and answers CONFLICT/command_id_reused, final, not the
// code_reused of the consumed flow and not the first's success. The same command with the first's own bytes still replays.
func TestADuplicateWithAnotherPayloadIsACommandIDReusedAfterTheFirstCommitted(t *testing.T) {
	h := newHarness(t, settings{policy: writePolicy})
	answer, second, complete, subject := racedRegistration(t, h, nil, func(request *publicapiv1.IdentityServiceCompletePasskeyRegistrationRequest) {
		request.Credential.Transports = append(request.Credential.Transports, "usb")
	})
	if answer.GetError() != nil || failure(second.GetError()) != "CONFLICT/command_id_reused" || h.receipts() != 1 ||
		h.count("SELECT count(*) FROM identity.auth_identity WHERE subject = $1", subject) != 1 {
		t.Fatalf("the first completion %v, the duplicate with another payload %v", answer, second)
	}
	if replay := complete(); replay.GetError() != nil || !proto.Equal(replay.GetValue(), answer.GetValue()) {
		t.Fatalf("the first's own bytes after it: %v", replay)
	}
	h.verifyAudit()
}
