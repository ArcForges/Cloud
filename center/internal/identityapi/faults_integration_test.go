// SPDX-License-Identifier: AGPL-3.0-only

package identityapi_test

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"strings"
	"testing"
	"time"

	foundationv1 "github.com/ArcForges/Contracts/go/arcforges/foundation/v1"
	publicapiv1 "github.com/ArcForges/Contracts/go/arcforges/publicapi/v1"
	"github.com/jackc/pgx/v5"
	"google.golang.org/protobuf/proto"

	"github.com/ArcForges/Cloud/center/internal/identity/passkey"
	"github.com/ArcForges/Cloud/center/internal/identity/passkey/virtual"
	"github.com/ArcForges/Cloud/center/internal/platform"
)

// exec runs statements as the migration role (the database's owner).
func (h *harness) exec(statements ...string) {
	h.t.Helper()
	for _, statement := range statements {
		if _, err := h.migration.Exec(context.Background(), statement); err != nil {
			h.t.Fatalf("%s: %v", statement, err)
		}
	}
}

// runtimeGroup is the quoted runtime group role whose grants the harness's migration reconciled.
func (h *harness) runtimeGroup() string { return pgx.Identifier{h.database + "_runtime"}.Sanitize() }

// TestARefreshWhoseReplyCannotBeBuiltKeepsItsToken (E1): RefreshSession reads the device of its reply in the rotating transaction,
// so when that read fails the rotation rolls back: the presented refresh token is not spent, nothing is revoked, and the retry the
// reply advises rotates it.
func TestARefreshWhoseReplyCannotBeBuiltKeepsItsToken(t *testing.T) {
	h := newHarness(t, settings{})
	who := h.seedAccount(1, "")
	claim := newClaim(t)
	native := h.signIn(who, claim, caller{})
	var sessionID platform.ID
	copy(sessionID[:], native.GetSessionId().GetValue())
	refresh := func() *publicapiv1.IdentityServiceRefreshSessionResponse {
		response := rpc(h, refreshPath, &publicapiv1.IdentityServiceRefreshSessionRequest{Meta: meta(), RefreshToken: proto.String(native.GetRefreshToken()),
			InstallationId: claim.GetInstallationId()}, caller{}, &publicapiv1.IdentityServiceRefreshSessionResponse{})
		if value := response.GetValue().GetSession(); value != nil {
			h.remember(value.GetAccessToken(), value.GetRefreshToken())
		}
		return response
	}
	// The runtime role may read the installation columns the rotation joins on, but not those of the reply's device view.
	h.exec("REVOKE SELECT ON device.installation FROM "+h.runtimeGroup(),
		"GRANT SELECT (installation_id, device_id, user_id, revoked_at) ON device.installation TO "+h.runtimeGroup())
	failed := refresh()
	if failure(failed.GetError()) != "INTERNAL/internal" ||
		h.count("SELECT refresh_generation FROM identity.session WHERE session_id = $1", sessionID) != 1 ||
		h.count("SELECT count(*) FROM identity.spent_refresh") != 0 {
		t.Fatalf("a refresh whose reply failed: %s", failure(failed.GetError()))
	}
	h.exec("GRANT SELECT ON device.installation TO " + h.runtimeGroup())
	retried := refresh()
	if retried.GetError() != nil || h.count("SELECT refresh_generation FROM identity.session WHERE session_id = $1", sessionID) != 2 ||
		h.audits("identity.session.refresh_reused") != 0 || h.count("SELECT count(*) FROM identity.session WHERE revoked_at IS NOT NULL") != 0 {
		t.Fatalf("the advised retry: %s", failure(retried.GetError()))
	}
	h.verifyAudit()
}

// TestAStoreFailureAfterTheProofGivesTheAttemptBack (F9): a passkey sign-in and an owner bootstrap whose proof verified but whose
// success transaction failed in the store answer RESOURCE/overloaded with AFTER_TIME, and the identical retry then succeeds once;
// a wrong proof never gets its attempt back.
func TestAStoreFailureAfterTheProofGivesTheAttemptBack(t *testing.T) {
	fault := func(h *harness) {
		h.exec("CREATE SCHEMA testfault",
			"CREATE FUNCTION testfault.unavailable() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'the store is unavailable (test)' USING ERRCODE = '57P01'; END; $$",
			"CREATE TRIGGER test_unavailable BEFORE INSERT ON identity.session FOR EACH ROW EXECUTE FUNCTION testfault.unavailable()")
	}
	overloaded := func(t *testing.T, value *foundationv1.ArcError) {
		t.Helper()
		if failure(value) != "RESOURCE/overloaded" || value.GetRetry().GetMode() != foundationv1.RetryMode_RETRY_MODE_AFTER_TIME ||
			value.GetEffect() != foundationv1.EffectCertainty_EFFECT_CERTAINTY_DID_NOT_HAPPEN {
			t.Fatalf("a store failure after the proof: %v", value)
		}
	}

	h := newHarness(t, settings{})
	who := h.seedAccount(1, "")
	fault(h)
	challenge := h.beginPasskey(newClaim(t), caller{})
	request := &publicapiv1.IdentityServiceCompleteAuthenticationRequest{Meta: meta(), FlowId: challenge.GetFlowId(),
		Proof: &publicapiv1.AuthProof{Proof: &publicapiv1.AuthProof_Passkey{Passkey: assertionOf(who.authenticator.Assert(who.key, challenge.GetChallenge()))}}}
	complete := func(request *publicapiv1.IdentityServiceCompleteAuthenticationRequest) *publicapiv1.IdentityServiceCompleteAuthenticationResponse {
		response := rpc(h, completePath, request, caller{}, &publicapiv1.IdentityServiceCompleteAuthenticationResponse{})
		if value := response.GetValue().GetSession(); value != nil {
			h.remember(value.GetAccessToken(), value.GetRefreshToken())
		}
		return response
	}
	overloaded(t, complete(request).GetError())
	if h.count("SELECT attempts FROM identity.auth_flow WHERE kind = 1 AND consumed_at IS NULL") != 0 || h.count("SELECT count(*) FROM identity.session") != 0 {
		t.Fatal("the attempt was not given back, or a session was written")
	}
	// A forged assertion with the fault in place still ends its flow.
	forged := h.beginPasskey(newClaim(t), caller{})
	forgedRequest := &publicapiv1.IdentityServiceCompleteAuthenticationRequest{Meta: meta(), FlowId: forged.GetFlowId(),
		Proof: &publicapiv1.AuthProof{Proof: &publicapiv1.AuthProof_Passkey{Passkey: assertionOf(who.authenticator.Assert(who.key, randomBytes(t, 32)))}}}
	if result := failure(complete(forgedRequest).GetError()); result != "AUTHENTICATION/unauthenticated" {
		t.Fatalf("a forged assertion: %s", result)
	}
	if result := failure(complete(forgedRequest).GetError()); result != "STATE/expired" {
		t.Fatalf("a forged assertion again: %s", result)
	}
	h.exec("DROP TRIGGER test_unavailable ON identity.session")
	if response := complete(request); response.GetError() != nil {
		t.Fatalf("the identical retry: %s", failure(response.GetError()))
	}
	if result := failure(complete(request).GetError()); result != "CONFLICT/code_reused" {
		t.Fatalf("the identical request after its success: %s", result)
	}

	// The owner bootstrap: the identical CompleteEnrollment creates the account once the store works again.
	b := newHarness(t, settings{})
	fault(b)
	begun := rpc(b, beginPath, &publicapiv1.IdentityServiceBeginAuthenticationRequest{Meta: meta(), Method: publicapiv1.AuthMethod_AUTH_METHOD_PASSKEY.Enum(),
		Purpose: publicapiv1.AuthPurpose_AUTH_PURPOSE_ENROLL.Enum(), Installation: newClaim(t)}, caller{}, &publicapiv1.IdentityServiceBeginAuthenticationResponse{}).
		GetValue().GetChallenge()
	creation, _ := virtual.New(rpID, origin).Create(begun.GetChallenge(), begun.GetOptions().GetUserHandle())
	enrollment := &publicapiv1.IdentityServiceCompleteEnrollmentRequest{Meta: meta(), FlowId: begun.GetFlowId(),
		Proof:      &publicapiv1.EnrollmentProof{Proof: &publicapiv1.EnrollmentProof_LocalCode{LocalCode: b.bootstrap}},
		Credential: &publicapiv1.CredentialReplacement{Replacement: &publicapiv1.CredentialReplacement_Passkey{Passkey: creationOf(creation)}},
		Profile:    &publicapiv1.ProfileUpdate{DisplayName: proto.String("Owner")}}
	enroll := func() *publicapiv1.IdentityServiceCompleteEnrollmentResponse {
		response := rpc(b, enrollPath, enrollment, caller{}, &publicapiv1.IdentityServiceCompleteEnrollmentResponse{})
		if value := response.GetValue().GetSession(); value != nil {
			b.remember(value.GetAccessToken(), value.GetRefreshToken())
		}
		return response
	}
	overloaded(t, enroll().GetError())
	if b.count("SELECT count(*) FROM identity.user") != 0 || b.count("SELECT attempts FROM identity.auth_flow WHERE kind = 3") != 0 {
		t.Fatal("a failed bootstrap wrote an account or kept its attempt")
	}
	b.exec("DROP TRIGGER test_unavailable ON identity.session")
	if response := enroll(); response.GetError() != nil || b.count("SELECT count(*) FROM identity.user") != 1 {
		t.Fatalf("the identical bootstrap retry: %s", failure(response.GetError()))
	}
	h.verifyAudit()
	b.verifyAudit()
}

// TestThePasskeyCounterIsRecheckedUnderTheRowLock (F14): a sign-in whose assertion the library accepted against the counter it read
// first is refused in the success transaction when a concurrent sign-in advanced the counter meanwhile, with the library's rule (a
// counter that does not exceed the stored one, unless both are zero), and the stored counter never decreases. The concurrent
// sign-in is a transaction that holds the credential's row, so the order is deterministic.
func TestThePasskeyCounterIsRecheckedUnderTheRowLock(t *testing.T) {
	h := newHarness(t, settings{})
	ctx := context.Background()
	for index, item := range []struct {
		name                       string
		stored, assertion, current uint32
	}{
		{"an equal counter", 3, 5, 5},
		{"a lower counter", 3, 4, 6},
		{"zero after a nonzero counter", 0, 0, 5},
	} {
		t.Run(item.name, func(t *testing.T) {
			who := h.seedAccount(1, "")
			from := caller{ip: fmt.Sprintf("198.51.%d.10", index+1)}
			h.exec(fmt.Sprintf("UPDATE identity.auth_identity SET sign_count = %d WHERE user_id = '%s' AND provider_id = 'passkey'", item.stored, who.id))
			sessions := h.count("SELECT count(*) FROM identity.session")
			challenge := h.beginPasskey(newClaim(t), from)
			assertion := assertionOf(who.authenticator.Assert(who.key, challenge.GetChallenge(), item.assertion))
			tx, err := h.migration.Begin(ctx)
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = tx.Rollback(ctx) }()
			if _, err = tx.Exec(ctx, "UPDATE identity.auth_identity SET sign_count = $2, rev = rev + 1 WHERE user_id = $1 AND provider_id = 'passkey'",
				who.id, int64(item.current)); err != nil {
				t.Fatal(err)
			}
			done := make(chan string, 1)
			go func() {
				answer := h.post(completePath, &publicapiv1.IdentityServiceCompleteAuthenticationRequest{Meta: meta(), FlowId: challenge.GetFlowId(),
					Proof: &publicapiv1.AuthProof{Proof: &publicapiv1.AuthProof_Passkey{Passkey: assertion}}}, from)
				var response publicapiv1.IdentityServiceCompleteAuthenticationResponse
				if answer.status != "0" || proto.Unmarshal(answer.body, &response) != nil {
					done <- "transport " + answer.status
					return
				}
				done <- failure(response.GetError())
			}()
			waited := false
			for deadline := time.Now().Add(10 * time.Second); !waited && time.Now().Before(deadline); time.Sleep(20 * time.Millisecond) {
				var waiting int
				if err = tx.QueryRow(ctx, "SELECT count(*) FROM pg_locks l WHERE NOT l.granted AND pg_backend_pid() = ANY(pg_blocking_pids(l.pid))").
					Scan(&waiting); err != nil {
					t.Fatal(err)
				}
				waited = waiting > 0
			}
			if err = tx.Commit(ctx); err != nil {
				t.Fatal(err)
			}
			result := <-done
			if !waited {
				t.Fatalf("the sign-in never waited on the credential's row (%s)", result)
			}
			if result != "AUTHENTICATION/unauthenticated" || h.count("SELECT count(*) FROM identity.session") != sessions ||
				h.count("SELECT sign_count FROM identity.auth_identity WHERE user_id = $1 AND provider_id = 'passkey'", who.id) != int(item.current) {
				t.Fatalf("result %s", result)
			}
		})
	}
	h.verifyAudit()
}

// lostCommit is a deferred trigger function that fails a COMMIT with the Neon pooler's protocol violation (08P01), which leaves the
// outcome of the commit unknown to the center (F6).
func (h *harness) lostCommit() {
	h.exec("CREATE SCHEMA IF NOT EXISTS testfault",
		"CREATE FUNCTION testfault.lost() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'the commit was lost (test)' USING ERRCODE = '08P01'; END; $$")
}

// TestOnlyTheCallsEffectReportsAnUnknownCommit (D10): a COMMIT without a definite answer of an auxiliary transaction, here
// RefreshSession's count of its client prefix's bucket, leaves the call's effect undone: the reply is RESOURCE/overloaded with
// AFTER_TIME and DID_NOT_HAPPEN, the refresh token is not spent, and the same token then rotates. The same failure of the rotation
// itself may have committed: INTERNAL/internal with effect UNKNOWN and retry NEVER, logged.
func TestOnlyTheCallsEffectReportsAnUnknownCommit(t *testing.T) {
	h := newHarness(t, settings{})
	who := h.seedAccount(1, "")
	claim := newClaim(t)
	native := h.signIn(who, claim, caller{})
	var sessionID platform.ID
	copy(sessionID[:], native.GetSessionId().GetValue())
	refresh := func(token string) *publicapiv1.IdentityServiceRefreshSessionResponse {
		response := rpc(h, refreshPath, &publicapiv1.IdentityServiceRefreshSessionRequest{Meta: meta(), RefreshToken: proto.String(token),
			InstallationId: claim.GetInstallationId()}, caller{}, &publicapiv1.IdentityServiceRefreshSessionResponse{})
		if value := response.GetValue().GetSession(); value != nil {
			h.remember(value.GetAccessToken(), value.GetRefreshToken())
		}
		return response
	}
	generation := func() int {
		return h.count("SELECT refresh_generation FROM identity.session WHERE session_id = $1", sessionID)
	}
	h.lostCommit()
	h.exec("CREATE CONSTRAINT TRIGGER test_lost AFTER INSERT OR UPDATE ON platform.rate_limit DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION testfault.lost()")
	counted := refresh(native.GetRefreshToken()).GetError()
	if failure(counted) != "RESOURCE/overloaded" || counted.GetRetry().GetMode() != foundationv1.RetryMode_RETRY_MODE_AFTER_TIME ||
		counted.GetEffect() != foundationv1.EffectCertainty_EFFECT_CERTAINTY_DID_NOT_HAPPEN || generation() != 1 ||
		h.count("SELECT count(*) FROM identity.spent_refresh") != 0 {
		t.Fatalf("a lost commit of the prefix count: %v (generation %d)", counted, generation())
	}
	h.exec("DROP TRIGGER test_lost ON platform.rate_limit")
	rotated := refresh(native.GetRefreshToken())
	if rotated.GetError() != nil || generation() != 2 || h.audits("identity.session.refresh_reused") != 0 {
		t.Fatalf("the same token after the lost count: %s", failure(rotated.GetError()))
	}
	h.exec("CREATE CONSTRAINT TRIGGER test_lost AFTER INSERT ON identity.spent_refresh DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION testfault.lost()")
	unknown := refresh(rotated.GetValue().GetSession().GetRefreshToken()).GetError()
	if failure(unknown) != "INTERNAL/internal" || unknown.GetRetry().GetMode() != foundationv1.RetryMode_RETRY_MODE_NEVER ||
		unknown.GetEffect() != foundationv1.EffectCertainty_EFFECT_CERTAINTY_UNKNOWN || !strings.Contains(h.logs.String(), "the outcome of the commit is unknown") {
		t.Fatalf("a lost commit of the rotation: %v", unknown)
	}
	h.exec("DROP TRIGGER test_lost ON identity.spent_refresh")
	h.verifyAudit()
}

// TestARightCodeWhoseSignInFailedGetsItsReservationBack (D2): a right e-mail code whose success transaction fails in the store
// answers RESOURCE/overloaded with AFTER_TIME and gives back both its flow attempt (F9) and its reservation in the address's failure
// bucket (E6), however often the store fails, so the advised identical retry signs in even with the bucket one short of its limit.
func TestARightCodeWhoseSignInFailedGetsItsReservationBack(t *testing.T) {
	h := newHarness(t, settings{policy: `{"signInPerPrefixLimit": 1000, "emailPerAddressLimit": 100, "emailPerPrefixLimit": 100}`})
	address := "owner@example.org"
	h.seedAccount(1, address)
	h.remember(address)
	digest := sha256.Sum256([]byte(address))
	bucket := sha256.Sum256([]byte("redeem_failures_address\x00" + hex.EncodeToString(digest[:])))
	failures := func() int { return h.count("SELECT count FROM platform.rate_limit WHERE bucket_hash = $1", bucket[:]) }
	// A wrong code on another flow creates the bucket's row; then it holds nine of its ten failures.
	other := h.beginEmail(address, caller{ip: "192.0.2.50"}).GetValue().GetChallenge().GetFlowId()
	h.requestCode(other, address, caller{ip: "192.0.2.50"})
	if result := failure(h.redeem(other, "BCDF-GHJK", caller{ip: "192.0.2.50"}).GetError()); result != "AUTHENTICATION/unauthenticated" {
		t.Fatalf("a wrong code: %s", result)
	}
	h.exec("UPDATE platform.rate_limit SET count = 9 WHERE bucket_hash = '\\x" + hex.EncodeToString(bucket[:]) + "'")
	flow := h.beginEmail(address, caller{}).GetValue().GetChallenge().GetFlowId()
	h.requestCode(flow, address, caller{})
	code := h.lastCode(address)
	h.exec("CREATE SCHEMA testfault",
		"CREATE FUNCTION testfault.unavailable() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'the store is unavailable (test)' USING ERRCODE = '57P01'; END; $$",
		"CREATE TRIGGER test_unavailable BEFORE INSERT ON identity.session FOR EACH ROW EXECUTE FUNCTION testfault.unavailable()")
	for try := range 3 {
		refusal := h.redeem(flow, code, caller{}).GetError()
		if failure(refusal) != "RESOURCE/overloaded" || refusal.GetRetry().GetMode() != foundationv1.RetryMode_RETRY_MODE_AFTER_TIME ||
			refusal.GetEffect() != foundationv1.EffectCertainty_EFFECT_CERTAINTY_DID_NOT_HAPPEN || failures() != 9 {
			t.Fatalf("try %d of the right code with the store failing: %v, %d failures counted", try+1, refusal, failures())
		}
	}
	h.exec("DROP TRIGGER test_unavailable ON identity.session")
	if response := h.redeem(flow, code, caller{}); response.GetError() != nil || failures() != 9 {
		t.Fatalf("the identical retry: %s, %d failures counted", failure(response.GetError()), failures())
	}
	h.verifyAudit()
}

// addPasskey gives a seeded account a second passkey, of another authenticator.
func (h *harness) addPasskey(who account) account {
	h.t.Helper()
	rp, err := passkey.New(rpID, origin)
	if err != nil {
		h.t.Fatal(err)
	}
	other := who
	other.authenticator = virtual.New(rpID, origin)
	challenge := randomBytes(h.t, 32)
	creation, key := other.authenticator.Create(challenge, who.handle)
	credential, err := rp.VerifyCreation(challenge, who.handle, creation, time.Now().Add(time.Minute))
	if err != nil {
		h.t.Fatal(err)
	}
	other.key = key
	if _, err = h.migration.Exec(context.Background(), `INSERT INTO identity.auth_identity (auth_identity_id, user_id, method, provider_id, subject, public_key, user_handle,
    sign_count, backup_eligible, backup_state, transports, aaguid, attestation_format, created_at, rev)
VALUES ($1, $2, 1, 'passkey', $3, $4, $5, 0, false, false, '{}', $6, 'none', $7, 1)`, platform.NewID(), who.id,
		base64.RawURLEncoding.EncodeToString(credential.ID), credential.PublicKey, who.handle, credential.AAGUID, h.clock.Now().Add(-time.Second)); err != nil {
		h.t.Fatal(err)
	}
	return other
}

// TestALostRaceForANewInstallationGivesTheAttemptBack (D4): two first sign-ins of one new installation with two passkeys of one
// account race; the loser meets the winner's installation on its primary key, which is a store contention: RESOURCE/overloaded
// with AFTER_TIME and DID_NOT_HAPPEN, its flow keeps its attempt, and the identical retry signs in on the winner's installation. The
// audit chain's head is held until both sign-ins wait (one on it, one on the other's installation), so the race is deterministic.
func TestALostRaceForANewInstallationGivesTheAttemptBack(t *testing.T) {
	h := newHarness(t, settings{})
	ctx := context.Background()
	first := h.seedAccount(1, "")
	second := h.addPasskey(first)
	claim := newClaim(t)
	requests := make([]*publicapiv1.IdentityServiceCompleteAuthenticationRequest, 2)
	for index, who := range []account{first, second} {
		challenge := h.beginPasskey(claim, caller{})
		requests[index] = &publicapiv1.IdentityServiceCompleteAuthenticationRequest{Meta: meta(), FlowId: challenge.GetFlowId(),
			Proof: &publicapiv1.AuthProof{Proof: &publicapiv1.AuthProof_Passkey{Passkey: assertionOf(who.authenticator.Assert(who.key, challenge.GetChallenge()))}}}
	}
	tx, err := h.migration.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if _, err = tx.Exec(ctx, "SELECT 1 FROM audit.chain_head WHERE singleton FOR UPDATE"); err != nil {
		t.Fatal(err)
	}
	type result struct {
		index     int
		response  *publicapiv1.IdentityServiceCompleteAuthenticationResponse
		transport string
	}
	done := make(chan result, 2)
	for index, request := range requests {
		go func() {
			answer := h.post(completePath, request, caller{})
			var response publicapiv1.IdentityServiceCompleteAuthenticationResponse
			if answer.status != "0" || proto.Unmarshal(answer.body, &response) != nil {
				done <- result{index: index, transport: answer.status}
				return
			}
			done <- result{index: index, response: &response}
		}()
	}
	waiting := 0
	for deadline := time.Now().Add(10 * time.Second); waiting < 2 && time.Now().Before(deadline); time.Sleep(20 * time.Millisecond) {
		if err = tx.QueryRow(ctx, `WITH RECURSIVE blocked(pid) AS (
    SELECT l.pid FROM pg_locks l WHERE NOT l.granted AND pg_backend_pid() = ANY(pg_blocking_pids(l.pid))
    UNION SELECT l.pid FROM pg_locks l JOIN blocked b ON b.pid = ANY(pg_blocking_pids(l.pid)) WHERE NOT l.granted)
SELECT count(DISTINCT pid) FROM blocked`).Scan(&waiting); err != nil {
			t.Fatal(err)
		}
	}
	if err = tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	results := [2]result{}
	for range 2 {
		item := <-done
		results[item.index] = item
	}
	if waiting < 2 {
		t.Fatalf("the sign-ins never both waited (%d)", waiting)
	}
	loser := -1
	for index, item := range results {
		if item.response == nil {
			t.Fatalf("completion %d: grpc-status %s", index, item.transport)
		}
		if value := item.response.GetValue().GetSession(); value != nil {
			h.remember(value.GetAccessToken(), value.GetRefreshToken())
			continue
		}
		refusal := item.response.GetError()
		if failure(refusal) != "RESOURCE/overloaded" || refusal.GetRetry().GetMode() != foundationv1.RetryMode_RETRY_MODE_AFTER_TIME ||
			refusal.GetEffect() != foundationv1.EffectCertainty_EFFECT_CERTAINTY_DID_NOT_HAPPEN || loser != -1 {
			t.Fatalf("completion %d: %v", index, refusal)
		}
		loser = index
	}
	if loser == -1 {
		t.Fatal("both first sign-ins of one installation succeeded without a race")
	}
	var loserFlow platform.ID
	copy(loserFlow[:], requests[loser].GetFlowId().GetValue())
	if h.count("SELECT attempts FROM identity.auth_flow WHERE flow_id = $1 AND consumed_at IS NULL", loserFlow) != 0 {
		t.Fatal("the losing flow did not get its attempt back")
	}
	retried := rpc(h, completePath, requests[loser], caller{}, &publicapiv1.IdentityServiceCompleteAuthenticationResponse{})
	if value := retried.GetValue().GetSession(); value != nil {
		h.remember(value.GetAccessToken(), value.GetRefreshToken())
	}
	if retried.GetError() != nil || h.count("SELECT count(*) FROM identity.session") != 2 || h.count("SELECT count(*) FROM device.installation") != 1 {
		t.Fatalf("the identical retry: %s", failure(retried.GetError()))
	}
	h.verifyAudit()
}
