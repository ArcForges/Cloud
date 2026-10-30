// SPDX-License-Identifier: AGPL-3.0-only

package identityapi_test

import (
	"crypto/sha256"
	"encoding/hex"
	"go/ast"
	"go/parser"
	"go/token"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	foundationv1 "github.com/ArcForges/Contracts/go/arcforges/foundation/v1"
	publicapiv1 "github.com/ArcForges/Contracts/go/arcforges/publicapi/v1"
	"google.golang.org/protobuf/proto"

	"github.com/ArcForges/Cloud/center/internal/identity"
	"github.com/ArcForges/Cloud/center/internal/identity/passkey/virtual"
	"github.com/ArcForges/Cloud/center/internal/session"
)

// The commit roles of D10 (R1 of the A1a review): a COMMIT without a definite answer leaves the effect of an effect transaction
// unknown (INTERNAL/internal, retry NEVER, effect UNKNOWN, logged), and a reservation or attempt is never given back after it (D2);
// the same failure of an auxiliary transaction (bookkeeping before or after the effect) leaves the call's effect undone
// (RESOURCE/overloaded, AFTER_TIME, DID_NOT_HAPPEN, a warning log), and the identical retry succeeds. A deferred constraint trigger
// fails the COMMIT of exactly the transaction under test with the Neon pooler's protocol violation (lostCommit).

func unknownCommit(value *foundationv1.ArcError) bool {
	return failure(value) == "INTERNAL/internal" && value.GetRetry().GetMode() == foundationv1.RetryMode_RETRY_MODE_NEVER &&
		value.GetEffect() == foundationv1.EffectCertainty_EFFECT_CERTAINTY_UNKNOWN
}

func undoneCommit(value *foundationv1.ArcError) bool {
	return failure(value) == "RESOURCE/overloaded" && value.GetRetry().GetMode() == foundationv1.RetryMode_RETRY_MODE_AFTER_TIME &&
		value.GetRetry().GetRetryAt() != nil && value.GetEffect() == foundationv1.EffectCertainty_EFFECT_CERTAINTY_DID_NOT_HAPPEN
}

// losing fails the COMMIT of the transactions that change a table as the event (and condition) names, while run runs.
func (h *harness) losing(event, table, condition string, run func()) {
	h.t.Helper()
	when := ""
	if condition != "" {
		when = " WHEN (" + condition + ")"
	}
	h.exec("CREATE CONSTRAINT TRIGGER test_lost AFTER " + event + " ON " + table + " DEFERRABLE INITIALLY DEFERRED FOR EACH ROW" + when +
		" EXECUTE FUNCTION testfault.lost()")
	defer h.exec("DROP TRIGGER test_lost ON " + table)
	run()
}

func TestALostCommitOfTheCallsEffectIsUnknown(t *testing.T) {
	h := newHarness(t, settings{policy: `{"signInPerPrefixLimit": 1000, "emailPerAddressLimit": 100, "emailPerPrefixLimit": 100, "stepUpPerAccountLimit": 100,
"signInFailuresAccountLimit": 100}`})
	h.lostCommit()
	check := func(what string, value *foundationv1.ArcError) {
		t.Helper()
		if !unknownCommit(value) {
			t.Errorf("%s: %v", what, value)
		}
	}
	// The bootstrap first: once an account exists, it is refused before its transaction.
	h.losing("INSERT", "identity.bootstrap", "", func() {
		response, _, _ := h.enroll(h.bootstrap, newClaim(t), caller{})
		check("the owner bootstrap", response.GetError())
	})
	address := "effects@example.org"
	who := h.seedAccount(1, address)
	h.remember(address)

	// A1a: a flow's creation, a code's send and a sign-in.
	h.losing("INSERT", "identity.auth_flow", "", func() {
		check("the creation of a flow", rpc(h, beginPath, &publicapiv1.IdentityServiceBeginAuthenticationRequest{Meta: meta(),
			Method: publicapiv1.AuthMethod_AUTH_METHOD_EMAIL.Enum(), Purpose: publicapiv1.AuthPurpose_AUTH_PURPOSE_AUTHENTICATE.Enum(),
			LoginHint: proto.String(address), Installation: newClaim(t)}, caller{}, &publicapiv1.IdentityServiceBeginAuthenticationResponse{}).GetError())
	})
	flow := h.beginEmail(address, caller{}).GetValue().GetChallenge().GetFlowId()
	h.losing("UPDATE", "identity.auth_flow", "", func() { check("a code's send", h.requestCode(flow, address, caller{}).GetError()) })
	flow = h.beginEmail(address, caller{}).GetValue().GetChallenge().GetFlowId()
	h.requestCode(flow, address, caller{})
	code := h.lastCode(address)
	digest := sha256.Sum256([]byte(address))
	bucket := sha256.Sum256([]byte("redeem_failures_address\x00" + hex.EncodeToString(digest[:])))
	h.losing("INSERT", "identity.session", "", func() {
		check("a sign-in", h.redeem(flow, code, caller{}).GetError())
		// D2: the failure the right code reserved is not given back after an unknown commit (the sign-in may have happened).
		if h.count("SELECT coalesce(sum(count), 0)::int FROM platform.rate_limit WHERE bucket_hash = $1", bucket[:]) != 1 {
			t.Error("the reservation was given back after an unknown commit")
		}
	})
	failures := func() int { return h.count("SELECT coalesce(sum(count), 0)::int FROM platform.rate_limit") }

	// A1b: a step-up's begin and proof, a registration's begin and a receipt-guarded write.
	from := bearer(h.signIn(who, newClaim(t), caller{}).GetAccessToken())
	target := h.issue(who.id, session.ScopeAccount, false).sessionID
	h.losing("INSERT", "identity.step_up_challenge", "", func() {
		check("a step-up's begin", h.beginStepUp(who, from, identity.ClassRevokeSession, target).GetError())
	})
	challenge := h.beginStepUp(who, from, identity.ClassRevokeSession, target).GetValue().GetChallenge()
	// CompleteStepUp counts no bucket but the failure it reserves.
	before := failures()
	h.losing("UPDATE", "identity.step_up_challenge", "OLD.state = 1 AND NEW.state = 2", func() {
		check("a step-up's proof", h.completeStepUp(who, from, challenge).GetError())
		// D2: neither the reserved failure nor the attempt is given back after an unknown commit.
		if failures() != before+1 || h.count("SELECT attempt_count FROM identity.step_up_challenge WHERE challenge_id = $1", idFrom(challenge.GetFlowId())) != 1 {
			t.Errorf("a step-up's proof gave its reservation or its attempt back after an unknown commit (%d failures, %d before)", failures(), before)
		}
	})
	h.stepUp(who, from, identity.ClassBeginRegistration, who.id)
	h.losing("INSERT", "identity.auth_flow", "", func() {
		check("a registration's begin", rpc(h, beginRegisterPath, &publicapiv1.IdentityServiceBeginPasskeyRegistrationRequest{Meta: meta(),
			DisplayName: proto.String("Key")}, from, &publicapiv1.IdentityServiceBeginPasskeyRegistrationResponse{}).GetError())
	})
	h.stepUp(who, from, identity.ClassRevokeSession, target)
	write := command()
	h.losing("INSERT", "platform.command_receipt", "", func() { check("a receipt-guarded write", h.revokeSession(from, write, target).GetError()) })
	// Here the COMMIT did fail, so the identical retry runs the command anew.
	expect(t, "the identical retry of the write", h.revokeSession(from, write, target).GetError(), "")
	if !strings.Contains(h.logs.String(), "the outcome of the commit is unknown") {
		t.Error("an unknown commit was not logged")
	}
	h.verifyAudit()
}

func TestALostCommitOfBookkeepingIsRetryable(t *testing.T) {
	h := newHarness(t, settings{policy: `{"signInPerPrefixLimit": 1000, "emailPerAddressLimit": 100, "emailPerPrefixLimit": 100, "stepUpPerAccountLimit": 100,
"signInFailuresAccountLimit": 100}`})
	address := "bookkeeping@example.org"
	who := h.seedAccount(1, address)
	h.remember(address)
	h.lostCommit()
	check := func(what string, value *foundationv1.ArcError) {
		t.Helper()
		if !undoneCommit(value) {
			t.Errorf("%s: %v", what, value)
		}
	}

	// A1a: a flow attempt's count.
	flow := h.beginEmail(address, caller{}).GetValue().GetChallenge().GetFlowId()
	h.requestCode(flow, address, caller{})
	code := h.lastCode(address)
	h.losing("UPDATE", "identity.auth_flow", "", func() { check("a flow attempt's count", h.redeem(flow, code, caller{}).GetError()) })
	expect(t, "the identical redeem", h.redeem(flow, code, caller{}).GetError(), "")

	// A1b: a step-up attempt's count and a step-up's denial.
	from := bearer(h.signIn(who, newClaim(t), caller{}).GetAccessToken())
	target := h.issue(who.id, session.ScopeAccount, false).sessionID
	challenge := h.beginStepUp(who, from, identity.ClassRevokeSession, target).GetValue().GetChallenge()
	h.losing("UPDATE", "identity.step_up_challenge", "NEW.attempt_count > OLD.attempt_count", func() {
		check("a step-up attempt's count", h.completeStepUp(who, from, challenge).GetError())
	})
	expect(t, "the identical proof", h.completeStepUp(who, from, challenge).GetError(), "")
	stranger := virtual.New(rpID, origin)
	_, strangerKey := stranger.Create(randomBytes(t, 32), who.handle)
	denied := h.beginStepUp(who, from, identity.ClassRevokeSession, target).GetValue().GetChallenge()
	h.losing("UPDATE", "identity.step_up_challenge", "NEW.state = 5", func() {
		check("a step-up's denial", rpc(h, completeStepUpPath, &publicapiv1.IdentityServiceCompleteStepUpRequest{Meta: meta(), FlowId: denied.GetFlowId(),
			Proof: &publicapiv1.AuthProof{Proof: &publicapiv1.AuthProof_Passkey{Passkey: assertionOf(stranger.Assert(strangerKey, denied.GetChallenge()))}}},
			from, &publicapiv1.IdentityServiceCompleteStepUpResponse{}).GetError())
	})
	// The lost denial leaves the challenge pending with its one attempt spent: even the owner's proof is STATE/expired (B12, the
	// per-challenge attempt bound).
	expect(t, "the owner's proof after the lost denial", h.completeStepUp(who, from, denied).GetError(), "STATE/expired")

	// A1b: a registration attempt's count; the same command then registers the passkey.
	h.stepUp(who, from, identity.ClassBeginRegistration, who.id)
	begun := rpc(h, beginRegisterPath, &publicapiv1.IdentityServiceBeginPasskeyRegistrationRequest{Meta: meta(), DisplayName: proto.String("Key")}, from,
		&publicapiv1.IdentityServiceBeginPasskeyRegistrationResponse{}).GetValue().GetChallenge()
	creation, _ := virtual.New(rpID, origin).Create(begun.GetChallenge(), who.handle)
	register := command()
	complete := func() *foundationv1.ArcError {
		return rpc(h, completeRegisterPath, &publicapiv1.IdentityServiceCompletePasskeyRegistrationRequest{Meta: register, FlowId: begun.GetFlowId(),
			Credential: creationOf(creation)}, from, &publicapiv1.IdentityServiceCompletePasskeyRegistrationResponse{}).GetError()
	}
	h.losing("UPDATE", "identity.auth_flow", "NEW.attempts > OLD.attempts", func() { check("a registration attempt's count", complete()) })
	expect(t, "the identical registration", complete(), "")
	lines := strings.Split(h.logs.String(), "\n")
	for _, operation := range []string{"count a flow attempt", "count a step-up attempt", "deny a step-up", "count a registration attempt"} {
		logged := false
		for _, line := range lines {
			logged = logged || strings.Contains(line, `"level":"WARN"`) && strings.Contains(line, `"msg":"an auxiliary commit went unanswered"`) &&
				strings.Contains(line, `"operation":"`+operation+`"`)
		}
		if !logged {
			t.Errorf("the unanswered commit of %q was not logged as a warning", operation)
		}
	}
	h.verifyAudit()
}

// TestAStoreFailureAfterAStepUpProofGivesTheAttemptBack (F9, D2, B17): a passkey step-up whose proof verified but whose proof
// transaction failed in the store answers RESOURCE/overloaded (AFTER_TIME, DID_NOT_HAPPEN) and gives back both its single attempt
// and its reservation in the account's failure bucket, however often the store fails; the identical retry then proves, and once
// more is CONFLICT/code_reused.
func TestAStoreFailureAfterAStepUpProofGivesTheAttemptBack(t *testing.T) {
	h := newHarness(t, settings{policy: writePolicy})
	who := h.seedAccount(1, "")
	from := bearer(h.signIn(who, newClaim(t), caller{}).GetAccessToken())
	target := h.issue(who.id, session.ScopeAccount, false).sessionID
	bucket := sha256.Sum256([]byte("sign_in_failures_account\x00account:" + who.id.String()))
	failures := func() int {
		return h.count("SELECT coalesce(sum(count), 0)::int FROM platform.rate_limit WHERE bucket_hash = $1", bucket[:])
	}
	challenge := h.beginStepUp(who, from, identity.ClassRevokeSession, target).GetValue().GetChallenge()
	challengeID := idFrom(challenge.GetFlowId())
	attempts := func() int {
		return h.count("SELECT attempt_count FROM identity.step_up_challenge WHERE challenge_id = $1", challengeID)
	}
	request := &publicapiv1.IdentityServiceCompleteStepUpRequest{Meta: meta(), FlowId: challenge.GetFlowId(),
		Proof: &publicapiv1.AuthProof{Proof: &publicapiv1.AuthProof_Passkey{Passkey: assertionOf(who.authenticator.Assert(who.key, challenge.GetChallenge()))}}}
	complete := func() *publicapiv1.IdentityServiceCompleteStepUpResponse {
		return rpc(h, completeStepUpPath, request, from, &publicapiv1.IdentityServiceCompleteStepUpResponse{})
	}
	before := failures()
	h.exec("CREATE SCHEMA testfault",
		"CREATE FUNCTION testfault.unavailable() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'the store is unavailable (test)' USING ERRCODE = '57P01'; END; $$",
		"CREATE TRIGGER test_unavailable BEFORE UPDATE ON identity.step_up_challenge FOR EACH ROW WHEN (OLD.state = 1 AND NEW.state = 2) EXECUTE FUNCTION testfault.unavailable()")
	for try := range 2 {
		if refusal := complete().GetError(); !undoneCommit(refusal) || attempts() != 0 || failures() != before {
			t.Fatalf("try %d of the right proof with the store failing: %v (%d attempts, %d failures, %d before)", try+1, refusal, attempts(), failures(), before)
		}
	}
	h.exec("DROP TRIGGER test_unavailable ON identity.step_up_challenge")
	if response := complete(); response.GetError() != nil || response.GetValue().GetEvidence() == nil || attempts() != 1 || failures() != before ||
		h.count("SELECT state FROM identity.step_up_challenge WHERE challenge_id = $1", challengeID) != 2 {
		t.Fatalf("the identical retry: %s (%d attempts, %d failures, %d before)", failure(response.GetError()), attempts(), failures(), before)
	}
	expect(t, "the identical retry after its success", complete().GetError(), "CONFLICT/code_reused")
	h.verifyAudit()
}

// TestEveryTransactionOfTheSurfaceStatesItsRole pins the role of each transaction of the identity surface (D10): its name and
// whether it is read-only, auxiliary bookkeeping or the call's effect. A new transaction fails this test until it is classified
// here, and a changed Auxiliary flag fails it as well.
func TestEveryTransactionOfTheSurfaceStatesItsRole(t *testing.T) {
	const read, auxiliary, effect = "read-only", "auxiliary", "effect"
	roles := map[string]string{
		// Reads.
		"find an e-mail flow": read, "read a profile": read, "list credentials": read, "check for an account": read, "find a passkey": read,
		"list sessions": read, "verify a session": read, "check a rate-limit bucket": read, "list devices": read,
		// Bookkeeping: counts, reservations, denials and give-backs around an effect, and the audits of refusals.
		"count a rate-limit bucket": auxiliary, "reserve a rate-limit failure": auxiliary, "give a failure reservation back": auxiliary,
		"audit an identity refusal": auxiliary, "audit an access decision": auxiliary, "count a flow attempt": auxiliary,
		"end an exhausted flow": auxiliary, "release a flow attempt": auxiliary, "count a step-up attempt": auxiliary, "deny a step-up": auxiliary,
		"release a step-up attempt": auxiliary, "count a registration attempt": auxiliary,
		// A2: a browser session's renewal on a page load or the bootstrap read.
		"renew a browser session": auxiliary,
		// Effects.
		"begin a sign-in": effect, "send an e-mail code": effect, "complete a sign-in": effect, "bootstrap the owner": effect,
		"refresh a session": effect, "begin a step-up": effect, "prove a step-up": effect, "begin a passkey registration": effect,
		"execute a command under its receipt": effect,
		// A2: the browser's sign-out (the pages' logout route).
		"sign out": effect,
	}
	found := map[string]string{}
	for _, directory := range []string{".", "../identity", "../access", "../ratelimit", "../session", "../device", "../pages"} {
		files, err := filepath.Glob(filepath.Join(directory, "*.go"))
		if err != nil {
			t.Fatal(err)
		}
		for _, file := range files {
			if strings.HasSuffix(file, "_test.go") {
				continue
			}
			parsed, err := parser.ParseFile(token.NewFileSet(), file, nil, 0)
			if err != nil {
				t.Fatal(err)
			}
			ast.Inspect(parsed, func(node ast.Node) bool {
				call, ok := node.(*ast.CallExpr)
				if !ok {
					return true
				}
				selector, ok := call.Fun.(*ast.SelectorExpr)
				if !ok {
					return true
				}
				var name string
				var options ast.Expr
				switch {
				case selector.Sel.Name == "InTx" && len(call.Args) == 4:
					literal, ok := call.Args[1].(*ast.BasicLit)
					if !ok {
						t.Errorf("%s: a transaction without a literal name", file)
						return true
					}
					name, _ = strconv.Unquote(literal.Value)
					options = call.Args[2]
				case selector.Sel.Name == "Execute" && len(call.Args) == 5:
					if receiver, ok := selector.X.(*ast.Ident); !ok || receiver.Name != "platform" {
						return true
					}
					name, options = "execute a command under its receipt", call.Args[3]
				default:
					return true
				}
				role := effect
				composite, ok := options.(*ast.CompositeLit)
				if !ok {
					t.Errorf("%s: the options of %q are not a literal", file, name)
					return true
				}
				for _, element := range composite.Elts {
					pair, ok := element.(*ast.KeyValueExpr)
					if !ok {
						continue
					}
					key, _ := pair.Key.(*ast.Ident)
					value, _ := pair.Value.(*ast.Ident)
					switch {
					case key == nil || value == nil || value.Name != "true":
					case key.Name == "ReadOnly":
						role = read
					case key.Name == "Auxiliary":
						role = auxiliary
					}
				}
				if previous, twice := found[name]; twice && previous != role {
					t.Errorf("two transactions named %q have different roles", name)
				}
				found[name] = role
				return true
			})
		}
	}
	for name, role := range found {
		if roles[name] != role {
			t.Errorf("the transaction %q is %s; the table says %q", name, role, roles[name])
		}
	}
	for name := range roles {
		if _, ok := found[name]; !ok {
			t.Errorf("the table lists %q, which no code runs", name)
		}
	}
}
