// SPDX-License-Identifier: AGPL-3.0-only

package identity

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"net/netip"
	"regexp"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/ArcForges/Cloud/center/internal/config"
	"github.com/ArcForges/Cloud/center/internal/dbtest"
	"github.com/ArcForges/Cloud/center/internal/device"
	"github.com/ArcForges/Cloud/center/internal/identity/passkey"
	"github.com/ArcForges/Cloud/center/internal/identity/passkey/virtual"
	"github.com/ArcForges/Cloud/center/internal/mail"
	"github.com/ArcForges/Cloud/center/internal/platform"
	"github.com/ArcForges/Cloud/center/internal/session"
	"github.com/ArcForges/Cloud/center/internal/store"
)

// These tests use the actual PostgreSQL runtime grants, PBKDF2 verifiers,
// WebAuthn signature/COSE/origin validation, transaction receipts and epochs.
// The mail peer only captures transport; it grants no authentication success.
type lifecycleRig struct {
	t      *testing.T
	db     *dbtest.Database
	s      *Service
	now    time.Time
	user   platform.ID
	caller Caller
	issued session.Browser
	mail   *mail.Fake
	auth   *virtual.Authenticator
	key    *virtual.Key
}

func newLifecycleRig(t *testing.T, state int16) *lifecycleRig {
	t.Helper()
	r := &lifecycleRig{t: t, db: dbtest.New(t), now: time.Now().UTC().Truncate(time.Microsecond), mail: mail.NewFake(), auth: virtual.New("center.example.test", "https://center.example.test")}
	rp, err := passkey.New("center.example.test", "https://center.example.test")
	if err != nil {
		t.Fatal(err)
	}
	policy := config.DefaultIdentityPolicy()
	r.s = New(Options{DB: r.db.Runtime, Policy: policy, RP: rp, Mail: r.mail, Clock: func() time.Time { return r.now }, Background: func(work func()) { work() }})
	r.user = r.db.Account(state)
	var handle []byte
	if err = r.db.Migration.QueryRow(context.Background(), `SELECT passkey_user_handle FROM identity.user WHERE user_id=$1`, r.user).Scan(&handle); err != nil {
		t.Fatal(err)
	}
	challenge := randomBytes(32)
	creation, key := r.auth.Create(challenge, handle)
	r.key = key
	credential, err := rp.VerifyCreation(challenge, handle, creation, r.now.Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	_, err = r.db.Migration.Exec(context.Background(), `INSERT INTO identity.auth_identity(auth_identity_id,user_id,method,provider_id,subject,public_key,user_handle,sign_count,backup_eligible,backup_state,transports,aaguid,attestation_format,created_at,rev)
VALUES($1,$2,1,'passkey',$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,1)`, platform.NewID(), r.user, base64.RawURLEncoding.EncodeToString(credential.ID), credential.PublicKey, handle,
		int64(credential.SignCount), credential.BackupEligible, credential.BackupState, credential.Transports, credential.AAGUID, credential.AttestationFormat, r.now)
	if err != nil {
		t.Fatal(err)
	}
	_, err = r.db.Migration.Exec(context.Background(), `INSERT INTO identity.auth_identity(auth_identity_id,user_id,method,provider_id,subject,created_at,rev) VALUES($1,$2,2,'email','owner@example.test',$3,1)`, platform.NewID(), r.user, r.now)
	if err != nil {
		t.Fatal(err)
	}
	r.signIn()
	return r
}

func (r *lifecycleRig) request() Request { return Request{ClientIP: netip.MustParseAddr("192.0.2.23")} }
func (r *lifecycleRig) claim() device.Claim {
	return device.Claim{InstallationID: platform.NewID(), Product: "arcforges-web", Platform: "web", AppVersion: "web"}
}
func (r *lifecycleRig) signIn() {
	r.t.Helper()
	challenge, err := r.s.BeginAuthentication(context.Background(), r.request(), Begin{Method: MethodValuePasskey, Purpose: int32(PurposeAuthenticate), Claim: r.claim(), HasClaim: true, Browser: true})
	if err != nil {
		r.t.Fatal(err)
	}
	result, err := r.s.CompleteBrowserPasskey(context.Background(), r.request(), challenge.FlowID, r.auth.Assert(r.key, challenge.Challenge))
	if err != nil {
		r.t.Fatal(err)
	}
	r.issued = *result.Browser
	r.caller = Caller{Request: r.request(), UserID: r.user, SessionID: result.Browser.SessionID, DeviceID: result.Device.DeviceID, Scope: "account", Browser: true,
		AuthEpoch: result.Browser.AuthEpoch, RecoveryGeneration: result.Browser.RecoveryGeneration}
}
func (r *lifecycleRig) prove(class string, target platform.ID) {
	r.t.Helper()
	method := int32(MethodValuePasskey)
	hash := TargetHash(class, r.user, target)
	challenge, err := r.s.BeginStepUp(context.Background(), r.caller, StepUpBegin{Class: &class, Method: &method, TargetHash: &hash})
	if err != nil {
		r.t.Fatal(err)
	}
	if _, err = r.s.CompleteStepUp(context.Background(), r.caller, challenge.FlowID, StepUpProof{Passkey: ptrAssertion(r.auth.Assert(r.key, challenge.Challenge))}); err != nil {
		r.t.Fatal(err)
	}
}
func ptrAssertion(value passkey.Assertion) *passkey.Assertion { return &value }
func (r *lifecycleRig) tx(run func(context.Context, pgx.Tx) error) error {
	return r.db.Runtime.InTx(context.Background(), "lifecycle test", store.TxOptions{}, run)
}

func (r *lifecycleRig) readExport(id platform.ID) []byte {
	r.t.Helper()
	var body []byte
	for offset := 0; offset <= MaxExportBytes; {
		page, err := r.s.ReadExport(context.Background(), r.caller, id, offset, 32*1024)
		if err != nil {
			r.t.Fatal(err)
		}
		body = append(body, page.Data...)
		if page.Done {
			return body
		}
		if len(page.Data) == 0 {
			r.t.Fatal("export page made no progress")
		}
		offset += len(page.Data)
	}
	r.t.Fatal("export exceeded its bound")
	return nil
}

func TestAccountExportIsBoundedCanonicalAndRechecksEveryRead(t *testing.T) {
	r := newLifecycleRig(t, 1)
	ctx := context.Background()
	r.prove(ClassExportAccount, r.user)
	// A legitimate multi-page account must fit the separate read budget even
	// when the configured sensitive-write budget is one request per window.
	if _, err := r.db.Migration.Exec(ctx, `INSERT INTO entitlement.grant(grant_id,account_id,kind,subject,value,source,source_ref,effective_from,issued_by_actor,created_at,reason)
SELECT md5('export-grant-'||i::text)::uuid,$1,1,repeat('x',128),'{}'::jsonb,5,repeat('r',120)||i::text,$2,'test',$2,'test' FROM generate_series(1,256)i`, r.user, r.now); err != nil {
		t.Fatal(err)
	}
	var exported Lifecycle
	if err := r.tx(func(ctx context.Context, tx pgx.Tx) error {
		var err error
		exported, err = r.s.PrepareExport(ctx, tx, r.caller, platform.NewID(), r.now)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	r.s.policy.StepUpPerAccount.Limit = 1
	first := r.readExport(exported.ID)
	if len(first) <= 32*1024 || !json.Valid(first) {
		t.Fatal("bounded account export did not produce its complete JSON")
	}
	for _, secret := range []string{r.issued.Handle, r.issued.CSRF, base64.RawURLEncoding.EncodeToString(r.key.ID), "public_key", "code_hash", "webauthn_user_handle"} {
		if bytes.Contains(first, []byte(secret)) {
			t.Fatal("account export contains excluded authentication material")
		}
	}
	handle, ok := session.ParseHandle(r.issued.Handle)
	if !ok {
		t.Fatal("browser handle")
	}
	if _, live, err := session.Renew(ctx, r.db.Runtime, r.s.policy, handle, r.now.Add(time.Minute)); err != nil || !live {
		t.Fatal("renew", err)
	}
	second := r.readExport(exported.ID)
	if !bytes.Equal(first, second) {
		t.Fatal("renewal changed the stable snapshot")
	}
	name := "Changed"
	if err := r.tx(func(ctx context.Context, tx pgx.Tx) error {
		_, err := r.s.UpdateProfile(ctx, tx, r.caller, ProfileChange{DisplayName: &name}, nil)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := r.s.ReadExport(ctx, r.caller, exported.ID, 0, MaxExportPageBytes); refusalOf(err) == nil || refusalOf(err).Reason != "snapshot_changed" {
		t.Fatal("changed snapshot was substituted", err)
	}
	if got := r.db.Count(`SELECT state FROM identity.lifecycle_operation WHERE operation_id=$1`, exported.ID); got != int(LifecycleRevoked) {
		t.Fatal("stale receipt was not retained revoked", got)
	}
	r.s.policy.StepUpPerAccount.Limit = 10
	r.prove(ClassExportAccount, r.user)
	if err := r.tx(func(ctx context.Context, tx pgx.Tx) error {
		var err error
		exported, err = r.s.PrepareExport(ctx, tx, r.caller, platform.NewID(), r.now)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	r.now = r.now.Add(exportTTL + time.Second)
	if _, err := r.s.ReadExport(ctx, r.caller, exported.ID, 0, MaxExportPageBytes); refusalOf(err) == nil || refusalOf(err).Code != "expired" {
		t.Fatal("export expiry", err)
	}
	if got := r.db.Count(`SELECT state FROM identity.lifecycle_operation WHERE operation_id=$1`, exported.ID); got != int(LifecycleExpired) {
		t.Fatal("expiry was rolled back", got)
	}
}

func TestRecoveryUsesRealBoundProofRevokesAuthorityAndReplaysItsReceipt(t *testing.T) {
	r := newLifecycleRig(t, 1)
	ctx := context.Background()
	old := r.caller
	oldCookie := r.issued.Handle
	known, err := r.s.BeginRecovery(ctx, r.request(), RecoveryBegin{Email: "owner@example.test", Claim: r.claim(), HasClaim: true, Browser: true})
	if err != nil {
		t.Fatal(err)
	}
	unknown, err := r.s.BeginRecovery(ctx, r.request(), RecoveryBegin{Email: "missing@example.test", Claim: r.claim(), HasClaim: true, Browser: true})
	if err != nil {
		t.Fatal(err)
	}
	if known.Method != unknown.Method || known.Purpose != unknown.Purpose || len(known.Options.UserHandle) != len(unknown.Options.UserHandle) || bytes.Equal(known.Options.UserHandle, r.key.UserHandle) {
		t.Fatal("recovery begin disclosed stable account identity")
	}
	messages := r.mail.Messages()
	if len(messages) != 1 {
		t.Fatal("recovery transport", len(messages))
	}
	code := regexp.MustCompile(`[BCDFGHJKLMNPQRSTVWXZ]{4}-[BCDFGHJKLMNPQRSTVWXZ]{4}`).FindString(messages[0].Text)
	if code == "" {
		t.Fatal("missing captured recovery code")
	}
	creation, replacement := r.auth.Create(known.Challenge, known.Options.UserHandle)
	input := RecoveryComplete{FlowID: known.FlowID, EmailCode: code, Creation: creation, Browser: true, CommandID: platform.NewID()}
	result, err := r.s.CompleteRecovery(ctx, r.request(), input)
	if err != nil || result.State != LifecycleCompleted {
		t.Fatal("recovery", err)
	}
	replay, err := r.s.CompleteRecovery(ctx, r.request(), input)
	if err != nil || replay.ID != result.ID || replay.Revision != result.Revision {
		t.Fatal("recovery receipt replay", err)
	}
	changed := input
	changed.Creation.CredentialID = append([]byte(nil), input.Creation.CredentialID...)
	changed.Creation.CredentialID[0] ^= 1
	if _, err = r.s.CompleteRecovery(ctx, r.request(), changed); refusalOf(err) == nil || refusalOf(err).Code != "command_id_reused" {
		t.Fatal("changed recovery command was not refused", err)
	}
	verifier := session.NewVerifier(r.db.Runtime, r.s.rp.Origin(), func() time.Time { return r.now })
	if resolved, err := verifier.ResolveSession(ctx, oldCookie); err != nil || resolved != nil {
		t.Fatal("old browser authority survived", err)
	}
	if err = r.tx(func(ctx context.Context, tx pgx.Tx) error { return RecheckCaller(ctx, tx, old, r.now) }); refusalOf(err) == nil || refusalOf(err).Code != "credential_revoked" {
		t.Fatal("stale ingress caller survived", err)
	}
	r.key = replacement
	r.signIn()
	if r.caller.RecoveryGeneration != 1 || r.caller.AuthEpoch != 1 {
		t.Fatal("new session did not use current security generations")
	}
	if _, err = r.s.GetLifecycle(ctx, r.caller, result.ID); err != nil {
		t.Fatal("fresh authenticated reconcile", err)
	}
	if r.db.Count(`SELECT count(*) FROM identity.auth_identity WHERE user_id=$1 AND provider_id='email' AND revoked_at IS NULL`, r.user) != 1 {
		t.Fatal("verified recovery channel was lost")
	}
	input.CommandID = platform.NewID()
	if _, err = r.s.CompleteRecovery(ctx, r.request(), input); refusalOf(err) == nil || refusalOf(err).Code != "code_reused" {
		t.Fatal("recovery proof reused under another command", err)
	}
}

func TestRecoveryOutageDoesNotEnumerateOrCreateAnAlternativeProof(t *testing.T) {
	r := newLifecycleRig(t, 1)
	ctx := context.Background()
	r.mail.SetFailing(true)
	known, err := r.s.BeginRecovery(ctx, r.request(), RecoveryBegin{Email: "owner@example.test", Claim: r.claim(), HasClaim: true, Browser: true})
	if err != nil {
		t.Fatal("known address outage leaked", err)
	}
	unknown, err := r.s.BeginRecovery(ctx, r.request(), RecoveryBegin{Email: "missing@example.test", Claim: r.claim(), HasClaim: true, Browser: true})
	if err != nil {
		t.Fatal("unknown address outage", err)
	}
	if known.Purpose != unknown.Purpose || known.Method != unknown.Method || !known.ExpiresAt.Equal(unknown.ExpiresAt) || len(r.mail.Messages()) != 0 {
		t.Fatal("recipient outage changed public acceptance")
	}
	if got := r.db.Count(`SELECT delivery_state FROM identity.auth_flow WHERE flow_id=$1`, known.FlowID); got != 3 {
		t.Fatal("failed delivery was recorded as success", got)
	}
	creation, _ := r.auth.Create(known.Challenge, known.Options.UserHandle)
	if _, err = r.s.CompleteRecovery(ctx, r.request(), RecoveryComplete{FlowID: known.FlowID, EmailCode: "invalid", Creation: creation, Browser: true, CommandID: platform.NewID()}); refusalOf(err) == nil || refusalOf(err).Code != "unauthenticated" {
		t.Fatal("outage acquired an alternate proof path", err)
	}
	if r.db.Count(`SELECT auth_epoch FROM identity.account_security_state WHERE user_id=$1`, r.user) != 0 {
		t.Fatal("failed recovery changed account authority")
	}
	r.s.mailer = mail.Disabled{}
	for _, email := range []string{"owner@example.test", "missing@example.test"} {
		if _, err = r.s.BeginRecovery(ctx, r.request(), RecoveryBegin{Email: email, Claim: r.claim(), HasClaim: true, Browser: true}); refusalOf(err) == nil || refusalOf(err).Key() != "RESOURCE/overloaded" {
			t.Fatal("sender disablement was not uniform", err)
		}
	}
}

func TestRecoveryRechecksTheChannelAfterWaitingForCredentialRemoval(t *testing.T) {
	r := newLifecycleRig(t, 1)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	var emailID platform.ID
	if err := r.db.Migration.QueryRow(ctx, `SELECT auth_identity_id FROM identity.auth_identity WHERE user_id=$1 AND provider_id='email' AND revoked_at IS NULL`, r.user).Scan(&emailID); err != nil {
		t.Fatal(err)
	}
	r.prove(ClassRemoveCredential, emailID)
	tx, err := r.db.Migration.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(context.Background())
	if _, err = tx.Exec(ctx, `SELECT 1 FROM identity.user WHERE user_id=$1 FOR UPDATE`, r.user); err != nil {
		t.Fatal(err)
	}
	type begun struct {
		challenge Challenge
		err       error
	}
	done := make(chan begun, 1)
	go func() {
		challenge, err := r.s.BeginRecovery(ctx, r.request(), RecoveryBegin{Email: "owner@example.test", Claim: r.claim(), HasClaim: true, Browser: true})
		done <- begun{challenge, err}
	}()
	waited := false
	for deadline := time.Now().Add(8 * time.Second); !waited && time.Now().Before(deadline); time.Sleep(20 * time.Millisecond) {
		select {
		case result := <-done:
			t.Fatalf("recovery did not wait for the account mutation: %v", result.err)
		default:
		}
		var waiting int
		if err = tx.QueryRow(ctx, `SELECT count(*) FROM pg_locks l WHERE NOT l.granted AND pg_backend_pid()=ANY(pg_blocking_pids(l.pid))`).Scan(&waiting); err != nil {
			t.Fatal(err)
		}
		waited = waiting > 0
	}
	if !waited {
		t.Fatal("recovery never reached its account lock")
	}
	if err = ConsumeEvidence(ctx, tx, r.caller, ClassRemoveCredential, emailID, r.now); err != nil {
		t.Fatal(err)
	}
	if _, err = r.s.RemoveCredential(ctx, tx, r.caller, emailID, Cancellations{}, r.now); err != nil {
		t.Fatal(err)
	}
	if err = tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	select {
	case result := <-done:
		if result.err != nil {
			t.Fatal("channel removal changed non-enumerating acceptance", result.err)
		}
		if len(r.mail.Messages()) != 0 {
			t.Fatal("recovery delivered an authority proof to the revoked channel")
		}
		if got := r.db.Count(`SELECT count(*) FROM identity.auth_flow WHERE flow_id=$1 AND user_id IS NULL AND lifecycle_operation_id IS NULL`, result.challenge.FlowID); got != 1 {
			t.Fatal("revoked channel inherited the new account generation", got)
		}
		if got := r.db.Count(`SELECT count(*) FROM identity.lifecycle_operation WHERE operation_id=$1`, result.challenge.FlowID); got != 0 {
			t.Fatal("revoked channel acquired a recovery operation", got)
		}
	case <-ctx.Done():
		t.Fatal("recovery did not settle", ctx.Err())
	}
}

func TestOwnerDeletionCleanupIsRealAndProviderUncertaintyStaysPending(t *testing.T) {
	for _, providerPending := range []bool{false, true} {
		name := "self_hosted"
		if providerPending {
			name = "provider_pending"
		}
		t.Run(name, func(t *testing.T) {
			r := newLifecycleRig(t, 1)
			ctx := context.Background()
			kind := int16(2)
			var subscription *string
			if providerPending {
				kind = 1
				ref := "unreconciled-provider"
				subscription = &ref
			}
			if _, err := r.db.Migration.Exec(ctx, `INSERT INTO entitlement.service_term(term_id,account_id,kind,subscription_ref,period_ref,starts_at,ends_at,authorized_at,created_at)
VALUES($1,$2,$3,$4,'historical-term',$5,$6,$5,$5)`, platform.NewID(), r.user, kind, subscription, r.now, r.now.Add(time.Hour)); err != nil {
				t.Fatal(err)
			}
			// A real retained enrollment carries both the account's chosen name
			// and the node's independently reported personal hostname.
			key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
			if err != nil {
				t.Fatal(err)
			}
			publicKey, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
			if err != nil {
				t.Fatal(err)
			}
			enrollmentID := platform.NewID()
			if err = r.tx(func(ctx context.Context, tx pgx.Tx) error {
				deviceID, installationID, err := device.CreateNode(ctx, tx, device.Node{UserID: r.user, Name: "Private node label", Platform: device.PlatformLinux, PlatformText: "linux", AppVersion: "1.0.0", PublicKey: publicKey}, r.now)
				if err != nil {
					return err
				}
				_, err = tx.Exec(ctx, `INSERT INTO fleet.node(enrollment_id,node_id,user_id,device_id,installation_id,display_name,reported_name,named_by_account,os,arch,version,enrolled_at,last_seen_at,rev)
VALUES($1,$2,$3,$4,$5,'Private account label','Private host name',true,2,1,'1.0.0',$6,$6,1)`, enrollmentID, platform.NewID(), r.user, deviceID, installationID, r.now)
				return err
			}); err != nil {
				t.Fatal(err)
			}
			var plan Lifecycle
			if err := r.tx(func(ctx context.Context, tx pgx.Tx) error {
				var err error
				plan, err = r.s.PrepareDeletion(ctx, tx, r.caller, platform.NewID(), r.now)
				return err
			}); err != nil {
				t.Fatal(err)
			}
			r.prove(ClassConfirmDeletion, plan.ID)
			if err := r.tx(func(ctx context.Context, tx pgx.Tx) error {
				_, err := r.s.ConfirmDeletion(ctx, tx, r.caller, plan.ID, plan.PlanRevision, platform.NewID(), r.now)
				return err
			}); err != nil {
				t.Fatal(err)
			}
			if err := r.tx(func(ctx context.Context, tx pgx.Tx) error {
				_, err := tx.Exec(ctx, `SELECT identity.finish_account_deletion($1,$2)`, plan.ID, r.now)
				return err
			}); err == nil {
				t.Fatal("runtime acquired owner cleanup authority")
			}
			var completed bool
			if err := r.db.Migration.QueryRow(ctx, `SELECT identity.finish_account_deletion($1,$2)`, plan.ID, r.now).Scan(&completed); err != nil {
				t.Fatal(err)
			}
			if completed == providerPending {
				t.Fatal("cleanup invented or withheld an actual outcome", completed)
			}
			if got := r.db.Count(`SELECT count(*) FROM entitlement.service_term WHERE account_id=$1`, r.user); got != 1 {
				t.Fatal("financial evidence removed", got)
			}
			if providerPending {
				if got := r.db.Count(`SELECT state FROM identity.user WHERE user_id=$1`, r.user); got != 4 {
					t.Fatal("provider uncertainty finalized", got)
				}
				if got := r.db.Count(`SELECT blocked_reason FROM identity.lifecycle_operation WHERE operation_id=$1`, plan.ID); got != 1 {
					t.Fatal("provider blocker not retained", got)
				}
				if got := r.db.Count(`SELECT count(*) FROM identity.auth_identity WHERE user_id=$1`, r.user); got == 0 {
					t.Fatal("pending cleanup erased credentials before cancellation window")
				}
				if got := r.db.Count(`SELECT count(*) FROM fleet.node WHERE enrollment_id=$1 AND reported_name='Private host name' AND named_by_account`, enrollmentID); got != 1 {
					t.Fatal("pending provider cleanup erased the retained node fact", got)
				}
			} else {
				if got := r.db.Count(`SELECT state FROM identity.user WHERE user_id=$1`, r.user); got != 5 {
					t.Fatal("self-hosted cleanup did not finish", got)
				}
				if got := r.db.Count(`SELECT count(*) FROM identity.auth_identity WHERE user_id=$1`, r.user); got != 0 {
					t.Fatal("deleted account retained credentials", got)
				}
				if got := r.db.Count(`SELECT count(*) FROM identity.auth_flow WHERE user_id=$1`, r.user); got != 0 {
					t.Fatal("deleted account retained proof data", got)
				}
				if got := r.db.Count(`SELECT count(*) FROM device.device WHERE user_id=$1 AND display_name <> 'Deleted device'`, r.user); got != 0 {
					t.Fatal("personal device labels retained", got)
				}
				if got := r.db.Count(`SELECT count(*) FROM fleet.node WHERE enrollment_id=$1 AND display_name='Deleted node' AND reported_name IS NULL AND NOT named_by_account AND revoked_at IS NOT NULL`, enrollmentID); got != 1 {
					t.Fatal("retained node tombstone kept a personal name", got)
				}
				if err := r.db.Migration.QueryRow(ctx, `SELECT identity.finish_account_deletion($1,$2)`, plan.ID, r.now).Scan(&completed); err != nil || !completed {
					t.Fatal("cleanup replay", err)
				}
			}
		})
	}
}

func TestDeletionRevokesCallerRequiresNewAuthenticationAndPreservesRestrictionOnCancel(t *testing.T) {
	r := newLifecycleRig(t, 2)
	ctx := context.Background()
	oldCookie := r.issued.Handle
	var plan Lifecycle
	if err := r.tx(func(ctx context.Context, tx pgx.Tx) error {
		var err error
		plan, err = r.s.PrepareDeletion(ctx, tx, r.caller, platform.NewID(), r.now)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	r.prove(ClassConfirmDeletion, plan.ID)
	commandID := platform.NewID()
	request, _ := json.Marshal(struct {
		ID  platform.ID
		Rev int64
	}{plan.ID, plan.PlanRevision})
	command := platform.Command{Principal: Actor(r.user), CommandID: commandID, Operation: ClassConfirmDeletion, Request: request}
	runs := 0
	run := func(ctx context.Context, tx pgx.Tx) ([]byte, error) {
		runs++
		result, err := r.s.ConfirmDeletion(ctx, tx, r.caller, plan.ID, plan.PlanRevision, commandID, r.now)
		if err != nil {
			return nil, err
		}
		return json.Marshal(result)
	}
	first, err := platform.Execute(ctx, r.db.Runtime, command, store.TxOptions{}, run)
	if err != nil || !first.Succeeded {
		t.Fatal("confirm deletion", err)
	}
	second, err := platform.Execute(ctx, r.db.Runtime, command, store.TxOptions{}, run)
	if err != nil || !bytes.Equal(first.Result, second.Result) || runs != 1 {
		t.Fatal("duplicate confirmation executed again", err, runs)
	}
	verifier := session.NewVerifier(r.db.Runtime, r.s.rp.Origin(), func() time.Time { return r.now })
	if resolved, err := verifier.ResolveSession(ctx, oldCookie); err != nil || resolved != nil {
		t.Fatal("confirm did not revoke the caller", err)
	}
	r.signIn()
	current, err := r.s.GetDeletion(ctx, r.caller)
	if err != nil || current == nil || current.ID != plan.ID || current.State != LifecycleProcessing {
		t.Fatal("new authentication could not reconcile deletion", err)
	}
	class := ClassExportAccount
	method := int32(MethodValuePasskey)
	hash := TargetHash(class, r.user, r.user)
	if _, err = r.s.BeginStepUp(ctx, r.caller, StepUpBegin{Class: &class, Method: &method, TargetHash: &hash}); refusalOf(err) == nil {
		t.Fatal("pending deletion admitted general sensitive authority")
	}
	r.prove(ClassCancelDeletion, plan.ID)
	if err = r.tx(func(ctx context.Context, tx pgx.Tx) error {
		_, err := r.s.CancelDeletion(ctx, tx, r.caller, plan.ID, platform.NewID(), r.now)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	if got := r.db.Count(`SELECT state FROM identity.user WHERE user_id=$1`, r.user); got != 2 {
		t.Fatal("cancel escalated a restricted account", got)
	}
}
