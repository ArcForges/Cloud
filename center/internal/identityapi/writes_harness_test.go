// SPDX-License-Identifier: AGPL-3.0-only

package identityapi_test

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	foundationv1 "github.com/ArcForges/Contracts/go/arcforges/foundation/v1"
	publicapiv1 "github.com/ArcForges/Contracts/go/arcforges/publicapi/v1"
	"github.com/ArcForges/Contracts/go/arcforges/publicapi/v1/publicapiv1connect"
	"github.com/jackc/pgx/v5"
	"google.golang.org/protobuf/proto"

	"github.com/ArcForges/Cloud/center/internal/config"
	"github.com/ArcForges/Cloud/center/internal/device"
	"github.com/ArcForges/Cloud/center/internal/identity"
	"github.com/ArcForges/Cloud/center/internal/platform"
	"github.com/ArcForges/Cloud/center/internal/session"
)

// The paths of A1b's methods.
const (
	beginStepUpPath      = publicapiv1connect.IdentityServiceBeginStepUpProcedure
	completeStepUpPath   = publicapiv1connect.IdentityServiceCompleteStepUpProcedure
	updateProfilePath    = publicapiv1connect.IdentityServiceUpdateProfileProcedure
	beginRegisterPath    = publicapiv1connect.IdentityServiceBeginPasskeyRegistrationProcedure
	completeRegisterPath = publicapiv1connect.IdentityServiceCompletePasskeyRegistrationProcedure
	renameCredentialPath = publicapiv1connect.IdentityServiceRenameAuthIdentityProcedure
	removeCredentialPath = publicapiv1connect.IdentityServiceRemoveAuthIdentityProcedure
	revokeSessionPath    = publicapiv1connect.IdentityServiceRevokeSessionProcedure
	revokeAllPath        = publicapiv1connect.IdentityServiceRevokeAllSessionsProcedure
	renameDevicePath     = publicapiv1connect.DeviceServiceRenameProcedure
	revokeDevicePath     = publicapiv1connect.DeviceServiceRevokeProcedure
)

// writePolicy lifts the account buckets a test that steps up many times would otherwise reach.
const writePolicy = `{"stepUpPerAccountLimit": 1000, "signInFailuresAccountLimit": 1000, "signInPerPrefixLimit": 1000}`

// command is a RequestMeta with a fresh command ID.
func command() *foundationv1.RequestMeta {
	value := platform.NewID()
	return &foundationv1.RequestMeta{CommandId: &foundationv1.Id{Value: value[:]}}
}

func bearer(token string) caller { return caller{bearer: token} }

// deviceOf is the device a session is bound to.
func (h *harness) deviceOf(sessionID platform.ID) platform.ID {
	h.t.Helper()
	var deviceID platform.ID
	if err := h.migration.QueryRow(context.Background(), "SELECT device_id FROM identity.session WHERE session_id = $1", sessionID).Scan(&deviceID); err != nil {
		h.t.Fatal(err)
	}
	return deviceID
}

// sessionIDOf is the session of a native sign-in.
func sessionIDOf(native *publicapiv1.NativeSession) platform.ID {
	var sessionID platform.ID
	copy(sessionID[:], native.GetSessionId().GetValue())
	return sessionID
}

// beginStepUp begins a passkey step-up of the caller's session for a class and target.
func (h *harness) beginStepUp(who account, from caller, class string, target platform.ID) *publicapiv1.IdentityServiceBeginStepUpResponse {
	h.t.Helper()
	return rpc(h, beginStepUpPath, &publicapiv1.IdentityServiceBeginStepUpRequest{Meta: meta(), OperationClass: proto.String(class),
		Method: publicapiv1.AuthMethod_AUTH_METHOD_PASSKEY.Enum(), TargetHash: proto.String(identity.TargetHash(class, who.id, target))}, from,
		&publicapiv1.IdentityServiceBeginStepUpResponse{})
}

// completeStepUp proves a step-up challenge with a passkey assertion of the account.
func (h *harness) completeStepUp(who account, from caller, challenge *publicapiv1.AuthChallenge) *publicapiv1.IdentityServiceCompleteStepUpResponse {
	h.t.Helper()
	return rpc(h, completeStepUpPath, &publicapiv1.IdentityServiceCompleteStepUpRequest{Meta: meta(), FlowId: challenge.GetFlowId(),
		Proof: &publicapiv1.AuthProof{Proof: &publicapiv1.AuthProof_Passkey{Passkey: assertionOf(who.authenticator.Assert(who.key, challenge.GetChallenge()))}}},
		from, &publicapiv1.IdentityServiceCompleteStepUpResponse{})
}

// stepUp proves a passkey step-up of the caller's session for a class and target; it fails the test unless the step-up proves.
func (h *harness) stepUp(who account, from caller, class string, target platform.ID) *publicapiv1.StepUpEvidence {
	h.t.Helper()
	begun := h.beginStepUp(who, from, class, target)
	if begun.GetError() != nil {
		h.t.Fatalf("begin a step-up of %s: %s", class, failure(begun.GetError()))
	}
	completed := h.completeStepUp(who, from, begun.GetValue().GetChallenge())
	if completed.GetError() != nil {
		h.t.Fatalf("complete a step-up of %s: %s", class, failure(completed.GetError()))
	}
	return completed.GetValue().GetEvidence()
}

// revokeSession revokes a session of the caller's account under a command.
func (h *harness) revokeSession(from caller, meta *foundationv1.RequestMeta, sessionID platform.ID) *publicapiv1.IdentityServiceRevokeSessionResponse {
	h.t.Helper()
	return rpc(h, revokeSessionPath, &publicapiv1.IdentityServiceRevokeSessionRequest{Meta: meta, SessionId: &foundationv1.Id{Value: sessionID[:]}}, from,
		&publicapiv1.IdentityServiceRevokeSessionResponse{})
}

// stepUpByEmail proves an e-mail step-up of the caller's session for a class and target with the code the Fake delivered.
func (h *harness) stepUpByEmail(who account, from caller, class string, target platform.ID) {
	h.t.Helper()
	begun := rpc(h, beginStepUpPath, &publicapiv1.IdentityServiceBeginStepUpRequest{Meta: meta(), OperationClass: proto.String(class),
		Method: publicapiv1.AuthMethod_AUTH_METHOD_EMAIL.Enum(), TargetHash: proto.String(identity.TargetHash(class, who.id, target))}, from,
		&publicapiv1.IdentityServiceBeginStepUpResponse{})
	if begun.GetError() != nil {
		h.t.Fatalf("begin an e-mail step-up of %s: %s", class, failure(begun.GetError()))
	}
	completed := rpc(h, completeStepUpPath, &publicapiv1.IdentityServiceCompleteStepUpRequest{Meta: meta(), FlowId: begun.GetValue().GetChallenge().GetFlowId(),
		Proof: &publicapiv1.AuthProof{Proof: &publicapiv1.AuthProof_EmailCode{EmailCode: h.lastCode(who.email)}}}, from,
		&publicapiv1.IdentityServiceCompleteStepUpResponse{})
	if completed.GetError() != nil {
		h.t.Fatalf("complete an e-mail step-up of %s: %s", class, failure(completed.GetError()))
	}
}

// receipts is the number of command receipts.
func (h *harness) receipts() int { return h.count("SELECT count(*) FROM platform.command_receipt") }

// refusalsKept is the number of command receipts that keep a refusal with the code (only a refused command sets error_code).
func (h *harness) refusalsKept(code string) int {
	return h.count("SELECT count(*) FROM platform.command_receipt WHERE error_code = $1", code)
}

// live reports whether a session is live (not revoked).
func (h *harness) live(sessionID platform.ID) bool {
	return h.count("SELECT count(*) FROM identity.session WHERE session_id = $1 AND revoked_at IS NULL", sessionID) == 1
}

// credentialIDs are an account's live credentials in creation order (the passkey first for a seeded account).
func (h *harness) credentialIDs(userID platform.ID) []platform.ID {
	h.t.Helper()
	rows, err := h.migration.Query(context.Background(),
		"SELECT auth_identity_id FROM identity.auth_identity WHERE user_id = $1 AND revoked_at IS NULL ORDER BY created_at, method", userID)
	if err != nil {
		h.t.Fatal(err)
	}
	defer rows.Close()
	var ids []platform.ID
	for rows.Next() {
		var value platform.ID
		if err = rows.Scan(&value); err != nil {
			h.t.Fatal(err)
		}
		ids = append(ids, value)
	}
	if err = rows.Err(); err != nil {
		h.t.Fatal(err)
	}
	return ids
}

// issueOn issues a native session of a scope on an existing device of the account, on the device's installation of the scope's
// product (created when the device has none: a device holds one installation per product).
func (h *harness) issueOn(userID, deviceID platform.ID, scope session.Scope) issued {
	h.t.Helper()
	ctx := context.Background()
	tx, err := h.migration.Begin(ctx)
	if err != nil {
		h.t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	now := h.clock.Now()
	grant := session.Grant{UserID: userID, Scope: scope, Purpose: session.PurposeAuthenticate, AuthMethod: 1, AuthenticatedAt: now, DeviceID: deviceID,
		InstallationID: platform.NewID(), Product: device.ProductMobile}
	platformText := "android-15"
	if scope == session.ScopeNode {
		grant.Product, platformText = device.ProductNode, "linux-x64"
	}
	err = tx.QueryRow(ctx, "SELECT installation_id FROM device.installation WHERE device_id = $1 AND product_id = $2", deviceID, grant.Product).
		Scan(&grant.InstallationID)
	if errors.Is(err, pgx.ErrNoRows) {
		_, err = tx.Exec(ctx, `INSERT INTO device.installation (installation_id, device_id, user_id, product_id, app_version, platform, installed_at, last_active_at, rev)
VALUES ($1, $2, $3, $4, '1.0.0', $5, $6, $6, 1)`, grant.InstallationID, deviceID, userID, grant.Product, platformText, now)
	}
	if err != nil {
		h.t.Fatal(err)
	}
	native, err := session.IssueNative(ctx, tx, config.DefaultIdentityPolicy(), grant, now)
	if err != nil {
		h.t.Fatal(err)
	}
	if err = tx.Commit(ctx); err != nil {
		h.t.Fatal(err)
	}
	h.remember(native.AccessToken, native.RefreshToken)
	return issued{access: native.AccessToken, refresh: native.RefreshToken, installation: grant.InstallationID, sessionID: native.SessionID}
}

// refreshOf refreshes an issued native session and returns the reply's refusal, if any.
func (h *harness) refreshOf(credential issued) *foundationv1.ArcError {
	h.t.Helper()
	response := rpc(h, refreshPath, &publicapiv1.IdentityServiceRefreshSessionRequest{Meta: meta(), RefreshToken: proto.String(credential.refresh),
		InstallationId: &foundationv1.Id{Value: credential.installation[:]}}, caller{}, &publicapiv1.IdentityServiceRefreshSessionResponse{})
	if value := response.GetValue().GetSession(); value != nil {
		h.remember(value.GetAccessToken(), value.GetRefreshToken())
	}
	return response.GetError()
}

// idFrom is the platform ID of a contract ID.
func idFrom(value *foundationv1.Id) platform.ID {
	var result platform.ID
	copy(result[:], value.GetValue())
	return result
}

// idOf is an ID as the contract carries it.
func idOf(value platform.ID) *foundationv1.Id { return &foundationv1.Id{Value: value[:]} }

// resourceOf is the state.resource of a refusal as kind and ID.
func resourceOf(value *foundationv1.ArcError) (string, []byte) {
	resource := value.GetDetails().GetState().GetResource()
	return resource.GetKind(), resource.GetId().GetValue()
}

// participant stands in for the device revocation's cascade participants (DC-06: AF-CTR-07's agent grants and AF-CLD-06's push
// registrations): it records each device it was asked to revoke and the transaction it ran in.
type participant struct {
	mu      sync.Mutex
	devices []platform.ID
	fail    bool
}

func (p *participant) Name() string { return "test" }

func (p *participant) RevokeDevice(ctx context.Context, tx pgx.Tx, _, deviceID platform.ID, _ time.Time) (int64, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	// The participant runs in the revocation's transaction: it sees the device revoked already.
	var revoked bool
	if err := tx.QueryRow(ctx, "SELECT revoked_at IS NOT NULL FROM device.device WHERE device_id = $1", deviceID).Scan(&revoked); err != nil {
		return 0, err
	}
	if !revoked || p.fail {
		return 0, errParticipant
	}
	p.devices = append(p.devices, deviceID)
	return 1, nil
}

// failing makes the participant fail (or succeed again).
func (p *participant) failing(value bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.fail = value
}

func (p *participant) called() []platform.ID {
	p.mu.Lock()
	defer p.mu.Unlock()
	return append([]platform.ID(nil), p.devices...)
}

type participantError struct{}

func (participantError) Error() string { return "the test participant failed" }

var errParticipant = participantError{}

// expect fails the test unless a reply's error is the named refusal ("" for success).
func expect(t *testing.T, what string, value *foundationv1.ArcError, want string) {
	t.Helper()
	if failure(value) != want {
		t.Fatalf("%s: %q, want %q (%v)", what, failure(value), want, value)
	}
}

// hold is a migration-role transaction that holds row locks until it ends, so a test can park a call at a chosen statement.
type hold struct {
	h  *harness
	tx pgx.Tx
}

// holding begins a hold with one locking statement; the hold ends with release or with the test.
func (h *harness) holding(statement string, arguments ...any) *hold {
	h.t.Helper()
	ctx := context.Background()
	tx, err := h.migration.Begin(ctx)
	if err != nil {
		h.t.Fatal(err)
	}
	h.t.Cleanup(func() { _ = tx.Rollback(context.Background()) })
	if _, err = tx.Exec(ctx, statement, arguments...); err != nil {
		h.t.Fatal(err)
	}
	return &hold{h: h, tx: tx}
}

// waitFor waits until at least count backends wait on the hold, directly or behind another waiting backend, at most 10 s; it
// reports whether they did.
func (l *hold) waitFor(count int) bool {
	l.h.t.Helper()
	for deadline := time.Now().Add(10 * time.Second); time.Now().Before(deadline); time.Sleep(20 * time.Millisecond) {
		var waiting int
		if err := l.tx.QueryRow(context.Background(), `WITH RECURSIVE blocked(pid) AS (
    SELECT l.pid FROM pg_locks l WHERE NOT l.granted AND pg_backend_pid() = ANY(pg_blocking_pids(l.pid))
    UNION SELECT l.pid FROM pg_locks l JOIN blocked b ON b.pid = ANY(pg_blocking_pids(l.pid)) WHERE NOT l.granted)
SELECT count(DISTINCT pid) FROM blocked`).Scan(&waiting); err != nil {
			l.h.t.Fatal(err)
		}
		if waiting >= count {
			return true
		}
	}
	return false
}

// release ends the hold: commit keeps what its statements changed, otherwise they are rolled back.
func (l *hold) release(commit bool) {
	l.h.t.Helper()
	var err error
	if commit {
		err = l.tx.Commit(context.Background())
	} else {
		err = l.tx.Rollback(context.Background())
	}
	if err != nil {
		l.h.t.Fatal(err)
	}
}
