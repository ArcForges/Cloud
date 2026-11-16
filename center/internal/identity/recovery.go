// SPDX-License-Identifier: AGPL-3.0-only

package identity

import (
	"context"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/ArcForges/Cloud/center/internal/arc"
	"github.com/ArcForges/Cloud/center/internal/device"
	"github.com/ArcForges/Cloud/center/internal/identity/passkey"
	"github.com/ArcForges/Cloud/center/internal/mail"
	"github.com/ArcForges/Cloud/center/internal/platform"
	"github.com/ArcForges/Cloud/center/internal/ratelimit"
	"github.com/ArcForges/Cloud/center/internal/session"
	"github.com/ArcForges/Cloud/center/internal/store"
)

type RecoveryBegin struct {
	Email             string
	Claim             device.Claim
	HasClaim, Browser bool
}

type RecoveryComplete struct {
	FlowID    platform.ID
	EmailCode string
	Creation  passkey.Creation
	Browser   bool
	CommandID platform.ID
}

// BeginRecovery always returns the same accepted ceremony for a syntactically
// valid address, whether an eligible verified recovery channel exists or not.
// Sender-wide disablement is uniform. Recipient-specific failures happen after
// acceptance and are retained as pending/failed delivery, never as proof sent.
func (s *Service) BeginRecovery(ctx context.Context, request Request, in RecoveryBegin) (Challenge, error) {
	if !s.mailer.Enabled() {
		return Challenge{}, arc.Unavailable()
	}
	normalized, ok := NormalizeEmail(in.Email)
	if !ok {
		return Challenge{}, arc.InvalidArgument("email", "pattern")
	}
	refusal := device.ValidateNativeClaim(in.Claim, in.HasClaim)
	if in.Browser {
		refusal = device.ValidateBrowserClaim(in.Claim, in.HasClaim)
	}
	if refusal != nil {
		return Challenge{}, refusal
	}
	if err := s.take(ctx, request, s.bucket(ratelimit.EmailPrefix, ratelimit.Prefix(request.ClientIP)), Anonymous); err != nil {
		return Challenge{}, err
	}
	if err := s.take(ctx, request, s.bucket(ratelimit.EmailAddress, normalized), Anonymous); err != nil {
		return Challenge{}, err
	}
	if s.policy.AnonymousFlows.Limit > 0 {
		if err := s.take(ctx, request, s.bucket(ratelimit.AnonymousFlows, "all"), Anonymous); err != nil {
			return Challenge{}, err
		}
	}
	code, salt := NewCode(), randomBytes(16)
	codeHash, err := s.codeHash(ctx, code, salt)
	if err != nil {
		return Challenge{}, err
	}
	now := s.now()
	zero := int64(0)
	row := flow{ID: platform.NewID(), Channel: ChannelNative, Kind: FlowRecovery, Purpose: PurposeRecover, Claim: &in.Claim,
		Challenge: randomBytes(passkey.ChallengeBytes), UserHandle: randomBytes(32), EmailHash: EmailHash(normalized), CodeHash: codeHash, CodeSalt: salt,
		Sends: 1, MaxAttempts: int16(s.policy.EmailCodeAttempts), CreatedAt: now, ExpiresAt: now.Add(min(s.policy.EmailCodeLifetime, s.policy.PasskeyFlowLifetime)),
		AccountAuthEpoch: &zero, AccountRecoveryGeneration: &zero}
	if in.Browser {
		origin := s.rp.Origin()
		row.Channel = ChannelBrowser
		row.Origin = &origin
	}
	eligible := false
	err = s.db.InTx(ctx, "begin account recovery", store.TxOptions{}, func(ctx context.Context, tx pgx.Tx) error {
		eligible = false
		row.UserID = nil
		row.LifecycleOperationID = nil
		var userID platform.ID
		var state int16
		err := tx.QueryRow(ctx, `SELECT u.user_id,u.state FROM identity.auth_identity a
JOIN identity.user u ON u.user_id=a.user_id WHERE a.provider_id='email' AND a.subject=$1 AND a.revoked_at IS NULL`, normalized).Scan(&userID, &state)
		if err != nil && !errors.Is(err, pgx.ErrNoRows) {
			return err
		}
		if err == nil && UserState(state).MaySignIn() {
			security, err := session.LockAccountSecurity(ctx, tx, userID)
			if err != nil {
				return err
			}
			if UserState(security.State).MaySignIn() {
				eligible = true
				row.UserID = &userID
				row.AccountAuthEpoch = &security.AuthEpoch
				row.AccountRecoveryGeneration = &security.RecoveryGeneration
				operationID := row.ID
				row.LifecycleOperationID = &operationID
				intent := lifecycleIntent(LifecycleRecovery, userID, operationID)
				if _, err = tx.Exec(ctx, `INSERT INTO identity.lifecycle_operation(operation_id,user_id,kind,state,plan_rev,intent_sha256,auth_epoch,
recovery_generation,created_at,expires_at,rev) VALUES($1,$2,1,1,1,$3,$4,$5,$6,$7,1)`, operationID, userID, intent[:], security.AuthEpoch, security.RecoveryGeneration, now, row.ExpiresAt); err != nil {
					return err
				}
			}
		}
		if err = s.insertFlow(ctx, tx, row); err != nil {
			return err
		}
		_, err = tx.Exec(ctx, `UPDATE identity.auth_flow SET delivery_state=1 WHERE flow_id=$1`, row.ID)
		return err
	})
	if err != nil {
		return Challenge{}, err
	}
	if eligible {
		s.deliverRecovery(ctx, row.ID, mail.Message{To: normalized, Subject: "Your ArcForges recovery code", Text: recoveryText(code, s.policy.EmailCodeLifetime)})
	}
	options := s.rp.CreationOptions(row.UserHandle, nil)
	return Challenge{FlowID: row.ID, Method: MethodValueEmail, Purpose: PurposeRecover, Challenge: row.Challenge, Options: &options, ExpiresAt: row.ExpiresAt, ProviderID: "email"}, nil
}

func recoveryText(code string, lifetime time.Duration) string {
	return "Your ArcForges account recovery code is " + code[:4] + "-" + code[4:] + ".\n\nIt authorizes replacing your sign-in passkeys and revokes all existing sessions and device enrollments. If you did not request recovery, ignore this message.\n"
}

// Delivery failure leaves no success claim and no authority. Requesting another
// bounded recovery ceremony is the retry path; no raw mail/code is persisted.
func (s *Service) deliverRecovery(ctx context.Context, flowID platform.ID, message mail.Message) {
	if !s.deliveries.add() {
		return
	}
	s.background(func() {
		defer s.deliveries.done()
		outcome := "failed"
		defer func() {
			_ = recover()
			s.observeDelivery(outcome, "a recovery code could not be delivered")
			state := int16(3)
			if outcome == "sent" {
				state = 2
			}
			_ = s.db.InTx(context.WithoutCancel(ctx), "record recovery mail outcome", store.TxOptions{Timeout: 5 * time.Second, Auxiliary: true}, func(ctx context.Context, tx pgx.Tx) error {
				_, err := tx.Exec(ctx, `UPDATE identity.auth_flow SET delivery_state=$2 WHERE flow_id=$1 AND consumed_at IS NULL`, flowID, state)
				return err
			})
		}()
		sendContext, cancel := context.WithTimeout(context.WithoutCancel(ctx), deliveryTimeout)
		defer cancel()
		outcome = mail.Outcome(s.mailer.Send(sendContext, message))
	})
}

// CompleteRecovery verifies both the recovery-channel proof and a replacement
// WebAuthn creation bound to that same ceremony. Its actual receipt, epochs,
// credential replacement, revocations, audit and outbox commit atomically.
func (s *Service) CompleteRecovery(ctx context.Context, request Request, in RecoveryComplete) (Lifecycle, error) {
	if in.CommandID == (platform.ID{}) {
		return Lifecycle{}, arc.InvalidArgument("meta.command_id", "required")
	}
	if in.EmailCode == "" || len(in.EmailCode) > 128 {
		return Lifecycle{}, arc.InvalidArgument("proof.email_code", "length")
	}
	if refusal := validCreation("credential_replacement.passkey", in.Creation); refusal != nil {
		return Lifecycle{}, refusal
	}
	requestBytes, err := json.Marshal(in)
	if err != nil {
		return Lifecycle{}, err
	}
	command := platform.Command{Principal: "recovery:" + in.FlowID.String(), CommandID: in.CommandID, Operation: "identity.completeRecovery", Request: requestBytes}
	if outcome, found, err := platform.Lookup(ctx, s.db, command); err != nil {
		if errors.Is(err, platform.ErrCommandIDReused) {
			return Lifecycle{}, arc.CommandIDReused()
		}
		return Lifecycle{}, err
	} else if found {
		var result Lifecycle
		if !outcome.Succeeded {
			return result, arc.InvalidState("account_recovery", "failed")
		}
		err = json.Unmarshal(outcome.Result, &result)
		return result, err
	}
	if !s.mailer.Enabled() {
		return Lifecycle{}, arc.Unavailable()
	}
	if err = s.take(ctx, request, s.bucket(ratelimit.SignInPrefix, ratelimit.Prefix(request.ClientIP)), Anonymous); err != nil {
		return Lifecycle{}, err
	}
	channel := ChannelNative
	if in.Browser {
		channel = ChannelBrowser
	}
	row, err := s.takeAttempt(ctx, in.FlowID, channel, []FlowKind{FlowRecovery}, PurposeRecover)
	if err != nil {
		// A concurrent identical completion may have committed while this
		// attempt waited for the consumed flow. Reconcile its actual receipt.
		if outcome, found, lookupErr := platform.Lookup(ctx, s.db, command); lookupErr == nil && found && outcome.Succeeded {
			var result Lifecycle
			if decodeErr := json.Unmarshal(outcome.Result, &result); decodeErr != nil {
				return result, decodeErr
			}
			return result, nil
		} else if errors.Is(lookupErr, platform.ErrCommandIDReused) {
			return Lifecycle{}, arc.CommandIDReused()
		}
		return Lifecycle{}, err
	}
	failureKey := "recovery:" + base64.RawURLEncoding.EncodeToString(row.EmailHash)
	actor := Anonymous
	if row.UserID != nil {
		failureKey = "account:" + row.UserID.String()
		actor = Actor(*row.UserID)
	}
	failures := s.bucket(ratelimit.SignInFailuresAccount, failureKey)
	reservation, err := s.limits.Reserve(ctx, failures, s.now())
	if err != nil {
		s.release(ctx, row.ID)
		return Lifecycle{}, err
	}
	if !reservation.Allowed {
		s.release(ctx, row.ID)
		return Lifecycle{}, s.limited(ctx, request, failures, reservation, actor)
	}
	refuse := func(reason string) (Lifecycle, error) {
		if err := s.exhaust(ctx, row.ID); err != nil {
			return Lifecycle{}, err
		}
		if err := s.audited(ctx, request, failures, reservation, actor, "identity.recovery.failed", reason, map[string]any{}); err != nil {
			return Lifecycle{}, err
		}
		return Lifecycle{}, arc.Unauthenticated()
	}
	normalized, valid := NormalizeCode(in.EmailCode)
	if !valid {
		normalized = strings.Repeat("?", CodeLength)
	}
	candidate, err := s.codeHash(ctx, normalized, row.CodeSalt)
	if err != nil {
		s.giveBack(ctx, failures, reservation)
		s.release(ctx, row.ID)
		return Lifecycle{}, err
	}
	if !valid || subtle.ConstantTimeCompare(candidate, row.CodeHash) != 1 || row.UserID == nil || row.LifecycleOperationID == nil {
		return refuse("proof_invalid")
	}
	if in.Browser && (row.Origin == nil || *row.Origin != s.rp.Origin()) {
		return refuse("flow_origin")
	}
	credential, err := s.rp.VerifyCreation(row.Challenge, row.UserHandle, in.Creation, row.ExpiresAt)
	if err != nil {
		return refuse("passkey_invalid")
	}
	var result Lifecycle
	outcome, err := platform.Execute(ctx, s.db, command, store.TxOptions{}, func(ctx context.Context, tx pgx.Tx) ([]byte, error) {
		now := s.now()
		if _, err := s.CancelApprovals(ctx, tx, *row.UserID, now); err != nil {
			return nil, err
		}
		if _, err := tx.Exec(ctx, `SELECT 1 FROM identity.user WHERE user_id=$1 FOR UPDATE`, *row.UserID); err != nil {
			return nil, err
		}
		security, err := session.LockAccountSecurity(ctx, tx, *row.UserID)
		if err != nil {
			return nil, err
		}
		if !UserState(security.State).MaySignIn() || row.AccountAuthEpoch == nil || row.AccountRecoveryGeneration == nil ||
			security.AuthEpoch != *row.AccountAuthEpoch || security.RecoveryGeneration != *row.AccountRecoveryGeneration {
			return nil, arc.Expired()
		}
		operation, err := lifecycleOf(ctx, tx, *row.UserID, *row.LifecycleOperationID, true)
		if err != nil {
			return nil, err
		}
		if operation.Kind != LifecycleRecovery || operation.State != LifecycleAwaitingProof || !now.Before(operation.ExpiresAt) {
			return nil, arc.Expired()
		}
		if err = consume(ctx, tx, row.ID, now); err != nil {
			return nil, err
		}
		if err = s.rotateAccountSecurity(ctx, tx, *row.UserID, true, now); err != nil {
			return nil, err
		}
		if err = s.revokeAccountDevices(ctx, tx, *row.UserID, now); err != nil {
			return nil, err
		}
		// The verified recovery channel remains the account's trust anchor. Old
		// e-mail ceremonies carry the previous epochs and cannot authenticate;
		// passkeys are replaced and all remote enrollments were revoked above.
		if _, err = tx.Exec(ctx, `UPDATE identity.auth_identity SET revoked_at=$2,rev=rev+1 WHERE user_id=$1 AND provider_id='passkey' AND revoked_at IS NULL`, *row.UserID, now); err != nil {
			return nil, err
		}
		// A fresh per-operation handle keeps known/unknown Begin responses
		// indistinguishable even when the same address is requested repeatedly.
		if _, err = tx.Exec(ctx, `UPDATE identity.user SET passkey_user_handle=$2,rev=rev+1 WHERE user_id=$1`, *row.UserID, row.UserHandle); err != nil {
			return nil, err
		}
		identityID := platform.NewID()
		if _, err = tx.Exec(ctx, `INSERT INTO identity.auth_identity(auth_identity_id,user_id,method,provider_id,subject,public_key,user_handle,sign_count,
backup_eligible,backup_state,transports,aaguid,attestation_format,created_at,rev) VALUES($1,$2,1,'passkey',$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,1)`, identityID, *row.UserID,
			base64.RawURLEncoding.EncodeToString(credential.ID), credential.PublicKey, row.UserHandle, int64(credential.SignCount), credential.BackupEligible, credential.BackupState,
			credential.Transports, credential.AAGUID, credential.AttestationFormat, now); err != nil {
			return nil, err
		}
		if err = ratelimit.Release(ctx, tx, failures, reservation); err != nil {
			return nil, err
		}
		if _, err = tx.Exec(ctx, `UPDATE identity.lifecycle_operation SET state=4,command_id=$2,proof_id=$3,confirmed_at=$4,finished_at=$4,rev=rev+1 WHERE operation_id=$1`,
			operation.ID, in.CommandID, row.ID, now); err != nil {
			return nil, err
		}
		if _, err = platform.Enqueue(ctx, tx, platform.Message{DedupKey: "identity.recovery:" + operation.ID.String(), Topic: "identity.lifecycle.changed", AggregateKind: "account",
			AggregateID: *row.UserID, AggregateRev: operation.Revision + 1, Payload: []byte(`{"kind":"recovery_completed"}`), CorrelationID: in.CommandID}); err != nil {
			return nil, err
		}
		item, err := lifecycleOf(ctx, tx, *row.UserID, operation.ID, false)
		if err != nil {
			return nil, err
		}
		result = item.Lifecycle
		if err = s.audit(ctx, tx, request, Actor(*row.UserID), "identity.recovery.completed", "", "lifecycle_operation", operation.ID.String(), map[string]any{"credential": identityID.String()}); err != nil {
			return nil, err
		}
		return json.Marshal(result)
	})
	if err != nil {
		if !errors.Is(err, store.ErrCommitUnknown) {
			s.giveBack(ctx, failures, reservation)
			if refusalOf(err) == nil {
				s.release(ctx, row.ID)
			}
		}
		if errors.Is(err, platform.ErrCommandIDReused) {
			return Lifecycle{}, arc.CommandIDReused()
		}
		return Lifecycle{}, err
	}
	if !outcome.Succeeded {
		return Lifecycle{}, arc.InvalidState("account_recovery", "failed")
	}
	if outcome.Replayed {
		s.giveBack(ctx, failures, reservation)
	}
	err = json.Unmarshal(outcome.Result, &result)
	return result, err
}
