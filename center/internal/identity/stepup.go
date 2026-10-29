// SPDX-License-Identifier: AGPL-3.0-only

package identity

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/ArcForges/Cloud/center/internal/access"
	"github.com/ArcForges/Cloud/center/internal/arc"
	"github.com/ArcForges/Cloud/center/internal/identity/passkey"
	"github.com/ArcForges/Cloud/center/internal/mail"
	"github.com/ArcForges/Cloud/center/internal/platform"
	"github.com/ArcForges/Cloud/center/internal/ratelimit"
	"github.com/ArcForges/Cloud/center/internal/store"
)

// Caller is an authenticated call of the identity surface: the caller's account, session and device, the session's scope and
// credential kind, the epochs it was verified in, and the call's address and correlation.
type Caller struct {
	Request
	UserID    platform.ID
	SessionID platform.ID
	DeviceID  platform.ID
	// Scope is the session's scope name (account or mobile.limited; the operation table admits no other).
	Scope string
	// Browser is true for a cookie session, false for a native bearer.
	Browser            bool
	AuthEpoch          int64
	RecoveryGeneration int64
}

// PurposeStepUp is the contract's AuthPurpose of a step-up challenge (a challenge reply only: step-up challenges are not flows).
const PurposeStepUp Purpose = 3

// The step-up challenge states (identity.step_up_state).
const (
	stepUpPending  = 1
	stepUpProved   = 2
	stepUpConsumed = 3
	stepUpDenied   = 5
)

// maxStepUpAttempts is the attempts of an e-mail step-up code: the policy's e-mail code attempts, at most the five the store
// admits (identity.step_up_challenge.attempt_count). A passkey challenge serves one assertion.
func (s *Service) maxStepUpAttempts(method int32) int16 {
	if method == MethodValuePasskey {
		return passkeyAttempts
	}
	return int16(min(s.policy.EmailCodeAttempts, 5))
}

// TargetHash is a step-up target (DC-01): the lowercase hexadecimal SHA-256 of the class, the account and the target object, each
// on its own line, with the identifiers in their canonical lowercase text. An operation without a target object (RevokeAllSessions,
// BeginPasskeyRegistration) names the account as its target; the upgrade class names the session.
func TargetHash(class string, accountID, targetID platform.ID) string {
	digest := sha256.Sum256([]byte(class + "\n" + accountID.String() + "\n" + targetID.String()))
	return hex.EncodeToString(digest[:])
}

var (
	classPattern      = regexp.MustCompile(`^[A-Za-z0-9._:/-]{1,128}$`)
	targetHashPattern = regexp.MustCompile(`^[0-9a-f]{64}$`)
)

// StepUpBegin is a BeginStepUp request; a nil field was absent.
type StepUpBegin struct {
	Class      *string
	Method     *int32
	TargetHash *string
}

// Evidence is a proved step-up (the contract's StepUpEvidence): its class and when it expires.
type Evidence struct {
	Class     string
	ExpiresAt time.Time
}

// accountMethods are the live credentials a step-up can use: the account's passkey credential IDs and its oldest live e-mail
// address.
func accountMethods(ctx context.Context, tx pgx.Tx, userID platform.ID) (passkeys [][]byte, email string, err error) {
	rows, err := tx.Query(ctx, `SELECT provider_id, subject FROM identity.auth_identity WHERE user_id = $1 AND revoked_at IS NULL
ORDER BY created_at, auth_identity_id`, userID)
	if err != nil {
		return nil, "", err
	}
	defer rows.Close()
	for rows.Next() {
		var provider, subject string
		if err = rows.Scan(&provider, &subject); err != nil {
			return nil, "", err
		}
		switch provider {
		case "passkey":
			id, decodeErr := base64.RawURLEncoding.DecodeString(subject)
			if decodeErr == nil {
				passkeys = append(passkeys, id)
			}
		case "email":
			if email == "" {
				email = subject
			}
		}
	}
	return passkeys, email, rows.Err()
}

// BeginStepUp starts a step-up of the caller's session (DC-01, SEC-02): one challenge for one class and one target hash, proved by
// a passkey of the account or by an e-mail code sent to its address. The class is the operation ID of an operation that needs
// evidence, or the upgrade class of a mobile.limited session (whose target must be the session itself). The account's step-up
// bucket counts the request first. Authentication time is never evidence: only a proved challenge is.
func (s *Service) BeginStepUp(ctx context.Context, caller Caller, in StepUpBegin) (Challenge, error) {
	switch {
	case in.Class == nil:
		return Challenge{}, arc.InvalidArgument("operation_class", "required")
	case !classPattern.MatchString(*in.Class):
		return Challenge{}, arc.InvalidArgument("operation_class", "pattern")
	case in.Method == nil:
		return Challenge{}, arc.InvalidArgument("method", "required")
	case in.TargetHash == nil:
		return Challenge{}, arc.InvalidArgument("target_hash", "required")
	case !targetHashPattern.MatchString(*in.TargetHash):
		return Challenge{}, arc.InvalidArgument("target_hash", "pattern")
	}
	class, method := *in.Class, *in.Method
	if _, ok := access.StepUpClass(class); !ok {
		return Challenge{}, arc.InvalidArgument("operation_class", "not_offered")
	}
	if class == access.UpgradeClass {
		if caller.Scope != "mobile.limited" {
			return Challenge{}, arc.InvalidArgument("operation_class", "not_offered")
		}
		if *in.TargetHash != TargetHash(class, caller.UserID, caller.SessionID) {
			return Challenge{}, arc.InvalidArgument("target_hash", "not_the_session")
		}
	}
	if method != MethodValuePasskey && (method != MethodValueEmail || !s.mailer.Enabled()) {
		return Challenge{}, arc.InvalidArgument("method", "not_offered")
	}
	if err := s.take(ctx, caller.Request, s.bucket(ratelimit.StepUpAccount, "account:"+caller.UserID.String()), Actor(caller.UserID)); err != nil {
		return Challenge{}, err
	}
	target, err := hex.DecodeString(*in.TargetHash)
	if err != nil {
		return Challenge{}, arc.InvalidArgument("target_hash", "pattern")
	}
	now := s.now()
	result := Challenge{FlowID: platform.NewID(), Method: method, Purpose: PurposeStepUp}
	var code string
	var codeHash, codeSalt, challenge []byte
	if method == MethodValueEmail {
		code, codeSalt = NewCode(), randomBytes(16)
		if codeHash, err = s.codeHash(ctx, code, codeSalt); err != nil {
			return Challenge{}, err
		}
		result.Challenge, result.ProviderID, result.ExpiresAt = emailChallenge(result.FlowID), "email", now.Add(s.policy.EmailCodeLifetime)
	} else {
		challenge = randomBytes(passkey.ChallengeBytes)
		result.Challenge, result.ProviderID, result.ExpiresAt = challenge, "passkey", now.Add(s.policy.PasskeyFlowLifetime)
	}
	var recipient string
	err = s.db.InTx(ctx, "begin a step-up", store.TxOptions{}, func(ctx context.Context, tx pgx.Tx) error {
		recipient = ""
		passkeys, email, err := accountMethods(ctx, tx, caller.UserID)
		if err != nil {
			return err
		}
		switch {
		case method == MethodValuePasskey && len(passkeys) == 0, method == MethodValueEmail && email == "":
			return arc.InvalidArgument("method", "not_offered")
		case method == MethodValuePasskey:
			options := s.rp.StepUpOptions(passkeys)
			result.Options = &options
		default:
			recipient = email
		}
		_, err = tx.Exec(ctx, `INSERT INTO identity.step_up_challenge (challenge_id, user_id, session_id, operation_id, target_hash, method, challenge,
    code_hash, code_salt, state, attempt_count, created_at, expires_at, auth_epoch, recovery_generation, rev)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, 1, 0, $10, $11, $12, $13, 1)`, result.FlowID, caller.UserID, caller.SessionID, class, target, int16(method),
			challenge, codeHash, codeSalt, now, result.ExpiresAt, caller.AuthEpoch, caller.RecoveryGeneration)
		return err
	})
	if err != nil {
		return Challenge{}, err
	}
	if recipient != "" {
		message := mail.Message{To: recipient, Subject: "Your ArcForges verification code", Text: stepUpText(code, s.policy.EmailCodeLifetime)}
		s.background(func() {
			sendContext, cancel := context.WithTimeout(context.WithoutCancel(ctx), 30*time.Second)
			defer cancel()
			if err := s.mailer.Send(sendContext, message); err != nil {
				s.events.ObserveIdentity("email_send", "failed")
				s.logger.Warn("a step-up code could not be delivered")
				return
			}
			s.events.ObserveIdentity("email_send", "sent")
		})
	}
	s.events.ObserveIdentity("step_up_begin", methodLabel(method))
	return result, nil
}

func stepUpText(code string, lifetime time.Duration) string {
	return "Your ArcForges verification code is " + code[:4] + "-" + code[4:] + ".\n\nIt confirms one sensitive change to your account and expires in " +
		strconv.Itoa(int(lifetime.Minutes())) + " minutes. If you did not ask for it, someone may be using one of your sessions: review them in " +
		"your account's security settings.\n"
}

// StepUpProof is a CompleteStepUp proof: a passkey assertion or an e-mail code.
type StepUpProof struct {
	Passkey   *passkey.Assertion
	EmailCode *string
}

type stepUpChallenge struct {
	class                         string
	method                        int32
	challenge, codeHash, codeSalt []byte
	attempts                      int16
	expiresAt                     time.Time
	authEpoch, recoveryGeneration int64
}

// classifyStepUp explains why a challenge could not take an attempt: unknown or of another session (not_found), proved with
// another method (invalid_argument), already proved or consumed (code_reused), denied, expired or out of attempts (expired).
func classifyStepUp(ctx context.Context, tx pgx.Tx, id platform.ID, caller Caller, method int32, now time.Time) error {
	var sessionID, userID platform.ID
	var storedMethod, state int16
	var expiresAt time.Time
	err := tx.QueryRow(ctx, "SELECT session_id, user_id, method, state, expires_at FROM identity.step_up_challenge WHERE challenge_id = $1", id).
		Scan(&sessionID, &userID, &storedMethod, &state, &expiresAt)
	switch {
	case errors.Is(err, pgx.ErrNoRows):
		return arc.NotFound("step_up_challenge", id[:])
	case err != nil:
		return err
	case sessionID != caller.SessionID || userID != caller.UserID:
		return arc.NotFound("step_up_challenge", id[:])
	case int32(storedMethod) != method:
		return arc.InvalidArgument("proof", "not_offered")
	case state == stepUpProved || state == stepUpConsumed:
		return arc.CodeReused()
	case state != stepUpPending || !now.Before(expiresAt):
		return arc.Expired()
	}
	return arc.Expired() // pending, unexpired and out of attempts
}

// takeStepUpAttempt counts one completion attempt of a challenge of the caller's session in its own auxiliary transaction (D10),
// before the proof is checked.
func (s *Service) takeStepUpAttempt(ctx context.Context, id platform.ID, caller Caller, method int32) (stepUpChallenge, error) {
	now := s.now()
	var item stepUpChallenge
	err := s.db.InTx(ctx, "count a step-up attempt", store.TxOptions{Timeout: 5 * time.Second, Auxiliary: true}, func(ctx context.Context, tx pgx.Tx) error {
		var storedMethod int16
		err := tx.QueryRow(ctx, `UPDATE identity.step_up_challenge SET attempt_count = attempt_count + 1, rev = rev + 1
WHERE challenge_id = $1 AND session_id = $2 AND user_id = $3 AND method = $4 AND state = 1 AND expires_at > $5 AND attempt_count < $6
RETURNING operation_id, method, challenge, code_hash, code_salt, attempt_count, expires_at, auth_epoch, recovery_generation`,
			id, caller.SessionID, caller.UserID, int16(method), now, s.maxStepUpAttempts(method)).Scan(&item.class, &storedMethod, &item.challenge,
			&item.codeHash, &item.codeSalt, &item.attempts, &item.expiresAt, &item.authEpoch, &item.recoveryGeneration)
		if errors.Is(err, pgx.ErrNoRows) {
			return classifyStepUp(ctx, tx, id, caller, method, now)
		}
		item.method = int32(storedMethod)
		return err
	})
	return item, err
}

// denyStepUp ends a challenge whose last attempt failed, in its own auxiliary transaction (D10).
func (s *Service) denyStepUp(ctx context.Context, id platform.ID) error {
	return s.db.InTx(ctx, "deny a step-up", store.TxOptions{Timeout: 5 * time.Second, Auxiliary: true}, func(ctx context.Context, tx pgx.Tx) error {
		_, err := tx.Exec(ctx, "UPDATE identity.step_up_challenge SET state = $2, rev = rev + 1 WHERE challenge_id = $1 AND state = 1", id, stepUpDenied)
		return err
	})
}

// releaseStepUp gives back the attempt a step-up completion took when its proof verified but its transaction failed in the store
// (as release does for a flow; F9): best effort, in its own short auxiliary transaction, and only while the challenge is pending.
func (s *Service) releaseStepUp(ctx context.Context, id platform.ID) {
	_ = s.db.InTx(context.WithoutCancel(ctx), "release a step-up attempt", store.TxOptions{Timeout: 5 * time.Second, Auxiliary: true},
		func(ctx context.Context, tx pgx.Tx) error {
			_, err := tx.Exec(ctx, "UPDATE identity.step_up_challenge SET attempt_count = attempt_count - 1, rev = rev + 1 WHERE challenge_id = $1 AND state = 1 AND attempt_count > 0", id)
			return err
		})
}

// CompleteStepUp proves a step-up challenge of the caller's session: the account's failure bucket is checked, the challenge's
// attempt is counted, and one failure of the account is reserved atomically under the bucket's limit (as a wrong e-mail code's is,
// E6), so concurrent proofs over several challenges cannot pass the limit; a refused reservation gives the attempt back. The proof is
// checked outside any transaction (a passkey of this account under the F14 counter rule, or the code), and one transaction marks the
// challenge proved with an expiry of the policy's evidence lifetime (at most five minutes) from now, records the session's epochs,
// gives the reservation back and, for a mobile.limited session, upgrades the session to account (the upgrade class consumes the
// evidence at once). A wrong proof keeps its reservation as the counted failure and gives AUTHENTICATION/unauthenticated; a
// right proof whose transaction failed in the store gets its attempt and its reservation back (F9, D2).
func (s *Service) CompleteStepUp(ctx context.Context, caller Caller, challengeID platform.ID, proof StepUpProof) (Evidence, error) {
	method := int32(MethodValuePasskey)
	switch {
	case proof.Passkey != nil:
		if refusal := validAssertion(*proof.Passkey); refusal != nil {
			return Evidence{}, refusal
		}
	case proof.EmailCode != nil:
		method = MethodValueEmail
		if *proof.EmailCode == "" || len(*proof.EmailCode) > 128 {
			return Evidence{}, arc.InvalidArgument("proof.email_code", "length")
		}
		if !s.mailer.Enabled() {
			return Evidence{}, arc.InvalidArgument("method", "not_offered")
		}
	default:
		return Evidence{}, arc.InvalidArgument("proof", "required")
	}
	failures := s.bucket(ratelimit.SignInFailuresAccount, "account:"+caller.UserID.String())
	if err := s.check(ctx, caller.Request, failures, Actor(caller.UserID)); err != nil {
		return Evidence{}, err
	}
	row, err := s.takeStepUpAttempt(ctx, challengeID, caller, method)
	if err != nil {
		return Evidence{}, err
	}
	reservation, err := s.limits.Reserve(ctx, failures, s.now())
	if err != nil {
		return Evidence{}, err
	}
	if !reservation.Allowed {
		// No proof was checked: the attempt is given back, and the refusal is a limited request.
		s.releaseStepUp(ctx, challengeID)
		return Evidence{}, s.limited(ctx, caller.Request, failures, reservation, Actor(caller.UserID))
	}
	refuse := func(reason string) (Evidence, error) {
		s.events.ObserveIdentity("step_up_complete", "refused")
		if row.attempts >= s.maxStepUpAttempts(method) {
			if err := s.denyStepUp(ctx, challengeID); err != nil {
				return Evidence{}, err
			}
		}
		if err := s.audited(ctx, caller.Request, failures, reservation, Actor(caller.UserID), "identity.step_up.failed", reason,
			map[string]any{"method": methodLabel(method), "class": row.class}); err != nil {
			return Evidence{}, err
		}
		return Evidence{}, arc.Unauthenticated()
	}
	var found *storedPasskey
	var verified passkey.Verified
	if method == MethodValuePasskey {
		if found, err = s.findPasskey(ctx, proof.Passkey.CredentialID); err != nil {
			return Evidence{}, err
		}
		if found == nil || found.userID != caller.UserID || !found.state.MaySignIn() {
			return refuse("unknown_credential")
		}
		if verified, err = s.rp.VerifyAssertion(row.challenge, *proof.Passkey, found.stored, row.expiresAt); err != nil {
			return refuse("passkey_invalid")
		}
	} else {
		normalized, valid := NormalizeCode(*proof.EmailCode)
		if !valid {
			normalized = strings.Repeat("?", CodeLength) // still costs one PBKDF2 run, like any wrong code
		}
		candidate, err := s.codeHash(ctx, normalized, row.codeSalt)
		if err != nil {
			return Evidence{}, err
		}
		if !valid || subtle.ConstantTimeCompare(candidate, row.codeHash) != 1 {
			return refuse("code_invalid")
		}
	}
	var evidence Evidence
	upgraded := false
	err = s.db.InTx(ctx, "prove a step-up", store.TxOptions{}, func(ctx context.Context, tx pgx.Tx) error {
		evidence, upgraded = Evidence{}, false
		now := s.now()
		var scope int16
		var authEpoch, recoveryGeneration int64
		var live bool
		err := tx.QueryRow(ctx, `SELECT scope, auth_epoch, recovery_generation, revoked_at IS NULL FROM identity.session
WHERE session_id = $1 AND user_id = $2 FOR UPDATE`, caller.SessionID, caller.UserID).Scan(&scope, &authEpoch, &recoveryGeneration, &live)
		switch {
		case errors.Is(err, pgx.ErrNoRows), err == nil && !live:
			return arc.CredentialRevoked()
		case err != nil:
			return err
		case authEpoch != row.authEpoch || recoveryGeneration != row.recoveryGeneration:
			return arc.Expired() // the account's credentials changed since the challenge began
		}
		expiresAt := now.Add(s.policy.StepUpEvidenceTTL)
		tag, err := tx.Exec(ctx, `UPDATE identity.step_up_challenge SET state = 2, proved_at = $2, expires_at = $3, rev = rev + 1
WHERE challenge_id = $1 AND state = 1`, challengeID, now, expiresAt)
		if err != nil {
			return err
		}
		if tag.RowsAffected() != 1 {
			return arc.CodeReused()
		}
		if err = ratelimit.Release(ctx, tx, failures, reservation); err != nil {
			return err
		}
		if method == MethodValuePasskey {
			if err = advanceCounter(ctx, tx, found.identityID, verified, now); err != nil {
				return err
			}
		} else if _, err = tx.Exec(ctx, `UPDATE identity.auth_identity SET last_used_at = $2, rev = rev + 1
WHERE user_id = $1 AND provider_id = 'email' AND revoked_at IS NULL`, caller.UserID, now); err != nil {
			return err
		}
		if scope == 2 {
			upgraded = true
			if _, err = tx.Exec(ctx, "UPDATE identity.session SET scope = 1, step_up_at = $2, rev = rev + 1 WHERE session_id = $1", caller.SessionID, now); err != nil {
				return err
			}
		}
		if row.class == access.UpgradeClass {
			if _, err = tx.Exec(ctx, "UPDATE identity.step_up_challenge SET state = 3, consumed_at = $2, rev = rev + 1 WHERE challenge_id = $1",
				challengeID, now); err != nil {
				return err
			}
		}
		evidence = Evidence{Class: row.class, ExpiresAt: expiresAt}
		return s.audit(ctx, tx, caller.Request, Actor(caller.UserID), "identity.step_up.proved", "", "session", caller.SessionID.String(),
			map[string]any{"class": row.class, "method": methodLabel(method), "upgraded": upgraded})
	})
	if err != nil {
		refusal := refusalOf(err)
		if refusal != nil && refusal.Code == "unauthenticated" {
			return refuse("step_up_refused") // the F14 counter rule: a possible clone is a failed proof
		}
		if !errors.Is(err, store.ErrCommitUnknown) {
			// The proof verified: it is no failure. Its reservation goes back (the transaction that gave it back rolled back), and
			// after a store failure (not a refusal) its attempt too, so the advised retry can prove the same challenge.
			s.giveBack(ctx, failures, reservation)
			if refusal == nil {
				s.releaseStepUp(ctx, challengeID)
			}
		}
		return Evidence{}, err
	}
	s.events.ObserveIdentity("step_up_complete", "proved")
	if upgraded {
		s.events.ObserveIdentity("step_up_complete", "upgraded")
	}
	return evidence, nil
}

// advanceCounter records a verified passkey assertion on its credential under the credential's row lock (sign-in and step-up). The
// library's clone rule is checked again against the locked counter (F14): a counter that does not exceed the stored one is refused
// unless both are zero (an authenticator without a counter), because a concurrent use may have advanced it since the library
// checked. The credential's last use moves.
func advanceCounter(ctx context.Context, tx pgx.Tx, identityID platform.ID, verified passkey.Verified, now time.Time) error {
	var current int64
	if err := tx.QueryRow(ctx, "SELECT sign_count FROM identity.auth_identity WHERE auth_identity_id = $1 AND revoked_at IS NULL FOR UPDATE",
		identityID).Scan(&current); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return arc.Unauthenticated()
		}
		return err
	}
	if int64(verified.SignCount) <= current && (verified.SignCount != 0 || current != 0) {
		return arc.Unauthenticated() // a possible clone
	}
	_, err := tx.Exec(ctx, `UPDATE identity.auth_identity SET sign_count = $2, backup_state = $3, last_used_at = $4, rev = rev + 1
WHERE auth_identity_id = $1`, identityID, int64(verified.SignCount), verified.BackupState, now)
	return err
}

// ConsumeEvidence consumes, in the sensitive call's own transaction, one proved step-up of the caller's session for the class and
// the target object: same account, session, class and target hash, proved within the evidence lifetime, in the session's current
// epochs. It first locks the account's row, the lock under which a credential removal moves the authentication epoch, so the
// evidence is read only after any concurrent removal committed (B3); it locks the challenge, so two concurrent calls cannot use one
// proof; without evidence the call is refused with AUTHENTICATION/step_up_required (retry the same command after a step-up), which
// rolls the call back.
func ConsumeEvidence(ctx context.Context, tx pgx.Tx, caller Caller, class string, targetID platform.ID, now time.Time) error {
	target, err := hex.DecodeString(TargetHash(class, caller.UserID, targetID))
	if err != nil {
		return err
	}
	if _, err = tx.Exec(ctx, "SELECT 1 FROM identity.user WHERE user_id = $1 FOR UPDATE", caller.UserID); err != nil {
		return err
	}
	var challengeID platform.ID
	err = tx.QueryRow(ctx, `SELECT c.challenge_id FROM identity.step_up_challenge c JOIN identity.session s ON s.session_id = c.session_id
WHERE c.session_id = $1 AND c.user_id = $2 AND c.operation_id = $3 AND c.target_hash = $4 AND c.state = 2 AND c.expires_at > $5
    AND s.revoked_at IS NULL AND s.auth_epoch = c.auth_epoch AND s.recovery_generation = c.recovery_generation
ORDER BY c.proved_at, c.challenge_id LIMIT 1 FOR UPDATE OF c`, caller.SessionID, caller.UserID, class, target, now).Scan(&challengeID)
	if errors.Is(err, pgx.ErrNoRows) {
		return arc.StepUpRequired()
	}
	if err != nil {
		return err
	}
	tag, err := tx.Exec(ctx, "UPDATE identity.step_up_challenge SET state = 3, consumed_at = $2, rev = rev + 1 WHERE challenge_id = $1 AND state = 2",
		challengeID, now)
	if err != nil {
		return err
	}
	if tag.RowsAffected() != 1 {
		return arc.StepUpRequired()
	}
	return nil
}
