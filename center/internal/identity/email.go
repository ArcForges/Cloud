// SPDX-License-Identifier: AGPL-3.0-only

package identity

import (
	"context"
	"crypto/pbkdf2"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"math/big"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/ArcForges/Cloud/center/internal/arc"
	"github.com/ArcForges/Cloud/center/internal/mail"
	"github.com/ArcForges/Cloud/center/internal/platform"
	"github.com/ArcForges/Cloud/center/internal/ratelimit"
	"github.com/ArcForges/Cloud/center/internal/store"
)

// CodeAlphabet is AD-0011's e-mail code alphabet: twenty consonants that read unambiguously. A code is eight of them (about 34.6
// bits), shown as two groups of four.
const (
	CodeAlphabet = "BCDFGHJKLMNPQRSTVWXZ"
	CodeLength   = 8
)

// NewCode draws an e-mail code from the system's cryptographic random source.
func NewCode() string {
	var code strings.Builder
	limit := big.NewInt(int64(len(CodeAlphabet)))
	for range CodeLength {
		index, err := rand.Int(rand.Reader, limit)
		if err != nil {
			panic(err)
		}
		code.WriteByte(CodeAlphabet[index.Int64()])
	}
	return code.String()
}

// NormalizeCode is the canonical form of a presented code: upper case without spaces and hyphens; anything that is not eight
// letters of the alphabet is no code (and still counts as an attempt).
func NormalizeCode(text string) (string, bool) {
	if len(text) > 64 {
		return "", false
	}
	code := strings.ToUpper(strings.NewReplacer(" ", "", "-", "").Replace(text))
	if len(code) != CodeLength {
		return "", false
	}
	for index := range len(code) {
		if strings.IndexByte(CodeAlphabet, code[index]) < 0 {
			return "", false
		}
	}
	return code, true
}

// codeHash is the stored verifier of a code: PBKDF2-HMAC-SHA-256 with the flow's 16-byte salt. It runs outside every transaction
// and at most two at a time (PLT-9).
func (s *Service) codeHash(ctx context.Context, code string, salt []byte) ([]byte, error) {
	select {
	case s.codeSlots <- struct{}{}:
	case <-ctx.Done():
		return nil, ctx.Err()
	}
	defer func() { <-s.codeSlots }()
	return pbkdf2.Key(sha256.New, code, salt, s.policy.EmailCodeIterations, 32)
}

// RequestEmailCode sends a code for a native e-mail flow (DC-08): the flow must exist, be unconsumed and unexpired, and name the
// same address and purpose; a resend replaces the code and never resets the attempts, up to the policy's sends per flow. Every
// syntactically valid address gets the same answer and the same statements (SEC-05): the code is generated and stored whether or
// not an account has the address, and it is mailed, after the response and outside the transaction, only when one does.
func (s *Service) RequestEmailCode(ctx context.Context, request Request, flowID platform.ID, hasFlow bool, email string, purpose int32) (Challenge, error) {
	if !s.mailer.Enabled() {
		return Challenge{}, arc.InvalidArgument("method", "not_offered")
	}
	if purpose != int32(PurposeAuthenticate) {
		return Challenge{}, arc.InvalidArgument("purpose", "not_offered")
	}
	if !hasFlow {
		return Challenge{}, arc.InvalidArgument("flow_id", "required")
	}
	normalized, ok := NormalizeEmail(email)
	if !ok {
		return Challenge{}, arc.InvalidArgument("email", "pattern")
	}
	if err := s.take(ctx, request, s.bucket(ratelimit.EmailPrefix, ratelimit.Prefix(request.ClientIP)), Anonymous); err != nil {
		return Challenge{}, err
	}
	if err := s.take(ctx, request, s.bucket(ratelimit.EmailAddress, normalized), Anonymous); err != nil {
		return Challenge{}, err
	}
	code, salt := NewCode(), randomBytes(16)
	hash, err := s.codeHash(ctx, code, salt)
	if err != nil {
		return Challenge{}, err
	}
	var result Challenge
	var recipient *platform.ID
	err = s.db.InTx(ctx, "send an e-mail code", store.TxOptions{}, func(ctx context.Context, tx pgx.Tx) error {
		result, recipient = Challenge{}, nil
		now := s.now()
		var emailHash []byte
		var sends int16
		var expiresAt time.Time
		var consumed bool
		err := tx.QueryRow(ctx, `SELECT email_hash, sends, expires_at, consumed_at IS NOT NULL FROM identity.auth_flow
WHERE flow_id = $1 AND channel = 1 AND kind = 4 AND purpose = $2 FOR UPDATE`, flowID, int16(purpose)).Scan(&emailHash, &sends, &expiresAt, &consumed)
		switch {
		case errors.Is(err, pgx.ErrNoRows):
			return arc.NotFound()
		case err != nil:
			return err
		case subtle.ConstantTimeCompare(emailHash, EmailHash(normalized)) != 1:
			return arc.NotFound()
		case consumed:
			return classify(ctx, tx, flowID, ChannelNative, []FlowKind{FlowEmailCode}, PurposeAuthenticate, now)
		case !now.Before(expiresAt):
			return arc.Expired()
		case int(sends) >= s.policy.EmailCodeSends:
			return arc.RateLimited("email_code_sends", int64(s.policy.EmailCodeSends), expiresAt)
		}
		var userID platform.ID
		var state int16
		err = tx.QueryRow(ctx, `SELECT a.user_id, u.state FROM identity.auth_identity a JOIN identity.user u ON u.user_id = a.user_id
WHERE a.provider_id = 'email' AND a.subject = $1 AND a.revoked_at IS NULL`, normalized).Scan(&userID, &state)
		switch {
		case errors.Is(err, pgx.ErrNoRows):
		case err != nil:
			return err
		case UserState(state).MaySignIn():
			recipient = &userID
		}
		if _, err = tx.Exec(ctx, `UPDATE identity.auth_flow SET code_hash = $2, code_salt = $3, sends = sends + 1, user_id = $4 WHERE flow_id = $1`,
			flowID, hash, salt, recipient); err != nil {
			return err
		}
		result = Challenge{FlowID: flowID, Method: MethodValueEmail, Purpose: PurposeAuthenticate, Challenge: emailChallenge(flowID),
			ExpiresAt: expiresAt, ProviderID: "email"}
		return nil
	})
	if err != nil {
		return Challenge{}, err
	}
	if recipient != nil {
		message := mail.Message{To: normalized, Subject: "Your ArcForges sign-in code", Text: codeText(code, s.policy.EmailCodeLifetime)}
		s.background(func() {
			sendContext, cancel := context.WithTimeout(context.WithoutCancel(ctx), 30*time.Second)
			defer cancel()
			if err := s.mailer.Send(sendContext, message); err != nil {
				s.events.ObserveIdentity("email_send", "failed")
				s.logger.Warn("an e-mail code could not be delivered")
				return
			}
			s.events.ObserveIdentity("email_send", "sent")
		})
	}
	s.events.ObserveIdentity("email_request", "accepted")
	return result, nil
}

func codeText(code string, lifetime time.Duration) string {
	return "Your ArcForges sign-in code is " + code[:4] + "-" + code[4:] + ".\n\nIt expires in " + strconv.Itoa(int(lifetime.Minutes())) +
		" minutes. If you did not try to sign in, ignore this message: nobody can sign in without the code.\n"
}

// RedeemEmailCode completes a native e-mail flow with its code (RedeemEmailCode, or CompleteAuthentication with an e-mail code
// proof): the sign-in bucket of the prefix, the failure bucket of the flow's address (across flows), the flow's attempt, the
// PBKDF2 check outside any transaction (at most the policy's attempts per flow ever reach it), and the success transaction. A
// wrong code, a code of an address without an account and an account that may not sign in all give AUTHENTICATION/unauthenticated.
func (s *Service) RedeemEmailCode(ctx context.Context, request Request, flowID platform.ID, code string) (SignedIn, error) {
	if code == "" || len(code) > 128 {
		return SignedIn{}, arc.InvalidArgument("code", "length")
	}
	if !s.mailer.Enabled() {
		return SignedIn{}, arc.InvalidArgument("method", "not_offered")
	}
	if err := s.take(ctx, request, s.bucket(ratelimit.SignInPrefix, ratelimit.Prefix(request.ClientIP)), Anonymous); err != nil {
		return SignedIn{}, err
	}
	var emailHash []byte
	err := s.db.InTx(ctx, "find an e-mail flow", store.TxOptions{ReadOnly: true, Timeout: 5 * time.Second}, func(ctx context.Context, tx pgx.Tx) error {
		err := tx.QueryRow(ctx, "SELECT email_hash FROM identity.auth_flow WHERE flow_id = $1 AND kind = 4", flowID).Scan(&emailHash)
		if errors.Is(err, pgx.ErrNoRows) {
			emailHash = nil
			return nil
		}
		return err
	})
	if err != nil {
		return SignedIn{}, err
	}
	var failures ratelimit.Bucket
	if emailHash != nil {
		failures = s.bucket(ratelimit.RedeemFailuresAddress, hex.EncodeToString(emailHash))
		if err = s.check(ctx, request, failures, Anonymous); err != nil {
			return SignedIn{}, err
		}
	}
	row, err := s.takeAttempt(ctx, flowID, ChannelNative, []FlowKind{FlowEmailCode}, PurposeAuthenticate)
	if err != nil {
		return SignedIn{}, err
	}
	failures = s.bucket(ratelimit.RedeemFailuresAddress, hex.EncodeToString(row.EmailHash))
	normalized, valid := NormalizeCode(code)
	if !valid {
		normalized = strings.Repeat("?", CodeLength) // still costs one PBKDF2 run, like any wrong code
	}
	candidate, err := s.codeHash(ctx, normalized, row.CodeSalt)
	if err != nil {
		return SignedIn{}, err
	}
	if !valid || row.UserID == nil || subtle.ConstantTimeCompare(candidate, row.CodeHash) != 1 {
		s.events.ObserveIdentity("sign_in_complete", "refused")
		if row.Attempts >= row.MaxAttempts {
			if err = s.exhaust(ctx, row.ID); err != nil {
				return SignedIn{}, err
			}
		}
		if err = s.fail(ctx, request, failures, Anonymous, "identity.sign_in.failed", "code_invalid", map[string]any{"method": "email_code", "channel": "native"}); err != nil {
			return SignedIn{}, err
		}
		return SignedIn{}, arc.Unauthenticated()
	}
	userID := *row.UserID
	return s.signIn(ctx, request, row, userID, int16(MethodEmailCode), func(ctx context.Context, tx pgx.Tx, now time.Time) error {
		var identityID platform.ID
		err := tx.QueryRow(ctx, `SELECT auth_identity_id FROM identity.auth_identity
WHERE user_id = $1 AND provider_id = 'email' AND revoked_at IS NULL AND sha256(convert_to(subject, 'UTF8')) = $2 FOR UPDATE`, userID, row.EmailHash).
			Scan(&identityID)
		if errors.Is(err, pgx.ErrNoRows) {
			return arc.Unauthenticated()
		}
		if err != nil {
			return err
		}
		_, err = tx.Exec(ctx, "UPDATE identity.auth_identity SET last_used_at = $2, rev = rev + 1 WHERE auth_identity_id = $1", identityID, now)
		return err
	})
}
