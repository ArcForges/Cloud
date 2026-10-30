// SPDX-License-Identifier: AGPL-3.0-only

package identity

import (
	"context"
	"encoding/base64"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/ArcForges/Cloud/center/internal/arc"
	"github.com/ArcForges/Cloud/center/internal/device"
	"github.com/ArcForges/Cloud/center/internal/identity/passkey"
	"github.com/ArcForges/Cloud/center/internal/platform"
	"github.com/ArcForges/Cloud/center/internal/session"
	"github.com/ArcForges/Cloud/center/internal/store"
)

// The account's writes (AF-CTR-03 A1b). Each write that runs under a command receipt takes the receipt's transaction (tx) and is
// called by the identity surface inside platform.Execute, after the step-up evidence it needs was consumed in the same transaction:
// it locks what it changes, checks the expected revision, changes it and appends its audit event as its last statement, so a
// refusal or a failed audit leaves nothing behind. A final refusal (retry NEVER) is kept by the receipt; any other rolls it back.

// The step-up classes of the account's writes (the operation table's evidence rows).
const (
	ClassBeginRegistration = "identity.beginPasskeyRegistration"
	ClassRevokeSession     = "identity.revokeSession"
	ClassRevokeAllSessions = "identity.revokeAllSessions"
	ClassRemoveCredential  = "identity.removeAuthIdentity"
	ClassRevokeDevice      = "device.revoke"
)

// ProfileChange is an UpdateProfile patch: a nil field is unchanged.
type ProfileChange struct {
	DisplayName *string
	Locale      *string
	Timezone    *string
}

// checkRevision refuses a stale meta.expected_rev with CONFLICT/revision_conflict (expected is nil when the request stated none).
func checkRevision(expected *int64, current int64) error {
	if expected != nil && *expected != current {
		return arc.RevisionConflict(*expected, current)
	}
	return nil
}

// UpdateProfile changes the caller's profile in the receipt's transaction (UpdateProfile): the display name (1 to 128 characters),
// the locale and the time zone, each only when present, against meta.expected_rev of the account. An empty patch changes nothing.
func (s *Service) UpdateProfile(ctx context.Context, tx pgx.Tx, caller Caller, change ProfileChange, expected *int64) (Profile, error) {
	switch {
	case change.DisplayName != nil && !ValidDisplayName(*change.DisplayName):
		return Profile{}, arc.InvalidArgument("patch.display_name", "length")
	case change.Locale != nil && !ValidLocale(*change.Locale):
		return Profile{}, arc.InvalidArgument("patch.locale", "pattern")
	case change.Timezone != nil && !ValidTimezone(*change.Timezone):
		return Profile{}, arc.InvalidArgument("patch.timezone", "pattern")
	}
	var current int64
	if err := tx.QueryRow(ctx, "SELECT rev FROM identity.user WHERE user_id = $1 FOR UPDATE", caller.UserID).Scan(&current); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return Profile{}, arc.NotFound("account", caller.UserID[:])
		}
		return Profile{}, err
	}
	if err := checkRevision(expected, current); err != nil {
		return Profile{}, err
	}
	if change.DisplayName != nil || change.Locale != nil || change.Timezone != nil {
		if _, err := tx.Exec(ctx, `UPDATE identity.user SET display_name = coalesce($2, display_name), locale = coalesce($3, locale),
    timezone = coalesce($4, timezone), rev = rev + 1 WHERE user_id = $1`, caller.UserID, change.DisplayName, change.Locale, change.Timezone); err != nil {
			return Profile{}, err
		}
	}
	var profile Profile
	if err := tx.QueryRow(ctx, `SELECT u.display_name, u.locale, u.timezone, u.rev,
    (SELECT a.subject FROM identity.auth_identity a WHERE a.user_id = u.user_id AND a.provider_id = 'email' AND a.revoked_at IS NULL
     ORDER BY a.created_at, a.auth_identity_id LIMIT 1)
FROM identity.user u WHERE u.user_id = $1`, caller.UserID).Scan(&profile.DisplayName, &profile.Locale, &profile.Timezone, &profile.Revision,
		&profile.PrimaryEmail); err != nil {
		return Profile{}, err
	}
	fields := []string{}
	for name, present := range map[string]bool{"display_name": change.DisplayName != nil, "locale": change.Locale != nil, "timezone": change.Timezone != nil} {
		if present {
			fields = append(fields, name)
		}
	}
	return profile, s.audit(ctx, tx, caller.Request, Actor(caller.UserID), "identity.profile.updated", "", "account", caller.UserID.String(),
		map[string]any{"fields": len(fields)})
}

// credentialOf reads one live credential of an account for a write, locked; another account's, a revoked and an unknown one are
// STATE/not_found with the credential the caller named.
func credentialOf(ctx context.Context, tx pgx.Tx, userID, credentialID platform.ID) (int64, error) {
	var revision int64
	err := tx.QueryRow(ctx, "SELECT rev FROM identity.auth_identity WHERE auth_identity_id = $1 AND user_id = $2 AND revoked_at IS NULL FOR UPDATE",
		credentialID, userID).Scan(&revision)
	if errors.Is(err, pgx.ErrNoRows) {
		return 0, arc.NotFound("credential", credentialID[:])
	}
	return revision, err
}

// readCredential is a credential as ListAuthIdentities shows it.
func readCredential(ctx context.Context, tx pgx.Tx, credentialID platform.ID) (Credential, error) {
	var item Credential
	var method int16
	err := tx.QueryRow(ctx, `SELECT auth_identity_id, method, coalesce(label, CASE WHEN method = 1 THEN 'Passkey' ELSE subject END), created_at, last_used_at
FROM identity.auth_identity WHERE auth_identity_id = $1`, credentialID).Scan(&item.ID, &method, &item.DisplayName, &item.CreatedAt, &item.LastUsedAt)
	item.Kind = Method(method).Kind()
	return item, err
}

// RenameCredential renames one of the caller's credentials in the receipt's transaction (RenameAuthIdentity): the name follows the
// credential label rule (1 to 64 characters of plain text), against meta.expected_rev of the credential.
func (s *Service) RenameCredential(ctx context.Context, tx pgx.Tx, caller Caller, credentialID platform.ID, name *string, expected *int64) (Credential, error) {
	if refusal := labelRefusal("name", name); refusal != nil {
		return Credential{}, refusal
	}
	current, err := credentialOf(ctx, tx, caller.UserID, credentialID)
	if err != nil {
		return Credential{}, err
	}
	if err = checkRevision(expected, current); err != nil {
		return Credential{}, err
	}
	if _, err = tx.Exec(ctx, "UPDATE identity.auth_identity SET label = $2, rev = rev + 1 WHERE auth_identity_id = $1", credentialID, *name); err != nil {
		return Credential{}, err
	}
	item, err := readCredential(ctx, tx, credentialID)
	if err != nil {
		return Credential{}, err
	}
	return item, s.audit(ctx, tx, caller.Request, Actor(caller.UserID), "identity.credential.renamed", "", "credential", credentialID.String(),
		map[string]any{"kind": item.Kind})
}

// RemoveCredential revokes one of the caller's credentials in the receipt's transaction (RemoveAuthIdentity, after its step-up
// evidence was consumed): the account is locked, so concurrent removals run one after the other, and the last live credential
// cannot be removed (STATE/invalid_state, reason last_credential; the center has no recovery path yet). The removal moves the
// authentication epoch of the account's live sessions, so step-up evidence proved before it is spent. It returns the credential's
// new revision.
func (s *Service) RemoveCredential(ctx context.Context, tx pgx.Tx, caller Caller, credentialID platform.ID, now time.Time) (int64, error) {
	var state int16
	if err := tx.QueryRow(ctx, "SELECT state FROM identity.user WHERE user_id = $1 FOR UPDATE", caller.UserID).Scan(&state); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return 0, arc.NotFound("account", caller.UserID[:])
		}
		return 0, err
	}
	rows, err := tx.Query(ctx, "SELECT auth_identity_id FROM identity.auth_identity WHERE user_id = $1 AND revoked_at IS NULL", caller.UserID)
	if err != nil {
		return 0, err
	}
	var live []string
	for rows.Next() {
		var id platform.ID
		if err = rows.Scan(&id); err != nil {
			rows.Close()
			return 0, err
		}
		live = append(live, id.String())
	}
	rows.Close()
	if err = rows.Err(); err != nil {
		return 0, err
	}
	if err = CheckRemoval(UserState(state), live, credentialID.String()); err != nil {
		if errors.Is(err, ErrNotFound) {
			return 0, arc.NotFound("credential", credentialID[:])
		}
		return 0, err
	}
	var revision int64
	var method int16
	if err = tx.QueryRow(ctx, "UPDATE identity.auth_identity SET revoked_at = $2, rev = rev + 1 WHERE auth_identity_id = $1 RETURNING rev, method",
		credentialID, now).Scan(&revision, &method); err != nil {
		return 0, err
	}
	epochs, err := tx.Exec(ctx, "UPDATE identity.session SET auth_epoch = auth_epoch + 1, rev = rev + 1 WHERE user_id = $1 AND revoked_at IS NULL", caller.UserID)
	if err != nil {
		return 0, err
	}
	return revision, s.audit(ctx, tx, caller.Request, Actor(caller.UserID), "identity.credential.removed", "", "credential", credentialID.String(),
		map[string]any{"kind": Method(method).Kind(), "sessions": epochs.RowsAffected()})
}

// RevokeSession revokes one live account session of the caller's account in the receipt's transaction (RevokeSession): the caller's
// own session is a sign-out, any other was revoked by the account. A node, push or automation session, another account's, a revoked
// or expired one are STATE/not_found. It returns the session's new revision.
func (s *Service) RevokeSession(ctx context.Context, tx pgx.Tx, caller Caller, sessionID platform.ID, now time.Time) (int64, error) {
	reason, own := session.RevokedByAccount, sessionID == caller.SessionID
	if own {
		reason = session.RevokedSignedOut
	}
	revision, err := session.RevokeOne(ctx, tx, caller.UserID, sessionID, reason, now)
	if err != nil {
		return 0, err
	}
	return revision, s.audit(ctx, tx, caller.Request, Actor(caller.UserID), "identity.session.revoked", "", "session", sessionID.String(),
		map[string]any{"own": own})
}

// RevokeAllSessions revokes every live account session of the caller's account except its own in the receipt's transaction
// (RevokeAllSessions); node, push and automation sessions stay (DC-03). It returns how many it revoked.
func (s *Service) RevokeAllSessions(ctx context.Context, tx pgx.Tx, caller Caller, now time.Time) (int64, error) {
	count, err := session.RevokeAll(ctx, tx, caller.UserID, caller.SessionID, now)
	if err != nil {
		return 0, err
	}
	return count, s.audit(ctx, tx, caller.Request, Actor(caller.UserID), "identity.sessions.revoked_all", "", "account", caller.UserID.String(),
		map[string]any{"sessions": count})
}

// RenameDevice renames one of the caller's live devices in the receipt's transaction (DeviceService.Rename), by the label rule.
func (s *Service) RenameDevice(ctx context.Context, tx pgx.Tx, caller Caller, deviceID platform.ID, name *string, expected *int64, now time.Time) (*device.View, error) {
	// A device name follows the credential label rule: required, at most 64 UTF-16 units (rule length), plain text that is not only
	// white space (rule pattern).
	if refusal := labelRefusal("name", name); refusal != nil {
		return nil, refusal
	}
	view, err := device.Rename(ctx, tx, caller.UserID, deviceID, *name, expected, now)
	if err != nil {
		return nil, err
	}
	return view, s.audit(ctx, tx, caller.Request, Actor(caller.UserID), "device.renamed", "", "device", deviceID.String(), map[string]any{})
}

// RevokeDevice revokes one of the caller's live devices and everything bound to it in the receipt's transaction
// (DeviceService.Revoke; DC-17): its installations, every session on it whatever its scope and each registered participant's rows,
// counted in the device.revoked audit event. It returns the device's new revision.
func (s *Service) RevokeDevice(ctx context.Context, tx pgx.Tx, caller Caller, deviceID platform.ID, now time.Time) (int64, error) {
	cascade, err := device.Revoke(ctx, tx, caller.UserID, deviceID, device.RevokedByOwner, s.participants, now)
	if err != nil {
		return 0, err
	}
	return cascade.Revision, s.audit(ctx, tx, caller.Request, Actor(caller.UserID), "device.revoked", "", "device", deviceID.String(),
		map[string]any{"own": deviceID == caller.DeviceID, "installations": cascade.Installations, "sessions": cascade.Sessions,
			"participants": cascade.Participants})
}

// labelRefusal checks a credential label at a field: required, at most 64 characters (a longer one, which the contract allows up to
// 256, is refused with rule length), plain text that is not only white space.
func labelRefusal(field string, label *string) *arc.Refusal {
	switch {
	case label == nil:
		return arc.InvalidArgument(field, "required")
	case UTF16Units(*label) > LabelMaxUnits:
		return arc.InvalidArgument(field, "length")
	case !ValidLabel(label):
		return arc.InvalidArgument(field, "pattern")
	}
	return nil
}

// BeginRegistration starts the registration of a new passkey for the caller's account (BeginPasskeyRegistration): the display name
// becomes the credential's label (the credential label rule: at most 64 characters), the account must be active, and the step-up
// evidence of the class identity.beginPasskeyRegistration for the account is consumed in the transaction that creates the flow. The
// flow is bound to the caller's account and session and to its channel (a cookie session's flow to the browser channel and the
// relying party's origin); the creation options exclude the account's passkeys. There is no receipt: a lost reply is a new begin.
func (s *Service) BeginRegistration(ctx context.Context, caller Caller, label *string) (Challenge, error) {
	if refusal := labelRefusal("display_name", label); refusal != nil {
		return Challenge{}, refusal
	}
	now := s.now()
	userID, sessionID := caller.UserID, caller.SessionID
	row := flow{ID: platform.NewID(), Channel: ChannelNative, Kind: FlowPasskeyRegistration, Purpose: PurposeEnroll, UserID: &userID,
		SessionID: &sessionID, Label: label, Challenge: randomBytes(passkey.ChallengeBytes), MaxAttempts: passkeyAttempts, CreatedAt: now,
		ExpiresAt: now.Add(s.policy.PasskeyFlowLifetime)}
	if caller.Browser {
		origin := s.rp.Origin()
		row.Channel, row.Origin = ChannelBrowser, &origin
	}
	result := Challenge{FlowID: row.ID, Method: MethodValuePasskey, Purpose: PurposeEnroll, Challenge: row.Challenge, ExpiresAt: row.ExpiresAt,
		ProviderID: "passkey"}
	err := s.db.InTx(ctx, "begin a passkey registration", store.TxOptions{}, func(ctx context.Context, tx pgx.Tx) error {
		var state int16
		var handle []byte
		// FOR UPDATE, the lock ConsumeEvidence takes next: two concurrent begins never upgrade a shared lock (B3).
		if err := tx.QueryRow(ctx, "SELECT state, passkey_user_handle FROM identity.user WHERE user_id = $1 FOR UPDATE", userID).Scan(&state, &handle); err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				return arc.NotFound("account", userID[:])
			}
			return err
		}
		if !UserState(state).MayAddCredential() {
			return ErrNotPermitted
		}
		if err := ConsumeEvidence(ctx, tx, caller, ClassBeginRegistration, userID, now); err != nil {
			return err
		}
		passkeys, _, err := accountMethods(ctx, tx, userID)
		if err != nil {
			return err
		}
		row.UserHandle = handle
		options := s.rp.CreationOptions(handle, passkeys)
		result.Options = &options
		return s.insertFlow(ctx, tx, row)
	})
	if err != nil {
		return Challenge{}, err
	}
	s.events.ObserveIdentity("registration_begin", "passkey")
	return result, nil
}

// Registration is a verified passkey registration of the caller's flow, ready for FinishRegistration in its receipt's transaction.
type Registration struct {
	flow       flow
	credential passkey.Credential
}

// RunningGrace is how long past a registration flow's expiry its attempt still counts as held by a running completion (A-1): the
// completion took its attempt before the expiry (the library refuses a ceremony after it), and its success transaction is bounded by
// store.DefaultTimeout, with a margin for the work between the attempt and that transaction. A duplicate that arrives in this
// window is told the store is busy and replays the receipt on its retry; after it the commit is settled or will never come, and the
// flow is expired.
const RunningGrace = store.DefaultTimeout + 5*time.Second

// takeRegistrationAttempt counts the attempt of a registration flow of the caller's account, session and channel in its own
// auxiliary transaction, before the creation is verified; a flow of another account or session is STATE/not_found.
func (s *Service) takeRegistrationAttempt(ctx context.Context, id platform.ID, caller Caller, channel Channel) (flow, error) {
	now := s.now()
	var item flow
	err := s.db.InTx(ctx, "count a registration attempt", store.TxOptions{Timeout: 5 * time.Second, Auxiliary: true}, func(ctx context.Context, tx pgx.Tx) error {
		var err error
		item, err = scanFlow(tx.QueryRow(ctx, `UPDATE identity.auth_flow SET attempts = attempts + 1
WHERE flow_id = $1 AND channel = $2 AND kind = $3 AND purpose = $4 AND user_id = $5 AND session_id = $6 AND consumed_at IS NULL AND expires_at > $7
    AND attempts < max_attempts
RETURNING `+flowColumns, id, int16(channel), int16(FlowPasskeyRegistration), int16(PurposeEnroll), caller.UserID, caller.SessionID, now))
		if !errors.Is(err, pgx.ErrNoRows) {
			return err
		}
		var owner, boundSession *platform.ID
		lookup := tx.QueryRow(ctx, "SELECT user_id, session_id FROM identity.auth_flow WHERE flow_id = $1", id).Scan(&owner, &boundSession)
		if errors.Is(lookup, pgx.ErrNoRows) || lookup == nil && (owner == nil || *owner != caller.UserID || boundSession == nil || *boundSession != caller.SessionID) {
			return arc.NotFound("auth_flow", id[:])
		}
		if lookup != nil {
			return lookup
		}
		// B4: a flow of this caller whose only attempt is taken but which has no outcome is held by a completion that is still
		// running (a duplicate of the same command, say): the duplicate is answered as a busy store, so it retries and then replays
		// that completion's receipt, rather than a final code_reused although the command succeeds. The completion is running past
		// the flow's expiry too: it took its attempt before the expiry and its success transaction is bounded by RunningGrace, so
		// the check holds until the expiry plus RunningGrace (A-1); an expired flow answered STATE/expired (final, DID_NOT_HAPPEN)
		// to a duplicate whose command then committed. An attempt that is never settled answers RESOURCE/overloaded until the
		// flow's expiry plus RunningGrace, then STATE/expired: the process stopped before the attempt was settled, or the store
		// failed when the attempt was to be given back or the flow ended (exhaust, after not_verified or from AbandonRegistration).
		var running bool
		if err := tx.QueryRow(ctx, `SELECT count(*) = 1 FROM identity.auth_flow WHERE flow_id = $1 AND channel = $2 AND kind = $3 AND purpose = $4
    AND consumed_at IS NULL AND outcome IS NULL AND expires_at > $5 AND attempts >= max_attempts`, id, int16(channel), int16(FlowPasskeyRegistration),
			int16(PurposeEnroll), now.Add(-RunningGrace)).Scan(&running); err != nil {
			return err
		}
		if running {
			return arc.Unavailable()
		}
		return classify(ctx, tx, id, channel, []FlowKind{FlowPasskeyRegistration}, PurposeEnroll, now)
	})
	return item, err
}

// PrepareRegistration counts the attempt of the caller's registration flow and verifies its creation outside any transaction
// (CompletePasskeyRegistration, before its receipt): attestation "none" only, read before the library parses it (G3). A creation that
// does not verify ends the flow and is VALIDATION/invalid_argument (credential: not_verified).
func (s *Service) PrepareRegistration(ctx context.Context, caller Caller, flowID platform.ID, creation passkey.Creation) (Registration, error) {
	if refusal := validCreation("credential", creation); refusal != nil {
		return Registration{}, refusal
	}
	channel := ChannelNative
	if caller.Browser {
		channel = ChannelBrowser
	}
	row, err := s.takeRegistrationAttempt(ctx, flowID, caller, channel)
	if err != nil {
		return Registration{}, err
	}
	credential, err := s.rp.VerifyCreation(row.Challenge, row.UserHandle, creation, row.ExpiresAt)
	if err != nil {
		if err = s.exhaust(ctx, row.ID); err != nil {
			return Registration{}, err
		}
		s.events.ObserveIdentity("registration_complete", "refused")
		return Registration{}, arc.InvalidArgument("credential", "not_verified")
	}
	return Registration{flow: row, credential: credential}, nil
}

// FinishRegistration stores a verified registration in its receipt's transaction: the flow is consumed (a flow consumed meanwhile is
// CONFLICT/code_reused), the account must still be active, and the credential is inserted with the flow's label; a credential ID
// that is already registered (to this account or another, revoked ones included) is CONFLICT/already_exists. It returns the new
// credential as ListAuthIdentities shows it.
func (s *Service) FinishRegistration(ctx context.Context, tx pgx.Tx, caller Caller, registration Registration, now time.Time) (Credential, error) {
	row, credential := registration.flow, registration.credential
	if err := consume(ctx, tx, row.ID, now); err != nil {
		return Credential{}, err
	}
	var state int16
	if err := tx.QueryRow(ctx, "SELECT state FROM identity.user WHERE user_id = $1 FOR SHARE", caller.UserID).Scan(&state); err != nil {
		return Credential{}, err
	}
	if !UserState(state).MayAddCredential() {
		return Credential{}, ErrNotPermitted
	}
	identityID := platform.NewID()
	tag, err := tx.Exec(ctx, `INSERT INTO identity.auth_identity (auth_identity_id, user_id, method, provider_id, subject, label, public_key, user_handle,
    sign_count, backup_eligible, backup_state, transports, aaguid, attestation_format, created_at, rev)
VALUES ($1, $2, 1, 'passkey', $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, 1) ON CONFLICT (provider_id, subject) DO NOTHING`, identityID, caller.UserID,
		base64.RawURLEncoding.EncodeToString(credential.ID), row.Label, credential.PublicKey, row.UserHandle, int64(credential.SignCount),
		credential.BackupEligible, credential.BackupState, credential.Transports, credential.AAGUID, credential.AttestationFormat, now)
	if err != nil {
		return Credential{}, err
	}
	if tag.RowsAffected() != 1 {
		// The credential ID is registered already. Only the caller's own live credential is named by its ID (B6): another account's
		// is never revealed.
		var own platform.ID
		err := tx.QueryRow(ctx, `SELECT auth_identity_id FROM identity.auth_identity
WHERE provider_id = 'passkey' AND subject = $1 AND user_id = $2 AND revoked_at IS NULL`, base64.RawURLEncoding.EncodeToString(credential.ID),
			caller.UserID).Scan(&own)
		switch {
		case errors.Is(err, pgx.ErrNoRows):
			return Credential{}, arc.AlreadyExists("credential", nil)
		case err != nil:
			return Credential{}, err
		}
		return Credential{}, arc.AlreadyExists("credential", own[:])
	}
	item, err := readCredential(ctx, tx, identityID)
	if err != nil {
		return Credential{}, err
	}
	s.events.ObserveIdentity("registration_complete", "succeeded")
	return item, s.audit(ctx, tx, caller.Request, Actor(caller.UserID), "identity.passkey.registered", "", "credential", identityID.String(),
		map[string]any{"channel": channelName(row.Channel)})
}

// AbandonRegistration settles a prepared registration that did not commit its credential: a refusal (refused) ends the flow; a
// store failure gives its attempt back (F9), so the advised retry of the same command can succeed.
func (s *Service) AbandonRegistration(ctx context.Context, registration Registration, refused bool) {
	if !refused {
		s.release(ctx, registration.flow.ID)
		return
	}
	_ = s.exhaust(ctx, registration.flow.ID)
}

func channelName(channel Channel) string {
	if channel == ChannelBrowser {
		return "browser"
	}
	return "native"
}
