// SPDX-License-Identifier: AGPL-3.0-only

package device

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"
	"unicode"
	"unicode/utf16"
	"unicode/utf8"

	"github.com/jackc/pgx/v5"

	"github.com/ArcForges/Cloud/center/internal/arc"
	"github.com/ArcForges/Cloud/center/internal/platform"
	"github.com/ArcForges/Cloud/center/internal/session"
)

// The device revoke reasons (device.revoke_reason).
const (
	RevokedByOwner    int16 = 1
	RevokedByOperator int16 = 2
)

// trustRevoked is device.trust_level revoked, set only by the revocation cascade.
const trustRevoked = 3

// MaxNameUnits bounds a device name (device.device.display_name): 1 to 64 UTF-16 units of plain text, the credential label rule
// (con-07 bounds the name at 256 Unicode scalar values and the store at 64 code points; every admitted name meets both).
const MaxNameUnits = 64

// Participant is a part of the center that holds a credential or grant bound to a device and revokes it in the device revocation's
// own transaction (DC-06, DC-17): agent grants (AF-CTR-07) and push registrations (AF-CLD-06) register one; none exists in
// AF-CTR-03, and the tests register a stand-in. It returns how many of its rows it revoked.
type Participant interface {
	Name() string
	RevokeDevice(ctx context.Context, tx pgx.Tx, userID, deviceID platform.ID, now time.Time) (int64, error)
}

// Cascade counts what one device revocation revoked, for its audit event.
type Cascade struct {
	Revision      int64
	Installations int64
	// Sessions counts the revoked sessions per scope.
	Sessions map[string]int64
	// Participants counts each participant's revoked rows by its name.
	Participants map[string]int64
}

// Revoke revokes a live device of an account in the caller's transaction (DeviceService.Revoke; DC-17): the device is locked and
// marked revoked with trust level revoked (3) and remote control off, its installations are revoked, then every session bound to
// it whatever its scope (the account's, mobile.limited, node and push), then each participant's rows. The next call of any of
// those credentials is refused (auth.credential_revoked), and a refresh answers credential_revoked. A device of another account,
// a revoked one and an unknown one are all STATE/not_found with the device the caller named.
func Revoke(ctx context.Context, tx pgx.Tx, userID, deviceID platform.ID, reason int16, participants []Participant, now time.Time) (Cascade, error) {
	cascade := Cascade{Participants: map[string]int64{}}
	err := tx.QueryRow(ctx, `UPDATE device.device SET revoked_at = $3, revoke_reason = $4, trust_level = $5, remote_enabled = false, rev = rev + 1
WHERE device_id = $1 AND user_id = $2 AND revoked_at IS NULL RETURNING rev`, deviceID, userID, now, reason, trustRevoked).Scan(&cascade.Revision)
	if errors.Is(err, pgx.ErrNoRows) {
		return Cascade{}, arc.NotFound("device", deviceID[:])
	}
	if err != nil {
		return Cascade{}, err
	}
	tag, err := tx.Exec(ctx, "UPDATE device.installation SET revoked_at = $2, rev = rev + 1 WHERE device_id = $1 AND revoked_at IS NULL", deviceID, now)
	if err != nil {
		return Cascade{}, err
	}
	cascade.Installations = tag.RowsAffected()
	if cascade.Sessions, err = session.RevokeOnDevice(ctx, tx, deviceID, now); err != nil {
		return Cascade{}, err
	}
	for _, participant := range participants {
		count, err := participant.RevokeDevice(ctx, tx, userID, deviceID, now)
		if err != nil {
			return Cascade{}, fmt.Errorf("the device revocation of %s: %w", participant.Name(), err)
		}
		cascade.Participants[participant.Name()] = count
	}
	return cascade, nil
}

// nameUnits is a name's length in UTF-16 units.
func nameUnits(name string) int {
	units := 0
	for _, r := range name {
		units += utf16.RuneLen(r)
	}
	return units
}

// ValidName is a device name: plain text of 1 to 64 UTF-16 units without control characters that is not only white space.
func ValidName(name string) bool {
	if name == "" || !utf8.ValidString(name) || nameUnits(name) > MaxNameUnits || strings.TrimFunc(name, unicode.IsSpace) == "" {
		return false
	}
	for _, r := range name {
		if unicode.IsControl(r) || (r >= 0xD800 && r <= 0xDFFF) {
			return false
		}
	}
	return true
}

// Rename renames a live device of an account in the caller's transaction (DeviceService.Rename) and returns it. A stale
// meta.expected_rev (expected, when set) is CONFLICT/revision_conflict with the current revision; a device of another account, a
// revoked one and an unknown one are STATE/not_found with the device the caller named.
func Rename(ctx context.Context, tx pgx.Tx, userID, deviceID platform.ID, name string, expected *int64, now time.Time) (*View, error) {
	switch {
	case nameUnits(name) > MaxNameUnits:
		return nil, arc.InvalidArgument("name", "length")
	case !ValidName(name):
		return nil, arc.InvalidArgument("name", "pattern")
	}
	var current int64
	err := tx.QueryRow(ctx, "SELECT rev FROM device.device WHERE device_id = $1 AND user_id = $2 AND revoked_at IS NULL FOR UPDATE", deviceID, userID).
		Scan(&current)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, arc.NotFound("device", deviceID[:])
	}
	if err != nil {
		return nil, err
	}
	if expected != nil && *expected != current {
		return nil, arc.RevisionConflict(*expected, current)
	}
	if _, err = tx.Exec(ctx, "UPDATE device.device SET display_name = $3, last_seen_at = greatest(last_seen_at, $4), rev = rev + 1 WHERE device_id = $1 AND user_id = $2",
		deviceID, userID, name, now); err != nil {
		return nil, err
	}
	view, err := Get(ctx, tx, userID, deviceID)
	if err != nil {
		return nil, err
	}
	if view == nil {
		return nil, errors.New("the renamed device is not readable")
	}
	return view, nil
}
