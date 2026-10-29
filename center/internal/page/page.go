// SPDX-License-Identifier: AGPL-3.0-only

// Package page is the paging of the center's listings (foundation PageRequest and PageState): a bounded page size and an opaque
// keyset cursor that names the listing it belongs to, the sort instant and the identifier of the last item returned. A cursor is
// not a credential: it only positions a listing of the caller's own rows, so one from another account pages through the caller's
// rows from that position.
package page

import (
	"encoding/base64"
	"encoding/binary"
	"time"

	"github.com/ArcForges/Cloud/center/internal/arc"
)

// The page size bounds: the contract's minimum is 1, and a value list holds at most 200 items; the center serves at most 100.
const (
	DefaultLimit = 50
	MaxLimit     = 100
)

// Listing names the listing a cursor belongs to.
type Listing byte

// The listings.
const (
	Sessions    Listing = 1
	Credentials Listing = 2
	Devices     Listing = 3
)

const cursorVersion = 1

// The instants a cursor may carry: the contract Timestamp range, 0001-01-01T00:00:00Z to 9999-12-31T23:59:59.999999Z, in
// microseconds since the Unix epoch. PostgreSQL holds all of it, and every cursor the center issues carries an instant of a row it
// wrote.
const (
	minInstant int64 = -62135596800000000
	maxInstant int64 = 253402300799999999
)

// cursorBytes is the version, the listing, the instant in microseconds and a 16-byte identifier.
const cursorBytes = 1 + 1 + 8 + 16

// Cursor is a position in a listing: the sort instant and the identifier of the last item returned.
type Cursor struct {
	At time.Time
	ID [16]byte
}

// Request is a validated page request.
type Request struct {
	Limit int
	// After is the position to continue after, or nil for the first page.
	After *Cursor
}

// Parse validates a page request: a limit below 1 is VALIDATION/invalid_argument, a limit above the maximum is clamped, and a
// malformed cursor, one of another listing or one whose instant is outside the contract's range is VALIDATION/invalid_cursor.
func Parse(listing Listing, cursor string, limit int32, hasLimit bool) (Request, *arc.Refusal) {
	request := Request{Limit: DefaultLimit}
	if hasLimit {
		if limit < 1 {
			return Request{}, arc.InvalidArgument("page.limit", "min")
		}
		request.Limit = min(int(limit), MaxLimit)
	}
	if cursor == "" {
		return request, nil
	}
	data, err := base64.RawURLEncoding.DecodeString(cursor)
	if err != nil || len(data) != cursorBytes || data[0] != cursorVersion || Listing(data[1]) != listing ||
		base64.RawURLEncoding.EncodeToString(data) != cursor {
		return Request{}, arc.InvalidCursor()
	}
	instant := int64(binary.BigEndian.Uint64(data[2:10]))
	if instant < minInstant || instant > maxInstant {
		return Request{}, arc.InvalidCursor()
	}
	position := &Cursor{At: time.UnixMicro(instant).UTC()}
	copy(position.ID[:], data[10:])
	request.After = position
	return request, nil
}

// Encode is the opaque cursor after a position.
func Encode(listing Listing, position Cursor) string {
	data := make([]byte, cursorBytes)
	data[0], data[1] = cursorVersion, byte(listing)
	binary.BigEndian.PutUint64(data[2:10], uint64(position.At.UTC().UnixMicro()))
	copy(data[10:], position.ID[:])
	return base64.RawURLEncoding.EncodeToString(data)
}
