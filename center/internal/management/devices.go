// SPDX-License-Identifier: AGPL-3.0-only

package management

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"strings"
	"time"

	"github.com/ArcForges/Cloud/center/internal/arc"
	"github.com/ArcForges/Cloud/center/internal/page"
	"github.com/ArcForges/Cloud/center/internal/platform"
	"github.com/ArcForges/Cloud/center/internal/store"
	"github.com/jackc/pgx/v5"
)

// DeviceRecord is one account-scoped device with a V2 enrollment.
// Channel capabilities are intentionally absent from persistent registry reads.
type DeviceRecord struct {
	Device, Enrollment, Node, ProtocolEpoch platform.ID
	Connection                              *platform.ID
	Name                                    string
	OS                                      int16
	Revision                                int64
	EnrolledAt, LastSeenAt                  time.Time
	DeviceRevoked, EnrollmentRevoked        bool
}

const deviceListing page.Listing = 5

const deviceRecords = `SELECT d.device_id,p.enrollment_id,p.node_id,p.protocol_epoch,n.connection_id,n.display_name,
 n.os,d.rev,n.enrolled_at,greatest(n.last_seen_at,n.last_heartbeat_at),
 d.revoked_at IS NOT NULL,n.revoked_at IS NOT NULL OR p.revoked_at IS NOT NULL
 FROM device.device d
 JOIN fleet.node n ON (n.device_id,n.user_id)=(d.device_id,d.user_id)
 JOIN management.node_protocol p ON (p.enrollment_id,p.node_id,p.account_id)=(n.enrollment_id,n.node_id,n.user_id)
 WHERE d.user_id=$1`

func scanDevice(row interface{ Scan(...any) error }) (record DeviceRecord, err error) {
	err = row.Scan(&record.Device, &record.Enrollment, &record.Node, &record.ProtocolEpoch, &record.Connection, &record.Name,
		&record.OS, &record.Revision, &record.EnrolledAt, &record.LastSeenAt, &record.DeviceRevoked, &record.EnrollmentRevoked)
	return
}

// deviceCursorScope is only a position namespace. The account predicate still
// authorizes every row independently of any bytes in a cursor.
func deviceCursorScope(account platform.ID) string {
	digest := sha256.Sum256(account[:])
	return base64.RawURLEncoding.EncodeToString(digest[:16]) + "."
}

func devicePageRequest(account platform.ID, cursor string, limit *uint32) (page.Request, error) {
	if cursor != "" {
		var ok bool
		cursor, ok = strings.CutPrefix(cursor, deviceCursorScope(account))
		if !ok || cursor == "" {
			return page.Request{}, arc.InvalidCursor()
		}
	}
	request, refusal := page.Parse(deviceListing, cursor, 0, false)
	if refusal != nil {
		return page.Request{}, refusal
	}
	if limit != nil {
		if *limit < 1 || *limit > 200 {
			return page.Request{}, arc.InvalidArgument("limit", "range")
		}
		request.Limit = int(*limit)
	}
	return request, nil
}

// ListDevices returns stable, account-scoped keyset pages of V2 enrollments.
func (s *Store) ListDevices(ctx context.Context, account platform.ID, cursor string, limit *uint32) (records []DeviceRecord, next string, err error) {
	request, err := devicePageRequest(account, cursor, limit)
	if err != nil {
		return nil, "", err
	}
	var afterAt any
	var afterID any
	if request.After != nil {
		afterAt, afterID = request.After.At, platform.ID(request.After.ID)
	}
	err = s.db.InTx(ctx, "list V2 devices", store.TxOptions{ReadOnly: true}, func(ctx context.Context, tx pgx.Tx) error {
		records = nil
		rows, e := tx.Query(ctx, deviceRecords+`
 AND ($2::timestamptz IS NULL OR (n.enrolled_at,d.device_id)<($2,$3::uuid))
 ORDER BY n.enrolled_at DESC,d.device_id DESC LIMIT $4`, account, afterAt, afterID, request.Limit+1)
		if e != nil {
			return e
		}
		defer rows.Close()
		for rows.Next() {
			record, e := scanDevice(rows)
			if e != nil {
				return e
			}
			records = append(records, record)
		}
		return rows.Err()
	})
	if err != nil {
		return nil, "", err
	}
	if len(records) > request.Limit {
		records = records[:request.Limit]
		last := records[len(records)-1]
		next = deviceCursorScope(account) + page.Encode(deviceListing, page.Cursor{At: last.EnrolledAt, ID: last.Device})
	}
	return records, next, nil
}

// InspectDevice reads a current or revoked V2 device owned by account.
func (s *Store) InspectDevice(ctx context.Context, account, id platform.ID) (record DeviceRecord, err error) {
	err = s.db.InTx(ctx, "inspect V2 device", store.TxOptions{ReadOnly: true}, func(ctx context.Context, tx pgx.Tx) error {
		var e error
		record, e = readDevice(ctx, tx, account, id, "")
		return e
	})
	return
}

// LockDeviceForRevoke compares the expected revision while locking its exact
// device row in the receipt transaction. The caller has locked the account.
func LockDeviceForRevoke(ctx context.Context, tx pgx.Tx, account, id platform.ID, expected int64) (DeviceRecord, error) {
	record, err := readDevice(ctx, tx, account, id, " FOR UPDATE OF d")
	if err != nil {
		return DeviceRecord{}, err
	}
	// A backup restore can retire the protocol while the device is still
	// enrolled. It needs the ordinary device cascade before replacement.
	if record.DeviceRevoked {
		return DeviceRecord{}, arc.NotFound("device", id[:])
	}
	if record.Revision != expected {
		return DeviceRecord{}, arc.RevisionConflict(expected, record.Revision)
	}
	return record, nil
}

func readDevice(ctx context.Context, tx pgx.Tx, account, id platform.ID, lock string) (DeviceRecord, error) {
	record, err := scanDevice(tx.QueryRow(ctx, deviceRecords+" AND d.device_id=$2"+lock, account, id))
	if errors.Is(err, pgx.ErrNoRows) {
		return DeviceRecord{}, arc.NotFound("device", id[:])
	}
	return record, err
}
