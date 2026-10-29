// SPDX-License-Identifier: AGPL-3.0-only

package session

import (
	"context"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/ArcForges/Cloud/center/internal/page"
	"github.com/ArcForges/Cloud/center/internal/platform"
	"github.com/ArcForges/Cloud/center/internal/store"
)

// Summary is one listed session (the contract's SessionSummary).
type Summary struct {
	SessionID  platform.ID
	DeviceID   platform.ID
	Product    string
	IssuedAt   time.Time
	LastUsedAt time.Time
	ExpiresAt  time.Time
	Current    bool
	Revision   int64
}

// List is one page of an account's live account sessions (account and mobile.limited; DC-03), newest first: not revoked, within
// their absolute expiry and their sliding one (a browser session's idle expiry, a native session's refresh expiry). Node, push and
// automation sessions are never listed here.
func List(ctx context.Context, db *store.DB, userID platform.ID, current string, request page.Request, now time.Time) ([]Summary, string, error) {
	var items []Summary
	next := ""
	err := db.InTx(ctx, "list sessions", store.TxOptions{ReadOnly: true}, func(ctx context.Context, tx pgx.Tx) error {
		items, next = nil, ""
		after, afterID := now.Add(100*365*24*time.Hour), platform.ID{0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff}
		if request.After != nil {
			after, afterID = request.After.At, request.After.ID
		}
		rows, err := tx.Query(ctx, `SELECT session_id, device_id, product_id, issued_at, last_activity_at, expires_at, rev
FROM identity.session
WHERE user_id = $1 AND scope IN (1, 2) AND revoked_at IS NULL AND expires_at > $2 AND (idle_expires_at IS NULL OR idle_expires_at > $2)
    AND (refresh_expires_at IS NULL OR refresh_expires_at > $2) AND (issued_at, session_id) < ($3, $4)
ORDER BY issued_at DESC, session_id DESC
LIMIT $5`, userID, now, after, afterID, request.Limit+1)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var item Summary
			if err = rows.Scan(&item.SessionID, &item.DeviceID, &item.Product, &item.IssuedAt, &item.LastUsedAt, &item.ExpiresAt, &item.Revision); err != nil {
				return err
			}
			item.Current = item.SessionID.String() == current
			items = append(items, item)
		}
		if err = rows.Err(); err != nil {
			return err
		}
		if len(items) > request.Limit {
			items = items[:request.Limit]
			last := items[len(items)-1]
			next = page.Encode(page.Sessions, page.Cursor{At: last.IssuedAt, ID: last.SessionID})
		}
		return nil
	})
	if err != nil {
		return nil, "", store.Sanitize("list sessions", err)
	}
	return items, next, nil
}
