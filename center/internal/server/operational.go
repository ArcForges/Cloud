// SPDX-License-Identifier: AGPL-3.0-only

package server

import (
	"context"
	"sync"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/ArcForges/Cloud/center/internal/management"
	"github.com/ArcForges/Cloud/center/internal/observe"
	"github.com/ArcForges/Cloud/center/internal/store"
)

const (
	pulseInterval = 10 * time.Second
	pulseTimeout  = 500 * time.Millisecond
	pulseRowLimit = 512
	remoteUnknown = `SELECT count(*), min(updated_at) FROM (
		SELECT updated_at FROM management.remote_operation
		WHERE state = $2 AND final_at IS NULL ORDER BY updated_at LIMIT $1
	) AS pending`
	// The existing provider-event work index leads with (state, next_check_at).
	// The sample counts only due work. Future retries and manual holds do not
	// represent work that the provider worker can process at this instant.
	billingDue = `SELECT count(*), min(received_at) FROM (
		SELECT received_at FROM commerce.provider_event
		WHERE state IN (1, 3) AND next_check_at IS NOT NULL AND next_check_at <= $2
		ORDER BY state, next_check_at LIMIT $1
	) AS pending`
	billingReview = `SELECT count(*), min(received_at) FROM (
		SELECT received_at FROM commerce.provider_event
		WHERE state = 3 AND next_check_at IS NULL LIMIT $1
	) AS pending`
)

type pulseSampler struct {
	mu      sync.Mutex
	next    time.Time
	storage observe.OperationalPulse
}

func (c *Center) operationalPulse(ctx context.Context) observe.OperationalPulse {
	result := c.sampleStoragePulse(ctx)
	c.Metrics.ReadManagementWatch(&result)
	if s := c.httpSlots; s != nil {
		result.HTTPRequests = observe.Capacity{Active: s.requestOpen.Load(), Limit: int64(cap(s.requests))}
		result.HTTPNodes = observe.Capacity{Active: s.nodeOpen.Load(), Limit: int64(cap(s.nodes))}
	}
	if s := c.grpcSlots; s != nil {
		result.GRPCRequests = observe.Capacity{Active: s.requestOpen.Load(), Limit: int64(cap(s.requests))}
		result.GRPCNodes = observe.Capacity{Active: s.nodeOpen.Load(), Limit: int64(cap(s.nodes))}
	}
	return result
}

// Admin scrapes and periodic hosted pulse logs share one bounded database
// sample. Every queue and readiness check has its own short deadline so a
// problem with one optional signal does not negate the others.
func (c *Center) sampleStoragePulse(ctx context.Context) observe.OperationalPulse {
	p := &c.pulse
	p.mu.Lock()
	defer p.mu.Unlock()
	now := time.Now()
	if now.Before(p.next) {
		return p.storage
	}
	result := observe.OperationalPulse{
		RuntimeDatabase: observe.SourceDisabled,
		SchemaAdmission: observe.SourceDisabled,
		RemoteUnknown:   observe.QueuePulse{State: observe.SourceDisabled},
		BillingDue:      observe.QueuePulse{State: observe.SourceDisabled},
		BillingReview:   observe.QueuePulse{State: observe.SourceDisabled},
	}
	if c.Store != nil {
		result.RuntimeDatabase = c.pulseCheck(ctx, "database")
		result.SchemaAdmission = observe.SourceUnavailable
		result.RemoteUnknown.State = observe.SourceUnavailable
		if c.commerce != nil {
			result.BillingDue.State = observe.SourceUnavailable
			result.BillingReview.State = observe.SourceUnavailable
		}
		if result.RuntimeDatabase == observe.SourceReady {
			result.SchemaAdmission = c.pulseCheck(ctx, "databaseSchema")
		}
		if result.SchemaAdmission == observe.SourceReady {
			result.RemoteUnknown = c.pendingPulse(ctx, now, remoteUnknown, management.StateUnknown)
			// A running commerce surface has already checked its immutable
			// single provider realm. This query need not read configuration,
			// customer identities, or notification payloads.
			if c.commerce != nil {
				result.BillingDue = c.pendingPulse(ctx, now, billingDue, now)
				result.BillingReview = c.pendingPulse(ctx, now, billingReview)
			}
		}
	}
	if ctx.Err() == nil {
		p.next = time.Now().Add(pulseInterval)
		p.storage = result
	}
	return result
}

func (c *Center) pulseCheck(ctx context.Context, name string) observe.SourceState {
	for _, item := range c.ready {
		if item.name == name {
			check, cancel := context.WithTimeout(ctx, pulseTimeout)
			err := item.check(check)
			cancel()
			if err == nil {
				return observe.SourceReady
			}
			break
		}
	}
	return observe.SourceUnavailable
}

func (c *Center) pendingPulse(ctx context.Context, now time.Time, query string, args ...any) observe.QueuePulse {
	var count int
	var oldest *time.Time
	err := c.Store.InTx(ctx, "sample operational pending records", store.TxOptions{ReadOnly: true, Timeout: pulseTimeout, Attempts: 1},
		func(ctx context.Context, tx pgx.Tx) error {
			if _, err := tx.Exec(ctx, "SET LOCAL statement_timeout = '400ms'"); err != nil {
				return err
			}
			return tx.QueryRow(ctx, query, append([]any{pulseRowLimit + 1}, args...)...).Scan(&count, &oldest)
		})
	if err != nil {
		return observe.QueuePulse{State: observe.SourceUnavailable}
	}
	result := observe.QueuePulse{State: observe.SourceReady, Count: min(count, pulseRowLimit), Truncated: count > pulseRowLimit}
	if oldest != nil {
		result.OldestSeconds = max(0, int64(now.Sub(*oldest)/time.Second))
	}
	return result
}
