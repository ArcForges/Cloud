// SPDX-License-Identifier: AGPL-3.0-only

package migrate

import (
	"context"
	"errors"
	"strings"
)

// This database comment is a refusal-only isolation marker. It cannot admit,
// resume or finalize a restore. Only the same invocation's private capability
// and the 0011 admission transaction can authorize the READY transition.
const ctr06RestoreIsolationPrefix = "arcforges-ctr06-restore-quarantine-"
const ctr06RestoreIsolationMarker = ctr06RestoreIsolationPrefix + "v1"

func ctr06DatabaseIsolation(ctx context.Context, q Querier, name string) (bool, string, error) {
	var allowed bool
	var comment string
	err := q.QueryRow(ctx, `SELECT d.datallowconn,coalesce(pg_catalog.shobj_description(d.oid,'pg_database'),'')
 FROM pg_database d WHERE d.datname=$1`, name).Scan(&allowed, &comment)
	if err != nil {
		return false, "", errors.New("the database isolation state is unavailable")
	}
	return allowed, comment, nil
}

// RequireOrdinaryDatabase is also used from a maintenance connection before
// EnsureDatabase accepts an existing target. Disabled databases and every
// reserved quarantine marker, including malformed successors, are refused.
func RequireOrdinaryDatabase(ctx context.Context, q Querier, name string) error {
	allowed, comment, err := ctr06DatabaseIsolation(ctx, q, name)
	if err != nil || !allowed || strings.HasPrefix(comment, ctr06RestoreIsolationPrefix) {
		return ErrCTR06RetirementUnproven
	}
	return nil
}

func requireCTR06RestoreIsolation(ctx context.Context, q Querier) error {
	var name string
	if err := q.QueryRow(ctx, "SELECT current_database()").Scan(&name); err != nil {
		return ErrCTR06RetirementUnproven
	}
	allowed, comment, err := ctr06DatabaseIsolation(ctx, q, name)
	if err != nil || !allowed || comment != ctr06RestoreIsolationMarker {
		return ErrCTR06RetirementUnproven
	}
	return nil
}
