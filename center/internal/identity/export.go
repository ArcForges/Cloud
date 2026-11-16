// SPDX-License-Identifier: AGPL-3.0-only

package identity

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/ArcForges/Cloud/center/internal/arc"
	"github.com/ArcForges/Cloud/center/internal/platform"
	"github.com/ArcForges/Cloud/center/internal/ratelimit"
	"github.com/ArcForges/Cloud/center/internal/store"
)

// Export bounds apply before any body is persisted or returned. A receipt stores
// only its opaque artifact ID, size and canonical digest, never the body.
const (
	MaxExportRows      = 256
	MaxExportBytes     = 2 * 1024 * 1024
	MaxExportPageBytes = 64 * 1024
)

type ExportPage struct {
	Lifecycle     Lifecycle
	Offset, Total int
	Data          []byte
	Done          bool
}

// All sections run in one PostgreSQL statement/snapshot. Every projection is an
// explicit public-data allowlist, ordered and limited independently. Authentication
// counters, tokens, keys, proofs and activity changed by this read are excluded.
const accountExportQuery = `
SELECT 'profile', jsonb_build_object('accountId',user_id,'displayName',display_name,'state',state,'locale',locale,'timezone',timezone,'createdAt',created_at)
FROM identity.user WHERE user_id=$1
UNION ALL SELECT 'credentials',coalesce(jsonb_agg(v ORDER BY v->>'id'),'[]'::jsonb) FROM
 (SELECT jsonb_build_object('id',auth_identity_id,'kind',method,'label',label,'email',CASE WHEN provider_id='email' THEN subject END,
 'createdAt',created_at,'revokedAt',revoked_at) v FROM identity.auth_identity WHERE user_id=$1 ORDER BY auth_identity_id LIMIT 257) q
UNION ALL SELECT 'devices',coalesce(jsonb_agg(v ORDER BY v->>'id'),'[]'::jsonb) FROM
 (SELECT jsonb_build_object('id',device_id,'name',display_name,'platform',platform,'trust',trust_level,'remoteEnabled',remote_enabled,
 'createdAt',first_seen_at,'revokedAt',revoked_at) v FROM device.device WHERE user_id=$1 ORDER BY device_id LIMIT 257) q
UNION ALL SELECT 'sessions',coalesce(jsonb_agg(v ORDER BY v->>'id'),'[]'::jsonb) FROM
 (SELECT jsonb_build_object('id',session_id,'deviceId',device_id,'scope',scope,'method',auth_method,'issuedAt',issued_at,
 'expiresAt',expires_at,'revokedAt',revoked_at) v FROM identity.session WHERE user_id=$1 ORDER BY session_id LIMIT 257) q
UNION ALL SELECT 'grants',coalesce(jsonb_agg(v ORDER BY v->>'id'),'[]'::jsonb) FROM
 (SELECT jsonb_build_object('id',grant_id,'kind',kind,'subject',subject,'value',value,'source',source,'sourceRef',source_ref,
 'effectiveFrom',effective_from,'effectiveUntil',effective_until,'createdAt',created_at) v FROM entitlement.grant WHERE account_id=$1 ORDER BY grant_id LIMIT 257) q
UNION ALL SELECT 'revocations',coalesce(jsonb_agg(v ORDER BY v->>'id'),'[]'::jsonb) FROM
 (SELECT jsonb_build_object('id',revocation_id,'grantId',grant_id,'effectiveFrom',effective_from,'createdAt',created_at) v
 FROM entitlement.revocation WHERE account_id=$1 ORDER BY revocation_id LIMIT 257) q
UNION ALL SELECT 'serviceTerms',coalesce(jsonb_agg(v ORDER BY v->>'id'),'[]'::jsonb) FROM
 (SELECT jsonb_build_object('id',term_id,'kind',kind,'subscriptionRef',subscription_ref,'periodRef',period_ref,'startsAt',starts_at,'endsAt',ends_at,
 'graceEndsAt',grace_ends_at,'authorizedAt',authorized_at,'createdAt',created_at) v FROM entitlement.service_term WHERE account_id=$1 ORDER BY term_id LIMIT 257) q
UNION ALL SELECT 'termActions',coalesce(jsonb_agg(v ORDER BY v->>'id'),'[]'::jsonb) FROM
 (SELECT jsonb_build_object('id',action_id,'termId',term_id,'kind',kind,'effectiveAt',effective_at,'recordedAt',recorded_at,'replacementTermId',replacement_term_id) v
 FROM entitlement.service_term_action WHERE account_id=$1 ORDER BY action_id LIMIT 257) q
UNION ALL SELECT 'billingStatus',coalesce(jsonb_agg(v ORDER BY v->>'id'),'[]'::jsonb) FROM
 (SELECT jsonb_build_object('id',status_fact_id,'recordedAt',recorded_at,'status',status,'autoRenew',auto_renew,'purchasePending',purchase_pending) v
 FROM entitlement.account_status_fact WHERE account_id=$1 ORDER BY status_fact_id LIMIT 257) q`

func canonicalAccountExport(ctx context.Context, tx pgx.Tx, userID platform.ID) ([]byte, error) {
	rows, err := tx.Query(ctx, accountExportQuery, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	document := map[string]any{"format": "arcforges.account-export.v1"}
	total := 0
	for rows.Next() {
		var name string
		var raw []byte
		if err = rows.Scan(&name, &raw); err != nil {
			return nil, err
		}
		total += len(raw)
		if total > MaxExportBytes {
			return nil, arc.InvalidState("account_export", "byte_limit")
		}
		var value any
		decoder := json.NewDecoder(bytes.NewReader(raw))
		decoder.UseNumber()
		if err = decoder.Decode(&value); err != nil {
			return nil, err
		}
		if items, ok := value.([]any); ok && len(items) > MaxExportRows {
			return nil, arc.InvalidState("account_export", "row_limit")
		}
		document[name] = value
	}
	if err = rows.Err(); err != nil {
		return nil, err
	}
	body, err := json.Marshal(document)
	if err == nil && len(body) > MaxExportBytes {
		return nil, arc.InvalidState("account_export", "byte_limit")
	}
	return body, err
}

// PrepareExport proves authority once, then retains the canonical snapshot's
// identity. It does not copy private account content into a command receipt.
func (s *Service) PrepareExport(ctx context.Context, tx pgx.Tx, caller Caller, commandID platform.ID, now time.Time) (Lifecycle, error) {
	security, err := lockLifecycleCaller(ctx, tx, caller, now, true)
	if err != nil {
		return Lifecycle{}, err
	}
	if security.State != int16(StateActive) && security.State != int16(StateRestricted) {
		return Lifecycle{}, arc.InvalidState("account", "pending_deletion")
	}
	proofID, err := consumeLifecycleEvidence(ctx, tx, caller, ClassExportAccount, caller.UserID, now)
	if err != nil {
		return Lifecycle{}, err
	}
	body, err := canonicalAccountExport(ctx, tx, caller.UserID)
	if err != nil {
		return Lifecycle{}, err
	}
	digest := sha256.Sum256(body)
	result := Lifecycle{ID: platform.NewID(), Kind: LifecycleExport, State: LifecycleCompleted, PlanRevision: 1, Revision: 1, ExpiresAt: now.Add(exportTTL), ExportBytes: int64(len(body))}
	intent := lifecycleIntent(result.Kind, caller.UserID, result.ID)
	_, err = tx.Exec(ctx, `INSERT INTO identity.lifecycle_operation(operation_id,user_id,kind,state,plan_rev,command_id,intent_sha256,
auth_epoch,recovery_generation,created_at,expires_at,confirmed_at,finished_at,rev,export_artifact_id,export_sha256,export_bytes,proof_id)
VALUES($1,$2,3,4,1,$3,$4,$5,$6,$7,$8,$7,$7,1,$9,$10,$11,$12)`, result.ID, caller.UserID, commandID, intent[:], security.AuthEpoch, security.RecoveryGeneration,
		now, result.ExpiresAt, platform.NewID(), digest[:], len(body), proofID)
	if err != nil {
		return Lifecycle{}, err
	}
	err = s.audit(ctx, tx, caller.Request, Actor(caller.UserID), "identity.export.prepared", "", "lifecycle_operation", result.ID.String(), map[string]any{"bytes": len(body)})
	return result, err
}

// ReadExport rechecks current authority and the complete canonical digest on
// every bounded read. Changed facts fail the old receipt; they are never silently
// substituted with a different successful export after a retry or restart.
func (s *Service) ReadExport(ctx context.Context, caller Caller, operationID platform.ID, offset, limit int) (ExportPage, error) {
	if offset < 0 || limit < 1 || limit > MaxExportPageBytes {
		return ExportPage{}, arc.InvalidArgument("range", "bounds")
	}
	if err := s.checkExportReadRate(ctx, caller); err != nil {
		return ExportPage{}, err
	}
	var result ExportPage
	var refusal error
	err := s.db.InTx(ctx, "read account export", store.TxOptions{}, func(ctx context.Context, tx pgx.Tx) error {
		result = ExportPage{}
		refusal = nil
		now := s.now()
		security, err := lockLifecycleCaller(ctx, tx, caller, now, true)
		if err != nil {
			return err
		}
		item, err := lifecycleOf(ctx, tx, caller.UserID, operationID, true)
		if err != nil {
			return err
		}
		if item.Kind != LifecycleExport {
			return arc.NotFound("account_export", operationID[:])
		}
		if item.State != LifecycleCompleted {
			return arc.InvalidState("account_export", "unavailable")
		}
		state := int16(0)
		switch {
		case !now.Before(item.ExpiresAt):
			state = LifecycleExpired
			refusal = arc.Expired()
		case security.State != int16(StateActive) && security.State != int16(StateRestricted), item.authEpoch != security.AuthEpoch || item.recoveryGeneration != security.RecoveryGeneration:
			state = LifecycleRevoked
			refusal = arc.CredentialRevoked()
		}
		var body []byte
		if state == 0 {
			body, err = canonicalAccountExport(ctx, tx, caller.UserID)
			if err != nil {
				return err
			}
			digest := sha256.Sum256(body)
			if int64(len(body)) != item.ExportBytes || !bytes.Equal(digest[:], item.exportDigest) {
				state = LifecycleRevoked
				refusal = arc.InvalidState("account_export", "snapshot_changed")
			}
		}
		if state != 0 {
			_, err = tx.Exec(ctx, `UPDATE identity.lifecycle_operation SET state=$2,finished_at=$3,rev=rev+1 WHERE operation_id=$1`, operationID, state, now)
			return err
		}
		if offset > len(body) {
			return arc.InvalidArgument("offset", "bounds")
		}
		end := min(offset+limit, len(body))
		result = ExportPage{Lifecycle: item.Lifecycle, Offset: offset, Total: len(body), Data: append([]byte(nil), body[offset:end]...), Done: end == len(body)}
		return nil
	})
	if err != nil {
		return ExportPage{}, err
	}
	if refusal != nil {
		return ExportPage{}, refusal
	}
	return result, nil
}

// Reads have their own budget, scaled by the maximum 32-KiB page count so a
// permitted 2-MiB export remains downloadable under the ordinary policy.
func (s *Service) checkExportReadRate(ctx context.Context, caller Caller) error {
	const pages = MaxExportBytes / (32 * 1024)
	for _, bucket := range []ratelimit.Bucket{
		s.bucket(ratelimit.SignInPrefix, "export-read:"+ratelimit.Prefix(caller.ClientIP)),
		s.bucket(ratelimit.StepUpAccount, "export-read:"+caller.UserID.String()),
	} {
		bucket.Window.Limit *= pages
		if err := s.take(ctx, caller.Request, bucket, Actor(caller.UserID)); err != nil {
			return err
		}
	}
	return nil
}
