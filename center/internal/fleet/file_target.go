// SPDX-License-Identifier: AGPL-3.0-only

package fleet

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/jackc/pgx/v5"

	"github.com/ArcForges/Cloud/center/internal/platform"
	"github.com/ArcForges/Cloud/center/internal/store"
)

// FileTargetKind identifies which signed identifier indexes an association.
type FileTargetKind int16

const (
	FileTargetPlan      FileTargetKind = 1
	FileTargetOperation FileTargetKind = 2
)

// FileTarget is bounded metadata, never file or command contents.
type FileTarget struct {
	WorkspaceID, AttemptID *platform.ID
	Path                   *string
}

// FileTargetBinding is a target associated with one account, enrolled node,
// authenticated caller class and signed plan or command identifier.
type FileTargetBinding struct {
	AccountID, NodeID, EnrollmentID, LookupID platform.ID
	Caller                                    RoutedCaller
	Kind                                      FileTargetKind
	Target                                    FileTarget
	Now                                       time.Time
}

func fileCallerHash(c RoutedCaller) ([]byte, error) {
	var fixed [2]byte
	h := sha256.New()
	h.Write([]byte("ArcForges routed-file-target-caller v1\n"))
	binary.BigEndian.PutUint16(fixed[:], uint16(c.Kind))
	h.Write(fixed[:])
	switch c.Kind {
	case RoutedCallerSession:
		if c.SessionID == (platform.ID{}) {
			return nil, errors.New("file target has no authenticated session")
		}
		// The account ID is part of the key; different sessions of the same
		// account use the existing routed caller-class identity.
	case RoutedCallerRelay:
		if c.RelayingNodeID == (platform.ID{}) || c.LocalSessionID == (platform.ID{}) || c.LocalOrigin < 1 || c.LocalOrigin > 3 {
			return nil, errors.New("file target has no verified relay")
		}
		h.Write(c.RelayingNodeID[:])
		binary.BigEndian.PutUint16(fixed[:], uint16(c.LocalOrigin))
		h.Write(fixed[:])
		h.Write(c.LocalSessionID[:])
	default:
		return nil, errors.New("unknown file target caller")
	}
	return h.Sum(nil), nil
}

func validTarget(t FileTarget) bool {
	if t.WorkspaceID != nil && *t.WorkspaceID != (platform.ID{}) && t.AttemptID == nil && t.Path != nil {
		return len(*t.Path) > 0 && len(*t.Path) <= 4096 && utf8.ValidString(*t.Path) && !strings.ContainsRune(*t.Path, 0)
	}
	return t.WorkspaceID == nil && t.AttemptID != nil && *t.AttemptID != (platform.ID{}) && t.Path == nil
}

// SaveFileTarget persists an immutable association in the same transaction as
// the signed result, accepted mutation or audited signed status. Conflicting
// associations fail closed instead of overwriting an earlier target.
func SaveFileTarget(ctx context.Context, tx pgx.Tx, b FileTargetBinding) error {
	if b.AccountID == (platform.ID{}) || b.NodeID == (platform.ID{}) || b.EnrollmentID == (platform.ID{}) || b.LookupID == (platform.ID{}) ||
		(b.Kind != FileTargetPlan && b.Kind != FileTargetOperation) || !validTarget(b.Target) {
		return errors.New("invalid file target binding")
	}
	caller, err := fileCallerHash(b.Caller)
	if err != nil {
		return err
	}
	_, err = tx.Exec(ctx, `INSERT INTO fleet.routed_file_target (account_id,node_enrollment_id,node_id,caller_hash,target_kind,lookup_id,workspace_id,target_attempt_id,target_path,created_at)
VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10) ON CONFLICT DO NOTHING`, b.AccountID, b.EnrollmentID, b.NodeID, caller, b.Kind, b.LookupID, b.Target.WorkspaceID, b.Target.AttemptID, b.Target.Path, b.Now)
	if err != nil {
		return store.Sanitize("save a file target association", err)
	}
	var same bool
	err = tx.QueryRow(ctx, `SELECT node_enrollment_id=$6 AND workspace_id IS NOT DISTINCT FROM $7::uuid AND target_attempt_id IS NOT DISTINCT FROM $8::uuid AND target_path IS NOT DISTINCT FROM $9::text
FROM fleet.routed_file_target WHERE account_id=$1 AND node_id=$2 AND caller_hash=$3 AND target_kind=$4 AND lookup_id=$5`,
		b.AccountID, b.NodeID, caller, b.Kind, b.LookupID, b.EnrollmentID, b.Target.WorkspaceID, b.Target.AttemptID, b.Target.Path).Scan(&same)
	if err != nil {
		return store.Sanitize("confirm a file target association", err)
	}
	if !same {
		return errors.New("a file target association conflicts with an earlier binding")
	}
	return nil
}

// LookupFileTarget never searches across accounts, node enrollments or caller
// identities. A missing/foreign association returns no metadata.
func LookupFileTarget(ctx context.Context, db *store.DB, account, node platform.ID, caller RoutedCaller, kind FileTargetKind, id platform.ID) (*FileTarget, error) {
	hash, err := fileCallerHash(caller)
	if err != nil {
		return nil, err
	}
	var target FileTarget
	err = db.Pool().QueryRow(ctx, `SELECT t.workspace_id,t.target_attempt_id,t.target_path
FROM fleet.routed_file_target t JOIN fleet.node n ON n.enrollment_id=t.node_enrollment_id AND n.node_id=t.node_id AND n.user_id=t.account_id AND n.revoked_at IS NULL
WHERE t.account_id=$1 AND t.node_id=$2 AND t.caller_hash=$3 AND t.target_kind=$4 AND t.lookup_id=$5`, account, node, hash, kind, id).Scan(&target.WorkspaceID, &target.AttemptID, &target.Path)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, store.Sanitize("read a file target association", err)
	}
	if !validTarget(target) {
		return nil, errors.New("stored file target association is invalid")
	}
	return &target, nil
}

// FileOperationReceipt is the authenticated caller's original mutation's
// exact inner-wire digest and method, independent of the target association.
type FileOperationReceipt struct {
	Method        int16
	RequestSHA256 []byte
}

// LookupFileOperationReceipt grants status only to the account caller class
// or to the exact verified relay identity that admitted this command. A new
// account session may inspect the same account's operation. It never resolves
// another account, node enrollment or relay session.
func LookupFileOperationReceipt(ctx context.Context, db *store.DB, account, node platform.ID, caller RoutedCaller, command platform.ID) (*FileOperationReceipt, error) {
	if _, err := fileCallerHash(caller); err != nil {
		return nil, err
	}
	var receipt FileOperationReceipt
	err := db.Pool().QueryRow(ctx, `SELECT f.method, f.request_sha256
FROM fleet.routed_file_call f
JOIN fleet.node n ON n.enrollment_id=f.node_enrollment_id AND n.node_id=f.node_id AND n.user_id=f.account_id AND n.revoked_at IS NULL
WHERE f.account_id=$1 AND f.node_id=$2 AND f.command_id=$3 AND
((f.caller_kind=1 AND $4::smallint=1) OR
 (f.caller_kind=2 AND $4::smallint=2 AND f.relaying_node_id=$5 AND f.local_origin=$6 AND f.local_session_id=$7))`,
		account, node, command, caller.Kind, caller.RelayingNodeID, caller.LocalOrigin, caller.LocalSessionID).Scan(&receipt.Method, &receipt.RequestSHA256)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, store.Sanitize("read an operation receipt", err)
	}
	if len(receipt.RequestSHA256) != sha256.Size {
		return nil, errors.New("stored file request digest is invalid")
	}
	return &receipt, nil
}
