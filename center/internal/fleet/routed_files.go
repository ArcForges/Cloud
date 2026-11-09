// SPDX-License-Identifier: AGPL-3.0-only

package fleet

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"time"

	"github.com/ArcForges/Cloud/center/internal/platform"
	"github.com/ArcForges/Cloud/center/internal/store"
	"github.com/jackc/pgx/v5"
)

// RoutedObservation is a bounded observation from the verified node. It never
// claims that the center independently read the target file.
type RoutedObservation struct {
	Kind             int32   `json:"kind"`
	SizeBytes        uint64  `json:"sizeBytes"`
	SHA256           string  `json:"sha256"`
	DigestInputBytes uint64  `json:"digestInputBytes"`
	ItemCount        *uint32 `json:"itemCount,omitempty"`
}

func addFileTarget(payload map[string]any, workspace, attempt *platform.ID, path *string) {
	if workspace != nil {
		payload["workspaceId"] = workspace.String()
	}
	if attempt != nil {
		payload["targetAttemptId"] = attempt.String()
	}
	if path != nil {
		payload["path"] = *path
	}
}

// RoutedReadAudit persists only closed metadata for one cloud-originated read.
// The commandless audit does not create a mutation receipt.
type RoutedReadAudit struct {
	Request                      Request
	Caller                       RoutedCaller
	NodeID                       platform.ID
	Method                       int16
	WorkspaceID, TargetAttemptID *platform.ID
	TargetPath                   *string
	RequestSHA256                []byte
	RequestSize                  int
	Outcome                      string
	NodeAuditAvailable           bool
	Observations                 []RoutedObservation
	Now                          time.Time
}

func AuditRoutedFileRead(ctx context.Context, db *store.DB, audit RoutedReadAudit) error {
	return db.InTx(ctx, "audit a routed file read", store.TxOptions{Timeout: registryTimeout, Auxiliary: true}, func(ctx context.Context, tx pgx.Tx) error {
		payload := audit.Caller.audit(map[string]any{"method": audit.Method, "nodeId": audit.NodeID.String(),
			"requestSha256": hex.EncodeToString(audit.RequestSHA256), "requestSize": audit.RequestSize,
			"nodeAuditAvailable": audit.NodeAuditAvailable, "observations": audit.Observations})
		addFileTarget(payload, audit.WorkspaceID, audit.TargetAttemptID, audit.TargetPath)
		data, err := json.Marshal(payload)
		if err != nil {
			return err
		}
		_, err = platform.AppendAudit(ctx, tx, platform.Event{EventID: platform.NewID(), OccurredAt: audit.Now, ActorRef: audit.Caller.Actor,
			EventType: "fleet.file.read", Reason: audit.Outcome, CorrelationID: audit.Request.CorrelationID,
			TargetKind: "node", TargetID: audit.NodeID.String(), Payload: data})
		return err
	})
}
