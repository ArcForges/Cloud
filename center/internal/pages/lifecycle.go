// SPDX-License-Identifier: AGPL-3.0-only

package pages

import (
	"context"
	"encoding/json"
	"errors"
	"strconv"
	"time"

	foundationv1 "github.com/ArcForges/Contracts/go/arcforges/foundation/v1"
	"github.com/ArcForges/Contracts/go/arcforges/publicapi/v1/publicapiv1connect"
	"github.com/jackc/pgx/v5"
	"google.golang.org/protobuf/proto"

	"github.com/ArcForges/Cloud/center/internal/arc"
	"github.com/ArcForges/Cloud/center/internal/correlation"
	"github.com/ArcForges/Cloud/center/internal/identity"
	"github.com/ArcForges/Cloud/center/internal/identityapi"
	"github.com/ArcForges/Cloud/center/internal/platform"
	"github.com/ArcForges/Cloud/center/internal/session"
	"github.com/ArcForges/Cloud/center/internal/store"
)

const exportPageBytes = 32 * 1024 // Base64url and metadata fit the route's 64 KiB reply.

type lifecycleView struct {
	Pending      bool
	Operation    *lifecycleReply
	ExportTarget string
}

// lifecycleReply is metadata only. A blocked deletion remains processing; it
// does not promise a purge date or claim that a billing provider was contacted.
type lifecycleReply struct {
	OperationID          string `json:"operationId"`
	State                string `json:"state"`
	PlanRevision         string `json:"planRevision"`
	Revision             string `json:"revision"`
	ExpiresAt            string `json:"expiresAt"`
	ActiveSubscriptions  int    `json:"activeSubscriptions"`
	UnresolvedOperations int    `json:"unresolvedOperations"`
	BlockedReason        int16  `json:"blockedReason"`
	ExportBytes          int64  `json:"exportBytes"`
	ConfirmTarget        string `json:"confirmTarget,omitempty"`
	CancelTarget         string `json:"cancelTarget,omitempty"`
}

func lifecycleOf(item identity.Lifecycle, userID platform.ID) lifecycleReply {
	result := lifecycleReply{OperationID: uuidText(item.ID), State: identityapi.LifecycleState(item.State),
		PlanRevision: strconv.FormatInt(item.PlanRevision, 10), Revision: strconv.FormatInt(item.Revision, 10),
		ExpiresAt: formatInstant(item.ExpiresAt), ActiveSubscriptions: item.ActiveSubscriptions,
		UnresolvedOperations: item.UnresolvedOperations, BlockedReason: item.BlockedReason, ExportBytes: item.ExportBytes}
	if item.Kind == identity.LifecycleDeletion {
		result.ConfirmTarget = identity.TargetHash(identity.ClassConfirmDeletion, userID, item.ID)
		result.CancelTarget = identity.TargetHash(identity.ClassCancelDeletion, userID, item.ID)
	}
	return result
}

func (e *exchange) lifecycleCaller(resolved *session.BrowserSession) identity.Caller {
	return identity.Caller{Request: e.request(), UserID: resolved.UserID, SessionID: resolved.SessionID, DeviceID: resolved.DeviceID,
		Scope: resolved.Credential.Caller.Scope, Browser: true, AuthEpoch: resolved.Credential.Caller.AuthEpoch,
		RecoveryGeneration: resolved.RecoveryGeneration}
}

func (e *exchange) lifecyclePage() {
	resolved, ok := e.protected()
	if !ok {
		return
	}
	if _, ok = e.authorized(publicapiv1connect.IdentityServiceGetAccountDeletionProcedure, resolved, nil); !ok {
		return
	}
	item, err := e.h.options.Identity.GetDeletion(e.r.Context(), e.lifecycleCaller(resolved))
	if err != nil {
		e.fail(err)
		return
	}
	view := lifecycleView{Pending: resolved.Credential.Caller.AccountState == 4,
		ExportTarget: identity.TargetHash(identity.ClassExportAccount, resolved.UserID, resolved.UserID)}
	if item != nil {
		projected := lifecycleOf(*item, resolved.UserID)
		view.Operation = &projected
	}
	e.serve("lifecycle", pageData{Title: "Account data and deletion", Signed: true, CSRF: resolved.CSRF, Lifecycle: view})
}

// lifecycleInput is normalized before computing the receipt digest. CSRF tokens,
// HTTP formatting and correlation IDs are not part of an operation's intent.
type lifecycleInput struct {
	CommandID     platform.ID
	PlanID        platform.ID
	PlanRevision  int64
	OperationID   platform.ID
	Offset, Limit int
}

func parseLifecycle(data []byte, kind string) (lifecycleInput, *arc.Refusal) {
	fields := []string{"commandId"}
	switch kind {
	case "confirm":
		fields = append(fields, "planId", "planRevision")
	case "cancel":
		fields = append(fields, "planId")
	case "read":
		fields = []string{"operationId", "offset", "limit"}
	case "prepare", "export":
	default:
		return lifecycleInput{}, arc.InvalidArgument("operation", "not_offered")
	}
	root, refusal := parseObject(data, "", fields...)
	if refusal != nil {
		return lifecycleInput{}, refusal
	}
	var result lifecycleInput
	if kind == "read" {
		if result.OperationID, refusal = root.requiredUUID("operationId"); refusal != nil {
			return result, refusal
		}
		if result.Offset, refusal = lifecycleInteger(root, "offset", 0, identity.MaxExportBytes); refusal != nil {
			return result, refusal
		}
		if result.Limit, refusal = lifecycleInteger(root, "limit", 1, exportPageBytes); refusal != nil {
			return result, refusal
		}
		return result, nil
	}
	if result.CommandID, refusal = root.requiredUUID("commandId"); refusal != nil {
		return result, refusal
	}
	if kind == "confirm" || kind == "cancel" {
		if result.PlanID, refusal = root.requiredUUID("planId"); refusal != nil {
			return result, refusal
		}
	}
	if kind == "confirm" {
		text, refusal := root.requiredText("planRevision", textRule{min: 1, max: 19})
		if refusal != nil {
			return result, refusal
		}
		revision, err := strconv.ParseInt(text, 10, 64)
		if err != nil || revision < 1 || strconv.FormatInt(revision, 10) != text {
			return result, arc.InvalidArgument("planRevision", "pattern")
		}
		result.PlanRevision = revision
	}
	return result, nil
}

func lifecycleInteger(root object, name string, low, high int) (int, *arc.Refusal) {
	var value int
	raw, ok := root.fields[name]
	if !ok {
		return 0, arc.InvalidArgument(name, "required")
	}
	if string(raw) == "null" || json.Unmarshal(raw, &value) != nil || value < low || value > high {
		return 0, arc.InvalidArgument(name, "bounds")
	}
	return value, nil
}

func (e *exchange) prepareDeletion() { e.lifecycleWrite("prepare", "identity.prepareAccountDeletion") }
func (e *exchange) confirmDeletion() { e.lifecycleWrite("confirm", identity.ClassConfirmDeletion) }
func (e *exchange) cancelDeletion()  { e.lifecycleWrite("cancel", identity.ClassCancelDeletion) }
func (e *exchange) prepareExport()   { e.lifecycleWrite("export", identity.ClassExportAccount) }

func (e *exchange) lifecycleWrite(kind, operation string) {
	resolved, ok := e.guard(true, "")
	if !ok {
		return
	}
	input, refusal := parseLifecycle(e.body, kind)
	if refusal != nil {
		e.fail(refusal)
		return
	}
	caller := e.lifecycleCaller(resolved)
	if caller.Scope != "account" {
		e.fail(arc.PermissionDenied(operation))
		return
	}
	canonical, err := json.Marshal(input)
	if err != nil {
		e.fail(err)
		return
	}
	command := platform.Command{Principal: identity.Actor(caller.UserID), CommandID: input.CommandID, Operation: operation, Request: canonical}
	if resolved.Credential.Caller.AccountState == 4 && kind != "cancel" {
		if kind != "confirm" {
			e.fail(arc.PermissionDenied(operation))
			return
		}
		// A fresh pending-account session may reconcile an already committed
		// confirmation after its reply was lost. This branch cannot execute an
		// effect, consume a proof, create a receipt, or confirm another command.
		item, err := e.h.options.Identity.GetLifecycle(e.r.Context(), caller, input.PlanID)
		if err != nil {
			e.fail(err)
			return
		}
		if item.Kind != identity.LifecycleDeletion || item.State != identity.LifecycleProcessing {
			e.fail(arc.PermissionDenied(operation))
			return
		}
		outcome, found, err := platform.Lookup(e.r.Context(), e.h.options.DB, command)
		if err != nil {
			e.lifecycleOutcome(caller.UserID, input.CommandID, outcome, err)
			return
		}
		if !found || !outcome.Succeeded {
			e.fail(arc.PermissionDenied(operation))
			return
		}
		e.lifecycleOutcome(caller.UserID, input.CommandID, outcome, nil)
		return
	}
	if err := e.h.options.Identity.CheckLifecycleRate(e.r.Context(), caller); err != nil {
		e.fail(err)
		return
	}
	outcome, err := platform.Execute(e.r.Context(), e.h.options.DB, command, store.TxOptions{}, func(ctx context.Context, tx pgx.Tx) ([]byte, error) {
		now := e.h.options.Clock().UTC().Truncate(time.Microsecond)
		var item identity.Lifecycle
		var err error
		switch kind {
		case "prepare":
			item, err = e.h.options.Identity.PrepareDeletion(ctx, tx, caller, input.CommandID, now)
		case "confirm":
			item, err = e.h.options.Identity.ConfirmDeletion(ctx, tx, caller, input.PlanID, input.PlanRevision, input.CommandID, now)
		case "cancel":
			item, err = e.h.options.Identity.CancelDeletion(ctx, tx, caller, input.PlanID, input.CommandID, now)
		case "export":
			item, err = e.h.options.Identity.PrepareExport(ctx, tx, caller, input.CommandID, now)
		}
		if err == nil {
			return json.Marshal(item)
		}
		var refused *arc.Refusal
		if errors.As(err, &refused) && refused.Final() {
			encoded, encodeErr := proto.MarshalOptions{Deterministic: true}.Marshal(refused.ArcError(correlation.Context{}))
			if encodeErr != nil {
				return nil, encodeErr
			}
			return nil, &platform.Refusal{Code: refused.Key(), Result: encoded}
		}
		return nil, err
	})
	e.lifecycleOutcome(caller.UserID, input.CommandID, outcome, err)
}

func (e *exchange) lifecycleOutcome(userID, commandID platform.ID, outcome platform.Outcome, err error) {
	switch {
	case errors.Is(err, platform.ErrCommandIDReused):
		e.fail(arc.CommandIDReused())
		return
	case errors.Is(err, platform.ErrCommandInProgress):
		e.fail(arc.Unavailable())
		return
	case err != nil:
		e.fail(err)
		return
	case !outcome.Succeeded:
		value := &foundationv1.ArcError{}
		if err := proto.Unmarshal(outcome.Result, value); err != nil {
			e.fail(err)
			return
		}
		value.CorrelationId = &foundationv1.Id{Value: correlation.IDBytes(e.correlation.CorrelationID)}
		e.refuseError(value, 0)
		return
	}
	var item identity.Lifecycle
	if err := json.Unmarshal(outcome.Result, &item); err != nil {
		e.fail(err)
		return
	}
	e.writeJSON(struct {
		Operation lifecycleReply `json:"operation"`
		Receipt   receiptReply   `json:"receipt"`
	}{lifecycleOf(item, userID), receiptReply{CommandID: uuidText(commandID), ResultRevision: strconv.FormatInt(item.Revision, 10), Effect: "happened"}}, "")
}

func (e *exchange) readExport() {
	resolved, ok := e.guard(true, "")
	if !ok {
		return
	}
	input, refusal := parseLifecycle(e.body, "read")
	if refusal != nil {
		e.fail(refusal)
		return
	}
	page, err := e.h.options.Identity.ReadExport(e.r.Context(), e.lifecycleCaller(resolved), input.OperationID, input.Offset, input.Limit)
	if err != nil {
		e.fail(err)
		return
	}
	e.writeJSON(struct {
		Operation lifecycleReply `json:"operation"`
		Offset    int            `json:"offset"`
		Total     int            `json:"total"`
		Data      string         `json:"data"`
		Done      bool           `json:"done"`
	}{lifecycleOf(page.Lifecycle, resolved.UserID), page.Offset, page.Total, b64(page.Data), page.Done}, "")
}
