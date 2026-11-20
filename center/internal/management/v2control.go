// SPDX-License-Identifier: AGPL-3.0-only

package management

import (
	"errors"
	"time"

	"github.com/ArcForges/Cloud/center/internal/platform"
)

type V2ControlSelector uint8

// V2ControlAuthority is an exact observed channel binding. The Hub validates
// it again against the current connection and durable lease before sending.
type V2ControlAuthority struct {
	AccountID, NodeID, EnrollmentID, ProtocolEpoch platform.ID
	ConnectionID, NodeOwnerEpoch, HubHolder        platform.ID
	HubFence                                       int64
}

// V2ControlCall holds the admitted typed message only for the live response.
// Body is never stored in Center routing receipts.
type V2ControlCall struct {
	Selector                                        V2ControlSelector
	ActorID, OriginalOwnerEpoch, CommandID, GrantID platform.ID
	GrantRevision                                   int64
	Deadline                                        time.Time
	Body                                            []byte
}

var (
	ErrV2ControlUpgradeRequired = errors.New("the node enrollment has no V2 control channel")
	ErrV2ControlUnavailable     = errors.New("the exact V2 control channel is unavailable")
	ErrV2ControlNotClaimed      = errors.New("this operation did not claim a V2 send")
	ErrV2ControlUncertain       = errors.New("the V2 control response is uncertain")
)
