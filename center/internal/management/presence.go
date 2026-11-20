// SPDX-License-Identifier: AGPL-3.0-only

package management

import (
	"time"

	"github.com/ArcForges/Cloud/center/internal/platform"
)

// V2Presence is the last accepted observation of an exact live V2 connection.
type V2Presence struct {
	ConnectionID, NodeOwnerEpoch platform.ID
	NodeEpoch, Platform          string
	Capabilities                 []string
	HubFence                     int64
	SeenAt                       time.Time
}
