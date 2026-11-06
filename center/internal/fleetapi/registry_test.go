// SPDX-License-Identifier: AGPL-3.0-only

package fleetapi

import (
	"math"
	"strings"
	"testing"
	"time"

	fleetv1 "github.com/ArcForges/Contracts/go/arcforges/fleet/v1"
	"github.com/ArcForges/Contracts/go/arcforges/fleet/v1/fleetv1connect"
	"google.golang.org/protobuf/proto"

	"github.com/ArcForges/Cloud/center/internal/config"
	"github.com/ArcForges/Cloud/center/internal/correlation"
	"github.com/ArcForges/Cloud/center/internal/device"
	"github.com/ArcForges/Cloud/center/internal/fleet"
	"github.com/ArcForges/Cloud/center/internal/ingress"
	"github.com/ArcForges/Cloud/center/internal/platform"
	"github.com/ArcForges/Cloud/center/internal/routes"
)

// TestTheListNodesReplyFitsItsBoundAtTheCap (AF-CTR-05 E2a; review A B-1, B B-2; EVIDENCE: REAL code): a ListNodes reply of
// config.MaxNodesPerAccountBound nodes, each as large as the rules admit (both names of 64 UTF-16 units of 3-byte characters, a
// 128-character canonical version, every ID and instant set, the largest instants), fits ListNodes' route budget with its gRPC-Web frame
// header (the Worker's frame guard), the whole reply with its trailers frame (the Worker's unary bound), and the center's Connect send
// bound, the largest budget of the registrations.
func TestTheListNodesReplyFitsItsBoundAtTheCap(t *testing.T) {
	name := strings.Repeat("界", device.MaxNameUnits)
	if !device.ValidNodeName(name) {
		t.Fatal("the worst name is not a valid node name")
	}
	version := "999999999.999999999.999999999-" + strings.Repeat("a", fleet.MaxVersionLength-30)
	if canonical, ok := fleet.ValidNodeVersion(version); !ok || canonical != version || len(version) != fleet.MaxVersionLength {
		t.Fatalf("the worst version is not a canonical node version: %q %v", canonical, ok)
	}
	latest := time.Unix(math.MaxInt32*16, 999_999_000).UTC()
	id := platform.ID{0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff}
	worst := fleet.NodeRecord{NodeID: id, DeviceID: id, EnrollmentID: id, Name: name, ReportedName: name, Version: version, OS: 2, Arch: 2,
		EnrolledAt: latest, LastSeenAt: latest, Connected: true, CredentialExpiresAt: &latest}
	reply := &fleetv1.FleetServiceListNodesResponse{Meta: ingress.ResponseMeta(correlation.Context{CorrelationID: id.String()})}
	value := &fleetv1.FleetServiceListNodesValue{}
	for range config.MaxNodesPerAccountBound {
		value.Nodes = append(value.Nodes, fleetNode(worst, true))
	}
	reply.Outcome = &fleetv1.FleetServiceListNodesResponse_Value{Value: value}
	node := proto.Size(fleetNode(worst, true))
	frame := ingress.HeaderLength + proto.Size(reply)
	const trailers = 64 // "grpc-status: 0\r\ngrpc-message: \r\n" and its frame header, with room
	modules, err := routes.Center()
	if err != nil {
		t.Fatal(err)
	}
	var budget routes.Budget
	for _, module := range modules {
		if found, ok := module.Budgets[fleetv1connect.FleetServiceListNodesProcedure]; ok {
			budget = found
		}
	}
	if node < 600 || frame > budget.MaxFrameBytes || frame+trailers > budget.MaxUnaryResponseBytes || frame > routes.MaxResponseBytes(modules) {
		t.Fatalf("a worst node of %d bytes; %d nodes are a frame of %d bytes; budget %+v, send bound %d", node, config.MaxNodesPerAccountBound, frame, budget,
			routes.MaxResponseBytes(modules))
	}
	t.Logf("worst node %d bytes, worst reply frame %d bytes, budget %d", node, frame, budget.MaxFrameBytes)
}
