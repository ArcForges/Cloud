// SPDX-License-Identifier: AGPL-3.0-only

package fleetapi

import (
	"bytes"
	"context"
	"errors"
	"math"
	"strings"
	"time"

	fleetv1 "github.com/ArcForges/Contracts/go/arcforges/fleet/v1"
	"github.com/ArcForges/Contracts/go/arcforges/fleet/v1/fleetv1connect"
	foundationv1 "github.com/ArcForges/Contracts/go/arcforges/foundation/v1"
	"github.com/jackc/pgx/v5"
	"google.golang.org/protobuf/proto"

	"github.com/ArcForges/Cloud/center/internal/config"
	"github.com/ArcForges/Cloud/center/internal/identity"
	"github.com/ArcForges/Cloud/center/internal/ingress"
	"github.com/ArcForges/Cloud/center/internal/platform"
	"github.com/ArcForges/Cloud/center/internal/routes"
	"github.com/ArcForges/Cloud/center/internal/session"
)

// SigningKeyReplyBudget checks both actual published key sets plus a proposed command or entitlement key. The caller holds a
// table lock through registration so another write cannot make the checked set stale before the INSERT. The Worker sends binary
// gRPC-Web and enforces each fleet method's own frame and unary bounds, which are taken from the actual registrations.
func SigningKeyReplyBudget(ctx context.Context, tx pgx.Tx, now time.Time, proposed platform.SigningKey) (int, int, error) {
	command, err := platform.PublishedKeys(ctx, tx, platform.CommandSigning, now)
	if err != nil {
		return 0, 0, err
	}
	entitlement, err := platform.PublishedKeys(ctx, tx, platform.EntitlementToken, now)
	if err != nil {
		return 0, 0, err
	}
	switch proposed.Purpose {
	case platform.CommandSigning:
		command = append(command, proposed)
	case platform.EntitlementToken:
		entitlement = append(entitlement, proposed)
	default:
		return 0, 0, errors.New("the key purpose is not published with node credentials")
	}
	return proofKeyReplyBudget(command, entitlement)
}

// proofKeyReplyBudget constructs conservative protobuf replies of all three operations that deliver these sets. Each response's
// fields follow the actual handlers: two 48-byte tokens, 16-byte IDs, no entitlement token or certificate, a maximum 128-UTF16-unit
// name (three UTF-8 bytes per unit), a masked email bounded by the 254-byte address plus three mask bytes, and maximal integer/instant encodings. The existing ListNodes
// sizing test reserves 64 bytes for gRPC-Web trailers; the Worker enforces the frame header plus that trailer inside its route bound.
func proofKeyReplyBudget(command, entitlement []platform.SigningKey) (int, int, error) {
	id := func() *foundationv1.Id { return &foundationv1.Id{Value: bytes.Repeat([]byte{0xff}, 16)} }
	instant := func() *foundationv1.Instant {
		return &foundationv1.Instant{UnixSeconds: proto.Int64(math.MinInt64), Nanos: proto.Uint32(math.MaxUint32)}
	}
	token := strings.Repeat("x", len(session.AccessPrefix)+session.EncodedLength)
	credentials := &fleetv1.NodeCredentials{
		RefreshToken: proto.String(token), AccessToken: proto.String(token), AccessExpiresAt: instant(),
		Account: &fleetv1.AccountSummary{AccountId: id(), DisplayName: proto.String(strings.Repeat("界", identity.DisplayNameMaxUnits)),
			EmailMasked: proto.String(strings.Repeat("x", config.MaxMailAddressBytes+3))},
		CommandKeys: publicKeys(command), EntitlementKeys: publicKeys(entitlement), InstallationId: id(),
		SessionExpiresAt: instant(), AccessLifetimeMs: proto.Uint64(math.MaxUint64),
	}
	meta := &foundationv1.ResponseMeta{CorrelationId: id()}
	complete := &fleetv1.NodeEnrollmentServiceCompleteNodeSignInResponse{Meta: meta,
		Outcome: &fleetv1.NodeEnrollmentServiceCompleteNodeSignInResponse_Value{
			Value: &fleetv1.NodeEnrollmentServiceCompleteNodeSignInValue{Credentials: credentials}}}
	poll := &fleetv1.NodeEnrollmentServicePollDeviceAuthorizationResponse{Meta: meta,
		Outcome: &fleetv1.NodeEnrollmentServicePollDeviceAuthorizationResponse_Value{
			Value: &fleetv1.NodeEnrollmentServicePollDeviceAuthorizationValue{
				State: fleetv1.DeviceAuthorizationState(math.MaxInt32).Enum(), IntervalMs: proto.Uint64(math.MaxUint64), Credentials: credentials}}}
	refresh := &fleetv1.NodeEnrollmentServiceRefreshNodeSessionResponse{Meta: meta,
		Outcome: &fleetv1.NodeEnrollmentServiceRefreshNodeSessionResponse_Value{
			Value: &fleetv1.NodeEnrollmentServiceRefreshNodeSessionValue{
				RefreshToken: proto.String(token), AccessToken: proto.String(token), AccessExpiresAt: instant(),
				CommandKeys: publicKeys(command), EntitlementKeys: publicKeys(entitlement), SessionExpiresAt: instant(),
				AccessLifetimeMs: proto.Uint64(math.MaxUint64)}}}

	paths := map[string]proto.Message{
		fleetv1connect.NodeEnrollmentServiceCompleteNodeSignInProcedure:      complete,
		fleetv1connect.NodeEnrollmentServicePollDeviceAuthorizationProcedure: poll,
		fleetv1connect.NodeEnrollmentServiceRefreshNodeSessionProcedure:      refresh,
	}
	modules, err := routes.Center()
	if err != nil {
		return 0, 0, err
	}
	const trailers = 64 // the same conservative gRPC-Web trailer allowance as TestTheListNodesReplyFitsItsBoundAtTheCap
	largest, narrowest, found := 0, math.MaxInt, 0
	for _, module := range modules {
		for procedure, message := range paths {
			if budget, ok := module.Budgets[procedure]; ok {
				found++
				frame := ingress.HeaderLength + proto.Size(message)
				largest = max(largest, frame+trailers)
				narrowest = min(narrowest, budget.MaxUnaryResponseBytes, budget.MaxFrameBytes+trailers)
			}
		}
	}
	if found != len(paths) {
		return 0, 0, errors.New("the fleet key-response transport budgets are unavailable")
	}
	return largest, narrowest, nil
}
