// SPDX-License-Identifier: AGPL-3.0-only

package fleetapi

import (
	"errors"
	"strings"
	"testing"

	foundationv1 "github.com/ArcForges/Contracts/go/arcforges/foundation/v1"
	nodev1 "github.com/ArcForges/Contracts/go/arcforges/node/v1"
	relayv1 "github.com/ArcForges/Contracts/go/arcforges/relay/v1"
	"google.golang.org/protobuf/proto"

	"github.com/ArcForges/Cloud/center/internal/arc"
	"github.com/ArcForges/Cloud/center/internal/correlation"
	"github.com/ArcForges/Cloud/center/internal/platform"
)

func TestCTR06DecodedResourceLimitsHaveExactOuterDetails(t *testing.T) {
	command, workspace := platform.NewID(), platform.NewID()
	meta := &foundationv1.RequestMeta{CommandId: pid(command)}
	path := func(value string) *nodev1.FilePath {
		return &nodev1.FilePath{WorkspaceId: pid(workspace), Path: proto.String(value)}
	}
	cases := []struct {
		name, limit string
		maximum     string
		method      relayv1.RoutedMethod
		request     proto.Message
		command     *platform.ID
	}{
		{"write", "file_write_bytes", "196608", relayv1.RoutedMethod_ROUTED_METHOD_WRITE_NODE_FILE,
			&nodev1.FileServiceWriteFileRequest{Meta: meta, Path: path("a"), Data: make([]byte, 196609),
				Precondition: &nodev1.FileServiceWriteFileRequest_ExpectedAbsent{ExpectedAbsent: true}}, &command},
		{"edit old", "file_edit_text_bytes", "65536", relayv1.RoutedMethod_ROUTED_METHOD_EDIT_NODE_FILE,
			&nodev1.FileServiceEditFileRequest{Meta: meta, Path: path("a"), OldText: proto.String(strings.Repeat("a", 65537)),
				NewText: proto.String("b"), ExpectedOccurrences: proto.Uint32(1), ExpectedSha256: make([]byte, 32)}, &command},
		{"edit new", "file_edit_text_bytes", "65536", relayv1.RoutedMethod_ROUTED_METHOD_EDIT_NODE_FILE,
			&nodev1.FileServiceEditFileRequest{Meta: meta, Path: path("a"), OldText: proto.String("a"),
				NewText: proto.String(strings.Repeat("b", 65537)), ExpectedOccurrences: proto.Uint32(1), ExpectedSha256: make([]byte, 32)}, &command},
		{"read path", "path_bytes", "4096", relayv1.RoutedMethod_ROUTED_METHOD_READ_NODE_FILE,
			&nodev1.FileServiceReadFileRequest{Path: path(strings.Repeat("a", 4097)), Offset: proto.Uint64(0), Length: proto.Uint64(1)}, nil},
		{"plan path", "path_bytes", "4096", relayv1.RoutedMethod_ROUTED_METHOD_PLAN_NODE_REMOVAL,
			&nodev1.FileServicePlanRemovalRequest{Meta: meta, Target: &nodev1.FileServicePlanRemovalRequest_WorkspacePath{WorkspacePath: path(strings.Repeat("a", 4097))}}, &command},
		{"register path", "workspace_root_path_bytes", "4096", relayv1.RoutedMethod_ROUTED_METHOD_REGISTER_NODE_WORKSPACE,
			&nodev1.WorkspaceServiceRegisterWorkspaceRequest{Meta: meta, Path: proto.String("/" + strings.Repeat("a", 4096))}, &command},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := checkInner(tc.method, marshal(t, tc.request), tc.command)
			var refusal *arc.Refusal
			if !errors.As(err, &refusal) || refusal.Key() != "RESOURCE/too_large" {
				t.Fatalf("wanted resource limit refusal: %v", err)
			}
			wire := refusal.ArcError(correlation.New())
			if wire.GetRetry().GetMode() != foundationv1.RetryMode_RETRY_MODE_NEVER ||
				wire.GetEffect() != foundationv1.EffectCertainty_EFFECT_CERTAINTY_DID_NOT_HAPPEN ||
				wire.GetDetails().GetLimit().GetLimitName() != tc.limit || wire.GetDetails().GetLimit().GetMaximum().GetValue() != tc.maximum {
				t.Fatalf("wrong actual limit: %v", wire)
			}
		})
	}

	malformed := &nodev1.FileServiceReadFileRequest{Path: path(strings.Repeat("a", 4096) + "\x00"),
		Offset: proto.Uint64(0), Length: proto.Uint64(1)}
	_, err := checkInner(relayv1.RoutedMethod_ROUTED_METHOD_READ_NODE_FILE, marshal(t, malformed), nil)
	var refusal *arc.Refusal
	if !errors.As(err, &refusal) || refusal.Key() != "VALIDATION/invalid_argument" {
		t.Fatalf("malformed path must remain validation: %v", err)
	}
	write := &nodev1.FileServiceWriteFileRequest{Meta: meta, Path: path("a"), Data: make([]byte, 196608),
		Precondition: &nodev1.FileServiceWriteFileRequest_ExpectedAbsent{ExpectedAbsent: true}}
	if _, err := checkInner(relayv1.RoutedMethod_ROUTED_METHOD_WRITE_NODE_FILE, marshal(t, write), &command); err != nil {
		t.Fatalf("exact write maximum rejected: %v", err)
	}
}
