// SPDX-License-Identifier: AGPL-3.0-only

package hub_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"testing"

	fleetv1 "github.com/ArcForges/Contracts/go/arcforges/fleet/v1"
	"github.com/ArcForges/Contracts/go/arcforges/fleet/v1/fleetv1connect"
	foundationv1 "github.com/ArcForges/Contracts/go/arcforges/foundation/v1"
	nodev1 "github.com/ArcForges/Contracts/go/arcforges/node/v1"
	relayv1 "github.com/ArcForges/Contracts/go/arcforges/relay/v1"
	"google.golang.org/protobuf/proto"

	"github.com/ArcForges/Cloud/center/internal/fleet"
	"github.com/ArcForges/Cloud/center/internal/platform"
	"github.com/ArcForges/Cloud/center/internal/session"
)

func signedSearchFixture(path string, data []byte, matchLength uint32) []byte {
	var transcript bytes.Buffer
	transcript.WriteString("ArcForges search-scan v1\x00")
	var count uint32
	if len(data) > 0 {
		count = 1
		var length [8]byte
		binary.BigEndian.PutUint32(length[:4], uint32(len(path)))
		transcript.Write(length[:4])
		transcript.WriteString(path)
		binary.BigEndian.PutUint64(length[:], uint64(len(data)))
		transcript.Write(length[:])
		transcript.Write(data)
	}
	digest := sha256.Sum256(transcript.Bytes())
	size := uint64(transcript.Len())
	r := &nodev1.FileServiceSearchFilesResponse{
		Outcome: &nodev1.FileServiceSearchFilesResponse_Value{Value: &nodev1.FileServiceSearchFilesValue{
			Matches:        []*nodev1.FileMatch{{Path: proto.String(path), ByteOffset: proto.Uint64(0), ByteLength: proto.Uint32(matchLength)}},
			VisitedEntries: proto.Uint32(1), ScannedBytes: proto.Uint64(uint64(len(data))), SkippedFiles: proto.Uint32(0),
			Truncated: proto.Bool(false), ScanDigest: digest[:], ScanTranscriptBytes: proto.Uint64(size), ScanFileCount: proto.Uint32(count),
		}},
		Audit: &nodev1.FileAuditMetadata{Observations: []*nodev1.FileAuditObservation{{
			Kind: nodev1.FileAuditKind_FILE_AUDIT_KIND_SEARCH_TRANSCRIPT.Enum(), SizeBytes: proto.Uint64(uint64(len(data))),
			DigestInputBytes: proto.Uint64(size), ItemCount: proto.Uint32(count), Sha256: digest[:],
		}}},
	}
	result, err := proto.Marshal(r)
	if err != nil {
		panic(err)
	}
	return result
}

// Real center, authorization, PostgreSQL and signed channel; the node and
// keys are synthetic and do not read a native file.
func TestCTR06SignedSearchRangeAndAudit(t *testing.T) {
	h := routedHarness(t)
	user := h.db.Account(1)
	node := h.enrollIn(user)
	channel := h.connectFiles(node)
	issued := h.accountSession(user, session.ScopeAccount)
	answers := make(chan []byte, 1)
	calls := serve(t, node, channel, func(call *relayv1.ChannelCall) (*relayv1.ResultHeader, []byte, bool) {
		body := <-answers
		return node.node.Executed(call, body), body, true
	})
	for _, tc := range []struct {
		name    string
		mode    nodev1.FileSearchMode
		pattern string
		data    []byte
		length  uint32
		valid   bool
	}{
		{"impossible_literal", nodev1.FileSearchMode_FILE_SEARCH_MODE_LITERAL, "x", nil, 1, false},
		{"empty_regex", nodev1.FileSearchMode_FILE_SEARCH_MODE_REGEX, ".*", nil, 0, true},
		{"literal_bytes", nodev1.FileSearchMode_FILE_SEARCH_MODE_LITERAL, "x", []byte("x"), 1, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			path := "range-" + tc.name + ".txt"
			response := signedSearchFixture(path, tc.data, tc.length)
			answers <- response
			request := mustMarshal(t, &nodev1.FileServiceSearchFilesRequest{
				Path:    &nodev1.FilePath{WorkspaceId: idValue(platform.NewID()), Path: proto.String(path)},
				Pattern: proto.String(tc.pattern), Mode: tc.mode.Enum(),
			})
			reply := &fleetv1.FleetServiceSearchNodeFilesResponse{}
			h.rpc(fleetv1connect.FleetServiceSearchNodeFilesProcedure, &fleetv1.FleetServiceSearchNodeFilesRequest{
				NodeId: idValue(node.node.ID), Request: request,
			}, issued.AccessToken, reply)
			<-calls
			if tc.valid {
				if reply.GetError() != nil || !bytes.Equal(reply.GetValue().GetResponse(), response) {
					t.Fatalf("valid signed search: %v", reply)
				}
				if h.count("SELECT count(*) FROM audit.audit_event WHERE event_type='fleet.file.read' AND convert_from(payload,'UTF8')::jsonb->>'path'=$1 AND convert_from(payload,'UTF8')::jsonb->>'nodeAuditAvailable'='true'", path) != 1 {
					t.Fatal("verified search observation was not audited")
				}
			} else {
				if errorKey(reply.GetError()) != "STATE/node_unreachable" || reply.GetError().GetEffect() != foundationv1.EffectCertainty_EFFECT_CERTAINTY_DID_NOT_HAPPEN {
					t.Fatalf("impossible signed search accepted: %v", reply)
				}
				if h.count("SELECT count(*) FROM audit.audit_event WHERE event_type='fleet.file.read' AND convert_from(payload,'UTF8')::jsonb->>'path'=$1 AND convert_from(payload,'UTF8')::jsonb->>'nodeAuditAvailable'='false'", path) != 1 {
					t.Fatal("impossible search was credited with a trusted observation")
				}
			}
		})
	}
}

func signedLimitResponse(name, maximum string) []byte {
	failure := &foundationv1.ArcError{
		Category: foundationv1.ErrorCategory_ERROR_CATEGORY_RESOURCE.Enum(), Code: proto.String("too_large"),
		MessageKey: proto.String("error.resource.too_large"),
		Retry:      &foundationv1.RetryAdvice{Mode: foundationv1.RetryMode_RETRY_MODE_NEVER.Enum()},
		Effect:     foundationv1.EffectCertainty_EFFECT_CERTAINTY_DID_NOT_HAPPEN.Enum(), CorrelationId: idValue(platform.NewID()),
		Details: &foundationv1.ErrorDetails{Detail: &foundationv1.ErrorDetails_Limit{Limit: &foundationv1.LimitFailure{
			LimitName: proto.String(name), Maximum: &foundationv1.Decimal{Value: proto.String(maximum)},
		}}},
	}
	response := &nodev1.FileServiceWriteFileResponse{Outcome: &nodev1.FileServiceWriteFileResponse_Error{Error: failure}}
	result, err := proto.Marshal(response)
	if err != nil {
		panic(err)
	}
	return result
}

// A fabricated fixed bound must not settle a mutation. The positive control
// describes the node-observed existing file, whose size the center cannot know.
func TestCTR06SignedResourceLimitAndReceipt(t *testing.T) {
	h := routedHarness(t)
	user := h.db.Account(1)
	node := h.enrollIn(user)
	channel := h.connectFiles(node)
	issued := h.accountSession(user, session.ScopeAccount)
	answers := make(chan []byte, 1)
	calls := serve(t, node, channel, func(call *relayv1.ChannelCall) (*relayv1.ResultHeader, []byte, bool) {
		body := <-answers
		return node.node.Executed(call, body), body, true
	})
	for _, tc := range []struct {
		name, limit, maximum string
		valid, absent        bool
	}{
		{"false_maximum", "file_write_bytes", "3", false, false},
		{"known_small_payload", "file_write_bytes", "196608", false, false},
		{"unknown_existing_file", "file_existing_bytes", "4194304", true, false},
		{"absence_requested_existing_file", "file_existing_bytes", "4194304", true, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			command := platform.NewID()
			response := signedLimitResponse(tc.limit, tc.maximum)
			answers <- response
			inner := &nodev1.FileServiceWriteFileRequest{Meta: &foundationv1.RequestMeta{CommandId: idValue(command)},
				Path: &nodev1.FilePath{WorkspaceId: idValue(platform.NewID()), Path: proto.String("limit-" + tc.name + ".txt")},
				Data: []byte("x"), Precondition: &nodev1.FileServiceWriteFileRequest_ExpectedSha256{ExpectedSha256: make([]byte, 32)}}
			if tc.absent {
				inner.Precondition = &nodev1.FileServiceWriteFileRequest_ExpectedAbsent{ExpectedAbsent: true}
			}
			h.proveFor(issued, user, "fleet.writeNodeFile", node.node.ID)
			reply := &fleetv1.FleetServiceWriteNodeFileResponse{}
			h.rpc(fleetv1connect.FleetServiceWriteNodeFileProcedure, &fleetv1.FleetServiceWriteNodeFileRequest{
				Meta: inner.Meta, NodeId: idValue(node.node.ID), Request: mustMarshal(t, inner),
			}, issued.AccessToken, reply)
			<-calls
			record, err := fleet.ReadRoutedForMethod(context.Background(), h.db.Runtime, user, command, int16(relayv1.RoutedMethod_ROUTED_METHOD_WRITE_NODE_FILE))
			if err != nil || record == nil || record.Final {
				t.Fatalf("non-final receipt required: %+v %v", record, err)
			}
			if tc.valid {
				if reply.GetError() != nil || !bytes.Equal(reply.GetValue().GetResponse(), response) || record.State != fleet.RoutedFailed {
					t.Fatalf("valid signed node-observed limit: reply=%v receipt=%+v", reply, record)
				}
				if h.count("SELECT count(*) FROM audit.audit_event WHERE event_type='fleet.routed.result' AND command_id=$1 AND (convert_from(payload,'UTF8')::jsonb->>'refusal')::int=$2", command, fleet.RefusalCode("resource/too_large")) != 1 {
					t.Fatal("valid refusal absent from audit")
				}
			} else {
				if errorKey(reply.GetError()) != "STATE/node_unreachable" || reply.GetError().GetEffect() != foundationv1.EffectCertainty_EFFECT_CERTAINTY_UNKNOWN || record.State != fleet.RoutedUnknown {
					t.Fatalf("invalid signed bound settled: reply=%v receipt=%+v", reply, record)
				}
				if h.count("SELECT count(*) FROM audit.audit_event WHERE event_type='fleet.routed.result' AND command_id=$1 AND convert_from(payload,'UTF8')::jsonb->>'nodeAuditAvailable'='false'", command) != 1 {
					t.Fatal("invalid signed limit was credited with a trusted observation")
				}
			}
		})
	}
}

// A non-growing edit cannot exceed the bound of its already bounded input;
// a growing edit may exceed it based on the node-only input size.
func TestCTR06SignedEditResultLimitAndReceipt(t *testing.T) {
	h := routedHarness(t)
	user := h.db.Account(1)
	node := h.enrollIn(user)
	channel := h.connectFiles(node)
	issued := h.accountSession(user, session.ScopeAccount)
	answers := make(chan []byte, 1)
	calls := serve(t, node, channel, func(call *relayv1.ChannelCall) (*relayv1.ResultHeader, []byte, bool) {
		body := <-answers
		return node.node.Executed(call, body), body, true
	})
	for _, tc := range []struct {
		name, replacement string
		valid             bool
	}{
		{"non_growing", "x", false},
		{"growing_unknown_input", "xx", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			command := platform.NewID()
			var write nodev1.FileServiceWriteFileResponse
			if err := proto.Unmarshal(signedLimitResponse("file_edit_result_bytes", "4194304"), &write); err != nil {
				t.Fatal(err)
			}
			response := mustMarshal(t, &nodev1.FileServiceEditFileResponse{Outcome: &nodev1.FileServiceEditFileResponse_Error{Error: write.GetError()}})
			answers <- response
			inner := &nodev1.FileServiceEditFileRequest{Meta: &foundationv1.RequestMeta{CommandId: idValue(command)},
				Path:    &nodev1.FilePath{WorkspaceId: idValue(platform.NewID()), Path: proto.String("edit-" + tc.name + ".txt")},
				OldText: proto.String("x"), NewText: proto.String(tc.replacement), ExpectedOccurrences: proto.Uint32(1), ExpectedSha256: make([]byte, 32)}
			h.proveFor(issued, user, "fleet.editNodeFile", node.node.ID)
			reply := &fleetv1.FleetServiceEditNodeFileResponse{}
			h.rpc(fleetv1connect.FleetServiceEditNodeFileProcedure, &fleetv1.FleetServiceEditNodeFileRequest{
				Meta: inner.Meta, NodeId: idValue(node.node.ID), Request: mustMarshal(t, inner),
			}, issued.AccessToken, reply)
			<-calls
			record, err := fleet.ReadRoutedForMethod(context.Background(), h.db.Runtime, user, command, int16(relayv1.RoutedMethod_ROUTED_METHOD_EDIT_NODE_FILE))
			if err != nil || record == nil || record.Final {
				t.Fatalf("non-final receipt required: %+v %v", record, err)
			}
			if tc.valid {
				if reply.GetError() != nil || !bytes.Equal(reply.GetValue().GetResponse(), response) || record.State != fleet.RoutedFailed {
					t.Fatalf("valid node-observed growing result: reply=%v receipt=%+v", reply, record)
				}
				if h.count("SELECT count(*) FROM audit.audit_event WHERE event_type='fleet.routed.result' AND command_id=$1 AND (convert_from(payload,'UTF8')::jsonb->>'refusal')::int=$2", command, fleet.RefusalCode("resource/too_large")) != 1 {
					t.Fatal("valid refusal absent from audit")
				}
			} else {
				if errorKey(reply.GetError()) != "STATE/node_unreachable" || reply.GetError().GetEffect() != foundationv1.EffectCertainty_EFFECT_CERTAINTY_UNKNOWN || record.State != fleet.RoutedUnknown {
					t.Fatalf("impossible result limit settled: reply=%v receipt=%+v", reply, record)
				}
				if h.count("SELECT count(*) FROM audit.audit_event WHERE event_type='fleet.routed.result' AND command_id=$1 AND convert_from(payload,'UTF8')::jsonb->>'nodeAuditAvailable'='false'", command) != 1 {
					t.Fatal("invalid signed edit was credited with a trusted observation")
				}
			}
		})
	}
}
