// SPDX-License-Identifier: AGPL-3.0-only

package fleetapi

import (
	"crypto/sha256"
	"testing"

	foundationv1 "github.com/ArcForges/Contracts/go/arcforges/foundation/v1"
	nodev1 "github.com/ArcForges/Contracts/go/arcforges/node/v1"
	relayv1 "github.com/ArcForges/Contracts/go/arcforges/relay/v1"
	"google.golang.org/protobuf/proto"

	"github.com/ArcForges/Cloud/center/internal/platform"
)

func TestCTR06MalformedSignedResponseNeverSettlesSuccess(t *testing.T) {
	command, workspace, plan := platform.NewID(), platform.NewID(), platform.NewID()
	path := &nodev1.FilePath{WorkspaceId: pid(workspace), Path: proto.String("p")}
	readReq := marshal(t, &nodev1.FileServiceReadFileRequest{Path: path, Offset: proto.Uint64(0), Length: proto.Uint64(4)})
	readData := []byte("a")
	readHash := sha256.Sum256(readData)
	read := &nodev1.FileServiceReadFileResponse{Outcome: &nodev1.FileServiceReadFileResponse_Value{Value: &nodev1.FileServiceReadFileValue{
		Data: readData, Offset: proto.Uint64(0), NextOffset: proto.Uint64(1), Eof: proto.Bool(true), FileSize: proto.Uint64(100), Sha256: readHash[:]}},
		Audit: &nodev1.FileAuditMetadata{Observations: []*nodev1.FileAuditObservation{{Kind: nodev1.FileAuditKind_FILE_AUDIT_KIND_READ_BYTES.Enum(), SizeBytes: proto.Uint64(1), DigestInputBytes: proto.Uint64(1), Sha256: readHash[:]}}}}
	writeReq := marshal(t, &nodev1.FileServiceWriteFileRequest{Meta: &foundationv1.RequestMeta{CommandId: pid(command)}, Path: path, Data: readData,
		Precondition: &nodev1.FileServiceWriteFileRequest_ExpectedAbsent{ExpectedAbsent: true}})
	write := &nodev1.FileServiceWriteFileResponse{Outcome: &nodev1.FileServiceWriteFileResponse_Value{Value: &nodev1.FileServiceWriteFileValue{Result: &nodev1.FileMutationResult{
		CommandId: pid(platform.NewID()), SizeBytes: proto.Uint64(1), Sha256: readHash[:]}}}, Audit: &nodev1.FileAuditMetadata{Observations: []*nodev1.FileAuditObservation{{
		Kind: nodev1.FileAuditKind_FILE_AUDIT_KIND_WRITTEN_BYTES.Enum(), SizeBytes: proto.Uint64(1), DigestInputBytes: proto.Uint64(1), Sha256: readHash[:]}}}}
	removeReq := marshal(t, &nodev1.FileServiceExecuteRemovalRequest{Meta: &foundationv1.RequestMeta{CommandId: pid(command)}, PlanId: pid(plan), PlanDigest: make([]byte, 32)})
	remove := &nodev1.FileServiceExecuteRemovalResponse{Outcome: &nodev1.FileServiceExecuteRemovalResponse_Value{Value: &nodev1.FileServiceExecuteRemovalValue{}}}
	emptyErr := &nodev1.FileServiceReadFileResponse{Outcome: &nodev1.FileServiceReadFileResponse_Error{Error: &foundationv1.ArcError{}}}
	scanReq := marshal(t, &nodev1.FileServiceSearchFilesRequest{Path: path, Pattern: proto.String("a"), Mode: nodev1.FileSearchMode_FILE_SEARCH_MODE_LITERAL.Enum()})
	scanHash := sha256.Sum256([]byte("ArcForges search-scan v1\x00"))
	scan := &nodev1.FileServiceSearchFilesResponse{Outcome: &nodev1.FileServiceSearchFilesResponse_Value{Value: &nodev1.FileServiceSearchFilesValue{
		VisitedEntries: proto.Uint32(0), ScannedBytes: proto.Uint64(0), SkippedFiles: proto.Uint32(0), Truncated: proto.Bool(false), ScanDigest: scanHash[:],
		ScanTranscriptBytes: proto.Uint64(uint64(len("ArcForges search-scan v1\x00"))), ScanFileCount: proto.Uint32(0)}}, Audit: &nodev1.FileAuditMetadata{
		Observations: []*nodev1.FileAuditObservation{{Kind: nodev1.FileAuditKind_FILE_AUDIT_KIND_SEARCH_TRANSCRIPT.Enum(), SizeBytes: proto.Uint64(0),
			DigestInputBytes: proto.Uint64(uint64(len("ArcForges search-scan v1\x00"))), ItemCount: proto.Uint32(0), Sha256: make([]byte, 32)}}}}
	for _, tc := range []struct {
		name     string
		method   relayv1.RoutedMethod
		request  []byte
		response proto.Message
		mutation bool
	}{
		{"read impossible EOF", relayv1.RoutedMethod_ROUTED_METHOD_READ_NODE_FILE, readReq, read, false},
		{"write different command", relayv1.RoutedMethod_ROUTED_METHOD_WRITE_NODE_FILE, writeReq, write, true},
		{"empty removal", relayv1.RoutedMethod_ROUTED_METHOD_EXECUTE_NODE_REMOVAL, removeReq, remove, true},
		{"empty error", relayv1.RoutedMethod_ROUTED_METHOD_READ_NODE_FILE, readReq, emptyErr, false},
		{"search digest differs", relayv1.RoutedMethod_ROUTED_METHOD_SEARCH_NODE_FILES, scanReq, scan, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			wire := marshal(t, tc.response)
			if _, err := decodeFileResponse(tc.method, wire, tc.request); err == nil {
				t.Fatal("malformed response accepted")
			}
			if tc.mutation {
				answer := answerOf(tc.method, RoutedResult{Outcome: relayv1.RoutedOutcome_ROUTED_OUTCOME_EXECUTED, Response: wire}, nil, tc.request)
				if !answer.HandlerError || answer.Effect != foundationv1.EffectCertainty_EFFECT_CERTAINTY_UNKNOWN || answer.ComparableReplay() {
					t.Fatalf("not conservative: %+v", answer)
				}
			}
		})
	}
	// The same empty scan is valid when the node's signed observation agrees.
	scan.Audit.Observations[0].Sha256 = scanHash[:]
	if _, err := decodeFileResponse(relayv1.RoutedMethod_ROUTED_METHOD_SEARCH_NODE_FILES, marshal(t, scan), scanReq); err != nil {
		t.Fatalf("valid empty scan: %v", err)
	}
}
