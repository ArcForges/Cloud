// SPDX-License-Identifier: AGPL-3.0-only

package fleetapi

import (
	"bytes"
	"crypto/sha256"
	"testing"

	foundationv1 "github.com/ArcForges/Contracts/go/arcforges/foundation/v1"
	nodev1 "github.com/ArcForges/Contracts/go/arcforges/node/v1"
	relayv1 "github.com/ArcForges/Contracts/go/arcforges/relay/v1"
	"google.golang.org/protobuf/proto"

	"github.com/ArcForges/Cloud/center/internal/fleet"
	"github.com/ArcForges/Cloud/center/internal/platform"
)

func TestCTR06FileReplayBindsTheSpecificAgentSession(t *testing.T) {
	node, user, command := platform.NewID(), platform.NewID(), platform.NewID()
	payload := marshal(t, &nodev1.FileServiceWriteFileRequest{Meta: &foundationv1.RequestMeta{CommandId: pid(command)}})
	caller := fleet.RoutedCaller{Kind: fleet.RoutedCallerRelay, RelayingNodeID: node, LocalOrigin: 3, LocalSessionID: platform.NewID()}
	first, err := recordDigest(relayv1.RoutedMethod_ROUTED_METHOD_WRITE_NODE_FILE, node, caller, user, payload)
	if err != nil {
		t.Fatal(err)
	}
	caller.LocalSessionID = platform.NewID()
	second, err := recordDigest(relayv1.RoutedMethod_ROUTED_METHOD_WRITE_NODE_FILE, node, caller, user, payload)
	if err != nil || bytes.Equal(first, second) {
		t.Fatal("another agent session must conflict")
	}
	// Historical task-class replay semantics stay unchanged.
	a, _ := recordDigest(relayv1.RoutedMethod_ROUTED_METHOD_SUBMIT_NODE_TASK, node, caller, user, payload)
	caller.LocalSessionID = platform.NewID()
	z, _ := recordDigest(relayv1.RoutedMethod_ROUTED_METHOD_SUBMIT_NODE_TASK, node, caller, user, payload)
	if !bytes.Equal(a, z) {
		t.Fatal("task replay semantics changed")
	}
}

func TestCTR06InnerFileBoundsAndCommandPreconditions(t *testing.T) {
	command, workspace := platform.NewID(), platform.NewID()
	path := &nodev1.FilePath{WorkspaceId: pid(workspace), Path: proto.String("a.txt")}
	makeWrite := func() *nodev1.FileServiceWriteFileRequest {
		return &nodev1.FileServiceWriteFileRequest{Meta: &foundationv1.RequestMeta{CommandId: pid(command)}, Path: path, Data: []byte{},
			Precondition: &nodev1.FileServiceWriteFileRequest_ExpectedAbsent{ExpectedAbsent: true}}
	}
	base := makeWrite()
	if _, err := checkInner(relayv1.RoutedMethod_ROUTED_METHOD_WRITE_NODE_FILE, marshal(t, base), &command); err != nil {
		t.Fatal(err)
	}
	for name, change := range map[string]func(*nodev1.FileServiceWriteFileRequest){
		"oversize": func(v *nodev1.FileServiceWriteFileRequest) { v.Data = make([]byte, 196609) },
		"false absent": func(v *nodev1.FileServiceWriteFileRequest) {
			v.Precondition = &nodev1.FileServiceWriteFileRequest_ExpectedAbsent{}
		},
		"short hash": func(v *nodev1.FileServiceWriteFileRequest) {
			v.Precondition = &nodev1.FileServiceWriteFileRequest_ExpectedSha256{ExpectedSha256: []byte{1}}
		},
		"missing precondition": func(v *nodev1.FileServiceWriteFileRequest) { v.Precondition = nil },
		"other command":        func(v *nodev1.FileServiceWriteFileRequest) { v.Meta.CommandId = pid(platform.NewID()) },
	} {
		t.Run(name, func(t *testing.T) {
			v := makeWrite()
			change(v)
			if _, err := checkInner(relayv1.RoutedMethod_ROUTED_METHOD_WRITE_NODE_FILE, marshal(t, v), &command); err == nil {
				t.Fatal("invalid mutation admitted")
			}
		})
	}
	read := &nodev1.FileServiceReadFileRequest{Meta: &foundationv1.RequestMeta{CommandId: pid(command)}, Path: path, Offset: proto.Uint64(0), Length: proto.Uint64(1)}
	if _, err := checkInner(relayv1.RoutedMethod_ROUTED_METHOD_READ_NODE_FILE, marshal(t, read), nil); err == nil {
		t.Fatal("read accepted a command")
	}
	read.Meta = nil
	read.Length = proto.Uint64(^uint64(0))
	if _, err := checkInner(relayv1.RoutedMethod_ROUTED_METHOD_READ_NODE_FILE, marshal(t, read), nil); err != nil {
		t.Fatal("large reads must permit bounded prefix at target", err)
	}
}

func TestCTR06SignedAuditMetadataIsBoundedAndOutcomeDigested(t *testing.T) {
	method := relayv1.RoutedMethod_ROUTED_METHOD_READ_NODE_FILE
	data := []byte("one")
	sum := sha256.Sum256(data)
	value := &nodev1.FileServiceReadFileResponse{Outcome: &nodev1.FileServiceReadFileResponse_Value{Value: &nodev1.FileServiceReadFileValue{
		Data: data, Offset: proto.Uint64(0), NextOffset: proto.Uint64(3), Eof: proto.Bool(true), Sha256: sum[:], FileSize: proto.Uint64(3)}},
		Audit: &nodev1.FileAuditMetadata{Observations: []*nodev1.FileAuditObservation{{Kind: nodev1.FileAuditKind_FILE_AUDIT_KIND_READ_BYTES.Enum(),
			SizeBytes: proto.Uint64(3), DigestInputBytes: proto.Uint64(3), Sha256: sum[:]}}}}
	first := marshal(t, value)
	if _, err := decodeFileResponse(method, first); err != nil {
		t.Fatal(err)
	}
	before, _ := OutcomeDigest(first)
	value.Audit.Observations[0].Sha256 = make([]byte, 32)
	after, _ := OutcomeDigest(marshal(t, value))
	if bytes.Equal(before, after) {
		t.Fatal("signed audit digest omitted from replay comparison")
	}
	value.Audit.Observations = append(value.Audit.Observations, value.Audit.Observations[0])
	if _, err := decodeFileResponse(method, marshal(t, value)); err == nil {
		t.Fatal("duplicate audit kind accepted")
	}
	value.Outcome = nil
	if _, err := decodeFileResponse(method, marshal(t, value)); err == nil {
		t.Fatal("missing outcome accepted")
	}
}
