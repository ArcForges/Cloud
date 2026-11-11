// SPDX-License-Identifier: AGPL-3.0-only

package hub_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"os"
	"path/filepath"
	"testing"
	"time"

	fleetv1 "github.com/ArcForges/Contracts/go/arcforges/fleet/v1"
	"github.com/ArcForges/Contracts/go/arcforges/fleet/v1/fleetv1connect"
	foundationv1 "github.com/ArcForges/Contracts/go/arcforges/foundation/v1"
	nodev1 "github.com/ArcForges/Contracts/go/arcforges/node/v1"
	relayv1 "github.com/ArcForges/Contracts/go/arcforges/relay/v1"
	"google.golang.org/protobuf/proto"

	"github.com/ArcForges/Cloud/center/internal/config"
	"github.com/ArcForges/Cloud/center/internal/fleet"
	"github.com/ArcForges/Cloud/center/internal/nodetest"
	"github.com/ArcForges/Cloud/center/internal/platform"
	"github.com/ArcForges/Cloud/center/internal/session"
)

// Actual center, authenticated ingress, PG and signed channel; the node/key
// are isolated test fixtures and do not perform native filesystem operations.
func TestCTR06SlowSignedNodeReplyFitsFileDeadline(t *testing.T) {
	h := routedHarness(t)
	user := h.db.Account(1)
	node := h.enrollIn(user)
	channel := h.connectFiles(node)
	issued := h.accountSession(user, session.ScopeAccount)
	data := []byte("x")
	digest := sha256.Sum256(data)
	response := mustMarshal(t, &nodev1.FileServiceReadFileResponse{
		Outcome: &nodev1.FileServiceReadFileResponse_Value{Value: &nodev1.FileServiceReadFileValue{
			Data: data, Offset: proto.Uint64(0), NextOffset: proto.Uint64(1), Eof: proto.Bool(true), FileSize: proto.Uint64(1), Sha256: digest[:],
		}},
		Audit: &nodev1.FileAuditMetadata{Observations: []*nodev1.FileAuditObservation{{
			Kind: nodev1.FileAuditKind_FILE_AUDIT_KIND_READ_BYTES.Enum(), SizeBytes: proto.Uint64(1), DigestInputBytes: proto.Uint64(1), Sha256: digest[:],
		}}},
	})
	calls := serve(t, node, channel, func(call *relayv1.ChannelCall) (*relayv1.ResultHeader, []byte, bool) {
		time.Sleep(9500 * time.Millisecond)
		return node.node.Executed(call, response), response, true
	})
	payload := mustMarshal(t, &nodev1.FileServiceReadFileRequest{
		Path:   &nodev1.FilePath{WorkspaceId: idValue(platform.NewID()), Path: proto.String("fixture.txt")},
		Offset: proto.Uint64(0), Length: proto.Uint64(1),
	})
	reply := &fleetv1.FleetServiceReadNodeFileResponse{}
	start := time.Now()
	h.rpc(fleetv1connect.FleetServiceReadNodeFileProcedure, &fleetv1.FleetServiceReadNodeFileRequest{NodeId: idValue(node.node.ID), Request: payload}, issued.AccessToken, reply)
	elapsed := time.Since(start)
	if reply.GetError() != nil || !bytes.Equal(reply.GetValue().GetResponse(), response) {
		t.Fatalf("slow signed response failed: %v", reply.GetError())
	}
	if elapsed < 9*time.Second || elapsed >= 15*time.Second {
		t.Fatalf("unexpected end-to-end duration: %v", elapsed)
	}
	call := <-calls
	var header relayv1.CallHeader
	if err := proto.Unmarshal(call.GetHeader().GetHeader(), &header); err != nil {
		t.Fatal(err)
	}
	if header.GetDeadline().GetUnixSeconds()-header.GetIssuedAt().GetUnixSeconds() != 14 {
		t.Fatalf("expected 14-second hub budget inside the 15-second Fleet deadline: %v", &header)
	}
}

// A real composed center emits a bounded outer Fleet error before any node
// frame. A 450.1 SDK consumer can validate the exact captured wire response.
func TestCTR06OuterTooLargeRefusesBeforeNodeFrame(t *testing.T) {
	h := routedHarness(t)
	user := h.db.Account(1)
	node := h.enrollIn(user)
	channel := h.connectFiles(node)
	issued := h.accountSession(user, session.ScopeAccount)
	command := platform.NewID()
	calls := serve(t, node, channel, func(call *relayv1.ChannelCall) (*relayv1.ResultHeader, []byte, bool) {
		return nil, nil, false
	})
	payload := mustMarshal(t, &nodev1.FileServiceWriteFileRequest{
		Meta: &foundationv1.RequestMeta{CommandId: idValue(command)},
		Path: &nodev1.FilePath{WorkspaceId: idValue(platform.NewID()), Path: proto.String("fixture.txt")},
		Data: make([]byte, 196609), Precondition: &nodev1.FileServiceWriteFileRequest_ExpectedAbsent{ExpectedAbsent: true},
	})
	request := &fleetv1.FleetServiceWriteNodeFileRequest{Meta: &foundationv1.RequestMeta{CommandId: idValue(command)}, NodeId: idValue(node.node.ID), Request: payload}
	wire, err := (nodetest.Client{URL: h.url, ClientIPHeader: config.ClientIPHeader}).Post(fleetv1connect.FleetServiceWriteNodeFileProcedure, request, issued.AccessToken)
	if err != nil {
		t.Fatal(err)
	}
	reply := &fleetv1.FleetServiceWriteNodeFileResponse{}
	if _, err := nodetest.Decode(wire, reply); err != nil {
		t.Fatal(err)
	}
	failure := reply.GetError()
	if errorKey(failure) != "RESOURCE/too_large" || failure.GetEffect() != foundationv1.EffectCertainty_EFFECT_CERTAINTY_DID_NOT_HAPPEN ||
		failure.GetRetry().GetMode() != foundationv1.RetryMode_RETRY_MODE_NEVER ||
		failure.GetDetails().GetLimit().GetLimitName() != "file_write_bytes" ||
		failure.GetDetails().GetLimit().GetMaximum().GetValue() != "196608" {
		t.Fatalf("wrong outer refusal: %v", failure)
	}
	select {
	case call := <-calls:
		t.Fatalf("oversized request reached node: %v", call)
	default:
	}
	if h.count("SELECT count(*) FROM fleet.routed_file_call WHERE account_id=$1 AND command_id=$2", user, command) != 0 {
		t.Fatal("oversized request created a mutation receipt")
	}
	if directory := os.Getenv("ARCFORGES_CTR06_CONSUMER_CAPTURE"); directory != "" {
		if err := os.WriteFile(filepath.Join(directory, "outer-too-large.bin"), wire.Body, 0o600); err != nil {
			t.Fatal(err)
		}
	}
}

// A software-key node signs the actual inner refusal. The pending six-method
// Design erratum must be independently approved before this WIP can ship.
func TestCTR06SignedReadChangedResponseAndAudit(t *testing.T) {
	h := routedHarness(t)
	user := h.db.Account(1)
	node := h.enrollIn(user)
	channel := h.connectFiles(node)
	issued := h.accountSession(user, session.ScopeAccount)
	observed := []byte("PRIVATE-READ-CHANGE-MARKER")
	digest := sha256.Sum256(observed)
	failure := &foundationv1.ArcError{Category: foundationv1.ErrorCategory_ERROR_CATEGORY_CONFLICT.Enum(), Code: proto.String("file_changed"),
		MessageKey: proto.String("error.conflict.file_changed"), Retry: &foundationv1.RetryAdvice{Mode: foundationv1.RetryMode_RETRY_MODE_NEVER.Enum()},
		Effect: foundationv1.EffectCertainty_EFFECT_CERTAINTY_DID_NOT_HAPPEN.Enum(), CorrelationId: idValue(platform.NewID()),
		Details: &foundationv1.ErrorDetails{Detail: &foundationv1.ErrorDetails_State{State: &foundationv1.StateFailure{
			State: proto.String("file"), Reason: proto.String("file_changed_while_reading")}}}}
	response := mustMarshal(t, &nodev1.FileServiceReadFileResponse{Outcome: &nodev1.FileServiceReadFileResponse_Error{Error: failure},
		Audit: &nodev1.FileAuditMetadata{Observations: []*nodev1.FileAuditObservation{{Kind: nodev1.FileAuditKind_FILE_AUDIT_KIND_READ_BYTES.Enum(),
			SizeBytes: proto.Uint64(uint64(len(observed))), DigestInputBytes: proto.Uint64(uint64(len(observed))), Sha256: digest[:]}}}})
	calls := serve(t, node, channel, func(call *relayv1.ChannelCall) (*relayv1.ResultHeader, []byte, bool) {
		return node.node.Executed(call, response), response, true
	})
	request := mustMarshal(t, &nodev1.FileServiceReadFileRequest{Path: &nodev1.FilePath{WorkspaceId: idValue(platform.NewID()), Path: proto.String("changed.txt")},
		Offset: proto.Uint64(0), Length: proto.Uint64(100)})
	reply := &fleetv1.FleetServiceReadNodeFileResponse{}
	h.rpc(fleetv1connect.FleetServiceReadNodeFileProcedure, &fleetv1.FleetServiceReadNodeFileRequest{NodeId: idValue(node.node.ID), Request: request}, issued.AccessToken, reply)
	<-calls
	if reply.GetError() != nil || !bytes.Equal(reply.GetValue().GetResponse(), response) {
		t.Fatalf("signed read refusal was not forwarded unchanged: %v", reply.GetError())
	}
	if h.count("SELECT count(*) FROM audit.audit_event WHERE event_type='fleet.file.read' AND reason='refused' AND convert_from(payload,'UTF8')::jsonb->>'path'='changed.txt' AND convert_from(payload,'UTF8')::jsonb->>'nodeAuditAvailable'='true'") != 1 {
		t.Fatal("signed read refusal observation was not audited")
	}
	if h.count("SELECT count(*) FROM audit.audit_event WHERE convert_from(payload,'UTF8') LIKE '%PRIVATE-READ-CHANGE-MARKER%'") != 0 {
		t.Fatal("file content leaked to audit")
	}
	if directory := os.Getenv("ARCFORGES_CTR06_CONSUMER_CAPTURE"); directory != "" {
		if err := os.WriteFile(filepath.Join(directory, "inner-read-changed.bin"), reply.GetValue().GetResponse(), 0o600); err != nil {
			t.Fatal(err)
		}
	}
}

// Invalid method/precondition/reason combinations are truly signed by the
// software-key node and must not become successful or final PG receipts.
func TestCTR06SignedContradictoryFileErrorsRemainUnknown(t *testing.T) {
	h := routedHarness(t)
	user := h.db.Account(1)
	node := h.enrollIn(user)
	channel := h.connectFiles(node)
	issued := h.accountSession(user, session.ScopeAccount)
	responses := make(chan []byte, 1)
	calls := serve(t, node, channel, func(call *relayv1.ChannelCall) (*relayv1.ResultHeader, []byte, bool) {
		replyBytes := <-responses
		return node.node.Executed(call, replyBytes), replyBytes, true
	})
	for _, tc := range []struct {
		name, code, reason string
		category           foundationv1.ErrorCategory
		absent             bool
	}{
		{"hash_for_absence", "file_changed", "hash_mismatch", foundationv1.ErrorCategory_ERROR_CATEGORY_CONFLICT, true},
		{"absence_for_hash", "file_changed", "expected_absent_conflict", foundationv1.ErrorCategory_ERROR_CATEGORY_CONFLICT, false},
		{"native_reason", "file_access_denied", "native_13", foundationv1.ErrorCategory_ERROR_CATEGORY_STATE, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			command := platform.NewID()
			category := "conflict"
			if tc.category == foundationv1.ErrorCategory_ERROR_CATEGORY_STATE {
				category = "state"
			}
			failure := &foundationv1.ArcError{Category: tc.category.Enum(), Code: proto.String(tc.code), MessageKey: proto.String("error." + category + "." + tc.code),
				Retry: &foundationv1.RetryAdvice{Mode: foundationv1.RetryMode_RETRY_MODE_NEVER.Enum()}, Effect: foundationv1.EffectCertainty_EFFECT_CERTAINTY_DID_NOT_HAPPEN.Enum(),
				CorrelationId: idValue(platform.NewID()), Details: &foundationv1.ErrorDetails{Detail: &foundationv1.ErrorDetails_State{State: &foundationv1.StateFailure{State: proto.String("file"), Reason: proto.String(tc.reason)}}}}
			responses <- mustMarshal(t, &nodev1.FileServiceWriteFileResponse{Outcome: &nodev1.FileServiceWriteFileResponse_Error{Error: failure}})
			inner := &nodev1.FileServiceWriteFileRequest{Meta: &foundationv1.RequestMeta{CommandId: idValue(command)}, Path: &nodev1.FilePath{WorkspaceId: idValue(platform.NewID()), Path: proto.String("signed-negative.txt")}, Data: []byte("x")}
			if tc.absent {
				inner.Precondition = &nodev1.FileServiceWriteFileRequest_ExpectedAbsent{ExpectedAbsent: true}
			} else {
				inner.Precondition = &nodev1.FileServiceWriteFileRequest_ExpectedSha256{ExpectedSha256: make([]byte, 32)}
			}
			payload := mustMarshal(t, inner)
			h.proveFor(issued, user, "fleet.writeNodeFile", node.node.ID)
			reply := &fleetv1.FleetServiceWriteNodeFileResponse{}
			h.rpc(fleetv1connect.FleetServiceWriteNodeFileProcedure, &fleetv1.FleetServiceWriteNodeFileRequest{Meta: inner.Meta, NodeId: idValue(node.node.ID), Request: payload}, issued.AccessToken, reply)
			<-calls
			if f := reply.GetError(); errorKey(f) != "STATE/node_unreachable" || f.GetEffect() != foundationv1.EffectCertainty_EFFECT_CERTAINTY_UNKNOWN {
				t.Fatalf("invalid signed result: %v", f)
			}
			record, err := fleet.ReadRoutedForMethod(context.Background(), h.db.Runtime, user, command, int16(relayv1.RoutedMethod_ROUTED_METHOD_WRITE_NODE_FILE))
			if err != nil || record == nil || record.State != fleet.RoutedUnknown || record.Final {
				t.Fatalf("contradictory receipt: %+v %v", record, err)
			}
			if h.count("SELECT count(*) FROM audit.audit_event WHERE event_type='fleet.routed.result' AND command_id=$1 AND convert_from(payload,'UTF8')::jsonb->>'nodeAuditAvailable'='false'", command) != 1 {
				t.Fatal("invalid signed response was credited as trusted audit")
			}
		})
	}
}

func TestCTR06EarlyOuterRefusalAuthenticatesRelayForAudit(t *testing.T) {
	h := routedHarness(t)
	user := h.db.Account(1)
	node := h.enrollIn(user)
	channel := h.connectFiles(node)
	workspace := platform.NewID()
	origin := nodev1.Origin_ORIGIN_AGENT
	actor := "node:" + node.result.InstallationID.String()
	readPayload := mustMarshal(t, &nodev1.FileServiceReadFileRequest{Path: &nodev1.FilePath{WorkspaceId: idValue(workspace), Path: proto.String("early-read.txt")}, Offset: proto.Uint64(0), Length: proto.Uint64(1)})
	readDigest := sha256.Sum256(readPayload)
	signRead := func(nonce []byte) *relayv1.RelayAssertion {
		return node.node.Assertion(publicBaseURL, nodetest.Relay{InstallationID: node.result.InstallationID, LocalOrigin: origin, LocalSession: platform.NewID(),
			Method: relayv1.RoutedMethod_ROUTED_METHOD_READ_NODE_FILE, RequestSHA256: readDigest[:], Target: &node.node.ID, Nonce: nonce})
	}
	nonces := [][]byte{nonceOf(t, channel), nonceOf(t, channel), nonceOf(t, channel), nonceOf(t, channel)}
	badMeta := func(assertion *relayv1.RelayAssertion) *fleetv1.FleetServiceReadNodeFileResponse {
		reply := &fleetv1.FleetServiceReadNodeFileResponse{}
		h.rpc(fleetv1connect.FleetServiceReadNodeFileProcedure, &fleetv1.FleetServiceReadNodeFileRequest{
			Meta: &foundationv1.RequestMeta{WorkspaceId: idValue(workspace)}, NodeId: idValue(node.node.ID), Caller: relayedCaller(node, origin),
			RelayAssertion: mustMarshal(t, assertion), Request: readPayload}, node.access, reply)
		return reply
	}
	if reply := badMeta(signRead(nonces[0])); errorKey(reply.GetError()) != "VALIDATION/invalid_argument" {
		t.Fatalf("valid relay outer meta: %v", reply)
	}
	if h.count("SELECT count(*) FROM audit.audit_event WHERE event_type='fleet.file.refused' AND actor_ref=$1 AND convert_from(payload,'UTF8')::jsonb->>'workspaceId'=$2 AND convert_from(payload,'UTF8')::jsonb->>'path'='early-read.txt'", actor, workspace.String()) != 1 {
		t.Fatal("verified relay outer-meta refusal lacked actor/target audit")
	}
	forged := signRead(nonces[1])
	forged.Signature[0] ^= 1
	if reply := badMeta(forged); errorKey(reply.GetError()) != "VALIDATION/invalid_argument" {
		t.Fatalf("forged outer meta: %v", reply)
	}
	if h.count("SELECT count(*) FROM audit.audit_event WHERE event_type='fleet.file.refused' AND actor_ref=$1 AND convert_from(payload,'UTF8')::jsonb->>'path'='early-read.txt'", actor) != 1 {
		t.Fatal("forged assertion attributed a relay actor")
	}

	command := platform.NewID()
	writePayload := mustMarshal(t, &nodev1.FileServiceWriteFileRequest{Meta: &foundationv1.RequestMeta{CommandId: idValue(command)},
		Path: &nodev1.FilePath{WorkspaceId: idValue(workspace), Path: proto.String("early-write.txt")}, Data: []byte("x"),
		Precondition: &nodev1.FileServiceWriteFileRequest_ExpectedAbsent{ExpectedAbsent: true}})
	writeDigest := sha256.Sum256(writePayload)
	writeAssertion := node.node.Assertion(publicBaseURL, nodetest.Relay{InstallationID: node.result.InstallationID, LocalOrigin: origin, LocalSession: platform.NewID(),
		Method: relayv1.RoutedMethod_ROUTED_METHOD_WRITE_NODE_FILE, RequestSHA256: writeDigest[:], Target: &node.node.ID, Command: &command, Nonce: nonces[2]})
	writeReply := &fleetv1.FleetServiceWriteNodeFileResponse{}
	h.rpc(fleetv1connect.FleetServiceWriteNodeFileProcedure, &fleetv1.FleetServiceWriteNodeFileRequest{Meta: &foundationv1.RequestMeta{}, NodeId: idValue(node.node.ID),
		Caller: relayedCaller(node, origin), RelayAssertion: mustMarshal(t, writeAssertion), Request: writePayload}, node.access, writeReply)
	if errorKey(writeReply.GetError()) != "VALIDATION/invalid_argument" {
		t.Fatalf("missing outer command: %v", writeReply)
	}
	if h.count("SELECT count(*) FROM audit.audit_event WHERE event_type='fleet.file.refused' AND actor_ref=$1 AND command_id IS NULL AND convert_from(payload,'UTF8')::jsonb->>'workspaceId'=$2 AND convert_from(payload,'UTF8')::jsonb->>'path'='early-write.txt'", actor, workspace.String()) != 1 {
		t.Fatal("missing command refusal lacked verified actor/target audit")
	}

	// An untrusted outer command may not be attached to an actor verified for a
	// different signed command, even when another outer metadata field fails.
	otherCommand := platform.NewID()
	writeAssertion = node.node.Assertion(publicBaseURL, nodetest.Relay{InstallationID: node.result.InstallationID, LocalOrigin: origin, LocalSession: platform.NewID(),
		Method: relayv1.RoutedMethod_ROUTED_METHOD_WRITE_NODE_FILE, RequestSHA256: writeDigest[:], Target: &node.node.ID, Command: &command, Nonce: nonces[3]})
	writeReply = &fleetv1.FleetServiceWriteNodeFileResponse{}
	h.rpc(fleetv1connect.FleetServiceWriteNodeFileProcedure, &fleetv1.FleetServiceWriteNodeFileRequest{Meta: &foundationv1.RequestMeta{CommandId: idValue(otherCommand), WorkspaceId: idValue(workspace)}, NodeId: idValue(node.node.ID),
		Caller: relayedCaller(node, origin), RelayAssertion: mustMarshal(t, writeAssertion), Request: writePayload}, node.access, writeReply)
	if errorKey(writeReply.GetError()) != "VALIDATION/invalid_argument" {
		t.Fatalf("mismatched outer command: %v", writeReply)
	}
	if h.count("SELECT count(*) FROM audit.audit_event WHERE event_type='fleet.file.refused' AND actor_ref=$1 AND command_id=$2", actor, otherCommand) != 0 {
		t.Fatal("unverified outer command attributed to actor")
	}
	if h.count("SELECT count(*) FROM fleet.routed_file_call") != 0 {
		t.Fatal("early refusals created receipts")
	}
}
