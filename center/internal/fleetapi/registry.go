// SPDX-License-Identifier: AGPL-3.0-only

package fleetapi

import (
	"context"
	"crypto/sha256"
	"time"

	"connectrpc.com/connect/v2"
	fleetv1 "github.com/ArcForges/Contracts/go/arcforges/fleet/v1"
	"github.com/ArcForges/Contracts/go/arcforges/fleet/v1/fleetv1connect"
	foundationv1 "github.com/ArcForges/Contracts/go/arcforges/foundation/v1"
	nodev1 "github.com/ArcForges/Contracts/go/arcforges/node/v1"
	relayv1 "github.com/ArcForges/Contracts/go/arcforges/relay/v1"
	"github.com/jackc/pgx/v5"
	"google.golang.org/protobuf/encoding/protowire"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"

	"github.com/ArcForges/Cloud/center/internal/access"
	"github.com/ArcForges/Cloud/center/internal/arc"
	"github.com/ArcForges/Cloud/center/internal/device"
	"github.com/ArcForges/Cloud/center/internal/fleet"
	"github.com/ArcForges/Cloud/center/internal/identity"
	"github.com/ArcForges/Cloud/center/internal/ingress"
	"github.com/ArcForges/Cloud/center/internal/platform"
)

// The node registry of FleetService on the nodes surface (AF-CTR-05 part E2a; Plan CTR5-API-02..04, CTR5-CALL-02, C-N6; Contracts
// fleet.proto FleetService): ListNodes and GetNode for an account session and for a node-relayed caller, RenameNode and RevokeNode for an
// account session. Every other FleetService method stays unregistered (CTR5-API-01).
//
// A node credential reads the registry only as the relay of its own node (C-N6): its request carries a routed caller and a relay
// assertion, and the authorizer itself verifies the assertion (access.Authorizer.AuthorizeRelayed with the hub's verifier; the
// assertion's request digest is SHA-256 of the request's top-level fields as transmitted, every occurrence of the relay_assertion field
// left out; Contracts relay.proto RelayAssertion) and admits the call only with a relay verified for the credential's own installation.
// A bearer token alone is refused AUTHENTICATION/unauthenticated (relay_assertion missing) before anything is read or written. An
// account session whose request names a NODE_RELAY caller or carries a relay assertion is refused AUTHORIZATION/permission_denied
// (principal), audited access.refused; a routed caller of any other kind is VALIDATION/invalid_argument (caller.kind), refused before
// authorization and not audited, whoever sends it.

// Channels tells whether a node's channel is open in this process (hub.Hub.Connected): FleetNode.online.
type Channels interface {
	Connected(nodeID platform.ID) bool
}

// RevokeDevice revokes one of the caller's devices with its cascade and audits device.revoked in the caller's transaction
// (identity.Service.RevokeDevice); it returns the device's new revision.
type RevokeDevice func(ctx context.Context, tx pgx.Tx, caller identity.Caller, deviceID platform.ID, now time.Time) (int64, error)

// Registry serves FleetService's node registry.
type Registry struct {
	*Server
	channels Channels
	revoke   RevokeDevice
}

// Registry is the node registry of this fleet server: the nodes surface's methods.
func (s *Server) Registry(channels Channels, revoke RevokeDevice) *Registry {
	return &Registry{Server: s, channels: channels, revoke: revoke}
}

// registryMethod is one served unary method of FleetService.
func registryMethod[Request any, PRequest interface {
	*Request
	proto.Message
}, Response proto.Message](name, procedure string, handle func(context.Context, *ingress.Call, PRequest) (Response, error)) connect.Method {
	served := method[Request, PRequest, Response](name, procedure, handle)
	served.Spec.Schema = fleetv1.File_arcforges_fleet_v1_fleet_proto.Services().ByName("FleetService").Methods().ByName(protoreflect.Name(name))
	return served
}

// Methods are exactly the served FleetService methods, in the order of routes.NodesMethods.
func (r *Registry) Methods() []connect.Method {
	return []connect.Method{
		registryMethod("ListNodes", fleetv1connect.FleetServiceListNodesProcedure, r.listNodes),
		registryMethod("GetNode", fleetv1connect.FleetServiceGetNodeProcedure, r.getNode),
		registryMethod("RenameNode", fleetv1connect.FleetServiceRenameNodeProcedure, r.renameNode),
		registryMethod("RevokeNode", fleetv1connect.FleetServiceRevokeNodeProcedure, r.revokeNode),
	}
}

// The field numbers of relay_assertion in the two relayed registry requests (fleet.proto).
const (
	listNodesAssertionField protowire.Number = 11
	getNodeAssertionField   protowire.Number = 12
)

// claim is what a registry read states about its relay, for the authorizer's verification (access.AuthorizeRelayed): nil when it
// states neither a routed caller nor a relay assertion; otherwise the assertion as received, the method, the request digest (SHA-256
// of the request's top-level fields as transmitted, every occurrence of the relay_assertion field left out), the target and the caller
// it names. A routed caller of another kind than NODE_RELAY is VALIDATION/invalid_argument.
func claim(call *ingress.Call, caller *fleetv1.RoutedCaller, assertion []byte, method relayv1.RoutedMethod, target *platform.ID,
	field protowire.Number) (*access.RelayClaim, error) {
	if caller == nil && assertion == nil {
		return nil, nil
	}
	if caller != nil && caller.GetKind() != fleetv1.CallerKind_CALLER_KIND_NODE_RELAY {
		return nil, arc.InvalidArgument("caller.kind", "not_admitted")
	}
	digested, err := withoutField(call.Message, field)
	if err != nil {
		return nil, arc.InvalidArgument("request", "malformed")
	}
	digest := sha256.Sum256(digested)
	relaying, _ := parseID(caller.GetRelayingNodeId())
	return &access.RelayClaim{Assertion: assertion, Method: method, RequestSHA256: digest[:], TargetNodeID: target, CallerRelayingNodeID: relaying,
		CallerLocalOrigin: caller.GetLocalOrigin()}, nil
}

// withoutField is a message's top-level fields as transmitted, in wire order and byte for byte, with every occurrence of one field
// number left out (relay.proto RelayAssertion request_sha256 for LIST_NODES and GET_NODE). A malformed message is an error.
func withoutField(message []byte, number protowire.Number) ([]byte, error) {
	out := make([]byte, 0, len(message))
	for rest := message; len(rest) > 0; {
		found, kind, tagLength := protowire.ConsumeTag(rest)
		if tagLength < 0 {
			return nil, protowire.ParseError(tagLength)
		}
		valueLength := protowire.ConsumeFieldValue(found, kind, rest[tagLength:])
		if valueLength < 0 {
			return nil, protowire.ParseError(valueLength)
		}
		if found != number {
			out = append(out, rest[:tagLength+valueLength]...)
		}
		rest = rest[tagLength+valueLength:]
	}
	return out, nil
}

// nodeSubject is the subject of a row whose Object is node: the authorizer asks for the node's owner (stage 2), so an unknown or
// foreign node is STATE/not_found before anything else is decided (nothing is written for it), and so is a revoked one for a read. A
// receipted write (receipted) also owns the caller's own revoked enrollments of the node ID, before any other account's, so the
// caller's replay reaches its receipt (fleet.NodeOwner).
func (r *Registry) nodeSubject(call *ingress.Call, nodeID platform.ID, receipted bool) *access.Subject {
	caller, _ := textID(call.Caller.UserID)
	return &access.Subject{Kind: access.ObjectNode, ID: append([]byte(nil), nodeID[:]...), Owner: func(ctx context.Context) (string, bool, error) {
		return fleet.NodeOwner(ctx, r.db, nodeID, caller, receipted)
	}}
}

// fleetNode is the contract view of a node: ONLINE while its channel is open in this process (a process that does not hold the hub
// lease has no channel, so it states every node OFFLINE or NEVER_CONNECTED), OFFLINE once a channel was accepted, NEVER_CONNECTED before.
func fleetNode(record fleet.NodeRecord, connected bool) *fleetv1.FleetNode {
	state := fleetv1.NodeOnlineState_NODE_ONLINE_STATE_NEVER_CONNECTED
	switch {
	case connected:
		state = fleetv1.NodeOnlineState_NODE_ONLINE_STATE_ONLINE
	case record.Connected:
		state = fleetv1.NodeOnlineState_NODE_ONLINE_STATE_OFFLINE
	}
	node := &fleetv1.FleetNode{NodeId: id(record.NodeID), Name: proto.String(record.Name), Os: nodev1.OsFamily(record.OS).Enum(),
		Arch: nodev1.CpuArchitecture(record.Arch).Enum(), Version: proto.String(record.Version), Online: state.Enum(), LastSeenAt: arc.Instant(record.LastSeenAt),
		EnrolledAt: arc.Instant(record.EnrolledAt), DeviceId: id(record.DeviceID), ReportedName: proto.String(record.ReportedName)}
	if record.CredentialExpiresAt != nil {
		node.CredentialExpiresAt = arc.Instant(*record.CredentialExpiresAt)
	}
	return node
}

func (r *Registry) view(record fleet.NodeRecord) *fleetv1.FleetNode {
	return fleetNode(record, r.channels != nil && r.channels.Connected(record.NodeID))
}

// requiredNode reads a request's node_id: 16 bytes that are not all zero.
func requiredNode(value *foundationv1.Id) (platform.ID, error) {
	nodeID, ok := parseID(value)
	if !ok {
		return platform.ID{}, arc.InvalidArgument("node_id", "required")
	}
	return nodeID, nil
}

func (r *Registry) listNodes(ctx context.Context, call *ingress.Call, message *fleetv1.FleetServiceListNodesRequest) (*fleetv1.FleetServiceListNodesResponse, error) {
	value, err := func() (*fleetv1.FleetServiceListNodesValue, error) {
		if err := checkMeta(message.GetMeta()); err != nil {
			return nil, err
		}
		stated, err := claim(call, message.GetCaller(), message.RelayAssertion, relayv1.RoutedMethod_ROUTED_METHOD_LIST_NODES, nil, listNodesAssertionField)
		if err != nil {
			return nil, err
		}
		if _, _, err = r.access.AuthorizeRelayed(ctx, call, nil, stated); err != nil {
			return nil, err
		}
		userID, ok := textID(call.Caller.UserID)
		if !ok {
			return nil, arc.Unauthenticated()
		}
		records, err := fleet.ListNodes(ctx, r.db, userID)
		if err != nil {
			return nil, err
		}
		value := &fleetv1.FleetServiceListNodesValue{Nodes: make([]*fleetv1.FleetNode, 0, len(records))}
		for _, record := range records {
			value.Nodes = append(value.Nodes, r.view(record))
		}
		return value, nil
	}()
	response := &fleetv1.FleetServiceListNodesResponse{Meta: ingress.ResponseMeta(call.Correlation)}
	if failure := r.failure(ctx, call, err); failure != nil {
		response.Outcome = &fleetv1.FleetServiceListNodesResponse_Error{Error: failure}
		return response, nil
	}
	response.Outcome = &fleetv1.FleetServiceListNodesResponse_Value{Value: value}
	return response, nil
}

func (r *Registry) getNode(ctx context.Context, call *ingress.Call, message *fleetv1.FleetServiceGetNodeRequest) (*fleetv1.FleetServiceGetNodeResponse, error) {
	value, err := func() (*fleetv1.FleetServiceGetNodeValue, error) {
		if err := checkMeta(message.GetMeta()); err != nil {
			return nil, err
		}
		nodeID, err := requiredNode(message.GetNodeId())
		if err != nil {
			return nil, err
		}
		stated, err := claim(call, message.GetCaller(), message.RelayAssertion, relayv1.RoutedMethod_ROUTED_METHOD_GET_NODE, &nodeID, getNodeAssertionField)
		if err != nil {
			return nil, err
		}
		if _, _, err = r.access.AuthorizeRelayed(ctx, call, r.nodeSubject(call, nodeID, false), stated); err != nil {
			return nil, err
		}
		userID, ok := textID(call.Caller.UserID)
		if !ok {
			return nil, arc.Unauthenticated()
		}
		record, err := fleet.GetNode(ctx, r.db, userID, nodeID)
		if err != nil {
			return nil, err
		}
		// recent_commands stays empty: routing records are not command views (Plan CTR5-API-02).
		return &fleetv1.FleetServiceGetNodeValue{Node: r.view(record)}, nil
	}()
	response := &fleetv1.FleetServiceGetNodeResponse{Meta: ingress.ResponseMeta(call.Correlation)}
	if failure := r.failure(ctx, call, err); failure != nil {
		response.Outcome = &fleetv1.FleetServiceGetNodeResponse_Error{Error: failure}
		return response, nil
	}
	response.Outcome = &fleetv1.FleetServiceGetNodeResponse_Value{Value: value}
	return response, nil
}

// renameNode gives a node the account's name (CTR5-API-03, Q25) under a command receipt of the account: the name follows the node
// name rule (1 to 64 characters, ValidNodeName), and the node and its device take it in one transaction (fleet.Service.Rename). The
// receipt keeps the reply, so a replay answers the node as it was renamed.
func (r *Registry) renameNode(ctx context.Context, call *ingress.Call, message *fleetv1.FleetServiceRenameNodeRequest) (*fleetv1.FleetServiceRenameNodeResponse, error) {
	value, err := func() (*fleetv1.FleetServiceRenameNodeValue, error) {
		if err := checkMeta(message.GetMeta()); err != nil {
			return nil, err
		}
		nodeID, err := requiredNode(message.GetNodeId())
		if err != nil {
			return nil, err
		}
		if _, err = r.access.AuthorizeSubject(ctx, call, r.nodeSubject(call, nodeID, true)); err != nil {
			return nil, err
		}
		account, err := accountOf(call)
		if err != nil {
			return nil, err
		}
		receiptCommand, err := accountCommand(call, account, message.GetMeta())
		if err != nil {
			return nil, err
		}
		name := message.GetName()
		switch {
		case message.Name == nil:
			return nil, arc.InvalidArgument("name", "required")
		case device.NameTooLong(name):
			return nil, arc.InvalidArgument("name", "length")
		case !device.ValidNodeName(name):
			return nil, arc.InvalidArgument("name", "pattern")
		}
		return execute(ctx, r.Server, receiptCommand, &fleetv1.FleetServiceRenameNodeValue{},
			func(ctx context.Context, tx pgx.Tx, now time.Time) (*fleetv1.FleetServiceRenameNodeValue, error) {
				record, err := r.fleet.Rename(ctx, tx, request(call), account, nodeID, name, now)
				if err != nil {
					return nil, err
				}
				return &fleetv1.FleetServiceRenameNodeValue{Node: r.view(record)}, nil
			})
	}()
	response := &fleetv1.FleetServiceRenameNodeResponse{Meta: ingress.ResponseMeta(call.Correlation)}
	if failure := r.failure(ctx, call, err); failure != nil {
		response.Outcome = &fleetv1.FleetServiceRenameNodeResponse_Error{Error: failure}
		return response, nil
	}
	response.Outcome = &fleetv1.FleetServiceRenameNodeResponse_Value{Value: value}
	return response, nil
}

// revokeNode revokes a node's device with the revocation cascade (CTR5-API-04) under a command receipt of the account: the step-up
// evidence of class fleet.revokeNode bound to the node ID is consumed first, then device.Revoke takes the device, its installations,
// its sessions and its participants' rows (the node row; the channel closes 4401 once the transaction commits), and device.revoked is
// audited, all in the receipt's transaction. Without evidence the call is AUTHENTICATION/step_up_required and nothing is written.
// Locks: the receipt row, then the account (the evidence), then the cascade's order (device, installations, sessions, node).
func (r *Registry) revokeNode(ctx context.Context, call *ingress.Call, message *fleetv1.FleetServiceRevokeNodeRequest) (*fleetv1.FleetServiceRevokeNodeResponse, error) {
	value, err := func() (*fleetv1.FleetServiceRevokeNodeValue, error) {
		if err := checkMeta(message.GetMeta()); err != nil {
			return nil, err
		}
		nodeID, err := requiredNode(message.GetNodeId())
		if err != nil {
			return nil, err
		}
		operation, err := r.access.AuthorizeSubject(ctx, call, r.nodeSubject(call, nodeID, true))
		if err != nil {
			return nil, err
		}
		account, err := accountOf(call)
		if err != nil {
			return nil, err
		}
		receiptCommand, err := accountCommand(call, account, message.GetMeta())
		if err != nil {
			return nil, err
		}
		return execute(ctx, r.Server, receiptCommand, &fleetv1.FleetServiceRevokeNodeValue{},
			func(ctx context.Context, tx pgx.Tx, now time.Time) (*fleetv1.FleetServiceRevokeNodeValue, error) {
				if operation.NeedsEvidence(false) {
					if err := identity.ConsumeEvidence(ctx, tx, account.Caller, operation.ID, nodeID, now); err != nil {
						return nil, err
					}
				}
				deviceID, err := fleet.NodeDevice(ctx, tx, account.Caller.UserID, nodeID)
				if err != nil {
					return nil, err
				}
				revision, err := r.revoke(ctx, tx, account.Caller, deviceID, now)
				if err != nil {
					return nil, err
				}
				receipt := receipt(receiptCommand)
				receipt.ResultRevision = &foundationv1.Revision{Value: proto.Int64(revision)}
				return &fleetv1.FleetServiceRevokeNodeValue{Receipt: receipt}, nil
			})
	}()
	response := &fleetv1.FleetServiceRevokeNodeResponse{Meta: ingress.ResponseMeta(call.Correlation)}
	if failure := r.failure(ctx, call, err); failure != nil {
		response.Outcome = &fleetv1.FleetServiceRevokeNodeResponse_Error{Error: failure}
		return response, nil
	}
	response.Outcome = &fleetv1.FleetServiceRevokeNodeResponse_Value{Value: value}
	return response, nil
}
