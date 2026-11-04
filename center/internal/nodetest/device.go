// SPDX-License-Identifier: AGPL-3.0-only

package nodetest

import (
	fleetv1 "github.com/ArcForges/Contracts/go/arcforges/fleet/v1"
	foundationv1 "github.com/ArcForges/Contracts/go/arcforges/foundation/v1"
	"google.golang.org/protobuf/proto"
)

// The device-code sign-in as a node runs it (AF-CTR-04 E2): StartDeviceAuthorization with its description and public key, the
// derived verification URIs it requires the center's strings to equal, and PollDeviceAuthorization with the device code and a node
// key proof of purpose 0x02.

const proofPoll = 0x02

// StartRequest is the node's StartDeviceAuthorization request.
func (n *Node) StartRequest() *fleetv1.NodeEnrollmentServiceStartDeviceAuthorizationRequest {
	return &fleetv1.NodeEnrollmentServiceStartDeviceAuthorizationRequest{Meta: &foundationv1.RequestMeta{}, Node: n.Info(),
		NodePublicKey: append([]byte(nil), n.PublicKey...)}
}

// DerivedVerificationURI is the activation page a node derives from its configured center (C0: <center>/activate).
func DerivedVerificationURI(center string) string { return center + "/activate" }

// DerivedVerificationURIComplete is the activation page with the code a node derives (C0: <center>/activate#code=XXXX-XXXX) from the
// 8 letters of the reply's user_code.
func DerivedVerificationURIComplete(center, userCode string) string {
	return center + "/activate#code=" + DisplayUserCode(userCode)
}

// DisplayUserCode is a user code as a node shows it: XXXX-XXXX (a code of another length is returned unchanged).
func DisplayUserCode(userCode string) string {
	if len(userCode) != 8 {
		return userCode
	}
	return userCode[:4] + "-" + userCode[4:]
}

// PollProof is the node key proof of a PollDeviceAuthorization: ES256 over domain || 0x02 || SHA-256(audience) || node ID ||
// device code (UTF-8, as received), the audience being the center the node is configured with, s normalized to the lower half.
func (n *Node) PollProof(audience, deviceCode string) []byte {
	return n.Sign(proofPoll, audience, []byte(deviceCode))
}

// PollRequest is the node's PollDeviceAuthorization request.
func (n *Node) PollRequest(deviceCode string, proof []byte) *fleetv1.NodeEnrollmentServicePollDeviceAuthorizationRequest {
	return &fleetv1.NodeEnrollmentServicePollDeviceAuthorizationRequest{Meta: &foundationv1.RequestMeta{}, DeviceCode: proto.String(deviceCode),
		NodeKeyProof: proof}
}
