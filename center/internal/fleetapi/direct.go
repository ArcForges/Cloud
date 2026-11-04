// SPDX-License-Identifier: AGPL-3.0-only

package fleetapi

import (
	"context"

	fleetv1 "github.com/ArcForges/Contracts/go/arcforges/fleet/v1"
	foundationv1 "github.com/ArcForges/Contracts/go/arcforges/foundation/v1"

	"github.com/ArcForges/Cloud/center/internal/fleet"
	"github.com/ArcForges/Cloud/center/internal/ingress"
	"github.com/ArcForges/Cloud/center/internal/platform"
)

// Direct is the in-process view of the four account methods of the fleet surface, for the /connect and /activate pages (AF-CTR-04
// E3): the same functions the Connect methods run (the operation table, the domain call, the receipt and the entry choreography of
// a device decision), returning the domain values the pages render (the stored node key, for its fingerprint, is no field of the
// contract's views) and the ArcError of a failure as the Connect reply would carry it. The caller passes an ingress.Call with the
// method's own policy and the cookie session's caller, so the page and the API take one decision.
type Direct struct{ s *Server }

// Direct is the in-process view of the server's account methods.
func (s *Server) Direct() *Direct { return &Direct{s} }

// Account is the account a node will join as the consent pages show it (fleet.Service.Summary).
func (d *Direct) Account(ctx context.Context, userID platform.ID) (fleet.AccountSummary, error) {
	return d.s.fleet.Summary(ctx, userID)
}

// GetNodeSignInFlow is NodeEnrollmentService.GetNodeSignInFlow.
func (d *Direct) GetNodeSignInFlow(ctx context.Context, call *ingress.Call, message *fleetv1.NodeEnrollmentServiceGetNodeSignInFlowRequest) (fleet.FlowView, *foundationv1.ArcError) {
	view, err := d.s.reviewFlow(ctx, call, message)
	return view, d.s.failure(ctx, call, err)
}

// ApproveNodeSignIn is NodeEnrollmentService.ApproveNodeSignIn.
func (d *Direct) ApproveNodeSignIn(ctx context.Context, call *ingress.Call, message *fleetv1.NodeEnrollmentServiceApproveNodeSignInRequest) (fleet.Decision, *foundationv1.ArcError) {
	decision, err := d.s.decideFlow(ctx, call, message)
	return decision, d.s.failure(ctx, call, err)
}

// LookupDeviceCode is NodeEnrollmentService.LookupDeviceCode.
func (d *Direct) LookupDeviceCode(ctx context.Context, call *ingress.Call, message *fleetv1.NodeEnrollmentServiceLookupDeviceCodeRequest) (fleet.DeviceView, *foundationv1.ArcError) {
	view, err := d.s.lookup(ctx, call, message)
	return view, d.s.failure(ctx, call, err)
}

// ApproveDeviceCode is NodeEnrollmentService.ApproveDeviceCode with the fingerprint tail the /activate page asks for (the last group of
// the node key's fingerprint, typed by the person who approves; nil for a denial). The tail is checked inside the decision, before
// any step-up evidence is consumed, and it joins the receipt's request digest.
func (d *Direct) ApproveDeviceCode(ctx context.Context, call *ingress.Call, message *fleetv1.NodeEnrollmentServiceApproveDeviceCodeRequest,
	tail *string) (*fleetv1.NodeEnrollmentServiceApproveDeviceCodeValue, *foundationv1.ArcError) {
	value, err := d.s.decideDevice(ctx, call, message, tail)
	return value, d.s.failure(ctx, call, err)
}

// ReviewedDevice reads, without counting a lookup or writing anything, the authorization a user code names when the calling account
// reviewed it within the review window (fleet.Service.ReviewedDevice). The /activate decision page calls it only after
// ApproveDeviceCode answered AUTHENTICATION/step_up_required or a fingerprint tail mismatch, both of which the decision gives only
// after its review check passed, to show the review again without a second LookupDeviceCode (E2 NB-9). call is the decision's call.
func (d *Direct) ReviewedDevice(ctx context.Context, call *ingress.Call, meta *foundationv1.RequestMeta, raw string) (fleet.DeviceView, *foundationv1.ArcError) {
	view, err := func() (fleet.DeviceView, error) {
		_, account, err := d.s.account(ctx, call, meta)
		if err != nil {
			return fleet.DeviceView{}, err
		}
		code, err := userCode(true, raw)
		if err != nil {
			return fleet.DeviceView{}, err
		}
		return d.s.fleet.ReviewedDevice(ctx, account, code)
	}()
	return view, d.s.failure(ctx, call, err)
}
