// SPDX-License-Identifier: AGPL-3.0-only

package fleetapi_test

import (
	"context"
	"testing"

	foundationv1 "github.com/ArcForges/Contracts/go/arcforges/foundation/v1"
	managementv2 "github.com/ArcForges/Contracts/go/arcforges/management/v2"
	"github.com/ArcForges/Contracts/go/arcforges/management/v2/managementv2connect"
	"google.golang.org/protobuf/proto"

	"github.com/ArcForges/Cloud/center/internal/platform"
)

// This test uses the real Center, PostgreSQL, passkey/session and enrollment
// endpoints. Protocol bindings and a lost hub's marker are database fixtures
// for the registry, not proof of a live V2 channel.
func TestManagementDevicesOwnerPresenceAndRevocation(t *testing.T) {
	h := newHarness(t, settings{surfaces: "identity,pages,fleet,relay,nodes"})
	owner, other := h.person(1), h.person(1)
	first := h.v2RegistryEnrollment(owner)
	second := h.v2RegistryEnrollment(owner)
	foreign := h.v2RegistryEnrollment(other)
	foreignID := &foundationv1.Id{Value: foreign[:]}
	inspect := func(bearer string, device platform.ID) *managementv2.DeviceServiceInspectResponse {
		t.Helper()
		return rpc(h, managementv2connect.DeviceServiceInspectProcedure,
			&managementv2.DeviceServiceInspectRequest{Meta: meta(), DeviceId: &foundationv1.Id{Value: device[:]}}, bearer,
			&managementv2.DeviceServiceInspectResponse{})
	}
	list := func(bearer string, cursor *string) *managementv2.DeviceServiceListResponse {
		t.Helper()
		return rpc(h, managementv2connect.DeviceServiceListProcedure,
			&managementv2.DeviceServiceListRequest{Meta: meta(), Limit: proto.Uint32(1), Cursor: cursor}, bearer,
			&managementv2.DeviceServiceListResponse{})
	}
	page := list(owner.bearer, nil).GetValue().GetPage()
	if len(page.GetDevices()) != 1 || page.GetNextCursor() == "" ||
		proto.Equal(page.GetDevices()[0].GetDeviceId(), foreignID) {
		t.Fatal("missing or cross-account device page")
	}
	next := list(owner.bearer, page.NextCursor).GetValue().GetPage()
	if len(next.GetDevices()) != 1 || next.GetNextCursor() != "" ||
		proto.Equal(page.GetDevices()[0].GetDeviceId(), next.GetDevices()[0].GetDeviceId()) ||
		proto.Equal(next.GetDevices()[0].GetDeviceId(), foreignID) {
		t.Fatal("the next device page is not an independent owner row")
	}
	if got := failure(list(other.bearer, page.NextCursor).GetError()); got != "VALIDATION/invalid_cursor" {
		t.Fatalf("a foreign cursor: %s", got)
	}
	for _, target := range []platform.ID{first, platform.NewID()} {
		if got := failure(inspect(other.bearer, target).GetError()); got != "STATE/not_found" {
			t.Fatalf("foreign or unavailable device: %s", got)
		}
	}

	read := inspect(owner.bearer, first).GetValue().GetDevice()
	if read == nil || read.GetPresence() != "offline" || read.GetLastSeenAt() == nil || len(read.GetCapabilities()) != 0 ||
		read.NodeEpoch != nil || read.GetRevision().GetValue() < 1 {
		t.Fatal("the enrolled device without a channel did not report offline")
	}
	if _, err := h.db.Migration.Exec(context.Background(), `UPDATE fleet.node SET connection_id=$1,
 online_since=clock_timestamp(),last_heartbeat_at=clock_timestamp() WHERE device_id=$2`, platform.NewID(), first); err != nil {
		t.Fatal(err)
	}
	stale := inspect(owner.bearer, first).GetValue().GetDevice()
	if stale == nil || stale.GetPresence() != "stale" || stale.NodeEpoch != nil || len(stale.GetCapabilities()) != 0 {
		t.Fatal("a retained channel marker established live capabilities")
	}

	revoke := func(bearer string, target platform.ID, m *foundationv1.RequestMeta) *managementv2.DeviceServiceRevokeResponse {
		t.Helper()
		return rpc(h, managementv2connect.DeviceServiceRevokeProcedure,
			&managementv2.DeviceServiceRevokeRequest{Meta: m, DeviceId: &foundationv1.Id{Value: target[:]}}, bearer,
			&managementv2.DeviceServiceRevokeResponse{})
	}
	revision := stale.GetRevision().GetValue()
	wrong := command()
	wrong.ExpectedRev = &foundationv1.Revision{Value: proto.Int64(revision + 1)}
	if got := failure(revoke(other.bearer, first, wrong).GetError()); got != "STATE/not_found" {
		t.Fatalf("foreign revocation: %s", got)
	}
	mismatch := revoke(owner.bearer, first, wrong).GetError()
	detail := mismatch.GetDetails().GetRevision()
	if failure(mismatch) != "CONFLICT/revision_mismatch" || mismatch.GetMessageKey() != "error.conflict.revision_mismatch" ||
		mismatch.GetEffect() != foundationv1.EffectCertainty_EFFECT_CERTAINTY_DID_NOT_HAPPEN ||
		detail.GetExpected().GetValue() != revision+1 || detail.GetActual().GetValue() != revision {
		t.Fatalf("stale revision: %s", failure(mismatch))
	}
	exact := command()
	exact.ExpectedRev = &foundationv1.Revision{Value: proto.Int64(revision)}
	if got := failure(revoke(owner.bearer, first, exact).GetError()); got != "AUTHENTICATION/step_up_required" {
		t.Fatalf("unproved revocation: %s", got)
	}
	h.stepUp(owner, "management.deviceRevoke", first, false)
	revoked := revoke(owner.bearer, first, exact)
	device := revoked.GetValue().GetDevice()
	if revoked.GetError() != nil || device == nil || device.GetPresence() != "revoked" ||
		device.GetRevision().GetValue() != revision+1 || !proto.Equal(revoked.GetMeta().GetResultRev(), device.GetRevision()) ||
		len(device.GetCapabilities()) != 0 || device.NodeEpoch != nil {
		t.Fatalf("revocation: %s", failure(revoked.GetError()))
	}
	if replay := revoke(owner.bearer, first, exact); !proto.Equal(replay.GetValue(), revoked.GetValue()) {
		t.Fatal("a receipt replay changed the original result")
	}
	changed := proto.Clone(exact).(*foundationv1.RequestMeta)
	changed.ExpectedRev = wrong.ExpectedRev
	if got := failure(revoke(owner.bearer, first, changed).GetError()); got != "CONFLICT/command_id_reused" {
		t.Fatalf("changed replay: %s", got)
	}
	if inspected := inspect(owner.bearer, first).GetValue().GetDevice(); !proto.Equal(inspected, device) {
		t.Fatal("inspection did not retain the revoked device")
	}
	if unaffected := inspect(owner.bearer, second).GetValue().GetDevice(); unaffected.GetPresence() != "offline" ||
		h.count(`SELECT count(*) FROM management.node_protocol p JOIN fleet.node n USING (enrollment_id) WHERE n.device_id=$1
 AND n.revoked_at IS NOT NULL AND p.revoked_at IS NOT NULL`, first) != 1 || h.audits("device.revoked") != 1 {
		t.Fatal("revocation did not fence exactly the selected enrollment")
	}

	// A backup restore retires protocol authority without deleting or revoking
	// the underlying device. Its owner must still be able to revoke the device.
	if _, err := h.db.Migration.Exec(context.Background(), `UPDATE management.node_protocol p
 SET revoked_at=greatest(clock_timestamp(),p.initialized_at),rev=p.rev+1
 FROM fleet.node n WHERE p.enrollment_id=n.enrollment_id AND n.device_id=$1`, second); err != nil {
		t.Fatal(err)
	}
	retired := inspect(owner.bearer, second).GetValue().GetDevice()
	if retired.GetPresence() != "revoked" || retired.NodeEpoch != nil || len(retired.GetCapabilities()) != 0 {
		t.Fatal("a retired protocol still advertised live device authority")
	}
	retiredCommand := command()
	retiredCommand.ExpectedRev = retired.GetRevision()
	h.stepUp(owner, "management.deviceRevoke", second, false)
	afterRestore := revoke(owner.bearer, second, retiredCommand)
	if afterRestore.GetValue().GetDevice().GetRevision().GetValue() != retired.GetRevision().GetValue()+1 ||
		h.count(`SELECT count(*) FROM device.device WHERE device_id=$1 AND revoked_at IS NOT NULL`, second) != 1 ||
		h.audits("device.revoked") != 2 {
		t.Fatalf("revocation after protocol retirement: %s", failure(afterRestore.GetError()))
	}
}

func (h *harness) v2RegistryEnrollment(owner *person) platform.ID {
	h.t.Helper()
	device := h.enrolledRegistryDevice(owner)
	if _, err := h.db.Migration.Exec(context.Background(), `INSERT INTO management.node_protocol
 (enrollment_id,node_id,account_id,protocol_major,protocol_epoch,initialized_at,rev)
 SELECT enrollment_id,node_id,user_id,2,$1,clock_timestamp(),1 FROM fleet.node WHERE device_id=$2 AND user_id=$3`,
		platform.NewID(), device, owner.id); err != nil {
		h.t.Fatal(err)
	}
	return device
}

func (h *harness) enrolledRegistryDevice(owner *person) platform.ID {
	h.t.Helper()
	signIn, refusal := h.begin()
	if refusal != nil {
		h.t.Fatalf("begin enrollment: %s", failure(refusal))
	}
	h.approve(owner, signIn, false)
	complete := h.complete(signIn)
	if complete.GetError() != nil {
		h.t.Fatalf("complete enrollment: %s", failure(complete.GetError()))
	}
	var device platform.ID
	if err := h.db.Migration.QueryRow(context.Background(), `SELECT device_id FROM fleet.node WHERE node_id=$1 AND user_id=$2`,
		signIn.node.ID, owner.id).Scan(&device); err != nil {
		h.t.Fatal(err)
	}
	return device
}

func TestManagementDeviceBeforeFirstChannel(t *testing.T) {
	h := newHarness(t, settings{surfaces: "identity,pages,fleet,relay,nodes"})
	owner := h.person(1)
	deviceID := h.enrolledRegistryDevice(owner)
	target := &foundationv1.Id{Value: deviceID[:]}
	inspect := func() *managementv2.Device {
		t.Helper()
		response := rpc(h, managementv2connect.DeviceServiceInspectProcedure,
			&managementv2.DeviceServiceInspectRequest{Meta: meta(), DeviceId: target}, owner.bearer,
			&managementv2.DeviceServiceInspectResponse{})
		device := response.GetValue().GetDevice()
		if device == nil || device.GetPresence() != "offline" || device.GetEnrollmentId() == nil ||
			device.NodeEpoch != nil || len(device.GetCapabilities()) != 0 || device.GetRevision().GetValue() < 1 {
			t.Fatalf("device without a V2 channel: %s", failure(response.GetError()))
		}
		return device
	}
	initial := inspect()
	list := rpc(h, managementv2connect.DeviceServiceListProcedure, &managementv2.DeviceServiceListRequest{Meta: meta()}, owner.bearer,
		&managementv2.DeviceServiceListResponse{}).GetValue().GetPage().GetDevices()
	if len(list) != 1 || !proto.Equal(list[0], initial) {
		t.Fatal("the account's newly enrolled device was missing from the inventory")
	}

	// A marker without protocol proof must not turn a V1 enrollment into a
	// claimed V2 channel. Never create or authenticate a socket in this test.
	if _, err := h.db.Migration.Exec(context.Background(), `UPDATE fleet.node SET connection_id=$1,
 online_since=clock_timestamp(),last_heartbeat_at=clock_timestamp() WHERE device_id=$2`, platform.NewID(), deviceID); err != nil {
		t.Fatal(err)
	}
	current := inspect()
	revokeMeta := command()
	revokeMeta.ExpectedRev = current.GetRevision()
	h.stepUp(owner, "management.deviceRevoke", deviceID, false)
	revoked := rpc(h, managementv2connect.DeviceServiceRevokeProcedure,
		&managementv2.DeviceServiceRevokeRequest{Meta: revokeMeta, DeviceId: target}, owner.bearer,
		&managementv2.DeviceServiceRevokeResponse{})
	result := revoked.GetValue().GetDevice()
	if result.GetPresence() != "revoked" || !proto.Equal(result.GetEnrollmentId(), current.GetEnrollmentId()) ||
		result.GetRevision().GetValue() != current.GetRevision().GetValue()+1 {
		t.Fatalf("owner revocation before the first channel: %s", failure(revoked.GetError()))
	}
	if h.count(`SELECT count(*) FROM identity.session s JOIN fleet.node n USING (installation_id) WHERE n.device_id=$1
 AND n.revoked_at IS NOT NULL AND s.scope=3 AND s.revoked_at IS NOT NULL`, deviceID) != 1 ||
		h.count(`SELECT count(*) FROM management.node_protocol p JOIN fleet.node n USING (enrollment_id) WHERE n.device_id=$1`,
			deviceID) != 0 {
		t.Fatal("revocation did not invalidate the enrollment and its Node credential independently of a V2 binding")
	}
}
