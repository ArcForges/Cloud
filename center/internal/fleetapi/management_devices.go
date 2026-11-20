// SPDX-License-Identifier: AGPL-3.0-only

package fleetapi

import (
	"context"
	"slices"
	"time"

	"connectrpc.com/connect/v2"
	foundationv1 "github.com/ArcForges/Contracts/go/arcforges/foundation/v1"
	managementv2 "github.com/ArcForges/Contracts/go/arcforges/management/v2"
	"github.com/ArcForges/Contracts/go/arcforges/management/v2/managementv2connect"
	"github.com/jackc/pgx/v5"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"

	"github.com/ArcForges/Cloud/center/internal/arc"
	"github.com/ArcForges/Cloud/center/internal/identity"
	"github.com/ArcForges/Cloud/center/internal/ingress"
	"github.com/ArcForges/Cloud/center/internal/management"
	"github.com/ArcForges/Cloud/center/internal/platform"
)

// DeviceChannels reads only an exact, currently qualified V2 channel.
type DeviceChannels interface {
	V2Presence(account, enrollment, node, protocolEpoch platform.ID) (management.V2Presence, bool)
}

type devices struct {
	*Server
	store    *management.Store
	channels DeviceChannels
	revoke   RevokeDevice
}

// DeviceMethods serves List, Inspect and Revoke from the published V2 service.
func (s *Server) DeviceMethods(channels DeviceChannels, revoke RevokeDevice) []connect.Method {
	api := &devices{Server: s, store: management.New(s.db), channels: channels, revoke: revoke}
	return []connect.Method{
		deviceMethod("List", managementv2connect.DeviceServiceListProcedure, api.list),
		deviceMethod("Inspect", managementv2connect.DeviceServiceInspectProcedure, api.inspect),
		deviceMethod("Revoke", managementv2connect.DeviceServiceRevokeProcedure, api.revokeDevice),
	}
}

func deviceMethod[Request any, PRequest interface {
	*Request
	proto.Message
}, Response proto.Message](name, procedure string, handle func(context.Context, *ingress.Call, PRequest) (Response, error)) connect.Method {
	served := method[Request, PRequest, Response](name, procedure, handle)
	served.Spec.Schema = managementv2.File_arcforges_management_v2_devices_proto.Services().ByName("DeviceService").Methods().ByName(protoreflect.Name(name))
	return served
}

func deviceMeta(meta *foundationv1.RequestMeta) error {
	if meta == nil {
		return arc.InvalidArgument("meta", "required")
	}
	return checkMeta(meta)
}

func requiredDeviceID(value *foundationv1.Id) (platform.ID, error) {
	deviceID, ok := parseID(value)
	if !ok {
		return platform.ID{}, arc.InvalidArgument("device_id", "required")
	}
	return deviceID, nil
}

func (s *devices) view(account platform.ID, record management.DeviceRecord) *managementv2.Device {
	os := "windows"
	if record.OS == 2 {
		os = "linux"
	}
	presence := "offline"
	result := &managementv2.Device{
		DeviceId: id(record.Device), EnrollmentId: id(record.Enrollment), DisplayName: proto.String(record.Name),
		Revision: &foundationv1.Revision{Value: proto.Int64(record.Revision)},
		Platform: proto.String(os), LastSeenAt: arc.Instant(record.LastSeenAt),
	}
	switch {
	case record.DeviceRevoked || record.EnrollmentRevoked:
		presence = "revoked"
	case record.Connection != nil:
		presence = "stale"
		if s.channels != nil {
			current, found := s.channels.V2Presence(account, record.Enrollment, record.Node, record.ProtocolEpoch)
			if found && current.ConnectionID == *record.Connection && current.Platform == os && current.NodeEpoch != "" && !current.SeenAt.IsZero() {
				presence = "online"
				result.NodeEpoch = proto.String(current.NodeEpoch)
				result.Capabilities = slices.Clone(current.Capabilities)
				if current.SeenAt.After(record.LastSeenAt) {
					result.LastSeenAt = arc.Instant(current.SeenAt)
				}
			}
		}
	}
	result.Presence = proto.String(presence)
	return result
}

func (s *devices) list(ctx context.Context, call *ingress.Call, message *managementv2.DeviceServiceListRequest) (*managementv2.DeviceServiceListResponse, error) {
	value, err := func() (*managementv2.DeviceServiceListValue, error) {
		if err := deviceMeta(message.GetMeta()); err != nil {
			return nil, err
		}
		_, account, err := s.account(ctx, call, message.GetMeta())
		if err != nil {
			return nil, err
		}
		accountID := account.Caller.UserID
		records, next, err := s.store.ListDevices(ctx, accountID, message.GetCursor(), message.Limit)
		if err != nil {
			return nil, err
		}
		page := &managementv2.DevicePage{Devices: make([]*managementv2.Device, 0, len(records))}
		for _, record := range records {
			page.Devices = append(page.Devices, s.view(accountID, record))
		}
		if next != "" {
			page.NextCursor = proto.String(next)
		}
		return &managementv2.DeviceServiceListValue{Page: page}, nil
	}()
	response := &managementv2.DeviceServiceListResponse{Meta: ingress.ResponseMeta(call.Correlation)}
	if failure := s.failure(ctx, call, err); failure != nil {
		response.Outcome = &managementv2.DeviceServiceListResponse_Error{Error: failure}
		return response, nil
	}
	response.Outcome = &managementv2.DeviceServiceListResponse_Value{Value: value}
	return response, nil
}

func (s *devices) inspect(ctx context.Context, call *ingress.Call, message *managementv2.DeviceServiceInspectRequest) (*managementv2.DeviceServiceInspectResponse, error) {
	device, err := func() (*managementv2.Device, error) {
		if err := deviceMeta(message.GetMeta()); err != nil {
			return nil, err
		}
		_, account, err := s.account(ctx, call, message.GetMeta())
		if err != nil {
			return nil, err
		}
		deviceID, err := requiredDeviceID(message.GetDeviceId())
		if err != nil {
			return nil, err
		}
		accountID := account.Caller.UserID
		record, err := s.store.InspectDevice(ctx, accountID, deviceID)
		if err != nil {
			return nil, err
		}
		return s.view(accountID, record), nil
	}()
	response := &managementv2.DeviceServiceInspectResponse{Meta: ingress.ResponseMeta(call.Correlation)}
	if failure := s.failure(ctx, call, err); failure != nil {
		response.Outcome = &managementv2.DeviceServiceInspectResponse_Error{Error: failure}
		return response, nil
	}
	response.Meta.ResultRev = device.Revision
	response.Outcome = &managementv2.DeviceServiceInspectResponse_Value{Value: &managementv2.DeviceServiceInspectValue{Device: device}}
	return response, nil
}

func (s *devices) revokeDevice(ctx context.Context, call *ingress.Call, message *managementv2.DeviceServiceRevokeRequest) (*managementv2.DeviceServiceRevokeResponse, error) {
	value, err := s.revokeDeviceOnce(ctx, call, message)
	response := &managementv2.DeviceServiceRevokeResponse{Meta: ingress.ResponseMeta(call.Correlation)}
	if failure := s.failure(ctx, call, err); failure != nil {
		response.Outcome = &managementv2.DeviceServiceRevokeResponse_Error{Error: failure}
		return response, nil
	}
	response.Meta.ResultRev = value.Device.Revision
	response.Outcome = &managementv2.DeviceServiceRevokeResponse_Value{Value: value}
	return response, nil
}

func (s *devices) revokeDeviceOnce(ctx context.Context, call *ingress.Call, message *managementv2.DeviceServiceRevokeRequest) (*managementv2.DeviceServiceRevokeValue, error) {
	meta := message.GetMeta()
	if err := deviceMeta(meta); err != nil {
		return nil, err
	}
	operation, account, err := s.account(ctx, call, meta)
	if err != nil {
		return nil, err
	}
	deviceID, err := requiredDeviceID(message.GetDeviceId())
	if err != nil {
		return nil, err
	}
	revision := meta.GetExpectedRev().GetValue()
	if revision < 1 {
		return nil, arc.InvalidArgument("meta.expected_rev", "required")
	}
	command, err := accountCommand(call, account, meta)
	if err != nil {
		return nil, err
	}
	// Match the retained account/step-up guard. A different account always
	// has an identical not-found view for this device ID.
	caller := account.Caller
	if _, err := s.store.InspectDevice(ctx, caller.UserID, deviceID); err != nil {
		return nil, err
	}
	own := deviceID == caller.DeviceID
	if operation.NeedsUpgrade(call.Caller, own) {
		return nil, arc.StepUpRequired()
	}
	return execute(ctx, s.Server, command, &managementv2.DeviceServiceRevokeValue{},
		func(ctx context.Context, tx pgx.Tx, now time.Time) (*managementv2.DeviceServiceRevokeValue, error) {
			if err := identity.RecheckCaller(ctx, tx, caller, now); err != nil {
				return nil, err
			}
			record, err := management.LockDeviceForRevoke(ctx, tx, caller.UserID, deviceID, revision)
			if err != nil {
				return nil, err
			}
			if operation.NeedsEvidence(own) {
				if err := identity.ConsumeEvidence(ctx, tx, caller, operation.ID, deviceID, now); err != nil {
					return nil, err
				}
			}
			record.Revision, err = s.revoke(ctx, tx, caller, deviceID, now)
			if err != nil {
				return nil, err
			}
			record.DeviceRevoked = true
			return &managementv2.DeviceServiceRevokeValue{Device: s.view(caller.UserID, record)}, nil
		})
}
