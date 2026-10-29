// SPDX-License-Identifier: AGPL-3.0-only

package identityapi

import (
	foundationv1 "github.com/ArcForges/Contracts/go/arcforges/foundation/v1"
	publicapiv1 "github.com/ArcForges/Contracts/go/arcforges/publicapi/v1"
	"google.golang.org/protobuf/proto"

	"github.com/ArcForges/Cloud/center/internal/arc"
	"github.com/ArcForges/Cloud/center/internal/correlation"
	"github.com/ArcForges/Cloud/center/internal/device"
	"github.com/ArcForges/Cloud/center/internal/identity"
	"github.com/ArcForges/Cloud/center/internal/identity/passkey"
	"github.com/ArcForges/Cloud/center/internal/platform"
	"github.com/ArcForges/Cloud/center/internal/session"
)

func id(value platform.ID) *foundationv1.Id { return &foundationv1.Id{Value: value[:]} }

// parseID reads a contract Id: 16 bytes that are not all zero.
func parseID(value *foundationv1.Id) (platform.ID, bool) {
	var result platform.ID
	if value == nil || len(value.GetValue()) != len(result) {
		return platform.ID{}, false
	}
	copy(result[:], value.GetValue())
	return result, result != platform.ID{}
}

// textID reads the canonical text of an ID (the ingress caller's).
func textID(text string) (platform.ID, bool) {
	var result platform.ID
	raw := correlation.IDBytes(text)
	if len(raw) != len(result) {
		return platform.ID{}, false
	}
	copy(result[:], raw)
	return result, true
}

func deviceView(view device.View) *publicapiv1.DeviceView {
	result := &publicapiv1.DeviceView{
		DeviceId: id(view.DeviceID), Name: proto.String(view.Name), Platform: proto.String(view.Platform.String()),
		Trust: publicapiv1.TrustLevel(view.Trust).Enum(), RemoteEnabled: proto.Bool(view.RemoteEnabled),
		Revision: &foundationv1.Revision{Value: proto.Int64(view.Revision)},
	}
	if view.RevokedAt != nil {
		result.RevokedAt = arc.Instant(*view.RevokedAt)
	}
	for _, item := range view.Installed {
		result.Installed = append(result.Installed, &publicapiv1.InstalledProduct{Product: proto.String(item.Product), Version: proto.String(item.Version),
			InstalledAt: arc.Instant(item.InstalledAt)})
	}
	return result
}

func nativeSession(signedIn identity.SignedIn) *publicapiv1.NativeSession {
	issued := signedIn.Session
	return &publicapiv1.NativeSession{
		SessionId: id(issued.SessionID), AccessToken: proto.String(issued.AccessToken), AccessExpiresAt: arc.Instant(issued.AccessExpiresAt),
		RefreshToken: proto.String(issued.RefreshToken), RefreshExpiresAt: arc.Instant(issued.RefreshExpiresAt), Device: deviceView(signedIn.Device),
		RecoveryGeneration: proto.Uint64(0), Purpose: publicapiv1.AuthPurpose(issued.Purpose).Enum(),
	}
}

func webAuthnOptions(options *passkey.Options) *publicapiv1.WebAuthnOptions {
	if options == nil {
		return nil
	}
	result := &publicapiv1.WebAuthnOptions{RpId: proto.String(options.RPID), UserVerification: proto.String(options.UserVerification),
		ExcludedCredentials: options.Excluded, Algorithms: options.Algorithms}
	if len(options.UserHandle) > 0 {
		result.UserHandle = options.UserHandle
	}
	return result
}

func authChallenge(challenge identity.Challenge, rpID string) *publicapiv1.AuthChallenge {
	result := &publicapiv1.AuthChallenge{
		FlowId: id(challenge.FlowID), Method: publicapiv1.AuthMethod(challenge.Method).Enum(), Challenge: challenge.Challenge,
		ExpiresAt: arc.Instant(challenge.ExpiresAt), Options: webAuthnOptions(challenge.Options), ProviderId: proto.String(challenge.ProviderID),
		Purpose: publicapiv1.AuthPurpose(challenge.Purpose).Enum(),
	}
	if challenge.Options != nil {
		result.RpId = proto.String(rpID)
	}
	return result
}

func assertion(value *publicapiv1.WebAuthnAssertion) passkey.Assertion {
	return passkey.Assertion{CredentialID: value.GetCredentialId(), ClientDataJSON: value.GetClientDataJson(),
		AuthenticatorData: value.GetAuthenticatorData(), Signature: value.GetSignature(), UserHandle: value.GetUserHandle()}
}

func creation(value *publicapiv1.WebAuthnCreation) passkey.Creation {
	return passkey.Creation{CredentialID: value.GetCredentialId(), ClientDataJSON: value.GetClientDataJson(),
		AttestationObject: value.GetAttestationObject(), Transports: value.GetTransports()}
}

func claim(value *publicapiv1.InstallationClaim) (device.Claim, bool) {
	if value == nil {
		return device.Claim{}, false
	}
	installation, _ := parseID(value.GetInstallationId())
	return device.Claim{InstallationID: installation, Product: value.GetProduct(), Platform: value.GetPlatform(), AppVersion: value.GetAppVersion()}, true
}

func pageState(next string) *foundationv1.PageState {
	state := &foundationv1.PageState{HasMore: proto.Bool(next != "")}
	if next != "" {
		state.NextCursor = proto.String(next)
	}
	return state
}

func sessionSummary(item session.Summary) *publicapiv1.SessionSummary {
	return &publicapiv1.SessionSummary{
		SessionId: id(item.SessionID), DeviceId: id(item.DeviceID), Product: proto.String(item.Product), CreatedAt: arc.Instant(item.IssuedAt),
		LastUsedAt: arc.Instant(item.LastUsedAt), ExpiresAt: arc.Instant(item.ExpiresAt), Current: proto.Bool(item.Current),
		Revision: &foundationv1.Revision{Value: proto.Int64(item.Revision)},
	}
}

func credentialSummary(item identity.Credential) *publicapiv1.CredentialSummary {
	result := &publicapiv1.CredentialSummary{CredentialId: id(item.ID), Kind: proto.String(item.Kind), DisplayName: proto.String(item.DisplayName),
		CreatedAt: arc.Instant(item.CreatedAt)}
	if item.LastUsedAt != nil {
		result.LastUsedAt = arc.Instant(*item.LastUsedAt)
	}
	return result
}

func accountProfile(profile identity.Profile) *publicapiv1.AccountProfile {
	return &publicapiv1.AccountProfile{DisplayName: proto.String(profile.DisplayName), PrimaryEmail: profile.PrimaryEmail,
		Locale: proto.String(profile.Locale), Timezone: proto.String(profile.Timezone), Revision: &foundationv1.Revision{Value: proto.Int64(profile.Revision)}}
}

func providerView(provider identity.Provider) *publicapiv1.AuthProviderView {
	return &publicapiv1.AuthProviderView{ProviderId: proto.String(provider.ID), Method: publicapiv1.AuthMethod(provider.Method).Enum(),
		Name: proto.String(provider.Name), Enrollment: proto.Bool(provider.Enrollment)}
}
