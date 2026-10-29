// SPDX-License-Identifier: AGPL-3.0-only

package routes

import (
	"github.com/ArcForges/Contracts/go/arcforges/publicapi/v1/publicapiv1connect"

	"github.com/ArcForges/Cloud/center/internal/ingress"
)

// SurfaceIdentity is the identity surface: accounts, sessions and devices (AF-CTR-03). Its methods are served only where the
// surface is enabled; elsewhere the Worker and the center answer STATE/not_activated.
const SurfaceIdentity = "identity"

// The request bounds of the identity methods: a WebAuthn creation or assertion (attestation none, ES256) fits 16 KiB with room;
// every other request is small.
const (
	identityCeremonyBytes = 16_384
	identityRequestBytes  = 4096
)

// IdentityMethod is one served method of the identity surface: its path, whether it needs a session, and its request bound.
type IdentityMethod struct {
	Path            string
	Session         bool
	MaxRequestBytes int
}

// IdentityMethods are the IdentityService and DeviceService methods AF-CTR-03 A1a serves, in registration order. Every other
// method of the two services (and every WorkspaceService method) stays unregistered: the center answers UNIMPLEMENTED and the
// Worker table has no row for it. A1b extends this list (step-up, sign-out and revocation, credential and device management).
func IdentityMethods() []IdentityMethod {
	return []IdentityMethod{
		{publicapiv1connect.IdentityServiceBeginAuthenticationProcedure, false, identityRequestBytes},
		{publicapiv1connect.IdentityServiceCompleteAuthenticationProcedure, false, identityCeremonyBytes},
		{publicapiv1connect.IdentityServiceRequestEmailCodeProcedure, false, identityRequestBytes},
		{publicapiv1connect.IdentityServiceRedeemEmailCodeProcedure, false, identityRequestBytes},
		{publicapiv1connect.IdentityServiceCompleteEnrollmentProcedure, false, identityCeremonyBytes},
		{publicapiv1connect.IdentityServiceListAuthProvidersProcedure, false, identityRequestBytes},
		{publicapiv1connect.IdentityServiceRefreshSessionProcedure, false, identityRequestBytes},
		{publicapiv1connect.IdentityServiceGetProfileProcedure, true, identityRequestBytes},
		{publicapiv1connect.IdentityServiceListAuthIdentitiesProcedure, true, identityRequestBytes},
		{publicapiv1connect.IdentityServiceListSessionsProcedure, true, identityRequestBytes},
		{publicapiv1connect.DeviceServiceListProcedure, true, identityRequestBytes},
	}
}

// identityBudget is the transport budget of every identity method: replies are a session, a challenge or one page of at most 100
// items; the deadline covers a PBKDF2 verification and a few short transactions.
var identityBudget = Budget{MaxFrameBytes: 65_536, MaxUnaryResponseBytes: 65_536, MaxDurationMilliseconds: 15_000, Instance: HealthInstance}

// Identity is the identity surface's module.
func Identity() (Module, error) {
	module := Module{Name: "identity", Surface: SurfaceIdentity, Budgets: map[string]Budget{}}
	for _, method := range IdentityMethods() {
		authentication := ingress.Anonymous
		if method.Session {
			authentication = ingress.Session
		}
		// Every identity request starts with a RequestMeta: the pipeline reads it strictly and the correlation id it states.
		policy, err := ingress.NewUnary(method.Path, authentication, ingress.NoScope, method.MaxRequestBytes, true)
		if err != nil {
			return Module{}, err
		}
		module.Policies = append(module.Policies, policy.InSurface(SurfaceIdentity))
		module.Budgets[method.Path] = identityBudget
	}
	return module, nil
}
