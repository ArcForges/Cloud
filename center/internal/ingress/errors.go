// SPDX-License-Identifier: AGPL-3.0-only

package ingress

import (
	"errors"

	"connectrpc.com/connect/v2"
	foundationv1 "github.com/ArcForges/Contracts/go/arcforges/foundation/v1"
	"google.golang.org/protobuf/proto"

	"github.com/ArcForges/Cloud/center/internal/correlation"
)

// Reason is one transport refusal of the pipeline: the registry code it carries as grpc-message, the gRPC status it is
// answered with and the ArcError category the code belongs to. A transport refusal is a trailers-only status produced before
// any business code runs; it has no reply message and therefore carries no correlation id.
//
// The C# host has no category-to-status table: these rows are the complete set of refusals its IngressPipeline produces, ported
// exactly (docs/center.md, "ArcError and gRPC status"). Every other ArcError is a domain refusal: gRPC OK with the ArcError in
// the reply message, carrying the call's correlation id (DomainError).
type Reason struct {
	Code     string
	Status   Status
	Category foundationv1.ErrorCategory
}

// The pipeline's refusals.
var (
	// ReasonUnimplemented answers a method-shaped path that has no registered policy. It is not an ArcError code.
	ReasonUnimplemented = Reason{Code: "unimplemented", Status: StatusUnimplemented, Category: foundationv1.ErrorCategory_ERROR_CATEGORY_UNSPECIFIED}
	// ReasonUnauthenticated answers a missing, malformed, unknown or conflicting credential.
	ReasonUnauthenticated = Reason{Code: "auth.unauthenticated", Status: StatusUnauthenticated, Category: foundationv1.ErrorCategory_ERROR_CATEGORY_AUTHENTICATION}
	// ReasonPermissionDenied answers a wrong Origin or CSRF token, or a workspace the caller does not currently own.
	ReasonPermissionDenied = Reason{Code: "perm.resource_denied", Status: StatusPermissionDenied, Category: foundationv1.ErrorCategory_ERROR_CATEGORY_AUTHORIZATION}
	// ReasonInvalidRequest answers a malformed frame or envelope, including a malformed correlation id.
	ReasonInvalidRequest = Reason{Code: "validation.invalid_request", Status: StatusInvalidArgument, Category: foundationv1.ErrorCategory_ERROR_CATEGORY_VALIDATION}
	// ReasonRequestTooLarge answers a request body over the method's bound (declared or actual).
	ReasonRequestTooLarge = Reason{Code: "validation.invalid_request", Status: StatusResourceExhausted, Category: foundationv1.ErrorCategory_ERROR_CATEGORY_VALIDATION}
	// ReasonStaleGeneration answers an envelope whose recovery generation differs from the caller's session.
	ReasonStaleGeneration = Reason{Code: "state.stale_generation", Status: StatusFailedPrecondition, Category: foundationv1.ErrorCategory_ERROR_CATEGORY_STATE}
	// ReasonDependencyUnavailable answers a credential check whose store could not be reached.
	ReasonDependencyUnavailable = Reason{Code: "dependency.unavailable", Status: StatusUnavailable, Category: foundationv1.ErrorCategory_ERROR_CATEGORY_EXECUTION}
	// ReasonTokenExpired answers a known bearer whose access token expired; the client refreshes and retries (AF-CTR-03,
	// errors.md AUTHENTICATION/token_expired as a transport status).
	ReasonTokenExpired = Reason{Code: "auth.token_expired", Status: StatusUnauthenticated, Category: foundationv1.ErrorCategory_ERROR_CATEGORY_AUTHENTICATION}
	// ReasonCredentialRevoked answers a known bearer whose session, device or installation was revoked (AF-CTR-03, errors.md
	// AUTHENTICATION/credential_revoked as a transport status).
	ReasonCredentialRevoked = Reason{Code: "auth.credential_revoked", Status: StatusUnauthenticated, Category: foundationv1.ErrorCategory_ERROR_CATEGORY_AUTHENTICATION}
)

// The errors a BearerVerifier returns for a known credential that is no longer usable; any other error is a store that could not be
// reached.
var (
	ErrTokenExpired      = errors.New("the access token expired")
	ErrCredentialRevoked = errors.New("the credential was revoked")
)

// Reasons is every refusal the pipeline produces, in the order of the table in docs/center.md.
func Reasons() []Reason {
	return []Reason{
		ReasonUnimplemented, ReasonUnauthenticated, ReasonPermissionDenied, ReasonInvalidRequest, ReasonRequestTooLarge,
		ReasonStaleGeneration, ReasonDependencyUnavailable, ReasonTokenExpired, ReasonCredentialRevoked,
	}
}

// ConnectError is the refusal as a Connect error, for a refusal that a Connect interceptor or handler must produce before any
// business code runs (for example a credential check moved behind the pipeline). Connect writes it as the same grpc-status and
// grpc-message.
func (r Reason) ConnectError() *connect.Error {
	return connect.NewError(connect.Code(r.Status), r.Code)
}

// ResponseMeta is the reply meta that carries the call's correlation id (ResponseMeta.correlation_id, tag 4).
func ResponseMeta(call correlation.Context) *foundationv1.ResponseMeta {
	return &foundationv1.ResponseMeta{CorrelationId: &foundationv1.Id{Value: correlation.IDBytes(call.CorrelationID)}}
}

// DomainError is a domain refusal carrying the call's correlation id (ArcError.correlation_id, tag 6): retry never, effect
// did-not-happen. It is returned in the reply message with gRPC OK, as the C# host's CorrelationReplies.Error does. The code
// and message key are registry values, never request text.
func DomainError(call correlation.Context, code string, category foundationv1.ErrorCategory, messageKey string) *foundationv1.ArcError {
	return &foundationv1.ArcError{
		Code:          proto.String(code),
		Category:      category.Enum(),
		MessageKey:    proto.String(messageKey),
		Retry:         &foundationv1.RetryAdvice{Mode: foundationv1.RetryMode_RETRY_MODE_NEVER.Enum()},
		Effect:        foundationv1.EffectCertainty_EFFECT_CERTAINTY_DID_NOT_HAPPEN.Enum(),
		CorrelationId: &foundationv1.Id{Value: correlation.IDBytes(call.CorrelationID)},
	}
}
