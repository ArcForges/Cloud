// SPDX-License-Identifier: AGPL-3.0-only

package pages

import (
	"encoding/base64"
	"strconv"
	"strings"
	"time"

	foundationv1 "github.com/ArcForges/Contracts/go/arcforges/foundation/v1"
	publicapiv1 "github.com/ArcForges/Contracts/go/arcforges/publicapi/v1"

	"github.com/ArcForges/Cloud/center/internal/correlation"
	"github.com/ArcForges/Cloud/center/internal/platform"
	"github.com/ArcForges/Cloud/center/internal/session"
)

// The WebBrowserSession replies (Contracts web-browser.schema.json at 62ccef1) as strict JSON: UUIDs in canonical lowercase text,
// instants as RFC 3339 UTC, int64 values as decimal strings, bytes as unpadded base64url.

type sessionProjection struct {
	SessionID          string   `json:"sessionId"`
	ExpiresAt          string   `json:"expiresAt"`
	IdleExpiresAt      string   `json:"idleExpiresAt,omitempty"`
	UserID             string   `json:"userId"`
	DeviceID           string   `json:"deviceId"`
	WorkspaceIDs       []string `json:"workspaceIds"`
	RecoveryGeneration string   `json:"recoveryGeneration"`
	Purpose            string   `json:"purpose"`
}

type profileProjection struct {
	DisplayName string `json:"displayName"`
	Locale      string `json:"locale"`
	Timezone    string `json:"timezone"`
	Revision    string `json:"revision"`
}

type bootstrapReply struct {
	CSRFToken     string             `json:"csrfToken"`
	Authenticated bool               `json:"authenticated"`
	Session       *sessionProjection `json:"session,omitempty"`
	Profile       *profileProjection `json:"profile,omitempty"`
}

type optionsReply struct {
	RPID                string   `json:"rpId"`
	UserHandle          string   `json:"userHandle,omitempty"`
	AllowedCredentials  []string `json:"allowedCredentials,omitempty"`
	ExcludedCredentials []string `json:"excludedCredentials,omitempty"`
	UserVerification    string   `json:"userVerification"`
	Algorithms          []int32  `json:"algorithms"`
}

type challengeReply struct {
	FlowID     string        `json:"flowId"`
	Method     string        `json:"method"`
	Challenge  string        `json:"challenge"`
	RPID       string        `json:"rpId,omitempty"`
	ExpiresAt  string        `json:"expiresAt"`
	Options    *optionsReply `json:"options,omitempty"`
	ProviderID string        `json:"providerId,omitempty"`
	Purpose    string        `json:"purpose"`
}

type evidenceReply struct {
	OperationClass string `json:"operationClass"`
	ExpiresAt      string `json:"expiresAt"`
}

type receiptReply struct {
	CommandID      string `json:"commandId"`
	ResultRevision string `json:"resultRevision,omitempty"`
	Effect         string `json:"effect"`
}

// maxCredentialList is the contract's bound of allowedCredentials and excludedCredentials.
const maxCredentialList = 64

func formatInstant(at time.Time) string { return at.UTC().Format(time.RFC3339Nano) }

func instantOf(value *foundationv1.Instant) time.Time {
	return time.Unix(value.GetUnixSeconds(), int64(value.GetNanos())).UTC()
}

func uuidText(id platform.ID) string { return correlation.FormatID(id[:]) }

func b64(data []byte) string { return base64.RawURLEncoding.EncodeToString(data) }

var purposeNames = map[publicapiv1.AuthPurpose]string{
	publicapiv1.AuthPurpose_AUTH_PURPOSE_AUTHENTICATE:    "authenticate",
	publicapiv1.AuthPurpose_AUTH_PURPOSE_ENROLL:          "enroll",
	publicapiv1.AuthPurpose_AUTH_PURPOSE_STEP_UP:         "stepUp",
	publicapiv1.AuthPurpose_AUTH_PURPOSE_RECOVER:         "recover",
	publicapiv1.AuthPurpose_AUTH_PURPOSE_CANCEL_DELETION: "cancelDeletion",
}

// challengeOf is the WebBrowserAuthChallenge of a contract AuthChallenge. A list of more credentials than the document admits is
// left out (the authenticator then offers its own discoverable credentials; the center checks the owner's user handle either way).
func challengeOf(value *publicapiv1.AuthChallenge) challengeReply {
	flow, _ := parseUUIDBytes(value.GetFlowId().GetValue())
	result := challengeReply{
		FlowID: uuidText(flow), Method: "passkey", Challenge: b64(value.GetChallenge()), RPID: value.GetRpId(), ExpiresAt: formatInstant(instantOf(value.GetExpiresAt())),
		ProviderID: value.GetProviderId(), Purpose: purposeNames[value.GetPurpose()],
	}
	if options := value.GetOptions(); options != nil {
		result.Options = &optionsReply{RPID: options.GetRpId(), UserVerification: options.GetUserVerification(), Algorithms: options.GetAlgorithms()}
		if handle := options.GetUserHandle(); len(handle) > 0 {
			result.Options.UserHandle = b64(handle)
		}
		if len(options.GetAllowedCredentials()) <= maxCredentialList {
			for _, id := range options.GetAllowedCredentials() {
				result.Options.AllowedCredentials = append(result.Options.AllowedCredentials, b64(id))
			}
		}
		if len(options.GetExcludedCredentials()) <= maxCredentialList {
			for _, id := range options.GetExcludedCredentials() {
				result.Options.ExcludedCredentials = append(result.Options.ExcludedCredentials, b64(id))
			}
		}
	}
	return result
}

func parseUUIDBytes(raw []byte) (platform.ID, bool) {
	var id platform.ID
	if len(raw) != len(id) {
		return id, false
	}
	copy(id[:], raw)
	return id, true
}

// projectionOf is the WebBrowserSessionProjection of a resolved cookie session.
func projectionOf(resolved *session.BrowserSession) *sessionProjection {
	return &sessionProjection{
		SessionID: uuidText(resolved.SessionID), ExpiresAt: formatInstant(resolved.ExpiresAt), IdleExpiresAt: formatInstant(resolved.IdleExpiresAt),
		UserID: uuidText(resolved.UserID), DeviceID: uuidText(resolved.DeviceID), WorkspaceIDs: []string{},
		RecoveryGeneration: strconv.FormatInt(resolved.RecoveryGeneration, 10), Purpose: purposeName(int32(resolved.Purpose)),
	}
}

func purposeName(purpose int32) string {
	if name, ok := purposeNames[publicapiv1.AuthPurpose(purpose)]; ok {
		return name
	}
	return "authenticate"
}

// The error body (an ArcError as JSON). The WebBrowserSession document defines no error body, so the center answers every refusal
// of these routes with {"error": ...}: the ArcError of errors.md in the document's own conventions (category and code as
// errors.md names them in lower camel case, UUIDs as text, instants as RFC 3339, int64 values as strings).

type errorReply struct {
	Error arcErrorJSON `json:"error"`
}

type arcErrorJSON struct {
	Category      string       `json:"category"`
	Code          string       `json:"code"`
	MessageKey    string       `json:"messageKey"`
	Retry         retryJSON    `json:"retry"`
	Effect        string       `json:"effect"`
	CorrelationID string       `json:"correlationId,omitempty"`
	Details       *detailsJSON `json:"details,omitempty"`
}

type retryJSON struct {
	Mode    string `json:"mode"`
	RetryAt string `json:"retryAt,omitempty"`
}

type detailsJSON struct {
	State    *stateJSON    `json:"state,omitempty"`
	Limit    *limitJSON    `json:"limit,omitempty"`
	Revision *revisionJSON `json:"revision,omitempty"`
}

type stateJSON struct {
	State    string        `json:"state,omitempty"`
	Reason   string        `json:"reason,omitempty"`
	Resource *resourceJSON `json:"resource,omitempty"`
}

type resourceJSON struct {
	Kind string `json:"kind"`
	ID   string `json:"id,omitempty"`
}

type limitJSON struct {
	LimitName  string `json:"limitName"`
	Maximum    string `json:"maximum,omitempty"`
	RecoveryAt string `json:"recoveryAt,omitempty"`
}

type revisionJSON struct {
	Expected string `json:"expected"`
	Actual   string `json:"actual"`
}

func camelCase(name string) string {
	parts := strings.Split(strings.ToLower(name), "_")
	for index := 1; index < len(parts); index++ {
		if parts[index] != "" {
			parts[index] = strings.ToUpper(parts[index][:1]) + parts[index][1:]
		}
	}
	return strings.Join(parts, "")
}

// errorOf is the JSON of an ArcError.
func errorOf(value *foundationv1.ArcError) errorReply {
	result := arcErrorJSON{
		Category:   camelCase(strings.TrimPrefix(value.GetCategory().String(), "ERROR_CATEGORY_")),
		Code:       value.GetCode(),
		MessageKey: value.GetMessageKey(),
		Retry:      retryJSON{Mode: camelCase(strings.TrimPrefix(value.GetRetry().GetMode().String(), "RETRY_MODE_"))},
		Effect:     camelCase(strings.TrimPrefix(value.GetEffect().String(), "EFFECT_CERTAINTY_")),
	}
	if at := value.GetRetry().GetRetryAt(); at != nil {
		result.Retry.RetryAt = formatInstant(instantOf(at))
	}
	if id := value.GetCorrelationId().GetValue(); len(id) == 16 {
		result.CorrelationID = correlation.FormatID(id)
	}
	if details := value.GetDetails(); details != nil {
		result.Details = &detailsJSON{}
		if state := details.GetState(); state != nil {
			result.Details.State = &stateJSON{State: state.GetState(), Reason: state.GetReason()}
			if resource := state.GetResource(); resource != nil {
				result.Details.State.Resource = &resourceJSON{Kind: resource.GetKind()}
				if raw := resource.GetId().GetValue(); len(raw) == 16 {
					result.Details.State.Resource.ID = correlation.FormatID(raw)
				}
			}
		}
		if limit := details.GetLimit(); limit != nil {
			result.Details.Limit = &limitJSON{LimitName: limit.GetLimitName(), Maximum: limit.GetMaximum().GetValue()}
			if at := limit.GetRecoveryAt(); at != nil {
				result.Details.Limit.RecoveryAt = formatInstant(instantOf(at))
			}
		}
		if revision := details.GetRevision(); revision != nil {
			result.Details.Revision = &revisionJSON{Expected: strconv.FormatInt(revision.GetExpected().GetValue(), 10),
				Actual: strconv.FormatInt(revision.GetActual().GetValue(), 10)}
		}
	}
	return errorReply{Error: result}
}

// statusOf is the HTTP status of a refusal. The Worker's page handler lets only 200, 303, 400, 403, 404, 413, 415 and 429
// through, so a refusal takes the nearest of them: a malformed or contradicting request 400, a refused credential, origin, token or
// authorization 403, an unknown object and a disabled surface 404, a limit 429; a store that is down or an internal failure is 503
// (the Worker answers its own 503 for it).
func statusOf(value *foundationv1.ArcError) int {
	switch value.GetCategory() {
	case foundationv1.ErrorCategory_ERROR_CATEGORY_AUTHENTICATION, foundationv1.ErrorCategory_ERROR_CATEGORY_AUTHORIZATION,
		foundationv1.ErrorCategory_ERROR_CATEGORY_ENTITLEMENT:
		return 403
	case foundationv1.ErrorCategory_ERROR_CATEGORY_VALIDATION, foundationv1.ErrorCategory_ERROR_CATEGORY_CONFLICT:
		return 400
	case foundationv1.ErrorCategory_ERROR_CATEGORY_STATE:
		if value.GetCode() == "not_found" || value.GetCode() == "not_activated" {
			return 404
		}
		return 400
	case foundationv1.ErrorCategory_ERROR_CATEGORY_RESOURCE:
		if value.GetCode() == "rate_limited" {
			return 429
		}
		return 503
	}
	return 503
}
