// SPDX-License-Identifier: AGPL-3.0-only

package ingress

import (
	"context"
	"net/http"
	"net/netip"
	"slices"
	"strings"
	"time"

	"github.com/ArcForges/Cloud/center/internal/correlation"
)

// The credential names the pipeline reads; they equal the C# host's and the Worker's generated edge guard.
const (
	SessionCookieName  = "__Host-af_session"
	CSRFHeader         = "X-AF-CSRF"
	TraceparentHeader  = "Traceparent"
	MaxBearerLength    = 4096
	minBearerLength    = 16
	bearerSchemePrefix = "bearer "
)

// CredentialKind is the kind of credential that authenticated a caller.
type CredentialKind int

// The credential kinds.
const (
	CredentialNone CredentialKind = iota
	CredentialBrowserSession
	CredentialNativeBearer
)

// Caller is the authenticated principal of one request. It is a validated fact about the credential, never a client
// assertion.
type Caller struct {
	Credential         CredentialKind
	SessionID          string
	UserID             string
	DeviceID           string
	WorkspaceIDs       []string
	RecoveryGeneration uint64
	// InstallationID, Scope, Product and AuthMethod are the session's (AF-CTR-03): its installation, its scope (account,
	// mobile.limited, node, push or automation; AD-0011 section 5), its installation's product and how it authenticated.
	InstallationID string
	Scope          string
	Product        string
	AuthMethod     string
	// AuthenticatedAt is when the session's account authenticated; it is never step-up evidence.
	AuthenticatedAt time.Time
	// AuthEpoch is the account's authentication epoch the session was issued in.
	AuthEpoch int64
	// AccountState is the account's state (identity.user_state) when the credential was verified.
	AccountState int16
}

// IsAuthenticated reports a caller with a credential.
func (c Caller) IsAuthenticated() bool { return c.Credential != CredentialNone }

// Owner is the current owner of a workspace-scoped call: the workspace the envelope addressed, which the validated session of
// the caller currently owns, in the recovery generation that session is bound to.
type Owner struct {
	WorkspaceID        string
	UserID             string
	DeviceID           string
	RecoveryGeneration uint64
}

// Call is everything the pipeline decided about one admitted request; handlers read it and never re-derive authority. The
// Correlation is the call-scoped identity handlers return in ResponseMeta and ArcError; it is not an authorization input.
type Call struct {
	Policy      Policy
	Caller      Caller
	Owner       *Owner
	Correlation correlation.Context
	// ClientIP is the client's address for a surface method (the Worker's header in hosted mode, else the TCP peer or a trusted
	// proxy's header); it is zero when unknown. It keys rate limits and is never logged.
	ClientIP netip.Addr
	// Message is the request message exactly as transmitted (the bytes of its one frame) for a method that reads its RequestMeta;
	// a command receipt's digest covers these bytes, never a re-encoding (AD-0021 section 10). It is never logged.
	Message []byte
}

type callKey struct{}

// CallFrom is the admitted call of a request context.
func CallFrom(ctx context.Context) (*Call, bool) {
	call, ok := ctx.Value(callKey{}).(*Call)
	return call, ok
}

// BearerVerifier validates a native bearer credential against the authoritative store. A nil caller is unauthenticated; an
// error is a store that could not be reached.
type BearerVerifier interface {
	Verify(ctx context.Context, token string) (*Caller, error)
}

// BrowserCredential is a resolved browser session: the caller, and the check of the CSRF token that belongs to exactly this
// session. VerifyCSRF receives the single CSRF header value, or present=false when there is none or more than one.
type BrowserCredential struct {
	Caller     Caller
	VerifyCSRF func(token string, present bool) bool
}

// BrowserSessionVerifier validates the origin-bound browser cookie. Implementations read the authoritative store on every call
// and do not renew idle expiry.
type BrowserSessionVerifier interface {
	// AllowedOrigin is the one exact origin that may use the cookie on an unsafe request.
	AllowedOrigin() string
	// Resolve returns nil when the cookie is unknown, revoked, expired or in another recovery generation.
	Resolve(ctx context.Context, cookie string) (*BrowserCredential, error)
}

// SessionCookie is the unique session cookie value; absent, repeated or empty cookies are no credential.
func SessionCookie(header http.Header) (string, bool) {
	found, seen := "", false
	for _, line := range header.Values("Cookie") {
		for pair := range strings.SplitSeq(line, ";") {
			text := strings.TrimSpace(pair)
			separator := strings.IndexByte(text, '=')
			if separator <= 0 || text[:separator] != SessionCookieName {
				continue
			}
			if seen {
				return "", false
			}
			found, seen = text[separator+1:], true
		}
	}
	return found, found != ""
}

// BearerToken is the token of exactly one Bearer authorization value of plausible length and alphabet; anything else is no
// credential.
func BearerToken(header http.Header) (string, bool) {
	values := header.Values("Authorization")
	if len(values) != 1 || len(values[0]) < len(bearerSchemePrefix) || !strings.EqualFold(values[0][:len(bearerSchemePrefix)], bearerSchemePrefix) {
		return "", false
	}
	token := values[0][len(bearerSchemePrefix):]
	if len(token) < minBearerLength || len(token) > MaxBearerLength {
		return "", false
	}
	for index := range len(token) {
		c := token[index]
		if !(c >= 'A' && c <= 'Z' || c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || strings.IndexByte("._~+/=-", c) >= 0) {
			return "", false
		}
	}
	return token, true
}

// authorizeOwner reads the envelope strictly: a malformed one is validation.invalid_request before the owner decision. For a
// workspace-scoped method the caller must also have addressed one workspace, own it now and be in the generation of its own
// session. The correlation id is carried out of the envelope but never consulted by the decisions.
func authorizeOwner(policy Policy, caller Caller, body []byte) (*Owner, string, *Reason) {
	message, ok := ReadSingleMessage(body)
	if !ok {
		return nil, "", &ReasonInvalidRequest
	}
	envelope, ok := ReadEnvelope(message)
	if !ok {
		return nil, "", &ReasonInvalidRequest
	}
	if policy.Scope != Workspace {
		return nil, envelope.CorrelationID, nil
	}
	if envelope.WorkspaceID == "" {
		return nil, "", &ReasonInvalidRequest
	}
	if !slices.Contains(caller.WorkspaceIDs, envelope.WorkspaceID) || caller.UserID == "" {
		return nil, "", &ReasonPermissionDenied
	}
	if envelope.HasRecoveryGeneration && envelope.RecoveryGeneration != caller.RecoveryGeneration {
		return nil, "", &ReasonStaleGeneration
	}
	return &Owner{
		WorkspaceID: envelope.WorkspaceID, UserID: caller.UserID, DeviceID: caller.DeviceID,
		RecoveryGeneration: caller.RecoveryGeneration,
	}, envelope.CorrelationID, nil
}
