// SPDX-License-Identifier: AGPL-3.0-only

// Package mobiletest is MobileProbe's library (AF-CTR-04 part M; the Plan task's fakes_allowed "MobileProbe: center/internal/mobiletest
// and center/cmd/mobile-probe"): a MOCKED development stand-in of the ArcForges Android app for the mobile native authorization. It
// does what the contract (Contracts MobileNativeAuth v1) asks of the app: a fresh random PKCE verifier and state per attempt, one
// begin, the authorization page URL derived from its configured center and required byte-equal to the reply (MB-2), the callback's
// state and issuer checked against its one pending attempt before any network call, and one token request per code. It is not the
// Android app (AF-AND-01 proves that one, with App Link verification on a device), never claims a result for it, and is never part
// of the center's image (.dockerignore keeps it out of the Docker context; tests/worker/docker-context.test.ts pins that). The
// integration tests and center/cmd/mobile-probe (H3) use it.
package mobiletest

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"

	"github.com/ArcForges/Cloud/center/internal/platform"
)

// The clients of the contract.
const (
	ClientRelease = "arcforges.android"
	ClientDebug   = "arcforges.android.local"
)

// App is one MOCKED app installation talking to one center.
type App struct {
	// Center is the configured center's public base URL (the issuer the app expects, and the base of the URLs it derives).
	Center string
	// Endpoint is where the requests go, when not Center (a test listener that serves the center's paths at its root); empty is Center.
	Endpoint string
	// HTTP sends the requests; nil is http.DefaultClient (redirects are never followed).
	HTTP *http.Client
	// Header adds headers to every request (a test's client-address header); nil adds none.
	Header http.Header
	// ClientID and Redirect are the app's client and its registered redirect.
	ClientID string
	Redirect string
	// The installation claim as the app reports it.
	InstallationID platform.ID
	Platform       string
	AppVersion     string
}

// NewInstallation is a fresh installation ID: a random canonical UUID (version 4).
func NewInstallation() platform.ID { return platform.NewID() }

// Attempt is the app's one pending attempt (MB-2 (c)): the center, the flow, the state and the verifier. The verifier and the state
// never leave the app but in begin (the challenge) and token (the verifier).
type Attempt struct {
	Center       string
	FlowID       string
	State        string
	Verifier     string
	Challenge    string
	AuthorizeURL string
	ExpiresAt    string
}

// Reply is one HTTP answer: its status and its body, decoded as JSON when it is.
type Reply struct {
	Status int
	Body   []byte
	JSON   map[string]any
}

// Refusal is the "<category>/<code>" of a JSON error reply ({"error": {category, code}}), with the category as the wire writes it (in
// lower case, for example "conflict/code_reused"), or "" for none. RefusalOf brings a gRPC ArcError to the same form.
func (r Reply) Refusal() string {
	failure, ok := r.JSON["error"].(map[string]any)
	if !ok {
		return ""
	}
	category, _ := failure["category"].(string)
	code, _ := failure["code"].(string)
	return category + "/" + code
}

// random is n random bytes in unpadded base64url.
func random(n int) string {
	data := make([]byte, n)
	if _, err := rand.Read(data); err != nil {
		panic(err)
	}
	return base64.RawURLEncoding.EncodeToString(data)
}

// NewVerifier is a fresh PKCE verifier (32 random bytes, 43 characters) and its S256 challenge.
func NewVerifier() (verifier, challenge string) {
	verifier = random(32)
	digest := sha256.Sum256([]byte(verifier))
	return verifier, base64.RawURLEncoding.EncodeToString(digest[:])
}

// NewState is a fresh random state (24 random bytes, 32 characters).
func NewState() string { return random(24) }

// AuthorizeURL is the authorization page the app derives itself from its configured center and a flow ID.
func AuthorizeURL(center, flowID string) string { return center + "/mobile/authorize#flow=" + flowID }

// BeginBody is the MobileBeginRequest of an attempt.
func (a *App) BeginBody(attempt Attempt) []byte {
	body, _ := json.Marshal(map[string]any{"clientId": a.ClientID, "redirectUri": a.Redirect, "codeChallenge": attempt.Challenge, "codeChallengeMethod": "S256",
		"state": attempt.State, "installation": map[string]string{"installationId": a.InstallationID.String(), "product": "arcforges-mobile",
			"platform": a.Platform, "appVersion": a.AppVersion}})
	return body
}

// NewAttempt draws a fresh verifier and state.
func (a *App) NewAttempt() Attempt {
	verifier, challenge := NewVerifier()
	return Attempt{Center: a.Center, State: NewState(), Verifier: verifier, Challenge: challenge}
}

// Post sends one native JSON request (Content-Type exactly application/json, no cookie) and reads its reply.
func (a *App) Post(ctx context.Context, path string, body []byte) (Reply, error) {
	base := a.Endpoint
	if base == "" {
		base = a.Center
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, base+path, bytes.NewReader(body))
	if err != nil {
		return Reply{}, err
	}
	request.Header.Set("Content-Type", "application/json")
	for name, values := range a.Header {
		for _, value := range values {
			request.Header.Add(name, value)
		}
	}
	client := a.HTTP
	if client == nil {
		client = &http.Client{}
	}
	// A redirect is never followed: the contract's native routes never redirect.
	copied := *client
	copied.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	response, err := copied.Do(request)
	if err != nil {
		return Reply{}, err
	}
	defer response.Body.Close()
	data, err := io.ReadAll(io.LimitReader(response.Body, 1<<20))
	if err != nil {
		return Reply{}, err
	}
	reply := Reply{Status: response.StatusCode, Body: data}
	if strings.HasPrefix(response.Header.Get("Content-Type"), "application/json") {
		_ = json.Unmarshal(data, &reply.JSON)
	}
	return reply, nil
}

// Begin begins an attempt and checks the reply as the app does: the authorizeUrl must be byte-equal to the one the app derives from
// its configured center and the reply's flowId (MB-2 (a)); a reply that is not is refused (ErrMixUp) and the attempt is dropped.
func (a *App) Begin(ctx context.Context) (Attempt, Reply, error) {
	attempt := a.NewAttempt()
	reply, err := a.Post(ctx, "/session/v1/mobile/begin", a.BeginBody(attempt))
	if err != nil || reply.Status != http.StatusOK {
		return Attempt{}, reply, err
	}
	flowID, authorize, expires, err := CheckBeginReply(reply.Body, a.Center)
	if err != nil {
		return Attempt{}, reply, err
	}
	attempt.FlowID, attempt.AuthorizeURL, attempt.ExpiresAt = flowID, authorize, expires
	return attempt, reply, nil
}

var (
	flowShape    = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)
	instantShape = regexp.MustCompile(`^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(\.[0-9]{1,9})?Z$`)
)

// CheckBeginReply reads a MobileBeginResponse as the app does: exactly flowId (a nonzero canonical UUID), authorizeUrl and expiresAt
// (an RFC 3339 UTC instant), and the authorizeUrl byte-equal to the one the app derives from its configured center (MB-2 (a)), at most
// 512 characters. A reply naming another URL is ErrMixUp; any other fault is an error of its own.
func CheckBeginReply(body []byte, center string) (flowID, authorizeURL, expiresAt string, err error) {
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.DisallowUnknownFields()
	var reply struct {
		FlowID       *string `json:"flowId"`
		AuthorizeURL *string `json:"authorizeUrl"`
		ExpiresAt    *string `json:"expiresAt"`
	}
	if err = decoder.Decode(&reply); err != nil || decoder.More() || reply.FlowID == nil || reply.AuthorizeURL == nil || reply.ExpiresAt == nil {
		return "", "", "", errors.New("mobiletest: the begin reply is not exactly flowId, authorizeUrl and expiresAt")
	}
	if !flowShape.MatchString(*reply.FlowID) || *reply.FlowID == "00000000-0000-0000-0000-000000000000" || !instantShape.MatchString(*reply.ExpiresAt) {
		return "", "", "", errors.New("mobiletest: the begin reply's flowId or expiresAt is not of the contract's shape")
	}
	if *reply.AuthorizeURL != AuthorizeURL(center, *reply.FlowID) || len(*reply.AuthorizeURL) > 512 {
		return "", "", "", ErrMixUp
	}
	return *reply.FlowID, *reply.AuthorizeURL, *reply.ExpiresAt, nil
}

// ErrMixUp is a begin reply whose authorizeUrl is not the one the app derives (RFC 9700 section 4.4), or a callback whose issuer is
// not the configured center: the app drops it without any further network call.
var ErrMixUp = errors.New("mobiletest: the center's answer does not name the configured center")

// ErrState is a callback whose state is not the pending attempt's: the app drops it without any network call.
var ErrState = errors.New("mobiletest: the callback's state is not the pending attempt's")

// Callback is a parsed callback: the code of an approval, or the denial.
type Callback struct {
	Code   string
	Denied bool
}

// The shapes the app checks in a callback (MobileAuthorizeCallbackSuccess and Failure).
var (
	codeShape  = regexp.MustCompile(`^[A-Za-z0-9_-]{42}[AEIMQUYcgkosw048]$`)
	stateShape = regexp.MustCompile(`^[A-Za-z0-9._~-]{16,128}$`)
)

// ParseCallback reads the callback a browser hands the app (MobileAuthorizeCallbackSuccess or Failure): the registered redirect with a
// form-urlencoded fragment of exactly three distinct members, code (or error=access_denied), state and iss, in any order (the center
// writes them in the contract's order, with iss percent-encoded). It checks the redirect, the shapes, the issuer against the configured
// center and the state against the pending attempt before anything else (MB-2 (b), (c)); nothing here sends a request.
func (a *App) ParseCallback(link string, attempt Attempt) (Callback, error) {
	target, fragment, found := strings.Cut(link, "#")
	if !found || target != a.Redirect {
		return Callback{}, errors.New("mobiletest: the callback is not the registered redirect")
	}
	return ParseFragment(fragment, a.Center, attempt.State)
}

// ParseFragment checks a callback's fragment against a configured center and a pending state.
func ParseFragment(fragment, center, state string) (Callback, error) {
	values, err := url.ParseQuery(fragment)
	if err != nil || len(values) != 3 || strings.Count(fragment, "&") != 2 {
		return Callback{}, errors.New("mobiletest: the fragment is not three members")
	}
	for name, list := range values {
		if len(list) != 1 || name != "code" && name != "error" && name != "state" && name != "iss" {
			return Callback{}, errors.New("mobiletest: a repeated or unknown fragment member")
		}
	}
	if !values.Has("state") || !values.Has("iss") || !stateShape.MatchString(values.Get("state")) {
		return Callback{}, errors.New("mobiletest: the fragment has no state or iss of the contract's shape")
	}
	if values.Get("iss") != center {
		return Callback{}, ErrMixUp
	}
	if values.Get("state") != state {
		return Callback{}, ErrState
	}
	switch {
	case values.Has("code") && codeShape.MatchString(values.Get("code")):
		return Callback{Code: values.Get("code")}, nil
	case values.Has("error") && values.Get("error") == "access_denied":
		return Callback{Denied: true}, nil
	}
	return Callback{}, errors.New("mobiletest: the fragment is neither a canonical code nor a denial")
}

// TokenBody is the MobileTokenRequest of an attempt's code with a verifier.
func (a *App) TokenBody(attempt Attempt, code, verifier string) []byte {
	body, _ := json.Marshal(map[string]string{"flowId": attempt.FlowID, "code": code, "codeVerifier": verifier, "clientId": a.ClientID,
		"redirectUri": a.Redirect, "installationId": a.InstallationID.String()})
	return body
}

// Token redeems a code with the attempt's verifier.
func (a *App) Token(ctx context.Context, attempt Attempt, code string) (Reply, error) {
	return a.Post(ctx, "/session/v1/mobile/token", a.TokenBody(attempt, code, attempt.Verifier))
}

// TokenWith redeems a code with another verifier (the wrong-verifier case).
func (a *App) TokenWith(ctx context.Context, attempt Attempt, code, verifier string) (Reply, error) {
	return a.Post(ctx, "/session/v1/mobile/token", a.TokenBody(attempt, code, verifier))
}
