// SPDX-License-Identifier: AGPL-3.0-only

package config

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"strings"
	"time"
)

// The environment of the identity surface (AF-CTR-03).
const (
	EnvSurfaces           = "ARCFORGES_CENTER_SURFACES"
	EnvClientIPHeader     = "ARCFORGES_CENTER_CLIENT_IP_HEADER"
	EnvTrustedProxies     = "ARCFORGES_CENTER_TRUSTED_PROXIES"
	EnvBootstrapSHA256    = "ARCFORGES_CENTER_BOOTSTRAP_SHA256"
	EnvBootstrapExpiresAt = "ARCFORGES_CENTER_BOOTSTRAP_EXPIRES_AT"
	EnvIdentityPolicy     = "ARCFORGES_CENTER_IDENTITY_POLICY"
)

// Surface is a switchable group of routes (AD-0021 section 13a; AF-PLAT-01 owns the activation variable and its other names).
type Surface string

// SurfaceIdentity is accounts, sessions and devices (the IdentityService and DeviceService methods).
const SurfaceIdentity Surface = "identity"

// SurfacePages is the center's own account pages and the WebBrowserSession routes under /session/v1/web (AF-CTR-03 A2): the
// sign-in, bootstrap, account and passkeys, sessions, devices and sign-out pages and the JSON routes their script calls. It needs
// the identity surface, whose domain functions it calls; it is off wherever FLAGSHIP_SURFACES does not name it.
const SurfacePages Surface = "pages"

// SurfaceOperations is the interim operations page (AF-CTR-03 part B): the operator's grant of features to an account, with step-up
// evidence, until AF-OPS-01's operator service replaces it. It needs the identity and pages surfaces (the page's script proves the
// step-up through the pages' JSON routes), exists on the official hosted center only, and is never part of a self-hosted center's
// default: it is on only where FLAGSHIP_SURFACES names it.
const SurfaceOperations Surface = "operations"

// KnownSurfaces is every surface name, in generated order.
func KnownSurfaces() []Surface { return []Surface{SurfaceIdentity, SurfacePages, SurfaceOperations} }

// DefaultSelfHostedSurfaces are the surfaces a self-hosted center enables when the list is not stated: the account surfaces, never the
// operations page.
func DefaultSelfHostedSurfaces() []Surface { return []Surface{SurfaceIdentity, SurfacePages} }

// ClientIPHeader is the one header the hosted Worker sets to the client's address (from cf-connecting-ip, overwriting any client
// value); the generated Worker tables carry the same name.
const ClientIPHeader = "X-Arcforges-Client-Ip"

// MaxBootstrapLead bounds how far ahead a bootstrap token may expire.
const MaxBootstrapLead = 7 * 24 * time.Hour

// Bootstrap is the configured owner bootstrap: the SHA-256 of the one-time token and its expiry. The token itself is never
// configuration, never logged and never in the repository.
type Bootstrap struct {
	TokenSHA256 [32]byte
	ExpiresAt   time.Time
}

// Identity is the configuration of the identity surface.
type Identity struct {
	// Surfaces are the enabled surfaces. Official-hosted mode enables none unless listed; self-hosted mode enables every known
	// surface unless listed.
	Surfaces []Surface
	// ClientIPHeader names the header that carries the client's address (official-hosted mode with a surface enabled requires
	// exactly ClientIPHeader); empty means the TCP peer.
	ClientIPHeader string
	// TrustedProxies are the peers whose ClientIPHeader a self-hosted center trusts; the TCP peer is used for anyone else.
	TrustedProxies []netip.Prefix
	// Bootstrap is the owner bootstrap, or nil.
	Bootstrap *Bootstrap
	// Policy is every lifetime and limit of the identity surface.
	Policy IdentityPolicy
	// Disabled explains why a self-hosted center's default left the identity surface off (its public base URL cannot be a WebAuthn
	// relying party); the center logs it at start. Empty otherwise.
	Disabled string
}

// Enabled reports whether a surface is enabled.
func (i Identity) Enabled(surface Surface) bool { return slices.Contains(i.Surfaces, surface) }

// Window is a fixed-window rate limit: at most Limit requests per Window.
type Window struct {
	Limit  int           `json:"limit"`
	Window time.Duration `json:"-"`
}

// IdentityPolicy holds every lifetime and limit of the identity surface in one place, with documented defaults (docs/center.md,
// "Identity policy"). An operator may override values within their bounds with ARCFORGES_CENTER_IDENTITY_POLICY (JSON); the hosted
// Worker passes it only where wrangler.json sets it, which only the acceptance environment does (its anonymous-flow ceiling).
type IdentityPolicy struct {
	AccessTokenLifetime   time.Duration
	RefreshIdleLifetime   time.Duration
	RefreshAbsolute       time.Duration
	BrowserAbsolute       time.Duration
	BrowserIdle           time.Duration
	PasskeyFlowLifetime   time.Duration
	EmailCodeLifetime     time.Duration
	EmailCodeAttempts     int
	EmailCodeSends        int
	EmailCodeIterations   int
	StepUpEvidenceTTL     time.Duration
	SignInPerPrefix       Window
	SignInFailuresAccount Window
	EmailPerPrefix        Window
	EmailPerAddress       Window
	RedeemFailuresAddress Window
	RefreshPerPrefix      Window
	StepUpPerAccount      Window
	BootstrapPerPrefix    Window
	// AnonymousFlows is an opt-in global ceiling on the flows anonymous calls create (C1): every BeginAuthentication, of every method
	// and purpose, counts in one bucket. A limit of 0 (the default) sets no ceiling. Only the acceptance environment sets one: it
	// shares the production Neon project, and its flows are never deleted before AF-PLAT-01's sweeps exist. A global bucket would let
	// anyone lock every sign-in out, so production sets none (AF-PROD-01 decides with the sweeps).
	AnonymousFlows Window
}

// DefaultIdentityPolicy is the policy without an override.
func DefaultIdentityPolicy() IdentityPolicy {
	return IdentityPolicy{
		AccessTokenLifetime:   15 * time.Minute,
		RefreshIdleLifetime:   30 * 24 * time.Hour,
		RefreshAbsolute:       90 * 24 * time.Hour,
		BrowserAbsolute:       12 * time.Hour,
		BrowserIdle:           30 * time.Minute,
		PasskeyFlowLifetime:   5 * time.Minute,
		EmailCodeLifetime:     10 * time.Minute,
		EmailCodeAttempts:     5,
		EmailCodeSends:        3,
		EmailCodeIterations:   20_000,
		StepUpEvidenceTTL:     5 * time.Minute,
		SignInPerPrefix:       Window{Limit: 30, Window: 10 * time.Minute},
		SignInFailuresAccount: Window{Limit: 10, Window: 10 * time.Minute},
		EmailPerPrefix:        Window{Limit: 10, Window: time.Hour},
		EmailPerAddress:       Window{Limit: 5, Window: time.Hour},
		RedeemFailuresAddress: Window{Limit: 10, Window: time.Hour},
		RefreshPerPrefix:      Window{Limit: 120, Window: 10 * time.Minute},
		StepUpPerAccount:      Window{Limit: 10, Window: 10 * time.Minute},
		BootstrapPerPrefix:    Window{Limit: 10, Window: time.Hour},
		AnonymousFlows:        Window{Limit: 0, Window: time.Hour},
	}
}

type durationBound struct {
	target   *time.Duration
	min, max time.Duration
}

type countBound struct {
	target   *int
	min, max int
}

// policyFields lists every overridable field with its bounds, keyed by its JSON name.
func (p *IdentityPolicy) policyFields() (map[string]durationBound, map[string]countBound) {
	durations := map[string]durationBound{
		"accessTokenLifetime": {&p.AccessTokenLifetime, time.Minute, time.Hour},
		"refreshIdleLifetime": {&p.RefreshIdleLifetime, time.Hour, 90 * 24 * time.Hour},
		"refreshAbsolute":     {&p.RefreshAbsolute, time.Hour, 400 * 24 * time.Hour},
		"browserAbsolute":     {&p.BrowserAbsolute, 10 * time.Minute, 7 * 24 * time.Hour},
		"browserIdle":         {&p.BrowserIdle, time.Minute, 24 * time.Hour},
		"passkeyFlowLifetime": {&p.PasskeyFlowLifetime, time.Minute, 15 * time.Minute},
		"emailCodeLifetime":   {&p.EmailCodeLifetime, time.Minute, 30 * time.Minute},
		"stepUpEvidenceTtl":   {&p.StepUpEvidenceTTL, time.Minute, 5 * time.Minute},
	}
	counts := map[string]countBound{
		"emailCodeAttempts":   {&p.EmailCodeAttempts, 1, 10},
		"emailCodeSends":      {&p.EmailCodeSends, 1, 3},
		"emailCodeIterations": {&p.EmailCodeIterations, 10_000, 600_000},
	}
	for name, window := range map[string]*Window{
		"signInPerPrefix": &p.SignInPerPrefix, "signInFailuresAccount": &p.SignInFailuresAccount, "emailPerPrefix": &p.EmailPerPrefix,
		"emailPerAddress": &p.EmailPerAddress, "redeemFailuresAddress": &p.RedeemFailuresAddress, "refreshPerPrefix": &p.RefreshPerPrefix,
		"stepUpPerAccount": &p.StepUpPerAccount, "bootstrapPerPrefix": &p.BootstrapPerPrefix,
	} {
		counts[name+"Limit"] = countBound{&window.Limit, 1, 10_000}
		durations[name+"Window"] = durationBound{&window.Window, time.Minute, 24 * time.Hour}
	}
	// The anonymous-flow ceiling is opt-in: 0 sets none.
	counts["anonymousFlowsLimit"] = countBound{&p.AnonymousFlows.Limit, 0, 10_000}
	durations["anonymousFlowsWindow"] = durationBound{&p.AnonymousFlows.Window, time.Minute, 24 * time.Hour}
	return durations, counts
}

// Validate checks every value against its bounds and the relations between them.
func (p IdentityPolicy) Validate() error {
	durations, counts := p.policyFields()
	for name, bound := range durations {
		if *bound.target < bound.min || *bound.target > bound.max {
			return fmt.Errorf("%s must be from %s to %s", name, bound.min, bound.max)
		}
	}
	for name, bound := range counts {
		if *bound.target < bound.min || *bound.target > bound.max {
			return fmt.Errorf("%s must be from %d to %d", name, bound.min, bound.max)
		}
	}
	switch {
	case p.RefreshIdleLifetime > p.RefreshAbsolute:
		return errors.New("refreshIdleLifetime must not exceed refreshAbsolute")
	case p.BrowserIdle > p.BrowserAbsolute:
		return errors.New("browserIdle must not exceed browserAbsolute")
	case p.AccessTokenLifetime > p.RefreshIdleLifetime:
		return errors.New("accessTokenLifetime must not exceed refreshIdleLifetime")
	}
	return nil
}

// MaxIdentityPolicyBytes bounds the override document.
const MaxIdentityPolicyBytes = 4096

// ParseIdentityPolicy applies an override document to the defaults: a JSON object whose keys are field names (durations as Go
// duration strings such as "15m", counts as integers); unknown keys, repeated keys and values out of bounds refuse.
func ParseIdentityPolicy(document string) (IdentityPolicy, error) {
	policy := DefaultIdentityPolicy()
	if document == "" {
		return policy, nil
	}
	if len(document) > MaxIdentityPolicyBytes {
		return IdentityPolicy{}, errors.New("longer than 4096 bytes")
	}
	decoder := json.NewDecoder(bytes.NewReader([]byte(document)))
	decoder.UseNumber()
	var raw map[string]json.RawMessage
	if err := decoder.Decode(&raw); err != nil || decoder.More() {
		return IdentityPolicy{}, errors.New("not one JSON object")
	}
	if err := refuseRepeatedKeys(document); err != nil {
		return IdentityPolicy{}, err
	}
	durations, counts := policy.policyFields()
	for name, value := range raw {
		if bound, ok := durations[name]; ok {
			var text string
			if err := json.Unmarshal(value, &text); err != nil {
				return IdentityPolicy{}, fmt.Errorf("%s must be a duration string", name)
			}
			parsed, err := time.ParseDuration(text)
			if err != nil {
				return IdentityPolicy{}, fmt.Errorf("%s must be a duration string", name)
			}
			*bound.target = parsed
			continue
		}
		if bound, ok := counts[name]; ok {
			var number int
			if err := json.Unmarshal(value, &number); err != nil {
				return IdentityPolicy{}, fmt.Errorf("%s must be a whole number", name)
			}
			*bound.target = number
			continue
		}
		return IdentityPolicy{}, fmt.Errorf("unknown setting %q", name)
	}
	if err := policy.Validate(); err != nil {
		return IdentityPolicy{}, err
	}
	return policy, nil
}

// refuseRepeatedKeys refuses an object that names a key twice (encoding/json would keep the last).
func refuseRepeatedKeys(document string) error {
	decoder := json.NewDecoder(strings.NewReader(document))
	if token, err := decoder.Token(); err != nil || token != json.Delim('{') {
		return errors.New("not one JSON object")
	}
	seen := map[string]bool{}
	for decoder.More() {
		token, err := decoder.Token()
		if err != nil {
			return errors.New("not one JSON object")
		}
		key, _ := token.(string)
		if seen[key] {
			return fmt.Errorf("setting %q is repeated", key)
		}
		seen[key] = true
		var skip json.RawMessage
		if err = decoder.Decode(&skip); err != nil {
			return errors.New("not one JSON object")
		}
	}
	return nil
}

// loadIdentity reads the identity configuration of a mode.
func loadIdentity(get func(string) string, mode Mode, publicBaseURL string, now time.Time) (Identity, error) {
	var identity Identity
	surfaces, err := parseSurfaces(get(EnvSurfaces), mode)
	if err != nil {
		return Identity{}, invalid("%s: %v", EnvSurfaces, err)
	}
	identity.Surfaces = surfaces
	header := get(EnvClientIPHeader)
	switch {
	case header == "":
	case strings.EqualFold(header, ClientIPHeader):
		identity.ClientIPHeader = ClientIPHeader
	default:
		return Identity{}, invalid("%s must be empty or %s", EnvClientIPHeader, ClientIPHeader)
	}
	if mode == OfficialHosted && len(identity.Surfaces) > 0 && identity.ClientIPHeader == "" {
		return Identity{}, invalid("%s must be %s in %s mode while a surface is enabled: the rate limits key on the client address the Worker sets",
			EnvClientIPHeader, ClientIPHeader, OfficialHosted)
	}
	if value := get(EnvTrustedProxies); value != "" {
		if mode != SelfHosted {
			return Identity{}, invalid("%s applies to a self-hosted center only", EnvTrustedProxies)
		}
		for item := range strings.SplitSeq(value, ",") {
			prefix, err := netip.ParsePrefix(item)
			if err != nil || prefix != prefix.Masked() {
				return Identity{}, invalid("%s must be a comma-separated list of CIDR prefixes", EnvTrustedProxies)
			}
			identity.TrustedProxies = append(identity.TrustedProxies, prefix)
		}
		if identity.ClientIPHeader == "" {
			return Identity{}, invalid("%s needs %s", EnvTrustedProxies, EnvClientIPHeader)
		}
	} else if mode == SelfHosted && identity.ClientIPHeader != "" {
		return Identity{}, invalid("%s in %s mode needs %s (the proxies whose header is trusted)", EnvClientIPHeader, SelfHosted, EnvTrustedProxies)
	}
	if identity.Bootstrap, err = parseBootstrap(get(EnvBootstrapSHA256), get(EnvBootstrapExpiresAt), now); err != nil {
		return Identity{}, err
	}
	if identity.Policy, err = ParseIdentityPolicy(get(EnvIdentityPolicy)); err != nil {
		return Identity{}, invalid("%s: %v", EnvIdentityPolicy, err)
	}
	if identity.Enabled(SurfacePages) && !identity.Enabled(SurfaceIdentity) {
		return Identity{}, invalid("the %s surface needs the %s surface: the pages call its domain functions", SurfacePages, SurfaceIdentity)
	}
	if identity.Enabled(SurfaceOperations) {
		if !identity.Enabled(SurfaceIdentity) || !identity.Enabled(SurfacePages) {
			return Identity{}, invalid("the %s surface needs the %s and %s surfaces: its page proves a step-up through the pages' routes", SurfaceOperations, SurfaceIdentity, SurfacePages)
		}
		if mode != OfficialHosted {
			return Identity{}, invalid("the %s surface exists on the official hosted center only: operator grants have no place on a self-hosted center", SurfaceOperations)
		}
	}
	if identity.Enabled(SurfaceIdentity) {
		if err = RequireRelyingParty(publicBaseURL); err != nil {
			if get(EnvSurfaces) != "" {
				return Identity{}, invalid("the identity surface is listed in %s: %v", EnvSurfaces, err)
			}
			// The self-hosted default never refuses to start: identity stays off, and so do the pages that need it, and the start-up
			// log says why (PLT-16).
			identity.Surfaces = slices.DeleteFunc(identity.Surfaces, func(s Surface) bool { return s == SurfaceIdentity || s == SurfacePages || s == SurfaceOperations })
			identity.Disabled = err.Error()
		}
	}
	return identity, nil
}

// parseSurfaces reads the surface list: exact generated names, comma-separated, without whitespace or repetition. Official-hosted
// mode enables none unless listed; self-hosted mode enables the default surfaces (identity and pages, not operations) unless listed,
// so an explicit list pins the surfaces across upgrades.
func parseSurfaces(value string, mode Mode) ([]Surface, error) {
	if value == "" {
		if mode == SelfHosted {
			return DefaultSelfHostedSurfaces(), nil
		}
		return nil, nil
	}
	if value == "none" {
		return nil, nil
	}
	var surfaces []Surface
	for item := range strings.SplitSeq(value, ",") {
		surface := Surface(item)
		if !slices.Contains(KnownSurfaces(), surface) {
			return nil, errors.New("not a comma-separated list of known surface names (or none)")
		}
		if slices.Contains(surfaces, surface) {
			return nil, errors.New("a surface is listed twice")
		}
		surfaces = append(surfaces, surface)
	}
	return surfaces, nil
}

// parseBootstrap reads the owner bootstrap: both variables or neither; 64 lowercase hexadecimal characters and an RFC 3339 UTC
// instant at most seven days ahead. A past instant loads (E2): the bootstrap is then refused at use with the reason expired, and a
// restart with the variables left set still starts the center (the start-up log warns that they can be removed).
func parseBootstrap(digest, expires string, now time.Time) (*Bootstrap, error) {
	if digest == "" && expires == "" {
		return nil, nil
	}
	if digest == "" || expires == "" {
		return nil, invalid("%s and %s are set together or not at all", EnvBootstrapSHA256, EnvBootstrapExpiresAt)
	}
	var bootstrap Bootstrap
	if len(digest) != 64 || strings.ToLower(digest) != digest {
		return nil, invalid("%s must be 64 lowercase hexadecimal characters", EnvBootstrapSHA256)
	}
	for index := range 32 {
		var value byte
		for _, c := range digest[2*index : 2*index+2] {
			switch {
			case c >= '0' && c <= '9':
				value = value<<4 | byte(c-'0')
			case c >= 'a' && c <= 'f':
				value = value<<4 | byte(c-'a'+10)
			default:
				return nil, invalid("%s must be 64 lowercase hexadecimal characters", EnvBootstrapSHA256)
			}
		}
		bootstrap.TokenSHA256[index] = value
	}
	at, err := time.Parse(time.RFC3339, expires)
	if err != nil || !strings.HasSuffix(expires, "Z") || at.Format(time.RFC3339) != expires && at.Format(time.RFC3339Nano) != expires {
		return nil, invalid("%s must be an RFC 3339 UTC instant (…Z)", EnvBootstrapExpiresAt)
	}
	if at.Sub(now) > MaxBootstrapLead {
		return nil, invalid("%s must be at most seven days ahead", EnvBootstrapExpiresAt)
	}
	bootstrap.ExpiresAt = at.UTC()
	return &bootstrap, nil
}

// RequireRelyingParty refuses a public base URL whose host cannot be a WebAuthn relying party ID: an IP literal (PLT-16).
func RequireRelyingParty(publicBaseURL string) error {
	host := RelyingPartyID(publicBaseURL)
	if host == "" {
		return errors.New("the public base URL has no host")
	}
	if _, err := netip.ParseAddr(strings.Trim(host, "[]")); err == nil {
		return errors.New("passkeys need a domain name as the public base URL's host, not an IP address")
	}
	return nil
}

// RelyingPartyID is the host of the public base URL (the WebAuthn RP ID).
func RelyingPartyID(publicBaseURL string) string {
	rest, ok := strings.CutPrefix(publicBaseURL, "https://")
	if !ok {
		rest, _ = strings.CutPrefix(publicBaseURL, "http://")
	}
	host, _, _ := strings.Cut(rest, "/")
	if strings.HasPrefix(host, "[") {
		end := strings.IndexByte(host, ']')
		if end < 0 {
			return ""
		}
		return host[:end+1]
	}
	name, _, _ := strings.Cut(host, ":")
	return name
}

// Origin is the scheme, host and port of the public base URL (the WebAuthn origin and the exact Origin of browser requests).
func Origin(publicBaseURL string) string {
	scheme, rest, ok := strings.Cut(publicBaseURL, "://")
	if !ok {
		return ""
	}
	host, _, _ := strings.Cut(rest, "/")
	return scheme + "://" + host
}

// BasePath is the path of the public base URL below its origin, without a trailing slash: "" for a center at the root of its host,
// "/api" for the hosted center. The center's pages link and redirect below it.
func BasePath(publicBaseURL string) string {
	_, rest, ok := strings.Cut(publicBaseURL, "://")
	if !ok {
		return ""
	}
	_, path, found := strings.Cut(rest, "/")
	if !found {
		return ""
	}
	return strings.TrimRight("/"+path, "/")
}
