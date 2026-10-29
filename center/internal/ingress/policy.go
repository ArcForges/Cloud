// SPDX-License-Identifier: AGPL-3.0-only

// Package ingress is the center's public admission pipeline: the deny-by-default method policy registry, the binary
// gRPC-Web and gRPC framing checks, the credential shape and owner gate, the per-method body bound, the correlation identity
// and the mapping of refusals to gRPC status codes and trailers. It is a port of the C# host's IngressPipeline
// (src/ArcForges.Cloud/Ingress) for the methods the Go center serves; every method registers against it by declaring its
// policy, and a method without a policy is refused.
package ingress

import (
	"errors"
	"fmt"
	"regexp"
)

// Kind is the shape of a method.
type Kind int

const (
	// Unary is one request message, one response message and the status trailer.
	Unary Kind = iota + 1
	// ServerStream is one request message and a stream of response frames ended by the status trailer. There is no client
	// or bidirectional stream.
	ServerStream
)

// Authentication is what a method requires of its caller.
type Authentication int

const (
	// Anonymous reads, validates and forwards no credential; the caller is anonymous.
	Anonymous Authentication = iota + 1
	// Session requires a native bearer or an origin-bound browser cookie session that validates before any business code
	// runs.
	Session
)

// Scope is the ownership a method requires.
type Scope int

const (
	// NoScope is account or anonymous scope: the envelope is not interpreted for ownership.
	NoScope Scope = iota + 1
	// Workspace requires the envelope to name a workspace the authenticated caller currently owns, in the caller's recovery
	// generation.
	Workspace
)

// AbsoluteMaxRequestBytes bounds every declared request bound.
const AbsoluteMaxRequestBytes = 262_144

// DefaultMaxRequestBytes is the request bound of a method that declares no other.
const DefaultMaxRequestBytes = 4096

// Policy is the declared ingress contract of one public method. MaxRequestBytes bounds the whole request body including the
// five-byte frame header.
type Policy struct {
	FullName        string
	Kind            Kind
	Authentication  Authentication
	Scope           Scope
	MaxRequestBytes int
	// CarriesRequestMeta states that the request message starts with a RequestMeta (field 1, wire registry 04) even though
	// the method is not workspace-scoped. A method whose field 1 means something else (the Hello name) never does, so its
	// body is not interpreted.
	CarriesRequestMeta bool
	// Surface names the switchable surface the method belongs to (AF-CTR-03; empty for the always-on Hello). A method of a disabled
	// surface is answered with the domain refusal STATE/not_activated before any credential is read.
	Surface string
}

// InSurface is the policy as a method of a surface.
func (p Policy) InSurface(surface string) Policy {
	p.Surface = surface
	return p
}

// ReadsRequestMeta reports whether the pipeline reads and validates the RequestMeta envelope of the method's request.
func (p Policy) ReadsRequestMeta() bool { return p.Scope == Workspace || p.CarriesRequestMeta }

var namePattern = regexp.MustCompile(`^/[a-z][a-z0-9_]*(\.[a-z][a-z0-9_]*)*\.[A-Z][A-Za-z0-9]*/[A-Z][A-Za-z0-9]*$`)

// IsValidName reports whether path is /package.Service/Method: a lowercase dotted proto package, a service and a method in
// PascalCase.
func IsValidName(path string) bool { return namePattern.MatchString(path) }

// ErrInvalidPolicy is returned for a policy that cannot be registered.
var ErrInvalidPolicy = errors.New("invalid RPC policy")

// NewUnary declares a unary method.
func NewUnary(fullName string, authentication Authentication, scope Scope, maxRequestBytes int, carriesRequestMeta bool) (Policy, error) {
	return newPolicy(fullName, Unary, authentication, scope, maxRequestBytes, carriesRequestMeta)
}

// NewServerStream declares a server-streaming method.
func NewServerStream(fullName string, authentication Authentication, scope Scope, maxRequestBytes int, carriesRequestMeta bool) (Policy, error) {
	return newPolicy(fullName, ServerStream, authentication, scope, maxRequestBytes, carriesRequestMeta)
}

func newPolicy(fullName string, kind Kind, authentication Authentication, scope Scope, maxRequestBytes int, carriesRequestMeta bool) (Policy, error) {
	switch {
	case !IsValidName(fullName):
		return Policy{}, fmt.Errorf("%w: the name is not /package.Service/Method", ErrInvalidPolicy)
	case maxRequestBytes < 1 || maxRequestBytes > AbsoluteMaxRequestBytes:
		return Policy{}, fmt.Errorf("%w: the request bound of %s is out of range", ErrInvalidPolicy, fullName)
	case authentication != Anonymous && authentication != Session:
		return Policy{}, fmt.Errorf("%w: unknown authentication for %s", ErrInvalidPolicy, fullName)
	case scope != NoScope && scope != Workspace:
		return Policy{}, fmt.Errorf("%w: unknown scope for %s", ErrInvalidPolicy, fullName)
	case authentication == Anonymous && scope != NoScope:
		return Policy{}, fmt.Errorf("%w: an anonymous method has no owner scope (%s)", ErrInvalidPolicy, fullName)
	}
	return Policy{
		FullName: fullName, Kind: kind, Authentication: authentication, Scope: scope, MaxRequestBytes: maxRequestBytes,
		CarriesRequestMeta: carriesRequestMeta,
	}, nil
}

// Registry is the deny-by-default method table: exact path to policy, duplicates refused at composition.
type Registry struct {
	byName map[string]Policy
	order  []string
}

// NewRegistry composes the method table; a duplicate path is refused.
func NewRegistry(policies ...Policy) (*Registry, error) {
	registry := &Registry{byName: make(map[string]Policy, len(policies))}
	for _, policy := range policies {
		if policy.FullName == "" || policy.Kind == 0 {
			return nil, fmt.Errorf("%w: an undeclared policy", ErrInvalidPolicy)
		}
		if _, duplicate := registry.byName[policy.FullName]; duplicate {
			return nil, fmt.Errorf("%w: duplicate RPC policy %s", ErrInvalidPolicy, policy.FullName)
		}
		registry.byName[policy.FullName] = policy
		registry.order = append(registry.order, policy.FullName)
	}
	return registry, nil
}

// Lookup is the policy of an exact method path.
func (r *Registry) Lookup(path string) (Policy, bool) {
	policy, ok := r.byName[path]
	return policy, ok
}

// All is every registered policy in registration order.
func (r *Registry) All() []Policy {
	result := make([]Policy, 0, len(r.order))
	for _, name := range r.order {
		result = append(result, r.byName[name])
	}
	return result
}

// Routes is everything the center serves on a public listener: the RPC policy table and the few plain HTTP routes (health)
// that have their own checks. A path in neither is refused before routing, so deny-by-default does not depend on how a path
// happens to look.
type Routes struct {
	Registry *Registry
	plain    map[string]bool
	prefixes []string
}

// NewRoutes composes the public routes.
func NewRoutes(registry *Registry, plainPaths, plainPrefixes []string) *Routes {
	plain := make(map[string]bool, len(plainPaths))
	for _, path := range plainPaths {
		plain[path] = true
	}
	return &Routes{Registry: registry, plain: plain, prefixes: append([]string(nil), plainPrefixes...)}
}

// IsPlain reports an exact plain route, or a path strictly under a plain prefix (case-sensitive).
func (r *Routes) IsPlain(path string) bool {
	if r.plain[path] {
		return true
	}
	for _, prefix := range r.prefixes {
		if len(path) > len(prefix) && path[:len(prefix)] == prefix {
			return true
		}
	}
	return false
}
