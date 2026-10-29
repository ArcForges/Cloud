// SPDX-License-Identifier: AGPL-3.0-only

package ingress

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/http"
	"net/netip"
	"strconv"
	"strings"

	"github.com/ArcForges/Cloud/center/internal/arc"
	"github.com/ArcForges/Cloud/center/internal/correlation"
)

// Outcome is what the pipeline reports about one request to its observer (logs and metrics). It carries no request content:
// Method is a registered method path or a fixed word, never a client value.
type Outcome struct {
	// Method is the registered method path, "plain" for a plain route, "unregistered" for a method-shaped path without a
	// policy and "not_found" for any other path.
	Method string
	// Refusal is the pipeline's refusal, or nil when the request was admitted or answered with a plain status.
	Refusal *Reason
	// HTTPStatus is the plain HTTP status the pipeline answered with (404, 405, 415), or 0.
	HTTPStatus int
	// Call is the admitted call, or nil.
	Call *Call
	// Domain is the code of a domain refusal the pipeline answered itself (STATE/not_activated of a disabled surface), or empty.
	Domain string
	// Correlation is the correlation id of that domain reply, or empty.
	Correlation string
}

// Options configure the pipeline.
type Options struct {
	Routes *Routes
	// Bearer validates native bearer credentials; nil admits none.
	Bearer BearerVerifier
	// Browser validates browser session cookies; nil admits none.
	Browser BrowserSessionVerifier
	// Observe receives the pipeline's decision about every request; it may be nil.
	Observe func(*http.Request, Outcome)
	// SurfaceEnabled reports whether a surface is enabled; nil enables none.
	SurfaceEnabled func(surface string) bool
	// ClientIP extracts the client's address of a surface method's request; nil knows none.
	ClientIP func(*http.Request) (netip.Addr, bool)
	// RequireClientIP refuses a surface method whose client address is unknown (hosted mode: the Worker always sets it, so its
	// absence is never counted in a shared bucket).
	RequireClientIP bool
}

// NewPipeline is the public admission pipeline in front of next (the Connect handlers and the plain routes): a path that is not
// byte-for-byte canonical is refused, and a canonical path must be a registered RPC or one of the declared plain routes. A
// refusal is a trailers-only status (or a plain HTTP status); no handler has run when it is produced.
func NewPipeline(options Options, next http.Handler) http.Handler {
	return &pipeline{options: options, next: next}
}

type pipeline struct {
	options Options
	next    http.Handler
}

func (p *pipeline) observe(request *http.Request, outcome Outcome) {
	if p.options.Observe != nil {
		p.options.Observe(request, outcome)
	}
}

func (p *pipeline) ServeHTTP(writer http.ResponseWriter, request *http.Request) {
	path := request.URL.Path
	switch {
	case !IsCanonical(request):
		p.observe(request, Outcome{Method: "not_found", HTTPStatus: http.StatusNotFound})
		plain(writer, http.StatusNotFound)
	case p.options.Routes.IsPlain(path):
		p.observe(request, Outcome{Method: "plain"})
		p.next.ServeHTTP(writer, request)
	case LooksLikeRPC(path):
		p.admit(writer, request)
	default:
		// A path shaped like a method but not registered gets a gRPC status; anything else is simply not served.
		p.observe(request, Outcome{Method: "not_found", HTTPStatus: http.StatusNotFound})
		plain(writer, http.StatusNotFound)
	}
}

// IsCanonical reports a request target that is exactly its decoded path: no percent-encoding, no dot segments, no empty
// segment, no trailing slash, no backslash and no absolute-form target. Routing would otherwise match variants that the exact
// tables here (and the Worker's) do not.
func IsCanonical(request *http.Request) bool {
	path := request.URL.Path
	if path == "" || path[0] != '/' || strings.Contains(path, "//") || strings.ContainsRune(path, '\\') {
		return false
	}
	if len(path) > 1 && path[len(path)-1] == '/' {
		return false
	}
	for segment := range strings.SplitSeq(path[1:], "/") {
		if segment == "." || segment == ".." {
			return false
		}
	}
	target := request.RequestURI
	if target == "" {
		return true // a request built in process, never one read from a connection
	}
	if query := strings.IndexByte(target, '?'); query >= 0 {
		target = target[:query]
	}
	return target == path
}

// LooksLikeRPC reports two segments, the first a dotted proto package and service: the shape every public method has.
func LooksLikeRPC(path string) bool {
	if len(path) <= 3 || path[0] != '/' {
		return false
	}
	separator := strings.IndexByte(path[1:], '/') + 1
	return separator > 1 && separator < len(path)-1 && !strings.Contains(path[separator+1:], "/") &&
		strings.Contains(path[1:separator], ".")
}

func (p *pipeline) admit(writer http.ResponseWriter, request *http.Request) {
	if request.Method != http.MethodPost {
		p.observe(request, Outcome{Method: "unregistered", HTTPStatus: http.StatusMethodNotAllowed})
		plain(writer, http.StatusMethodNotAllowed)
		return
	}
	policy, ok := p.options.Routes.Registry.Lookup(request.URL.Path)
	if !ok {
		p.refuse(writer, request, Outcome{Method: "unregistered"}, ReasonUnimplemented)
		return
	}
	outcome := Outcome{Method: policy.FullName}
	if !isAdmittedMedia(request.Header) {
		outcome.HTTPStatus = http.StatusUnsupportedMediaType
		p.observe(request, outcome)
		plain(writer, http.StatusUnsupportedMediaType)
		return
	}
	var clientIP netip.Addr
	if policy.Surface != "" {
		// A disabled surface is answered before any credential, body or store is read, with the same domain refusal the Worker
		// sends (this one carries the call's correlation id).
		if p.options.SurfaceEnabled == nil || !p.options.SurfaceEnabled(policy.Surface) {
			call := correlation.ForRequest(request.Header.Values(TraceparentHeader), "")
			reply, err := arc.ReplyMessage(arc.NotActivated(policy.Surface).ArcError(call))
			if err != nil {
				p.refuse(writer, request, outcome, ReasonInvalidRequest)
				return
			}
			outcome.Domain, outcome.Correlation = "not_activated", call.CorrelationID
			p.observe(request, outcome)
			WriteDomainReply(writer, request, reply)
			return
		}
		address, known := netip.Addr{}, false
		if p.options.ClientIP != nil {
			address, known = p.options.ClientIP(request)
		}
		if !known && p.options.RequireClientIP {
			p.refuse(writer, request, outcome, ReasonInvalidRequest)
			return
		}
		clientIP = address
	}

	caller := Caller{}
	if policy.Authentication != Anonymous {
		authenticated, refusal := p.authenticate(request)
		if refusal != nil {
			p.refuse(writer, request, outcome, *refusal)
			return
		}
		caller = *authenticated
	}

	// Each method states its own bound before any body byte is read.
	if request.ContentLength > int64(policy.MaxRequestBytes) {
		p.refuse(writer, request, outcome, ReasonRequestTooLarge)
		return
	}
	var owner *Owner
	var message []byte
	stated := ""
	if policy.ReadsRequestMeta() {
		body, ok := readBounded(request.Body, policy.MaxRequestBytes)
		if !ok {
			p.refuse(writer, request, outcome, ReasonRequestTooLarge)
			return
		}
		var refusal *Reason
		if owner, stated, refusal = authorizeOwner(policy, caller, body); refusal != nil {
			p.refuse(writer, request, outcome, *refusal)
			return
		}
		message, _ = ReadSingleMessage(body)
		request.Body = io.NopCloser(bytes.NewReader(body))
		request.ContentLength = int64(len(body))
	} else {
		request.Body = http.MaxBytesReader(writer, request.Body, int64(policy.MaxRequestBytes))
	}

	// One correlation identity per call: the client's validated value, else the Worker's traceparent trace id, else a new one.
	// It is bound after every admission decision above and read by none of them.
	call := &Call{
		Policy: policy, Caller: caller, Owner: owner,
		Correlation: correlation.ForRequest(request.Header.Values(TraceparentHeader), stated),
		ClientIP:    clientIP, Message: message,
	}
	outcome.Call = call
	p.observe(request, outcome)
	header := writer.Header()
	header.Set("Cache-Control", "no-store")
	header.Set("X-Content-Type-Options", "nosniff")
	p.next.ServeHTTP(writer, request.WithContext(context.WithValue(request.Context(), callKey{}, call)))
}

// authenticate checks a native bearer or an origin-bound browser cookie with exact Origin and CSRF. Every RPC is an unsafe
// request: the exact Origin first, then the session, then that session's CSRF token.
func (p *pipeline) authenticate(request *http.Request) (*Caller, *Reason) {
	header := request.Header
	cookie, hasCookie := SessionCookie(header)
	hasAuthorization := len(header.Values("Authorization")) > 0
	if hasAuthorization && hasCookie {
		return nil, &ReasonUnauthenticated
	}
	if hasAuthorization {
		token, ok := BearerToken(header)
		if !ok || p.options.Bearer == nil {
			return nil, &ReasonUnauthenticated
		}
		caller, err := p.options.Bearer.Verify(request.Context(), token)
		switch {
		case errors.Is(err, ErrTokenExpired):
			return nil, &ReasonTokenExpired
		case errors.Is(err, ErrCredentialRevoked):
			return nil, &ReasonCredentialRevoked
		case err != nil:
			return nil, &ReasonDependencyUnavailable
		}
		if caller == nil || caller.Credential != CredentialNativeBearer {
			return nil, &ReasonUnauthenticated
		}
		return caller, nil
	}
	if !hasCookie || p.options.Browser == nil {
		return nil, &ReasonUnauthenticated
	}
	origins := header.Values("Origin")
	if len(origins) != 1 || origins[0] != p.options.Browser.AllowedOrigin() {
		return nil, &ReasonPermissionDenied
	}
	credential, err := p.options.Browser.Resolve(request.Context(), cookie)
	if err != nil {
		return nil, &ReasonDependencyUnavailable
	}
	if credential == nil || credential.Caller.Credential != CredentialBrowserSession || credential.VerifyCSRF == nil {
		return nil, &ReasonUnauthenticated
	}
	tokens := header.Values(CSRFHeader)
	token := ""
	if len(tokens) == 1 {
		token = tokens[0]
	}
	if !credential.VerifyCSRF(token, len(tokens) == 1) {
		return nil, &ReasonPermissionDenied
	}
	return &credential.Caller, nil
}

// readBounded reads the whole body, or reports false when it exceeds the bound or cannot be read.
func readBounded(body io.Reader, limit int) ([]byte, bool) {
	data, err := io.ReadAll(io.LimitReader(body, int64(limit)+1))
	if err != nil || len(data) > limit {
		return nil, false
	}
	return data, true
}

// isAdmittedMedia admits binary gRPC-Web (what the Worker forwards, the only form the C# host admitted) and binary gRPC over
// HTTP/2 (direct clients of a self-hosted center and the gRPC listener), uncompressed. JSON and text codecs, the Connect
// protocol and any content or message encoding other than identity are refused.
func isAdmittedMedia(header http.Header) bool {
	switch mediaType(header) {
	case "application/grpc-web", "application/grpc-web+proto", "application/grpc", "application/grpc+proto":
	default:
		return false
	}
	if len(header.Values("Content-Encoding")) > 0 {
		return false
	}
	encodings := header.Values("Grpc-Encoding")
	return len(encodings) == 0 || len(encodings) == 1 && strings.EqualFold(encodings[0], "identity")
}

func isNativeGRPC(header http.Header) bool {
	media := mediaType(header)
	return media == "application/grpc" || media == "application/grpc+proto"
}

// mediaType is the lowercase type of the one Content-Type value without its parameters, as the C# host compares it; a missing
// or repeated Content-Type has none.
func mediaType(header http.Header) string {
	values := header.Values("Content-Type")
	if len(values) != 1 {
		return ""
	}
	media, _, _ := strings.Cut(values[0], ";")
	return strings.ToLower(strings.TrimSpace(media))
}

func plain(writer http.ResponseWriter, status int) {
	header := writer.Header()
	header.Set("Cache-Control", "no-store")
	header.Set("X-Content-Type-Options", "nosniff")
	header.Set("Content-Length", "0")
	writer.WriteHeader(status)
}

func (p *pipeline) refuse(writer http.ResponseWriter, request *http.Request, outcome Outcome, reason Reason) {
	outcome.Refusal = &reason
	p.observe(request, outcome)
	WriteRefusal(writer, request, reason)
}

// WriteDomainReply answers with a domain reply: gRPC OK and one reply message (an ArcError outcome). To a gRPC-Web (or
// unidentified) request it is one data frame and the status trailer frame in the body; to a native gRPC request it is the data
// frame and the status in HTTP/2 trailers.
func WriteDomainReply(writer http.ResponseWriter, request *http.Request, message []byte) {
	header := writer.Header()
	header.Set("Cache-Control", "no-store")
	header.Set("X-Content-Type-Options", "nosniff")
	frame := Frame(message)
	if isNativeGRPC(request.Header) {
		header.Set("Content-Type", "application/grpc")
		header.Set("Trailer", "Grpc-Status")
		writer.WriteHeader(http.StatusOK)
		_, _ = writer.Write(frame)
		header.Set("Grpc-Status", "0")
		return
	}
	body := append(frame, TrailerFrame(StatusOK, "", false)...)
	header.Set("Content-Type", "application/grpc-web+proto")
	header.Set("Content-Length", strconv.Itoa(len(body)))
	writer.WriteHeader(http.StatusOK)
	_, _ = writer.Write(body)
}

// WriteRefusal answers with a trailers-only refusal: HTTP 200 and the status. To a gRPC-Web (or unidentified) request it is one
// trailer frame in the body, byte-for-byte the C# host's refusal; to a native gRPC request it is the trailers-only HEADERS of
// gRPC over HTTP/2.
func WriteRefusal(writer http.ResponseWriter, request *http.Request, reason Reason) {
	header := writer.Header()
	header.Set("Cache-Control", "no-store")
	header.Set("X-Content-Type-Options", "nosniff")
	if isNativeGRPC(request.Header) {
		header.Set("Content-Type", "application/grpc")
		header.Set("Grpc-Status", strconv.Itoa(int(reason.Status)))
		header.Set("Grpc-Message", EscapeDataString(reason.Code))
		writer.WriteHeader(http.StatusOK)
		return
	}
	frame := TrailerFrame(reason.Status, reason.Code, true)
	header.Set("Content-Type", "application/grpc-web+proto")
	header.Set("Content-Length", strconv.Itoa(len(frame)))
	writer.WriteHeader(http.StatusOK)
	_, _ = writer.Write(frame)
}
