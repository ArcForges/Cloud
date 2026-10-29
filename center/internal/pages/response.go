// SPDX-License-Identifier: AGPL-3.0-only

package pages

import (
	"bytes"
	"encoding/json"
	"net/http"
	"strconv"

	foundationv1 "github.com/ArcForges/Contracts/go/arcforges/foundation/v1"

	"github.com/ArcForges/Cloud/center/internal/arc"
	"github.com/ArcForges/Cloud/center/internal/routes"
	"github.com/ArcForges/Cloud/center/internal/session"
)

// setHeaders writes the headers every reply of the handler carries: the security set of routes.PageSecurityHeaders, whatever the
// status and the content (SEC-16). Every reply is written through write, so none lacks one.
func setHeaders(header http.Header) {
	for _, item := range routes.PageSecurityHeaders() {
		header.Set(item.Name, item.Value)
	}
}

// write sends a complete reply: the security headers, the media type and length of the body, the cookie the route may set, the
// location of a redirect and the body.
func (e *exchange) write(status int, mediaType string, body []byte, cookie, location string) {
	if e.written {
		return
	}
	e.written = true
	header := e.w.Header()
	setHeaders(header)
	if mediaType != "" {
		header.Set("Content-Type", mediaType)
	}
	header.Set("Content-Length", strconv.Itoa(len(body)))
	if cookie != "" {
		header.Add("Set-Cookie", cookie)
	}
	if location != "" {
		header.Set("Location", location)
	}
	e.w.WriteHeader(status)
	if e.r.Method != http.MethodHead {
		_, _ = e.w.Write(body)
	}
}

// status answers a bare status with the security headers and no body.
func (e *exchange) status(status int) { e.write(status, "", nil, "", "") }

// notFound answers 404 with no body: a disabled surface, a path the pages do not serve.
func (e *exchange) notFound() { e.status(http.StatusNotFound) }

// writeJSON answers 200 with a JSON body (and a cookie the route allows).
func (e *exchange) writeJSON(value any, cookie string) {
	var buffer bytes.Buffer
	encoder := json.NewEncoder(&buffer)
	encoder.SetEscapeHTML(false)
	if err := encoder.Encode(value); err != nil {
		e.refuseError(arc.Internal().Dated(e.h.options.Clock()).ArcError(e.correlation), 0)
		return
	}
	e.write(http.StatusOK, routes.TypeJSON, bytes.TrimRight(buffer.Bytes(), "\n"), cookie, "")
}

// redirect answers 303 to a location below the pages' prefix (the Worker admits no other), with the cookie the route allows.
func (e *exchange) redirect(location, cookie string) {
	e.write(http.StatusSeeOther, "", nil, cookie, location)
}

// refuse answers a refusal of the browser protocol.
func (e *exchange) refuse(f *refusalWithStatus) {
	e.refuseError(e.arcError(f.refusal), f.status)
}

// refuseError answers an ArcError as the route's kind answers it: the JSON body of the routes under /session/v1/web, an HTML page
// with the refusal's text on the account pages and the forms, a bare status for an asset. A status of 0 takes the refusal's own.
func (e *exchange) refuseError(value *foundationv1.ArcError, status int) {
	if status == 0 {
		status = statusOf(value)
	}
	switch e.route.Kind {
	case routes.PageJSONKind:
		var buffer bytes.Buffer
		encoder := json.NewEncoder(&buffer)
		encoder.SetEscapeHTML(false)
		if err := encoder.Encode(errorOf(value)); err != nil {
			e.status(http.StatusServiceUnavailable)
			return
		}
		e.write(status, routes.TypeJSON, bytes.TrimRight(buffer.Bytes(), "\n"), "", "")
	case routes.PageHTMLKind:
		e.writeErrorPage(status, value)
	default:
		e.status(status)
	}
}

// sessionCookie is the Set-Cookie value of a new browser session (SEC-03): the __Host- cookie of the handle, valid for the session's
// absolute lifetime, Secure, HttpOnly, SameSite=Strict, Path=/ and no Domain. It is written byte for byte, and the Worker's page
// handler checks exactly this form.
func sessionCookie(handle string, maxAgeSeconds int) string {
	return routes.PageCookieName + "=" + handle + "; Path=/; Max-Age=" + strconv.Itoa(maxAgeSeconds) + "; Secure; HttpOnly; SameSite=Strict"
}

// clearCookie is the Set-Cookie value that removes the session cookie.
func clearCookie() string {
	return routes.PageCookieName + "=; Path=/; Max-Age=0; Secure; HttpOnly; SameSite=Strict"
}

// cookieFor is the cookie of a freshly issued browser session; its lifetime is the session's, counted from now.
func (e *exchange) cookieFor(issued *session.Browser) string {
	seconds := int(issued.ExpiresAt.Sub(e.h.options.Clock()).Seconds())
	if seconds < 1 {
		seconds = 1
	}
	return sessionCookie(issued.Handle, seconds)
}
