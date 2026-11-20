// SPDX-License-Identifier: AGPL-3.0-only

package server

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"mime"
	"net/http"
	"net/netip"
	"strconv"
	"strings"
	"time"

	"google.golang.org/protobuf/encoding/protojson"

	"github.com/ArcForges/Cloud/center/internal/access"
	"github.com/ArcForges/Cloud/center/internal/arc"
	"github.com/ArcForges/Cloud/center/internal/commerce"
	"github.com/ArcForges/Cloud/center/internal/correlation"
	"github.com/ArcForges/Cloud/center/internal/ingress"
	"github.com/ArcForges/Cloud/center/internal/platform"
	"github.com/ArcForges/Cloud/center/internal/routes"
)

func commercePortal(service *commerce.Service, authorizer *access.Authorizer, browser ingress.BrowserSessionVerifier,
	address func(*http.Request) (netip.Addr, bool)) http.Handler {
	return http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		callID := correlation.ForRequest(request.Header.Values(ingress.TraceparentHeader), "")
		ctx, cancel := context.WithTimeout(request.Context(), routes.PageDurationMilliseconds*time.Millisecond)
		defer cancel()
		status, result, refusal := createPortal(ctx, writer, request.WithContext(ctx), callID, service, authorizer, browser, address)
		for _, security := range routes.PageSecurityHeaders() {
			writer.Header().Set(security.Name, security.Value)
		}
		writer.Header().Set("Content-Type", routes.TypeJSON)
		if status == http.StatusMethodNotAllowed {
			writer.Header().Set("Allow", http.MethodPost)
		}
		if entry := recordFrom(request.Context()); entry != nil {
			entry.method, entry.code, entry.correlation = routes.CommercePortalPath, "http_"+strconv.Itoa(status), callID.CorrelationID
		}
		if refusal == nil {
			writer.WriteHeader(status)
			_ = json.NewEncoder(writer).Encode(struct {
				URL string `json:"url"`
			}{result})
			return
		}
		wire, err := protojson.Marshal(refusal.Dated(time.Now()).ArcError(callID))
		if err != nil {
			writer.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		writer.WriteHeader(status)
		_ = json.NewEncoder(writer).Encode(struct {
			Error json.RawMessage `json:"error"`
		}{wire})
	})
}

func createPortal(ctx context.Context, writer http.ResponseWriter, request *http.Request, callID correlation.Context,
	service *commerce.Service, authorizer *access.Authorizer, browser ingress.BrowserSessionVerifier,
	address func(*http.Request) (netip.Addr, bool)) (int, string, *arc.Refusal) {
	if !ingress.IsCanonical(request) || request.URL.Path != routes.CommercePortalPath {
		return http.StatusNotFound, "", arc.NotFound("portal", nil)
	}
	client, ok := address(request)
	if !ok {
		return http.StatusNotFound, "", arc.NotFound("portal", nil)
	}
	if request.Method != http.MethodPost {
		return http.StatusMethodNotAllowed, "", arc.InvalidArgument("method", "not_admitted")
	}
	if request.URL.RawQuery != "" || request.URL.ForceQuery {
		return http.StatusBadRequest, "", arc.InvalidArgument("query", "not_admitted")
	}
	types := request.Header.Values("Content-Type")
	if len(types) != 1 || len(request.Header.Values("Content-Encoding")) != 0 || len(request.Header.Values("Content-Range")) != 0 {
		return http.StatusUnsupportedMediaType, "", arc.InvalidArgument("content_type", "not_admitted")
	}
	mediaType, parameters, err := mime.ParseMediaType(types[0])
	if err != nil || mediaType != routes.TypeJSON || len(parameters) != 0 && (len(parameters) != 1 || !strings.EqualFold(parameters["charset"], "utf-8")) {
		return http.StatusUnsupportedMediaType, "", arc.InvalidArgument("content_type", "not_admitted")
	}
	if request.ContentLength > routes.CommercePortalMaxRequestBytes {
		return http.StatusRequestEntityTooLarge, "", arc.InvalidArgument("body", "max")
	}
	caller, reason := ingress.AuthenticateBrowser(request, browser)
	switch reason {
	case nil:
	case &ingress.ReasonDependencyUnavailable:
		return http.StatusServiceUnavailable, "", arc.Unavailable()
	case &ingress.ReasonPermissionDenied:
		return http.StatusForbidden, "", arc.PermissionDenied(routes.CommercePortalID)
	default:
		return http.StatusForbidden, "", arc.Unauthenticated()
	}
	call := &ingress.Call{Policy: ingress.Policy{FullName: routes.CommercePortalPath}, Caller: *caller, Correlation: callID, ClientIP: client}
	defer call.Finish()
	if _, err := authorizer.Authorize(ctx, call); err != nil {
		return portalFailure(err)
	}
	actor, err := commerceActor(call)
	if err != nil {
		return portalFailure(err)
	}
	deadline, _ := ctx.Deadline()
	controller := http.NewResponseController(writer)
	if controller.SetReadDeadline(deadline) == nil {
		defer func() { _ = controller.SetReadDeadline(time.Time{}) }()
	}
	raw, err := io.ReadAll(http.MaxBytesReader(writer, request.Body, routes.CommercePortalMaxRequestBytes))
	var tooLarge *http.MaxBytesError
	switch {
	case errors.As(err, &tooLarge):
		return http.StatusRequestEntityTooLarge, "", arc.InvalidArgument("body", "max")
	case ctx.Err() != nil:
		return http.StatusServiceUnavailable, "", arc.Unavailable()
	case err != nil:
		return http.StatusBadRequest, "", arc.InvalidArgument("body", "typed_message_invalid")
	}
	var input struct {
		SubscriptionID string `json:"subscription_id"`
	}
	if !commerceDocument(raw, &input, "subscription_id") {
		return http.StatusBadRequest, "", arc.InvalidArgument("body", "typed_message_invalid")
	}
	subscription := commerceTextID(input.SubscriptionID)
	if subscription == (platform.ID{}) {
		return http.StatusBadRequest, "", arc.InvalidArgument("subscription_id", "required")
	}
	location, err := service.CreatePortal(ctx, actor, subscription)
	if err != nil {
		return portalFailure(err)
	}
	return http.StatusOK, location, nil
}

func portalFailure(err error) (int, string, *arc.Refusal) {
	refusal := commerceRefusal(err)
	switch refusal.Code {
	case "invalid_argument":
		return http.StatusBadRequest, "", refusal
	case "not_found":
		return http.StatusNotFound, "", refusal
	case "unauthenticated", "permission_denied", "step_up_required", "credential_revoked":
		return http.StatusForbidden, "", refusal
	default:
		return http.StatusServiceUnavailable, "", refusal
	}
}
