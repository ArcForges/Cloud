// SPDX-License-Identifier: AGPL-3.0-only

package routes

import (
	"net/http"

	"github.com/ArcForges/Contracts/go/arcforges/publicapi/v1/publicapiv1connect"

	"github.com/ArcForges/Cloud/center/internal/ingress"
)

const (
	SurfaceCommerce                      = "commerce"
	CommercePortalPath                   = "/account/billing/v1/portal"
	CommercePortalID                     = "commerce.portal"
	CommercePortalMaxRequestBytes        = 512
	CommercePortalMaxResponseBytes       = 4096
	PaddleWebhookPath                    = "/commerce/v1/paddle/webhook"
	PaddleWebhookSignatureHeader         = "Paddle-Signature"
	PaddleWebhookMaxRequestBytes         = 256 * 1024
	PaddleWebhookMaxSignatureBytes       = 512
	PaddleWebhookMaxDurationMilliseconds = 5_000
)

func commercePortalRoute() PageRoute {
	return PageRoute{Method: http.MethodPost, Path: CommercePortalPath, ID: CommercePortalID, Surface: SurfaceCommerce,
		Kind: PageJSONKind, RequestType: TypeJSON, ResponseTypes: []string{TypeJSON}, MaxRequestBytes: CommercePortalMaxRequestBytes,
		MaxResponseBytes: CommercePortalMaxResponseBytes, Cookie: true, SetCookie: SetCookieNone}
}

func isCommercePortal(row PageRoute) bool {
	return row.Method == http.MethodPost && row.Path == CommercePortalPath && row.ID == CommercePortalID && row.Surface == SurfaceCommerce &&
		row.Kind == PageJSONKind && row.RequestType == TypeJSON && len(row.ResponseTypes) == 1 && row.ResponseTypes[0] == TypeJSON &&
		row.MaxRequestBytes == CommercePortalMaxRequestBytes && row.MaxResponseBytes == CommercePortalMaxResponseBytes &&
		row.Cookie && row.SetCookie == SetCookieNone && !row.Redirects
}

// WebhookRoute declares the dedicated provider ingress for the Worker and Center.
type WebhookRoute struct {
	Path                    string
	Method                  string
	Surface                 string
	ContentType             string
	SignatureHeader         string
	MaxSignatureBytes       int
	MaxRequestBytes         int
	MaxDurationMilliseconds int
	Instance                string
}

func paddleWebhookRoute() WebhookRoute {
	return WebhookRoute{
		Path: PaddleWebhookPath, Method: http.MethodPost, Surface: SurfaceCommerce,
		ContentType: "application/json", SignatureHeader: PaddleWebhookSignatureHeader,
		MaxSignatureBytes: PaddleWebhookMaxSignatureBytes, MaxRequestBytes: PaddleWebhookMaxRequestBytes,
		MaxDurationMilliseconds: PaddleWebhookMaxDurationMilliseconds, Instance: HealthInstance,
	}
}

// CommerceMethods are the published methods supported by subscription commerce.
func CommerceMethods() []string {
	return []string{
		publicapiv1connect.CommerceServiceGetCatalogueProcedure,
		publicapiv1connect.CommerceServiceCreatePurchaseIntentProcedure,
		publicapiv1connect.CommerceServiceCreateCheckoutAttemptProcedure,
		publicapiv1connect.CommerceServiceGetPurchaseStateProcedure,
		publicapiv1connect.CommerceServiceGetSubscriptionProcedure,
		publicapiv1connect.CommerceServiceCancelSubscriptionProcedure,
		publicapiv1connect.CommerceServiceReactivateSubscriptionProcedure,
		publicapiv1connect.CommerceServiceListBillingHistoryProcedure,
	}
}

func Commerce() (Module, error) {
	callback := paddleWebhookRoute()
	module := Module{Name: "commerce", Surface: SurfaceCommerce, Budgets: map[string]Budget{}, PaddleWebhook: &callback,
		Pages: []PageRoute{commercePortalRoute()}}
	for _, method := range CommerceMethods() {
		policy, err := ingress.NewUnary(method, ingress.Session, ingress.NoScope, identityRequestBytes, true)
		if err != nil {
			return Module{}, err
		}
		module.Policies = append(module.Policies, policy.InSurface(SurfaceCommerce))
		module.Budgets[method] = identityBudget
	}
	return module, nil
}
