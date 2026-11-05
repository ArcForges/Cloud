// SPDX-License-Identifier: AGPL-3.0-only

package routes

import "slices"

// SurfaceMobile is the mobile surface: the mobile app's native authorization (AF-CTR-04 part M; Contracts
// public/http/v1/mobile-native.schema.json, MobileNativeAuth v1). Its routes are served only where the surface is enabled; elsewhere
// the Worker and the center answer 404 for every one of them (pages, native JSON and apex rows alike).
const SurfaceMobile = "mobile"

// The paths of the mobile surface, relative to the public base URL, except the two apex paths, which are relative to the origin of
// the public base URL (the hosted Worker maps the apex paths of its host to the same center paths; a self-hosted center at the root of
// its host serves them where they are).
const (
	// PageMobilePrefix is the authorization page the app opens in a Custom Tab (<base>/mobile/authorize#flow=<flow ID>) and the prefix
	// of its two forms.
	PageMobilePrefix = "/mobile/authorize"
	// NativeMobileBegin and NativeMobileToken are the contract's two native JSON routes (MobileNativeAuth x-arcforges-routes
	// mobile.begin and mobile.token).
	NativeMobileBegin = "/session/v1/mobile/begin"
	NativeMobileToken = "/session/v1/mobile/token"
	// ApexAssetLinks is the Digital Asset Links statement list Android's App Link verifier and Credential Manager read; ApexAppCallback
	// is the release app's verified App Link, whose page a browser shows only when the link did not open the app.
	ApexAssetLinks  = "/.well-known/assetlinks.json"
	ApexAppCallback = "/app/callback"
)

// The two further kinds of a page route the mobile surface declares (MB-3): a native JSON route of the app (POST, exactly
// application/json, no cookie in or out, no Origin or CSRF requirement, no redirect) and an apex route (GET, no cookie, no redirect,
// at the origin of the public base URL rather than below it).
const (
	PageNativeKind PageKind = "native"
	PageApexKind   PageKind = "apex"
)

// The bounds of the mobile routes: the contract's x-arcforges-max-bytes of the native requests and replies (begin 4096 in and out,
// token 4096 in and 65536 out), and the asset links statement (at most 4 apps of 4 fingerprints, a few kilobytes).
const (
	mobileNativeRequestBytes = 4096
	mobileBeginReplyBytes    = 4096
	mobileTokenReplyBytes    = 65_536
	mobileAssetLinksBytes    = 8192
)

// MobilePageRoutes are the routes of the mobile surface, in registration order: the authorization page (static: its script reads the
// flow ID from the fragment), its review and its decision (form POSTs with the exact Origin, the CSRF token and the cookie session, as
// the fleet pages), the two native JSON routes, and the two apex routes. The pages' script and style sheet are the pages surface's
// assets, which this surface needs enabled.
func MobilePageRoutes() []PageRoute {
	html := []string{TypeHTML}
	jsonReply := []string{TypeJSON}
	form := func(path, id string) PageRoute {
		return PageRoute{Method: "POST", Path: path, ID: id, Surface: SurfaceMobile, Kind: PageHTMLKind, RequestType: TypeForm, ResponseTypes: html,
			MaxRequestBytes: pageBytesForm, MaxResponseBytes: pageBytesPageReply, Cookie: true, SetCookie: SetCookieNone}
	}
	native := func(path, id string, replyBytes int) PageRoute {
		return PageRoute{Method: "POST", Path: path, ID: id, Surface: SurfaceMobile, Kind: PageNativeKind, RequestType: TypeJSON, ResponseTypes: jsonReply,
			MaxRequestBytes: mobileNativeRequestBytes, MaxResponseBytes: replyBytes, SetCookie: SetCookieNone}
	}
	apex := func(path, id string, responseTypes []string, replyBytes int) PageRoute {
		return PageRoute{Method: "GET", Path: path, ID: id, Surface: SurfaceMobile, Kind: PageApexKind, ResponseTypes: responseTypes, MaxResponseBytes: replyBytes,
			SetCookie: SetCookieNone}
	}
	return []PageRoute{
		{Method: "GET", Path: PageMobilePrefix, ID: "mobile.page", Surface: SurfaceMobile, Kind: PageHTMLKind, ResponseTypes: html,
			MaxResponseBytes: pageBytesPageReply, SetCookie: SetCookieNone},
		form(PageMobilePrefix+"/review", "mobile.review"),
		form(PageMobilePrefix+"/decision", "mobile.decision"),
		native(NativeMobileBegin, "mobile.begin", mobileBeginReplyBytes),
		native(NativeMobileToken, "mobile.token", mobileTokenReplyBytes),
		apex(ApexAssetLinks, "apex.assetLinks", jsonReply, mobileAssetLinksBytes),
		apex(ApexAppCallback, "apex.appCallback", html, pageBytesPageReply),
	}
}

// mobileRowAdmitted reports a mobile route of an admitted shape (cloud-13 for the mobile surface): an HTML page or form below
// /mobile/authorize; a native JSON route at exactly one of the two contract paths, POST, exactly application/json in and out, no
// cookie and no redirect; an apex route at exactly one of the two apex paths, GET, no cookie and no redirect, the asset links statement
// JSON and the callback page HTML. Every other surface declares neither a native nor an apex route.
func mobileRowAdmitted(row PageRoute) bool {
	plain := !row.Cookie && row.SetCookie == SetCookieNone && !row.Redirects
	switch row.Kind {
	case PageHTMLKind:
		return underPrefix(row.Path, PageMobilePrefix)
	case PageNativeKind:
		return (row.Path == NativeMobileBegin || row.Path == NativeMobileToken) && row.Method == "POST" && row.RequestType == TypeJSON && plain &&
			slices.Equal(row.ResponseTypes, []string{TypeJSON})
	case PageApexKind:
		return row.Method == "GET" && plain && (row.Path == ApexAssetLinks && slices.Equal(row.ResponseTypes, []string{TypeJSON}) ||
			row.Path == ApexAppCallback && slices.Equal(row.ResponseTypes, []string{TypeHTML}))
	}
	return false
}

// Mobile is the mobile surface's module: its pages, native JSON routes and apex routes (no Connect method).
func Mobile() (Module, error) {
	rows := MobilePageRoutes()
	if err := CheckPages(rows); err != nil {
		return Module{}, err
	}
	return Module{Name: "mobile", Surface: SurfaceMobile, Pages: rows, Budgets: map[string]Budget{}}, nil
}
