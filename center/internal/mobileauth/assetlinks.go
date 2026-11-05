// SPDX-License-Identifier: AGPL-3.0-only

package mobileauth

import (
	"strings"

	"github.com/ArcForges/Cloud/center/internal/config"
)

// The Digital Asset Links relations every statement grants (MB-8, Q-2): App Links need handle_all_urls, and Android Credential
// Manager admits the app's own passkeys for the center's RP ID only with get_login_creds.
const (
	RelationHandleAllURLs = "delegate_permission/common.handle_all_urls"
	RelationGetLoginCreds = "delegate_permission/common.get_login_creds"
)

// AssetLinks is the exact body of /.well-known/assetlinks.json for an app identity: a JSON array with one statement per app, each
// granting both relations to the android_app target of its package and certificate fingerprints, in the configuration's order,
// without white space. No app (production) is the empty array []. The values are of closed grammars (config.ParseAndroidApps: an
// Android application ID and upper-case hexadecimal pairs), so they need no escaping; the body is built here, byte for byte, and a
// test pins its exact form.
func AssetLinks(apps []config.AndroidApp) []byte {
	var text strings.Builder
	text.WriteString("[")
	for index, app := range apps {
		if index > 0 {
			text.WriteString(",")
		}
		text.WriteString(`{"relation":["` + RelationHandleAllURLs + `","` + RelationGetLoginCreds + `"],"target":{"namespace":"android_app","package_name":"`)
		text.WriteString(app.PackageName)
		text.WriteString(`","sha256_cert_fingerprints":[`)
		for position, fingerprint := range app.Fingerprints {
			if position > 0 {
				text.WriteString(",")
			}
			text.WriteString(`"` + fingerprint + `"`)
		}
		text.WriteString("]}}")
	}
	text.WriteString("]")
	return []byte(text.String())
}
