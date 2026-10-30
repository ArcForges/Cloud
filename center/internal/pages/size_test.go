// SPDX-License-Identifier: AGPL-3.0-only

package pages

import (
	"strings"
	"testing"

	"github.com/ArcForges/Cloud/center/internal/platform"
	"github.com/ArcForges/Cloud/center/internal/routes"
)

// worstName is the longest name any account object can have (64 characters) made of the character that escapes to the most bytes
// in an HTML attribute (a quote becomes five bytes, &#34;), each of which a template writes several times a row.
var worstName = strings.Repeat(`"`, 64)

// TestAFullPageOfTheWorstCaseRowsFitsItsReplyBound (reviewer-4): the Worker answers 503 to a page reply above the route's registered
// bound, so a page that lists as many rows as it asks for (pageLimit) must fit the bound with the longest names in their most
// expensive escaped form, the most software a device can list, and every identifier at its full length.
func TestAFullPageOfTheWorstCaseRowsFitsItsReplyBound(t *testing.T) {
	views, err := loadViews("/api")
	if err != nil {
		t.Fatal(err)
	}
	bound := map[string]int{}
	for _, route := range routes.PageRoutes() {
		bound[route.Path] = route.MaxResponseBytes
	}
	id := func() string { return uuidText(platform.NewID()) }
	target := strings.Repeat("f", 64)
	csrf := strings.Repeat("A", 43)
	const instant = "2026-10-29T12:00:00.123456Z"
	const text = "2026-10-29 12:00 UTC"
	version := strings.Repeat("9", 128)

	data := pageData{Title: "Worst", Signed: true, CSRF: csrf, HasMore: true, RevokeAllTarget: target, RevokeAllCommand: id(), AddTarget: target, CanRemove: true,
		Profile: profileView{DisplayName: worstName, Locale: "en-US", Timezone: "America/Argentina/ComodRivadavia"}}
	for range pageLimit {
		data.Passkeys = append(data.Passkeys, passkeyRow{ID: id(), Name: worstName, CreatedAt: instant, CreatedText: text, LastUsedAt: instant, LastUsedText: text,
			RenameCommand: id(), RemoveCommand: id(), RemoveTarget: target})
		data.Sessions = append(data.Sessions, sessionRow{ID: id(), Where: worstName + " (Phone app)", IssuedAt: instant, IssuedText: text, LastUsedAt: instant,
			LastUsedText: text, ExpiresAt: instant, ExpiresText: text, RevokeCommand: id(), RevokeTarget: target})
		row := deviceRow{ID: id(), Name: worstName, Platform: strings.Repeat("w", 32), RenameCommand: id(), RevokeCommand: id(), RevokeTarget: target}
		// A device has at most one live installation of each of the five products (installation_device_product).
		for _, product := range []string{"arcscope", "companion", "arcforges-node", "arcforges-mobile", "arcforges-web"} {
			row.Installed = append(row.Installed, product+" "+version)
		}
		data.Devices = append(data.Devices, row)
	}
	for page, path := range map[string]string{"passkeys": "/account/passkeys", "sessions": "/account/sessions", "devices": "/account/devices"} {
		body, err := views.render(page, data)
		if err != nil {
			t.Fatal(err)
		}
		if limit := bound[path]; limit == 0 || len(body) > limit {
			t.Errorf("%s: a full page of %d worst-case rows is %d bytes, over the %d the route is bound to", page, pageLimit, len(body), limit)
		}
	}
}
