// SPDX-License-Identifier: AGPL-3.0-only

package pages

import "github.com/ArcForges/Cloud/center/internal/access"

// PageLimit is the number of rows a page lists, for the tests of package pages_test.
const PageLimit = pageLimit

// RemoveMobileOperation makes the decision find no center-defined operation identity.authorizeMobile (the fail-closed test of package
// pages_test); the returned function restores it.
func RemoveMobileOperation() (restore func()) {
	saved := mobileOperation
	mobileOperation = func() (access.CenterOperation, bool) { return access.CenterOperation{}, false }
	return func() { mobileOperation = saved }
}
