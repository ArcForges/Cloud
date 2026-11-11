// SPDX-License-Identifier: AGPL-3.0-only

//go:build !linux && !windows

package migrate

import "errors"

func restoreScratch() (string, func() error, error) {
	return "", nil, errors.New("logical restore is unavailable on this platform")
}
