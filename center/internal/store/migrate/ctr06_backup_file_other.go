// SPDX-License-Identifier: AGPL-3.0-only

//go:build !windows && !linux

package migrate

import "os"

func openCaptureFile(path string) (*os.File, func() error, func(), error) {
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	return file, nil, func() {}, err
}
