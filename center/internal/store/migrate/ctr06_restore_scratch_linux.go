// SPDX-License-Identifier: AGPL-3.0-only

//go:build linux

package migrate

import (
	"errors"
	"os"
	"path/filepath"
	"syscall"
)

// A private scratch directory must not sit below an untrusted rename/delete
// parent. Root and the current account are the explicit OS trust boundary;
// shared writable parents must additionally have the sticky bit.
func restoreScratch() (string, func() error, error) {
	base, err := filepath.EvalSymlinks(os.TempDir())
	if err != nil || !filepath.IsAbs(base) {
		return "", nil, errors.New("invalid temporary directory")
	}
	for current := base; ; current = filepath.Dir(current) {
		info, err := os.Stat(current)
		if err != nil || !info.IsDir() {
			return "", nil, errors.New("invalid temporary directory ancestor")
		}
		stat, ok := info.Sys().(*syscall.Stat_t)
		if !ok || stat.Uid != 0 && stat.Uid != uint32(os.Geteuid()) ||
			info.Mode().Perm()&0o022 != 0 && info.Mode()&os.ModeSticky == 0 {
			return "", nil, errors.New("temporary directory ancestor is not protected")
		}
		if current == filepath.Dir(current) {
			break
		}
	}
	dir, err := os.MkdirTemp(base, "arcforges-ctr06-restore-")
	if err != nil {
		return "", nil, err
	}
	return dir, func() error { return os.RemoveAll(dir) }, nil
}
