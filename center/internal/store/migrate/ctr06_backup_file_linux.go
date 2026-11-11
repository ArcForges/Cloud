// SPDX-License-Identifier: AGPL-3.0-only

//go:build linux

package migrate

import (
	"errors"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/sys/unix"
)

// Hold the exact non-symlink ancestors and create relative to the checked
// parent. Only root and this OS account are trusted. A shared writable parent
// must be sticky, so another account cannot replace a trusted-owned component.
func openCaptureFile(path string) (*os.File, func() error, func(), error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return nil, nil, nil, errors.New("backup output path must be absolute and canonical")
	}
	root, err := unix.Open("/", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return nil, nil, nil, err
	}
	parents := []int{root}
	release := func() {
		for i := len(parents) - 1; i >= 0; i-- {
			_ = unix.Close(parents[i])
		}
	}
	check := func(fd int) error {
		var st unix.Stat_t
		if err := unix.Fstat(fd, &st); err != nil {
			return err
		}
		if st.Mode&unix.S_IFMT != unix.S_IFDIR || st.Uid != 0 && st.Uid != uint32(os.Geteuid()) ||
			st.Mode&0o022 != 0 && st.Mode&unix.S_ISVTX == 0 {
			return errors.New("backup output ancestor is not protected")
		}
		return nil
	}
	if err := check(root); err != nil {
		release()
		return nil, nil, nil, err
	}
	parent := filepath.Dir(path)
	for _, part := range strings.Split(strings.TrimPrefix(parent, "/"), "/") {
		if part == "" {
			continue
		}
		fd, err := unix.Openat(parents[len(parents)-1], part, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
		if err != nil {
			release()
			return nil, nil, nil, err
		}
		parents = append(parents, fd)
		if err := check(fd); err != nil {
			release()
			return nil, nil, nil, err
		}
	}
	fd, err := unix.Openat(parents[len(parents)-1], filepath.Base(path), unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0o600)
	if err != nil {
		release()
		return nil, nil, nil, err
	}
	file := os.NewFile(uintptr(fd), path)
	if file == nil {
		_ = unix.Close(fd)
		release()
		return nil, nil, nil, errors.New("backup output handle could not be opened")
	}
	return file, func() error { return unix.Fsync(parents[len(parents)-1]) }, release, nil
}
