// SPDX-License-Identifier: AGPL-3.0-only

//go:build windows

package migrate

import (
	"crypto/sha256"
	"encoding/hex"
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"
)

// Windows denies write and delete sharing on the opened executable and delete
// sharing on every non-reparse ancestor until the child has stopped. Thus the
// pathname executed cannot be replaced or redirected after hashing. The
// manager's own OS account and administrators remain trusted.
type localBridgeExecutable struct {
	path       string
	digest     string
	extraFiles []*os.File
	file       *os.File
	dirs       []syscall.Handle
}

func openLocalBridge(source string) (*localBridgeExecutable, error) {
	expected, err := localArtifactDigest()
	if err != nil || !filepath.IsAbs(source) {
		return nil, ErrCTR06RetirementUnproven
	}
	path := filepath.Clean(source)
	volume := filepath.VolumeName(path)
	if len(volume) != 2 || volume[1] != ':' || strings.Contains(path[len(volume):], ":") {
		return nil, ErrCTR06RetirementUnproven
	}
	bridge := &localBridgeExecutable{}
	defer func() {
		if bridge.file == nil {
			bridge.close()
		}
	}()
	rest := strings.TrimPrefix(path[len(volume):], string(filepath.Separator))
	parts := strings.Split(rest, string(filepath.Separator))
	if len(parts) == 0 || parts[len(parts)-1] == "" {
		return nil, ErrCTR06RetirementUnproven
	}
	current := volume + string(filepath.Separator)
	for _, part := range append([]string{""}, parts[:len(parts)-1]...) {
		if part != "" {
			current = filepath.Join(current, part)
		}
		handle, err := openLocalHandle(current, true)
		if err != nil {
			return nil, ErrCTR06RetirementUnproven
		}
		bridge.dirs = append(bridge.dirs, handle)
	}
	handle, err := openLocalHandle(path, false)
	if err != nil {
		return nil, ErrCTR06RetirementUnproven
	}
	file := os.NewFile(uintptr(handle), path)
	hash := sha256.New()
	size, err := io.Copy(hash, io.LimitReader(file, 128*1024*1024+1))
	if err != nil || size < 1 || size > 128*1024*1024 || hex.EncodeToString(hash.Sum(nil)) != expected {
		_ = file.Close()
		return nil, ErrCTR06RetirementUnproven
	}
	bridge.path, bridge.digest, bridge.file = path, expected, file
	return bridge, nil
}

func openLocalHandle(path string, directory bool) (syscall.Handle, error) {
	name, err := syscall.UTF16PtrFromString(path)
	if err != nil {
		return syscall.InvalidHandle, err
	}
	access, sharing, flags := uint32(syscall.GENERIC_READ), uint32(syscall.FILE_SHARE_READ), uint32(syscall.FILE_FLAG_OPEN_REPARSE_POINT)
	if directory {
		access = 0x80 // FILE_READ_ATTRIBUTES
		sharing = syscall.FILE_SHARE_READ | syscall.FILE_SHARE_WRITE
		flags |= syscall.FILE_FLAG_BACKUP_SEMANTICS
	}
	handle, err := syscall.CreateFile(name, access, sharing, nil, syscall.OPEN_EXISTING, flags, 0)
	if err != nil {
		return syscall.InvalidHandle, err
	}
	var info syscall.ByHandleFileInformation
	if err := syscall.GetFileInformationByHandle(handle, &info); err != nil ||
		info.FileAttributes&syscall.FILE_ATTRIBUTE_REPARSE_POINT != 0 ||
		(info.FileAttributes&syscall.FILE_ATTRIBUTE_DIRECTORY != 0) != directory {
		_ = syscall.CloseHandle(handle)
		return syscall.InvalidHandle, ErrCTR06RetirementUnproven
	}
	return handle, nil
}

func (b *localBridgeExecutable) close() {
	if b.file != nil {
		_ = b.file.Close()
		b.file = nil
	}
	for i := len(b.dirs) - 1; i >= 0; i-- {
		_ = syscall.CloseHandle(b.dirs[i])
	}
	b.dirs = nil
}
