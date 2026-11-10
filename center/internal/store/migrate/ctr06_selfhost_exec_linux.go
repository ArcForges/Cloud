// SPDX-License-Identifier: AGPL-3.0-only

//go:build linux

package migrate

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"path/filepath"
)

// The bridge is copied into an owner-only directory and hashed there. The
// executable passed to exec is the held file descriptor, not a path that can
// be replaced after the hash check. The local account running the manager is
// part of the trusted computing boundary.
type localBridgeExecutable struct {
	path       string
	digest     string
	extraFiles []*os.File
	file       *os.File
	dir        string
}

func openLocalBridge(source string) (*localBridgeExecutable, error) {
	expected, err := localArtifactDigest()
	if err != nil || !filepath.IsAbs(source) {
		return nil, ErrCTR06RetirementUnproven
	}
	input, err := os.Open(source)
	if err != nil {
		return nil, ErrCTR06RetirementUnproven
	}
	defer input.Close()
	info, err := input.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Size() < 1 || info.Size() > 128*1024*1024 {
		return nil, ErrCTR06RetirementUnproven
	}
	dir, err := os.MkdirTemp("", "arcforges-ctr06-bridge-")
	if err != nil {
		return nil, ErrCTR06RetirementUnproven
	}
	bridge := &localBridgeExecutable{dir: dir}
	defer func() {
		if bridge.file == nil {
			bridge.close()
		}
	}()
	path := filepath.Join(dir, "bridge")
	target, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o500)
	if err != nil {
		return nil, ErrCTR06RetirementUnproven
	}
	_, copyErr := io.Copy(target, io.LimitReader(input, 128*1024*1024+1))
	closeErr := target.Close()
	if copyErr != nil || closeErr != nil {
		return nil, ErrCTR06RetirementUnproven
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, ErrCTR06RetirementUnproven
	}
	hash := sha256.New()
	size, err := io.Copy(hash, file)
	if err != nil || size != info.Size() || hex.EncodeToString(hash.Sum(nil)) != expected {
		_ = file.Close()
		return nil, ErrCTR06RetirementUnproven
	}
	if _, err = file.Seek(0, io.SeekStart); err != nil {
		_ = file.Close()
		return nil, ErrCTR06RetirementUnproven
	}
	if _, err = os.Stat("/proc/self/fd"); err != nil {
		_ = file.Close()
		return nil, errors.New("the verified bridge file descriptor cannot be executed on this host")
	}
	bridge.file, bridge.path, bridge.digest = file, "/proc/self/fd/3", expected
	bridge.extraFiles = []*os.File{file}
	return bridge, nil
}

func (b *localBridgeExecutable) close() {
	if b.file != nil {
		_ = b.file.Close()
		b.file = nil
	}
	if b.dir != "" {
		_ = os.Remove(filepath.Join(b.dir, "bridge"))
		_ = os.Remove(b.dir)
		b.dir = ""
	}
}
