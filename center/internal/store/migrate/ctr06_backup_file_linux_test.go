// SPDX-License-Identifier: AGPL-3.0-only

//go:build linux

package migrate

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestCTR06LinuxCaptureUsesProtectedParentAndSyncsDirectory(t *testing.T) {
	base := t.TempDir()
	protected := filepath.Join(base, "protected")
	if err := os.Mkdir(protected, 0o700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(protected, "backup")
	if err := captureFile(path, strings.NewReader("synthetic archive")); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("backup permissions: %v %v", info, err)
	}
	if err := captureFile(path, strings.NewReader("replacement")); err == nil {
		t.Fatal("existing backup was overwritten")
	}
	if content, err := os.ReadFile(path); err != nil || string(content) != "synthetic archive" {
		t.Fatal("existing backup was changed")
	}
	file, syncParent, release, err := openCaptureFile(filepath.Join(protected, "sync"))
	if err != nil {
		t.Fatal(err)
	}
	if syncParent == nil || syncParent() != nil {
		t.Fatal("the actual held parent directory could not be synchronized")
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	release()
}

func TestCTR06LinuxCaptureRejectsSharedWritableAndSymlinkAncestors(t *testing.T) {
	base := t.TempDir()
	shared := filepath.Join(base, "shared")
	if err := os.Mkdir(shared, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(shared, 0o777); err != nil {
		t.Fatal(err)
	}
	output := filepath.Join(shared, "backup")
	if err := captureFile(output, strings.NewReader("synthetic")); err == nil {
		t.Fatal("non-sticky shared writable parent was accepted")
	}
	if _, err := os.Lstat(output); !os.IsNotExist(err) {
		t.Fatal("refusal created an output")
	}
	if err := os.Chmod(shared, os.ModeSticky|0o777); err != nil {
		t.Fatal(err)
	}
	if err := captureFile(output, strings.NewReader("synthetic")); err != nil {
		t.Fatalf("trusted-owned sticky parent was refused: %v", err)
	}
	link := filepath.Join(base, "link")
	if err := os.Symlink(shared, link); err != nil {
		t.Fatal(err)
	}
	if err := captureFile(filepath.Join(link, "other"), strings.NewReader("synthetic")); err == nil {
		t.Fatal("symlink ancestor was accepted")
	}
	if _, err := os.Lstat(filepath.Join(shared, "other")); !os.IsNotExist(err) {
		t.Fatal("symlink refusal created an output")
	}
}
