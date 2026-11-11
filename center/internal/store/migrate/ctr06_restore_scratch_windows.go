// SPDX-License-Identifier: AGPL-3.0-only

//go:build windows

package migrate

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"unsafe"

	"golang.org/x/sys/windows"
)

// Hold each non-reparse directory open without delete sharing until the caller
// has finished operating on the exact object under the final parent.
func ctr06HoldWindowsAncestors(base string) ([]windows.Handle, func(), error) {
	volume := filepath.VolumeName(base)
	if len(volume) != 2 || volume[1] != ':' || strings.Contains(base[len(volume):], ":") {
		return nil, nil, errors.New("directory must be on a local volume")
	}
	var ancestors []windows.Handle
	closeAncestors := func() {
		for i := len(ancestors) - 1; i >= 0; i-- {
			_ = windows.CloseHandle(ancestors[i])
		}
	}
	current := volume + string(filepath.Separator)
	parts := strings.Split(strings.TrimPrefix(base[len(volume):], string(filepath.Separator)), string(filepath.Separator))
	for _, part := range append([]string{""}, parts...) {
		if part != "" {
			current = filepath.Join(current, part)
		}
		name, err := windows.UTF16PtrFromString(current)
		if err != nil {
			closeAncestors()
			return nil, nil, err
		}
		h, err := windows.CreateFile(name, windows.FILE_READ_ATTRIBUTES, windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE,
			nil, windows.OPEN_EXISTING, windows.FILE_FLAG_BACKUP_SEMANTICS|windows.FILE_FLAG_OPEN_REPARSE_POINT, 0)
		if err != nil {
			closeAncestors()
			return nil, nil, err
		}
		var info windows.ByHandleFileInformation
		if err = windows.GetFileInformationByHandle(h, &info); err != nil || info.FileAttributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 || info.FileAttributes&windows.FILE_ATTRIBUTE_DIRECTORY == 0 {
			_ = windows.CloseHandle(h)
			closeAncestors()
			return nil, nil, errors.New("temporary directory ancestor is not a real directory")
		}
		ancestors = append(ancestors, h)
	}
	return ancestors, closeAncestors, nil
}

// The temporary directory is atomically created with an explicit protected
// DACL for this account, SYSTEM and administrators. Open non-reparse ancestor
// handles and the directory handle deny delete sharing until cleanup; another
// OS principal cannot replace the archive or the table-of-contents list.
func restoreScratch() (string, func() error, error) {
	base, err := filepath.Abs(os.TempDir())
	if err != nil {
		return "", nil, err
	}
	ancestors, closeAncestors, err := ctr06HoldWindowsAncestors(base)
	if err != nil {
		return "", nil, err
	}
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil || user.User.Sid == nil || user.User.Sid.String() == "" {
		closeAncestors()
		return "", nil, errors.New("the restore account identity is unavailable")
	}
	sid := user.User.Sid.String()
	descriptor, err := windows.SecurityDescriptorFromString("D:P(A;OICI;FA;;;" + sid + ")(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)")
	if err != nil {
		closeAncestors()
		return "", nil, err
	}
	var random [16]byte
	if _, err := rand.Read(random[:]); err != nil {
		closeAncestors()
		return "", nil, err
	}
	name := "arcforges-ctr06-restore-" + hex.EncodeToString(random[:])
	objectName, err := windows.NewNTUnicodeString(name)
	if err != nil {
		closeAncestors()
		return "", nil, err
	}
	attributes := windows.OBJECT_ATTRIBUTES{RootDirectory: ancestors[len(ancestors)-1], ObjectName: objectName,
		Attributes: windows.OBJ_CASE_INSENSITIVE, SecurityDescriptor: descriptor}
	attributes.Length = uint32(unsafe.Sizeof(attributes))
	var iosb windows.IO_STATUS_BLOCK
	var directory windows.Handle
	err = windows.NtCreateFile(&directory, windows.FILE_GENERIC_READ|windows.FILE_GENERIC_WRITE|windows.DELETE|windows.SYNCHRONIZE,
		&attributes, &iosb, nil, 0, windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE, windows.FILE_CREATE,
		windows.FILE_DIRECTORY_FILE|windows.FILE_OPEN_REPARSE_POINT|windows.FILE_SYNCHRONOUS_IO_NONALERT, 0, 0)
	if err != nil {
		closeAncestors()
		return "", nil, err
	}
	dir := filepath.Join(base, name)
	cleanup := func() error {
		var result error
		for _, file := range []string{"archive", "restore-list"} {
			if err := os.Remove(filepath.Join(dir, file)); err != nil && !os.IsNotExist(err) {
				result = errors.Join(result, err)
			}
		}
		disposition := byte(1)
		if err := windows.SetFileInformationByHandle(directory, windows.FileDispositionInfo, &disposition, 1); err != nil {
			result = errors.Join(result, err)
		}
		if err := windows.CloseHandle(directory); err != nil {
			result = errors.Join(result, err)
		}
		closeAncestors()
		return result
	}
	return dir, cleanup, nil
}
