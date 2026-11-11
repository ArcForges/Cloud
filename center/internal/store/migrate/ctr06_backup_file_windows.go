// SPDX-License-Identifier: AGPL-3.0-only

//go:build windows

package migrate

import (
	"errors"
	"os"
	"path/filepath"
	"unsafe"

	"golang.org/x/sys/windows"
)

// An inherited Windows parent DACL can be public even when Go receives 0600.
// Create the output relative to a held, non-reparse parent with a protected
// account/SYSTEM/administrators DACL and deny deletion while it is written.
// Afterward, the administrator remains responsible for the chosen directory.
func openCaptureFile(path string) (*os.File, func() error, func(), error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return nil, nil, nil, errors.New("backup output path must be absolute and canonical")
	}
	ancestors, closeAncestors, err := ctr06HoldWindowsAncestors(filepath.Dir(path))
	if err != nil {
		return nil, nil, nil, err
	}
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil || user.User.Sid == nil || user.User.Sid.String() == "" {
		closeAncestors()
		return nil, nil, nil, errors.New("the backup account identity is unavailable")
	}
	descriptor, err := windows.SecurityDescriptorFromString("D:P(A;;FA;;;" + user.User.Sid.String() + ")(A;;FA;;;SY)(A;;FA;;;BA)")
	if err != nil {
		closeAncestors()
		return nil, nil, nil, err
	}
	name, err := windows.NewNTUnicodeString(filepath.Base(path))
	if err != nil {
		closeAncestors()
		return nil, nil, nil, err
	}
	attributes := windows.OBJECT_ATTRIBUTES{RootDirectory: ancestors[len(ancestors)-1], ObjectName: name,
		Attributes: windows.OBJ_CASE_INSENSITIVE, SecurityDescriptor: descriptor}
	attributes.Length = uint32(unsafe.Sizeof(attributes))
	var iosb windows.IO_STATUS_BLOCK
	var handle windows.Handle
	err = windows.NtCreateFile(&handle, windows.FILE_GENERIC_WRITE|windows.FILE_READ_ATTRIBUTES|windows.SYNCHRONIZE,
		&attributes, &iosb, nil, 0, windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE, windows.FILE_CREATE,
		windows.FILE_NON_DIRECTORY_FILE|windows.FILE_OPEN_REPARSE_POINT|windows.FILE_SYNCHRONOUS_IO_NONALERT, 0, 0)
	if err != nil {
		closeAncestors()
		return nil, nil, nil, err
	}
	file := os.NewFile(uintptr(handle), path)
	if file == nil {
		_ = windows.CloseHandle(handle)
		closeAncestors()
		return nil, nil, nil, errors.New("backup output handle could not be opened")
	}
	// File.Sync flushes the file; a Windows directory-entry crash-durability
	// guarantee is not inferred from this handle or from the Linux fsync path.
	return file, nil, closeAncestors, nil
}
