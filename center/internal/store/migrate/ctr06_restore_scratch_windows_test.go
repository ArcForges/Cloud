// SPDX-License-Identifier: AGPL-3.0-only

//go:build windows

package migrate

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

func TestCTR06WindowsRestoreScratchDACLAndAncestorHandles(t *testing.T) {
	base := t.TempDir()
	t.Setenv("TMP", base)
	t.Setenv("TEMP", base)
	dir, cleanup, err := restoreScratch()
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := cleanup(); err != nil {
			t.Error(err)
		}
	}()
	archive := filepath.Join(dir, "archive")
	if err := os.WriteFile(archive, []byte("synthetic"), 0o600); err != nil {
		t.Fatal(err)
	}
	sd, err := windows.GetNamedSecurityInfo(dir, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION|windows.GROUP_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION)
	if err != nil || sd == nil {
		t.Fatalf("scratch descriptor unavailable: %v", err)
	}
	control, _, err := sd.Control()
	if err != nil || control&windows.SE_DACL_PROTECTED == 0 {
		t.Fatalf("scratch DACL is not protected: %v", err)
	}
	acl, _, err := sd.DACL()
	if err != nil || acl == nil || acl.AceCount != 3 {
		t.Fatalf("scratch DACL has an unexpected ACE count: %v", err)
	}
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		t.Fatal(err)
	}
	expected := map[string]bool{user.User.Sid.String(): false, "S-1-5-18": false, "S-1-5-32-544": false}
	if len(expected) != 3 {
		t.Fatal("test account is a system or administrators SID")
	}
	for i := uint32(0); i < uint32(acl.AceCount); i++ {
		var ace *windows.ACCESS_ALLOWED_ACE
		if err := windows.GetAce(acl, i, &ace); err != nil || ace == nil || ace.Header.AceType != windows.ACCESS_ALLOWED_ACE_TYPE ||
			ace.Header.AceFlags&(windows.OBJECT_INHERIT_ACE|windows.CONTAINER_INHERIT_ACE) != windows.OBJECT_INHERIT_ACE|windows.CONTAINER_INHERIT_ACE || uint32(ace.Mask) != 0x001f01ff {
			t.Fatalf("scratch ACE is not the expected inherited full access: %v", err)
		}
		sid := (*windows.SID)(unsafe.Pointer(&ace.SidStart)).String()
		if _, ok := expected[sid]; !ok || expected[sid] {
			t.Fatal("scratch DACL grants an unexpected or duplicate principal")
		}
		expected[sid] = true
	}
	for _, present := range expected {
		if !present {
			t.Fatal("scratch DACL is missing an expected trusted principal")
		}
	}
	if err := windowsRestrictedScratchAccess(sd, archive); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(dir, dir+"-moved"); err == nil {
		_ = os.Rename(dir+"-moved", dir)
		t.Fatal("the held scratch directory could be renamed")
	}
	if err := os.Rename(base, base+"-moved"); err == nil {
		_ = os.Rename(base+"-moved", base)
		t.Fatal("the held scratch ancestor could be renamed")
	}
}

type ctr06GenericMapping struct{ read, write, execute, all uint32 }

// Check the actual descriptor with Windows AccessCheck using both the current
// token and a token restricted to Everyone, then attempt a real restricted
// CreateFile. The nontrusted token is an OS object, not a mocked ACL decision.
func windowsRestrictedScratchAccess(sd *windows.SECURITY_DESCRIPTOR, path string) error {
	var process windows.Token
	if err := windows.OpenProcessToken(windows.CurrentProcess(), windows.TOKEN_QUERY|windows.TOKEN_DUPLICATE, &process); err != nil {
		return err
	}
	defer process.Close()
	world, err := windows.CreateWellKnownSid(windows.WinWorldSid)
	if err != nil {
		return err
	}
	restriction := windows.SIDAndAttributes{Sid: world}
	var restricted windows.Token
	create := windows.NewLazySystemDLL("advapi32.dll").NewProc("CreateRestrictedToken")
	ok, _, callErr := create.Call(uintptr(process), 1, 0, 0, 0, 0, 1, uintptr(unsafe.Pointer(&restriction)), uintptr(unsafe.Pointer(&restricted)))
	if ok == 0 {
		return fmt.Errorf("create restricted token: %w", callErr)
	}
	defer restricted.Close()
	impersonation := func(token windows.Token) (windows.Token, error) {
		var result windows.Token
		err := windows.DuplicateTokenEx(token, windows.TOKEN_QUERY|windows.TOKEN_IMPERSONATE, nil, windows.SecurityImpersonation, windows.TokenImpersonation, &result)
		return result, err
	}
	full, err := impersonation(process)
	if err != nil {
		return err
	}
	defer full.Close()
	limited, err := impersonation(restricted)
	if err != nil {
		return err
	}
	defer limited.Close()
	access := windows.NewLazySystemDLL("advapi32.dll").NewProc("AccessCheck")
	check := func(descriptor *windows.SECURITY_DESCRIPTOR, token windows.Token) (bool, error) {
		mapping := ctr06GenericMapping{windows.FILE_GENERIC_READ, windows.FILE_GENERIC_WRITE, windows.FILE_GENERIC_EXECUTE, 0x001f01ff}
		privileges := [256]byte{}
		size := uint32(len(privileges))
		var granted, result uint32
		ok, _, callErr := access.Call(uintptr(unsafe.Pointer(descriptor)), uintptr(token), uintptr(windows.FILE_GENERIC_READ),
			uintptr(unsafe.Pointer(&mapping)), uintptr(unsafe.Pointer(&privileges[0])), uintptr(unsafe.Pointer(&size)),
			uintptr(unsafe.Pointer(&granted)), uintptr(unsafe.Pointer(&result)))
		if ok == 0 {
			return false, callErr
		}
		return result != 0, nil
	}
	allowed, err := check(sd, full)
	if err != nil || !allowed {
		return errors.New("the trusted account cannot read its private scratch descriptor")
	}
	allowed, err = check(sd, limited)
	if err != nil || allowed {
		return errors.New("the restricted token was allowed by the private scratch DACL")
	}
	control, err := windows.SecurityDescriptorFromString("O:SYG:SYD:(A;;FA;;;WD)")
	if err != nil {
		return err
	}
	allowed, err = check(control, limited)
	if err != nil || !allowed {
		return errors.New("the restricted-token positive control was not allowed")
	}
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	if err := windows.SetThreadToken(nil, limited); err != nil {
		return err
	}
	name, err := windows.UTF16PtrFromString(path)
	if err != nil {
		_ = windows.RevertToSelf()
		return err
	}
	handle, openErr := windows.CreateFile(name, windows.GENERIC_READ, windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE, nil, windows.OPEN_EXISTING, 0, 0)
	revertErr := windows.RevertToSelf()
	if openErr == nil {
		_ = windows.CloseHandle(handle)
		return errors.New("the restricted token opened the protected archive")
	}
	if revertErr != nil || !errors.Is(openErr, windows.ERROR_ACCESS_DENIED) {
		return fmt.Errorf("restricted archive access or token restoration was not established: %v %v", openErr, revertErr)
	}
	return nil
}

func TestCTR06WindowsBackupPrivateCopyAgainstMappedSource(t *testing.T) {
	if os.Getenv("CTR06_MAPPING_CHILD") == "1" {
		ctr06WindowsMappingChild(t)
		return
	}
	fixtures := t.TempDir()
	source, ready, proceed := filepath.Join(fixtures, "source"), filepath.Join(fixtures, "ready"), filepath.Join(fixtures, "proceed")
	original := []byte("synthetic-original-backup")
	if err := os.WriteFile(source, original, 0o600); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	child := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestCTR06WindowsBackupPrivateCopyAgainstMappedSource$")
	child.Env = []string{"SystemRoot=" + os.Getenv("SystemRoot"), "CTR06_MAPPING_CHILD=1", "CTR06_MAPPING_SOURCE=" + source,
		"CTR06_MAPPING_READY=" + ready, "CTR06_MAPPING_PROCEED=" + proceed}
	var output strings.Builder
	child.Stdout, child.Stderr = &output, &output
	if err := child.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() {
		if child.ProcessState == nil {
			_ = child.Process.Kill()
			_ = child.Wait()
		}
	}()
	deadline := time.Now().Add(10 * time.Second)
	for {
		if _, err := os.Stat(ready); err == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("mapped child did not establish its view")
		}
		time.Sleep(25 * time.Millisecond)
	}
	dir, cleanup, err := restoreScratch()
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := cleanup(); err != nil {
			t.Error(err)
		}
	}()
	sum := sha256.Sum256(original)
	copyFile, err := copyRestoreBackup(source, hex.EncodeToString(sum[:]), dir)
	if err != nil {
		t.Fatal(err)
	}
	defer copyFile.Close()
	if err := os.WriteFile(proceed, []byte("go"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := child.Wait(); err != nil {
		t.Fatalf("mapped child failed: %v %s", err, output.String())
	}
	copied, err := io.ReadAll(copyFile)
	if err != nil || string(copied) != string(original) {
		t.Fatalf("the protected copy changed after source mapping write: %v", err)
	}
	changed, err := os.ReadFile(source)
	if err != nil || string(changed) == string(original) {
		t.Fatalf("the source mapping did not actually change the source: %v", err)
	}
}

func ctr06WindowsMappingChild(t *testing.T) {
	name, err := windows.UTF16PtrFromString(os.Getenv("CTR06_MAPPING_SOURCE"))
	if err != nil {
		t.Fatal(err)
	}
	file, err := windows.CreateFile(name, windows.GENERIC_READ|windows.GENERIC_WRITE, windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE, nil, windows.OPEN_EXISTING, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	mapping, err := windows.CreateFileMapping(file, nil, windows.PAGE_READWRITE, 0, 0, nil)
	if err != nil {
		_ = windows.CloseHandle(file)
		t.Fatal(err)
	}
	view, err := windows.MapViewOfFile(mapping, windows.FILE_MAP_WRITE, 0, 0, 0)
	_ = windows.CloseHandle(file) // the real writable view survives without a file handle
	if err != nil {
		_ = windows.CloseHandle(mapping)
		t.Fatal(err)
	}
	defer windows.CloseHandle(mapping)
	defer windows.UnmapViewOfFile(view)
	if err := os.WriteFile(os.Getenv("CTR06_MAPPING_READY"), []byte("ready"), 0o600); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(10 * time.Second)
	for {
		if _, err := os.Stat(os.Getenv("CTR06_MAPPING_PROCEED")); err == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("mapping child was not released")
		}
		time.Sleep(25 * time.Millisecond)
	}
	data := unsafe.Slice((*byte)(unsafe.Pointer(view)), len("synthetic-original-backup"))
	copy(data, []byte("modified--original-backup"))
	if err := windows.FlushViewOfFile(view, uintptr(len(data))); err != nil {
		t.Fatal(err)
	}
}

func TestCTR06WindowsRestoreChildCancellationReapsOwnedProcess(t *testing.T) {
	if os.Getenv("CTR06_CHILD_WAIT") == "1" {
		if err := os.WriteFile(os.Getenv("CTR06_CHILD_PID_FILE"), []byte(strconv.Itoa(os.Getpid())), 0o600); err != nil {
			t.Fatal(err)
		}
		time.Sleep(30 * time.Second)
		return
	}
	dir := t.TempDir()
	pidFile := filepath.Join(dir, "child-pid")
	archive, err := os.CreateTemp(dir, "input")
	if err != nil {
		t.Fatal(err)
	}
	defer archive.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	started := time.Now()
	_, err = runRestoreTool(ctx, os.Args[0], []string{"SystemRoot=" + os.Getenv("SystemRoot"), "CTR06_CHILD_WAIT=1", "CTR06_CHILD_PID_FILE=" + pidFile}, archive, "-test.run=^TestCTR06WindowsRestoreChildCancellationReapsOwnedProcess$")
	if err == nil || time.Since(started) > 9*time.Second {
		t.Fatalf("owned Windows child was not cancelled in the bound: %v", err)
	}
	raw, err := os.ReadFile(pidFile)
	if err != nil {
		t.Fatalf("owned child never actually started: %v", err)
	}
	pid, err := strconv.ParseUint(string(raw), 10, 32)
	if err != nil || pid == 0 {
		t.Fatal("owned child PID is invalid")
	}
	handle, err := windows.OpenProcess(windows.SYNCHRONIZE, false, uint32(pid))
	if err == nil {
		defer windows.CloseHandle(handle)
		state, waitErr := windows.WaitForSingleObject(handle, 0)
		if waitErr != nil || state != windows.WAIT_OBJECT_0 {
			t.Fatalf("owned child remained alive: %v %v", state, waitErr)
		}
	} else if !errors.Is(err, windows.ERROR_INVALID_PARAMETER) {
		t.Fatalf("owned child state could not be verified: %v", err)
	}
}

func TestCTR06WindowsCaptureOutputHasPrivateDACLAndHeldParent(t *testing.T) {
	base := t.TempDir()
	path := filepath.Join(base, "backup")
	file, syncParent, release, err := openCaptureFile(path)
	if err != nil {
		t.Fatal(err)
	}
	closed := false
	defer func() {
		if !closed {
			_ = file.Close()
			release()
		}
	}()
	if _, err := file.WriteString("synthetic-backup"); err != nil {
		t.Fatal(err)
	}
	sd, err := windows.GetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION|windows.GROUP_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION)
	if err != nil || sd == nil {
		t.Fatalf("backup descriptor unavailable: %v", err)
	}
	control, _, err := sd.Control()
	if err != nil || control&windows.SE_DACL_PROTECTED == 0 {
		t.Fatalf("backup DACL is not protected: %v", err)
	}
	acl, _, err := sd.DACL()
	if err != nil || acl == nil || acl.AceCount != 3 {
		t.Fatalf("backup DACL has unexpected principals: %v", err)
	}
	if err := windowsRestrictedScratchAccess(sd, path); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(base, base+"-moved"); err == nil {
		_ = os.Rename(base+"-moved", base)
		t.Fatal("the held backup parent could be renamed")
	}
	if syncParent != nil {
		t.Fatal("Windows unexpectedly claims an equivalent parent sync")
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	release()
	closed = true
	if err := captureFile(path, strings.NewReader("replacement")); err == nil {
		t.Fatal("existing backup was overwritten")
	}
	if data, err := os.ReadFile(path); err != nil || string(data) != "synthetic-backup" {
		t.Fatal("existing backup was changed")
	}
	second := filepath.Join(base, "backup-two")
	if err := captureFile(second, strings.NewReader("second")); err != nil {
		t.Fatalf("new backup capture failed: %v", err)
	}
	if data, err := os.ReadFile(second); err != nil || string(data) != "second" {
		t.Fatal("new backup contents do not match")
	}
}
