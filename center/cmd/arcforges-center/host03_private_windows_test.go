// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"context"
	"os/exec"
	"testing"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

func host03PrivateDirectory(t *testing.T, name string) {
	t.Helper()
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil || user.User.Sid == nil {
		t.Fatal("resolve the current Windows owner for the private fixture directory")
	}
	sid := user.User.Sid.String()
	descriptor, err := windows.SecurityDescriptorFromString("O:" + sid + "D:P(A;OICI;FA;;;" + sid + ")")
	if err != nil {
		t.Fatal("prepare the explicit owner-only Windows fixture DACL")
	}
	target, err := windows.UTF16PtrFromString(name)
	if err != nil {
		t.Fatal("prepare the native private fixture directory name")
	}
	attributes := windows.SecurityAttributes{SecurityDescriptor: descriptor}
	attributes.Length = uint32(unsafe.Sizeof(attributes))
	if err = windows.CreateDirectory(target, &attributes); err != nil {
		t.Fatal("create the owner-private Windows fixture directory")
	}
}

func host03CheckNativeChildren(t *testing.T, data, install string) {
	t.Helper()
	const check = `
$ErrorActionPreference = 'Stop'
$data = $env:ARCFORGES_HOST03_OWNED_DATA + '\'
$install = $env:ARCFORGES_HOST03_OWNED_INSTALL + '\'
function ownedWorkers {
  Get-CimInstance Win32_Process -Filter "Name = 'arcforges-run-supervisor.exe' OR Name = 'wxc-exec.exe'" |
    Where-Object { $_.CommandLine -and $_.ExecutablePath -and
        $_.CommandLine.IndexOf($data, [StringComparison]::OrdinalIgnoreCase) -ge 0 -and
        $_.ExecutablePath.StartsWith($install, [StringComparison]::OrdinalIgnoreCase) }
}
$deadline = [DateTime]::UtcNow.AddSeconds(6)
do {
  $owned = @(ownedWorkers)
  if ($owned.Count -eq 0) { exit 0 }
  Start-Sleep -Milliseconds 200
} while ([DateTime]::UtcNow -lt $deadline)
foreach ($worker in ($owned | Sort-Object Name -Descending)) {
  $current = @(ownedWorkers | Where-Object ProcessId -eq $worker.ProcessId)
  if ($current.Count -eq 1) { Stop-Process -Id $worker.ProcessId -Force }
}
if (@(ownedWorkers).Count -ne 0) { exit 3 }
exit 2
`
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "powershell.exe", "-NoLogo", "-NoProfile", "-NonInteractive", "-Command", check)
	cmd.Env = host03Environment(map[string]string{"ARCFORGES_HOST03_OWNED_DATA": data, "ARCFORGES_HOST03_OWNED_INSTALL": install})
	if err := cmd.Run(); err != nil {
		t.Errorf("Windows Run child cleanup required intervention or could not be confirmed (%v)", host03Exit(err))
	}
}
