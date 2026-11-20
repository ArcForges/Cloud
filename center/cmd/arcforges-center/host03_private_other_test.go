// SPDX-License-Identifier: AGPL-3.0-only

//go:build !windows

package main

import (
	"os"
	"testing"
)

func host03PrivateDirectory(t *testing.T, name string) {
	t.Helper()
	if err := os.Mkdir(name, 0700); err != nil {
		t.Fatal("create the owner-private native fixture directory")
	}
}

func host03CheckNativeChildren(*testing.T, string, string) {}
