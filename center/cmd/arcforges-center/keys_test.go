// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"os"
	"testing"
)

// TestTheCommandKeysAreReadOnceAndUnset (AF-CTR-05 E1a, CTR5-KEY-01): serve reads every ARCFORGES_CENTER_KEY_ variable of the process
// environment and unsets it from the process environment, a valid one and a malformed one alike, and a malformed one never leaves the
// variables after it set, so no later reader of os.Environ finds a private half.
func TestTheCommandKeysAreReadOnceAndUnset(t *testing.T) {
	private, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(private)
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("ARCFORGES_CENTER_KEY_ONE", base64.StdEncoding.EncodeToString(der))
	keys, err := commandKeys()
	if err != nil || len(keys) != 1 || keys[0].Binding != "ARCFORGES_CENTER_KEY_ONE" {
		t.Fatalf("%v %v", keys, err)
	}
	if _, left := os.LookupEnv("ARCFORGES_CENTER_KEY_ONE"); left {
		t.Fatal("the key's variable is still set")
	}
	t.Setenv("ARCFORGES_CENTER_KEY_BAD", "not base64")
	if _, err := commandKeys(); err == nil {
		t.Fatal("a malformed key was admitted")
	}
	if _, left := os.LookupEnv("ARCFORGES_CENTER_KEY_BAD"); left {
		t.Fatal("a refused key's variable is still set")
	}
	// A malformed key ahead of valid ones, in os.Environ order and in name order: every one is unset all the same.
	t.Setenv("ARCFORGES_CENTER_KEY_A", "not base64")
	t.Setenv("ARCFORGES_CENTER_KEY_B", base64.StdEncoding.EncodeToString(der))
	t.Setenv("ARCFORGES_CENTER_KEY_bad", base64.StdEncoding.EncodeToString(der))
	t.Setenv("ARCFORGES_CENTER_KEY_Z", base64.StdEncoding.EncodeToString(der))
	if _, err := commandKeys(); err == nil {
		t.Fatal("a malformed key was admitted")
	}
	for _, name := range []string{"ARCFORGES_CENTER_KEY_A", "ARCFORGES_CENTER_KEY_B", "ARCFORGES_CENTER_KEY_bad", "ARCFORGES_CENTER_KEY_Z"} {
		if _, left := os.LookupEnv(name); left {
			t.Fatalf("%s is still set after a refused start", name)
		}
	}
}
