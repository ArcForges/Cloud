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
// environment and unsets it, a valid one and a malformed one alike, so no later reader of the environment finds a private half.
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
}
