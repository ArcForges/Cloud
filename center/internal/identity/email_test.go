// SPDX-License-Identifier: AGPL-3.0-only

package identity

import (
	"bytes"
	"context"
	"encoding/hex"
	"testing"

	"github.com/ArcForges/Cloud/center/internal/config"
)

// TestTheCodeVerifierIsPBKDF2 pins the stored verifier of an e-mail code (F13): PBKDF2-HMAC-SHA-256 of the code with the flow's
// 16-byte salt and the policy's iterations, 32 bytes, against vectors computed independently with Python's hashlib.pbkdf2_hmac.
func TestTheCodeVerifierIsPBKDF2(t *testing.T) {
	for _, item := range []struct {
		code       string
		salt       []byte
		iterations int
		want       string
	}{
		{"BCDFGHJK", []byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15}, 20_000, "a2e9d238123b8baef6afe1f88d95441cc3be987d99982d9a962fbd8af6241ee3"},
		{"ZZZZZZZZ", bytes.Repeat([]byte{0xa5}, 16), 10_000, "5753aae0db8555140c09677bd422a7f945238a560e7e6922ef1efbd3a957c1a5"},
	} {
		policy := config.DefaultIdentityPolicy()
		policy.EmailCodeIterations = item.iterations
		verifier, err := New(Options{Policy: policy}).codeHash(context.Background(), item.code, item.salt)
		if err != nil || hex.EncodeToString(verifier) != item.want || bytes.Contains(verifier, []byte(item.code)) {
			t.Fatalf("the verifier of %s: %x %v", item.code, verifier, err)
		}
	}
	if config.DefaultIdentityPolicy().EmailCodeIterations != 20_000 {
		t.Fatal("the default iterations changed")
	}
}
