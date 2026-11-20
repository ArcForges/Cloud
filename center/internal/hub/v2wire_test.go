// SPDX-License-Identifier: AGPL-3.0-only

package hub

import (
	"bytes"
	"encoding/binary"
	"slices"
	"testing"
	"time"

	"github.com/ArcForges/Cloud/center/internal/platform"
)

func TestV2WireBindsExactCapabilityAndHubGeneration(t *testing.T) {
	v := v2Codec{enrollment: platform.ID{1}, epoch: platform.ID{2}, account: platform.ID{3}, fence: 258}
	challenge, err := v.Challenge(1, bytes.Repeat([]byte{4}, NonceBytes), platform.ID{5}, time.UnixMilli(1000))
	if err != nil || len(challenge) != 122 || challenge[0] != 2 || challenge[1] != 1 ||
		binary.BigEndian.Uint64(challenge[2:10]) != 1 || binary.BigEndian.Uint64(challenge[106:114]) != 258 {
		t.Fatalf("wrong challenge frame, error %v", err)
	}
	intent := make([]byte, 48)
	intent[0], intent[16], intent[32] = 1, 2, 3
	intent = append(intent, 3, '4', '5', '6', 1, 2)
	for _, key := range []string{v2Cohort, "win-wrapper-local-v1"} {
		intent = append(intent, byte(len(key)))
		intent = append(intent, key...)
	}
	raw := slices.Concat(v2Header(v2Hello, 1), intent, make([]byte, v2SignatureSize))
	seen, err := v.Decode(raw)
	if err != nil || seen.kind != inboundHello || seen.hello.nodeEpoch != "456" || seen.hello.ownerEpoch != (platform.ID{3}) {
		t.Fatalf("expected an exact V2 hello observation, error %v", err)
	}
	keys, compatible := v2QualifiedClaims(seen.hello)
	if !compatible || !slices.Equal(keys, []string{"win-wrapper-local-v1"}) {
		t.Fatalf("wrong qualified capability projection: %v", keys)
	}
	if _, err := v.Decode(raw); err == nil {
		t.Fatal("a duplicate frame sequence was accepted")
	}
	base := v.helloMessage("https://center.example.test/api", intent)
	v.fence++
	if _, err := v.Challenge(1, bytes.Repeat([]byte{4}, NonceBytes), platform.ID{5}, time.UnixMilli(1000)); err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(base, v.helloMessage("https://center.example.test/api", intent)) {
		t.Fatal("a stale hub generation produced the same signed hello input")
	}
}
