// SPDX-License-Identifier: AGPL-3.0-only

package fleetapi

import (
	"bytes"
	"fmt"
	"testing"
	"time"

	"github.com/ArcForges/Cloud/center/internal/platform"
)

// The proof deploy must account for every published command and entitlement key, not only the one key a new Worker holds. Its
// guarded registration uses the actual protobuf replies and route budgets, and the check refuses before inserting a key that
// would make a node's sign-in or refresh reply too large.
func TestProofKeyReplyBudgetCountsThePublishedSetsAndStopsBeforeTheRouteBound(t *testing.T) {
	now := time.Unix(1_800_000_000, 0).UTC()
	key := func(i int) platform.SigningKey {
		return platform.SigningKey{
			KID: fmt.Sprintf("proof-%032x", i), Purpose: platform.CommandSigning, Algorithm: "ES256",
			PublicKey: bytes.Repeat([]byte{byte(i)}, 91), NotBefore: now, NotAfter: now.Add(400 * 24 * time.Hour),
		}
	}
	one, limit, err := proofKeyReplyBudget([]platform.SigningKey{key(1)}, nil)
	if err != nil || one <= 0 || limit != 65_536 || one >= limit {
		t.Fatalf("one key: size %d limit %d: %v", one, limit, err)
	}
	two, limit2, err := proofKeyReplyBudget([]platform.SigningKey{key(1)}, []platform.SigningKey{key(2)})
	if err != nil || limit2 != limit || two <= one {
		t.Fatalf("entitlement key not counted: one %d two %d limit %d: %v", one, two, limit2, err)
	}
	keys := make([]platform.SigningKey, 0, 1000)
	last := one
	crossed := false
	for i := range 1000 {
		keys = append(keys, key(i))
		size, gotLimit, checkErr := proofKeyReplyBudget(keys, nil)
		if checkErr != nil || gotLimit != limit || size < last {
			t.Fatalf("key set %d: size %d previous %d limit %d: %v", i+1, size, last, gotLimit, checkErr)
		}
		if size > limit {
			if last > limit || i < 1 {
				t.Fatalf("unsafe boundary: previous %d next %d limit %d", last, size, limit)
			}
			crossed = true
			break
		}
		last = size
	}
	if !crossed {
		t.Fatal("an accumulating published set never reached the actual route bound")
	}
}
