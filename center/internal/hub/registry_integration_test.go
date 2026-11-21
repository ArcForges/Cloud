// SPDX-License-Identifier: AGPL-3.0-only

package hub_test

import (
	"crypto/sha256"
	"testing"

	foundationv1 "github.com/ArcForges/Contracts/go/arcforges/foundation/v1"
	nodev1 "github.com/ArcForges/Contracts/go/arcforges/node/v1"
	relayv1 "github.com/ArcForges/Contracts/go/arcforges/relay/v1"
	"google.golang.org/protobuf/proto"

	"github.com/ArcForges/Cloud/center/internal/nodetest"
	"github.com/ArcForges/Cloud/center/internal/platform"
)

// The retired FleetService route suite is retained at Cloud commit
// 9b8796eac760982d9814f371b820b736ddd945c4 (tree 2b35c50007089d6e6c51797f62437334bd2826f3).
// In that checkout, the Linux `python eng/center.py check` lane supplies the pinned
// PostgreSQL fixture and runs `go test -race -count=1 -timeout 10m ./...` from center/.
// The helpers below also serve the direct signed Hub transport tests.

func idValue(id platform.ID) *foundationv1.Id {
	return &foundationv1.Id{Value: append([]byte(nil), id[:]...)}
}

// sign binds the marshalled request to the node channel's one-use nonce.
func sign(t *testing.T, node *enrolled, channel *nodetest.Channel, request proto.Message, method relayv1.RoutedMethod, target *platform.ID,
	origin nodev1.Origin, set func([]byte)) {
	t.Helper()
	data, err := proto.Marshal(request)
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(data)
	assertion := node.node.Assertion(publicBaseURL, nodetest.Relay{InstallationID: node.result.InstallationID, LocalOrigin: origin, LocalSession: platform.NewID(),
		Method: method, RequestSHA256: digest[:], Target: target, Nonce: nonceOf(t, channel)})
	encoded, err := proto.Marshal(assertion)
	if err != nil {
		t.Fatal(err)
	}
	set(encoded)
}
