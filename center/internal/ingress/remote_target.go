// SPDX-License-Identifier: AGPL-3.0-only

package ingress

import (
	"net/http"
	"strconv"
	"strings"

	"github.com/ArcForges/Cloud/center/internal/correlation"
)

const (
	RemoteNodeHeader          = "X-ArcForges-Node-Id"
	RemoteEnrollmentHeader    = "X-ArcForges-Enrollment-Id"
	RemoteGrantHeader         = "X-ArcForges-Grant-Id"
	RemoteGrantRevisionHeader = "X-ArcForges-Grant-Revision"
)

// RemoteTarget is untrusted selection data validated at ingress. It carries
// no account, actor, proof or grant authority.
type RemoteTarget struct {
	Node, Enrollment, Grant [16]byte
	GrantRevision           int64
}

func parseRemoteTarget(headers http.Header) (*RemoteTarget, bool) {
	target := &RemoteTarget{}
	for _, field := range []struct {
		header string
		id     *[16]byte
	}{
		{RemoteNodeHeader, &target.Node}, {RemoteEnrollmentHeader, &target.Enrollment}, {RemoteGrantHeader, &target.Grant},
	} {
		values := headers.Values(field.header)
		if len(values) != 1 || len(values[0]) != 36 {
			return nil, false
		}
		id := correlation.IDBytes(strings.ToLower(values[0]))
		if len(id) != len(field.id) {
			return nil, false
		}
		copy(field.id[:], id)
	}
	values := headers.Values(RemoteGrantRevisionHeader)
	if len(values) != 1 || len(values[0]) > 19 {
		return nil, false
	}
	revision, err := strconv.ParseInt(values[0], 10, 64)
	if err != nil || revision <= 0 || strconv.FormatInt(revision, 10) != values[0] {
		return nil, false
	}
	target.GrantRevision = revision
	return target, true
}
