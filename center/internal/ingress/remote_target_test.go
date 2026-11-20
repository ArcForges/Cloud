// SPDX-License-Identifier: AGPL-3.0-only

package ingress

import (
	"math"
	"net/http"
	"testing"
)

func TestTypedManagementTargetUsesExactHeadersAndRevision(t *testing.T) {
	headers := make(http.Header)
	headers.Set(RemoteNodeHeader, "F0000000-0000-0000-0000-000000000001")
	headers.Set(RemoteEnrollmentHeader, "F0000000-0000-0000-0000-000000000002")
	headers.Set(RemoteGrantHeader, "F0000000-0000-0000-0000-000000000003")
	headers.Set(RemoteGrantRevisionHeader, "9223372036854775807")
	target, valid := parseRemoteTarget(headers)
	if !valid || target.Node != ([16]byte{0xf0, 15: 1}) || target.Enrollment != ([16]byte{0xf0, 15: 2}) ||
		target.Grant != ([16]byte{0xf0, 15: 3}) || target.GrantRevision != math.MaxInt64 {
		t.Fatalf("exact typed target: %+v %v", target, valid)
	}
	for _, name := range []string{RemoteNodeHeader, RemoteEnrollmentHeader, RemoteGrantHeader, RemoteGrantRevisionHeader} {
		invalid := headers.Clone()
		invalid.Del(name)
		if _, ok := parseRemoteTarget(invalid); ok {
			t.Errorf("accepted missing %s", name)
		}
		invalid = headers.Clone()
		invalid.Add(name, headers.Get(name))
		if _, ok := parseRemoteTarget(invalid); ok {
			t.Errorf("accepted repeated %s", name)
		}
	}
	for _, revision := range []string{"0", "01", "+1", "1, 2", "9223372036854775808"} {
		invalid := headers.Clone()
		invalid.Set(RemoteGrantRevisionHeader, revision)
		if _, ok := parseRemoteTarget(invalid); ok {
			t.Errorf("accepted invalid revision %q", revision)
		}
	}
	headers.Set(RemoteNodeHeader, "00000000-0000-0000-0000-000000000000")
	if _, ok := parseRemoteTarget(headers); ok {
		t.Error("accepted empty Node identity")
	}
}
