// SPDX-License-Identifier: AGPL-3.0-only

package page

import (
	"strings"
	"testing"
	"time"
)

func TestPageRequestsAreBoundedAndCursorsBelongToTheirListing(t *testing.T) {
	request, refusal := Parse(Sessions, "", 0, false)
	if refusal != nil || request.Limit != DefaultLimit || request.After != nil {
		t.Fatalf("default %+v %v", request, refusal)
	}
	if request, refusal = Parse(Sessions, "", 1, true); refusal != nil || request.Limit != 1 {
		t.Fatal("limit 1")
	}
	if request, refusal = Parse(Sessions, "", 1000, true); refusal != nil || request.Limit != MaxLimit {
		t.Fatal("limit clamp")
	}
	if _, refusal = Parse(Sessions, "", 0, true); refusal == nil || refusal.Key() != "VALIDATION/invalid_argument" {
		t.Fatal("limit 0")
	}
	position := Cursor{At: time.Date(2026, 10, 28, 12, 0, 0, 123456000, time.UTC), ID: [16]byte{1, 2, 3}}
	cursor := Encode(Devices, position)
	request, refusal = Parse(Devices, cursor, 0, false)
	if refusal != nil || request.After == nil || !request.After.At.Equal(position.At) || request.After.ID != position.ID {
		t.Fatalf("round trip %+v %v", request, refusal)
	}
	versioned := []byte(cursor)
	versioned[1] = 'g' // version 2
	for _, invalid := range []string{"x", cursor + "A", string(versioned), cursor[:len(cursor)-1], cursor + "=", strings.Repeat("A", 4097)} {
		if _, refusal = Parse(Devices, invalid, 0, false); refusal == nil || refusal.Key() != "VALIDATION/invalid_cursor" {
			t.Errorf("%q was admitted", invalid)
		}
	}
	if _, refusal = Parse(Sessions, cursor, 0, false); refusal == nil || refusal.Key() != "VALIDATION/invalid_cursor" {
		t.Fatal("a cursor of another listing was admitted")
	}
}

func FuzzParseCursor(f *testing.F) {
	f.Add(Encode(Sessions, Cursor{At: time.Unix(1, 0), ID: [16]byte{9}}))
	f.Add("")
	f.Add("AQ")
	f.Fuzz(func(t *testing.T, text string) {
		request, refusal := Parse(Sessions, text, 0, false)
		if refusal != nil {
			return
		}
		if text == "" {
			if request.After != nil {
				t.Fatal("an empty cursor has a position")
			}
			return
		}
		if request.After == nil || Encode(Sessions, *request.After) != text {
			t.Fatalf("%q is admitted but not canonical", text)
		}
	})
}
