// SPDX-License-Identifier: AGPL-3.0-only

package identity

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/ArcForges/Cloud/center/internal/device"
)

// The rules below are ported from the C# IdentityDomainTests (tests/ArcForges.Cloud.Tests/Identity/IdentityDomainTests.cs) where
// they encode behaviour the center keeps; identifier parsing, workspace ownership and realms have no counterpart here (one center
// database is one realm, and workspaces are not part of AF-CTR-03).

func TestDisplayNamesArePlainBoundedText(t *testing.T) {
	cases := map[string]bool{"Ada": true, "Ádá 😀": true, "": false, "   ": false, "tab\there": false, "new\nline": false, "del\x7f": false,
		"c1\u0085": false}
	for text, valid := range cases {
		if ValidDisplayName(text) != valid {
			t.Errorf("%q: want %v", text, valid)
		}
	}
	// An unpaired surrogate cannot be valid UTF-8 (its three-byte encoding is refused); a paired one is ordinary text.
	for _, invalid := range []string{"\xed\xa0\x80", "a\xed\xa0\x80", "\xed\xb0\x80x", "\xff"} {
		if utf8.ValidString(invalid) || ValidDisplayName(invalid) {
			t.Errorf("%q was admitted", invalid)
		}
	}
	if !ValidDisplayName("\U0001F600") {
		t.Fatal("a supplementary character was refused")
	}
}

func TestTextBoundsAreExactInUTF16Units(t *testing.T) {
	if !ValidDisplayName(strings.Repeat("a", DisplayNameMaxUnits)) || ValidDisplayName(strings.Repeat("a", DisplayNameMaxUnits+1)) {
		t.Fatal("display name bound")
	}
	// A supplementary character counts two units, as the C# host counts it.
	if !ValidDisplayName(strings.Repeat("\U0001F600", DisplayNameMaxUnits/2)) || ValidDisplayName(strings.Repeat("\U0001F600", DisplayNameMaxUnits/2)+"a") {
		t.Fatal("display name bound in UTF-16 units")
	}
	if !ValidSubject(strings.Repeat("a", SubjectMaxUnits)) || ValidSubject(strings.Repeat("a", SubjectMaxUnits+1)) || ValidSubject("") {
		t.Fatal("subject bound")
	}
	empty, long, exact := "", strings.Repeat("a", LabelMaxUnits+1), strings.Repeat("a", LabelMaxUnits)
	if !ValidLabel(nil) || ValidLabel(&empty) || !ValidLabel(&exact) || ValidLabel(&long) {
		t.Fatal("label bound")
	}
}

func TestOnlyAnActiveUserMayAddAndOnlyAnActiveOrRestrictedUserMayChangeCredentials(t *testing.T) {
	cases := []struct {
		state                     UserState
		signIn, mayAdd, mayChange bool
	}{
		{StateActive, true, true, true},
		{StateRestricted, true, false, true},
		{StateSuspended, false, false, false},
		{StatePendingDeletion, false, false, false},
		{StateDeleted, false, false, false},
	}
	for _, item := range cases {
		if item.state.MaySignIn() != item.signIn || item.state.MayAddCredential() != item.mayAdd || item.state.MayChangeCredentials() != item.mayChange {
			t.Errorf("state %d", item.state)
		}
	}
}

func TestTheLastCredentialRuleKeepsAUsableCredential(t *testing.T) {
	// The center has no recovery path yet (AF-ID-02), so the last live credential can never be removed.
	if err := CheckRemoval(StateActive, []string{"one"}, "one"); !errors.Is(err, ErrLastCredential) {
		t.Fatalf("the only credential: %v", err)
	}
	if err := CheckRemoval(StateActive, []string{"one", "two"}, "one"); err != nil {
		t.Fatalf("a second credential: %v", err)
	}
	if err := CheckRemoval(StateRestricted, []string{"one", "two"}, "two"); err != nil {
		t.Fatalf("a restricted account removes a credential: %v", err)
	}
	// The live list holds only the account's unrevoked credentials: another's, or a revoked one, is not the account's.
	if err := CheckRemoval(StateActive, []string{"one"}, "other"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("a credential that is not the account's: %v", err)
	}
	if err := CheckRemoval(StateSuspended, []string{"one", "two"}, "one"); !errors.Is(err, ErrNotPermitted) {
		t.Fatalf("a suspended account: %v", err)
	}
}

func TestEmailAddressesAreNormalizedOrRefused(t *testing.T) {
	cases := map[string]string{
		"Ada@Example.ORG": "ada@example.org", "a.b+c@sub.example.org": "a.b+c@sub.example.org", "x@a-b.example": "x@a-b.example",
		"": "", "ada": "", "ada@": "", "@example.org": "", "a@b@example.org": "", "ada@localhost": "", "a da@example.org": "",
		".ada@example.org": "", "ada.@example.org": "", "a..da@example.org": "", "ada@-example.org": "", "ada@example-.org": "",
		"\"ada\"@example.org": "", "ada@exa_mple.org": "", strings.Repeat("a", 65) + "@example.org": "",
	}
	for text, want := range cases {
		got, ok := NormalizeEmail(text)
		if got != want || ok != (want != "") {
			t.Errorf("%q: got %q %v, want %q", text, got, ok, want)
		}
	}
}

func FuzzNormalizeEmail(f *testing.F) {
	for _, seed := range []string{"ada@example.org", "A@B.CD", "a@b", "\x00@x.y", "a@b..c", strings.Repeat("x", 400)} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, text string) {
		normalized, ok := NormalizeEmail(text)
		if !ok {
			if normalized != "" {
				t.Fatal("a refused address has a normal form")
			}
			return
		}
		again, ok := NormalizeEmail(normalized)
		if !ok || again != normalized || normalized != strings.ToLower(normalized) || len(normalized) > EmailMaxLength ||
			strings.Count(normalized, "@") != 1 {
			t.Fatalf("%q normalized to %q", text, normalized)
		}
		for _, c := range []byte(normalized) {
			if c <= ' ' || c >= 0x7f {
				t.Fatalf("%q normalized to a control or non-ASCII byte", text)
			}
		}
	})
}

func TestCodesUseTheAlphabetAndNormalize(t *testing.T) {
	seen := map[string]bool{}
	for range 200 {
		code := NewCode()
		if len(code) != CodeLength || strings.Trim(code, CodeAlphabet) != "" {
			t.Fatalf("code %q", code)
		}
		seen[code] = true
		normalized, ok := NormalizeCode(strings.ToLower(code[:4]) + "-" + code[4:])
		if !ok || normalized != code {
			t.Fatalf("normalize %q", code)
		}
	}
	if len(seen) < 190 {
		t.Fatal("codes repeat")
	}
	for _, invalid := range []string{"", "BCDFGHJ", "BCDFGHJKL", "BCDFGHJA", "BCDF GHJ1", strings.Repeat("B", 65)} {
		if _, ok := NormalizeCode(invalid); ok {
			t.Errorf("%q was admitted", invalid)
		}
	}
}

// TestTheEnumNumbersAreTheStoredPositionsOfThePhysicalEnums pins the stored smallints to the positions of the D1 manifest's enums
// (1-based), as the C# test of the same name does; the trust level's 3 = revoked is the PostgreSQL deviation (docs/postgres-store.md).
func TestTheEnumNumbersAreTheStoredPositionsOfThePhysicalEnums(t *testing.T) {
	values := func(file, name string) []string {
		t.Helper()
		data, err := os.ReadFile(filepath.Join("..", "..", "..", "src", "ArcForges.Cloud.Storage.D1", "Physical", "manifest", file))
		if err != nil {
			t.Fatal(err)
		}
		var manifest struct {
			Enums map[string]struct {
				Values []string `json:"values"`
			} `json:"enums"`
		}
		if err = json.Unmarshal(data, &manifest); err != nil {
			t.Fatal(err)
		}
		return manifest.Enums[name].Values
	}
	check := func(name string, manifest []string, stored map[string]int) {
		t.Helper()
		for position, value := range manifest {
			if number, ok := stored[value]; ok && number != position+1 {
				t.Errorf("%s %s is %d, the manifest's position is %d", name, value, number, position+1)
			}
		}
		for value := range stored {
			found := false
			for _, item := range manifest {
				found = found || item == value
			}
			if !found {
				t.Errorf("%s %s is not in the manifest", name, value)
			}
		}
	}
	check("identity.user_state", values("identity.json", "identity.user_state"), map[string]int{"active": int(StateActive), "restricted": int(StateRestricted),
		"suspended": int(StateSuspended), "pendingDeletion": int(StatePendingDeletion), "deleted": int(StateDeleted)})
	check("identity.auth_method", values("identity.json", "identity.auth_method"), map[string]int{"passkey": int(MethodPasskey), "emailCode": int(MethodEmailCode)})
	check("identity.credential_kind", values("identity.json", "identity.credential_kind"), map[string]int{"nativeBearer": 1, "browserCookie": 2})
	check("device.platform", values("device.json", "device.platform"), map[string]int{"windows": int(device.PlatformWindows), "macos": int(device.PlatformMacOS),
		"linux": int(device.PlatformLinux), "android": int(device.PlatformAndroid), "ios": int(device.PlatformIOS), "web": int(device.PlatformWeb)})
	check("device.trust_level", values("device.json", "device.trust_level"), map[string]int{"untrusted": int(device.TrustUntrusted), "trusted": int(device.TrustTrusted)})
	if device.TrustRevoked != 3 {
		t.Fatal("the revoked trust level is 3")
	}
}

// TestTimeZonesFollowTheContractPattern (F20): a time zone is admitted only within the contract's timezone pattern, which has no
// '+', so a profile never echoes a value the contract refuses.
func TestTimeZonesFollowTheContractPattern(t *testing.T) {
	for _, zone := range []string{"UTC", "Europe/Zurich", "America/Port-au-Prince", "America/Argentina/Buenos_Aires", "Etc/GMT-14"} {
		if !ValidTimezone(zone) {
			t.Errorf("%q was refused", zone)
		}
	}
	for _, zone := range []string{"Etc/GMT+5", "GMT+0", "", "/UTC", "UTC/", "Europe//Zurich", "UTC:00", "Europe/Zürich", strings.Repeat("A", 65)} {
		if ValidTimezone(zone) {
			t.Errorf("%q was admitted", zone)
		}
	}
}
