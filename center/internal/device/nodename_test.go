// SPDX-License-Identifier: AGPL-3.0-only

package device

import (
	"strings"
	"testing"
)

// TestValidNodeName pins protocol-11's allow list for the name a node reports: every hostile case of the corrected fix is refused
// (bidirectional controls, zero-width and other format characters, fillers and blanks, padding with other spaces, runs of spaces,
// line and paragraph separators, private use, unassigned code points, an all-invisible name, combining-mark stacks), while ordinary
// names of several scripts are admitted. ValidName (the account's own rename) is unchanged. ASCII imitations and look-alike letters
// pass by design: the pages label the name as the node's own (a documented residual).
func TestValidNodeName(t *testing.T) {
	for _, name := range []string{"my-laptop", "Sam's PC", "B\u00fcro-Rechner", "\u05e9\u05e8\u05ea 2", "buildbox", "ArcForges Updater (verified)", "\u0410rcForges",
		"x", strings.Repeat("a", 64), "e\u0301\u0301\u0301", "\u6771\u4eac \u30b5\u30fc\u30d0\u30fc"} {
		if !ValidNodeName(name) {
			t.Errorf("%q refused", name)
		}
	}
	for _, name := range []string{"", " lead", "trail ", "two  spaces", "ArcForges \u202eerawtfoS\u202c", "Linux \u2067 64 \u2069 ok", "a\u200eb\u200fc",
		"\u200b", " \u200b\u200b ", "\ufeff", "\u3164", "\u2800", "a\u2028b", "a\u2029b", "a\ue000b", "a\u0378b", "Caf\u00e9\u00a0\u00a0x",
		"ArcForges Updater (verified)" + strings.Repeat("\u00a0", 20) + "x", "a\u061cb", "a\u2060b", "a\u200db", "a\tb", "a\x00b", "\u115f\u1160",
		"e\u0301\u0301\u0301\u0301", strings.Repeat("a", 65), "\xff"} {
		if ValidNodeName(name) {
			t.Errorf("%q admitted", name)
		}
	}
	if !NameTooLong(strings.Repeat("a", 65)) || NameTooLong(strings.Repeat("a", 64)) {
		t.Fatal("the length rule")
	}
}
