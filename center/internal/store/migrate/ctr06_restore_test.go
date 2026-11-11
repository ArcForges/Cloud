// SPDX-License-Identifier: AGPL-3.0-only

package migrate

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRestoreListRetainsEveryUnrelatedEntryAndRejectsAmbiguity(t *testing.T) {
	const base = `; archive
1; 2615 11 SCHEMA - platform owner
2; 2615 12 SCHEMA - fleet owner
3; 1259 13 TABLE platform ctr06_runtime_floor owner
4; 0 13 TABLE DATA platform ctr06_runtime_floor owner
5; 2606 14 CONSTRAINT platform ctr06_runtime_floor ctr06_runtime_floor_pkey owner
6; 1259 15 TABLE platform ctr06_runtime_floor_extra owner
7; 0 15 TABLE DATA platform ctr06_runtime_floor_extra owner
8; 1259 16 TABLE fleet routed_call owner
10; 1259 20 TABLE platform ctr06_restore_admission owner
11; 0 20 TABLE DATA platform ctr06_restore_admission owner
12; 2606 21 CONSTRAINT platform ctr06_restore_admission ctr06_restore_admission_pkey owner
`
	got, err := restoreList([]byte(base), []string{"platform", "fleet"})
	if err != nil {
		t.Fatal(err)
	}
	const retained = `; archive
6; 1259 15 TABLE platform ctr06_runtime_floor_extra owner
7; 0 15 TABLE DATA platform ctr06_runtime_floor_extra owner
8; 1259 16 TABLE fleet routed_call owner
`
	if string(got) != retained {
		t.Fatalf("retained table of contents differs: %q", got)
	}
	for name, raw := range map[string]string{
		"missing schema":       strings.Replace(base, "2; 2615 12 SCHEMA - fleet owner\n", "", 1),
		"missing floor data":   strings.Replace(base, "4; 0 13 TABLE DATA platform ctr06_runtime_floor owner\n", "", 1),
		"missing admission":    strings.Replace(base, "11; 0 20 TABLE DATA platform ctr06_restore_admission owner\n", "", 1),
		"duplicate admission":  base + "13; 1259 20 TABLE platform ctr06_restore_admission owner\n",
		"unexpected admission": base + "13; 0 20 ACL platform ctr06_restore_admission owner\n",
		"duplicate floor":      base + "9; 1259 13 TABLE platform ctr06_runtime_floor owner\n",
		"duplicate id":         base + "8; 1259 17 TABLE fleet other owner\n",
		"unexpected floor ACL": base + "9; 0 13 ACL platform ctr06_runtime_floor owner\n",
		"ambiguous floor":      base + "9; 0 13 TABLE platform ctr06_runtime_floor owner other\n",
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := restoreList([]byte(raw), []string{"platform", "fleet"}); err == nil {
				t.Fatal("ambiguous or incomplete archive was accepted")
			}
		})
	}
}

func TestRestoreBackupUsesExpectedBytesAndPrivateCopy(t *testing.T) {
	dir, cleanup, err := restoreScratch()
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := cleanup(); err != nil {
			t.Error(err)
		}
	}()
	sourceDir := t.TempDir()
	source := filepath.Join(sourceDir, "source")
	if err := os.WriteFile(source, []byte("trusted backup"), 0o600); err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256([]byte("trusted backup"))
	file, err := copyRestoreBackup(source, hex.EncodeToString(digest[:]), dir)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	if err := os.WriteFile(source, []byte("changed backup"), 0o600); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(file.Name())
	if err != nil || !bytes.Equal(got, []byte("trusted backup")) {
		t.Fatalf("private copy changed: %v", err)
	}
}

func TestRestoreBackupRejectsWrongDigest(t *testing.T) {
	dir, cleanup, err := restoreScratch()
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := cleanup(); err != nil {
			t.Error(err)
		}
	}()
	source := filepath.Join(t.TempDir(), "source")
	if err := os.WriteFile(source, []byte("backup"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := copyRestoreBackup(source, strings.Repeat("0", 64), dir); err == nil {
		t.Fatal("backup with the wrong digest was accepted")
	}
}

func TestCTR06ArchiveInventoryRequiresEverySupportedDataAndObject(t *testing.T) {
	var builder strings.Builder
	builder.WriteString(";\n;     Format: CUSTOM\n;     Dumped by pg_dump version: 18.4\n")
	for i, entry := range strings.Split(strings.TrimSpace(ctr06Schema11Inventory), "\n") {
		fmt.Fprintf(&builder, "%d; 0 0 %s owner\n", i+1, entry)
	}
	base := builder.String()
	if err := ctr06ArchiveInventory([]byte(base), nil); err != nil {
		t.Fatalf("complete supported inventory refused: %v", err)
	}
	for name, altered := range map[string]string{
		"omitted non-floor data": strings.Replace(base, "TABLE DATA platform outbox owner\n", "TABLE DATA platform missing owner\n", 1),
		"omitted history":        strings.Replace(base, "TABLE DATA platform schema_migration owner\n", "TABLE DATA platform missing owner\n", 1),
		"omitted sequence":       strings.Replace(base, "SEQUENCE SET platform outbox_sequence_seq owner\n", "SEQUENCE SET platform missing owner\n", 1),
		"extra definition":       base + "9001; 0 0 TABLE fleet unexpected owner\n",
		"duplicate definition":   base + "9001; 0 0 TABLE platform outbox owner\n",
		"unknown object class":   base + "9001; 0 0 EXTENSION - unwanted owner\n",
		"wrong format":           strings.Replace(base, "Format: CUSTOM", "Format: TAR", 1),
		"wrong tool major":       strings.Replace(base, "version: 18.4", "version: 17.5", 1),
		"unknown ACL":            base + "9001; 0 0 ACL fleet TABLE unexpected owner\n",
		"duplicate ACL":          base + "9001; 0 0 ACL platform TABLE outbox owner\n9002; 0 0 ACL platform TABLE outbox owner\n",
	} {
		t.Run(name, func(t *testing.T) {
			if err := ctr06ArchiveInventory([]byte(altered), nil); err == nil {
				t.Fatal("incomplete or unsupported inventory was accepted")
			}
		})
	}
	objects := []ctr06BackupLargeObject{{OID: 17715}}
	complete := base + "9001; 0 0 BLOB METADATA - 17715 owner\n9002; 0 0 BLOBS - 17715 owner\n"
	if err := ctr06ArchiveInventory([]byte(complete), objects); err != nil {
		t.Fatalf("complete large-object inventory refused: %v", err)
	}
	if err := ctr06ArchiveInventory([]byte(strings.Replace(complete, "9002; 0 0 BLOBS - 17715 owner\n", "", 1)), objects); err == nil {
		t.Fatal("large-object data omission was accepted")
	}
}

func TestCTR06LegacyCopyObservationIsStreamingAndRejectsAmbiguity(t *testing.T) {
	longValue := strings.Repeat("x", 150000)
	text := "-- preamble\nCOPY platform.outbox (sequence, event_type) FROM stdin;\n" + longValue + "\nsecond\\nvalue\n\\.\n-- end\n"
	got, err := ctr06ReadArchivedCopy(strings.NewReader(text), "platform.outbox")
	if err != nil || got.Rows != 2 || len(got.Columns) != 2 {
		t.Fatalf("stream observation: %+v %v", got, err)
	}
	expected := sha256.Sum256([]byte(longValue + "\nsecond\\nvalue\n"))
	if got.SHA256 != hex.EncodeToString(expected[:]) {
		t.Fatal("streamed archive data digest differs")
	}
	for name, text := range map[string]string{
		"missing terminator": "COPY platform.outbox (sequence) FROM stdin;\n1\n",
		"wrong table":        "COPY platform.inbox (sequence) FROM stdin;\n\\.\n",
		"duplicate columns":  "COPY platform.outbox (sequence, sequence) FROM stdin;\n\\.\n",
		"duplicate data":     "COPY platform.outbox (sequence) FROM stdin;\n\\.\nCOPY platform.outbox (sequence) FROM stdin;\n\\.\n",
		"sql injection":      "COPY platform.outbox (sequence); DROP TABLE fleet.node; --) FROM stdin;\n\\.\n",
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := ctr06ReadArchivedCopy(strings.NewReader(text), "platform.outbox"); err == nil {
				t.Fatal("incomplete or ambiguous COPY data was accepted")
			}
		})
	}
}

func TestCTR06LegacyLargeObjectObservationHashesActualArchiveBytes(t *testing.T) {
	input := "SELECT pg_catalog.lo_open('23', 131072);\nSELECT pg_catalog.lowrite(0, '\\x616263');\nSELECT pg_catalog.lo_close(0);\n"
	got, err := ctr06ReadArchivedLargeObjects(strings.NewReader(input), []ctr06BackupLargeObject{{OID: 23}})
	if err != nil || len(got) != 1 || got[0].OID != 23 || got[0].Bytes != 3 || got[0].SHA256 != ctr06SHA([]byte("abc")) {
		t.Fatalf("archive large-object observation: %+v %v", got, err)
	}
	for _, text := range []string{
		strings.Replace(input, "SELECT pg_catalog.lo_close(0);\n", "", 1),
		strings.Replace(input, "lo_open('23'", "lo_open('24'", 1),
		strings.Replace(input, "lo_open('23'", "lo_open('23'", 1) + input,
	} {
		if _, err := ctr06ReadArchivedLargeObjects(strings.NewReader(text), []ctr06BackupLargeObject{{OID: 23}}); err == nil {
			t.Fatal("incomplete or unexpected large-object stream was accepted")
		}
	}
}

func TestCTR06MetadataRejectsNestedDuplicateJSONKeys(t *testing.T) {
	for _, input := range []string{
		`{"a":1,"a":2}`,
		`{"a":[{"b":1,"b":2}]}`,
		`{"a":1} {"b":2}`,
		`{"a":[1,]}`,
	} {
		if err := ctr06UniqueJSON([]byte(input)); err == nil {
			t.Fatalf("ambiguous metadata accepted: %s", input)
		}
	}
	if err := ctr06UniqueJSON([]byte(`{"a":1,"b":[{"a":2},null]}`)); err != nil {
		t.Fatalf("valid metadata rejected: %v", err)
	}
}
