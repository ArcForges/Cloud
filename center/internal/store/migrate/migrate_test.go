// SPDX-License-Identifier: AGPL-3.0-only

package migrate

import (
	"errors"
	"strings"
	"testing"
	"testing/fstest"

	"github.com/ArcForges/Cloud/center/internal/schema"
)

func files(contents ...string) fstest.MapFS {
	directory := fstest.MapFS{}
	names := []string{"0001_first.sql", "0002_second.sql", "0003_third.sql", "0004_fourth.sql"}
	for index, content := range contents {
		directory[names[index]] = &fstest.MapFile{Data: []byte(content)}
	}
	return directory
}

func TestTheCenterMigrationsLoad(t *testing.T) {
	migrations, err := Load(schema.Migrations())
	if err != nil {
		t.Fatal(err)
	}
	if migrations[0].Name != "0001_platform_store.sql" || len(migrations[0].SHA256) != 64 {
		t.Fatalf("unexpected first migration %s %s", migrations[0].Name, migrations[0].SHA256)
	}
}

func TestLoadRequiresANumberedSequence(t *testing.T) {
	cases := map[string]fstest.MapFS{
		"gap":       {"0001_a.sql": {Data: []byte("SELECT 1;")}, "0003_c.sql": {Data: []byte("SELECT 1;")}},
		"zero":      {"0000_a.sql": {Data: []byte("SELECT 1;")}},
		"name":      {"0001_A.sql": {Data: []byte("SELECT 1;")}},
		"extension": {"0001_a.sql": {Data: []byte("SELECT 1;")}, "README.md": {Data: []byte("x")}},
		"empty":     {"0001_a.sql": {Data: []byte(" \n\t")}},
		"none":      {},
		"directory": {"0001_a.sql/x": {Data: []byte("SELECT 1;")}},
	}
	for name, directory := range cases {
		if _, err := Load(directory); err == nil {
			t.Errorf("%s: Load accepted it", name)
		}
	}
}

func TestLineEndingsDoNotChangeTheChecksum(t *testing.T) {
	lf, err := Load(files("CREATE TABLE a (x int);\nCREATE TABLE b (y int);\n"))
	if err != nil {
		t.Fatal(err)
	}
	crlf, err := Load(files("CREATE TABLE a (x int);\r\nCREATE TABLE b (y int);\r\n"))
	if err != nil {
		t.Fatal(err)
	}
	if lf[0].SHA256 != crlf[0].SHA256 || lf[0].SQL != crlf[0].SQL {
		t.Fatal("a CRLF checkout changes the checksum")
	}
}

func TestCompareRefusesEditedRemovedAndAheadRecords(t *testing.T) {
	build, err := Load(files("SELECT 1;", "SELECT 2;", "SELECT 3;"))
	if err != nil {
		t.Fatal(err)
	}
	record := func(versions ...int) []Applied {
		applied := []Applied{}
		for _, version := range versions {
			migration := build[version-1]
			applied = append(applied, Applied{Version: version, Name: migration.Name, SHA256: migration.SHA256})
		}
		return applied
	}
	if comparison := Compare(build, record(1)); len(comparison.Problems) != 0 || len(comparison.Pending) != 2 {
		t.Fatalf("pending: %+v", comparison)
	}
	if comparison := Compare(build, record(1, 2, 3)); len(comparison.Problems) != 0 || len(comparison.Pending) != 0 {
		t.Fatalf("current: %+v", comparison)
	}
	edited := record(1, 2)
	edited[1].SHA256 = strings.Repeat("0", 64)
	removed := []Applied{record(1)[0], record(1, 2, 3)[2]}
	ahead := append(record(1, 2, 3), Applied{Version: 4, Name: "0004_fourth.sql", SHA256: strings.Repeat("1", 64)})
	renamed := record(1, 2)
	renamed[1].Name = "0002_other.sql"
	for name, applied := range map[string][]Applied{"edited": edited, "removed": removed, "ahead": ahead, "renamed": renamed} {
		comparison := Compare(build, applied)
		if len(comparison.Problems) == 0 || len(comparison.Pending) != 0 {
			t.Errorf("%s: %+v", name, comparison)
		}
	}
	if problem := Compare(build, edited).Problems[0]; !strings.Contains(problem, "was edited") {
		t.Errorf("edited: %s", problem)
	}
	if problem := Compare(build, removed).Problems[0]; !strings.Contains(problem, "removed") {
		t.Errorf("removed: %s", problem)
	}
	if problem := Compare(build, ahead).Problems[0]; !strings.Contains(problem, "ahead") {
		t.Errorf("ahead: %s", problem)
	}
}

func TestRoleNames(t *testing.T) {
	for _, name := range []string{"arcforges_center_runtime", "arcforges_acceptance_runtime", "abc"} {
		if err := ValidRoleName(name); err != nil {
			t.Errorf("%s: %v", name, err)
		}
	}
	for _, name := range []string{"", "ab", "Runtime", "pg_runtime", "neondb_owner", "postgres", "public", "a-b", strings.Repeat("a", 42), "1abc"} {
		if err := ValidRoleName(name); err == nil {
			t.Errorf("%s was accepted", name)
		}
	}
}

func TestFailureNeverCarriesTheDetail(t *testing.T) {
	failure := &Failure{Version: 2, Name: "0002_second.sql", SQLState: "23505", Message: "duplicate key value violates unique constraint \"x\""}
	if !strings.Contains(failure.Error(), "0002_second.sql") || !strings.Contains(failure.Error(), "23505") {
		t.Fatal(failure.Error())
	}
	if err := Sanitize("op", errors.New("password=secret")); strings.Contains(err.Error(), "secret") {
		t.Fatal("a non-database error leaked its text")
	}
}
