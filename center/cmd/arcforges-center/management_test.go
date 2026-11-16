// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/ArcForges/Cloud/center/internal/config"
	"github.com/ArcForges/Cloud/center/internal/pgtest"
	"github.com/ArcForges/Cloud/center/internal/schema"
	"github.com/ArcForges/Cloud/center/internal/store/migrate"
)

func TestManagementFlagsRefuseBeforeReadingDatabaseConfiguration(t *testing.T) {
	for _, args := range [][]string{nil, {"--force"}, {"--archive", "relative", "--metadata", "relative"}, {"--archive", "one", "--archive", "two"}} {
		var stdout, stderr bytes.Buffer
		lookup := func(string) (string, bool) { t.Fatal("invalid flags reached configuration"); return "", false }
		arguments := append([]string{"migrate", "management"}, args...)
		if code := run(arguments, lookup, &stdout, &stderr); code != exitUsage || stdout.Len() != 0 || stderr.Len() == 0 {
			t.Fatalf("invalid flag boundary: code=%d", code)
		}
	}
}

func TestManagementCLIUsesTheRealMigrationBoundary(t *testing.T) {
	for _, version := range []int{10, 11} {
		t.Run(strconv.Itoa(version), func(t *testing.T) {
			ctx := context.Background()
			url, name := pgtest.Database(t)
			owner := pgtest.Connect(t, url)
			group := name + "_runtime"
			build, err := migrate.Load(schema.Migrations())
			if err != nil {
				t.Fatal(err)
			}
			if _, err := migrate.Apply(ctx, owner, build[:version], migrate.Options{Runner: "isolated-cli-source", RuntimeRole: group}); err != nil {
				t.Fatal(err)
			}
			values := map[string]string{config.EnvMode: string(config.SelfHosted), config.EnvMigrationDatabaseURL: url, config.EnvRuntimeRole: group}
			lookup := func(key string) (string, bool) { value, found := values[key]; return value, found }
			dir := t.TempDir()
			var stdout, stderr bytes.Buffer
			code := run([]string{"migrate", "management", "--archive", filepath.Join(dir, "source.dump"), "--metadata", filepath.Join(dir, "source.json")}, lookup, &stdout, &stderr)
			if strings.Contains(stdout.String(), url) || strings.Contains(stderr.String(), url) {
				t.Fatal("CLI exposed a migration credential")
			}

			var result migrate.Result
			if code != exitOK || stderr.Len() != 0 || json.Unmarshal(stdout.Bytes(), &result) != nil || result.Version != 12 || result.RuntimeRole == group || result.Grants != "reconciled" {
				t.Fatalf("valid11 CLI result: code=%d", code)
			}
		})
	}
}
