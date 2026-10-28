// SPDX-License-Identifier: AGPL-3.0-only

package provision

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/ArcForges/Cloud/center/internal/pgtest"
	"github.com/ArcForges/Cloud/center/internal/schema"
	"github.com/ArcForges/Cloud/center/internal/store/migrate"
)

func TestPasswords(t *testing.T) {
	seen := map[string]bool{}
	for range 200 {
		password, err := Password()
		if err != nil {
			t.Fatal(err)
		}
		if len(password) != 40 || tripled(password) || strings.ContainsAny(password, "'\\%@:/?#") || seen[password] {
			t.Fatalf("unexpected password shape %d", len(password))
		}
		seen[password] = true
	}
}

func TestPooledHosts(t *testing.T) {
	cases := map[string]string{
		"ep-cool-darkness-123456.us-east-2.aws.neon.tech":        "ep-cool-darkness-123456-pooler.us-east-2.aws.neon.tech",
		"ep-cool-darkness-123456-pooler.us-east-2.aws.neon.tech": "ep-cool-darkness-123456-pooler.us-east-2.aws.neon.tech",
		"db.example.org": "db.example.org",
		"127.0.0.1":      "127.0.0.1",
	}
	for direct, pooled := range cases {
		if got := PooledHost(direct); got != pooled {
			t.Errorf("%s: %s", direct, got)
		}
	}
	value, err := RuntimeURL("postgresql://owner:x@ep-a-1.eu-central-1.aws.neon.tech/neondb?sslmode=verify-full&channel_binding=require", "rt_a", "p-w_1", "")
	if err != nil || value != "postgresql://rt_a:p-w_1@ep-a-1-pooler.eu-central-1.aws.neon.tech/neondb?sslmode=verify-full&channel_binding=require" {
		t.Fatalf("%s %v", value, err)
	}
}

func migrated(t *testing.T) (url, group string) {
	t.Helper()
	url, name := pgtest.Database(t)
	group = name + "_runtime"
	build, err := migrate.Load(schema.Migrations())
	if err != nil {
		t.Fatal(err)
	}
	if _, err = migrate.Apply(context.Background(), pgtest.Connect(t, url), build, migrate.Options{Runner: "test", RuntimeRole: group}); err != nil {
		t.Fatal(err)
	}
	return url, group
}

func connects(t *testing.T, value string) bool {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	conn, err := pgx.Connect(ctx, value)
	if err != nil {
		return false
	}
	_ = conn.Close(ctx)
	return true
}

func TestRotationAlternatesSlotsAndKeepsThePreviousCredential(t *testing.T) {
	url, group := migrated(t)
	rotate := func() Rotation {
		t.Helper()
		rotation, err := Rotate(context.Background(), pgtest.Connect(t, url), Options{Group: group, DirectURL: url, PooledHost: pgtest.Host(t), Runner: "test", ProbeTimeout: 10 * time.Second})
		if err != nil {
			t.Fatal(err)
		}
		probe := rotation.Probe
		if !probe.ConnectedAsLogin || !probe.ReadsGrantedTable || !probe.CannotCreate || !probe.CannotReadUngranted {
			t.Fatalf("probe %+v", probe)
		}
		return rotation
	}
	first := rotate()
	second := rotate()
	if first.Slot != "a" || second.Slot != "b" || first.LoginRole != group+"_a" || second.LoginRole != group+"_b" {
		t.Fatalf("slots %s %s", first.Slot, second.Slot)
	}
	// The revision deployed with the first credential keeps working while the second deploys.
	if !connects(t, first.RuntimeURL) || !connects(t, second.RuntimeURL) {
		t.Fatal("a credential of the two latest rotations does not connect")
	}
	third := rotate()
	if third.Slot != "a" || connects(t, first.RuntimeURL) || !connects(t, second.RuntimeURL) || !connects(t, third.RuntimeURL) {
		t.Fatalf("third rotation: slot %s", third.Slot)
	}
	if strings.Contains(third.RuntimeURL, "@"+pgtest.Host(t)) == false {
		t.Fatal("the runtime URL does not use the pooled host")
	}
}

func TestRotationNeedsAMigratedDatabase(t *testing.T) {
	url, name := pgtest.Database(t)
	_, err := Rotate(context.Background(), pgtest.Connect(t, url), Options{Group: name + "_runtime", DirectURL: url, Runner: "test"})
	if err == nil || !strings.Contains(err.Error(), "migrate first") {
		t.Fatalf("an unmigrated database: %v", err)
	}
}

func TestEnsureDatabase(t *testing.T) {
	url, name := pgtest.Database(t)
	target := name + "_extra"
	t.Cleanup(func() { pgtest.Drop(t, target) })
	conn := pgtest.Connect(t, url)
	created, err := EnsureDatabase(context.Background(), conn, target)
	if err != nil || !created {
		t.Fatalf("create: %v %v", created, err)
	}
	if created, err = EnsureDatabase(context.Background(), conn, target); err != nil || created {
		t.Fatalf("again: %v %v", created, err)
	}
	for _, bad := range []string{"Bad", "postgres", "template1", "a-b", ""} {
		if _, err = EnsureDatabase(context.Background(), conn, bad); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
}
