// SPDX-License-Identifier: AGPL-3.0-only

package provision

import (
	"context"
	"errors"
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

// rotator rotates and confirms the runtime credential of a migrated database as the deployment does.
type rotator struct {
	t          *testing.T
	url, group string
}

func (r rotator) rotate() Rotation {
	r.t.Helper()
	rotation, err := Rotate(context.Background(), pgtest.Connect(r.t, r.url), Options{Group: r.group, DirectURL: r.url, PooledHost: pgtest.Host(r.t), Runner: "test", ProbeTimeout: 10 * time.Second})
	if err != nil {
		r.t.Fatal(err)
	}
	probe := rotation.Probe
	if !probe.ConnectedAsLogin || !probe.ReadsGrantedTable || !probe.CannotCreate || !probe.CannotReadUngranted || !probe.CannotCreateTemporary {
		r.t.Fatalf("probe %+v", probe)
	}
	return rotation
}

func (r rotator) confirm(slot string) Confirmation {
	r.t.Helper()
	confirmation, err := Confirm(context.Background(), pgtest.Connect(r.t, r.url), r.group, slot)
	if err != nil {
		r.t.Fatal(err)
	}
	return confirmation
}

func TestPromotedRotationsAlternateSlotsAndKeepTheRunningCredential(t *testing.T) {
	url, group := migrated(t)
	r := rotator{t: t, url: url, group: group}
	first := r.rotate()
	r.confirm(first.Slot)
	second := r.rotate()
	if first.Slot != "a" || second.Slot != "b" || first.LoginRole != group+"_a" || second.LoginRole != group+"_b" {
		t.Fatalf("slots %s %s", first.Slot, second.Slot)
	}
	// The revision deployed with the first credential keeps working while the second deploys.
	if !connects(t, first.RuntimeURL) || !connects(t, second.RuntimeURL) {
		t.Fatal("a credential of the two latest rotations does not connect")
	}
	r.confirm(second.Slot)
	third := r.rotate()
	if third.Slot != "a" || connects(t, first.RuntimeURL) || !connects(t, second.RuntimeURL) || !connects(t, third.RuntimeURL) {
		t.Fatalf("third rotation: slot %s", third.Slot)
	}
	if !strings.Contains(third.RuntimeURL, "@"+pgtest.Host(t)) {
		t.Fatal("the runtime URL does not use the pooled host")
	}
}

// A deployment that fails after its rotation is retried: the retry rotates the unpromoted slot again and never the slot of the
// running revision, however often it fails.
func TestARetriedDeploymentNeverRotatesThePromotedSlot(t *testing.T) {
	url, group := migrated(t)
	r := rotator{t: t, url: url, group: group}
	live := r.rotate()
	r.confirm(live.Slot)
	failed := r.rotate()
	retried := r.rotate()
	again := r.rotate()
	if live.Slot != "a" || failed.Slot != "b" || retried.Slot != "b" || again.Slot != "b" {
		t.Fatalf("slots %s %s %s %s", live.Slot, failed.Slot, retried.Slot, again.Slot)
	}
	if !connects(t, live.RuntimeURL) {
		t.Fatal("a retried deployment broke the running revision's credential")
	}
	if connects(t, failed.RuntimeURL) || connects(t, retried.RuntimeURL) || !connects(t, again.RuntimeURL) {
		t.Fatal("the unpromoted slot keeps only its latest password")
	}
	r.confirm(again.Slot)
	next := r.rotate()
	if next.Slot != "a" || connects(t, live.RuntimeURL) || !connects(t, again.RuntimeURL) || !connects(t, next.RuntimeURL) {
		t.Fatalf("after the promotion of b: slot %s", next.Slot)
	}
}

func TestConfirmIsIdempotentAndRefusesUnknownSlots(t *testing.T) {
	url, group := migrated(t)
	r := rotator{t: t, url: url, group: group}
	conn := pgtest.Connect(t, url)
	for _, slot := range []string{"c", "", "A"} {
		if _, err := Confirm(context.Background(), conn, group, slot); !errors.Is(err, ErrUnknownSlot) {
			t.Fatalf("slot %q: %v", slot, err)
		}
	}
	// No slot was rotated yet, then only a.
	if _, err := Confirm(context.Background(), conn, group, "a"); !errors.Is(err, ErrUnknownSlot) {
		t.Fatalf("a before any rotation: %v", err)
	}
	rotation := r.rotate()
	if _, err := Confirm(context.Background(), conn, group, "b"); !errors.Is(err, ErrUnknownSlot) {
		t.Fatalf("b never rotated: %v", err)
	}
	first := r.confirm(rotation.Slot)
	second := r.confirm(rotation.Slot)
	if first.Already || !second.Already || first.PromotedAt == "" || second.PromotedAt != first.PromotedAt || first.LoginRole != group+"_a" {
		t.Fatalf("confirmations %+v %+v", first, second)
	}
	// Another runtime role's confirmation does not touch this database's slots.
	if _, err := Confirm(context.Background(), conn, group+"_other", "a"); err == nil {
		t.Fatal("a slot was confirmed for another runtime role")
	}
	// A new rotation of the slot clears its promotion.
	var promoted bool
	r.rotate() // b
	r.confirm("b")
	r.rotate() // a again
	if err := conn.QueryRow(context.Background(), "SELECT promoted_at IS NOT NULL FROM platform.runtime_credential WHERE slot = 'a'").Scan(&promoted); err != nil || promoted {
		t.Fatalf("a rotated slot kept its promotion: %v %v", promoted, err)
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

// The deployment names the live version's slot (read from Cloudflare): the rotation takes the other slot even when the record
// is behind the live revision (its promotion was never confirmed).
func TestARotationNeverTouchesTheLiveSlotItIsGiven(t *testing.T) {
	url, group := migrated(t)
	r := rotator{t: t, url: url, group: group}
	first := r.rotate()
	r.confirm(first.Slot)
	live := r.rotate() // b went live, but its confirmation was lost
	rotation, err := Rotate(context.Background(), pgtest.Connect(t, url), Options{Group: group, DirectURL: url, PooledHost: pgtest.Host(t), Runner: "test",
		ProbeTimeout: 10 * time.Second, LiveSlot: live.Slot})
	if err != nil {
		t.Fatal(err)
	}
	if live.Slot != "b" || rotation.Slot != "a" || rotation.SlotSource != "live-version" || !connects(t, live.RuntimeURL) {
		t.Fatalf("live %s rotated %s (%s)", live.Slot, rotation.Slot, rotation.SlotSource)
	}
	if _, err = Rotate(context.Background(), pgtest.Connect(t, url), Options{Group: group, DirectURL: url, LiveSlot: "c"}); !errors.Is(err, ErrUnknownSlot) {
		t.Fatalf("live slot c: %v", err)
	}
}

// A login role whose membership does not inherit (PostgreSQL 16 and later) is corrected by the rotation.
func TestARotationCorrectsANonInheritingMembership(t *testing.T) {
	url, group := migrated(t)
	conn := pgtest.Connect(t, url)
	ctx := context.Background()
	var version int
	if err := conn.QueryRow(ctx, "SELECT current_setting('server_version_num')::int").Scan(&version); err != nil || version < 160000 {
		t.Skipf("membership inherit options need PostgreSQL 16 (%d %v)", version, err)
	}
	login := group + "_a"
	for _, statement := range []string{
		"CREATE ROLE " + login + " LOGIN",
		"GRANT " + group + " TO " + login + " WITH INHERIT FALSE",
	} {
		if _, err := conn.Exec(ctx, statement); err != nil {
			t.Fatal(err)
		}
	}
	var inherits bool
	if err := conn.QueryRow(ctx, "SELECT pg_has_role($1, $2, 'USAGE')", login, group).Scan(&inherits); err != nil || inherits {
		t.Fatalf("the fixture membership inherits: %v", err)
	}
	r := rotator{t: t, url: url, group: group}
	if rotation := r.rotate(); rotation.Slot != "a" {
		t.Fatalf("slot %s", rotation.Slot)
	}
	if err := conn.QueryRow(ctx, "SELECT pg_has_role($1, $2, 'USAGE')", login, group).Scan(&inherits); err != nil || !inherits {
		t.Fatalf("the membership was not corrected: %v", err)
	}
}

// After a restore between two deployments the record can lack the live version's slot (here: live b, record a only). Confirming
// b is refused as unknown (this database's record has no row for the live slot, so it cannot be confirmed), and the rotation
// still never takes the live slot.
func TestARestoredRecordWithoutTheLiveSlot(t *testing.T) {
	url, group := migrated(t)
	r := rotator{t: t, url: url, group: group}
	r.confirm(r.rotate().Slot) // the record holds a only
	if _, err := Confirm(context.Background(), pgtest.Connect(t, url), group, "b"); !errors.Is(err, ErrUnknownSlot) {
		t.Fatalf("confirm b: %v", err)
	}
	rotation, err := Rotate(context.Background(), pgtest.Connect(t, url), Options{Group: group, DirectURL: url, PooledHost: pgtest.Host(t), Runner: "test",
		ProbeTimeout: 10 * time.Second, LiveSlot: "b"})
	if err != nil || rotation.Slot != "a" || rotation.SlotSource != "live-version" {
		t.Fatalf("rotation %+v %v", rotation, err)
	}
}
