// SPDX-License-Identifier: AGPL-3.0-only

package provision

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/ArcForges/Cloud/center/internal/pgtest"
	"github.com/ArcForges/Cloud/center/internal/schema"
	"github.com/ArcForges/Cloud/center/internal/store/migrate"
	"github.com/jackc/pgx/v5"
)

func TestCTR06HistoricalPreparationIssuesNewLeastPrivilegeCredentialWithoutChangingOldSlots(t *testing.T) {
	ctx := context.Background()
	url, name := pgtest.Database(t)
	owner := pgtest.Connect(t, url)
	build, err := migrate.Load(schema.Migrations())
	if err != nil {
		t.Fatal(err)
	}
	var grants []schema.Grant
	for _, g := range schema.RuntimeGrants {
		if g.Schema == "fleet" && (g.Table == "routed_file_call" || g.Table == "routed_command_id" || g.Table == "routed_file_target") {
			continue
		}
		grants = append(grants, g)
	}
	legacy := name + "_runtime"
	if _, err := migrate.Apply(ctx, owner, build[:10], migrate.Options{RuntimeRole: legacy, Grants: grants, Schemas: schema.Schemas}); err != nil {
		t.Fatal(err)
	}
	old, err := Rotate(ctx, owner, Options{Group: legacy, DirectURL: url})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Confirm(ctx, owner, legacy, old.Slot); err != nil {
		t.Fatal(err)
	}
	prepared, err := prepareCTR06BridgeHistorical(ctx, owner, build, Options{Group: legacy, DirectURL: url, Runner: "test"})
	if err != nil {
		t.Fatal(err)
	}
	if prepared.BridgeRole == legacy || prepared.BridgeLogin == old.LoginRole || len(prepared.Nonce) != 64 ||
		!prepared.Probe.ConnectsUnpooled || !prepared.Probe.ConnectedAsLogin || !prepared.Probe.CannotCreate || !prepared.Probe.CannotReadUngranted {
		t.Fatalf("bridge preparation did not prove least privilege: %+v", prepared.Probe)
	}
	encoded, err := json.Marshal(prepared)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(encoded), prepared.RuntimeURL) || strings.Contains(string(encoded), passwordOf(prepared.RuntimeURL)) {
		t.Fatal("runtime credential was serialized")
	}
	var role string
	var retained bool
	if err := owner.QueryRow(ctx, "SELECT login_role,promoted_at IS NOT NULL FROM platform.runtime_credential WHERE slot=$1", old.Slot).Scan(&role, &retained); err != nil ||
		role != old.LoginRole || !retained {
		t.Fatalf("old rotation slot changed: %s %v %v", role, retained, err)
	}
	bridge := pgtest.Connect(t, prepared.RuntimeURL)
	var active bool
	if err := bridge.QueryRow(ctx, "SELECT current_user=$1 AND has_table_privilege(current_user,'fleet.routed_call','INSERT')", prepared.BridgeLogin).Scan(&active); err != nil || !active {
		t.Fatalf("prepared login lacks schema10 grants: %v %v", active, err)
	}
	var noTable bool
	if err := owner.QueryRow(ctx, "SELECT to_regclass('platform.ctr06_bridge_prepared') IS NULL").Scan(&noTable); err != nil || !noTable {
		t.Fatalf("preparation created an unversioned business table: %v %v", noTable, err)
	}
}

func TestCTR06HistoricalPreparationWithdrawsOnlyRolesCreatedInThatFailedCall(t *testing.T) {
	ctx := context.Background()
	url, name := pgtest.Database(t)
	owner := pgtest.Connect(t, url)
	build, err := migrate.Load(schema.Migrations())
	if err != nil {
		t.Fatal(err)
	}
	var grants []schema.Grant
	for _, g := range schema.RuntimeGrants {
		if g.Schema == "fleet" && (g.Table == "routed_file_call" || g.Table == "routed_command_id" || g.Table == "routed_file_target") {
			continue
		}
		grants = append(grants, g)
	}
	legacy := name + "_runtime"
	if _, err := migrate.Apply(ctx, owner, build[:10], migrate.Options{RuntimeRole: legacy, Grants: grants, Schemas: schema.Schemas}); err != nil {
		t.Fatal(err)
	}
	other := name + "_c06_other"
	if _, err := owner.Exec(ctx, "CREATE ROLE "+pgx.Identifier{other}.Sanitize()+" LOGIN"); err != nil {
		t.Fatal(err)
	}
	if _, err := owner.Exec(ctx, "GRANT INSERT ON fleet.routed_call TO "+pgx.Identifier{other}.Sanitize()); err != nil {
		t.Fatal(err)
	}
	previous := newPassword
	newPassword = func() (string, error) { return "", errors.New("injected failure after role grant") }
	defer func() { newPassword = previous }()
	if _, err := prepareCTR06BridgeHistorical(ctx, owner, build, Options{Group: legacy, DirectURL: url, Runner: "test"}); err == nil {
		t.Fatal("injected preparation failure was accepted")
	}
	var unrelated, bad int
	if err := owner.QueryRow(ctx, `SELECT
 (SELECT count(*) FROM pg_roles WHERE rolname=$1 AND rolcanlogin AND has_table_privilege(oid,'fleet.routed_call','INSERT')),
 (SELECT count(*) FROM pg_roles WHERE rolname LIKE $2 AND rolname<>$1 AND
  (rolcanlogin OR has_table_privilege(oid,'fleet.routed_call','INSERT') OR has_table_privilege(oid,'fleet.hub_lease','UPDATE')))`,
		other, name+"_c06_%").Scan(&unrelated, &bad); err != nil || unrelated != 1 || bad != 0 {
		t.Fatalf("same-call withdrawal touched another role or left a writer: unrelated=%d failed=%d err=%v", unrelated, bad, err)
	}
}

func TestCTR06Phase1CredentialEntriesRefuseBeforeConnection(t *testing.T) {
	ctx := context.Background()
	if _, err := PrepareCTR06Bridge(ctx, nil, nil, Options{}); !errors.Is(err, migrate.ErrCTR06SecurityBridgeUnbound) {
		t.Fatalf("prepare did not refuse before using a connection: %v", err)
	}
	if _, err := CompleteIssuedCTR06Bridge(ctx, nil, nil, Options{}, migrate.PreparedBridgeRoles{}); !errors.Is(err, migrate.ErrCTR06SecurityBridgeUnbound) {
		t.Fatalf("completion did not refuse before using a connection: %v", err)
	}
}
