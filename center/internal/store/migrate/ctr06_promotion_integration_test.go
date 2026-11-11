// SPDX-License-Identifier: AGPL-3.0-only

package migrate

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/ArcForges/Cloud/center/internal/bridgeproof"
	"github.com/ArcForges/Cloud/center/internal/pgtest"
	"github.com/ArcForges/Cloud/center/internal/platform"
	"github.com/ArcForges/Cloud/center/internal/store"
	"github.com/jackc/pgx/v5"
)

type ctr06RoundTrip func(*http.Request) (*http.Response, error)

func (f ctr06RoundTrip) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

// The transport substitutes only the owner-only OIDC provider. Real RSA
// signatures, all claim checks and all PostgreSQL privileges run unchanged.
func ctr06SignedProof(t *testing.T, owner *pgx.Conn, legacy, group, login, nonce string) (*bridgeproof.Verified, bridgeproof.Context) {
	t.Helper()
	return ctr06SignedProofForCluster(t, owner, legacy, group, login, nonce, "")
}

func ctr06SignedProofForCluster(t *testing.T, owner *pgx.Conn, legacy, group, login, nonce, signedCluster string) (*bridgeproof.Verified, bridgeproof.Context) {
	t.Helper()
	ctx := context.Background()
	var dbOID, ownerOID, oldOID, groupOID, loginOID uint32
	var db, cluster string
	err := owner.QueryRow(ctx, `SELECT d.oid,d.datdba,d.datname,(SELECT system_identifier::text FROM pg_catalog.pg_control_system()),
 (SELECT oid FROM pg_roles WHERE rolname=$1),(SELECT oid FROM pg_roles WHERE rolname=$2),(SELECT oid FROM pg_roles WHERE rolname=$3)
FROM pg_database d WHERE datname=current_database()`, legacy, group, login).Scan(&dbOID, &ownerOID, &db, &cluster, &oldOID, &groupOID, &loginOID)
	if err != nil {
		t.Fatal(store.Sanitize("read proof bindings", err))
	}
	binding := bridgeproof.Context{
		Environment: "production", DatabaseHost: strings.ToLower(owner.Config().Host), DatabasePort: owner.Config().Port,
		DatabaseName: db, ClusterSystemIdentifier: cluster, DatabaseOID: dbOID, OwnerOID: ownerOID,
		LegacyRole: legacy, LegacyRoleOID: oldOID, BridgeRole: group, BridgeRoleOID: groupOID, BridgeLogin: login, BridgeLoginOID: loginOID,
		Nonce: nonce, WorkflowRevision: strings.Repeat("b", 40), CloudAccount: strings.Repeat("c", 32),
		WorkerName: "arcforges-cloud", WorkerVersion: "00000000-0000-4000-8000-000000000001",
		ContainerApplication: "00000000-0000-4000-8000-000000000002",
		RegistryImage:        "registry.cloudflare.com/" + strings.Repeat("c", 32) + "/arcforges-cloud@" + bridgeproof.BridgeImageID,
	}
	if signedCluster != "" {
		binding.ClusterSystemIdentifier = signedCluster
	}
	audience, err := binding.Audience()
	if err != nil {
		t.Fatal(err)
	}
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	b64 := base64.RawURLEncoding.EncodeToString
	now := time.Now()
	claims := map[string]any{
		"iss": "https://token.actions.githubusercontent.com", "sub": "repo:ArcForges/Cloud:environment:cloudflare",
		"aud": audience, "iat": now.Unix(), "nbf": now.Unix(), "exp": now.Add(5 * time.Minute).Unix(),
		"repository": "ArcForges/Cloud", "ref": "refs/heads/main", "sha": binding.WorkflowRevision,
		"environment": "cloudflare", "event_name": "push",
		"workflow_ref": "ArcForges/Cloud/.github/workflows/ci.yml@refs/heads/main", "workflow_sha": binding.WorkflowRevision,
	}
	header, _ := json.Marshal(map[string]any{"alg": "RS256", "kid": "local-owner-transport", "typ": "JWT"})
	payload, _ := json.Marshal(claims)
	message := b64(header) + "." + b64(payload)
	hash := sha256.Sum256([]byte(message))
	sig, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, hash[:])
	if err != nil {
		t.Fatal(err)
	}
	jwks, _ := json.Marshal(map[string]any{"keys": []any{map[string]any{"kty": "RSA", "use": "sig", "alg": "RS256",
		"kid": "local-owner-transport", "n": b64(key.N.Bytes()), "e": b64([]byte{1, 0, 1})}}})
	previous := http.DefaultTransport
	http.DefaultTransport = ctr06RoundTrip(func(request *http.Request) (*http.Response, error) {
		if request.URL.String() != "https://token.actions.githubusercontent.com/.well-known/jwks" {
			return nil, errors.New("unexpected provider request")
		}
		return &http.Response{StatusCode: http.StatusOK, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(string(jwks))), Request: request}, nil
	})
	defer func() { http.DefaultTransport = previous }()
	verified, err := bridgeproof.VerifyGitHub(ctx, message+"."+b64(sig), binding, now)
	if err != nil {
		t.Fatal(err)
	}
	return verified, binding
}

func TestCTR06PromotedBridgeRetiresExistingRoleAndHandsOffLease(t *testing.T) {
	ctx := context.Background()
	url, name, owner, build := legacyGateFixture(t)
	legacy := name + "_runtime"
	oldLogin := legacy + "_a"
	schemas10, grants10 := schemasAndGrantsAt(10)
	if _, err := apply(t, url, build[:10], Options{RuntimeRole: legacy, Schemas: schemas10, Grants: grants10}); err != nil {
		t.Fatal(err)
	}
	roles, err := PrepareCTR06Roles(ctx, owner, legacy)
	if err != nil {
		t.Fatal(err)
	}
	group, bridgeLogin := roles.BridgeRole, roles.BridgeLogin
	if _, err := apply(t, url, build[:10], Options{RuntimeRole: group, Schemas: schemas10, Grants: grants10}); err != nil {
		t.Fatal(err)
	}
	password, bridgePassword := pgtest.Secret(), pgtest.Secret()
	for _, s := range []string{
		"CREATE ROLE " + pgx.Identifier{oldLogin}.Sanitize() + " LOGIN PASSWORD '" + password + "'",
		"GRANT " + pgx.Identifier{legacy}.Sanitize() + " TO " + pgx.Identifier{oldLogin}.Sanitize(),
		"ALTER ROLE " + pgx.Identifier{bridgeLogin}.Sanitize() + " LOGIN PASSWORD '" + bridgePassword + "'",
		"GRANT " + pgx.Identifier{group}.Sanitize() + " TO " + pgx.Identifier{bridgeLogin}.Sanitize(),
	} {
		if _, err := owner.Exec(ctx, s); err != nil {
			t.Fatal(store.Sanitize("prepare old and bridge role", err))
		}
	}
	if _, err := owner.Exec(ctx, `INSERT INTO platform.runtime_credential(slot,login_role,rotated_at,rotated_by,promoted_at)
VALUES('a',$1,now(),'old',now())`, oldLogin); err != nil {
		t.Fatal(err)
	}
	old := pgtest.Connect(t, pgtest.WithUser(t, url, oldLogin, password))
	bridge := pgtest.Connect(t, pgtest.WithUser(t, url, bridgeLogin, bridgePassword))
	f := seedNamespaceFixture(t, owner)
	command, oldHolder := platform.NewID(), platform.NewID()
	if err := insertNamespace(ctx, old, f, command, false, 1, 10, false); err != nil {
		t.Fatal(err)
	}
	if _, err := old.Exec(ctx, `INSERT INTO fleet.hub_lease(singleton,holder,fence,acquired_at,renewed_at,expires_at)
VALUES(true,$1,1,clock_timestamp(),clock_timestamp(),clock_timestamp()+interval '1 hour')`, oldHolder); err != nil {
		t.Fatal(err)
	}
	proof, binding := ctr06SignedProof(t, owner, legacy, group, bridgeLogin, roles.Nonce)
	result, err := apply(t, url, build, Options{Runner: binding.WorkflowRevision, RuntimeRole: group, BridgeProof: proof})
	if err != nil || result.Version != 11 {
		t.Fatalf("promoted 0011: %+v %v", result, err)
	}
	var preserved, retired bool
	err = owner.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM platform.ctr06_legacy_runtime_credential WHERE slot='a' AND login_role=$1),
 EXISTS(SELECT 1 FROM platform.ctr06_runtime_floor WHERE runtime_role=$2 AND legacy_role=$3 AND promotion_digest IS NOT NULL)`, oldLogin, group, legacy).Scan(&preserved, &retired)
	if err != nil || !preserved || !retired {
		t.Fatalf("floor and history: %v %v %v", preserved, retired, err)
	}
	requireNamespaceCode(t, insertNamespace(ctx, old, f, platform.NewID(), false, 1, 10, false), "42501", "")
	if _, err := old.Exec(ctx, "UPDATE fleet.hub_lease SET expires_at=clock_timestamp()+interval '1 hour' WHERE singleton"); err == nil {
		t.Fatal("old open session renewed its lease")
	}
	newHolder := platform.NewID()
	tag, err := bridge.Exec(ctx, `UPDATE fleet.hub_lease SET holder=$1,fence=fence+1,acquired_at=clock_timestamp(),
renewed_at=clock_timestamp(),expires_at=clock_timestamp()+interval '1 minute' WHERE singleton AND expires_at<=clock_timestamp()`, newHolder)
	if err != nil || tag.RowsAffected() != 1 {
		t.Fatalf("bridge could not take expired lease: %v", store.Sanitize("handoff lease", err))
	}
	if err := insertNamespace(ctx, bridge, f, platform.NewID(), false, 1, 10, false); err != nil {
		t.Fatal(store.Sanitize("bridge receipt", err))
	}
	if _, err := apply(t, url, build, Options{RuntimeRole: legacy}); !errors.Is(err, ErrCTR06RetirementUnproven) {
		t.Fatalf("current migrator regranted legacy group: %v", err)
	}
}

func TestCTR06ForgedMarkerNeverTakesOverUnknownAdminOrOpenWriters(t *testing.T) {
	ctx := context.Background()
	url, name, owner, build := legacyGateFixture(t)
	legacy := name + "_runtime"
	schemas10, grants10 := schemasAndGrantsAt(10)
	if _, err := apply(t, url, build[:10], Options{RuntimeRole: legacy, Schemas: schemas10, Grants: grants10}); err != nil {
		t.Fatal(err)
	}
	roles, err := PrepareCTR06Roles(ctx, owner, legacy)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := apply(t, url, build[:10], Options{RuntimeRole: roles.BridgeRole, Schemas: schemas10, Grants: grants10}); err != nil {
		t.Fatal(err)
	}
	oldLogin, password, bridgePassword := legacy+"_a", pgtest.Secret(), pgtest.Secret()
	for _, statement := range []string{
		"CREATE ROLE " + pgx.Identifier{oldLogin}.Sanitize() + " LOGIN PASSWORD '" + password + "'",
		"GRANT " + pgx.Identifier{legacy}.Sanitize() + " TO " + pgx.Identifier{oldLogin}.Sanitize(),
		"ALTER ROLE " + pgx.Identifier{roles.BridgeLogin}.Sanitize() + " LOGIN PASSWORD '" + bridgePassword + "'",
		"GRANT " + pgx.Identifier{roles.BridgeRole}.Sanitize() + " TO " + pgx.Identifier{roles.BridgeLogin}.Sanitize(),
	} {
		if _, err := owner.Exec(ctx, statement); err != nil {
			t.Fatal(store.Sanitize("prepare known roles", err))
		}
	}
	old := pgtest.Connect(t, pgtest.WithUser(t, url, oldLogin, password))

	// This unrelated role uses the same prefix and a self-filled marker. It
	// has CREATEROLE, an ADMIN membership and an already-open connection.
	admin := pgtest.Admin(t)
	foreignGroup, foreignLogin, foreignPassword := name+"_c06_foreign", name+"_c06_foreign_a", pgtest.Secret()
	for _, statement := range []string{
		"CREATE ROLE " + pgx.Identifier{foreignGroup}.Sanitize() + " NOLOGIN",
		"CREATE ROLE " + pgx.Identifier{foreignLogin}.Sanitize() + " LOGIN CREATEROLE PASSWORD '" + foreignPassword + "'",
		"GRANT " + pgx.Identifier{foreignGroup}.Sanitize() + " TO " + pgx.Identifier{foreignLogin}.Sanitize() + " WITH ADMIN TRUE",
	} {
		if _, err := admin.Exec(ctx, statement); err != nil {
			t.Fatal(store.Sanitize("prepare unknown admin", err))
		}
	}
	for _, statement := range []string{
		"GRANT CONNECT ON DATABASE " + pgx.Identifier{name}.Sanitize() + " TO " + pgx.Identifier{foreignGroup}.Sanitize(),
		"GRANT USAGE ON SCHEMA fleet TO " + pgx.Identifier{foreignGroup}.Sanitize(),
		"GRANT INSERT ON fleet.routed_call TO " + pgx.Identifier{foreignGroup}.Sanitize(),
	} {
		if _, err := owner.Exec(ctx, statement); err != nil {
			t.Fatal(store.Sanitize("grant unknown writer", err))
		}
	}
	var foreignGroupOID, foreignLoginOID uint32
	if err := admin.QueryRow(ctx, "SELECT (SELECT oid FROM pg_roles WHERE rolname=$1),(SELECT oid FROM pg_roles WHERE rolname=$2)", foreignGroup, foreignLogin).Scan(&foreignGroupOID, &foreignLoginOID); err != nil {
		t.Fatal(err)
	}
	fake := bridgeRoleMarker(roles.DatabaseOID, roles.OwnerOID, roles.LegacyRoleOID, foreignGroupOID, foreignLoginOID, strings.Repeat("f", 64))
	for _, role := range []string{foreignGroup, foreignLogin} {
		if _, err := admin.Exec(ctx, "COMMENT ON ROLE "+pgx.Identifier{role}.Sanitize()+" IS '"+fake+"'"); err != nil {
			t.Fatal(err)
		}
	}
	foreign := pgtest.Connect(t, pgtest.WithUser(t, url, foreignLogin, foreignPassword))
	fixture := seedNamespaceFixture(t, owner)
	if err := insertNamespace(ctx, foreign, fixture, platform.NewID(), false, 1, 10, false); err != nil {
		t.Fatal(store.Sanitize("unknown writer before gate", err))
	}
	proof, binding := ctr06SignedProof(t, owner, legacy, roles.BridgeRole, roles.BridgeLogin, roles.Nonce)
	if _, err := apply(t, url, build, Options{Runner: binding.WorkflowRevision, RuntimeRole: roles.BridgeRole, BridgeProof: proof}); !errors.Is(err, ErrCTR06RetirementUnproven) {
		t.Fatalf("unknown writer was adopted or retired: %v", err)
	}
	// Its old connection and same credential still write; no LOGIN, ADMIN,
	// CREATEROLE, membership or legacy permissions were silently changed.
	if err := insertNamespace(ctx, foreign, fixture, platform.NewID(), false, 1, 10, false); err != nil {
		t.Fatal(store.Sanitize("unknown writer after refused gate", err))
	}
	again := pgtest.Connect(t, pgtest.WithUser(t, url, foreignLogin, foreignPassword))
	if err := insertNamespace(ctx, again, fixture, platform.NewID(), false, 1, 10, false); err != nil {
		t.Fatal(store.Sanitize("unknown credential after refusal", err))
	}
	if err := insertNamespace(ctx, old, fixture, platform.NewID(), false, 1, 10, false); err != nil {
		t.Fatal(store.Sanitize("legacy connection after refusal", err))
	}
	var valid, absent bool
	err = owner.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM pg_roles r JOIN pg_auth_members m ON m.member=r.oid JOIN pg_roles g ON g.oid=m.roleid
WHERE r.rolname=$1 AND r.rolcanlogin AND r.rolcreaterole AND g.rolname=$2 AND m.admin_option),
to_regclass('fleet.routed_file_call') IS NULL`, foreignLogin, foreignGroup).Scan(&valid, &absent)
	if err != nil || !valid || !absent {
		t.Fatalf("unknown role or rollback changed: %v %v %v", valid, absent, err)
	}
}

func TestCTR06UnknownLegacySlotOrMemberIsNeverRetired(t *testing.T) {
	for _, kind := range []string{"same_slot_name", "unknown_group_member"} {
		t.Run(kind, func(t *testing.T) {
			ctx := context.Background()
			url, name, owner, build := legacyGateFixture(t)
			legacy := name + "_runtime"
			schemas10, grants10 := schemasAndGrantsAt(10)
			if _, err := apply(t, url, build[:10], Options{RuntimeRole: legacy, Schemas: schemas10, Grants: grants10}); err != nil {
				t.Fatal(err)
			}
			roles, err := PrepareCTR06Roles(ctx, owner, legacy)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := apply(t, url, build[:10], Options{RuntimeRole: roles.BridgeRole, Schemas: schemas10, Grants: grants10}); err != nil {
				t.Fatal(err)
			}
			bridgePassword, outsiderPassword := pgtest.Secret(), pgtest.Secret()
			for _, statement := range []string{
				"ALTER ROLE " + pgx.Identifier{roles.BridgeLogin}.Sanitize() + " LOGIN PASSWORD '" + bridgePassword + "'",
				"GRANT " + pgx.Identifier{roles.BridgeRole}.Sanitize() + " TO " + pgx.Identifier{roles.BridgeLogin}.Sanitize(),
			} {
				if _, err := owner.Exec(ctx, statement); err != nil {
					t.Fatal(store.Sanitize("prepare bridge role", err))
				}
			}
			outsider := legacy + "_b"
			if kind == "unknown_group_member" {
				outsider = name + "_unrelated"
			}
			if _, err := owner.Exec(ctx, "CREATE ROLE "+pgx.Identifier{outsider}.Sanitize()+" LOGIN PASSWORD '"+outsiderPassword+"'"); err != nil {
				t.Fatal(store.Sanitize("create unrelated login", err))
			}
			if kind == "same_slot_name" {
				for _, statement := range []string{
					"GRANT CONNECT ON DATABASE " + pgx.Identifier{name}.Sanitize() + " TO " + pgx.Identifier{outsider}.Sanitize(),
					"GRANT USAGE ON SCHEMA fleet TO " + pgx.Identifier{outsider}.Sanitize(),
					"GRANT INSERT ON fleet.routed_call TO " + pgx.Identifier{outsider}.Sanitize(),
				} {
					if _, err := owner.Exec(ctx, statement); err != nil {
						t.Fatal(store.Sanitize("grant unrelated writer", err))
					}
				}
			} else if _, err := owner.Exec(ctx, "GRANT "+pgx.Identifier{legacy}.Sanitize()+" TO "+pgx.Identifier{outsider}.Sanitize()); err != nil {
				t.Fatal(store.Sanitize("grant unrelated membership", err))
			}
			connection := pgtest.Connect(t, pgtest.WithUser(t, url, outsider, outsiderPassword))
			fixture := seedNamespaceFixture(t, owner)
			if err := insertNamespace(ctx, connection, fixture, platform.NewID(), false, 1, 10, false); err != nil {
				t.Fatal(store.Sanitize("unrelated writer before gate", err))
			}
			proof, binding := ctr06SignedProof(t, owner, legacy, roles.BridgeRole, roles.BridgeLogin, roles.Nonce)
			if _, err := apply(t, url, build, Options{Runner: binding.WorkflowRevision, RuntimeRole: roles.BridgeRole, BridgeProof: proof}); !errors.Is(err, ErrCTR06RetirementUnproven) {
				t.Fatalf("unrelated role was accepted: %v", err)
			}
			if err := insertNamespace(ctx, connection, fixture, platform.NewID(), false, 1, 10, false); err != nil {
				t.Fatal(store.Sanitize("unrelated writer after refusal", err))
			}
			again := pgtest.Connect(t, pgtest.WithUser(t, url, outsider, outsiderPassword))
			if err := insertNamespace(ctx, again, fixture, platform.NewID(), false, 1, 10, false); err != nil {
				t.Fatal(store.Sanitize("unrelated credential after refusal", err))
			}
		})
	}
}

// A remaining temporary-bridge backend must be visible to a non-superuser
// owner and rejected again under the 0011 write lock, even when PostgreSQL
// redacts backend_type. This exercises the real database predicate directly.
func TestCTR06SelfHostedFenceRejectsRemainingBridgeBackend(t *testing.T) {
	ctx := context.Background()
	url, name, owner, build := legacyGateFixture(t)
	legacy := name + "_runtime"
	schemas10, grants10 := schemasAndGrantsAt(10)
	if _, err := apply(t, url, build[:10], Options{RuntimeRole: legacy, Schemas: schemas10, Grants: grants10}); err != nil {
		t.Fatal(err)
	}
	roles, err := PrepareCTR06Roles(ctx, owner, legacy)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := apply(t, url, build[:10], Options{RuntimeRole: roles.BridgeRole, Schemas: schemas10, Grants: grants10}); err != nil {
		t.Fatal(err)
	}
	password := pgtest.Secret()
	for _, sql := range []string{
		"ALTER ROLE " + pgx.Identifier{roles.BridgeLogin}.Sanitize() + " LOGIN PASSWORD '" + password + "'",
		"GRANT " + pgx.Identifier{roles.BridgeRole}.Sanitize() + " TO " + pgx.Identifier{roles.BridgeLogin}.Sanitize(),
	} {
		if _, err := owner.Exec(ctx, sql); err != nil {
			t.Fatal(store.Sanitize("prepare temporary bridge", err))
		}
	}
	bridge := pgtest.Connect(t, pgtest.WithUser(t, url, roles.BridgeLogin, password))
	var observed, backendHidden bool
	err = owner.QueryRow(ctx, "SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE usesysid=$1::oid), EXISTS(SELECT 1 FROM pg_stat_activity WHERE usesysid=$1::oid AND backend_type IS NULL)", roles.BridgeLoginOID).Scan(&observed, &backendHidden)
	if err != nil || !observed || !backendHidden {
		t.Fatalf("non-superuser view: observed=%v backend-hidden=%v err=%v", observed, backendHidden, err)
	}
	tx, err := owner.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(context.Background()) }()
	if _, err := tx.Exec(ctx, "LOCK TABLE fleet.routed_call, fleet.hub_lease IN ACCESS EXCLUSIVE MODE"); err != nil {
		t.Fatal(err)
	}
	binding := bridgeproof.Context{
		DatabaseHost: strings.ToLower(owner.Config().Host), DatabasePort: owner.Config().Port,
		DatabaseName: roles.DatabaseName, ClusterSystemIdentifier: roles.ClusterSystemIdentifier, DatabaseOID: roles.DatabaseOID, OwnerOID: roles.OwnerOID,
		LegacyRole: roles.LegacyRole, LegacyRoleOID: roles.LegacyRoleOID,
		BridgeRole: roles.BridgeRole, BridgeRoleOID: roles.BridgeRoleOID,
		BridgeLogin: roles.BridgeLogin, BridgeLoginOID: roles.BridgeLoginOID, Nonce: roles.Nonce,
	}
	err = guardBoundBridge(ctx, tx, owner, binding, true)
	if !errors.Is(err, ErrCTR06RetirementUnproven) || !strings.Contains(err.Error(), "temporary bridge connection remains") {
		t.Fatalf("fence failed to identify remaining backend: %v", err)
	}
	if err := tx.Rollback(ctx); err != nil {
		t.Fatal(err)
	}
	// Refusal rolled back all retirements; this real backend is untouched.
	if _, err := bridge.Exec(ctx, "SELECT count(*) FROM fleet.hub_lease"); err != nil {
		t.Fatal(store.Sanitize("read after refused fence", err))
	}
}

func TestCTR06SignedOtherClusterProofCannotCrossThePGFence(t *testing.T) {
	ctx := context.Background()
	url, name, owner, build := legacyGateFixture(t)
	legacy := name + "_runtime"
	schemas10, grants10 := schemasAndGrantsAt(10)
	if _, err := apply(t, url, build[:10], Options{RuntimeRole: legacy, Schemas: schemas10, Grants: grants10}); err != nil {
		t.Fatal(err)
	}
	roles, err := PrepareCTR06Roles(ctx, owner, legacy)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := apply(t, url, build[:10], Options{RuntimeRole: roles.BridgeRole, Schemas: schemas10, Grants: grants10}); err != nil {
		t.Fatal(err)
	}
	for _, statement := range []string{
		"ALTER ROLE " + pgx.Identifier{roles.BridgeLogin}.Sanitize() + " LOGIN",
		"GRANT " + pgx.Identifier{roles.BridgeRole}.Sanitize() + " TO " + pgx.Identifier{roles.BridgeLogin}.Sanitize(),
	} {
		if _, err := owner.Exec(ctx, statement); err != nil {
			t.Fatal(err)
		}
	}
	wrong := "1"
	if roles.ClusterSystemIdentifier == wrong {
		wrong = "2"
	}
	proof, binding := ctr06SignedProofForCluster(t, owner, legacy, roles.BridgeRole, roles.BridgeLogin, roles.Nonce, wrong)
	if binding.ClusterSystemIdentifier == roles.ClusterSystemIdentifier {
		t.Fatal("signed test proof did not bind another cluster")
	}
	result, err := apply(t, url, build, Options{Runner: binding.WorkflowRevision, RuntimeRole: roles.BridgeRole, BridgeProof: proof})
	if !errors.Is(err, ErrCTR06RetirementUnproven) || !strings.Contains(err.Error(), "database identity") {
		t.Fatalf("signed proof for another real cluster identity crossed the fence: %+v %v", result, err)
	}
	var schema10, oldWritable, noFileSchema bool
	if err := owner.QueryRow(ctx, `SELECT (SELECT max(version)=10 FROM platform.schema_migration),
 has_table_privilege($1,'fleet.hub_lease','UPDATE'), to_regclass('platform.ctr06_runtime_floor') IS NULL`, legacy).
		Scan(&schema10, &oldWritable, &noFileSchema); err != nil || !schema10 || !oldWritable || !noFileSchema {
		t.Fatalf("wrong-cluster refusal changed schema or old privileges: %v %v %v %v", schema10, oldWritable, noFileSchema, err)
	}
	wrongPrepared := roles
	wrongPrepared.ClusterSystemIdentifier = wrong
	tx, err := owner.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(ctx)
	if err := ConfirmPreparedCTR06Roles(ctx, tx, wrongPrepared); !errors.Is(err, ErrCTR06RetirementUnproven) {
		t.Fatalf("prepared role context from another cluster was accepted: %v", err)
	}
}
