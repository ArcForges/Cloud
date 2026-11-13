// SPDX-License-Identifier: AGPL-3.0-only

package migrate

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/ArcForges/Cloud/center/internal/bridgeproof"
	"github.com/ArcForges/Cloud/center/internal/config"
	"github.com/jackc/pgx/v5"
)

const (
	// This is the executable extracted from the verified, released 615.1 OCI
	// carrier. The Windows binary is a separate reproducible native build from
	// the reviewed 8e5 source, not an executable shipped in that OCI release.
	localBridgeLinuxAMD64   = "028223a3dcbcbd6d7724558de02409e1e8874d876049f03fed38f47998773ba4"
	localBridgeWindowsAMD64 = "646338cd9bcfe0fcd0411abbf4fb036fc739b4a586d739c8a9fe58d9ff654f46"
)

type localBridgeAdmission struct {
	conn         *pgx.Conn
	binding      bridgeproof.Context
	finalRole    string
	runner       string
	binaryDigest string
	publicDigest string
	ready        bool
}

func (a *localBridgeAdmission) validFor(conn *pgx.Conn, role, runner string) bool {
	return a != nil && a.ready && a.conn == conn && a.finalRole == role && a.runner == runner
}

// CTR06LocalCredential configures the roles just created within the same
// manager call and returns their private URL. This function supplies no proof
// or success claim. The manager independently authenticates, starts and stops
// the pinned bridge, then performs the 0011 database fence itself.
type CTR06LocalCredential func(context.Context, PreparedBridgeRoles) (string, error)

// ApplySelfHostedCTR06 upgrades an existing schema-10 self-hosted database.
// Only this same call can create the unexported migration admission. It never
// accepts an operator-supplied proof, boolean or role marker as evidence.
// prepare must be the program's credential issuer, and the bridge credential
// is supplied only to the verified child through its private environment.
// The migration owner and the local OS account running this manager are trust
// boundaries; another process with that account's access must not inspect or
// change the manager or its child.
func ApplySelfHostedCTR06(ctx context.Context, conn *pgx.Conn, build []Migration, options Options, bridgePath string, prepare CTR06LocalCredential) (result Result, finalErr error) {
	if err := RequireCTR06SecurityBridge(); err != nil {
		return Result{State: StateRefused}, err
	}
	if prepare == nil || options.BridgeProof != nil || bridgePath == "" {
		return result, ErrCTR06RetirementUnproven
	}
	options.defaults()
	bridge, err := openLocalBridge(bridgePath)
	if err != nil {
		return result, err
	}
	defer bridge.close()
	return applySelfHostedCTR06(ctx, conn, build, options, bridge, prepare)
}

// applySelfHostedCTR06 accepts only a held, verified executable opened by the
// current manager. Legacy restore uses the very same object for pre-0011
// administration and the actual temporary bridge service.
func applySelfHostedCTR06(ctx context.Context, conn *pgx.Conn, build []Migration, options Options, bridge *localBridgeExecutable, prepare CTR06LocalCredential) (result Result, finalErr error) {
	if bridge == nil || prepare == nil || options.BridgeProof != nil {
		return result, ErrCTR06RetirementUnproven
	}
	options.defaults()
	if len(build) < 11 || build[9].Name != "0010_fleet_routed_call.sql" || build[10].Name != "0011_fleet_routed_files.sql" {
		return result, ErrCTR06RetirementUnproven
	}
	if err := lock(ctx, conn, options); err != nil {
		return result, err
	}
	defer unlock(conn)
	applied, exists, err := ReadApplied(ctx, conn)
	if err != nil || !exists || len(applied) != 10 {
		return result, ErrCTR06RetirementUnproven
	}
	compared := Compare(build[:10], applied)
	if len(compared.Pending) != 0 || len(compared.Problems) != 0 {
		return result, ErrCTR06RetirementUnproven
	}
	roles, err := prepareCTR06Roles(ctx, conn, options.RuntimeRole, options.localRestore)
	if err != nil {
		return result, err
	}
	// This invocation alone created these exact OIDs. On failure it may
	// withdraw their privileges; a later invocation must never infer ownership
	// from the public comment. A hard interruption instead fails closed.
	defer func() {
		if finalErr != nil {
			if err := withdrawLocalIssued(conn, roles); err != nil {
				finalErr = errors.Join(finalErr, errors.New("withdrawal of the roles created in this call failed"))
			}
		}
	}()
	prepareContext := ctx
	var restoreGrant *ctr06RestoreBridgeGrant
	if options.localRestore != nil {
		restoreGrant = &ctr06RestoreBridgeGrant{restore: options.localRestore, roles: roles, active: true}
		defer func() { restoreGrant.active = false }()
		prepareContext = context.WithValue(ctx, ctr06RestoreBridgeGrantKey{}, restoreGrant)
	}
	runtimeURL, err := prepare(prepareContext, roles)
	if restoreGrant != nil {
		restoreGrant.active = false
	}
	if err != nil {
		return result, err
	}
	pool, err := config.RuntimeDatabasePool(runtimeURL, config.SelfHosted, 1)
	if err != nil || pool.ConnConfig.User != roles.BridgeLogin || pool.ConnConfig.Database != roles.DatabaseName ||
		!strings.EqualFold(pool.ConnConfig.Host, conn.Config().Host) || pool.ConnConfig.Port != conn.Config().Port {
		return result, ErrCTR06RetirementUnproven
	}
	if err := waitLocalConnections(ctx, conn, roles.BridgeLoginOID, false); err != nil {
		return result, fmt.Errorf("before local bridge start: %w", err)
	}
	if err := runLocalBridge(ctx, conn, bridge, runtimeURL, roles.BridgeLoginOID); err != nil {
		return result, fmt.Errorf("local bridge run: %w", err)
	}
	// Do not retain the private credential in the migration admission.
	runtimeURL = ""
	// The issued name has a fixed "_c06_" plus 16 hex suffix. Preserve
	// its full randomness while keeping the final group within the existing
	// runtime role length limit.
	marker := len(roles.BridgeRole) - len("_c06_") - 16
	if marker < 0 || roles.BridgeRole[marker:marker+len("_c06_")] != "_c06_" {
		return result, ErrCTR06RetirementUnproven
	}
	finalRole := roles.BridgeRole[:marker] + "_n06_" + roles.BridgeRole[marker+len("_c06_"):]
	binding := bridgeproof.Context{
		DatabaseHost: strings.ToLower(conn.Config().Host), DatabasePort: conn.Config().Port,
		DatabaseName: roles.DatabaseName, ClusterSystemIdentifier: roles.ClusterSystemIdentifier, DatabaseOID: roles.DatabaseOID, OwnerOID: roles.OwnerOID,
		LegacyRole: roles.LegacyRole, LegacyRoleOID: roles.LegacyRoleOID,
		BridgeRole: roles.BridgeRole, BridgeRoleOID: roles.BridgeRoleOID,
		BridgeLogin: roles.BridgeLogin, BridgeLoginOID: roles.BridgeLoginOID, Nonce: roles.Nonce,
		WorkflowRevision: options.Runner,
	}
	public := strings.Join([]string{
		"ArcForges CTR06 local bridge v2", runtime.GOOS, runtime.GOARCH, bridge.digest,
		binding.DatabaseHost, strconv.Itoa(int(binding.DatabasePort)), binding.DatabaseName, binding.ClusterSystemIdentifier,
		strconv.FormatUint(uint64(binding.DatabaseOID), 10), strconv.FormatUint(uint64(binding.OwnerOID), 10),
		binding.LegacyRole, strconv.FormatUint(uint64(binding.LegacyRoleOID), 10),
		binding.BridgeRole, strconv.FormatUint(uint64(binding.BridgeRoleOID), 10),
		binding.BridgeLogin, strconv.FormatUint(uint64(binding.BridgeLoginOID), 10),
		binding.Nonce, finalRole, options.Runner,
	}, "\n")
	digest := sha256.Sum256([]byte(public))
	admission := &localBridgeAdmission{conn: conn, binding: binding, finalRole: finalRole, runner: options.Runner,
		binaryDigest: bridge.digest, publicDigest: hex.EncodeToString(digest[:]), ready: true}
	defer func() { admission.ready = false }()
	options.RuntimeRole = finalRole
	options.localBridge = admission
	return Apply(ctx, conn, build, options)
}

// waitLocalConnections counts actual PostgreSQL backend identities, not
// application_name or a self-reported process ID. A surviving backend refuses
// the upgrade, including one retained by a pooler.
func waitLocalConnections(ctx context.Context, conn *pgx.Conn, loginOID uint32, want bool) error {
	deadline := time.Now().Add(10 * time.Second)
	for {
		var exists bool
		err := conn.QueryRow(ctx, "SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE usesysid=$1::oid)", loginOID).Scan(&exists)
		if err != nil {
			return ErrCTR06RetirementUnproven
		}
		if exists == want {
			return nil
		}
		if time.Now().After(deadline) {
			return ErrCTR06RetirementUnproven
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(100 * time.Millisecond):
		}
	}
}

func runLocalBridge(ctx context.Context, conn *pgx.Conn, bridge *localBridgeExecutable, runtimeURL string, loginOID uint32) error {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return ErrCTR06RetirementUnproven
	}
	adminAddress := listener.Addr().String()
	if err := listener.Close(); err != nil {
		return ErrCTR06RetirementUnproven
	}
	cmd := exec.Command(bridge.path, "serve")
	cmd.ExtraFiles = bridge.extraFiles
	cmd.Env = []string{
		config.EnvMode + "=self-hosted", config.EnvPublicBaseURL + "=http://127.0.0.1:1",
		config.EnvDatabaseURL + "=" + runtimeURL, config.EnvDatabaseMaxConns + "=1",
		config.EnvHTTPAddress + "=127.0.0.1:0", config.EnvGRPCAddress + "=off",
		config.EnvAdminAddress + "=" + adminAddress, config.EnvSurfaces + "=none",
		config.EnvMetricsLogInterval + "=0",
	}
	if runtime.GOOS == "windows" {
		cmd.Env = append(cmd.Env, "SystemRoot="+os.Getenv("SystemRoot"))
	}
	cmd.Stdout, cmd.Stderr = io.Discard, io.Discard
	if err := cmd.Start(); err != nil {
		return ErrCTR06RetirementUnproven
	}
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	stopped := false
	defer func() {
		if !stopped {
			_ = cmd.Process.Kill()
			<-done
		}
	}()
	client := &http.Client{Timeout: time.Second, Transport: &http.Transport{},
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	defer client.CloseIdleConnections()
	deadline := time.Now().Add(15 * time.Second)
	for {
		select {
		case <-done:
			stopped = true
			return ErrCTR06RetirementUnproven
		default:
		}
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://"+adminAddress+"/readyz", nil)
		if err != nil {
			return ErrCTR06RetirementUnproven
		}
		response, err := client.Do(req)
		if err == nil {
			var state struct {
				Status     string            `json:"status"`
				Components map[string]string `json:"components"`
			}
			err = decodeBoundedReadiness(response.Body, &state)
			_ = response.Body.Close()
			if err == nil && response.StatusCode == http.StatusOK && state.Status == "ready" &&
				state.Components["database"] == "ready" && state.Components["databaseSchema"] == "ready" {
				break
			}
		}
		if time.Now().After(deadline) {
			return ErrCTR06RetirementUnproven
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(100 * time.Millisecond):
		}
	}
	if err := waitLocalConnections(ctx, conn, loginOID, true); err != nil {
		return fmt.Errorf("bridge database connection was not observed: %w", err)
	}
	if err := cmd.Process.Kill(); err != nil {
		return ErrCTR06RetirementUnproven
	}
	<-done
	stopped = true
	if err := waitLocalConnections(ctx, conn, loginOID, false); err != nil {
		return fmt.Errorf("bridge database connection remained after stop: %w", err)
	}
	return nil
}

func withdrawLocalIssued(conn *pgx.Conn, roles PreparedBridgeRoles) error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	return pgx.BeginFunc(ctx, conn, func(tx pgx.Tx) error {
		var exact bool
		err := tx.QueryRow(ctx, "SELECT EXISTS(SELECT 1 FROM pg_roles WHERE oid=$1 AND rolname=$2) AND EXISTS(SELECT 1 FROM pg_roles WHERE oid=$3 AND rolname=$4)",
			roles.BridgeRoleOID, roles.BridgeRole, roles.BridgeLoginOID, roles.BridgeLogin).Scan(&exact)
		if err != nil || !exact {
			return ErrCTR06RetirementUnproven
		}
		return revokeLocalBridge(ctx, tx, roles.DatabaseName, roles.BridgeRole, roles.BridgeLogin)
	})
}

func localArtifactDigest() (string, error) {
	switch runtime.GOOS + "/" + runtime.GOARCH {
	case "linux/amd64":
		return localBridgeLinuxAMD64, nil
	case "windows/amd64":
		return localBridgeWindowsAMD64, nil
	default:
		return "", fmt.Errorf("%w: no verified native bridge for this platform", ErrCTR06RetirementUnproven)
	}
}
