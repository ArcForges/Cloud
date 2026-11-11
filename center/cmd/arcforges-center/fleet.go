// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"log/slog"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/ArcForges/Cloud/center/internal/arc"
	"github.com/ArcForges/Cloud/center/internal/config"
	"github.com/ArcForges/Cloud/center/internal/correlation"
	"github.com/ArcForges/Cloud/center/internal/device"
	"github.com/ArcForges/Cloud/center/internal/fleet"
	"github.com/ArcForges/Cloud/center/internal/fleetapi"
	"github.com/ArcForges/Cloud/center/internal/observe"
	"github.com/ArcForges/Cloud/center/internal/platform"
	"github.com/ArcForges/Cloud/center/internal/store"
	"github.com/ArcForges/Cloud/center/internal/store/migrate"
)

// The fleet admin commands (AF-CTR-04 E1a): the registration and retirement of the center's public signing keys (Q6: registration
// here, generation and custody in AF-CTR-05) and the operator's release of a node ID (Q21: the revocation of a node's device).

// maxKeyFile bounds a public key file (a PEM or DER SubjectPublicKeyInfo is a few hundred bytes).
const maxKeyFile = 16 * 1024

// fleetFlags reads `--name value` or `--name=value` pairs: every name must be one of allowed, once; a value is never empty.
func fleetFlags(rest []string, allowed ...string) (map[string]string, bool) {
	values := map[string]string{}
	for index := 0; index < len(rest); index++ {
		name, value, inline := strings.Cut(rest[index], "=")
		if !inline {
			if index+1 >= len(rest) {
				return nil, false
			}
			index++
			value = rest[index]
		}
		known := false
		for _, candidate := range allowed {
			known = known || candidate == name
		}
		if _, twice := values[name]; !known || twice || value == "" {
			return nil, false
		}
		values[name] = value
	}
	return values, true
}

func uuidFlag(value string) (platform.ID, bool) {
	var id platform.ID
	raw := correlation.IDBytes(value)
	if len(raw) != len(id) {
		return platform.ID{}, false
	}
	copy(id[:], raw)
	return id, id.String() == value && id != platform.ID{}
}

// fleetAdmin runs one fleet admin command with the migration role in one transaction and prints its result as JSON.
func fleetAdmin(sub string, rest []string, lookup func(string) (string, bool), stdout, stderr io.Writer) int {
	logger := observe.NewLogger(stderr, slog.LevelInfo).With("command", "admin "+sub)
	var run func(ctx context.Context, tx pgx.Tx, now time.Time) (map[string]any, error)
	var ok bool
	switch sub {
	case "register-signing-key":
		run, ok = registerSigningKey(rest)
	case "inspect-signing-key":
		run, ok = inspectSigningKey(rest)
	case "retire-signing-key":
		run, ok = retireSigningKey(rest)
	case "revoke-device":
		run, ok = revokeDevice(rest)
	}
	if !ok {
		_, _ = io.WriteString(stderr, usage)
		return exitUsage
	}
	cfg, err := config.LoadMigration(lookup)
	if err != nil {
		logger.Error("the command refused to start", "error", err.Error())
		return exitFailure
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	ctx, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()
	conn, err := connect(ctx, cfg.URL)
	if err != nil {
		logger.Error("the command could not connect", "error", err.Error())
		return exitFailure
	}
	defer func() { _ = conn.Close(context.Background()) }()
	now := time.Now().UTC().Truncate(time.Microsecond)
	var result map[string]any
	options := pgx.TxOptions{}
	if sub == "register-signing-key" {
		// Each statement after the registration lock must see the last committed writer, even if the server default differs.
		options.IsoLevel = pgx.ReadCommitted
	}
	err = pgx.BeginTxFunc(ctx, conn, options, func(tx pgx.Tx) error {
		if err := migrate.RequireOrdinaryDatabase(ctx, tx, cfg.Database); err != nil {
			return err
		}
		var err error
		result, err = run(ctx, tx, now)
		return err
	})
	if err != nil {
		var refused *refusal
		if errors.As(err, &refused) {
			logger.Error("the command was refused", "error", refused.Error())
			return exitFailure
		}
		logger.Error("the command failed", "error", store.Sanitize(sub, err).Error())
		return exitFailure
	}
	_ = json.NewEncoder(stdout).Encode(result)
	logger.Info("done")
	return exitOK
}

// refusal is a command's own refusal, safe to print (it names no row value).
type refusal struct{ reason string }

func (r *refusal) Error() string { return r.reason }

func auditOperator(ctx context.Context, tx pgx.Tx, now time.Time, eventType, targetKind, targetID string, payload map[string]any) error {
	data, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	_, err = platform.AppendAudit(ctx, tx, platform.Event{EventID: platform.NewID(), OccurredAt: now, ActorRef: "operator:cli", EventType: eventType,
		TargetKind: targetKind, TargetID: targetID, Payload: data})
	return err
}

func purposeOf(name string) (platform.KeyPurpose, bool) {
	switch name {
	case "command":
		return platform.CommandSigning, true
	case "entitlement":
		return platform.EntitlementToken, true
	}
	return 0, false
}

func purposeName(purpose platform.KeyPurpose) string {
	if purpose == platform.EntitlementToken {
		return "entitlement"
	}
	return "command"
}

// registerSigningKey is `admin register-signing-key` (CTR4-KEY-04, Q6): it records the public half of a key whose private half lives
// in the platform secret the binding names (generated and held by AF-CTR-05's custody, never by this command), with the rotation
// rules of platform.RegisterKey (ES256 P-256, at most 400 days, a successor valid at least 7 days before the current keys expire),
// audited fleet.signing_key.registered. Nodes receive it with their next sign-in or refresh, a successor before it signs.
func registerSigningKey(rest []string) (func(ctx context.Context, tx pgx.Tx, now time.Time) (map[string]any, error), bool) {
	flags, ok := fleetFlags(rest, "--purpose", "--kid", "--public-key-file", "--secret-binding", "--not-before", "--not-after")
	if !ok || len(flags) != 6 {
		return nil, false
	}
	purpose, ok := purposeOf(flags["--purpose"])
	notBefore, beforeErr := time.Parse(time.RFC3339, flags["--not-before"])
	notAfter, afterErr := time.Parse(time.RFC3339, flags["--not-after"])
	if !ok || beforeErr != nil || afterErr != nil {
		return nil, false
	}
	return func(ctx context.Context, tx pgx.Tx, now time.Time) (map[string]any, error) {
		file, err := os.Open(flags["--public-key-file"])
		if err != nil {
			return nil, &refusal{"the public key file cannot be read"}
		}
		defer func() { _ = file.Close() }()
		data, err := io.ReadAll(io.LimitReader(file, maxKeyFile+1))
		if err != nil || len(data) > maxKeyFile {
			return nil, &refusal{"the public key file cannot be read or is too large"}
		}
		if block, _ := pem.Decode(data); block != nil {
			if block.Type != "PUBLIC KEY" {
				return nil, &refusal{"the PEM file holds no PUBLIC KEY block"}
			}
			data = block.Bytes
		}
		key := platform.SigningKey{KID: flags["--kid"], Purpose: purpose, Algorithm: "ES256", PublicKey: data, SecretBinding: flags["--secret-binding"],
			NotBefore: notBefore.UTC(), NotAfter: notAfter.UTC()}
		proof := strings.HasPrefix(key.SecretBinding, "ARCFORGES_CENTER_KEY_PROOF_")
		if proof {
			suffix := strings.TrimPrefix(key.KID, "proof-")
			_, decodeErr := hex.DecodeString(suffix)
			if purpose != platform.CommandSigning || !strings.HasPrefix(key.KID, "proof-") || len(suffix) != 32 ||
				suffix != strings.ToLower(suffix) || decodeErr != nil ||
				key.SecretBinding != "ARCFORGES_CENTER_KEY_PROOF_"+strings.ToUpper(suffix) {
				return nil, &refusal{"the proof command key metadata is invalid"}
			}
		}
		// Every supported command or entitlement registration takes the same lock before reading either published set.
		// READ COMMITTED makes the read after a wait observe the previous writer; a stale-snapshot transaction is refused.
		if _, err = tx.Exec(ctx, "LOCK TABLE fleet.signing_key IN SHARE ROW EXCLUSIVE MODE"); err != nil {
			return nil, err
		}
		var isolation string
		if err = tx.QueryRow(ctx, "SHOW transaction_isolation").Scan(&isolation); err != nil {
			return nil, err
		}
		if isolation != "read committed" {
			return nil, &refusal{"signing key registration requires read committed isolation"}
		}
		proofBytes, proofLimit, err := fleetapi.SigningKeyReplyBudget(ctx, tx, now, key)
		if err != nil {
			return nil, err
		}
		if proofBytes > proofLimit {
			return nil, &refusal{"the signing key would exceed the node-credential reply budget"}
		}

		if err = platform.RegisterKey(ctx, tx, key, now); err != nil {
			var storeErr *store.Error
			if errors.As(err, &storeErr) {
				return nil, err
			}
			return nil, &refusal{err.Error()}
		}
		result := map[string]any{"kid": key.KID, "purpose": purposeName(purpose), "notBefore": key.NotBefore.Format(time.RFC3339),
			"notAfter": key.NotAfter.Format(time.RFC3339), "fingerprint": fleet.Fingerprint(key.PublicKey)}
		if proof {
			result["proofReplyBytes"], result["proofReplyLimit"] = proofBytes, proofLimit
		}
		return result, auditOperator(ctx, tx, now, "fleet.signing_key.registered", "signing_key", key.KID, result)
	}, true
}

// inspectSigningKey returns public metadata only, including retired rows, without changing the registry. The complete SHA-256
// of the public DER lets an operator reconcile a registration whose reply was lost without relying on a truncated fingerprint.
func inspectSigningKey(rest []string) (func(ctx context.Context, tx pgx.Tx, now time.Time) (map[string]any, error), bool) {
	flags, ok := fleetFlags(rest, "--kid")
	if !ok || len(flags) != 1 || flags["--kid"] == "" {
		return nil, false
	}
	return func(ctx context.Context, tx pgx.Tx, _ time.Time) (map[string]any, error) {
		key, found, err := platform.FindSigningKey(ctx, tx, flags["--kid"])
		if err != nil {
			return nil, err
		}
		if !found {
			return map[string]any{"found": false}, nil
		}
		purpose := "unknown"
		switch key.Purpose {
		case platform.CommandSigning:
			purpose = "command"
		case platform.EntitlementToken:
			purpose = "entitlement"
		case platform.RelayHMAC:
			purpose = "relay"
		}
		result := map[string]any{"found": true, "kid": key.KID, "purpose": purpose, "algorithm": key.Algorithm,
			"secretBinding": key.SecretBinding, "notBefore": key.NotBefore.UTC().Format(time.RFC3339),
			"notAfter": key.NotAfter.UTC().Format(time.RFC3339), "retiredAt": nil}
		if key.RetiredAt != nil {
			result["retiredAt"] = key.RetiredAt.UTC().Format(time.RFC3339)
		}
		if key.PublicKey != nil {
			digest := sha256.Sum256(key.PublicKey)
			result["publicSha256"] = hex.EncodeToString(digest[:])
			result["fingerprint"] = fleet.Fingerprint(key.PublicKey)
		}
		return result, nil
	}, true
}

// retireSigningKey is `admin retire-signing-key` (Q6): the key is retired at the instant (now by default), so it is no longer
// published or valid; an emergency retirement may leave the purpose without a valid key, which the result reports (validKeys).
func retireSigningKey(rest []string) (func(ctx context.Context, tx pgx.Tx, now time.Time) (map[string]any, error), bool) {
	flags, ok := fleetFlags(rest, "--kid", "--at")
	if !ok || flags["--kid"] == "" {
		return nil, false
	}
	var at *time.Time
	if text, present := flags["--at"]; present {
		parsed, err := time.Parse(time.RFC3339, text)
		if err != nil {
			return nil, false
		}
		parsed = parsed.UTC()
		at = &parsed
	}
	return func(ctx context.Context, tx pgx.Tx, now time.Time) (map[string]any, error) {
		when := now
		if at != nil {
			if at.Before(now.Add(-time.Minute)) {
				return nil, &refusal{"a retirement is never backdated"}
			}
			when = *at
		}
		key, err := platform.RetireKey(ctx, tx, flags["--kid"], when)
		if errors.Is(err, platform.ErrKeyNotRetirable) {
			return nil, &refusal{err.Error()}
		}
		if err != nil {
			return nil, err
		}
		valid, err := platform.ValidKeys(ctx, tx, key.Purpose, when)
		if err != nil {
			return nil, err
		}
		result := map[string]any{"kid": key.KID, "purpose": purposeName(key.Purpose), "retiredAt": when.Format(time.RFC3339), "validKeys": len(valid)}
		return result, auditOperator(ctx, tx, now, "fleet.signing_key.retired", "signing_key", key.KID, result)
	}, true
}

// revokeDevice is `admin revoke-device` (Q21, cloud-15 item 6), the operator's release of a node ID that another account holds: the
// device (named directly, or as the device of the node ID's live enrollment) is revoked by the operator with the full cascade
// (installations, every session whatever its scope, the node rows), the account locked first as the step-up evidence path and
// admin revoke-sessions do (the global order of docs/center-fleet.md), audited
// device.revoked with the actor operator:cli. The node ID is then free; the revoked installation keeps holding its key.
func revokeDevice(rest []string) (func(ctx context.Context, tx pgx.Tx, now time.Time) (map[string]any, error), bool) {
	flags, ok := fleetFlags(rest, "--device", "--node")
	if !ok || len(flags) != 1 {
		return nil, false
	}
	byNode := flags["--node"] != ""
	id, ok := uuidFlag(flags["--device"] + flags["--node"])
	if !ok {
		return nil, false
	}
	return func(ctx context.Context, tx pgx.Tx, now time.Time) (map[string]any, error) {
		var userID, deviceID platform.ID
		var err error
		if byNode {
			err = tx.QueryRow(ctx, "SELECT user_id, device_id FROM fleet.node WHERE node_id = $1 AND revoked_at IS NULL", id).Scan(&userID, &deviceID)
		} else {
			deviceID = id
			err = tx.QueryRow(ctx, "SELECT user_id FROM device.device WHERE device_id = $1 AND revoked_at IS NULL", id).Scan(&userID)
		}
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, &refusal{"no live device or node has this ID"}
		}
		if err != nil {
			return nil, err
		}
		if _, err = tx.Exec(ctx, "SELECT 1 FROM identity.user WHERE user_id = $1 FOR UPDATE", userID); err != nil {
			return nil, err
		}
		cascade, err := device.Revoke(ctx, tx, userID, deviceID, device.RevokedByOperator, []device.Participant{fleet.NodeParticipant{}}, now)
		var refused *arc.Refusal
		if errors.As(err, &refused) {
			return nil, &refusal{"the device is no longer live"}
		}
		if err != nil {
			return nil, err
		}
		payload := map[string]any{"own": false, "installations": cascade.Installations, "sessions": cascade.Sessions, "participants": cascade.Participants}
		if err = auditOperator(ctx, tx, now, "device.revoked", "device", deviceID.String(), payload); err != nil {
			return nil, err
		}
		return map[string]any{"device": deviceID.String(), "account": userID.String(), "installations": cascade.Installations, "sessions": cascade.Sessions,
			"participants": cascade.Participants}, nil
	}, true
}
