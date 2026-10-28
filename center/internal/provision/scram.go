// SPDX-License-Identifier: AGPL-3.0-only

package provision

import (
	"context"
	"crypto/hmac"
	"crypto/pbkdf2"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"regexp"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/ArcForges/Cloud/center/internal/store/migrate"
)

// The forms in which a rotation sends the new password to the server.
const (
	// FormVerifier is a client-side SCRAM-SHA-256 verifier: PostgreSQL stores it as it is, and the password itself never leaves
	// the center.
	FormVerifier = "scram-sha-256-verifier"
	// FormNeonPlaintext is the password itself, which Neon requires: "Passwords must be supplied in plain text but are encrypted
	// when stored. Hashed passwords are not supported." (neon.com/docs/manage/roles).
	FormNeonPlaintext = "neon-plaintext"
)

// ScramIterations is the iteration count of the verifiers the center computes (PostgreSQL's default scram_iterations).
const ScramIterations = 4096

// passwordAlphabet is the alphabet of the generated passwords (base64url). SASLprep (RFC 4013) maps none of these characters
// and prohibits none, so it is the identity on them and the verifier needs no normalization.
var passwordAlphabet = regexp.MustCompile(`^[A-Za-z0-9_-]{1,128}$`)

// ScramVerifier returns the SCRAM-SHA-256 verifier of password in PostgreSQL's format,
// SCRAM-SHA-256$<iterations>:<salt>$<StoredKey>:<ServerKey> (standard base64): SaltedPassword is PBKDF2-HMAC-SHA-256 of the
// password, ClientKey and ServerKey are HMAC-SHA-256 of it with "Client Key" and "Server Key", and StoredKey is SHA-256 of the
// ClientKey (RFC 5802, RFC 7677).
func ScramVerifier(password string, salt []byte, iterations int) (string, error) {
	if !passwordAlphabet.MatchString(password) {
		return "", errors.New("the password is outside the alphabet on which SASLprep is the identity")
	}
	if len(salt) < 16 || iterations < ScramIterations {
		return "", errors.New("a verifier needs a salt of at least 16 bytes and at least 4096 iterations")
	}
	salted, err := pbkdf2.Key(sha256.New, password, salt, iterations, sha256.Size)
	if err != nil {
		return "", err
	}
	clientKey := keyed(salted, "Client Key")
	storedKey := sha256.Sum256(clientKey)
	serverKey := keyed(salted, "Server Key")
	encode := base64.StdEncoding.EncodeToString
	return fmt.Sprintf("SCRAM-SHA-256$%d:%s$%s:%s", iterations, encode(salt), encode(storedKey[:]), encode(serverKey)), nil
}

func keyed(key []byte, message string) []byte {
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte(message))
	return mac.Sum(nil)
}

// passwordSecret is the secret the role statement sets: on Neon the password itself (Neon does not support hashed passwords), on
// any other PostgreSQL a new SCRAM-SHA-256 verifier with a random 16-byte salt, so the password never leaves the center.
func passwordSecret(password string, neon bool) (secret, form string, err error) {
	if !passwordAlphabet.MatchString(password) {
		return "", "", errors.New("the password is outside the generated alphabet")
	}
	if neon {
		return password, FormNeonPlaintext, nil
	}
	salt := make([]byte, 16)
	if _, err = rand.Read(salt); err != nil {
		return "", "", err
	}
	if secret, err = ScramVerifier(password, salt, ScramIterations); err != nil {
		return "", "", err
	}
	return secret, FormVerifier, nil
}

// DefaultRoleLockTimeout bounds how long a rotation blocked on the login role's row (by another session) holds the migration
// lock: the secret-free role statement then fails cleanly. Its value does not matter for confidentiality, because the nested
// password statement cannot wait.
const DefaultRoleLockTimeout = 10 * time.Second

// takeRole creates or alters the login role without any secret (LOGIN, INHERIT and the connection limit only), with the lock
// timeout set before it. The role's catalog row is then this transaction's own, so the nested password statement that follows
// can never wait on a lock. Only these attributes are set: a CREATEROLE role (the Neon owner) may not name the superuser, replication or
// BYPASSRLS attributes at all.
func takeRole(ctx context.Context, tx pgx.Tx, login string, exists bool, connectionLimit int, lockTimeout time.Duration) error {
	if _, err := tx.Exec(ctx, fmt.Sprintf("SET LOCAL lock_timeout = %d", lockTimeout.Milliseconds())); err != nil {
		return migrate.Sanitize("bound the role lock", err)
	}
	verb := "ALTER"
	if !exists {
		verb = "CREATE"
	}
	statement := fmt.Sprintf("%s ROLE %s WITH LOGIN INHERIT CONNECTION LIMIT %d", verb, pgx.Identifier{login}.Sanitize(), connectionLimit)
	if _, err := tx.Exec(ctx, statement); err != nil {
		return migrate.Sanitize("take the login role "+login, err)
	}
	return nil
}

// The secret is in no statement text and no bind parameter: it is loaded with binary COPY (CopyData messages) into a temporary
// table that the transaction's commit drops, and a temporary PL/pgSQL function reads it and runs only `ALTER ROLE … PASSWORD`
// with EXECUTE, on the row takeRole already took. The nested statement does hold the secret. What holds:
//   - pg_stat_statements and pg_stat_monitor with track 'top' (the defaults) record top-level statements only; the rotation
//     refuses 'all', and log_parser_stats = on (migrate.Logging.CaptureRefusal);
//   - a caught error never quotes the statement: the handler (OTHERS OR query_canceled) re-raises with the SQLSTATE and a fixed
//     message only;
//   - a LOG message emitted while the statement runs would carry it as context; the known emitters are removed: the function
//     sets debug_print_parse, debug_print_rewritten and debug_print_plan off for its own execution, and the statement cannot
//     wait on a lock (no lock-wait message);
//   - a cancellation or termination during the statement can still log it, but that aborts the rotation's transaction: the role
//     keeps its old password, Neon's DDL forwarding (at pre-commit) never runs, no secret file is written, and the next rotation
//     draws a new password, so the logged value was never a working credential.
const (
	secretTable    = `CREATE TEMPORARY TABLE pg_temp.arcforges_login_secret (secret text NOT NULL) ON COMMIT DROP`
	setLoginSource = `CREATE OR REPLACE FUNCTION pg_temp.arcforges_set_login(role_name text)
RETURNS void LANGUAGE plpgsql
SET debug_print_parse = off SET debug_print_rewritten = off SET debug_print_plan = off
AS $function$
DECLARE
    stored text;
BEGIN
    SELECT s.secret INTO STRICT stored FROM pg_temp.arcforges_login_secret s;
    EXECUTE format('ALTER ROLE %I PASSWORD %L', role_name, stored);
EXCEPTION WHEN OTHERS OR query_canceled THEN
    RAISE EXCEPTION USING ERRCODE = SQLSTATE, MESSAGE = 'login role update failed';
END
$function$`
	setLoginCall = `SELECT pg_temp.arcforges_set_login($1)`
	setLoginDrop = `DROP FUNCTION pg_temp.arcforges_set_login(text)`
)

// setLogin sets the login role's secret in tx (the migration role's transaction, which owns the database and so keeps
// TEMPORARY), after takeRole.
func setLogin(ctx context.Context, tx pgx.Tx, login, secret string) error {
	if _, err := tx.Exec(ctx, secretTable); err != nil {
		return migrate.Sanitize("create the temporary secret table", err)
	}
	if _, err := tx.CopyFrom(ctx, pgx.Identifier{"pg_temp", "arcforges_login_secret"}, []string{"secret"}, pgx.CopyFromRows([][]any{{secret}})); err != nil {
		return migrate.Sanitize("load the secret", err)
	}
	if _, err := tx.Exec(ctx, setLoginSource); err != nil {
		return migrate.Sanitize("create the login role function", err)
	}
	if _, err := tx.Exec(ctx, setLoginCall, login); err != nil {
		return migrate.Sanitize("set the runtime credential of "+login, err)
	}
	if _, err := tx.Exec(ctx, setLoginDrop); err != nil {
		return migrate.Sanitize("drop the login role function", err)
	}
	return nil
}
