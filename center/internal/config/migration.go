// SPDX-License-Identifier: AGPL-3.0-only

package config

import (
	"net/url"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

// The environment variables of `arcforges-center migrate` and `arcforges-center admin`. They are read only by those commands,
// never by serve: the running center has only the runtime role's pooled URL.
const (
	EnvMigrationDatabaseURL = "ARCFORGES_CENTER_MIGRATION_DATABASE_URL"
	EnvDatabaseName         = "ARCFORGES_CENTER_DATABASE_NAME"
	EnvRuntimeRole          = "ARCFORGES_CENTER_RUNTIME_ROLE"
	EnvRuntimeSecretFile    = "ARCFORGES_CENTER_RUNTIME_SECRET_FILE"
	EnvRuntimePooledHost    = "ARCFORGES_CENTER_RUNTIME_POOLED_HOST"
	EnvMigrationLockTimeout = "ARCFORGES_CENTER_MIGRATION_LOCK_TIMEOUT"
)

// DefaultRuntimeRole is the runtime group role when none is configured.
const DefaultRuntimeRole = "arcforges_center_runtime"

var (
	databaseName = regexp.MustCompile(`^[a-z][a-z0-9_]{0,62}$`)
	hostPort     = regexp.MustCompile(`^[a-z0-9.-]{1,253}(:[0-9]{1,5})?$`)
)

// Migration is the configuration of the migration and administration commands.
type Migration struct {
	Mode Mode
	// URL is the migration role's direct (unpooled) URL with the configured database; it is a credential and is never printed.
	URL string
	// Database is the database the center uses (the URL's, or ARCFORGES_CENTER_DATABASE_NAME).
	Database string
	// Maintenance is the URL with the URL's own database, from which `admin ensure-database` creates Database.
	Maintenance string
	// RuntimeRole is the runtime group role.
	RuntimeRole string
	// SecretFile is where `admin rotate-runtime-credential` writes the runtime URL (a new file, mode 0600).
	SecretFile string
	// PooledHost is host[:port] of the pooled endpoint; empty derives it (the Neon -pooler host, or the direct host).
	PooledHost  string
	LockTimeout time.Duration
}

// LoadMigration reads and validates the migration configuration. The URL must be a direct connection: a Neon pooler host is
// refused, because a transaction pooler cannot hold the migration lock or run DDL safely.
func LoadMigration(lookup func(string) (string, bool)) (Migration, error) {
	get := func(name string) string {
		value, _ := lookup(name)
		return value
	}
	var config Migration
	switch Mode(get(EnvMode)) {
	case OfficialHosted, SelfHosted:
		config.Mode = Mode(get(EnvMode))
	default:
		return Migration{}, invalid("%s must be %s or %s", EnvMode, OfficialHosted, SelfHosted)
	}
	refused := invalid("%s must be a direct (unpooled) postgres URL with a user and a database; TLS with verify-full and channel binding is required except for a loopback host of a self-hosted center", EnvMigrationDatabaseURL)
	value := get(EnvMigrationDatabaseURL)
	if value == "" || len(value) > 8192 {
		return Migration{}, refused
	}
	uri, err := url.Parse(value)
	if err != nil || (uri.Scheme != "postgresql" && uri.Scheme != "postgres") || uri.Fragment != "" || uri.Opaque != "" ||
		uri.User == nil || uri.User.Username() == "" || uri.Hostname() == "" || strings.Contains(uri.Hostname(), ",") ||
		len(uri.Path) < 2 || strings.Contains(uri.Path[1:], "/") || strings.Contains(uri.Hostname(), "-pooler.") {
		return Migration{}, refused
	}
	plaintext := uri.Query().Get("sslmode") == "disable"
	if plaintext && (config.Mode != SelfHosted || !isLoopbackHost(uri.Hostname())) {
		return Migration{}, refused
	}
	if !secureQuery(uri, !plaintext) {
		return Migration{}, refused
	}
	config.Maintenance = uri.String()
	config.Database = uri.Path[1:]
	if name := get(EnvDatabaseName); name != "" {
		if !databaseName.MatchString(name) || name == "postgres" || strings.HasPrefix(name, "template") {
			return Migration{}, invalid("%s must be a lowercase database name", EnvDatabaseName)
		}
		config.Database = name
	}
	if !databaseName.MatchString(config.Database) {
		return Migration{}, invalid("the database of %s must be a lowercase name", EnvMigrationDatabaseURL)
	}
	uri.Path = "/" + config.Database
	config.URL = uri.String()
	config.RuntimeRole = get(EnvRuntimeRole)
	if config.RuntimeRole == "" {
		config.RuntimeRole = DefaultRuntimeRole
	}
	if config.RuntimeRole == uri.User.Username() {
		return Migration{}, invalid("%s must not be the migration role", EnvRuntimeRole)
	}
	if config.SecretFile = get(EnvRuntimeSecretFile); config.SecretFile != "" && !filepath.IsAbs(config.SecretFile) {
		return Migration{}, invalid("%s must be an absolute path", EnvRuntimeSecretFile)
	}
	if config.PooledHost = get(EnvRuntimePooledHost); config.PooledHost != "" && !hostPort.MatchString(config.PooledHost) {
		return Migration{}, invalid("%s must be host or host:port", EnvRuntimePooledHost)
	}
	config.LockTimeout = 2 * time.Minute
	if value := get(EnvMigrationLockTimeout); value != "" {
		timeout, err := time.ParseDuration(value)
		if err != nil || timeout < time.Second || timeout > time.Hour {
			return Migration{}, invalid("%s must be a duration from 1s to 1h", EnvMigrationLockTimeout)
		}
		config.LockTimeout = timeout
	}
	return config, nil
}
