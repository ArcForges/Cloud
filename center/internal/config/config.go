// SPDX-License-Identifier: AGPL-3.0-only

// Package config reads the center's configuration from its environment and refuses to start on anything missing or invalid.
// The mode is explicit (ArcForges-Design AD-0021 section 13a): official-hosted or self-hosted, with no default. The public
// base URL is configuration too (AD-0021 section 4): no official endpoint is compiled into a code path, and health and every
// URL the center issues derive from the configured value. Errors name the variable and never repeat its value, so a
// credential in a database URL never reaches a log.
package config

import (
	"errors"
	"fmt"
	"log/slog"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// Mode is the center mode.
type Mode string

// The center modes.
const (
	// OfficialHosted is the official hosted center: gated features need a valid subscription entitlement, and without a
	// valid plan configuration none is enabled.
	OfficialHosted Mode = "official-hosted"
	// SelfHosted is a center its owner runs: a built-in default enables the self-hostable capabilities.
	SelfHosted Mode = "self-hosted"
)

// The environment variables of the center.
const (
	EnvMode               = "ARCFORGES_CENTER_MODE"
	EnvPublicBaseURL      = "ARCFORGES_CENTER_PUBLIC_BASE_URL"
	EnvHTTPAddress        = "ARCFORGES_CENTER_HTTP_ADDRESS"
	EnvGRPCAddress        = "ARCFORGES_CENTER_GRPC_ADDRESS"
	EnvAdminAddress       = "ARCFORGES_CENTER_ADMIN_ADDRESS"
	EnvMaxConnections     = "ARCFORGES_CENTER_MAX_CONNECTIONS"
	EnvLogLevel           = "ARCFORGES_CENTER_LOG_LEVEL"
	EnvMetricsLogInterval = "ARCFORGES_CENTER_METRICS_LOG_INTERVAL"
	EnvDatabaseURL        = "ARCFORGES_CENTER_DATABASE_URL"
	EnvDatabaseMaxConns   = "ARCFORGES_CENTER_DATABASE_MAX_CONNS"
	EnvNeonHello          = "ARCFORGES_NEON_HELLO"
	EnvNeonDatabaseURL    = "NEON_DATABASE_URL"
)

// Defaults and bounds.
const (
	DefaultHTTPAddress        = ":8080"
	DefaultGRPCAddress        = ":8081"
	DefaultMaxConnections     = 64
	MaxMaxConnections         = 4096
	DefaultDatabaseMaxConns   = 4
	MaxDatabaseMaxConns       = 32
	DefaultMetricsLogInterval = time.Minute
	MinMetricsLogInterval     = 10 * time.Second
	MaxMetricsLogInterval     = time.Hour
	disabled                  = "off"
)

// Config is the validated configuration of one center process.
type Config struct {
	Mode Mode
	// PublicBaseURL is the canonical absolute URL under which clients reach this center (no trailing slash).
	PublicBaseURL string
	// HTTPAddress serves HTTP/1.1 and h2c; GRPCAddress serves h2c only and is empty when disabled; AdminAddress serves
	// readiness and metrics and is empty when disabled.
	HTTPAddress    string
	GRPCAddress    string
	AdminAddress   string
	MaxConnections int
	LogLevel       slog.Level
	// MetricsLogInterval is how often the metrics summary is logged; zero disables it.
	MetricsLogInterval time.Duration
	// HelloFromDatabase is true when ARCFORGES_NEON_HELLO is enabled: the Hello greeting is read from PostgreSQL, through the
	// runtime database when one is configured and otherwise through NeonHello.
	HelloFromDatabase bool
	// NeonHello is the Hello's own pooled Neon connection (NEON_DATABASE_URL), used only while no runtime database is
	// configured; nil otherwise.
	NeonHello *pgxpool.Config
	// Database is the center's pooled runtime database (the least-privilege runtime role), or nil when none is configured.
	Database *pgxpool.Config
}

// ErrInvalid is the error of every refused configuration.
var ErrInvalid = errors.New("invalid center configuration")

func invalid(format string, arguments ...any) error {
	return fmt.Errorf("%w: "+format, append([]any{ErrInvalid}, arguments...)...)
}

// Load reads and validates the configuration; lookup is os.LookupEnv in production. A missing or invalid mode refuses to
// start.
func Load(lookup func(string) (string, bool)) (Config, error) {
	get := func(name string) string {
		value, _ := lookup(name)
		return value
	}
	var config Config
	switch Mode(get(EnvMode)) {
	case OfficialHosted:
		config.Mode = OfficialHosted
	case SelfHosted:
		config.Mode = SelfHosted
	default:
		return Config{}, invalid("%s must be %s or %s; the center does not start without an explicit mode", EnvMode, OfficialHosted, SelfHosted)
	}
	var err error
	if config.PublicBaseURL, err = ParsePublicBaseURL(get(EnvPublicBaseURL), config.Mode); err != nil {
		return Config{}, invalid("%s: %v", EnvPublicBaseURL, err)
	}
	if config.HTTPAddress, err = address(get(EnvHTTPAddress), DefaultHTTPAddress, false); err != nil {
		return Config{}, invalid("%s: %v", EnvHTTPAddress, err)
	}
	if config.GRPCAddress, err = address(get(EnvGRPCAddress), DefaultGRPCAddress, true); err != nil {
		return Config{}, invalid("%s: %v", EnvGRPCAddress, err)
	}
	if config.AdminAddress, err = address(get(EnvAdminAddress), "", true); err != nil {
		return Config{}, invalid("%s: %v", EnvAdminAddress, err)
	}
	if config.Mode == OfficialHosted && config.AdminAddress != "" && !isLoopbackAddress(config.AdminAddress) {
		return Config{}, invalid("%s must be a loopback address in %s mode; readiness and metrics have no public route", EnvAdminAddress, OfficialHosted)
	}
	if err = distinct(config.HTTPAddress, config.GRPCAddress, config.AdminAddress); err != nil {
		return Config{}, err
	}
	if config.MaxConnections, err = bounded(get(EnvMaxConnections), DefaultMaxConnections, 1, MaxMaxConnections); err != nil {
		return Config{}, invalid("%s: %v", EnvMaxConnections, err)
	}
	if config.LogLevel, err = logLevel(get(EnvLogLevel)); err != nil {
		return Config{}, invalid("%s: %v", EnvLogLevel, err)
	}
	if config.MetricsLogInterval, err = metricsInterval(get(EnvMetricsLogInterval)); err != nil {
		return Config{}, invalid("%s: %v", EnvMetricsLogInterval, err)
	}
	maxConns, err := bounded(get(EnvDatabaseMaxConns), DefaultDatabaseMaxConns, 1, MaxDatabaseMaxConns)
	if err != nil {
		return Config{}, invalid("%s: %v", EnvDatabaseMaxConns, err)
	}
	if value := get(EnvDatabaseURL); value != "" {
		if config.Database, err = RuntimeDatabasePool(value, config.Mode, int32(maxConns)); err != nil {
			return Config{}, err
		}
	}
	switch get(EnvNeonHello) {
	case "", "disabled":
	case "enabled":
		config.HelloFromDatabase = true
		// The runtime role reads the greeting once the store exists; the Hello's own Neon credential is the configuration
		// before it (and of a center without a store), never both.
		if config.Database == nil {
			if config.NeonHello, err = NeonHelloPool(get(EnvNeonDatabaseURL)); err != nil {
				return Config{}, err
			}
		}
	default:
		return Config{}, invalid("%s must be enabled or disabled", EnvNeonHello)
	}
	return config, nil
}

// address is a listener address host:port; host is empty (every interface), an IP literal or localhost. "off" disables an
// optional listener.
func address(value, fallback string, optional bool) (string, error) {
	if value == "" {
		return fallback, nil
	}
	if value == disabled {
		if !optional {
			return "", errors.New("this listener cannot be disabled")
		}
		return "", nil
	}
	host, port, err := net.SplitHostPort(value)
	if err != nil {
		return "", errors.New("not a host:port address")
	}
	number, err := strconv.Atoi(port)
	if err != nil || number < 0 || number > 65535 || strconv.Itoa(number) != port {
		return "", errors.New("the port is not a number from 0 to 65535")
	}
	if host != "" && host != "localhost" && net.ParseIP(host) == nil {
		return "", errors.New("the host is not an IP address or localhost")
	}
	return value, nil
}

func isLoopbackAddress(value string) bool {
	host, _, err := net.SplitHostPort(value)
	if err != nil {
		return false
	}
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

// distinct refuses two listeners on one fixed address; port 0 (an ephemeral port) never collides.
func distinct(addresses ...string) error {
	seen := map[string]bool{}
	for _, value := range addresses {
		if value == "" || strings.HasSuffix(value, ":0") {
			continue
		}
		if seen[value] {
			return invalid("two listeners share one address")
		}
		seen[value] = true
	}
	return nil
}

func bounded(value string, fallback, minimum, maximum int) (int, error) {
	if value == "" {
		return fallback, nil
	}
	number, err := strconv.Atoi(value)
	if err != nil || number < minimum || number > maximum || strconv.Itoa(number) != value {
		return 0, fmt.Errorf("not a whole number from %d to %d", minimum, maximum)
	}
	return number, nil
}

func logLevel(value string) (slog.Level, error) {
	switch value {
	case "", "info":
		return slog.LevelInfo, nil
	case "debug":
		return slog.LevelDebug, nil
	case "warn":
		return slog.LevelWarn, nil
	case "error":
		return slog.LevelError, nil
	default:
		return 0, errors.New("not one of debug, info, warn or error")
	}
}

func metricsInterval(value string) (time.Duration, error) {
	switch value {
	case "":
		return DefaultMetricsLogInterval, nil
	case "0":
		return 0, nil
	}
	interval, err := time.ParseDuration(value)
	if err != nil || interval < MinMetricsLogInterval || interval > MaxMetricsLogInterval {
		return 0, fmt.Errorf("not 0 or a duration from %s to %s", MinMetricsLogInterval, MaxMetricsLogInterval)
	}
	return interval, nil
}
