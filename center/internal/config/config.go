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
	"slices"
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
	EnvPlanConfiguration  = "ARCFORGES_CENTER_PLAN_CONFIGURATION"
	EnvDisabledFeatures   = "ARCFORGES_CENTER_DISABLED_FEATURES"
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

// PlanConfiguration names the plan configuration of an official-hosted center (AD-0021 section 13a).
type PlanConfiguration string

// The plan configurations.
const (
	// PlanNone is the configuration of production until AF-PROD-01: no plan configuration, so no gated feature is enabled.
	PlanNone PlanConfiguration = ""
	// PlanDevelopmentFixtures is the acceptance environment's: the development fixtures of the plan catalogue (AF-CTR-03), for
	// attributable test identities only. It is never production configuration.
	PlanDevelopmentFixtures PlanConfiguration = "development-fixtures"
)

// Config is the validated configuration of one center process.
type Config struct {
	Mode Mode
	// Plan is the plan configuration (official-hosted only).
	Plan PlanConfiguration
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
	// Identity is the identity surface's configuration (AF-CTR-03).
	Identity Identity
	// DisabledFeatures are the gated feature keys the operator of a self-hosted center disabled (ARCFORGES_CENTER_DISABLED_FEATURES):
	// the built-in default enables every other key. It is empty in official-hosted mode, where the variable is refused.
	DisabledFeatures []string
}

// GatedFeatureKeys are the six gated feature keys of AD-0021 section 13a. Package feature owns the keys (feature.Gated); the list is
// here so the configuration can refuse an unknown key at start without importing it, and a test of package feature pins that the two
// lists are equal.
func GatedFeatureKeys() []string {
	return []string{"center.nodes", "center.execute", "remote.view", "remote.control", "center.mcp", "push"}
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
	switch PlanConfiguration(get(EnvPlanConfiguration)) {
	case PlanNone:
	case PlanDevelopmentFixtures:
		if config.Mode != OfficialHosted {
			return Config{}, invalid("%s applies to an official-hosted center only", EnvPlanConfiguration)
		}
		config.Plan = PlanDevelopmentFixtures
	default:
		return Config{}, invalid("%s must be empty or %s", EnvPlanConfiguration, PlanDevelopmentFixtures)
	}
	var err error
	if config.DisabledFeatures, err = loadDisabledFeatures(lookup, config.Mode); err != nil {
		return Config{}, err
	}
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
	if config.Identity, err = loadIdentity(get, config.Mode, config.PublicBaseURL, time.Now()); err != nil {
		return Config{}, err
	}
	if config.Identity.Enabled(SurfaceIdentity) && config.Database == nil {
		if get(EnvSurfaces) != "" {
			return Config{}, invalid("the identity surface needs the runtime database (%s)", EnvDatabaseURL)
		}
		// A self-hosted center without a store keeps serving Hello; identity stays off and the start-up log says why.
		config.Identity.Surfaces = nil
		config.Identity.Disabled = "no runtime database is configured (" + EnvDatabaseURL + ")"
	}
	return config, nil
}

// loadDisabledFeatures reads ARCFORGES_CENTER_DISABLED_FEATURES: comma-separated gated feature keys, exact, without whitespace, empty
// items or repetition; an unknown key refuses start (a misspelt limit that silently enabled the feature would be the opposite of the
// operator's intent). The variable is a self-hosted operator's limit and has no meaning on the hosted center, where the plan
// catalogue and the account's entitlement decide: its presence there, even empty, refuses start (PLT-18; the hosted Worker passes
// it never).
func loadDisabledFeatures(lookup func(string) (string, bool), mode Mode) ([]string, error) {
	value, present := lookup(EnvDisabledFeatures)
	if !present {
		return nil, nil
	}
	if mode != SelfHosted {
		return nil, invalid("%s applies to a self-hosted center only; the hosted center's availability comes from the plan catalogue", EnvDisabledFeatures)
	}
	if value == "" {
		return nil, nil
	}
	var keys []string
	for item := range strings.SplitSeq(value, ",") {
		if !slices.Contains(GatedFeatureKeys(), item) {
			return nil, invalid("%s must be a comma-separated list of known feature keys (%s)", EnvDisabledFeatures, strings.Join(GatedFeatureKeys(), ", "))
		}
		if slices.Contains(keys, item) {
			return nil, invalid("%s lists a feature key twice", EnvDisabledFeatures)
		}
		keys = append(keys, item)
	}
	return keys, nil
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
