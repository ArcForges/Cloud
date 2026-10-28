// SPDX-License-Identifier: AGPL-3.0-only

package config

import (
	"errors"
	"net"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// MaxPublicBaseURLLength bounds the configured public base URL.
const MaxPublicBaseURLLength = 2048

// ParsePublicBaseURL validates the public base URL and returns its canonical form. It is an absolute https URL (or, in
// self-hosted mode only, an http URL of a loopback host, for a center behind a local TLS-terminating proxy or under test) with a
// lowercase host, an optional port and an optional clean path without a trailing slash; it has no user information, query or
// fragment and no percent-encoding. The canonical form is the input itself: a value is accepted only as it would be written
// back.
func ParsePublicBaseURL(value string, mode Mode) (string, error) {
	if value == "" {
		return "", errors.New("required: the absolute URL under which clients reach this center")
	}
	if len(value) > MaxPublicBaseURLLength {
		return "", errors.New("longer than 2048 bytes")
	}
	for index := range len(value) {
		if value[index] <= ' ' || value[index] >= 0x7f {
			return "", errors.New("contains a space, a control character or a non-ASCII byte")
		}
	}
	uri, err := url.Parse(value)
	if err != nil || uri.Opaque != "" || uri.User != nil || uri.RawQuery != "" || uri.ForceQuery || uri.Fragment != "" ||
		strings.ContainsAny(value, "?#%@\\") || uri.RawPath != "" {
		return "", errors.New("not an absolute URL without user information, query, fragment or percent-encoding")
	}
	host := uri.Hostname()
	if host == "" || host != strings.ToLower(host) || strings.HasSuffix(host, ".") {
		return "", errors.New("the host is missing or not in lowercase canonical form")
	}
	if port := uri.Port(); port != "" {
		number, err := strconv.Atoi(port)
		if err != nil || number < 1 || number > 65535 || strconv.Itoa(number) != port {
			return "", errors.New("the port is not a number from 1 to 65535")
		}
	} else if strings.HasSuffix(uri.Host, ":") {
		return "", errors.New("the port is empty")
	}
	switch uri.Scheme {
	case "https":
	case "http":
		if mode != SelfHosted || !isLoopbackHost(host) {
			return "", errors.New("must use https (http only for a loopback host in self-hosted mode)")
		}
	default:
		return "", errors.New("must use https")
	}
	path := uri.Path
	if path != "" {
		if path == "/" || strings.HasSuffix(path, "/") || strings.Contains(path, "//") {
			return "", errors.New("the path has an empty segment or a trailing slash")
		}
		for segment := range strings.SplitSeq(path[1:], "/") {
			if segment == "." || segment == ".." {
				return "", errors.New("the path has a dot segment")
			}
		}
		for index := range len(path) {
			c := path[index]
			if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || strings.IndexByte("/-._~", c) >= 0) {
				return "", errors.New("the path has a character outside letters, digits and -._~")
			}
		}
	}
	canonical := uri.Scheme + "://" + uri.Host + path
	if canonical != value {
		return "", errors.New("not in canonical form (lowercase scheme, no trailing slash)")
	}
	return canonical, nil
}

func isLoopbackHost(host string) bool {
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

// NeonHelloPool is the pooled Neon connection of the Hello greeting: a complete pooled NEON_DATABASE_URL with verified TLS and
// required channel binding, a pool capped at two and the exec query mode, which keeps no session state for the pooler. It is
// the Go Hello's configuration, unchanged.
func NeonHelloPool(value string) (*pgxpool.Config, error) {
	refused := invalid("the Neon Hello requires a complete pooled %s with TLS and channel binding", EnvNeonDatabaseURL)
	if len(value) == 0 || len(value) > 8192 {
		return nil, refused
	}
	uri, err := url.Parse(strings.TrimSpace(value))
	if err != nil || (uri.Scheme != "postgresql" && uri.Scheme != "postgres") ||
		uri.Fragment != "" || uri.User == nil || uri.User.Username() == "" ||
		!strings.HasPrefix(uri.Hostname(), "ep-") || !strings.HasSuffix(uri.Hostname(), ".neon.tech") ||
		!strings.Contains(uri.Hostname(), "-pooler.") || (uri.Port() != "" && uri.Port() != "5432") ||
		len(uri.Path) < 2 || strings.Contains(uri.Path[1:], "/") {
		return nil, refused
	}
	if password, present := uri.User.Password(); !present || password == "" || strings.Contains(password, "*") {
		return nil, refused
	}
	if !secureQuery(uri, true) {
		return nil, refused
	}
	config, err := pgxpool.ParseConfig(uri.String())
	if err != nil || !verifiedTLS(config, true) {
		return nil, refused
	}
	config.MaxConns = 2
	config.MinConns = 0
	config.MaxConnIdleTime = 30 * time.Second
	config.MaxConnLifetime = time.Hour
	config.ConnConfig.ConnectTimeout = 10 * time.Second
	config.ConnConfig.DefaultQueryExecMode = pgx.QueryExecModeExec
	config.ConnConfig.RuntimeParams["application_name"] = "arcforges-center"
	return config, nil
}

// RuntimeDatabasePool is the center's pooled runtime database (the least-privilege runtime role of the PostgreSQL store, AF-CTR-02
// part B). Official-hosted mode requires verified TLS with channel binding; a self-hosted center may connect without TLS only to a
// loopback host. The pool keeps no session state (exec query mode), so it works behind a transaction pooler.
func RuntimeDatabasePool(value string, mode Mode, maxConns int32) (*pgxpool.Config, error) {
	refused := invalid("%s must be a postgres URL with a user; TLS with verify-full and channel binding is required except for a loopback host of a self-hosted center", EnvDatabaseURL)
	if len(value) > 8192 {
		return nil, refused
	}
	uri, err := url.Parse(value)
	if err != nil || (uri.Scheme != "postgresql" && uri.Scheme != "postgres") || uri.Fragment != "" || uri.Opaque != "" ||
		uri.User == nil || uri.User.Username() == "" || uri.Hostname() == "" || strings.Contains(uri.Hostname(), ",") ||
		len(uri.Path) < 2 || strings.Contains(uri.Path[1:], "/") {
		return nil, refused
	}
	plaintext := uri.Query().Get("sslmode") == "disable"
	if plaintext && (mode != SelfHosted || !isLoopbackHost(uri.Hostname())) {
		return nil, refused
	}
	if !secureQuery(uri, !plaintext) {
		return nil, refused
	}
	config, err := pgxpool.ParseConfig(uri.String())
	if err != nil || !verifiedTLS(config, !plaintext) {
		return nil, refused
	}
	config.MaxConns = maxConns
	config.MinConns = 0
	config.MaxConnIdleTime = 30 * time.Second
	config.MaxConnLifetime = time.Hour
	config.ConnConfig.ConnectTimeout = 10 * time.Second
	config.ConnConfig.DefaultQueryExecMode = pgx.QueryExecModeExec
	config.ConnConfig.RuntimeParams["application_name"] = "arcforges-center"
	return config, nil
}

// secureQuery admits only sslmode, channel_binding and connect_timeout, each once. With TLS it requires sslmode require or
// verify-full (upgraded to verify-full) and channel_binding=require; without TLS it requires sslmode=disable and no channel
// binding.
func secureQuery(uri *url.URL, tls bool) bool {
	query, err := url.ParseQuery(uri.RawQuery)
	if err != nil {
		return false
	}
	for key, values := range query {
		if len(values) != 1 || (key != "sslmode" && key != "channel_binding" && key != "connect_timeout") {
			return false
		}
	}
	if !tls {
		return query.Get("sslmode") == "disable" && !query.Has("channel_binding")
	}
	if (query.Get("sslmode") != "require" && query.Get("sslmode") != "verify-full") || query.Get("channel_binding") != "require" {
		return false
	}
	query.Set("sslmode", "verify-full")
	uri.RawQuery = query.Encode()
	return true
}

func verifiedTLS(config *pgxpool.Config, tls bool) bool {
	if len(config.ConnConfig.Fallbacks) != 0 {
		return false
	}
	if !tls {
		return config.ConnConfig.TLSConfig == nil
	}
	return config.ConnConfig.TLSConfig != nil && !config.ConnConfig.TLSConfig.InsecureSkipVerify &&
		config.ConnConfig.ChannelBinding == "require"
}
