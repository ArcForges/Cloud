// SPDX-License-Identifier: AGPL-3.0-only

// Package server composes the center: the ingress pipeline in front of the Connect handlers and the plain routes, the public
// listeners (HTTP/1.1 with h2c, and an h2c-only gRPC listener), the optional admin listener with readiness and metrics, request
// logging and graceful shutdown. The same composition serves the hosted Container behind the Worker and a self-hosted center
// standing alone.
package server

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	"connectrpc.com/connect/v2"
	"connectrpc.com/connect/v2/connecthttp"
	"github.com/ArcForges/Contracts/go/arcforges/hello/v1/hellov1connect"
	"github.com/jackc/pgx/v5/pgxpool"
	"golang.org/x/net/netutil"

	"github.com/ArcForges/Cloud/center/internal/buildinfo"
	"github.com/ArcForges/Cloud/center/internal/config"
	"github.com/ArcForges/Cloud/center/internal/feature"
	"github.com/ArcForges/Cloud/center/internal/hello"
	"github.com/ArcForges/Cloud/center/internal/ingress"
	"github.com/ArcForges/Cloud/center/internal/observe"
	"github.com/ArcForges/Cloud/center/internal/routes"
)

// Hello backends reported by health.
const (
	BackendStateless = "stateless"
	BackendNeon      = "neon-postgresql"
)

// Center is one composed center.
type Center struct {
	Config  config.Config
	Logger  *slog.Logger
	Metrics *observe.Metrics
	Health  buildinfo.Health
	// Features is the feature gate (AD-0021 section 13a); the stub answers per mode until AF-CTR-03.
	Features feature.Gate
	public   http.Handler
	admin    http.Handler
	pools    []*pgxpool.Pool
	ready    []component
}

type component struct {
	name  string
	check func(context.Context) error
}

// Options replace the parts a test substitutes.
type Options struct {
	// Greeting replaces the configured Hello greeting.
	Greeting hello.Greeting
}

// New composes a center from its configuration. Pools connect lazily, so a database that is down does not stop the start; it
// makes the center unready and its calls fail with UNAVAILABLE.
func New(cfg config.Config, logger *slog.Logger, options Options) (*Center, error) {
	center := &Center{Config: cfg, Logger: logger, Metrics: observe.NewMetrics(), Features: feature.NewGate(cfg.Mode)}
	greeting, backend := hello.Greeting(hello.Stateless), BackendStateless
	if cfg.NeonHello != nil {
		pool, err := pgxpool.NewWithConfig(context.Background(), cfg.NeonHello)
		if err != nil {
			return nil, errors.New("could not initialize the Hello database pool")
		}
		center.pools = append(center.pools, pool)
		center.ready = append(center.ready, component{"helloDatabase", pool.Ping})
		greeting, backend = hello.Database(pool), BackendNeon
	}
	if cfg.Database != nil {
		pool, err := pgxpool.NewWithConfig(context.Background(), cfg.Database)
		if err != nil {
			center.Close()
			return nil, errors.New("could not initialize the runtime database pool")
		}
		center.pools = append(center.pools, pool)
		center.ready = append(center.ready, component{"database", pool.Ping})
	}
	if options.Greeting != nil {
		greeting = options.Greeting
	}
	health, err := buildinfo.Document(backend, buildinfo.Center{Mode: string(cfg.Mode), PublicBaseURL: cfg.PublicBaseURL})
	if err != nil {
		center.Close()
		return nil, err
	}
	center.Health = health
	modules, err := routes.Center()
	if err != nil {
		center.Close()
		return nil, err
	}
	if _, err = routes.Table(modules); err != nil {
		center.Close()
		return nil, err
	}
	publicRoutes, err := routes.Ingress(modules)
	if err != nil {
		center.Close()
		return nil, err
	}

	dispatcher := connect.NewServer(center.recordOutcome)
	hellov1connect.RegisterHelloServiceHandler(dispatcher, &hello.Server{Greeting: greeting})
	mux := http.NewServeMux()
	// The message bound is the Hello policy's request bound without the five-byte frame header, as before.
	limit := routes.MaxBodyBytes - ingress.HeaderLength
	connecthttp.Mount(mux, dispatcher, connecthttp.WithReadMaxBytes(limit), connecthttp.WithSendMaxBytes(limit))
	mux.HandleFunc(routes.HealthPath, center.serveHealth)
	pipeline := ingress.NewPipeline(ingress.Options{Routes: publicRoutes, Observe: center.observeAdmission}, mux)
	center.public = center.track(pipeline)

	admin := http.NewServeMux()
	admin.HandleFunc("/readyz", center.serveReadiness)
	admin.HandleFunc("/metrics", center.serveMetrics)
	center.admin = admin
	return center, nil
}

// Public is the handler of the public listeners.
func (c *Center) Public() http.Handler { return c.public }

// Admin is the handler of the admin listener.
func (c *Center) Admin() http.Handler { return c.admin }

// Close releases the database pools.
func (c *Center) Close() {
	for _, pool := range c.pools {
		pool.Close()
	}
}

type recordKey struct{}

// record is what the center learns about one request while it is served; it holds no request content.
type record struct {
	start       time.Time
	method      string
	code        string
	refusal     *ingress.Reason
	correlation string
}

func recordFrom(ctx context.Context) *record {
	value, _ := ctx.Value(recordKey{}).(*record)
	return value
}

// track logs and counts every request after it finished.
func (c *Center) track(next http.Handler) http.Handler {
	return http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		entry := &record{start: time.Now(), method: "not_found"}
		next.ServeHTTP(writer, request.WithContext(context.WithValue(request.Context(), recordKey{}, entry)))
		duration := time.Since(entry.start)
		code := entry.code
		if code == "" {
			code = "unknown"
		}
		c.Metrics.ObserveRequest(entry.method, code, duration)
		attributes := []any{"method", entry.method, "code", code, "durationMs", float64(duration.Microseconds()) / 1000}
		if entry.correlation != "" {
			attributes = append(attributes, "correlationId", entry.correlation)
		}
		if entry.refusal != nil {
			category := categoryName(*entry.refusal)
			c.Metrics.ObserveRefusal(entry.refusal.Code, category)
			attributes = append(attributes, "refusal", entry.refusal.Code, "category", category)
		}
		level := slog.LevelInfo
		if entry.method == "plain" {
			level = slog.LevelDebug
		}
		c.Logger.Log(request.Context(), level, "request", attributes...)
	})
}

// observeAdmission records the pipeline's decision.
func (c *Center) observeAdmission(request *http.Request, outcome ingress.Outcome) {
	entry := recordFrom(request.Context())
	if entry == nil {
		return
	}
	entry.method = outcome.Method
	switch {
	case outcome.Refusal != nil:
		entry.refusal = outcome.Refusal
		entry.code = statusName(outcome.Refusal.Status)
	case outcome.HTTPStatus != 0:
		entry.code = "http_" + strconv.Itoa(outcome.HTTPStatus)
	}
	if outcome.Call != nil {
		entry.correlation = outcome.Call.Correlation.CorrelationID
		entry.code = "transport" // replaced by the method's outcome once a handler ran
	}
}

// recordOutcome is the Connect interceptor that records each call's outcome code.
func (c *Center) recordOutcome(next connect.ServerFunc) connect.ServerFunc {
	return func(ctx context.Context, spec connect.Spec, stream connect.ServerStream) error {
		err := next(ctx, spec, stream)
		if entry := recordFrom(ctx); entry != nil {
			entry.code = "ok"
			if err != nil {
				entry.code = connect.CodeOf(err).String()
			}
		}
		return err
	}
}

func statusName(status ingress.Status) string { return connect.Code(status).String() }

func categoryName(reason ingress.Reason) string {
	name := strings.TrimPrefix(reason.Category.String(), "ERROR_CATEGORY_")
	if name == "UNSPECIFIED" {
		return "none"
	}
	return strings.ToLower(name)
}

func (c *Center) serveHealth(writer http.ResponseWriter, request *http.Request) {
	entry := recordFrom(request.Context())
	if request.Method != http.MethodGet {
		if entry != nil {
			entry.code = "http_405"
		}
		writer.Header().Set("Cache-Control", "no-store")
		writer.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	if entry != nil {
		entry.code = "http_200"
	}
	writer.Header().Set("Content-Type", "application/json")
	writer.Header().Set("Cache-Control", "no-store")
	_ = json.NewEncoder(writer).Encode(c.Health)
}

// Readiness is the readiness report of the admin listener: the state of each configured dependency, separate from health
// (which reports identity and never touches a database).
type Readiness struct {
	Status     string            `json:"status"`
	Components map[string]string `json:"components"`
}

// Ready checks every configured dependency within the deadline.
func (c *Center) Ready(ctx context.Context) Readiness {
	result := Readiness{Status: "ready", Components: map[string]string{}}
	for _, item := range c.ready {
		check, cancel := context.WithTimeout(ctx, 2*time.Second)
		err := item.check(check)
		cancel()
		if err != nil {
			result.Components[item.name] = "unavailable"
			result.Status = "unavailable"
			continue
		}
		result.Components[item.name] = "ready"
	}
	return result
}

func (c *Center) serveReadiness(writer http.ResponseWriter, request *http.Request) {
	if request.Method != http.MethodGet {
		writer.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	readiness := c.Ready(request.Context())
	writer.Header().Set("Content-Type", "application/json")
	writer.Header().Set("Cache-Control", "no-store")
	if readiness.Status != "ready" {
		writer.WriteHeader(http.StatusServiceUnavailable)
	}
	_ = json.NewEncoder(writer).Encode(readiness)
}

func (c *Center) serveMetrics(writer http.ResponseWriter, request *http.Request) {
	if request.Method != http.MethodGet {
		writer.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	writer.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
	writer.Header().Set("Cache-Control", "no-store")
	_ = c.Metrics.WritePrometheus(writer)
}

// Run serves the center until ctx ends or a listener fails, then shuts down within five seconds.
func Run(ctx context.Context, cfg config.Config, logger *slog.Logger) error {
	center, err := New(cfg, logger, Options{})
	if err != nil {
		return err
	}
	defer center.Close()
	type plan struct {
		name, address string
		handler       http.Handler
		http1         bool
	}
	plans := []plan{{"http", cfg.HTTPAddress, center.Public(), true}}
	if cfg.GRPCAddress != "" {
		plans = append(plans, plan{"grpc", cfg.GRPCAddress, center.Public(), false})
	}
	if cfg.AdminAddress != "" {
		plans = append(plans, plan{"admin", cfg.AdminAddress, center.Admin(), true})
	}
	errorLog := slog.NewLogLogger(logger.Handler(), slog.LevelWarn)
	servers := make([]*http.Server, 0, len(plans))
	failures := make(chan error, len(plans))
	bound := map[string]string{}
	for _, item := range plans {
		listener, err := net.Listen("tcp", item.address)
		if err != nil {
			for _, server := range servers {
				_ = server.Close()
			}
			return errors.New("could not bind the " + item.name + " listener")
		}
		bound[item.name] = listener.Addr().String()
		protocols := new(http.Protocols)
		protocols.SetHTTP1(item.http1)
		protocols.SetUnencryptedHTTP2(true)
		server := &http.Server{
			Handler: item.handler, Protocols: protocols, ReadHeaderTimeout: 10 * time.Second, ReadTimeout: 20 * time.Second,
			WriteTimeout: 20 * time.Second, IdleTimeout: 60 * time.Second, MaxHeaderBytes: 16384, ErrorLog: errorLog,
		}
		servers = append(servers, server)
		go func() { failures <- server.Serve(netutil.LimitListener(listener, cfg.MaxConnections)) }()
	}
	logger.Info("center started", "mode", string(cfg.Mode), "publicBaseUrl", cfg.PublicBaseURL, "listeners", bound,
		"helloBackend", center.Health.HelloBackend, "revision", center.Health.Revision, "version", center.Health.Artifact.Version)
	if cfg.MetricsLogInterval > 0 {
		go center.logMetrics(ctx, cfg.MetricsLogInterval)
	}
	var result error
	select {
	case <-ctx.Done():
	case err := <-failures:
		if !errors.Is(err, http.ErrServerClosed) {
			result = errors.New("a center listener stopped unexpectedly")
		}
	}
	shutdown, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	for _, server := range servers {
		_ = server.Shutdown(shutdown)
	}
	logger.Info("center stopped")
	return result
}

func (c *Center) logMetrics(ctx context.Context, interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			c.Logger.Info("metrics", "requests", c.Metrics.Summary())
		}
	}
}
