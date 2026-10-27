// SPDX-License-Identifier: AGPL-3.0-only
package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"
	"unicode/utf8"

	"connectrpc.com/connect/v2"
	"connectrpc.com/connect/v2/connecthttp"
	hellov1 "github.com/ArcForges/Cloud/hello-go/internal/gen/arcforges/hello/v1"
	"github.com/ArcForges/Cloud/hello-go/internal/gen/arcforges/hello/v1/hellov1connect"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"golang.org/x/net/netutil"
)

var (
	appVersion   = "0.1.0-local.0"
	sourceCommit = "local"
	sourceDirty  = "true"
	buildKind    = "local"
	buildID      = "local"
	pipelineRun  = ""
	sourceEpoch  = "0"
)

type buildMetadata struct {
	SourceCommit    string  `json:"sourceCommit"`
	Dirty           bool    `json:"dirty"`
	Kind            string  `json:"kind"`
	BuildID         string  `json:"buildId"`
	RunID           *string `json:"runId"`
	RunAttempt      *int    `json:"runAttempt"`
	PipelineRun     *string `json:"pipelineRun"`
	SourceDateEpoch int64   `json:"sourceDateEpoch"`
}
type artifactMetadata struct {
	ID      string `json:"id"`
	Version string `json:"version"`
}
type healthDocument struct {
	Service      string           `json:"service"`
	Revision     string           `json:"revision"`
	NativeAOT    bool             `json:"nativeAot"`
	Runtime      string           `json:"runtime"`
	HelloBackend string           `json:"helloBackend"`
	Artifact     artifactMetadata `json:"artifact"`
	Build        buildMetadata    `json:"build"`
}
type helloServer struct {
	greeting func(context.Context, string) (string, error)
}

func (s *helloServer) SayHello(ctx context.Context, request *hellov1.SayHelloRequest) (*hellov1.SayHelloResponse, error) {
	name := request.GetName()
	if name == "" || !utf8.ValidString(name) {
		return nil, connect.NewError(connect.CodeInvalidArgument, "Name must not be empty.")
	}
	units := 0
	for _, r := range name {
		units++
		if r > 0xffff {
			units++
		}
	}
	if units > 256 {
		return nil, connect.NewError(connect.CodeResourceExhausted, "Name exceeds 256 UTF-16 code units.")
	}
	deadline, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	message, err := s.greeting(deadline, name)
	if err != nil {
		if errors.Is(err, context.DeadlineExceeded) {
			return nil, connect.NewError(connect.CodeDeadlineExceeded, "Hello request timed out.")
		}
		if errors.Is(err, context.Canceled) {
			return nil, connect.NewError(connect.CodeCanceled, "Hello request cancelled.")
		}
		// Never expose PostgreSQL errors or fall back to a successful local greeting.
		return nil, connect.NewError(connect.CodeUnavailable, "Hello database unavailable.")
	}
	return &hellov1.SayHelloResponse{Message: message}, nil
}

func neonConfig(value string) (*pgxpool.Config, error) {
	invalid := func() (*pgxpool.Config, error) {
		return nil, errors.New("Neon Hello requires a complete pooled NEON_DATABASE_URL with TLS and channel binding.")
	}
	if len(value) == 0 || len(value) > 8192 {
		return invalid()
	}
	uri, err := url.Parse(strings.TrimSpace(value))
	if err != nil || (uri.Scheme != "postgresql" && uri.Scheme != "postgres") ||
		uri.Fragment != "" || uri.User == nil || uri.User.Username() == "" ||
		!strings.HasPrefix(uri.Hostname(), "ep-") || !strings.HasSuffix(uri.Hostname(), ".neon.tech") ||
		!strings.Contains(uri.Hostname(), "-pooler.") || (uri.Port() != "" && uri.Port() != "5432") ||
		len(uri.Path) < 2 || strings.Contains(uri.Path[1:], "/") {
		return invalid()
	}
	password, present := uri.User.Password()
	if !present || password == "" || strings.Contains(password, "*") {
		return invalid()
	}
	query, err := url.ParseQuery(uri.RawQuery)
	if err != nil {
		return invalid()
	}
	for key, values := range query {
		if len(values) != 1 || (key != "sslmode" && key != "channel_binding" && key != "connect_timeout") {
			return invalid()
		}
	}
	if (query.Get("sslmode") != "require" && query.Get("sslmode") != "verify-full") ||
		query.Get("channel_binding") != "require" {
		return invalid()
	}
	query.Set("sslmode", "verify-full")
	uri.RawQuery = query.Encode()
	config, err := pgxpool.ParseConfig(uri.String())
	if err != nil {
		return invalid()
	}
	if config.ConnConfig.TLSConfig == nil || config.ConnConfig.TLSConfig.InsecureSkipVerify ||
		config.ConnConfig.ChannelBinding != "require" || len(config.ConnConfig.Fallbacks) != 0 {
		return invalid()
	}
	config.MaxConns = 2
	config.MinConns = 0
	config.MaxConnIdleTime = 30 * time.Second
	config.MaxConnLifetime = time.Hour
	config.ConnConfig.ConnectTimeout = 10 * time.Second
	config.ConnConfig.DefaultQueryExecMode = pgx.QueryExecModeExec
	config.ConnConfig.RuntimeParams["application_name"] = "arcforges-go-hello"
	return config, nil
}
func databaseGreeting(pool *pgxpool.Pool) func(context.Context, string) (string, error) {
	return func(ctx context.Context, name string) (string, error) {
		transaction, err := pool.BeginTx(ctx, pgx.TxOptions{AccessMode: pgx.ReadOnly})
		if err != nil {
			return "", err
		}
		defer transaction.Rollback(ctx)
		if _, err = transaction.Exec(ctx, "SET LOCAL statement_timeout = 5000"); err != nil {
			return "", err
		}
		var greeting []byte
		err = transaction.QueryRow(ctx,
			"SELECT convert_to('Hello, ', 'UTF8') || $1::bytea || convert_to('!', 'UTF8')",
			[]byte(name)).Scan(&greeting)
		if err != nil {
			return "", err
		}
		if err = transaction.Rollback(ctx); err != nil {
			return "", err
		}
		return string(greeting), nil
	}
}
func handler(source func(context.Context, string) (string, error), health healthDocument) http.Handler {
	dispatcher := connect.NewServer()
	hellov1connect.RegisterHelloServiceHandler(dispatcher, &helloServer{greeting: source})
	mux := http.NewServeMux()
	connecthttp.Mount(mux, dispatcher, connecthttp.WithReadMaxBytes(4091), connecthttp.WithSendMaxBytes(4091))
	mux.HandleFunc("/healthz", func(writer http.ResponseWriter, request *http.Request) {
		if request.Method != http.MethodGet {
			writer.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		writer.Header().Set("Content-Type", "application/json")
		writer.Header().Set("Cache-Control", "no-store")
		_ = json.NewEncoder(writer).Encode(health)
	})
	return http.MaxBytesHandler(mux, 4096)
}
func metadata(backend string) (healthDocument, error) {
	dirty, err := strconv.ParseBool(sourceDirty)
	if err != nil {
		return healthDocument{}, errors.New("Invalid build metadata.")
	}
	epoch, err := strconv.ParseInt(sourceEpoch, 10, 64)
	if err != nil {
		return healthDocument{}, errors.New("Invalid build metadata.")
	}
	build := buildMetadata{SourceCommit: sourceCommit, Dirty: dirty, Kind: buildKind, BuildID: buildID, SourceDateEpoch: epoch}
	if buildKind == "ci" {
		parts := strings.Split(buildID, ".")
		if len(parts) != 2 {
			return healthDocument{}, errors.New("Invalid CI build identity.")
		}
		attempt, err := strconv.Atoi(parts[1])
		if err != nil || attempt < 1 || len(sourceCommit) != 40 || dirty || pipelineRun == "" || epoch <= 0 {
			return healthDocument{}, errors.New("Invalid CI build identity.")
		}
		build.RunID = &parts[0]
		build.RunAttempt = &attempt
		build.PipelineRun = &pipelineRun
	}
	revision := sourceCommit
	if dirty {
		revision += "-dirty"
	}
	return healthDocument{
		Service: "arcforges-cloud", Revision: revision, NativeAOT: false, Runtime: "go",
		HelloBackend: backend, Artifact: artifactMetadata{ID: "Cloud", Version: appVersion}, Build: build,
	}, nil
}
func run() error {
	if len(os.Args) == 2 && os.Args[1] == "--build-info" {
		document, err := metadata("not-probed")
		if err != nil {
			return err
		}
		return json.NewEncoder(os.Stdout).Encode(document)
	}
	source := func(_ context.Context, name string) (string, error) { return "Hello, " + name + "!", nil }
	backend := "stateless"
	enabled := os.Getenv("ARCFORGES_NEON_HELLO")
	if enabled != "" && enabled != "disabled" && enabled != "enabled" {
		return errors.New("Invalid Hello mode.")
	}
	if enabled == "enabled" {
		config, err := neonConfig(os.Getenv("NEON_DATABASE_URL"))
		if err != nil {
			return err
		}
		pool, err := pgxpool.NewWithConfig(context.Background(), config)
		if err != nil {
			return errors.New("Could not initialize the Hello database pool.")
		}
		defer pool.Close()
		source = databaseGreeting(pool)
		backend = "neon-postgresql"
	}
	health, err := metadata(backend)
	if err != nil {
		return err
	}
	addresses := []string{os.Getenv("ARCFORGES_HELLO_HTTP_ADDRESS"), os.Getenv("ARCFORGES_HELLO_GRPC_ADDRESS")}
	if addresses[0] == "" {
		addresses[0] = ":8080"
	}
	if addresses[1] == "" {
		addresses[1] = ":8081"
	}
	serve := handler(source, health)
	servers := make([]*http.Server, 0, 2)
	listeners := make([]net.Listener, 0, 2)
	defer func() {
		for _, listener := range listeners {
			_ = listener.Close()
		}
	}()
	errorsChannel := make(chan error, 2)
	for index, address := range addresses {
		listener, err := net.Listen("tcp", address)
		if err != nil {
			return errors.New("Could not bind the Hello listener.")
		}
		listeners = append(listeners, listener)
		protocols := new(http.Protocols)
		protocols.SetHTTP1(index == 0)
		protocols.SetUnencryptedHTTP2(true)
		server := &http.Server{
			Handler: serve, Protocols: protocols, ReadHeaderTimeout: 10 * time.Second,
			ReadTimeout: 20 * time.Second, WriteTimeout: 20 * time.Second, IdleTimeout: 60 * time.Second,
			MaxHeaderBytes: 16384,
		}
		servers = append(servers, server)
		go func() { errorsChannel <- server.Serve(netutil.LimitListener(listener, 64)) }()
	}
	signalContext, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	var result error
	select {
	case <-signalContext.Done():
	case err := <-errorsChannel:
		if !errors.Is(err, http.ErrServerClosed) {
			result = errors.New("Hello listener stopped unexpectedly.")
		}
	}
	shutdown, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	for _, server := range servers {
		_ = server.Shutdown(shutdown)
	}
	return result
}
func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
