// SPDX-License-Identifier: AGPL-3.0-only

package server

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"go/ast"
	"go/parser"
	"go/printer"
	"go/token"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"connectrpc.com/connect/v2"

	"github.com/ArcForges/Cloud/center/internal/config"
	"github.com/ArcForges/Cloud/center/internal/identity"
	"github.com/ArcForges/Cloud/center/internal/ingress"
	"github.com/ArcForges/Cloud/center/internal/mail"
	"github.com/ArcForges/Cloud/center/internal/observe"
	"github.com/ArcForges/Cloud/center/internal/store"
)

// The mail composition and the shutdown sequence need no PostgreSQL, so these tests run on both hosts. MOCKED: no provider is
// contacted; the senders are only built.

func mailConfig(t *testing.T, extra map[string]string) config.Config {
	t.Helper()
	values := map[string]string{config.EnvMode: string(config.SelfHosted), config.EnvPublicBaseURL: "https://center.example/api", config.EnvSurfaces: "none",
		config.EnvHTTPAddress: "127.0.0.1:0", config.EnvGRPCAddress: "127.0.0.1:0"}
	for name, value := range extra {
		values[name] = value
	}
	cfg, err := config.Load(func(name string) (string, bool) { value, ok := values[name]; return value, ok })
	if err != nil {
		t.Fatal(err)
	}
	return cfg
}

const (
	composedToken = "synthetic-word-built-composed-token-sentinel"
	composedFrom  = "composed-sender-sentinel@example.test"
)

func postmarkVariables() map[string]string {
	return map[string]string{config.EnvMailProvider: config.MailPostmark, config.EnvMailFrom: composedFrom, config.EnvMailPostmarkToken: composedToken}
}

func TestTheMailSenderComesFromTheConfigurationAndAnInjectedOneWins(t *testing.T) {
	disabled := &Center{Config: mailConfig(t, nil)}
	sender, err := disabled.mailSender(Options{})
	if _, ok := sender.(mail.Disabled); !ok || err != nil || sender.Enabled() {
		t.Errorf("the default configuration built %T (%v)", sender, err)
	}
	for name, extra := range map[string]map[string]string{
		"postmark": postmarkVariables(),
		"smtp": {config.EnvMailProvider: config.MailSMTP, config.EnvMailFrom: composedFrom, config.EnvMailSMTPHost: "smtp.example.test",
			config.EnvMailSMTPUsername: "u", config.EnvMailSMTPPassword: "p"},
	} {
		sender, err = (&Center{Config: mailConfig(t, extra)}).mailSender(Options{})
		if guard, ok := sender.(*mail.Guard); !ok || guard == nil || !sender.Enabled() || err != nil {
			t.Errorf("%s: built %T (%v): a configured provider is a guarded adapter", name, sender, err)
		}
	}
	fake := mail.NewFake()
	if sender, err = (&Center{Config: mailConfig(t, postmarkVariables())}).mailSender(Options{Mail: fake}); sender != mail.Sender(fake) || err != nil {
		t.Errorf("an injected sender did not win: %T %v", sender, err)
	}
}

func TestAnUnbuildableMailConfigurationIsRefusedWithoutRepeatingIt(t *testing.T) {
	cfg := mailConfig(t, postmarkVariables())
	cfg.Mail.Provider = "ses" // a hand-built configuration; Load would have refused it
	sender, err := (&Center{Config: cfg}).mailSender(Options{})
	if err == nil || sender != nil || err.Error() != "the mail configuration cannot build a sender" {
		t.Errorf("%T %v", sender, err)
	}
}

// runStartLine runs a center until its start line is logged and returns that line's fields and every log line.
func runStartLine(t *testing.T, cfg config.Config) (map[string]any, string) {
	t.Helper()
	logs := &lockedBuffer{}
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan error, 1)
	go func() { done <- Run(ctx, cfg, observe.NewLogger(logs, slog.LevelInfo)) }()
	var fields map[string]any
	deadline := time.Now().Add(10 * time.Second)
	for fields == nil {
		select {
		case err := <-done:
			t.Fatalf("serve stopped: %v", err)
		case <-time.After(10 * time.Millisecond):
		}
		if time.Now().After(deadline) {
			t.Fatal("no start line")
		}
		for line := range strings.SplitSeq(logs.String(), "\n") {
			var entry map[string]any
			if json.Unmarshal([]byte(line), &entry) == nil && entry["msg"] == "center started" {
				fields = entry
			}
		}
	}
	cancel()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	return fields, logs.String()
}

func TestTheStartLineNamesTheMailProviderAndNothingElseOfIt(t *testing.T) {
	fields, _ := runStartLine(t, mailConfig(t, nil))
	if fields["mail"] != "disabled" {
		t.Errorf("the start line says mail %v", fields["mail"])
	}
	fields, logs := runStartLine(t, mailConfig(t, postmarkVariables()))
	if fields["mail"] != "postmark" {
		t.Errorf("the start line says mail %v", fields["mail"])
	}
	for _, leak := range []string{composedToken, composedFrom, "composed-sender", "api.postmarkapp.com"} {
		if strings.Contains(logs, leak) {
			t.Errorf("the log holds %q", leak)
		}
	}
}

// TestStopServingStopsTheListenersThenDrainsWithinTheBound pins the order (listeners first, then the drain) and that the bound is a
// parameter: a stuck drain ends at the bound the caller gave, not at the five seconds of Run.
func TestStopServingStopsTheListenersThenDrainsWithinTheBound(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	server := &http.Server{Handler: http.HandlerFunc(func(http.ResponseWriter, *http.Request) {})}
	go func() { _ = server.Serve(listener) }()
	// Shutdown closes only the listeners that Serve has registered: one round trip proves that it has, so the test cannot race the
	// start of the goroutine (without it the drain dials a listener that Shutdown never saw, and the order looks wrong).
	response, getErr := http.Get("http://" + listener.Addr().String() + "/")
	if getErr != nil {
		t.Fatal(getErr)
	}
	_ = response.Body.Close()
	var listenerClosedWhenDrained atomic.Bool
	logs := &lockedBuffer{}
	center := &Center{Logger: observe.NewLogger(logs, slog.LevelInfo), drain: func(ctx context.Context) error {
		connection, dialErr := net.DialTimeout("tcp", listener.Addr().String(), time.Second)
		if dialErr != nil {
			listenerClosedWhenDrained.Store(true)
		} else {
			_ = connection.Close()
		}
		return nil
	}}
	center.stopServing([]*http.Server{server}, 5*time.Second)
	if !listenerClosedWhenDrained.Load() {
		t.Error("the deliveries were drained while the listener still accepted connections")
	}
	if strings.Contains(logs.String(), "abandoned") {
		t.Errorf("a drain that finished was logged as abandoned: %s", logs.String())
	}

	stuck := &Center{Logger: observe.NewLogger(logs, slog.LevelInfo), drain: func(ctx context.Context) error { <-ctx.Done(); return ctx.Err() }}
	stopped := make(chan struct{})
	go func() {
		defer close(stopped)
		stuck.stopServing(nil, 80*time.Millisecond)
	}()
	select {
	case <-stopped:
	case <-time.After(3 * time.Second):
		t.Fatal("a stuck drain held the stop for over 3 s with an 80 ms bound")
	}
	if !strings.Contains(logs.String(), "deliveries still in flight were abandoned at the shutdown bound") {
		t.Errorf("an abandoned drain was not logged: %s", logs.String())
	}
	(&Center{Logger: observe.NewLogger(logs, slog.LevelInfo)}).stopServing(nil, time.Second) // no identity surface: nothing to drain
}

// TestStopServingWaitsForASlowDeliveryAndNotLongerThanItTakes: a drain that finishes inside the bound is waited for, and the stop
// takes no longer than the drain (the drain here is a fake; the real service's drain is pinned by the identity tests and by
// TestTheShutdownWiringOfRunAndComposeIdentityIsPinned).
func TestStopServingWaitsForASlowDeliveryAndNotLongerThanItTakes(t *testing.T) {
	var finished atomic.Bool
	center := &Center{Logger: observe.NewLogger(&lockedBuffer{}, slog.LevelInfo), drain: func(ctx context.Context) error {
		select {
		case <-time.After(60 * time.Millisecond):
			finished.Store(true)
			return nil
		case <-ctx.Done():
			return ctx.Err()
		}
	}}
	begun := time.Now()
	center.stopServing([]*http.Server{httptest.NewUnstartedServer(nil).Config}, 5*time.Second)
	if !finished.Load() || time.Since(begun) > 3*time.Second {
		t.Errorf("finished %v after %v", finished.Load(), time.Since(begun))
	}
}

// TestComposingTheIdentitySurfaceWiresItsDrainIntoTheShutdown: without the wiring a running center would stop with deliveries in
// flight and the drain would never run. The composition needs no database to be built (nothing queries until a request comes).
func TestComposingTheIdentitySurfaceWiresItsDrainIntoTheShutdown(t *testing.T) {
	center := &Center{Config: mailConfig(t, nil), Logger: observe.NewLogger(&lockedBuffer{}, slog.LevelInfo), Metrics: observe.NewMetrics(), Store: store.New(nil)}
	if center.drain != nil {
		t.Fatal("a center without an identity surface has a drain")
	}
	if _, err := center.composeIdentity(connect.NewServer(center.recordOutcome), &ingress.Options{}, Options{Mail: mail.NewFake()}, center.Logger); err != nil {
		t.Fatal(err)
	}
	if center.drain == nil {
		t.Fatal("composeIdentity did not hand the identity service's drain to the center")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := center.drain(ctx); err != nil {
		t.Errorf("an idle service did not drain: %v", err)
	}
}

// TestStopServingSpendsOneBoundOnTheListenersAndTheDrainTogether: a request that outlives the bound holds the listener shutdown for
// the whole bound, and the drain then gets what is left, which is nothing: the stop takes about one bound, not two (two bounds would
// pass the 6 s the Worker waits for a stale center, routes.StaleStopMilliseconds).
func TestStopServingSpendsOneBoundOnTheListenersAndTheDrainTogether(t *testing.T) {
	release := make(chan struct{})
	entered := make(chan struct{}, 1)
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		entered <- struct{}{}
		<-release
	}))
	server.Start()
	defer server.Close()
	defer close(release)
	go func() {
		if response, err := http.Get(server.URL); err == nil {
			_ = response.Body.Close()
		}
	}()
	select {
	case <-entered:
	case <-time.After(5 * time.Second):
		t.Fatal("the request never reached the handler")
	}
	var drainedWith time.Duration
	center := &Center{Logger: observe.NewLogger(&lockedBuffer{}, slog.LevelInfo), drain: func(ctx context.Context) error {
		deadline, ok := ctx.Deadline()
		if !ok {
			return errors.New("the drain has no deadline")
		}
		drainedWith = time.Until(deadline)
		<-ctx.Done()
		return ctx.Err()
	}}
	const bound = 400 * time.Millisecond
	begun := time.Now()
	center.stopServing([]*http.Server{server.Config}, bound)
	if elapsed := time.Since(begun); elapsed > bound*3/2 {
		t.Errorf("the stop took %v with a bound of %v: the drain got a bound of its own", elapsed, bound)
	}
	if drainedWith > bound/4 {
		t.Errorf("the drain was given %v after the listeners had spent the bound", drainedWith)
	}
}

// TestStopServingDoesNotReportAbandonmentWhenNothingIsInFlight: the drain of the real identity service, given a bound that is
// already spent (a request held the listeners for the whole bound), is nil when no delivery is pending, so no abandonment is logged.
func TestStopServingDoesNotReportAbandonmentWhenNothingIsInFlight(t *testing.T) {
	logs := &lockedBuffer{}
	idle := identity.New(identity.Options{})
	for range 50 {
		(&Center{Logger: observe.NewLogger(logs, slog.LevelInfo), drain: idle.Drain}).stopServing(nil, 0)
	}
	if strings.Contains(logs.String(), "abandoned") {
		t.Errorf("an idle service was reported as abandoned: %s", logs.String())
	}
}

// parsedPackageSources parses the non-test Go files of this package.
func parsedPackageSources(t *testing.T) map[string]*ast.File {
	t.Helper()
	paths, err := filepath.Glob("*.go")
	if err != nil || len(paths) == 0 {
		t.Fatalf("no sources: %v", err)
	}
	files := map[string]*ast.File{}
	for _, path := range paths {
		if strings.HasSuffix(path, "_test.go") {
			continue
		}
		file, parseErr := parser.ParseFile(token.NewFileSet(), path, nil, parser.SkipObjectResolution)
		if parseErr != nil {
			t.Fatal(parseErr)
		}
		files[path] = file
	}
	return files
}

func sourceOf(t *testing.T, node ast.Node) string {
	t.Helper()
	var out bytes.Buffer
	if err := printer.Fprint(&out, token.NewFileSet(), node); err != nil {
		t.Fatal(err)
	}
	return strings.Join(strings.Fields(out.String()), "")
}

// TestTheShutdownWiringOfRunAndComposeIdentityIsPinned pins what no unit test of the server can run without a delivery in flight: the
// drain the center stops with is the Drain of the identity service that composeIdentity built (not a no-op and not another
// service's), it is assigned nowhere else, Run stops through stopServing exactly once with the 5 s of routes.ShutdownMilliseconds,
// and Run closes the center only by the defer it starts with (so the pools outlive the stop).
func TestTheShutdownWiringOfRunAndComposeIdentityIsPinned(t *testing.T) {
	files := parsedPackageSources(t)
	assignments := 0
	var serviceName string
	for path, file := range files {
		ast.Inspect(file, func(node ast.Node) bool {
			assign, ok := node.(*ast.AssignStmt)
			if !ok {
				return true
			}
			for index, lhs := range assign.Lhs {
				if selector, isSelector := lhs.(*ast.SelectorExpr); isSelector && selector.Sel.Name == "drain" && index < len(assign.Rhs) {
					assignments++
					call, isSelectorValue := assign.Rhs[index].(*ast.SelectorExpr)
					if !isSelectorValue || call.Sel.Name != "Drain" || path != "server.go" {
						t.Errorf("%s: drain is assigned %s", path, sourceOf(t, assign.Rhs[index]))
						continue
					}
					serviceName = sourceOf(t, call.X)
				}
			}
			return true
		})
	}
	if assignments != 1 || serviceName == "" {
		t.Fatalf("drain is assigned %d times", assignments)
	}
	// The variable is the one that identity.New initialised in composeIdentity.
	var built string
	ast.Inspect(files["server.go"], func(node ast.Node) bool {
		function, ok := node.(*ast.FuncDecl)
		if !ok || function.Name.Name != "composeIdentity" {
			return true
		}
		ast.Inspect(function.Body, func(inner ast.Node) bool {
			assign, isAssign := inner.(*ast.AssignStmt)
			if !isAssign || len(assign.Lhs) != 1 || len(assign.Rhs) != 1 {
				return true
			}
			if call, isCall := assign.Rhs[0].(*ast.CallExpr); isCall && sourceOf(t, call.Fun) == "identity.New" {
				built = sourceOf(t, assign.Lhs[0])
			}
			return true
		})
		return false
	})
	if built == "" || built != serviceName {
		t.Errorf("c.drain is %s.Drain, but composeIdentity built the service %q with identity.New", serviceName, built)
	}
	stops, closes, deferredCloses := 0, 0, 0
	ast.Inspect(files["server.go"], func(node ast.Node) bool {
		function, ok := node.(*ast.FuncDecl)
		if !ok || function.Name.Name != "Run" {
			return true
		}
		ast.Inspect(function.Body, func(inner ast.Node) bool {
			switch n := inner.(type) {
			case *ast.DeferStmt:
				if sourceOf(t, n.Call) == "center.Close()" {
					deferredCloses++
				}
			case *ast.ExprStmt:
				if call, isCall := n.X.(*ast.CallExpr); isCall {
					switch sourceOf(t, call.Fun) {
					case "center.Close":
						closes++
					case "center.stopServing":
						stops++
						if got := sourceOf(t, call.Args[1]); got != "routes.ShutdownMilliseconds*time.Millisecond" {
							t.Errorf("Run stops with the bound %s", got)
						}
					}
				}
			}
			return true
		})
		return false
	})
	if stops != 1 || closes != 0 || deferredCloses != 1 {
		t.Errorf("Run calls stopServing %d times, closes the center %d times and defers its Close %d times", stops, closes, deferredCloses)
	}
}
