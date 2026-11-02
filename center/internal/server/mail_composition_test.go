// SPDX-License-Identifier: AGPL-3.0-only

package server

import (
	"context"
	"encoding/json"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"connectrpc.com/connect/v2"

	"github.com/ArcForges/Cloud/center/internal/config"
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

// TestARunningCenterWaitsForASlowDeliveryBeforeItStops composes the real pieces of the shutdown: the identity service's drain behind
// stopServing.
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
