// SPDX-License-Identifier: AGPL-3.0-only

package mail

import (
	"context"
	"crypto/tls"
	"flag"
	"fmt"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/ArcForges/Cloud/center/internal/config"
)

// The opt-in probes and the owner-run live send. Every live test here SKIPS unless its explicit local switch is set (the three tests
// that check the gates themselves are not live tests: they run in an ordinary run, except that
// TestTheOptInTestsSkipWithoutTheirSwitch skips itself when a live switch is set), so no CI leg and no ordinary `go test` contacts a
// real service (the ordinary run sends nothing beyond the loopback interface). The four live tests are the only REAL tests of the
// package; everything else is MOCKED.
//
//	ARCFORGES_TEST_POSTMARK_LIVE=1             the public Postmark test token against the real API: nothing is delivered (REAL, contract
//	                                           only: the test token accepts any sender and any stream, so sender, stream and account
//	                                           state are NOT exercised).
//	ARCFORGES_TEST_SES_PROBE_HOST, _PORT       an unauthenticated connection to an SES SMTP endpoint, stopping before AUTH: no
//	                                           credential exists in the process (REAL, capability only).
//	ARCFORGES_TEST_MAIL_LIVE_SEND=1            the owner-run live send: it SENDS ONE REAL MESSAGE through the real adapter. The token, the
//	                                           credentials, the sender and the recipient come from the environment only (the names are
//	                                           listed in docs/center.md) and are never printed. Nothing runs it automatically: it needs a
//	                                           SECOND, deliberately explicit gate that no verification leg sets (the confirmation variable
//	                                           below) and a non-empty -run, so a leg that merely inherits the first variable from a shell
//	                                           that exported it still sends nothing.
//	ARCFORGES_TEST_MAIL_LIVE_SEND_CONFIRM=send-one-real-message

// postmarkPublicTestToken is Postmark's documented public test token, built from its words (it is not a credential).
func postmarkPublicTestToken() string { return strings.Join([]string{"POSTMARK", "API", "TEST"}, "_") }

func TestLivePostmarkContractWithThePublicTestToken(t *testing.T) {
	if os.Getenv("ARCFORGES_TEST_POSTMARK_LIVE") != "1" {
		t.Skip("set ARCFORGES_TEST_POSTMARK_LIVE=1 to run the real Postmark API contract probe (public test token, nothing delivered)")
	}
	good := NewPostmark(PostmarkOptions{Token: config.NewSecret(postmarkPublicTestToken()), From: testFrom, FromName: "ArcForges", Timeout: 20 * time.Second})
	if err := good.Send(context.Background(), testMessage()); err != nil {
		t.Fatalf("the real API refused the draft request with the public test token: %v", err)
	}
	wrong := NewPostmark(PostmarkOptions{Token: config.NewSecret(sentinel("wrong-token")), From: testFrom, Timeout: 20 * time.Second})
	expectFailure(t, wrong.Send(context.Background(), testMessage()), ErrUnauthorized, "http", 401)
}

func TestLiveSESHandshakeStopsBeforeAUTH(t *testing.T) {
	host, port := os.Getenv("ARCFORGES_TEST_SES_PROBE_HOST"), os.Getenv("ARCFORGES_TEST_SES_PROBE_PORT")
	if host == "" || port == "" {
		t.Skip("set ARCFORGES_TEST_SES_PROBE_HOST and ARCFORGES_TEST_SES_PROBE_PORT to run the real SES handshake probe (no credential is used)")
	}
	number, err := strconv.Atoi(port)
	if err != nil {
		t.Fatalf("ARCFORGES_TEST_SES_PROBE_PORT is not a number")
	}
	mode := StartTLS
	if number == 465 || number == 2465 {
		mode = ImplicitTLS
	}
	// No Username and no Password: connect never authenticates, and there is nothing to send. The system roots verify the chain.
	probe := NewSMTP(SMTPOptions{Host: host, Port: number, Mode: mode, From: testFrom, HelloName: "example.test", Timeout: 20 * time.Second})
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	session, err := probe.connect(ctx)
	if err != nil {
		t.Fatalf("the handshake with the endpoint failed: %v", err)
	}
	defer session.close()
	state, ok := session.client.TLSConnectionState()
	if !ok || state.Version < tls.VersionTLS12 || len(state.VerifiedChains) == 0 {
		t.Fatalf("the connection is not TLS 1.2+ with a verified chain: %v %x", ok, state.Version)
	}
	available, mechanisms := session.client.Extension("AUTH")
	if !available || !strings.Contains(" "+strings.ToUpper(mechanisms)+" ", " PLAIN ") {
		t.Fatalf("AUTH PLAIN is not advertised after TLS: %v %q", available, mechanisms)
	}
	modeName := map[SMTPMode]string{StartTLS: "starttls", ImplicitTLS: "implicit"}[mode]
	t.Logf("REAL handshake (capability only): %s, %s, %d verified chains, AUTH %s", modeName, tls.VersionName(state.Version), len(state.VerifiedChains), mechanisms)
}

// liveSend is the owner-run live send: ONE real message through the real adapter. It skips unless the switch and every variable
// it needs are set, names the missing variables (names only), and prints neither the credentials nor the addresses.
func liveSend(t *testing.T, sender Sender) {
	t.Helper()
	message := Message{
		To:      os.Getenv("ARCFORGES_TEST_MAIL_RECIPIENT"),
		Subject: "ArcForges live send test",
		Text:    "This message was sent by the owner-run live send test of the ArcForges center mail adapter.\nNo action is needed.\n",
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if err := sender.Send(ctx, message); err != nil {
		t.Fatalf("the live send failed: %v", err) // a typed error: closed words and numbers only
	}
	t.Log("REAL: the provider accepted one message (delivery to the inbox is checked by the owner)")
}

// liveSendConfirmation is the value of the second gate of the live send.
const liveSendConfirmation = "send-one-real-message"

// liveSendRefusal says why the live send must not run, or "" when all three gates are open: the switch, the confirmation (which no
// verification leg sets) and an explicit -run (the pattern of the test run, "" when none was given).
func liveSendRefusal(getenv func(string) string, run string) string {
	switch {
	case getenv("ARCFORGES_TEST_MAIL_LIVE_SEND") != "1":
		return "set ARCFORGES_TEST_MAIL_LIVE_SEND=1 (and the variables of docs/center.md) to send ONE REAL message through the real adapter"
	case getenv("ARCFORGES_TEST_MAIL_LIVE_SEND_CONFIRM") != liveSendConfirmation:
		return "the live send also needs ARCFORGES_TEST_MAIL_LIVE_SEND_CONFIRM=" + liveSendConfirmation + " (a second gate that verification legs never set)"
	case run == "":
		return "the live send also needs an explicit -run naming the test, so that a run of the whole package never sends"
	}
	return ""
}

// skipper is the part of *testing.T the live-send gates use, so that a test can watch them.
type skipper interface {
	Helper()
	Skip(args ...any)
	Skipf(format string, args ...any)
}

// liveRunPattern is the -run pattern of this test run, "" when none was given.
func liveRunPattern() string {
	if run := flag.Lookup("test.run"); run != nil {
		return run.Value.String()
	}
	return ""
}

// requireLiveEnvironment skips unless the three gates are open (the -run pattern is the one of this test binary) and every named
// variable is set; it returns their values.
func requireLiveEnvironment(t skipper, getenv func(string) string, names ...string) map[string]string {
	t.Helper()
	if reason := liveSendRefusal(getenv, liveRunPattern()); reason != "" {
		t.Skip(reason)
	}
	values := map[string]string{}
	var missing []string
	for _, name := range names {
		if values[name] = getenv(name); values[name] == "" {
			missing = append(missing, name)
		}
	}
	if len(missing) > 0 {
		t.Skipf("the live send also needs: %s", strings.Join(missing, ", "))
	}
	return values
}

func TestLiveSendThroughPostmark(t *testing.T) {
	env := requireLiveEnvironment(t, os.Getenv, "ARCFORGES_TEST_POSTMARK_TOKEN", "ARCFORGES_TEST_MAIL_FROM", "ARCFORGES_TEST_MAIL_RECIPIENT")
	liveSend(t, NewPostmark(PostmarkOptions{Token: config.NewSecret(env["ARCFORGES_TEST_POSTMARK_TOKEN"]), From: env["ARCFORGES_TEST_MAIL_FROM"],
		Stream: os.Getenv("ARCFORGES_TEST_POSTMARK_STREAM"), Timeout: 25 * time.Second}))
}

func TestLiveSendThroughSMTP(t *testing.T) {
	env := requireLiveEnvironment(t, os.Getenv, "ARCFORGES_TEST_SMTP_HOST", "ARCFORGES_TEST_SMTP_PORT", "ARCFORGES_TEST_SMTP_USERNAME", "ARCFORGES_TEST_SMTP_PASSWORD",
		"ARCFORGES_TEST_MAIL_FROM", "ARCFORGES_TEST_MAIL_RECIPIENT")
	port, err := strconv.Atoi(env["ARCFORGES_TEST_SMTP_PORT"])
	if err != nil {
		t.Fatal("ARCFORGES_TEST_SMTP_PORT is not a number")
	}
	mode := StartTLS
	if port == 465 || port == 2465 {
		mode = ImplicitTLS
	}
	liveSend(t, NewSMTP(SMTPOptions{Host: env["ARCFORGES_TEST_SMTP_HOST"], Port: port, Mode: mode, Username: config.NewSecret(env["ARCFORGES_TEST_SMTP_USERNAME"]),
		Password: config.NewSecret(env["ARCFORGES_TEST_SMTP_PASSWORD"]), From: env["ARCFORGES_TEST_MAIL_FROM"], Timeout: 25 * time.Second}))
}

// TestTheLiveSendNeedsAllThreeGates pins the second gate: only the switch, the confirmation and an explicit -run together open it.
func TestTheLiveSendNeedsAllThreeGates(t *testing.T) {
	env := func(values map[string]string) func(string) string {
		return func(name string) string { return values[name] }
	}
	switchOn := map[string]string{"ARCFORGES_TEST_MAIL_LIVE_SEND": "1"}
	both := map[string]string{"ARCFORGES_TEST_MAIL_LIVE_SEND": "1", "ARCFORGES_TEST_MAIL_LIVE_SEND_CONFIRM": liveSendConfirmation}
	for name, c := range map[string]struct {
		values map[string]string
		run    string
		open   bool
	}{
		"nothing":                   {nil, "", false},
		"the switch alone":          {switchOn, "TestLiveSendThroughPostmark", false},
		"the confirmation alone":    {map[string]string{"ARCFORGES_TEST_MAIL_LIVE_SEND_CONFIRM": liveSendConfirmation}, "TestLiveSendThroughPostmark", false},
		"a wrong confirmation":      {map[string]string{"ARCFORGES_TEST_MAIL_LIVE_SEND": "1", "ARCFORGES_TEST_MAIL_LIVE_SEND_CONFIRM": "1"}, "TestLiveSendThroughPostmark", false},
		"the switch with a word":    {map[string]string{"ARCFORGES_TEST_MAIL_LIVE_SEND": "yes", "ARCFORGES_TEST_MAIL_LIVE_SEND_CONFIRM": liveSendConfirmation}, "TestLiveSendThroughPostmark", false},
		"both without a -run":       {both, "", false},
		"both with an explicit run": {both, "TestLiveSendThroughPostmark", true},
	} {
		if reason := liveSendRefusal(env(c.values), c.run); (reason == "") != c.open {
			t.Errorf("%s: refusal %q, open %v", name, reason, c.open)
		}
	}
}

// TestTheOptInTestsSkipWithoutTheirSwitch pins that the ordinary run contacts no real service: with no switch in the environment,
// each live test skips (it runs the four tests and requires that each skipped).
func TestTheOptInTestsSkipWithoutTheirSwitch(t *testing.T) {
	for _, name := range []string{"ARCFORGES_TEST_POSTMARK_LIVE", "ARCFORGES_TEST_SES_PROBE_HOST", "ARCFORGES_TEST_MAIL_LIVE_SEND"} {
		if os.Getenv(name) != "" {
			t.Skipf("%s is set: this run is an opt-in live run", name)
		}
	}

	for _, run := range []func(*testing.T){TestLivePostmarkContractWithThePublicTestToken, TestLiveSESHandshakeStopsBeforeAUTH, TestLiveSendThroughPostmark, TestLiveSendThroughSMTP} {
		skipped := false
		t.Run("", func(inner *testing.T) {
			defer func() { skipped = inner.Skipped() }()
			run(inner)
		})
		if !skipped {
			t.Error("a live test ran without its switch")
		}
	}
}

// recordingSkipper records what the gates of the live send do.
type recordingSkipper struct{ skipped []string }

func (r *recordingSkipper) Helper()          {}
func (r *recordingSkipper) Skip(args ...any) { r.skipped = append(r.skipped, fmt.Sprint(args...)) }
func (r *recordingSkipper) Skipf(format string, args ...any) {
	r.skipped = append(r.skipped, fmt.Sprintf(format, args...))
}

// TestTheLiveSendGlueAppliesTheGatesAndNamesTheMissingVariables: requireLiveEnvironment applies the three gates to the environment it
// is given and to the -run pattern of the running binary (the test sets that flag, as the two live tests have no other way to
// receive it), and a missing variable skips naming the variable and nothing else.
func TestTheLiveSendGlueAppliesTheGatesAndNamesTheMissingVariables(t *testing.T) {
	open := map[string]string{"ARCFORGES_TEST_MAIL_LIVE_SEND": "1", "ARCFORGES_TEST_MAIL_LIVE_SEND_CONFIRM": liveSendConfirmation, "ARCFORGES_TEST_X": "a", "ARCFORGES_TEST_Y": "b"}
	getenv := func(name string) string { return open[name] }
	// liveRunPattern is the flag of the running binary: it follows -test.run.
	run := flag.Lookup("test.run")
	before := run.Value.String()
	defer func() { _ = run.Value.Set(before) }()
	setRun := func(pattern string) {
		t.Helper()
		if err := run.Value.Set(pattern); err != nil || liveRunPattern() != pattern {
			t.Fatalf("liveRunPattern is %q after the flag was set to %q (%v)", liveRunPattern(), pattern, err)
		}
	}
	setRun("^TestLiveSendThroughPostmark$")
	var all recordingSkipper
	values := requireLiveEnvironment(&all, getenv, "ARCFORGES_TEST_X", "ARCFORGES_TEST_Y")
	if len(all.skipped) != 0 || values["ARCFORGES_TEST_X"] != "a" || values["ARCFORGES_TEST_Y"] != "b" {
		t.Fatalf("all three gates are open and the variables are set: skipped %v, values %v", all.skipped, values)
	}
	setRun("")
	var noRun recordingSkipper
	requireLiveEnvironment(&noRun, getenv, "ARCFORGES_TEST_X")
	if len(noRun.skipped) != 1 || !strings.Contains(noRun.skipped[0], "-run") {
		t.Errorf("an empty -run did not skip at the third gate: %v", noRun.skipped)
	}
	setRun("^TestLiveSendThroughPostmark$")
	var missing recordingSkipper
	requireLiveEnvironment(&missing, getenv, "ARCFORGES_TEST_X", "ARCFORGES_TEST_ABSENT")
	if len(missing.skipped) != 1 || !strings.Contains(missing.skipped[0], "ARCFORGES_TEST_ABSENT") || strings.Contains(missing.skipped[0], "ARCFORGES_TEST_X,") {
		t.Errorf("a missing variable: %v", missing.skipped)
	}
}
