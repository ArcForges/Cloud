// SPDX-License-Identifier: AGPL-3.0-only

package mail

import (
	"context"
	"crypto/tls"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/ArcForges/Cloud/center/internal/config"
)

// The opt-in probes and the owner-run live send. Every test here SKIPS unless its explicit local switch is set, so no CI leg and no
// ordinary `go test` reaches the network. They are the only REAL tests of the package; everything else is MOCKED.
//
//	ARCFORGES_TEST_POSTMARK_LIVE=1             the public Postmark test token against the real API: nothing is delivered (REAL, contract
//	                                           only: the test token accepts any sender and any stream, so sender, stream and account
//	                                           state are NOT exercised).
//	ARCFORGES_TEST_SES_PROBE_HOST, _PORT       an unauthenticated connection to an SES SMTP endpoint, stopping before AUTH: no
//	                                           credential exists in the process (REAL, capability only).
//	ARCFORGES_TEST_MAIL_LIVE_SEND=1            the owner-run live send: it SENDS ONE REAL MESSAGE through the real adapter. The token, the
//	                                           credentials, the sender and the recipient come from the environment only (the names are
//	                                           listed in docs/center.md) and are never printed. Nothing runs it automatically.

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
	t.Logf("REAL handshake (capability only): mode %d, TLS %x, chains %d, AUTH %s", mode, state.Version, len(state.VerifiedChains), mechanisms)
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

func requireLiveEnvironment(t *testing.T, names ...string) map[string]string {
	t.Helper()
	if os.Getenv("ARCFORGES_TEST_MAIL_LIVE_SEND") != "1" {
		t.Skip("set ARCFORGES_TEST_MAIL_LIVE_SEND=1 (and the variables of docs/center.md) to send ONE REAL message through the real adapter")
	}
	values := map[string]string{}
	var missing []string
	for _, name := range names {
		if values[name] = os.Getenv(name); values[name] == "" {
			missing = append(missing, name)
		}
	}
	if len(missing) > 0 {
		t.Skipf("the live send also needs: %s", strings.Join(missing, ", "))
	}
	return values
}

func TestLiveSendThroughPostmark(t *testing.T) {
	env := requireLiveEnvironment(t, "ARCFORGES_TEST_POSTMARK_TOKEN", "ARCFORGES_TEST_MAIL_FROM", "ARCFORGES_TEST_MAIL_RECIPIENT")
	liveSend(t, NewPostmark(PostmarkOptions{Token: config.NewSecret(env["ARCFORGES_TEST_POSTMARK_TOKEN"]), From: env["ARCFORGES_TEST_MAIL_FROM"],
		Stream: os.Getenv("ARCFORGES_TEST_POSTMARK_STREAM"), Timeout: 25 * time.Second}))
}

func TestLiveSendThroughSMTP(t *testing.T) {
	env := requireLiveEnvironment(t, "ARCFORGES_TEST_SMTP_HOST", "ARCFORGES_TEST_SMTP_PORT", "ARCFORGES_TEST_SMTP_USERNAME", "ARCFORGES_TEST_SMTP_PASSWORD",
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

// TestTheOptInTestsSkipWithoutTheirSwitch pins that the ordinary run reaches no network: with no switch in the environment, each
// live test skips (checked by running the helper that decides, not the tests themselves).
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
