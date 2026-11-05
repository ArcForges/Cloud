// SPDX-License-Identifier: AGPL-3.0-only

// Command mobile-probe is MobileProbe (AF-CTR-04 part M; the Plan task's fakes_allowed "MobileProbe: center/internal/mobiletest and
// center/cmd/mobile-probe"): a MOCKED development stand-in of the ArcForges Android app for the mobile native authorization. It begins
// a flow over the center's native JSON route, as the app does (a fresh verifier and state, the authorizeUrl required byte-equal to
// the one it derives from -center), and works with the browser flow mobile-approve (eng/verification/browser/mobile-approve.ts)
// through a handshake directory: it writes <case>.begin.json (the URL to open and the decision the browser is asked to take; no
// secret), waits for <case>.link.json (the callback link the browser read from the done page's "Open the ArcForges app" link: the
// MOCKED stand-in of a verified App Link handing the fragment to the app; it holds the one-use code, so the probe deletes it as soon
// as it is read), checks the callback's state and issuer against its pending attempt, redeems the code per scenario and writes
// <case>.result.json (the outcome of each step, the instant of each request and the device ID of each delivered session, so that the
// browser flow's clean-up revokes exactly those devices; no token, code, verifier or state).
//
// Scenarios: approve (token, then IdentityService.RefreshSession once), deny (the callback says access_denied), reuse (token, then the
// same code again: CONFLICT/code_reused, and the delivered family is refused at refresh), wrong-verifier (a token request with another
// verifier: unauthenticated; then the right one: code_reused, the flow was ended).
//
//	go run ./cmd/mobile-probe -center <public base URL> -dir <handshake dir> -case <name> [-scenario approve|deny|reuse|wrong-verifier]
//	    [-redirect <debug scheme>:/callback] [-timeout 9m]
//
// It is not the Android app (AF-AND-01 proves that one: App Link verification on a device, the same-host hand-off, the fragment in the
// intent), and it is never part of the center's image (.dockerignore keeps it out of the Docker context).
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"

	foundationv1 "github.com/ArcForges/Contracts/go/arcforges/foundation/v1"
	publicapiv1 "github.com/ArcForges/Contracts/go/arcforges/publicapi/v1"
	"google.golang.org/protobuf/proto"

	"github.com/ArcForges/Cloud/center/internal/mobiletest"
	"github.com/ArcForges/Cloud/center/internal/platform"
)

// options are the probe's flags.
type options struct {
	center   string
	dir      string
	caseName string
	scenario string
	redirect string
	timeout  time.Duration
}

var casePattern = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,62}$`)

func parse(args []string, stderr io.Writer) (options, error) {
	set := flag.NewFlagSet("mobile-probe", flag.ContinueOnError)
	set.SetOutput(stderr)
	var o options
	set.StringVar(&o.center, "center", "", "the center's public base URL (https; http only on this machine)")
	set.StringVar(&o.dir, "dir", "", "the handshake directory shared with mobile-approve")
	set.StringVar(&o.caseName, "case", "", "the case name: lower-case letters, digits and hyphens")
	set.StringVar(&o.scenario, "scenario", "approve", "approve, deny, reuse or wrong-verifier")
	set.StringVar(&o.redirect, "redirect", "", "a debug build's redirect <scheme>:/callback (default: the release App Link of -center)")
	set.DurationVar(&o.timeout, "timeout", 9*time.Minute, "the longest wait for the browser's link")
	if err := set.Parse(args); err != nil {
		return options{}, err
	}
	center, err := url.Parse(o.center)
	switch {
	case err != nil || center.Scheme != "https" && !(center.Scheme == "http" && (center.Hostname() == "localhost" || center.Hostname() == "127.0.0.1")) ||
		center.User != nil || center.RawQuery != "" || center.Fragment != "" || strings.HasSuffix(o.center, "/"):
		return options{}, errors.New("-center is an https URL without a query, a fragment or a trailing slash (http only on this machine)")
	case o.dir == "":
		return options{}, errors.New("-dir is required")
	case !casePattern.MatchString(o.caseName):
		return options{}, errors.New("-case is 1 to 63 lower-case letters, digits and hyphens")
	case o.scenario != "approve" && o.scenario != "deny" && o.scenario != "reuse" && o.scenario != "wrong-verifier":
		return options{}, errors.New("-scenario is approve, deny, reuse or wrong-verifier")
	case o.redirect != "" && !strings.HasSuffix(o.redirect, ":/callback"):
		return options{}, errors.New("-redirect is <scheme>:/callback")
	case o.timeout < time.Minute:
		return options{}, errors.New("-timeout is at least 1m")
	}
	return o, nil
}

// begin is the handshake file the probe writes when the person can act: nothing in it is a secret.
type begin struct {
	Case         string `json:"case"`
	Scenario     string `json:"scenario"`
	AuthorizeURL string `json:"authorizeUrl"`
	Decision     string `json:"decision"`
	CenterHost   string `json:"centerHost"`
	Platform     string `json:"platform"`
	AppVersion   string `json:"appVersion"`
}

// link is the handshake file the browser flow writes: the callback link of the done page.
type link struct {
	Link string `json:"link"`
}

// step is one checked step of the run.
type step struct {
	Name    string `json:"name"`
	OK      bool   `json:"ok"`
	Outcome string `json:"outcome"`
}

// result is the handshake file the probe writes at the end.
type result struct {
	Case     string      `json:"case"`
	Scenario string      `json:"scenario"`
	Passed   bool        `json:"passed"`
	Steps    []step      `json:"steps"`
	Requests []time.Time `json:"requests"`
	// DeviceIDs are the devices of the delivered sessions (the token replies' device.deviceId; not secret), for the clean-up.
	DeviceIDs []string `json:"deviceIds"`
}

// deviceIDShape is a device ID as the token reply writes it: a canonical lower-case UUID.
var deviceIDShape = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)

// probe is one run.
type probe struct {
	o      options
	app    *mobiletest.App
	out    io.Writer
	mu     sync.Mutex
	result result
}

func (p *probe) record(name string, ok bool, outcome string) bool {
	p.result.Steps = append(p.result.Steps, step{Name: name, OK: ok, Outcome: outcome})
	status := "ok"
	if !ok {
		status = "FAILED"
	}
	_, _ = fmt.Fprintf(p.out, "%s: %s (%s)\n", name, status, outcome)
	return ok
}

func (p *probe) requested() {
	p.mu.Lock()
	p.result.Requests = append(p.result.Requests, time.Now().UTC())
	p.mu.Unlock()
}

func (p *probe) write(name string, value any) error {
	data, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return err
	}
	temporary := filepath.Join(p.o.dir, "."+name+".tmp")
	if err = os.WriteFile(temporary, append(data, '\n'), 0o600); err != nil {
		return err
	}
	return os.Rename(temporary, filepath.Join(p.o.dir, name))
}

// waitLink waits for the browser's link file, reads it and removes it at once (it holds the one-use code).
func (p *probe) waitLink(ctx context.Context) (string, error) {
	path := filepath.Join(p.o.dir, p.o.caseName+".link.json")
	for {
		data, err := os.ReadFile(path)
		if err == nil {
			_ = os.Remove(path)
			var found link
			if err = json.Unmarshal(data, &found); err != nil {
				return "", errors.New("the link file is not JSON")
			}
			return found.Link, nil
		}
		select {
		case <-ctx.Done():
			return "", errors.New("no link from the browser in time")
		case <-time.After(500 * time.Millisecond):
		}
	}
}

func outcomeOf(reply mobiletest.Reply) string {
	if refusal := reply.Refusal(); refusal != "/" && refusal != "" {
		return fmt.Sprintf("HTTP %d %s", reply.Status, refusal)
	}
	return fmt.Sprintf("HTTP %d", reply.Status)
}

// token redeems a code and checks a session reply's shape; it returns the refresh token of a success.
func (p *probe) token(ctx context.Context, name string, attempt mobiletest.Attempt, code, verifier, want string) (string, bool) {
	p.requested()
	reply, err := p.app.TokenWith(ctx, attempt, code, verifier)
	if err != nil {
		return "", p.record(name, false, "transport: "+err.Error())
	}
	if want != "" {
		return "", p.record(name, reply.Refusal() == want, outcomeOf(reply))
	}
	scope, _ := reply.JSON["scope"].(string)
	purpose, _ := reply.JSON["purpose"].(string)
	refresh, _ := reply.JSON["refreshToken"].(string)
	device, _ := reply.JSON["device"].(map[string]any)
	platformName, _ := device["platform"].(string)
	deviceID, _ := device["deviceId"].(string)
	ok := reply.Status == http.StatusOK && scope == "account" && purpose == "authenticate" && refresh != "" && platformName == "android"
	if reply.Status == http.StatusOK && deviceIDShape.MatchString(deviceID) {
		p.result.DeviceIDs = append(p.result.DeviceIDs, deviceID)
	} else if reply.Status == http.StatusOK {
		ok = false
	}
	return refresh, p.record(name, ok, outcomeOf(reply)+" scope "+scope+" purpose "+purpose+" device "+platformName)
}

// refresh calls IdentityService.RefreshSession over the center's public gRPC-Web route with the installation's refresh token.
func (p *probe) refresh(name, token, want string) bool {
	p.requested()
	request := &publicapiv1.IdentityServiceRefreshSessionRequest{Meta: &foundationv1.RequestMeta{}, RefreshToken: proto.String(token),
		InstallationId: &foundationv1.Id{Value: p.app.InstallationID[:]}}
	response := &publicapiv1.IdentityServiceRefreshSessionResponse{}
	err := grpcWeb(p.o.center+"/arcforges.publicapi.v1.IdentityService/RefreshSession", request, response)
	if err != nil {
		return p.record(name, false, "transport: "+err.Error())
	}
	if failure := response.GetError(); failure != nil {
		got := strings.TrimPrefix(failure.GetCategory().String(), "ERROR_CATEGORY_") + "/" + failure.GetCode()
		return p.record(name, want != "" && got == want, got)
	}
	return p.record(name, want == "" && response.GetValue().GetSession().GetRefreshToken() != "", "refreshed")
}

func (p *probe) run(ctx context.Context) bool {
	p.requested()
	attempt, reply, err := p.app.Begin(ctx)
	if err != nil || reply.Status != http.StatusOK {
		outcome := outcomeOf(reply)
		if err != nil {
			outcome = err.Error()
		}
		return p.record("begin", false, outcome)
	}
	p.record("begin", true, "the authorizeUrl is the derived one")
	decision := "approve"
	if p.o.scenario == "deny" {
		decision = "deny"
	}
	center, _ := url.Parse(p.o.center)
	if err = p.write(p.o.caseName+".begin.json", begin{Case: p.o.caseName, Scenario: p.o.scenario, AuthorizeURL: attempt.AuthorizeURL, Decision: decision,
		CenterHost: center.Host, Platform: p.app.Platform, AppVersion: p.app.AppVersion}); err != nil {
		return p.record("handshake", false, err.Error())
	}
	waiting, cancel := context.WithTimeout(ctx, p.o.timeout)
	defer cancel()
	address, err := p.waitLink(waiting)
	if err != nil {
		return p.record("link", false, err.Error())
	}
	callback, err := p.app.ParseCallback(address, attempt)
	if err != nil {
		return p.record("callback", false, err.Error())
	}
	if p.o.scenario == "deny" {
		return p.record("callback", callback.Denied, "access_denied, state and iss checked")
	}
	if !p.record("callback", callback.Code != "", "a code, state and iss checked") {
		return false
	}
	switch p.o.scenario {
	case "approve":
		refresh, ok := p.token(ctx, "token", attempt, callback.Code, attempt.Verifier, "")
		return ok && p.refresh("refresh", refresh, "")
	case "reuse":
		refresh, ok := p.token(ctx, "token", attempt, callback.Code, attempt.Verifier, "")
		ok = ok && p.token2(ctx, "token again", attempt, callback.Code, attempt.Verifier, "CONFLICT/code_reused")
		return ok && p.refresh("refresh of the revoked family", refresh, "AUTHENTICATION/credential_revoked")
	case "wrong-verifier":
		wrong, _ := mobiletest.NewVerifier()
		ok := p.token2(ctx, "token with another verifier", attempt, callback.Code, wrong, "AUTHENTICATION/unauthenticated")
		return ok && p.token2(ctx, "token with the right verifier after", attempt, callback.Code, attempt.Verifier, "CONFLICT/code_reused")
	}
	return false
}

// token2 is a token request that must be refused with want.
func (p *probe) token2(ctx context.Context, name string, attempt mobiletest.Attempt, code, verifier, want string) bool {
	_, ok := p.token(ctx, name, attempt, code, verifier, want)
	return ok
}

func run(args []string, stdout, stderr io.Writer) int {
	o, err := parse(args, stderr)
	if err != nil {
		_, _ = fmt.Fprintln(stderr, err)
		return 2
	}
	redirect := o.redirect
	client := mobiletest.ClientDebug
	if redirect == "" {
		center, _ := url.Parse(o.center)
		redirect, client = center.Scheme+"://"+center.Host+"/app/callback", mobiletest.ClientRelease
	}
	app := &mobiletest.App{Center: o.center, ClientID: client, Redirect: redirect, InstallationID: platform.NewID(), Platform: "android-15",
		AppVersion: "0.0.0-mobile-probe"}
	p := &probe{o: o, app: app, out: stdout, result: result{Case: o.caseName, Scenario: o.scenario, DeviceIDs: []string{}}}
	ctx, cancel := context.WithTimeout(context.Background(), o.timeout+2*time.Minute)
	defer cancel()
	p.result.Passed = p.run(ctx)
	if err = p.write(o.caseName+".result.json", p.result); err != nil {
		_, _ = fmt.Fprintln(stderr, err)
		return 1
	}
	if !p.result.Passed {
		return 1
	}
	return 0
}

func main() { os.Exit(run(os.Args[1:], os.Stdout, os.Stderr)) }
