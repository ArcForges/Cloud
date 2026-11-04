// SPDX-License-Identifier: AGPL-3.0-only

// Command node-probe is a development stand-in for a node (AF-CTR-04 E3; the Plan task's fakes_allowed "center/cmd/node-probe"): it
// signs in to a center as a node does, through the browser sign-in (its own loopback receiver) or the device-code sign-in, over the
// center's public gRPC-Web routes, with a software ECDSA P-256 key (center/internal/nodetest). It is MOCKED: it is not the ArcForges
// node (parts N1, N2 and X prove that one), and it never claims an end-to-end result for it. It is never part of the center's image
// (.dockerignore keeps it out of the Docker context, so no release profile can hash it).
//
// It works with the browser flow node-approve (eng/verification/browser/node-approve.ts) through a handshake directory: it writes
// <case>.begin.json (what a person compares on the review page: the URL to open, the user code, the key's fingerprint, the node's
// description; no secret), waits for the approval, and writes <case>.result.json (the outcome of each step and the instant of each of
// its requests; no token, code, device code or proof). After the approval it checks the credentials' shape, refreshes once, waits,
// refreshes again (a center that slept answers it), presents the spent refresh token (a reuse: the center revokes the family) and the
// current one (refused as revoked); a device sign-in also polls its device code again (COMPLETED without credentials).
//
//	go run ./cmd/node-probe -center <public base URL> -flow pkce|device -dir <handshake dir> -case <name>
//	    [-name <node name>] [-decision approve|deny] [-idle 75s] [-poll-floor 10s] [-timeout 9m]
//
// A center behind a throwaway certificate authority (the local rehearsal) is trusted through SSL_CERT_FILE.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"sync"
	"time"

	fleetv1 "github.com/ArcForges/Contracts/go/arcforges/fleet/v1"
	foundationv1 "github.com/ArcForges/Contracts/go/arcforges/foundation/v1"
	nodev1 "github.com/ArcForges/Contracts/go/arcforges/node/v1"
	"google.golang.org/protobuf/proto"

	"github.com/ArcForges/Cloud/center/internal/fleet"
	"github.com/ArcForges/Cloud/center/internal/nodetest"
	"github.com/ArcForges/Cloud/center/internal/platform"
)

const service = "/arcforges.fleet.v1.NodeEnrollmentService/"

// options are the probe's flags.
type options struct {
	center    string
	flow      string
	dir       string
	caseName  string
	name      string
	decision  string
	idle      time.Duration
	pollFloor time.Duration
	timeout   time.Duration
}

var casePattern = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,62}$`)

func parse(args []string, stderr io.Writer) (options, error) {
	set := flag.NewFlagSet("node-probe", flag.ContinueOnError)
	set.SetOutput(stderr)
	var o options
	set.StringVar(&o.center, "center", "", "the center's public base URL (https; http only on this machine)")
	set.StringVar(&o.flow, "flow", "", "pkce (the browser sign-in) or device (the device-code sign-in)")
	set.StringVar(&o.dir, "dir", "", "the handshake directory shared with node-approve")
	set.StringVar(&o.caseName, "case", "", "the case name: lower-case letters, digits and hyphens")
	set.StringVar(&o.name, "name", "", "the node's name (default node-probe-<time>-<case>)")
	set.StringVar(&o.decision, "decision", "approve", "what the browser is asked to decide: approve or deny")
	set.DurationVar(&o.idle, "idle", 75*time.Second, "the wait between the two refreshes (over a minute lets a hosted Container sleep)")
	set.DurationVar(&o.pollFloor, "poll-floor", 10*time.Second, "the shortest wait between two polls of a device sign-in")
	set.DurationVar(&o.timeout, "timeout", 9*time.Minute, "the longest wait for the decision")
	if err := set.Parse(args); err != nil {
		return options{}, err
	}
	center, err := url.Parse(o.center)
	switch {
	case err != nil || center.Scheme != "https" && !(center.Scheme == "http" && (center.Hostname() == "localhost" || center.Hostname() == "127.0.0.1")) ||
		center.User != nil || center.RawQuery != "" || center.Fragment != "" || strings.HasSuffix(o.center, "/"):
		return options{}, errors.New("-center is an https URL without a query, a fragment or a trailing slash (http only on this machine)")
	case o.flow != "pkce" && o.flow != "device":
		return options{}, errors.New("-flow is pkce or device")
	case o.dir == "":
		return options{}, errors.New("-dir is required")
	case !casePattern.MatchString(o.caseName):
		return options{}, errors.New("-case is 1 to 63 lower-case letters, digits and hyphens")
	case o.decision != "approve" && o.decision != "deny":
		return options{}, errors.New("-decision is approve or deny")
	case o.pollFloor < time.Second || o.idle < 0 || o.timeout < time.Minute:
		return options{}, errors.New("-poll-floor is at least 1s, -idle not negative, -timeout at least 1m")
	}
	if o.name == "" {
		// One name per case and run: the run's clean-up finds each probe's device by its name.
		o.name = "node-probe-" + time.Now().UTC().Format("150405") + "-" + o.caseName
		if len(o.name) > 64 {
			o.name = o.name[:64]
		}
	}
	return o, nil
}

// begin is the handshake file the probe writes when the person can act: nothing in it is a secret (the user code and the
// fingerprint are shown to people by design).
type begin struct {
	Case        string `json:"case"`
	Kind        string `json:"kind"`
	URL         string `json:"url"`
	UserCode    string `json:"userCode,omitempty"`
	Fingerprint string `json:"fingerprint"`
	Name        string `json:"name"`
	OS          string `json:"os"`
	Arch        string `json:"arch"`
	Version     string `json:"version"`
	CenterHost  string `json:"centerHost"`
	Decision    string `json:"decision"`
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
	Kind     string      `json:"kind"`
	Passed   bool        `json:"passed"`
	Steps    []step      `json:"steps"`
	Requests []time.Time `json:"requests"`
}

// probe is one run.
type probe struct {
	o      options
	node   *nodetest.Node
	client nodetest.Client
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

// call sends one request and decodes its reply message; a transport failure is an error.
func call[Response proto.Message](p *probe, method string, request proto.Message, response Response) (Response, error) {
	p.mu.Lock()
	p.result.Requests = append(p.result.Requests, time.Now().UTC())
	p.mu.Unlock()
	reply, err := p.client.Post(service+method, request, "")
	if err != nil {
		return response, err
	}
	if reply.HTTP != http.StatusOK || reply.Status != "0" || reply.Body == nil {
		return response, fmt.Errorf("%s answered HTTP %d, gRPC status %q", method, reply.HTTP, reply.Status)
	}
	return response, proto.Unmarshal(reply.Body, response)
}

// refusal is the CATEGORY/code of an ArcError, or "" for none.
func refusal(value *foundationv1.ArcError) string {
	if value == nil {
		return ""
	}
	return strings.TrimPrefix(value.GetCategory().String(), "ERROR_CATEGORY_") + "/" + value.GetCode()
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

func (p *probe) beginFile(kind, address, userCode string) error {
	center, _ := url.Parse(p.o.center)
	osName, archName := "Linux", "x64"
	if p.node.OS == nodev1.OsFamily_OS_FAMILY_WINDOWS {
		osName = "Windows"
	}
	if p.node.Arch == nodev1.CpuArchitecture_CPU_ARCHITECTURE_ARM64 {
		archName = "Arm64"
	}
	return p.write(p.o.caseName+".begin.json", begin{Case: p.o.caseName, Kind: kind, URL: address, UserCode: userCode, Fingerprint: fleet.Fingerprint(p.node.PublicKey),
		Name: p.node.Name, OS: osName, Arch: archName, Version: p.node.Version, CenterHost: center.Host, Decision: p.o.decision})
}

// credentials checks a delivered credential's shape and returns its refresh token.
func (p *probe) credentials(credentials *fleetv1.NodeCredentials) (string, bool) {
	ok := strings.HasPrefix(credentials.GetAccessToken(), "afa1.") && strings.HasPrefix(credentials.GetRefreshToken(), "afr1.") &&
		credentials.GetAccessLifetimeMs() > 0 && credentials.GetSessionExpiresAt().GetUnixSeconds() > time.Now().Unix() &&
		len(credentials.GetInstallationId().GetValue()) == 16
	return credentials.GetRefreshToken(), p.record("credentials delivered", ok, fmt.Sprintf("command keys %d, entitlement keys %d", len(credentials.GetCommandKeys()),
		len(credentials.GetEntitlementKeys())))
}

// refresh rotates a refresh token; want is "" for a rotation, else the refusal expected.
func (p *probe) refresh(name, token, want string) (string, bool) {
	reply, err := call(p, "RefreshNodeSession", &fleetv1.NodeEnrollmentServiceRefreshNodeSessionRequest{Meta: &foundationv1.RequestMeta{}, RefreshToken: proto.String(token)},
		&fleetv1.NodeEnrollmentServiceRefreshNodeSessionResponse{})
	if err != nil {
		return "", p.record(name, false, err.Error())
	}
	got := refusal(reply.GetError())
	if want != "" {
		return "", p.record(name, got == want, "refused "+got)
	}
	next := reply.GetValue().GetRefreshToken()
	return next, p.record(name, got == "" && strings.HasPrefix(next, "afr1.") && next != token, "rotated "+got)
}

// afterCredentials runs the refresh, the idle refresh and the reuse checks; reuse is the case's own reuse step, run before the last
// refresh.
func (p *probe) afterCredentials(first string, reuse func(current string) bool) bool {
	second, ok := p.refresh("refresh", first, "")
	if !ok {
		return false
	}
	if p.o.idle > 0 {
		_, _ = fmt.Fprintf(p.out, "waiting %s before the next refresh\n", p.o.idle)
		time.Sleep(p.o.idle)
	}
	third, ok := p.refresh("refresh after idle", second, "")
	if !ok {
		return false
	}
	if !reuse(third) {
		return false
	}
	_, ok = p.refresh("the current token after the reuse", third, "AUTHENTICATION/credential_revoked")
	return ok
}

func run(args []string, stdout, stderr io.Writer) int {
	o, err := parse(args, stderr)
	if err != nil {
		_, _ = fmt.Fprintln(stderr, "node-probe:", err)
		return 2
	}
	node, err := nodetest.New()
	if err != nil {
		_, _ = fmt.Fprintln(stderr, "node-probe:", err)
		return 1
	}
	node.Name = o.name
	if runtime.GOOS == "windows" {
		node.OS = nodev1.OsFamily_OS_FAMILY_WINDOWS
	}
	if runtime.GOARCH == "arm64" {
		node.Arch = nodev1.CpuArchitecture_CPU_ARCHITECTURE_ARM64
	}
	p := &probe{o: o, node: node, client: nodetest.Client{URL: o.center}, out: stdout, result: result{Case: o.caseName, Kind: o.flow}}
	if err = os.MkdirAll(o.dir, 0o700); err != nil {
		_, _ = fmt.Fprintln(stderr, "node-probe:", err)
		return 1
	}
	passed := false
	if o.flow == "pkce" {
		passed = p.browser()
	} else {
		passed = p.device()
	}
	p.result.Passed = passed
	if err = p.write(o.caseName+".result.json", p.result); err != nil {
		_, _ = fmt.Fprintln(stderr, "node-probe:", err)
		return 1
	}
	if !passed {
		_, _ = fmt.Fprintln(stdout, "FAILED")
		return 1
	}
	_, _ = fmt.Fprintln(stdout, "PASSED")
	return 0
}

func main() { os.Exit(run(os.Args[1:], os.Stdout, os.Stderr)) }

// browser is the browser sign-in: Begin with the probe's loopback receiver, the person's decision, the receiver's one request, then
// Complete with the code, the verifier and the key proof.
func (p *probe) browser() bool {
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		return p.record("bind the loopback receiver", false, err.Error())
	}
	defer func() { _ = listener.Close() }()
	signIn := nodetest.NewSignIn()
	signIn.RedirectURI = fmt.Sprintf("http://127.0.0.1:%d/callback", listener.Addr().(*net.TCPAddr).Port)
	begun, err := call(p, "BeginNodeSignIn", p.node.BeginRequest(signIn), &fleetv1.NodeEnrollmentServiceBeginNodeSignInResponse{})
	if err != nil || begun.GetError() != nil {
		return p.record("begin", false, fmt.Sprint(err, refusal(begun.GetError())))
	}
	flowRaw := begun.GetValue().GetFlowId().GetValue()
	var flowID platform.ID
	copy(flowID[:], flowRaw)
	derived := nodetest.DerivedAuthorizeURL(p.o.center, flowRaw)
	if !p.record("begin", begun.GetValue().GetAuthorizeUrl() == derived, "the authorize URL is the derived one") {
		return false
	}
	if err = p.beginFile("pkce", derived, ""); err != nil {
		return p.record("write the begin file", false, err.Error())
	}
	_, _ = fmt.Fprintln(p.out, "waiting for the browser at the loopback receiver")
	redirect, err := receive(listener, signIn.State, p.o.timeout)
	if err != nil {
		return p.record("the browser came back", false, err.Error())
	}
	code, err := signIn.LoopbackCode(redirect)
	if p.o.decision == "deny" {
		return p.record("the browser came back", err != nil && strings.Contains(err.Error(), "access_denied"), "denied")
	}
	if !p.record("the browser came back", err == nil, "with a code") {
		return false
	}
	complete := p.node.CompleteRequest(flowID, code, signIn, p.node.CompleteProof(p.o.center, flowID, code))
	completed, err := call(p, "CompleteNodeSignIn", complete, &fleetv1.NodeEnrollmentServiceCompleteNodeSignInResponse{})
	if err != nil || completed.GetError() != nil {
		return p.record("complete", false, fmt.Sprint(err, refusal(completed.GetError())))
	}
	first, ok := p.credentials(completed.GetValue().GetCredentials())
	if !ok {
		return false
	}
	return p.afterCredentials(first, func(string) bool {
		_, reused := p.refresh("a reused refresh token", first, "AUTHENTICATION/credential_revoked")
		return reused
	})
}

// receive serves the loopback receiver until one valid request arrives: GET /callback for exactly 127.0.0.1:<port> with exactly
// code and state (or error and state) and the probe's state. Any other request is answered 400; after 20 of them the receiver gives up.
func receive(listener net.Listener, state string, timeout time.Duration) (string, error) {
	port := listener.Addr().(*net.TCPAddr).Port
	host := fmt.Sprintf("127.0.0.1:%d", port)
	found := make(chan string, 1)
	var mu sync.Mutex
	bad := 0
	server := &http.Server{ReadHeaderTimeout: 10 * time.Second, Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		query := r.URL.Query()
		keys := len(query)
		valid := r.Method == http.MethodGet && r.Host == host && r.URL.Path == "/callback" && keys == 2 && len(query["state"]) == 1 && query.Get("state") == state &&
			(len(query["code"]) == 1 || len(query["error"]) == 1)
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.Header().Set("Cache-Control", "no-store")
		if !valid {
			mu.Lock()
			bad++
			mu.Unlock()
			w.WriteHeader(http.StatusBadRequest)
			_, _ = io.WriteString(w, "This is not a sign-in result for this node.\n")
			return
		}
		_, _ = io.WriteString(w, "The sign-in result reached the node. You can close this tab.\n")
		select {
		case found <- "http://" + host + r.URL.RequestURI():
		default:
		}
	})}
	go func() { _ = server.Serve(listener) }()
	defer func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = server.Shutdown(ctx)
	}()
	deadline := time.After(timeout)
	ticker := time.NewTicker(200 * time.Millisecond)
	defer ticker.Stop()
	for {
		select {
		case redirect := <-found:
			return redirect, nil
		case <-deadline:
			return "", errors.New("no browser came back in time")
		case <-ticker.C:
			mu.Lock()
			many := bad >= 20
			mu.Unlock()
			if many {
				return "", errors.New("twenty requests that were no sign-in result")
			}
		}
	}
}

// device is the device-code sign-in: Start, the person's decision on /activate, polls at the center's interval (never faster than
// -poll-floor), then the credentials and a second poll of the same device code.
func (p *probe) device() bool {
	started, err := call(p, "StartDeviceAuthorization", p.node.StartRequest(), &fleetv1.NodeEnrollmentServiceStartDeviceAuthorizationResponse{})
	if err != nil || started.GetError() != nil {
		return p.record("start", false, fmt.Sprint(err, refusal(started.GetError())))
	}
	authorization := started.GetValue().GetAuthorization()
	userCode := authorization.GetUserCode()
	complete := nodetest.DerivedVerificationURIComplete(p.o.center, userCode)
	if !p.record("start", authorization.GetVerificationUri() == nodetest.DerivedVerificationURI(p.o.center) &&
		authorization.GetVerificationUriComplete() == complete, "the verification URIs are the derived ones") {
		return false
	}
	if err = p.beginFile("device", complete, nodetest.DisplayUserCode(userCode)); err != nil {
		return p.record("write the begin file", false, err.Error())
	}
	deviceCode := authorization.GetDeviceCode()
	interval := time.Duration(authorization.GetIntervalMs()) * time.Millisecond
	deadline := time.Now().Add(p.o.timeout)
	_, _ = fmt.Fprintln(p.out, "polling for the decision")
	var credentials *fleetv1.NodeCredentials
	for credentials == nil {
		if time.Now().After(deadline) {
			return p.record("the decision", false, "none in time")
		}
		time.Sleep(max(interval, p.o.pollFloor))
		polled, err := call(p, "PollDeviceAuthorization", p.node.PollRequest(deviceCode, p.node.PollProof(p.o.center, deviceCode)),
			&fleetv1.NodeEnrollmentServicePollDeviceAuthorizationResponse{})
		if err != nil || polled.GetError() != nil {
			return p.record("poll", false, fmt.Sprint(err, refusal(polled.GetError())))
		}
		value := polled.GetValue()
		if value.GetIntervalMs() > 0 {
			interval = time.Duration(value.GetIntervalMs()) * time.Millisecond
		}
		switch value.GetState() {
		case fleetv1.DeviceAuthorizationState_DEVICE_AUTHORIZATION_STATE_PENDING, fleetv1.DeviceAuthorizationState_DEVICE_AUTHORIZATION_STATE_SLOW_DOWN:
		case fleetv1.DeviceAuthorizationState_DEVICE_AUTHORIZATION_STATE_APPROVED:
			if p.o.decision == "deny" {
				return p.record("the decision", false, "approved, a denial was asked for")
			}
			credentials = value.GetCredentials()
		case fleetv1.DeviceAuthorizationState_DEVICE_AUTHORIZATION_STATE_DENIED:
			return p.record("the decision", p.o.decision == "deny", "denied")
		default:
			return p.record("the decision", false, value.GetState().String())
		}
	}
	p.record("the decision", true, "approved")
	first, ok := p.credentials(credentials)
	if !ok {
		return false
	}
	return p.afterCredentials(first, func(string) bool {
		polled, err := call(p, "PollDeviceAuthorization", p.node.PollRequest(deviceCode, p.node.PollProof(p.o.center, deviceCode)),
			&fleetv1.NodeEnrollmentServicePollDeviceAuthorizationResponse{})
		if err != nil {
			return p.record("a reused device code", false, err.Error())
		}
		value := polled.GetValue()
		return p.record("a reused device code", polled.GetError() == nil && value.GetState() == fleetv1.DeviceAuthorizationState_DEVICE_AUTHORIZATION_STATE_COMPLETED &&
			value.GetCredentials() == nil, "answered "+value.GetState().String())
	})
}
