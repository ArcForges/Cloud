// SPDX-License-Identifier: AGPL-3.0-only

package pages_test

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"connectrpc.com/connect/v2"
	"connectrpc.com/connect/v2/connecthttp"
	"connectrpc.com/connect/v2/connectproto"
	foundation "github.com/ArcForges/Contracts/go/arcforges/foundation/v1"
	v2 "github.com/ArcForges/Contracts/go/arcforges/sandbox/v2"
	"github.com/ArcForges/Contracts/go/arcforges/sandbox/v2/sandboxv2connect"
	"github.com/jackc/pgx/v5"
	"google.golang.org/protobuf/proto"

	"github.com/ArcForges/Cloud/center/internal/config"
	"github.com/ArcForges/Cloud/center/internal/fleetapi"
	"github.com/ArcForges/Cloud/center/internal/ingress"
	"github.com/ArcForges/Cloud/center/internal/management"
	"github.com/ArcForges/Cloud/center/internal/platform"
	"github.com/ArcForges/Cloud/center/internal/routes"
	"github.com/ArcForges/Cloud/center/internal/server"
	"github.com/ArcForges/Cloud/center/internal/session"
)

const center03Required = "ARCFORGES_CENTER03_E2E_REQUIRED"

type center03Provision struct {
	Grant            string
	Revision         int64
	TemplateRevision int64
	Config           []byte
	Unrelated        string
}

type center03Scope struct {
	Grant    string
	Revision int64
	Argv     []string
}

type center03Target struct {
	node, enrollment, grant platform.ID
	revision                int64
}

// TestCenter03InstalledNode uses the installed MXC-backed Node, real local owner
// operations and the same HTTPS Center, Hub and PostgreSQL for the entire case.
func TestCenter03InstalledNode(t *testing.T) {
	run := startCenter03InstalledNode(t)
	approval := center02Observation[center02Approval](t, run, "approval.json")
	b := run.ownerBrowser
	center02ApproveBrowserFlow(t, run.ctx, run.harness, b, run.owner, approval.VerificationURI)
	reported := center02Observation[center02Owner](t, run, "connected.json")
	var target center03Target
	epoch := center03ParseID(t, reported.OwnerEpoch)
	before := qualifyCenter03Peer(t, run, reported, &target)
	center02ConfirmConnection(t, run.coordination)

	provision := center02Observation[center03Provision](t, run, "provision.json")
	target.grant, target.revision = center03ParseID(t, provision.Grant), provision.Revision
	var sandboxConfig v2.SandboxConfig
	if err := proto.Unmarshal(provision.Config, &sandboxConfig); err != nil {
		t.Fatal("invalid fixture creation template")
	}
	create := &v2.SandboxServiceCreateRequest{
		Meta: center03Meta(true, nil), OwnerEpoch: center03ID(epoch),
		ProvisionGrantId: center03ID(target.grant), TemplateRevision: &foundation.Revision{Value: proto.Int64(provision.TemplateRevision + 1)},
		DisplayName: proto.String("Remote native fixture"), Config: &sandboxConfig,
	}
	var invalidTemplate v2.SandboxServiceCreateResponse
	center03Call(t, b, target, sandboxv2connect.SandboxServiceCreateProcedure, create, &invalidTemplate, nil)
	center03Denied(t, invalidTemplate.GetError(), "permission_denied")
	create.Meta = center03Meta(true, nil)
	create.TemplateRevision.Value = proto.Int64(provision.TemplateRevision)
	var created v2.SandboxServiceCreateResponse
	center03Call(t, b, target, sandboxv2connect.SandboxServiceCreateProcedure, create, &created, nil)
	center03Success(t, created.GetError(), created.GetValue())
	sandbox := created.GetValue().GetSandbox()
	if sandbox == nil || len(sandbox.GetSandboxId().GetValue()) != 16 || sandbox.GetDataLocation() != "" {
		t.Fatal("remote Create did not return an owned Sandbox identity with its local path withheld")
	}
	writeCenter03Observation(t, run, "center-sandbox.json", map[string]string{"sandbox": hex.EncodeToString(sandbox.GetSandboxId().GetValue())})

	scope := center02Observation[center03Scope](t, run, "scope.json")
	target.grant, target.revision = center03ParseID(t, scope.Grant), scope.Revision
	center03NoRemoteDeletePlan(t, b, target, sandbox.GetSandboxId())
	var unrelated v2.SandboxServiceInspectResponse
	center03Call(t, b, target, sandboxv2connect.SandboxServiceInspectProcedure, &v2.SandboxServiceInspectRequest{
		Meta: center03Meta(false, nil), SandboxId: center03ID(center03ParseID(t, provision.Unrelated)),
	}, &unrelated, nil)
	center03Denied(t, unrelated.GetError(), "permission_denied")

	configured := center03NarrowSandbox(t, b, target, epoch, sandbox, &sandboxConfig)
	policyRevision := center03NarrowResources(t, b, target, epoch, configured.GetSandboxId())
	request := &v2.RunServiceStartRequest{
		Meta: center03Meta(true, configured.GetRevision()), OwnerEpoch: center03ID(epoch), SandboxId: configured.GetSandboxId(),
		Argv: scope.Argv, WorkingDirectory: proto.String("work"), TerminalMode: v2.TerminalMode_TERMINAL_MODE_PIPES.Enum(),
	}
	stale := proto.CloneOf(request)
	stale.Meta, stale.OwnerEpoch = center03Meta(true, configured.GetRevision()), center03ID(platform.NewID())
	var staleStart v2.RunServiceStartResponse
	center03Call(t, b, target, sandboxv2connect.RunServiceStartProcedure, stale, &staleStart, nil)
	center03Denied(t, staleStart.GetError(), "owner_epoch_retired")
	command := platform.ID(request.GetMeta().GetCommandId().GetValue())
	fault := &center03LostResult{V2ControlTransport: run.harness.center.Hub, command: command}
	var uncertain v2.RunServiceStartResponse
	center03Call(t, b, target, sandboxv2connect.RunServiceStartProcedure, request, &uncertain, center03FaultHandler(t, run, fault))
	if failure := uncertain.GetError(); failure.GetCode() != "outcome_unknown" ||
		failure.GetEffect() != foundation.EffectCertainty_EFFECT_CERTAINTY_UNKNOWN ||
		failure.GetRetry().GetMode() != foundation.RetryMode_RETRY_MODE_RECONCILE || fault.run == nil {
		t.Fatalf("suppressed native response did not retain the expected uncertainty: %s/%s", failure.GetCode(), failure.GetEffect())
	}
	receipt := center03Receipt(t, run, target, command, epoch)
	if receipt.State != management.StateUnknown || receipt.Effect == nil || *receipt.Effect != management.EffectUnknown ||
		!receipt.MayHaveDelivered || receipt.DeliveryCount != 1 || receipt.FinalAt != nil || receipt.ResultID != nil {
		t.Fatal("PostgreSQL did not retain one uncertain delivery of the original command")
	}

	writeCenter03Observation(t, run, "start-uncertain.json", map[string]any{
		"command": hex.EncodeToString(command[:]), "run": hex.EncodeToString(fault.run.GetValue()),
		"sandboxRevision": configured.GetRevision().GetValue(), "policyRevision": policyRevision,
	})
	renewed := center02Observation[center02Owner](t, run, "reconnected.json")
	if renewed != reported || qualifyCenter03Peer(t, run, renewed, &target) == before {
		t.Fatal("explicit reconnect did not replace only the authenticated channel")
	}
	reloaded := run.harness.newBrowser()
	reloaded.mustSignIn(run.owner)
	reloaded.bootstrapState()

	query := &v2.NodeServiceGetOperationRequest{Meta: center03Meta(false, nil), OwnerEpoch: center03ID(platform.NewID()), CommandId: center03ID(command)}
	var wrongEpoch v2.NodeServiceGetOperationResponse
	center03Call(t, reloaded, target, sandboxv2connect.NodeServiceGetOperationProcedure, query, &wrongEpoch, nil)
	center03Denied(t, wrongEpoch.GetError(), "owner_epoch_retired")
	query.Meta, query.OwnerEpoch = center03Meta(false, nil), center03ID(epoch)
	var reconciled v2.NodeServiceGetOperationResponse
	center03Call(t, reloaded, target, sandboxv2connect.NodeServiceGetOperationProcedure, query, &reconciled, nil)
	center03Success(t, reconciled.GetError(), reconciled.GetValue())
	op := reconciled.GetValue().GetOperation()
	if !proto.Equal(op.GetAggregateId(), fault.run) || !proto.Equal(op.GetOwnerEpoch(), query.GetOwnerEpoch()) ||
		!proto.Equal(op.GetCommandId(), query.GetCommandId()) || op.GetResponseCompacted() ||
		op.GetState() != v2.OperationState_OPERATION_STATE_SUCCEEDED ||
		op.GetEffect() != foundation.EffectCertainty_EFFECT_CERTAINTY_HAPPENED {
		t.Fatal("authenticated reconciliation did not return the exact previously executed Run and original identity")
	}
	receipt = center03Receipt(t, run, target, command, epoch)
	if receipt.State != management.StateSucceeded || receipt.Effect == nil || *receipt.Effect != management.EffectHappened ||
		!receipt.MayHaveDelivered || receipt.DeliveryCount != 1 || receipt.FinalAt == nil ||
		receipt.ResultKind != "run" || receipt.ResultID == nil || *receipt.ResultID != platform.ID(fault.run.GetValue()) {
		t.Fatal("PostgreSQL did not reconcile the original single delivery to the confirmed Run")
	}

	var replay v2.RunServiceStartResponse
	replayErr := center03Unary(reloaded, target, sandboxv2connect.RunServiceStartProcedure, request, &replay, nil)
	var replayReceipt *connect.Error
	if !errors.As(replayErr, &replayReceipt) || replayReceipt.Code() != connect.CodeFailedPrecondition ||
		replayReceipt.Message() != "original_operation_reconciled" || len(replayReceipt.Details()) != 1 {
		t.Fatalf("the exact replay did not reference the existing receipt: %s", connect.CodeOf(replayErr))
	}
	detail, err := connectproto.UnmarshalErrorDetail(replayReceipt.Details()[0])
	readback, ok := detail.(*v2.NodeServiceGetOperationResponse)
	if err != nil || !ok || !proto.Equal(readback.GetValue().GetOperation(), op) {
		t.Fatal("the replay detail did not preserve the exact original Node operation")
	}
	changed := proto.CloneOf(request)
	changed.WorkingDirectory = proto.String("work/unused")
	var conflict v2.RunServiceStartResponse
	center03Call(t, reloaded, target, sandboxv2connect.RunServiceStartProcedure, changed, &conflict, nil)
	center03Denied(t, conflict.GetError(), "command_id_reused")

	var running v2.RunServiceInspectResponse
	center03Call(t, reloaded, target, sandboxv2connect.RunServiceInspectProcedure,
		&v2.RunServiceInspectRequest{Meta: center03Meta(false, nil), RunId: fault.run}, &running, nil)
	center03Success(t, running.GetError(), running.GetValue())
	if state := running.GetValue().GetRun().GetState(); state != v2.RunState_RUN_STATE_RUNNING {
		t.Fatalf("remote reconnect changed the running workload: %s", state)
	}
	writeCenter03Observation(t, run, "revoke-ready", struct{}{})
	revoked := center02Observation[struct{ Run string }](t, run, "revoked.json")
	if center03ParseID(t, revoked.Run) != platform.ID(fault.run.GetValue()) {
		t.Fatal("local fixture revoked the wrong Run scope")
	}
	var revokedStart v2.RunServiceStartResponse
	revokedRequest := proto.CloneOf(request)
	revokedRequest.Meta = center03Meta(true, configured.GetRevision())
	center03Call(t, reloaded, target, sandboxv2connect.RunServiceStartProcedure, revokedRequest, &revokedStart, nil)
	center03Denied(t, revokedStart.GetError(), "permission_denied")
	var revokedRead v2.NodeServiceGetOperationResponse
	center03Call(t, reloaded, target, sandboxv2connect.NodeServiceGetOperationProcedure, query, &revokedRead, nil)
	center03Denied(t, revokedRead.GetError(), "permission_denied")
	if got := center03Receipt(t, run, target, command, epoch); got.DeliveryCount != 1 || got.State != management.StateSucceeded {
		t.Fatal("replay or revocation changed the original PostgreSQL delivery evidence")
	}
	writeCenter03Observation(t, run, "revocation-confirmed", struct{}{})

	stopGrant := center02Observation[struct {
		Grant       string
		Revision    int64
		RunRevision int64
	}](t, run, "stop-authority.json")
	stopTarget := target
	stopTarget.grant, stopTarget.revision = center03ParseID(t, stopGrant.Grant), stopGrant.Revision
	if stopTarget.grant == target.grant || stopGrant.Revision < 1 || stopGrant.RunRevision < 1 {
		t.Fatal("the local owner did not provide a distinct valid Stop-only grant and the current Run revision")
	}
	stop := &v2.RunServiceStopRequest{Meta: center03Meta(true, &foundation.Revision{Value: proto.Int64(stopGrant.RunRevision)}),
		OwnerEpoch: center03ID(epoch), RunId: fault.run, GraceMs: proto.Uint32(0)}
	var stopped v2.RunServiceStopResponse
	center03Call(t, reloaded, stopTarget, sandboxv2connect.RunServiceStopProcedure, stop, &stopped, nil)
	center03Success(t, stopped.GetError(), stopped.GetValue())
	if !proto.Equal(stopped.GetValue().GetRun().GetRunId(), fault.run) ||
		!proto.Equal(stopped.GetValue().GetOperation().GetCommandId(), stop.GetMeta().GetCommandId()) {
		t.Fatal("remote Stop under the new grant did not address the original native Run")
	}
	writeCenter03Observation(t, run, "stopped", struct{}{})
	center02WaitExit(t, run)
}

func center03NarrowSandbox(t *testing.T, b *browser, target center03Target, epoch platform.ID, sandbox *v2.Sandbox, template *v2.SandboxConfig) *v2.Sandbox {
	t.Helper()
	narrow := proto.CloneOf(template)
	narrow.Resources.MemoryMaxBytes = proto.Uint64(224 << 20)
	configure := &v2.SandboxServiceConfigureRequest{
		Meta: center03Meta(true, sandbox.GetRevision()), OwnerEpoch: center03ID(epoch), SandboxId: sandbox.GetSandboxId(), Config: narrow,
	}
	var configured v2.SandboxServiceConfigureResponse
	center03Call(t, b, target, sandboxv2connect.SandboxServiceConfigureProcedure, configure, &configured, nil)
	center03Success(t, configured.GetError(), configured.GetValue())
	result := configured.GetValue().GetSandbox()
	if !proto.Equal(result.GetSandboxId(), sandbox.GetSandboxId()) || result.GetRevision().GetValue() != sandbox.GetRevision().GetValue()+1 ||
		result.GetConfig().GetResources().GetMemoryMaxBytes() != narrow.GetResources().GetMemoryMaxBytes() {
		t.Fatal("remote Configure did not commit the exact narrower sandbox policy")
	}
	configure.Meta = center03Meta(true, result.GetRevision())
	configure.Config = proto.CloneOf(template)
	var widened v2.SandboxServiceConfigureResponse
	center03Call(t, b, target, sandboxv2connect.SandboxServiceConfigureProcedure, configure, &widened, nil)
	center03Denied(t, widened.GetError(), "permission_denied")
	return result
}

func center03NarrowResources(t *testing.T, b *browser, target center03Target, epoch platform.ID, sandbox *foundation.Id) int64 {
	t.Helper()
	get := &v2.ResourceServiceGetBudgetRequest{Meta: center03Meta(false, nil), ScopeKind: proto.String("sandbox"), ScopeId: sandbox}
	var observed v2.ResourceServiceGetBudgetResponse
	center03Call(t, b, target, sandboxv2connect.ResourceServiceGetBudgetProcedure, get, &observed, nil)
	center03Success(t, observed.GetError(), observed.GetValue())
	current := observed.GetValue().GetSnapshot().GetPolicyRevision()
	change := &v2.ResourceServiceSetPolicyRequest{
		Meta: center03Meta(true, current), OwnerEpoch: center03ID(epoch), ScopeKind: get.ScopeKind, ScopeId: sandbox,
		Policy: &v2.ResourcePolicy{CpuMaxMillicores: proto.Uint32(500), MemoryMaxBytes: proto.Uint64(192 << 20),
			PressureAction: v2.PressureAction_PRESSURE_ACTION_THROTTLE.Enum()},
	}
	var narrowed v2.ResourceServiceSetPolicyResponse
	center03Call(t, b, target, sandboxv2connect.ResourceServiceSetPolicyProcedure, change, &narrowed, nil)
	center03Success(t, narrowed.GetError(), narrowed.GetValue())
	after := narrowed.GetValue().GetSnapshot().GetPolicyRevision()
	if after.GetValue() != current.GetValue()+1 {
		t.Fatal("remote Resource Policy did not commit the exact next revision")
	}
	change.Meta = center03Meta(true, after)
	change.Policy.MemoryMaxBytes = proto.Uint64(208 << 20)
	var widened v2.ResourceServiceSetPolicyResponse
	center03Call(t, b, target, sandboxv2connect.ResourceServiceSetPolicyProcedure, change, &widened, nil)
	center03Denied(t, widened.GetError(), "permission_denied")
	return after.GetValue()
}

type center03LostResult struct {
	fleetapi.V2ControlTransport
	command platform.ID
	run     *foundation.Id
}

// Discard precisely one real signed response after the bound Hub and native Node
// have executed the regular call. No request, effect or durable state is simulated.
func (f *center03LostResult) CallV2(ctx context.Context, authority management.V2ControlAuthority, call management.V2ControlCall,
	claim func(context.Context, management.V2ControlAuthority) (bool, error)) ([]byte, error) {
	response, err := f.V2ControlTransport.CallV2(ctx, authority, call, claim)
	if err != nil || call.CommandID != f.command || claim == nil {
		return response, err
	}
	var activated v2.RunServiceStartResponse
	if err := proto.Unmarshal(response, &activated); err != nil || activated.GetError() != nil ||
		len(activated.GetValue().GetRun().GetRunId().GetValue()) != 16 {
		return nil, errors.New("the native Start result could not be observed")
	}
	f.run = activated.GetValue().GetRun().GetRunId()
	return nil, management.ErrV2ControlUncertain
}

func center03FaultHandler(t *testing.T, run *center02NativeRun, fault fleetapi.V2ControlTransport) http.Handler {
	t.Helper()
	h := run.harness
	modules, err := routes.Center()
	if err != nil {
		t.Fatal(err)
	}
	publicRoutes, err := routes.Ingress(modules)
	if err != nil {
		t.Fatal(err)
	}
	center := h.center
	dispatcher := connect.NewServer(nil)
	api := fleetapi.New(nil, center.Authorizer, center.Store, h.clock.Now, center.Logger)
	dispatcher.Register(api.V2ControlMethods(fault, center.Config.Identity.Policy.RoutedReplayWindow)...)
	mux := http.NewServeMux()
	connecthttp.Mount(mux, dispatcher, connecthttp.WithReadMaxBytes(routes.MaxRequestBytes(modules)-ingress.HeaderLength),
		connecthttp.WithSendMaxBytes(routes.MaxResponseBytes(modules)-ingress.HeaderLength))
	sessionVerifier := session.NewVerifier(center.Store, h.origin, h.clock.Now)
	return ingress.NewPipeline(ingress.Options{
		Routes: publicRoutes, Bearer: sessionVerifier, Browser: sessionVerifier,
		SurfaceEnabled: func(surface string) bool { return center.Config.Identity.Enabled(config.Surface(surface)) },
		ClientIP:       server.ClientAddress(center.Config.Mode, center.Config.Identity),
	}, mux)
}

func center03Call(t *testing.T, b *browser, target center03Target, path string, in, out proto.Message, fault http.Handler) {
	t.Helper()
	if err := center03Unary(b, target, path, in, out, fault); err != nil {
		t.Fatalf("the typed Center transport returned %s for %s", connect.CodeOf(err), path)
	}
}

func center03Unary(b *browser, target center03Target, path string, in, out proto.Message, fault http.Handler) error {
	httpClient := center03BrowserTransport{browser: b, target: target, fault: fault}
	client := connect.NewClient(connecthttp.NewTransport(httpClient, b.h.url, connecthttp.WithGRPCWeb()))
	ctx, cancel := context.WithTimeout(context.Background(), 12*time.Second)
	defer cancel()
	return client.CallUnary(ctx, connect.Spec{Procedure: path, StreamType: connect.StreamTypeUnary}, in, out)
}

func center03NoRemoteDeletePlan(t *testing.T, b *browser, target center03Target, sandbox *foundation.Id) {
	t.Helper()
	const path = sandboxv2connect.SandboxServicePlanDeleteProcedure
	in := &v2.SandboxServicePlanDeleteRequest{Meta: center03Meta(false, nil), SandboxId: sandbox}
	var out v2.SandboxServicePlanDeleteResponse
	if result := connect.CodeOf(center03Unary(b, target, path, in, &out, nil)); result != connect.CodeUnimplemented {
		t.Fatalf("the local-only delete-plan method must have no remote route: %s", result)
	}
}

type center03BrowserTransport struct {
	browser *browser
	target  center03Target
	fault   http.Handler
}

func (c center03BrowserTransport) Do(req *http.Request) (*http.Response, error) {
	req.Header.Set("Origin", c.browser.h.origin)
	req.Header.Set("User-Agent", c.browser.userAgent)
	req.Header.Set(config.ClientIPHeader, "203.0.113.10")
	req.Header.Set(ingress.CSRFHeader, c.browser.csrf)
	req.Header.Set(ingress.RemoteNodeHeader, uuid(c.target.node))
	req.Header.Set(ingress.RemoteEnrollmentHeader, uuid(c.target.enrollment))
	req.Header.Set(ingress.RemoteGrantHeader, uuid(c.target.grant))
	req.Header.Set(ingress.RemoteGrantRevisionHeader, strconv.FormatInt(c.target.revision, 10))
	req.AddCookie(&http.Cookie{Name: routes.PageCookieName, Value: c.browser.cookie})
	if c.fault == nil {
		return c.browser.h.http.Do(req)
	}
	req.RemoteAddr = "127.0.0.1:1"
	w := httptest.NewRecorder()
	c.fault.ServeHTTP(w, req)
	return w.Result(), nil
}

func center03Success(t *testing.T, failure *foundation.ArcError, value proto.Message) {
	t.Helper()
	if failure != nil || !value.ProtoReflect().IsValid() {
		t.Fatalf("the typed Center operation failed: %s/%s", failure.GetCategory(), failure.GetCode())
	}
}

func center03Denied(t *testing.T, failure *foundation.ArcError, code string) {
	t.Helper()
	if failure.GetCode() != code || failure.GetEffect() != foundation.EffectCertainty_EFFECT_CERTAINTY_DID_NOT_HAPPEN {
		t.Fatalf("wanted typed %s/DID_NOT_HAPPEN, got %s/%s with state reason %q",
			code, failure.GetCode(), failure.GetEffect(), failure.GetDetails().GetState().GetReason())
	}
}

func center03Receipt(t *testing.T, run *center02NativeRun, target center03Target, command, epoch platform.ID) management.Receipt {
	t.Helper()
	identity, receipt, err := management.New(run.harness.center.Store).InspectOriginal(run.ctx, management.Authority{
		Account: run.owner.id, Actor: run.owner.id, Node: target.node, Enrollment: target.enrollment,
		Grant: target.grant, GrantRevision: target.revision,
	}, command)
	if err != nil || identity.OwnerEpoch != epoch || identity.Command != command || identity.Method != "RunService.Start" {
		t.Fatal("PostgreSQL did not retain the exact original typed command and owner epoch")
	}
	return receipt
}

func center03ID(value platform.ID) *foundation.Id { return &foundation.Id{Value: value[:]} }

func center03ParseID(t *testing.T, value string) platform.ID {
	t.Helper()
	id, err := hex.DecodeString(value)
	if err != nil || len(id) != 16 {
		t.Fatal("the fixture did not produce a valid exact identity")
	}
	return platform.ID(id)
}

func center03Meta(mutation bool, expected *foundation.Revision) *foundation.RequestMeta {
	m := &foundation.RequestMeta{CorrelationId: center03ID(platform.NewID()), ExpectedRev: expected}
	if mutation {
		m.CommandId = center03ID(platform.NewID())
	}
	return m
}

func startCenter03InstalledNode(t *testing.T) *center02NativeRun {
	t.Helper()
	if os.Getenv(center03Required) != "1" {
		t.Skip("the installed Node supplement requires a scoped native fixture")
	}
	project := center02File(t, center02Project)
	center02File(t, "ARCFORGES_HOST_PATH")
	center02File(t, "ARCFORGES_TESTLOAD_PATH")
	if os.Getenv("ARCFORGES_TEST_POSTGRES_REQUIRED") != "1" || os.Getenv("ARCFORGES_MXC_PACKAGE_TESTS") != "1" {
		t.Fatal("the native fixture requires both real PostgreSQL and the verified MXC extraction")
	}
	certificate, err := tls.LoadX509KeyPair(center02File(t, center02Cert), center02File(t, center02Key))
	if err != nil {
		t.Fatal("the scoped localhost TLS certificate and key could not be loaded")
	}
	leaf, err := x509.ParseCertificate(certificate.Certificate[0])
	if err != nil || leaf.VerifyHostname("localhost") != nil {
		t.Fatal("the scoped TLS identity must name localhost")
	}

	h := newHarness(t, settings{surfaces: "identity,pages,fleet,relay,nodes", policy: writePolicy, relay: true, nativeCertificate: &certificate})
	// The native Node checks the signed absolute deadline against its system clock.
	// Advance the existing fixture clock on each read to match the current host.
	h.clock.mu.Lock()
	h.clock.tick = func() {
		h.clock.mu.Lock()
		h.clock.now = time.Now().UTC()
		h.clock.mu.Unlock()
	}
	h.clock.mu.Unlock()
	owner := h.seedAccount(1)
	b := h.newBrowser()
	b.mustSignIn(owner)
	b.bootstrapState()
	dir := t.TempDir()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	t.Cleanup(cancel)
	processContext, cancelProcess := context.WithTimeout(context.Background(), 6*time.Minute)
	t.Cleanup(cancelProcess)
	command := exec.CommandContext(processContext, "dotnet", "test", "--project", project, "-c", "Release", "--no-build",
		"--filter-class", "ArcForges.ClosedLoop.Tests.RemoteManagementCenterTests", "--minimum-expected-tests", "1", "--fail-skips", "on")
	command.Dir = filepath.Dir(project)
	command.WaitDelay = 5 * time.Second
	command.Env = append(center02NodeEnvironment(command.Environ()), center02Required+"=1", center02URL+"="+h.origin, center02Evidence+"="+dir)
	run := &center02NativeRun{harness: h, owner: owner, ownerBrowser: b, ctx: ctx, coordination: dir, done: make(chan struct{})}
	command.Stdout, command.Stderr = &run.output, &run.output
	if err := command.Start(); err != nil {
		t.Fatalf("launch the installed Node test: %v", err)
	}
	go func() {
		run.exit = command.Wait()
		close(run.done)
	}()
	t.Cleanup(func() {
		center02DrainChild(t, dir, run.done, cancelProcess)
		if t.Failed() {
			for line := range strings.SplitSeq(h.logs.String(), "\n") {
				var event struct{ Msg, Phase, Outcome string }
				if json.Unmarshal([]byte(line), &event) == nil && event.Msg == "V2 control channel" {
					t.Logf("the V2 control transport reported %s/%s", event.Phase, event.Outcome)
				}
			}
			t.Log(run.output.String())
		}
	})
	return run
}

func qualifyCenter03Peer(t *testing.T, run *center02NativeRun, reported center02Owner, target *center03Target) platform.ID {
	t.Helper()
	ctx, cancel := context.WithTimeout(run.ctx, 10*time.Second)
	defer cancel()
	tick := time.NewTicker(100 * time.Millisecond)
	defer tick.Stop()
	wantOwner := center03ParseID(t, reported.OwnerEpoch)
	capabilities := []string{"linux-bubblewrap-sdk-v1"}
	if runtime.GOOS == "windows" {
		capabilities = []string{"win-wrapper-local-v1", "windows-process-executor-v1"}
	}
	for {
		var enrollment, node, protocol platform.ID
		err := run.harness.migration.QueryRow(ctx, "SELECT enrollment_id,node_id,protocol_epoch FROM management.node_protocol "+
			"WHERE account_id=$1 AND protocol_major=2 AND revoked_at IS NULL", run.owner.id).Scan(&enrollment, &node, &protocol)
		if err != nil && !errors.Is(err, pgx.ErrNoRows) && ctx.Err() == nil {
			t.Fatalf("the exact control enrollment read failed: %T", err)
		}
		if err == nil {
			hub := run.harness.center.Hub
			presence, online := hub.V2Presence(run.owner.id, enrollment, node, protocol)
			// Verified control authority independently requires the private control
			// capability. The public presence projects the native profiles.
			authority, ready := hub.V2ControlAuthority(ctx, run.owner.id, node, enrollment, protocol)
			if online && ready == nil {
				if presence.Platform != runtime.GOOS {
					t.Fatalf("the authenticated platform was %q, expected %q", presence.Platform, runtime.GOOS)
				}
				if !slices.Equal(presence.Capabilities, capabilities) {
					t.Fatalf("the qualified native profiles were %v, expected %v", presence.Capabilities, capabilities)
				}
				if presence.NodeEpoch != reported.NodeEpoch {
					t.Fatal("the authenticated Node process epoch differs from the local installed Node")
				}
				if presence.NodeOwnerEpoch != wantOwner || authority.NodeOwnerEpoch != wantOwner {
					t.Fatal("the authenticated owner epoch differs from the local retained owner epoch")
				}
				if authority.ConnectionID != presence.ConnectionID || authority.ProtocolEpoch != protocol {
					t.Fatal("the control authority does not match the authenticated channel and protocol")
				}
				if target.enrollment != (platform.ID{}) && (target.enrollment != enrollment || target.node != node) {
					t.Fatal("the replaced channel did not preserve the Node and enrollment identities")
				}
				target.enrollment, target.node = enrollment, node
				return authority.ConnectionID
			}
		}
		select {
		case <-tick.C:
		case <-run.done:
			t.Fatal("the installed Node drained before the exact V2 control peer passed readiness")
		case <-ctx.Done():
			t.Fatal("the installed Node did not establish the exact real V2 control peer")
		}
	}
}

func writeCenter03Observation(t *testing.T, run *center02NativeRun, name string, observation any) {
	t.Helper()
	path := filepath.Join(run.coordination, name)
	value, err := json.Marshal(observation)
	if err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(path+".input", value, 0600); err != nil {
		t.Fatal("could not write the private Center observation")
	}
	if err = os.Rename(path+".input", path); err != nil {
		t.Fatal("could not publish the private Center observation")
	}
}
