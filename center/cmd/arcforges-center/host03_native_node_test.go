// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/ArcForges/Cloud/center/internal/platform"
	foundation "github.com/ArcForges/Contracts/go/arcforges/foundation/v1"
	v2 "github.com/ArcForges/Contracts/go/arcforges/sandbox/v2"
	"google.golang.org/protobuf/encoding/protojson"
)

type host03Node struct {
	t         *testing.T
	binary    string
	origin    string
	directory string
	env       map[string]string
	child     *host03Child
	connects  string
	slice     string
}

type host03Enrollment struct {
	node, enrollment, ownerEpoch platform.ID
}

type host03Sandbox struct {
	id, work  string
	resources *v2.ResourcePolicy
}

type host03Scope struct {
	node, enrollment, grant platform.ID
	revision                int64
}

func startHost03Node(t *testing.T, directory, binary, origin string) *host03Node {
	t.Helper()
	n := &host03Node{t: t, binary: binary, origin: origin, directory: directory, connects: filepath.Join(directory, "node-authority.log")}
	settings := filepath.Join(directory, "node-settings")
	data := filepath.Join(directory, "node-data")
	host03PrivateDirectory(t, settings)
	host03PrivateDirectory(t, data)
	n.writeJSON(filepath.Join(settings, "node.json"), map[string]string{"dataRoot": data})
	tag := host03NodeTag()
	endpoint := tag
	n.env = map[string]string{"ARCFORGES_CONFIG_DIR": settings, "ARCFORGES_TEST_ALLOW_LOCAL_SCRIPT_SUBMIT": "1",
		"ARCFORGES_TEST_MACHINE": "isolated", "ARCFORGES_TEST_CENTER_URL": origin + "/api", "ARCFORGES_TEST_CONNECT_LOG": n.connects,
		"ARCFORGES_TEST_BROWSER_FILE": filepath.Join(directory, "open-browser.txt"), "DOTNET_EnableDiagnostics": "0"}
	if runtime.GOOS == "linux" {
		// The manager and cgroup are native and scoped to this installed Node.
		socket := filepath.Join("/tmp", tag)
		host03PrivateDirectory(t, socket)
		t.Cleanup(func() {
			if err := os.RemoveAll(socket); err != nil {
				t.Error("remove the owned Node socket directory")
			}
		})
		endpoint = filepath.Join(socket, "node.sock")
		n.slice = "arcforges-test-" + strings.TrimPrefix(tag, "af-host03-") + ".slice"
		n.env["ARCFORGES_SLICE"] = n.slice
		n.env["DBUS_SESSION_BUS_ADDRESS"] = "unix:path=" + filepath.Join(directory, "isolated-credential-bus")
	}
	n.env["ARCFORGES_ENDPOINT"] = endpoint
	n.child = host03Start(t, binary, n.env, "node", "run", "--test-mode")
	t.Cleanup(n.stop)
	ctx, cancel := context.WithTimeout(t.Context(), 35*time.Second)
	defer cancel()
	ready := exec.CommandContext(ctx, binary, "node", "wait-ready", "--timeout", "30s", "--test-mode")
	ready.Env = host03Environment(n.env)
	if err := ready.Run(); err != nil {
		n.child.requireRunning(t)
		t.Fatalf("the installed Node did not answer its owner-local readiness check (%v)", host03Exit(err))
	}
	return n
}

func host03NodeTag() string {
	id := platform.NewID()
	return fmt.Sprintf("af-host03-%x", id[:8])
}

func (n *host03Node) stop() {
	n.t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Second)
	defer cancel()
	stop := exec.CommandContext(ctx, n.binary, "node", "stop", "--timeout", "15s", "--test-mode")
	stop.Env = host03Environment(n.env)
	// The command is idempotent if the test already ran its explicit drain.
	if err := stop.Run(); err != nil {
		n.t.Errorf("the owned Node did not accept its normal stop (%v)", host03Exit(err))
		n.child.stop(n.t, false)
	} else {
		n.child.stop(n.t, true)
	}
	if n.slice != "" {
		stopSlice := exec.CommandContext(ctx, "systemctl", "--user", "stop", n.slice)
		showSlice := exec.CommandContext(ctx, "systemctl", "--user", "show", "--property=ActiveState", "--value", n.slice)
		if err := stopSlice.Run(); err != nil {
			n.t.Errorf("the owned Linux slice could not be stopped (%v)", host03Exit(err))
		}
		state, err := showSlice.Output()
		if err != nil || strings.TrimSpace(string(state)) != "inactive" {
			n.t.Error("the owned Linux slice remained active or its absence could not be verified")
		}
	}
	host03CheckNativeChildren(n.t, filepath.Join(n.directory, "node-data"), filepath.Dir(n.binary))
}

func (n *host03Node) call(arguments ...string) map[string]any {
	n.t.Helper()
	return n.command("", arguments...)
}

func (n *host03Node) command(allowedFailure string, arguments ...string) map[string]any {
	n.t.Helper()
	n.child.requireRunning(n.t)
	ctx, cancel := context.WithTimeout(n.t.Context(), 25*time.Second)
	defer cancel()
	command := exec.CommandContext(ctx, n.binary, append([]string{"--test-mode", "--json"}, arguments...)...)
	command.Env = host03Environment(n.env)
	output, err := command.Output()
	var view map[string]any
	decodeErr := json.Unmarshal(output, &view)
	if err != nil {
		failure := host03Obj(view, "error")
		code := host03Text(failure, "code")
		if decodeErr == nil && code == allowedFailure && code == "outcome_unknown" &&
			host03Text(failure, "effect") == "EFFECT_CERTAINTY_UNKNOWN" {
			return view
		}
		if !host03Token(code) {
			code = ""
		}
		reason := host03Text(host03Obj(host03Obj(failure, "details"), "state"), "reason")
		if !host03Token(reason) {
			reason = ""
		}
		n.t.Fatalf("installed Node %s: exit %v, code %q, reason %q", strings.Join(arguments[:min(2, len(arguments))], " "), host03Exit(err), code, reason)
	}
	if decodeErr != nil || view == nil {
		n.t.Fatal("the installed Node did not return one JSON result")
	}
	return view
}

func (n *host03Node) enroll(browser *host03Browser) host03Enrollment {
	n.t.Helper()
	start := n.call("center", "connect", n.origin, "--mode", "self_hosted", "--flow", "browser")
	flowID := host03Text(start, "flowId")
	owner := host03LocalID(n.t, host03Text(start, "ownerEpoch"))
	_ = host03LocalID(n.t, flowID)
	var verification string
	host03Wait(n.t, 35*time.Second, "the installed Node browser approval offer", func() bool {
		result := host03Obj(n.call("center", "flow", flowID), "flow")
		verification = host03Text(result, "verificationUri")
		return host03Text(result, "state") == "pending" && verification != ""
	})
	browser.approve(verification)
	return n.online(owner)
}

func (n *host03Node) online(owner platform.ID) host03Enrollment {
	n.t.Helper()
	var status map[string]any
	host03Wait(n.t, 35*time.Second, "the installed Node authenticated V2 connection", func() bool {
		status = host03Obj(n.call("center", "status"), "connection")
		return host03Text(status, "channelState") == "online"
	})
	if host03Text(status, "centerOrigin") != n.origin {
		n.t.Fatal("the installed Node connected to an unexpected origin")
	}
	// The independently observed authorized Center protocol supplies Node ID.
	return host03Enrollment{enrollment: host03LocalID(n.t, host03Text(status, "enrollmentId")), ownerEpoch: owner}
}

func (n *host03Node) requireOffline(first host03Enrollment) {
	n.t.Helper()
	host03Wait(n.t, 20*time.Second, "the installed Node offline observation", func() bool {
		connection := host03Obj(n.call("center", "status"), "connection")
		if host03Text(connection, "centerOrigin") != n.origin || host03Text(connection, "serviceMode") != "self_hosted" ||
			connection["connectionEnabled"] != true {
			n.t.Fatal("the stopped Center altered the Node's intended self-host connection")
		}
		// The local contract hides EnrollmentId when there is no active V2
		// observation. If it still exposes one, it must be the original.
		if id := host03Text(connection, "enrollmentId"); id != "" && host03LocalID(n.t, id) != first.enrollment {
			n.t.Fatal("the stopped Center altered the Node's owned enrollment")
		}
		state := host03Text(connection, "channelState")
		return state == "offline" || state == "stale"
	})
}

func (n *host03Node) endEnrollment() {
	n.t.Helper()
	n.command("outcome_unknown", "center", "signout")
	host03Wait(n.t, 20*time.Second, "the installed Node's local sign-out", func() bool {
		connection := host03Obj(n.call("center", "status"), "connection")
		return host03Text(connection, "state") == "signed_out"
	})
}

func (n *host03Node) rejoin(first host03Enrollment) {
	n.t.Helper()
	n.call("center", "disconnect")
	resumed := n.call("center", "connect", n.origin, "--mode", "self_hosted", "--flow", "browser")
	if host03Text(resumed, "flowId") != "" || host03LocalID(n.t, host03Text(resumed, "ownerEpoch")) != first.ownerEpoch ||
		n.online(first.ownerEpoch).enrollment != first.enrollment {
		n.t.Fatal("Windows restart needed new authority or changed the existing enrollment")
	}
}

func (n *host03Node) createSandbox(name string) host03Sandbox {
	n.t.Helper()
	profile, version := "linux-bubblewrap-sdk-v1", "linux-bubblewrap-sdk-v1"
	if runtime.GOOS == "windows" {
		profile, version = "windows-process-executor-v1", "win-wrapper-local-v1"
	}
	resources := &v2.ResourcePolicy{CpuMaxMillicores: new(uint32(500)), MemoryMaxBytes: new(uint64(256 << 20)),
		PressureAction: v2.PressureAction_PRESSURE_ACTION_THROTTLE.Enum()}
	encoded, err := protojson.Marshal(resources)
	if err != nil {
		n.t.Fatal("encode the real Sandbox resource configuration")
	}
	config := filepath.Join(n.directory, "sandbox.json")
	n.writeJSON(config, map[string]any{"profileId": profile, "profileVersion": version,
		"network":   map[string]any{"egress": "NETWORK_MODE_DENY", "ingress": "NETWORK_MODE_DENY", "hostLoopback": false},
		"resources": json.RawMessage(encoded)})
	sandbox := host03Obj(n.call("sandbox", "create", name, "--file", config), "sandbox")
	id, root := host03Text(sandbox, "sandboxId"), host03Text(sandbox, "dataLocation")
	_ = host03LocalID(n.t, id)
	relative, err := filepath.Rel(filepath.Join(n.directory, "node-data"), root)
	if err != nil || relative == "." || relative == ".." || !filepath.IsLocal(relative) {
		n.t.Fatal("the private Sandbox was not created under the owned native fixture root")
	}
	work := filepath.Join(root, "work")
	if err := os.WriteFile(filepath.Join(work, "private-host03.txt"), []byte("ArcForges HOST-03 preserved private data\n"), 0600); err != nil {
		n.t.Fatal("write the native Sandbox's private continuity witness")
	}
	return host03Sandbox{id: id, work: work, resources: resources}
}

func (n *host03Node) startRun(sandbox host03Sandbox) string {
	n.t.Helper()
	argv := []string{"/usr/bin/dash", "-c", "printf 'running\\n' > holding.txt; exec /usr/bin/sleep 240"}
	if runtime.GOOS == "windows" {
		testLoad := host03InputFile(n.t, "ARCFORGES_HOST03_TESTLOAD")
		if host03FileDigest(n.t, testLoad) != os.Getenv("ARCFORGES_HOST03_TESTLOAD_SHA256") {
			n.t.Fatal("the native Windows held-Run payload hash does not match its stock export")
		}
		body, err := os.ReadFile(testLoad)
		if err != nil || os.WriteFile(filepath.Join(sandbox.work, "arcforges-testload.exe"), body, 0600) != nil {
			n.t.Fatal("stage the original native held-Run test workload in its owned work root")
		}
		argv = []string{filepath.Join(os.Getenv("SystemRoot"), "System32", "cmd.exe"), "/d", "/c",
			".\\arcforges-testload.exe hold --hold-ms 240000 --marker holding.txt"}
	}
	run := n.start(sandbox, argv)
	host03Wait(n.t, 20*time.Second, "the local Run to enter Running and write its private marker", func() bool {
		_, err := os.Stat(filepath.Join(sandbox.work, "holding.txt"))
		return err == nil && n.runState(run) == "RUN_STATE_RUNNING"
	})
	return run
}

func (n *host03Node) start(sandbox host03Sandbox, argv []string) string {
	n.t.Helper()
	result := host03Obj(n.call(append([]string{"run", "start", sandbox.id, "--terminal", "off", "--cwd", "work", "--"}, argv...)...), "run")
	id := host03Text(result, "runId")
	_ = host03LocalID(n.t, id)
	return id
}

func (n *host03Node) runOffline(sandbox host03Sandbox) {
	n.t.Helper()
	argv := []string{"/usr/bin/dash", "-c", "printf 'local\\n' > offline.txt"}
	if runtime.GOOS == "windows" {
		argv = []string{filepath.Join(os.Getenv("SystemRoot"), "System32", "cmd.exe"), "/d", "/c", "echo local>offline.txt"}
	}
	run := n.start(sandbox, argv)
	host03Wait(n.t, 15*time.Second, "the offline local Run to exit", func() bool { return n.runState(run) == "RUN_STATE_EXITED" })
	body, err := os.ReadFile(filepath.Join(sandbox.work, "offline.txt"))
	if err != nil || strings.TrimSpace(string(body)) != "local" {
		n.t.Fatal("the offline local Run did not leave its actual private output")
	}
}

func (n *host03Node) runState(run string) string {
	return host03Text(host03Obj(n.call("run", "inspect", run), "run"), "state")
}

func (n *host03Node) assertLocalRun(sandbox host03Sandbox, run string) {
	n.t.Helper()
	view := host03Obj(n.call("run", "inspect", run), "run")
	if host03Text(view, "runId") != run || host03Text(view, "sandboxId") != sandbox.id || host03Text(view, "state") != "RUN_STATE_RUNNING" {
		n.t.Fatal("the same owned Run did not remain Running inside the selected Sandbox")
	}
	if _, err := os.Stat(filepath.Join(sandbox.work, "holding.txt")); err != nil {
		n.t.Fatal("the original native workload marker disappeared")
	}
}

func (n *host03Node) setGrant(sandbox host03Sandbox, target host03Enrollment) host03Scope {
	n.t.Helper()
	grantID := platform.NewID()
	result := &v2.RemoteGrant{GrantId: host03ProtoID(grantID), EnrollmentId: host03ProtoID(target.enrollment),
		SandboxId: host03ProtoID(host03LocalID(n.t, sandbox.id)), ScopeKind: new("sandbox"), ResourceCeiling: sandbox.resources,
		Methods: []string{host03InspectRun, host03InspectSandbox}}
	encoded, err := protojson.Marshal(result)
	if err != nil {
		n.t.Fatal("marshal the owner-local scoped grant")
	}
	path := filepath.Join(n.directory, grantID.String()+".json")
	if err = os.WriteFile(path, encoded, 0600); err != nil {
		n.t.Fatal("write the owner-local scoped grant")
	}
	granted := host03Obj(n.call("grant", "set", "--file", path), "grant")
	if host03LocalID(n.t, host03Text(granted, "grantId")) != grantID ||
		host03LocalID(n.t, host03Text(granted, "enrollmentId")) != target.enrollment {
		n.t.Fatal("the local Grant did not preserve its exact enrollment and requested identity")
	}
	revision, err := strconv.ParseInt(host03Text(host03Obj(granted, "revision"), "value"), 10, 64)
	if err != nil || revision < 1 {
		n.t.Fatal("the local grant is missing its durable positive revision")
	}
	return host03Scope{node: target.node, enrollment: target.enrollment, grant: grantID, revision: revision}
}

func (n *host03Node) privateDigest(sandbox host03Sandbox) string {
	return host03FileDigest(n.t, filepath.Join(sandbox.work, "private-host03.txt"))
}

func (n *host03Node) verifyNoOfficialCall() {
	n.t.Helper()
	authority, err := url.Parse(n.origin)
	if err != nil {
		n.t.Fatal("the scoped TLS authority is invalid")
	}
	data, err := os.ReadFile(n.connects)
	if err != nil || len(data) == 0 {
		n.t.Fatal("the installed Node did not record any guarded authority attempt")
	}
	for _, line := range strings.Split(strings.TrimSpace(string(data)), "\n") {
		fields := strings.Fields(line)
		if len(fields) < 2 || fields[0] != authority.Host || fields[1] != "sent" {
			n.t.Fatal("the installed Node attempted an authority other than the selected self-host TLS origin")
		}
	}
}

func (n *host03Node) drain(sandbox host03Sandbox, run string) {
	n.t.Helper()
	n.call("run", "stop", run, "--grace-ms", "100")
	host03Wait(n.t, 20*time.Second, "the owned held Run to reach its terminal state", func() bool {
		return n.runState(run) == "RUN_STATE_EXITED"
	})
	runs, _ := n.call("run", "list", "--sandbox", sandbox.id)["runs"].([]any)
	if len(runs) != 1 {
		n.t.Fatal("the original Sandbox did not retain exactly its original held Run")
	}
	only, _ := runs[0].(map[string]any)
	if host03Text(only, "runId") != run {
		n.t.Fatal("the final retained Run did not preserve its original ID")
	}
}

func (n *host03Node) writeJSON(filename string, document any) {
	n.t.Helper()
	data, err := json.Marshal(document)
	if err != nil || os.WriteFile(filename, data, 0600) != nil {
		n.t.Fatal("could not write a scoped native fixture JSON input")
	}
}

func host03LocalID(t *testing.T, value string) platform.ID {
	t.Helper()
	const digits = "0123456789abcdefghjkmnpqrstvwxyz"
	if len(value) != 26 || value[0] > '7' {
		t.Fatal("the local native CLI did not emit a canonical 26-digit identity")
	}
	var high, low uint64
	for _, digit := range value {
		number := strings.IndexRune(digits, digit)
		if number < 0 {
			t.Fatal("the local native CLI identity contains an invalid character")
		}
		high, low = high<<5|low>>59, low<<5|uint64(number)
	}
	var id platform.ID
	binary.BigEndian.PutUint64(id[:8], high)
	binary.BigEndian.PutUint64(id[8:], low)
	return id
}

func host03ProtoID(id platform.ID) *foundation.Id { return &foundation.Id{Value: id[:]} }

func host03Obj(document map[string]any, key string) map[string]any {
	value, _ := document[key].(map[string]any)
	return value
}

func host03Text(document map[string]any, key string) string {
	value, _ := document[key].(string)
	return value
}

func host03Token(value string) bool {
	return len(value) > 0 && len(value) < 80 && strings.IndexFunc(value, func(r rune) bool {
		return !(r >= 'a' && r <= 'z' || r == '_')
	}) < 0
}
