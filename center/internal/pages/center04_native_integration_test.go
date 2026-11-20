// SPDX-License-Identifier: AGPL-3.0-only

package pages_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"connectrpc.com/connect/v2"
	"connectrpc.com/connect/v2/connecthttp"
	foundation "github.com/ArcForges/Contracts/go/arcforges/foundation/v1"
	v2 "github.com/ArcForges/Contracts/go/arcforges/sandbox/v2"
	"github.com/ArcForges/Contracts/go/arcforges/sandbox/v2/sandboxv2connect"
	"google.golang.org/protobuf/proto"

	"github.com/ArcForges/Cloud/center/internal/fleetapi"
	"github.com/ArcForges/Cloud/center/internal/management"
	"github.com/ArcForges/Cloud/center/internal/platform"
)

const center04Required = "ARCFORGES_CENTER04_E2E_REQUIRED"
const center04ExpiryRequired = "ARCFORGES_CENTER04_EXPIRY_REQUIRED"

type center04Scope struct {
	Grant, Sandbox, Run, RunEpoch string
	Revision, SandboxRevision     int64
}

func (s center04Scope) target(t *testing.T, base center03Target) center03Target {
	t.Helper()
	base.grant, base.revision = center03ParseID(t, s.Grant), s.Revision
	return base
}

// TestCenter04InstalledNode uses the exact installed package, ordinary HTTPS,
// owner-local IPC and a real PostgreSQL Center on the designated native host.
func TestCenter04InstalledNode(t *testing.T) {
	run := startCenter04InstalledNode(t, center04Required, "ArcForges.ClosedLoop.Tests.RemoteStreamCenterTests", 5*time.Minute)
	approval := center02Observation[center02Approval](t, run, "approval.json")
	browser := run.ownerBrowser
	center02ApproveBrowserFlow(t, run.ctx, run.harness, browser, run.owner, approval.VerificationURI)
	reported := center02Observation[center02Owner](t, run, "connected.json")
	var peer center03Target
	oldConnection := qualifyCenter03Peer(t, run, reported, &peer)
	center02ConfirmConnection(t, run.coordination)

	stream := center02Observation[center04Scope](t, run, "stream-scope.json")
	watcher := stream.target(t, peer)
	cursor := center04Output(t, run, browser, watcher, stream)
	eventScope := center03ID(center03ParseID(t, stream.Sandbox))
	center04Events(t, run, browser, watcher, eventScope, center03ID(center03ParseID(t, stream.Run)), reported.NodeEpoch)
	previousSample := center04WatchQuota(t, run, browser, watcher, eventScope)

	files := center02Observation[center04Scope](t, run, "file-scope.json")
	transfer := files.target(t, peer)
	fileScope := center03ID(center03ParseID(t, files.Sandbox))
	ownerEpoch := center03ID(center03ParseID(t, reported.OwnerEpoch))
	contents := bytes.Repeat([]byte{'D'}, 1<<20)
	contents = append(contents, "native-final-tail"...)
	digest := sha256.Sum256(contents)
	expectedDigest := hex.EncodeToString(digest[:])
	center04RejectOversize(t, run, browser, transfer, fileScope, ownerEpoch, files.SandboxRevision, expectedDigest)
	center04Upload(t, run, browser, transfer, fileScope, ownerEpoch, files.SandboxRevision, contents, expectedDigest)

	export := center04Export(t, run, browser, transfer, fileScope, ownerEpoch, files.SandboxRevision, contents, expectedDigest)
	last := &v2.DataServiceReadExportRequest{Meta: center03Meta(false, nil), TransferId: export.GetTransferId(),
		Offset: proto.Uint64(1 << 20), MaxBytes: proto.Uint32(17)}
	loss := &center04LostResult{V2ControlTransport: run.harness.center.Hub, selector: 21}
	var withheld v2.DataServiceReadExportResponse
	center04Call(t, run, browser, transfer, sandboxv2connect.DataServiceReadExportProcedure, last, &withheld, loss)
	if withheld.GetValue() != nil || withheld.GetError() == nil || loss.read == nil {
		t.Fatal("the fixture must withhold only a real verified final range before browser disclosure")
	}
	requireCenter04Range(t, loss.read, 1<<20, contents[1<<20:], true)

	writeCenter03Observation(t, run, "usage-reconnect", struct{}{})
	reconnected := center02Observation[center02Owner](t, run, "reconnected.json")
	if reconnected != reported || qualifyCenter03Peer(t, run, reconnected, &peer) == oldConnection {
		t.Fatal("reconnect must replace the live connection and preserve the original Node and durable owner identities")
	}
	freshBrowser := run.harness.newBrowser()
	freshBrowser.mustSignIn(run.owner)
	freshBrowser.bootstrapState()
	center04OutputReconnect(t, run, freshBrowser, watcher, cursor)
	center04Usage(t, run, freshBrowser, watcher, eventScope, previousSample)

	retained := center04Inspect(t, run, freshBrowser, transfer, export.GetTransferId())
	verifyCenter04Export(t, retained.GetValue().GetTransfer(), export.GetTransferId(), fileScope, expectedDigest, uint64(len(contents)), false)
	last.Meta = center03Meta(false, nil)
	var replayed v2.DataServiceReadExportResponse
	center04Call(t, run, freshBrowser, transfer, sandboxv2connect.DataServiceReadExportProcedure, last, &replayed, nil)
	center03Success(t, replayed.GetError(), replayed.GetValue())
	requireCenter04Range(t, replayed.GetValue().GetChunk(), 1<<20, contents[1<<20:], true)
	if !proto.Equal(loss.read, replayed.GetValue().GetChunk()) {
		t.Fatal("the original snapshot final range changed after the discarded reply")
	}
	center04Close(t, run, freshBrowser, transfer, ownerEpoch, retained.GetValue().GetTransfer(), retained.GetMeta().GetResultRev())
	afterClose := center04Inspect(t, run, freshBrowser, transfer, export.GetTransferId())
	verifyCenter04Export(t, afterClose.GetValue().GetTransfer(), export.GetTransferId(), fileScope, expectedDigest, uint64(len(contents)), true)
	var closedRead v2.DataServiceReadExportResponse
	center04Call(t, run, freshBrowser, transfer, sandboxv2connect.DataServiceReadExportProcedure, last, &closedRead, nil)
	if closedRead.GetValue() != nil || closedRead.GetError().GetEffect() != foundation.EffectCertainty_EFFECT_CERTAINTY_DID_NOT_HAPPEN {
		t.Fatal("closed export still served bytes or failed with an uncertain effect")
	}
	if got := run.harness.count("SELECT count(*) FROM management.command_identity WHERE account_id=$1 AND method=$2",
		run.owner.id, "DataService.BeginExport"); got != 1 {
		t.Fatalf("the Center retained %d original BeginExport command identities, expected 1", got)
	}
	writeCenter03Observation(t, run, "round-trip.json", map[string]string{
		"export": hex.EncodeToString(export.GetTransferId().GetValue()), "digest": expectedDigest,
	})

	center04RejectLaterGrant(t, run, freshBrowser, transfer, fileScope, ownerEpoch, files.SandboxRevision, "revoke", "revoked")
	short := center02Observation[center04Scope](t, run, "short-grant.json")
	shortScope := center03ID(center03ParseID(t, short.Sandbox))
	if proto.Equal(shortScope, fileScope) {
		t.Fatal("the expiry case requires its own Sandbox, because the revoked staging still holds the original transfer scope")
	}
	center04RejectLaterGrant(t, run, freshBrowser, short.target(t, peer), shortScope, ownerEpoch, short.SandboxRevision, "expire", "expired")
	center02WaitExit(t, run)
}

// TestCenter04InstalledTransferExpires waits for the installed Node's real
// one-hour export expiry. The fast paired case does not inherit this deadline.
func TestCenter04InstalledTransferExpires(t *testing.T) {
	run := startCenter04InstalledNode(t, center04ExpiryRequired, "ArcForges.ClosedLoop.Tests.RemoteStreamCenterExpiryTests", 65*time.Minute)
	approval := center02Observation[center02Approval](t, run, "approval.json")
	browser := run.ownerBrowser
	center02ApproveBrowserFlow(t, run.ctx, run.harness, browser, run.owner, approval.VerificationURI)
	reported := center02Observation[center02Owner](t, run, "connected.json")
	var peer center03Target
	qualifyCenter03Peer(t, run, reported, &peer)
	center02ConfirmConnection(t, run.coordination)

	owned := center02Observation[struct {
		center04Scope
		Digest string
		Bytes  uint64
	}](t, run, "file-scope.json")
	decoded, err := hex.DecodeString(owned.Digest)
	if err != nil || len(decoded) != sha256.Size || owned.Bytes == 0 || owned.Bytes > 1<<20 {
		t.Fatal("the disposable source did not report its exact bounded length and SHA-256")
	}
	target := owned.target(t, peer)
	sandbox := center03ID(center03ParseID(t, owned.Sandbox))
	ownerEpoch := center03ParseID(t, reported.OwnerEpoch)
	begin := &v2.DataServiceBeginExportRequest{
		Meta:       center03Meta(true, &foundation.Revision{Value: proto.Int64(owned.SandboxRevision)}),
		OwnerEpoch: center03ID(ownerEpoch), SandboxId: sandbox, RelativePath: proto.String("data/natural-expiry.bin"),
	}
	startedAt := time.Now()
	var started v2.DataServiceBeginExportResponse
	center04Call(t, run, browser, target, sandboxv2connect.DataServiceBeginExportProcedure, begin, &started, nil)
	center03Success(t, started.GetError(), started.GetValue())
	id := started.GetValue().GetTransfer().GetTransferId()
	if len(id.GetValue()) != 16 {
		t.Fatal("the natural-expiry fixture did not create exactly one export identity")
	}

	var original *v2.Transfer
	materializeBy := time.Now().Add(18 * time.Second)
	for time.Now().Before(materializeBy) {
		observed := center04Inspect(t, run, browser, target, id).GetValue().GetTransfer()
		if !proto.Equal(observed.GetTransferId(), id) || !proto.Equal(observed.GetSandboxId(), sandbox) ||
			observed.GetDirection() != "export" || observed.GetClosedAt() != nil {
			t.Fatal("the original export must remain in its granted scope during materialization")
		}
		if observed.GetState() == v2.TransferState_TRANSFER_STATE_COMPLETE {
			original = observed
			break
		}
		if observed.GetState() != v2.TransferState_TRANSFER_STATE_OPEN && observed.GetState() != v2.TransferState_TRANSFER_STATE_STREAMING {
			t.Fatalf("the original export did not materialize: %s", observed.GetState())
		}
		time.Sleep(100 * time.Millisecond)
	}
	verifyCenter04Export(t, original, id, sandbox, owned.Digest, owned.Bytes, false)
	expiry := original.GetExpiresAt()
	if expiry == nil {
		t.Fatal("the installed Node did not report the export lifetime")
	}
	expiresAt := time.Unix(expiry.GetUnixSeconds(), int64(expiry.GetNanos()))
	if expiresAt.Before(startedAt.Add(time.Hour-2*time.Second)) || expiresAt.After(time.Now().Add(time.Hour+2*time.Second)) {
		t.Fatal("the disposable export did not use the installed Node's one-hour lifetime")
	}

	read := &v2.DataServiceReadExportRequest{Meta: center03Meta(false, nil), TransferId: id,
		Offset: proto.Uint64(0), MaxBytes: proto.Uint32(uint32(owned.Bytes))}
	var before v2.DataServiceReadExportResponse
	center04Call(t, run, browser, target, sandboxv2connect.DataServiceReadExportProcedure, read, &before, nil)
	center03Success(t, before.GetError(), before.GetValue())
	chunk := before.GetValue().GetChunk()
	observedHash := sha256.Sum256(chunk.GetData())
	if !chunk.GetEof() || chunk.GetOffset() != 0 || uint64(len(chunk.GetData())) != owned.Bytes ||
		!bytes.Equal(observedHash[:], decoded) {
		t.Fatal("the original native snapshot's range did not verify before expiration")
	}
	writeCenter03Observation(t, run, "expiry-export.json", map[string]any{
		"transfer": hex.EncodeToString(id.GetValue()), "digest": owned.Digest, "bytes": owned.Bytes,
	})
	t.Logf("waiting for the original export's real expiry at %s", expiresAt.UTC().Format(time.RFC3339Nano))
	wait := time.NewTimer(time.Until(expiresAt))
	defer wait.Stop()
	select {
	case <-wait.C:
	case <-run.done:
		t.Fatal("the installed Node fixture ended before its original export expired")
	case <-run.ctx.Done():
		t.Fatal("the native fixture deadline elapsed before the original export expired")
	}

	fresh := run.harness.newBrowser()
	fresh.mustSignIn(run.owner)
	fresh.bootstrapState()
	qualifyCenter03Peer(t, run, reported, &peer)
	closedBy := time.Now().Add(45 * time.Second)
	var closedAt *foundation.Instant
	for time.Now().Before(closedBy) {
		current := center04Inspect(t, run, fresh, target, id).GetValue().GetTransfer()
		closedAt = current.GetClosedAt()
		verifyCenter04Export(t, current, id, sandbox, owned.Digest, owned.Bytes, closedAt != nil)
		want := proto.CloneOf(original)
		want.ClosedAt = closedAt
		if !proto.Equal(current, want) {
			t.Fatal("natural expiration changed the original completed export beyond its closure time")
		}
		if closedAt != nil {
			break
		}
		time.Sleep(250 * time.Millisecond)
	}
	if closedAt == nil || time.Unix(closedAt.GetUnixSeconds(), int64(closedAt.GetNanos())).Before(expiresAt) {
		t.Fatal("the installed Node did not close the original snapshot at or after its actual expiry")
	}

	read.Meta = center03Meta(false, nil)
	var after v2.DataServiceReadExportResponse
	center04Call(t, run, fresh, target, sandboxv2connect.DataServiceReadExportProcedure, read, &after, nil)
	failure := after.GetError()
	if after.GetValue() != nil || !v2.ValidateDataServiceReadExportResponse(&after) ||
		failure.GetCategory() != foundation.ErrorCategory_ERROR_CATEGORY_STATE || failure.GetCode() != "managed_use" ||
		failure.GetEffect() != foundation.EffectCertainty_EFFECT_CERTAINTY_DID_NOT_HAPPEN ||
		failure.GetDetails().GetState().GetReason() != "transfer_closed" ||
		!proto.Equal(after.GetMeta().GetCorrelationId(), read.GetMeta().GetCorrelationId()) ||
		!proto.Equal(failure.GetCorrelationId(), read.GetMeta().GetCorrelationId()) {
		t.Fatal("the naturally closed snapshot did not refuse the same authorized range without an effect")
	}
	if got := run.harness.count("SELECT count(*) FROM management.command_identity WHERE account_id=$1 AND method=$2",
		run.owner.id, "DataService.BeginExport"); got != 1 {
		t.Fatalf("the expiry fixture has %d BeginExport identities, expected exactly one", got)
	}
	command := platform.ID(begin.GetMeta().GetCommandId().GetValue())
	identity, receipt, err := management.New(run.harness.center.Store).InspectOriginal(run.ctx, management.Authority{
		Account: run.owner.id, Actor: run.owner.id, Node: target.node, Enrollment: target.enrollment,
		Grant: target.grant, GrantRevision: target.revision,
	}, command)
	if err != nil || identity.OwnerEpoch != ownerEpoch || identity.Method != "DataService.BeginExport" || receipt.DeliveryCount != 1 {
		t.Fatal("the original BeginExport command was not retained as one exact delivery")
	}
	writeCenter03Observation(t, run, "expiry-confirmed", struct{}{})
	center02WaitExit(t, run)
}

func center04Output(t *testing.T, run *center02NativeRun, b *browser, scope center03Target, selected center04Scope) *v2.RunServiceWatchOutputRequest {
	t.Helper()
	id := center03ID(center03ParseID(t, selected.Run))
	request := &v2.RunServiceWatchOutputRequest{Meta: center03Meta(false, nil), RunId: id}
	path := sandboxv2connect.RunServiceWatchOutputProcedure
	stream, close := center04Stream(t, run, b, scope, path, request)
	var first v2.RunServiceWatchOutputFrame
	if err := stream.Receive(&first); err != nil {
		close()
		t.Fatalf("the authorized output stream did not send its first frame: %s", connect.CodeOf(err))
	}
	prefix := first.GetChunk()
	if first.GetError() != nil || prefix.GetEpoch() != selected.RunEpoch || prefix.GetStream() != v2.StreamKind_STREAM_KIND_STDOUT ||
		prefix.GetOffset() != 0 || prefix.GetNextOffset() == 0 || uint64(len(prefix.GetData())) != prefix.GetNextOffset() ||
		!bytes.HasPrefix([]byte("CORE03 slow viewer \n"), prefix.GetData()) {
		close()
		t.Fatal("the first credit did not return the exact initial native output prefix")
	}
	writeCenter03Observation(t, run, "view-paused", struct{}{})
	center02WaitFile(t, run.ctx, run.coordination, "view-backlog", run.done)
	close()
	writeCenter03Observation(t, run, "view-cancelled", struct{}{})
	center02WaitFile(t, run.ctx, run.coordination, "output-finished", run.done)
	request.Meta = center03Meta(false, nil)
	request.Epoch, request.Stream, request.Offset = proto.String(prefix.GetEpoch()), prefix.GetStream().Enum(), proto.Uint64(0)
	stream, close = center04Stream(t, run, b, scope, path, request)
	var frame v2.RunServiceWatchOutputFrame
	err := stream.Receive(&frame)
	close()
	lost := frame.GetGap()
	const produced = uint64(len("CORE03 slow viewer \n") + (512 << 10) + (3 << 20))
	if err != nil || lost == nil || lost.GetEpoch() != selected.RunEpoch || lost.GetRequestedOffset() != 0 ||
		lost.GetEarliestOffset() == 0 || lost.GetEarliestOffset() >= produced || lost.GetReason() != "retention" {
		t.Fatal("evicted native output must return the original epoch and an explicit retained offset")
	}
	request.Meta = center03Meta(false, nil)
	cursor := lost.GetEarliestOffset()
	request.Offset = proto.Uint64(cursor)
	stream, close = center04Stream(t, run, b, scope, path, request)
	defer close()
	for {
		frame.Reset()
		err := stream.Receive(&frame)
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil || frame.GetError() != nil || frame.GetGap() != nil {
			t.Fatal("the exact resumed stdout view did not drain cleanly")
		}
		if summary := frame.GetRun(); summary != nil {
			if summary.GetEpoch() != selected.RunEpoch || !proto.Equal(summary.GetRunId(), id) {
				t.Fatal("the resumed output reported a different Run")
			}
			continue
		}
		chunk := frame.GetChunk()
		if chunk == nil || chunk.GetEpoch() != selected.RunEpoch || chunk.GetOffset() != cursor || chunk.GetStream() != request.GetStream() ||
			uint64(len(chunk.GetData())) != chunk.GetNextOffset()-cursor || chunk.GetNextOffset() > produced ||
			bytes.Count(chunk.GetData(), []byte{'T'}) != len(chunk.GetData()) {
			t.Fatal("the resumed stdout bytes are discontinuous or differ from the known native tail")
		}
		cursor = chunk.GetNextOffset()
	}
	if cursor != produced || produced-lost.GetEarliestOffset() > 4096 {
		t.Fatal("the retained stdout exceeded its native cap or did not reach the original end offset")
	}
	return &v2.RunServiceWatchOutputRequest{Meta: center03Meta(false, nil), RunId: id,
		Epoch: request.Epoch, Stream: request.Stream, Offset: proto.Uint64(cursor)}
}

func center04OutputReconnect(t *testing.T, run *center02NativeRun, b *browser, scope center03Target,
	cursor *v2.RunServiceWatchOutputRequest) {
	t.Helper()
	path := sandboxv2connect.RunServiceWatchOutputProcedure
	stream, close := center04Stream(t, run, b, scope, path, cursor)
	var frame v2.RunServiceWatchOutputFrame
	err := stream.Receive(&frame)
	close()
	summary := frame.GetRun()
	if err != nil || summary.GetEpoch() != cursor.GetEpoch() || !proto.Equal(summary.GetRunId(), cursor.GetRunId()) ||
		summary.GetState() != v2.RunState_RUN_STATE_EXITED {
		t.Fatal("the exact end cursor did not resume the same completed Run after channel replacement")
	}
	stale := proto.CloneOf(cursor)
	stale.Meta, stale.Epoch = center03Meta(false, nil), proto.String(platform.NewID().String())
	stream, close = center04Stream(t, run, b, scope, path, stale)
	defer close()
	frame.Reset()
	if err := stream.Receive(&frame); err != nil || frame.GetGap().GetReason() != "epoch_changed" ||
		frame.GetGap().GetEpoch() != cursor.GetEpoch() || frame.GetGap().GetRequestedOffset() != cursor.GetOffset() {
		t.Fatal("a different output epoch must report the explicit requested offset and current Run epoch")
	}
}

func center04RejectOversize(t *testing.T, run *center02NativeRun, b *browser, target center03Target, scope, epoch *foundation.Id,
	revision int64, digest string) {
	t.Helper()
	const maximum = 256 << 20 // SandboxManager.DataMaxFileBytes.
	request := &v2.DataServiceBeginImportRequest{Meta: center03Meta(true, &foundation.Revision{Value: proto.Int64(revision)}),
		OwnerEpoch: epoch, SandboxId: scope, RelativePath: proto.String("data/oversize-import.bin"), ByteLength: proto.Uint64(maximum + 1),
		Sha256: proto.String(digest), Overwrite: proto.Bool(false)}
	var reply v2.DataServiceBeginImportResponse
	center04Call(t, run, b, target, sandboxv2connect.DataServiceBeginImportProcedure, request, &reply, nil)
	failure := reply.GetError()
	correlation := request.GetMeta().GetCorrelationId()
	if reply.GetValue() != nil || !v2.ValidateDataServiceBeginImportResponse(&reply) ||
		failure.GetCategory() != foundation.ErrorCategory_ERROR_CATEGORY_RESOURCE || failure.GetCode() != "disk_space" ||
		failure.GetEffect() != foundation.EffectCertainty_EFFECT_CERTAINTY_DID_NOT_HAPPEN ||
		failure.GetRetry().GetMode() != foundation.RetryMode_RETRY_MODE_AFTER_TIME || failure.GetRetry().GetRetryAt() == nil ||
		!proto.Equal(failure.GetCorrelationId(), correlation) || !proto.Equal(reply.GetMeta().GetCorrelationId(), correlation) ||
		failure.GetDetails().GetState().GetReason() != "transfer_storage_limit" {
		t.Fatalf("an oversized declared import must preserve the signed no-effect storage refusal, got %s/%s/%s",
			failure.GetCategory(), failure.GetCode(), failure.GetEffect())
	}
	command := platform.ID(request.GetMeta().GetCommandId().GetValue())
	identity, receipt, err := management.New(run.harness.center.Store).InspectOriginal(run.ctx, management.Authority{
		Account: run.owner.id, Actor: run.owner.id, Node: target.node, Enrollment: target.enrollment,
		Grant: target.grant, GrantRevision: target.revision,
	}, command)
	if err != nil || identity.OwnerEpoch != platform.ID(epoch.GetValue()) || identity.Method != "DataService.BeginImport" ||
		receipt.State != management.StateRejected || receipt.Effect == nil || *receipt.Effect != management.EffectDidNotHappen ||
		!receipt.MayHaveDelivered || receipt.DeliveryCount != 1 || receipt.FinalAt == nil || receipt.ResultID != nil ||
		receipt.ResultKind != "" || len(receipt.ResultSHA256) != sha256.Size || receipt.Reason != "disk_space" {
		t.Fatal("the original oversized import did not leave exactly one content-free rejected PostgreSQL receipt")
	}
	writeCenter03Observation(t, run, "oversize.json", map[string]string{"command": hex.EncodeToString(command[:])})
	t.Log("the oversized import declared only metadata and retained its signed no-effect storage refusal")
}

func center04Upload(t *testing.T, run *center02NativeRun, b *browser, target center03Target, scope, epoch *foundation.Id,
	revision int64, payload []byte, digest string) {
	t.Helper()
	started := center04BeginImport(t, run, b, target, scope, epoch, revision, "round-trip", "round-trip.bin", uint64(len(payload)), digest)
	id := started.GetValue().GetTransfer().GetTransferId()
	center04RecordTransfer(t, run, "import.json", id)
	var prefix v2.DataServiceWriteImportResponse
	first := &v2.DataServiceWriteImportRequest{Meta: center03Meta(true, center04Revision(t, started.GetMeta())), OwnerEpoch: epoch,
		TransferId: id, Offset: proto.Uint64(0), Chunk: payload[:1<<20]}
	center04Call(t, run, b, target, sandboxv2connect.DataServiceWriteImportProcedure, first, &prefix, nil)
	center03Success(t, prefix.GetError(), prefix.GetValue())
	partial := center04Inspect(t, run, b, target, id)
	current := partial.GetValue().GetTransfer()
	if !proto.Equal(current.GetTransferId(), id) || !proto.Equal(current.GetSandboxId(), scope) ||
		current.GetVerifiedOffset() != 1<<20 || current.GetByteLength() != uint64(len(payload)) ||
		current.GetState() != v2.TransferState_TRANSFER_STATE_STREAMING || current.GetClosedAt() != nil {
		t.Fatal("InspectTransfer did not describe the original partly written one-file staging")
	}
	last := &v2.DataServiceWriteImportRequest{Meta: center03Meta(true, center04Revision(t, partial.GetMeta())), OwnerEpoch: epoch,
		TransferId: id, Offset: proto.Uint64(1 << 20), Chunk: payload[1<<20:]}
	var staged v2.DataServiceWriteImportResponse
	center04Call(t, run, b, target, sandboxv2connect.DataServiceWriteImportProcedure, last, &staged, nil)
	center03Success(t, staged.GetError(), staged.GetValue())
	if got := staged.GetValue().GetTransfer().GetVerifiedOffset(); got != uint64(len(payload)) {
		t.Fatalf("final import offset=%d; original file length=%d", got, len(payload))
	}
	commit := &v2.DataServiceCommitImportRequest{Meta: center03Meta(true, center04Revision(t, staged.GetMeta())),
		OwnerEpoch: epoch, TransferId: id}
	command := platform.ID(commit.GetMeta().GetCommandId().GetValue())
	loss := &center04LostResult{V2ControlTransport: run.harness.center.Hub, selector: 19, command: command}
	var uncertain v2.DataServiceCommitImportResponse
	center04Call(t, run, b, target, sandboxv2connect.DataServiceCommitImportProcedure, commit, &uncertain, loss)
	if uncertain.GetValue() != nil || uncertain.GetError().GetCode() != "outcome_unknown" ||
		uncertain.GetError().GetEffect() != foundation.EffectCertainty_EFFECT_CERTAINTY_UNKNOWN || loss.commit == nil {
		t.Fatal("the missing verified commit reply did not preserve the uncertain effect")
	}
	identity, receipt, err := management.New(run.harness.center.Store).InspectOriginal(run.ctx, management.Authority{
		Account: run.owner.id, Actor: run.owner.id, Node: target.node, Enrollment: target.enrollment, Grant: target.grant, GrantRevision: target.revision,
	}, command)
	if err != nil || identity.OwnerEpoch != platform.ID(epoch.GetValue()) || identity.Method != "DataService.CommitImport" ||
		receipt.State != management.StateUnknown || !receipt.MayHaveDelivered || receipt.DeliveryCount != 1 {
		t.Fatal("PostgreSQL lost or advanced the original possibly delivered commit receipt")
	}
	readback := center04Inspect(t, run, b, target, id)
	imported, effect := readback.GetValue().GetTransfer(), loss.commit.GetOperation()
	if !proto.Equal(imported.GetTransferId(), id) || !proto.Equal(imported.GetSandboxId(), scope) ||
		imported.GetSha256() != digest || imported.GetVerifiedOffset() != uint64(len(payload)) ||
		imported.GetState() != v2.TransferState_TRANSFER_STATE_COMPLETE || !proto.Equal(imported, loss.commit.GetTransfer()) ||
		imported.GetClosedAt() != nil ||
		!proto.Equal(effect.GetCommandId(), commit.GetMeta().GetCommandId()) || !proto.Equal(effect.GetOwnerEpoch(), epoch) ||
		effect.GetEffect() != foundation.EffectCertainty_EFFECT_CERTAINTY_HAPPENED {
		t.Fatal("the one-file import did not produce its exact completed transfer and durable commit effect")
	}
	center04Close(t, run, b, target, epoch, imported, readback.GetMeta().GetResultRev())
	closed := center04Inspect(t, run, b, target, id).GetValue().GetTransfer()
	expected := proto.CloneOf(imported)
	expected.ClosedAt = closed.GetClosedAt()
	if expected.GetClosedAt() == nil || !proto.Equal(closed, expected) {
		t.Fatal("the original authorized import did not retain its exact committed state and digest after closing")
	}
}

func center04Export(t *testing.T, run *center02NativeRun, b *browser, target center03Target, scope, epoch *foundation.Id,
	revision int64, payload []byte, digest string) *v2.Transfer {
	t.Helper()
	request := &v2.DataServiceBeginExportRequest{Meta: center03Meta(true, &foundation.Revision{Value: proto.Int64(revision)}),
		OwnerEpoch: epoch, SandboxId: scope, RelativePath: proto.String("data/round-trip.bin")}
	var begun v2.DataServiceBeginExportResponse
	center04Call(t, run, b, target, sandboxv2connect.DataServiceBeginExportProcedure, request, &begun, nil)
	center03Success(t, begun.GetError(), begun.GetValue())
	id := begun.GetValue().GetTransfer().GetTransferId()
	center04RecordTransfer(t, run, "export.json", id)
	ctx, cancel := context.WithTimeout(run.ctx, 18*time.Second)
	defer cancel()
	ticker := time.NewTicker(75 * time.Millisecond)
	defer ticker.Stop()
	for {
		reply := center04Inspect(t, run, b, target, id)
		current := reply.GetValue().GetTransfer()
		if !proto.Equal(current.GetTransferId(), id) || !proto.Equal(current.GetSandboxId(), scope) ||
			current.GetDirection() != "export" || current.GetClosedAt() != nil {
			t.Fatal("export progress moved away from the same authorized unclosed transfer")
		}
		if current.GetState() == v2.TransferState_TRANSFER_STATE_COMPLETE {
			verifyCenter04Export(t, current, id, scope, digest, uint64(len(payload)), false)
			read := &v2.DataServiceReadExportRequest{Meta: center03Meta(false, nil), TransferId: id,
				Offset: proto.Uint64(0), MaxBytes: proto.Uint32(1 << 20)}
			var prefix v2.DataServiceReadExportResponse
			center04Call(t, run, b, target, sandboxv2connect.DataServiceReadExportProcedure, read, &prefix, nil)
			center03Success(t, prefix.GetError(), prefix.GetValue())
			requireCenter04Range(t, prefix.GetValue().GetChunk(), 0, payload[:1<<20], false)
			return current
		}
		if current.GetState() != v2.TransferState_TRANSFER_STATE_OPEN &&
			current.GetState() != v2.TransferState_TRANSFER_STATE_STREAMING {
			t.Fatalf("the original export materialization ended in %s", current.GetState())
		}
		select {
		case <-ticker.C:
		case <-ctx.Done():
			t.Fatal("the original export did not materialize before the native fixture deadline")
		}
	}
}

func center04BeginImport(t *testing.T, run *center02NativeRun, b *browser, target center03Target, scope, epoch *foundation.Id,
	revision int64, phase, name string, size uint64, digest string) *v2.DataServiceBeginImportResponse {
	t.Helper()
	request := &v2.DataServiceBeginImportRequest{Meta: center03Meta(true, &foundation.Revision{Value: proto.Int64(revision)}),
		OwnerEpoch: epoch, SandboxId: scope, RelativePath: proto.String("data/" + name), ByteLength: proto.Uint64(size),
		Sha256: proto.String(digest), Overwrite: proto.Bool(false)}
	var begun v2.DataServiceBeginImportResponse
	center04Call(t, run, b, target, sandboxv2connect.DataServiceBeginImportProcedure, request, &begun, nil)
	if begun.GetError() != nil || begun.GetValue() == nil {
		t.Fatalf("%s BeginImport expected usable staging, got %s", phase, center04DataError(begun.GetError()))
	}
	staged := begun.GetValue().GetTransfer()
	if !proto.Equal(staged.GetSandboxId(), scope) || staged.GetDirection() != "import" || staged.GetVerifiedOffset() != 0 ||
		staged.GetByteLength() != size || staged.GetClosedAt() != nil || staged.GetExpiresAt() == nil {
		t.Fatalf("%s BeginImport did not open exact zero-byte staging for its granted Sandbox", phase)
	}
	return &begun
}

func center04Inspect(t *testing.T, run *center02NativeRun, b *browser, target center03Target, id *foundation.Id) *v2.DataServiceInspectTransferResponse {
	t.Helper()
	var reply v2.DataServiceInspectTransferResponse
	center04Call(t, run, b, target, sandboxv2connect.DataServiceInspectTransferProcedure,
		&v2.DataServiceInspectTransferRequest{Meta: center03Meta(false, nil), TransferId: id}, &reply, nil)
	center03Success(t, reply.GetError(), reply.GetValue())
	return &reply
}

func center04Close(t *testing.T, run *center02NativeRun, b *browser, target center03Target, epoch *foundation.Id,
	original *v2.Transfer, revision *foundation.Revision) {
	t.Helper()
	if revision.GetValue() <= 0 {
		t.Fatal("no current transfer revision for the intended Close")
	}
	request := &v2.DataServiceCloseTransferRequest{Meta: center03Meta(true, revision), OwnerEpoch: epoch, TransferId: original.GetTransferId()}
	var closed v2.DataServiceCloseTransferResponse
	center04Call(t, run, b, target, sandboxv2connect.DataServiceCloseTransferProcedure, request, &closed, nil)
	center03Success(t, closed.GetError(), closed.GetValue())
	final := closed.GetValue().GetTransfer()
	if !proto.Equal(final.GetTransferId(), original.GetTransferId()) || final.GetClosedAt() == nil ||
		final.GetState() != original.GetState() || final.GetSha256() != original.GetSha256() {
		t.Fatal("CloseTransfer did not preserve the original completed transfer and release its staging or snapshot")
	}
}

func verifyCenter04Export(t *testing.T, transfer *v2.Transfer, id, sandbox *foundation.Id, hash string, length uint64, closed bool) {
	t.Helper()
	if !proto.Equal(transfer.GetTransferId(), id) || !proto.Equal(transfer.GetSandboxId(), sandbox) ||
		transfer.GetState() != v2.TransferState_TRANSFER_STATE_COMPLETE || transfer.GetDirection() != "export" ||
		transfer.GetByteLength() != length || transfer.GetVerifiedOffset() != length || transfer.GetSha256() != hash ||
		(transfer.GetClosedAt() != nil) != closed {
		t.Fatal("InspectTransfer did not preserve the original complete export, digest, range or actual closure")
	}
}

func requireCenter04Range(t *testing.T, chunk *v2.DataChunk, offset uint64, expected []byte, eof bool) {
	t.Helper()
	if chunk == nil || chunk.GetOffset() != offset || !bytes.Equal(chunk.GetData(), expected) || chunk.GetEof() != eof {
		t.Fatal("the verified bytes, offset or EOF do not describe the expected immutable snapshot range")
	}
}

func center04RejectLaterGrant(t *testing.T, run *center02NativeRun, b *browser, target center03Target, scope, epoch *foundation.Id,
	revision int64, trigger, result string) {
	t.Helper()
	content := []byte{'Z'}
	hash := sha256.Sum256(content)
	staged := center04BeginImport(t, run, b, target, scope, epoch, revision, trigger, result+".bin", 1, hex.EncodeToString(hash[:]))
	original := staged.GetValue().GetTransfer()
	id := original.GetTransferId()
	center04RecordTransfer(t, run, result+"-import.json", id)
	center04RecordTransfer(t, run, trigger+"-transfer.json", id)
	center02WaitFile(t, run.ctx, run.coordination, "grant-"+result, run.done)
	if original.GetExpiresAt().GetUnixSeconds() <= time.Now().Unix() {
		t.Fatal("the negative case must exercise owner grant expiry or revocation with an unexpired original transfer")
	}
	write := &v2.DataServiceWriteImportRequest{Meta: center03Meta(true, center04Revision(t, staged.GetMeta())), OwnerEpoch: epoch,
		TransferId: id, Offset: proto.Uint64(0), Chunk: content}
	var refused v2.DataServiceWriteImportResponse
	center04Call(t, run, b, target, sandboxv2connect.DataServiceWriteImportProcedure, write, &refused, nil)
	center04RequireGrantRefusal(t, trigger, "WriteImport", refused.GetError())
	if refused.GetValue() != nil {
		t.Fatal("a denied WriteImport returned observable mutation data")
	}
	if result == "revoked" {
		commit := &v2.DataServiceCommitImportRequest{Meta: center03Meta(true, center04Revision(t, staged.GetMeta())),
			OwnerEpoch: epoch, TransferId: id}
		var denied v2.DataServiceCommitImportResponse
		center04Call(t, run, b, target, sandboxv2connect.DataServiceCommitImportProcedure, commit, &denied, nil)
		center04RequireGrantRefusal(t, trigger, "CommitImport", denied.GetError())
	}
	var invisible v2.DataServiceInspectTransferResponse
	center04Call(t, run, b, target, sandboxv2connect.DataServiceInspectTransferProcedure,
		&v2.DataServiceInspectTransferRequest{Meta: center03Meta(false, nil), TransferId: id}, &invisible, nil)
	failure := invisible.GetError()
	if invisible.GetValue() != nil || failure.GetCategory() != foundation.ErrorCategory_ERROR_CATEGORY_STATE ||
		failure.GetCode() != "not_found" || failure.GetEffect() != foundation.EffectCertainty_EFFECT_CERTAINTY_DID_NOT_HAPPEN {
		t.Fatalf("%s InspectTransfer did not conceal the transfer after grant loss: %s", trigger, center04DataError(failure))
	}
	writeCenter03Observation(t, run, trigger+"-refused", struct{}{})
}

func center04RecordTransfer(t *testing.T, run *center02NativeRun, name string, id *foundation.Id) {
	t.Helper()
	if len(id.GetValue()) != 16 {
		t.Fatal("the original durable transfer ID is malformed")
	}
	writeCenter03Observation(t, run, name, map[string]string{"transfer": hex.EncodeToString(id.GetValue())})
}

func center04Revision(t *testing.T, meta *foundation.ResponseMeta) *foundation.Revision {
	t.Helper()
	if value := meta.GetResultRev(); value.GetValue() <= 0 {
		t.Fatal("the real data result did not report its current transfer revision")
	}
	return meta.GetResultRev()
}

type center04LostResult struct {
	fleetapi.V2ControlTransport
	selector management.V2ControlSelector
	command  platform.ID
	read     *v2.DataChunk
	commit   *v2.DataServiceCommitImportValue
}

func center04RequireGrantRefusal(t *testing.T, phase, method string, failure *foundation.ArcError) {
	t.Helper()
	if failure.GetCategory() != foundation.ErrorCategory_ERROR_CATEGORY_AUTHORIZATION || failure.GetCode() != "permission_denied" ||
		failure.GetEffect() != foundation.EffectCertainty_EFFECT_CERTAINTY_DID_NOT_HAPPEN {
		t.Fatalf("%s %s expected AUTHORIZATION/permission_denied/DID_NOT_HAPPEN, got %s", phase, method, center04DataError(failure))
	}
}

func center04DataError(failure *foundation.ArcError) string {
	if failure == nil {
		return "no typed error"
	}
	code, reason := failure.GetCode(), failure.GetDetails().GetState().GetReason()
	switch code {
	case "outcome_unknown", "permission_denied", "disk_space", "busy", "invalid_argument", "not_found",
		"command_id_reused", "owner_epoch_retired", "revision_mismatch", "overloaded", "internal", "store_corrupt",
		"unauthenticated", "node_offline":
	default:
		code = "other"
	}
	switch reason {
	case "", "admission_commit_uncertain", "no_verified_response", "no_delivery_not_confirmed", "unclaimed_result",
		"result_unverifiable", "result_identity_mismatch", "result_settlement_unconfirmed", "transfer_storage_limit",
		"transfer_staging_capacity", "import_stage_pending_reconciliation", "remote_grant_authority_unavailable":
	default:
		reason = "other"
	}
	return fmt.Sprintf("category=%s code=%s effect=%s retry=%s retry_at_present=%t reason=%q",
		failure.GetCategory(), code, failure.GetEffect(), failure.GetRetry().GetMode(), failure.GetRetry().GetRetryAt() != nil, reason)
}

func (f *center04LostResult) CallV2(ctx context.Context, authority management.V2ControlAuthority, call management.V2ControlCall,
	claim func(context.Context, management.V2ControlAuthority) (bool, error)) ([]byte, error) {
	body, err := f.V2ControlTransport.CallV2(ctx, authority, call, claim)
	if err != nil || call.Selector != f.selector || call.CommandID != f.command {
		return body, err
	}
	if f.selector == 19 && claim != nil {
		var reply v2.DataServiceCommitImportResponse
		if proto.Unmarshal(body, &reply) != nil || !v2.ValidateDataServiceCommitImportResponse(&reply) || reply.GetValue() == nil {
			return nil, errors.New("could not observe the verified original commit")
		}
		f.commit = reply.GetValue()
	}
	if f.selector == 21 && claim == nil {
		var reply v2.DataServiceReadExportResponse
		if proto.Unmarshal(body, &reply) != nil || !v2.ValidateDataServiceReadExportResponse(&reply) || reply.GetValue().GetChunk() == nil {
			return nil, errors.New("could not observe a verified typed final export range")
		}
		f.read = reply.GetValue().GetChunk()
	}
	if f.commit == nil && f.read == nil {
		return body, nil
	}
	return nil, management.ErrV2ControlUncertain
}

func center04TransferClient(b *browser, target center03Target, fault *center04LostResult, t *testing.T, run *center02NativeRun) *connect.Client {
	t.Helper()
	client := center03BrowserTransport{browser: b, target: target}
	if fault != nil {
		client.fault = center03FaultHandler(t, run, fault)
	}
	return connect.NewClient(connecthttp.NewTransport(client, b.h.url, connecthttp.WithGRPCWeb(),
		connecthttp.WithReadMaxBytes(2<<20), connecthttp.WithSendMaxBytes(2<<20)))
}

func center04Call(t *testing.T, run *center02NativeRun, b *browser, target center03Target, path string, in, out proto.Message, fault *center04LostResult) {
	t.Helper()
	client := center04TransferClient(b, target, fault, t, run)
	ctx, cancel := context.WithTimeout(run.ctx, 33*time.Second)
	defer cancel()
	if err := client.CallUnary(ctx, connect.Spec{Procedure: path, StreamType: connect.StreamTypeUnary}, in, out); err != nil {
		t.Fatalf("the typed Center RPC %s ended with transport status %s", path, connect.CodeOf(err))
	}
}

func center04Stream(t *testing.T, run *center02NativeRun, b *browser, target center03Target, path string, req proto.Message) (connect.ClientStream, func()) {
	t.Helper()
	client := center04TransferClient(b, target, nil, t, run)
	ctx, cancel := context.WithTimeout(run.ctx, 12*time.Second)
	stream, err := client.CallServerStream(ctx, connect.Spec{Procedure: path, StreamType: connect.StreamTypeServer}, req)
	if err != nil {
		cancel()
		t.Fatalf("the scoped Center stream %s was not admitted: %s", path, connect.CodeOf(err))
	}
	return stream, func() {
		cancel()
		_ = stream.Close()
	}
}

func startCenter04InstalledNode(t *testing.T, required, testClass string, duration time.Duration) *center02NativeRun {
	t.Helper()
	if os.Getenv(required) != "1" {
		t.Skip("the installed stream and data supplement requires a scoped native fixture")
	}
	project := center02File(t, center02Project)
	center02File(t, "ARCFORGES_HOST_PATH")
	center02File(t, "ARCFORGES_TESTLOAD_PATH")
	if os.Getenv("ARCFORGES_TEST_POSTGRES_REQUIRED") != "1" || os.Getenv("ARCFORGES_MXC_PACKAGE_TESTS") != "1" {
		t.Fatal("the native fixture requires real PostgreSQL and the verified MXC extraction")
	}
	cert, err := tls.LoadX509KeyPair(center02File(t, center02Cert), center02File(t, center02Key))
	if err != nil {
		t.Fatal("the scoped localhost TLS certificate and key could not be loaded")
	}
	leaf, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil || leaf.VerifyHostname("localhost") != nil {
		t.Fatal("the scoped TLS certificate must name localhost")
	}
	h := newHarness(t, settings{surfaces: "identity,pages,fleet,relay,nodes", policy: writePolicy, relay: true, nativeCertificate: &cert})
	h.http.Timeout = 35 * time.Second
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
	ctx, cancel := context.WithTimeout(context.Background(), duration)
	t.Cleanup(cancel)
	processContext, cancelProcess := context.WithTimeout(context.Background(), duration+time.Minute)
	t.Cleanup(cancelProcess)
	command := exec.CommandContext(processContext, "dotnet", "test", "--project", project, "-c", "Release", "--no-build",
		"--filter-class", testClass, "--minimum-expected-tests", "1", "--fail-skips", "on")
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
			t.Log(run.output.String())
		}
	})
	return run
}

func center04Events(t *testing.T, run *center02NativeRun, b *browser, scope center03Target, sandbox, runID *foundation.Id, epoch string) {
	t.Helper()
	path := sandboxv2connect.NodeServiceWatchEventsProcedure
	request := &v2.NodeServiceWatchEventsRequest{Meta: center03Meta(false, nil),
		Epoch: proto.String(platform.NewID().String()), AfterSequence: proto.Uint64(0)}
	stream, close := center04Stream(t, run, b, scope, path, request)
	var frame v2.NodeServiceWatchEventsFrame
	err := stream.Receive(&frame)
	close()
	gap := frame.GetGap()
	if err != nil || gap == nil || gap.GetEpoch() != epoch || gap.GetRequestedSequence() != 0 ||
		gap.GetEarliestSequence() == 0 || gap.GetReason() != "epoch_changed" {
		t.Fatal("a prior event epoch must report an explicit gap for the current Node event epoch")
	}
	request.Meta, request.Epoch = center03Meta(false, nil), proto.String(epoch)
	request.AfterSequence = proto.Uint64(gap.GetEarliestSequence() - 1)
	stream, close = center04Stream(t, run, b, scope, path, request)
	defer close()
	cursor := request.GetAfterSequence()
	for range 16 {
		frame.Reset()
		if err := stream.Receive(&frame); err != nil {
			t.Fatalf("the event resnapshot did not produce a scoped lifecycle event: %s", connect.CodeOf(err))
		}
		event := frame.GetEvent()
		if event == nil || event.GetEpoch() != epoch || event.GetSequence() <= cursor ||
			event.GetObservedAt() == nil || !proto.Equal(event.GetSandboxId(), sandbox) {
			t.Fatal("the resumed event is outside its exact Node epoch or granted Sandbox")
		}
		cursor = event.GetSequence()
		if event.GetKind() == v2.EventKind_EVENT_KIND_RUN && proto.Equal(event.GetRunId(), runID) {
			return
		}
	}
	t.Fatal("the bounded event resnapshot did not observe the original native Run")
}

func center04WatchQuota(t *testing.T, run *center02NativeRun, b *browser, scope center03Target, sandbox *foundation.Id) *v2.ResourceSnapshot {
	t.Helper()
	const capacity = 8
	path := sandboxv2connect.ResourceServiceWatchUsageProcedure
	var releases [capacity]func()
	for i := range releases {
		request := &v2.ResourceServiceWatchUsageRequest{Meta: center03Meta(false, nil), ScopeKind: proto.String("sandbox"),
			ScopeId: sandbox, IntervalMs: proto.Uint32(60_000)}
		stream, release := center04Stream(t, run, b, scope, path, request)
		releases[i] = release
		defer release()
		var frame v2.ResourceServiceWatchUsageFrame
		if err := stream.Receive(&frame); err != nil || !v2.ValidateResourceServiceWatchUsageFrame(&frame) ||
			!proto.Equal(frame.GetMeta().GetCorrelationId(), request.GetMeta().GetCorrelationId()) ||
			frame.GetError() != nil || !proto.Equal(frame.GetSnapshot().GetScopeId(), sandbox) {
			t.Fatalf("owned idle resource watch %d of %d was not admitted: %s/%s, transport %v",
				i+1, capacity, frame.GetError().GetCategory(), frame.GetError().GetCode(), connect.CodeOf(err))
		}
	}

	ninth := &v2.ResourceServiceWatchUsageRequest{Meta: center03Meta(false, nil), ScopeKind: proto.String("sandbox"),
		ScopeId: sandbox, IntervalMs: proto.Uint32(60_000)}
	stream, closeNinth := center04Stream(t, run, b, scope, path, ninth)
	defer closeNinth()
	var refused v2.ResourceServiceWatchUsageFrame
	if err := stream.Receive(&refused); err != nil || !center04QuotaRefusal(&refused, ninth.GetMeta().GetCorrelationId()) {
		t.Fatalf("the ninth live view did not return its exact typed, correlated RESOURCE/overloaded frame: %s/%s, transport %v",
			refused.GetError().GetCategory(), refused.GetError().GetCode(), connect.CodeOf(err))
	}
	if err := stream.Receive(new(v2.ResourceServiceWatchUsageFrame)); !errors.Is(err, io.EOF) {
		t.Fatal("the overloaded resource stream did not close after its one error frame")
	}
	closeNinth()
	for _, release := range releases {
		release()
	}

	released, cancel := context.WithTimeout(run.ctx, 4*time.Second)
	defer cancel()
	tick := time.NewTicker(40 * time.Millisecond)
	defer tick.Stop()
	client := center04TransferClient(b, scope, nil, t, run)
	for {
		request := &v2.ResourceServiceWatchUsageRequest{Meta: center03Meta(false, nil), ScopeKind: proto.String("sandbox"),
			ScopeId: sandbox, IntervalMs: proto.Uint32(1000)}
		canResume, err := client.CallServerStream(released, connect.Spec{Procedure: path, StreamType: connect.StreamTypeServer}, request)
		if err != nil {
			t.Fatalf("the resource stream could not reopen after owned cancellation: %s", connect.CodeOf(err))
		}
		var frame v2.ResourceServiceWatchUsageFrame
		correlation := request.GetMeta().GetCorrelationId()
		err = canResume.Receive(&frame)
		if err == nil && center04QuotaRefusal(&frame, correlation) {
			// The HTTP handlers can still be processing the just-issued cancellations.
			_ = canResume.Close()
			select {
			case <-tick.C:
				continue
			case <-released.Done():
				t.Fatal("the owned resource watches did not release their capacity")
			}
		}
		for err == nil && v2.ValidateResourceServiceWatchUsageFrame(&frame) && frame.GetError() == nil &&
			proto.Equal(frame.GetMeta().GetCorrelationId(), correlation) && proto.Equal(frame.GetSnapshot().GetScopeId(), sandbox) {
			sample := frame.GetSnapshot()
			if !sample.GetStale() && sample.GetSampleSequence() > 0 && sample.GetSampleEpoch() != "" && sample.GetSampledAt() != nil {
				_ = canResume.Close()
				t.Log("eight live resource watches admitted, the ninth closed overloaded, and cancellation permitted a fresh resnapshot")
				return sample
			}
			frame.Reset()
			err = canResume.Receive(&frame)
		}
		_ = canResume.Close()
		t.Fatal("released capacity did not deliver the authorized fresh resource snapshot")
	}
}

func center04QuotaRefusal(frame *v2.ResourceServiceWatchUsageFrame, correlation *foundation.Id) bool {
	failure := frame.GetError()
	return v2.ValidateResourceServiceWatchUsageFrame(frame) && frame.GetSnapshot() == nil &&
		failure.GetCategory() == foundation.ErrorCategory_ERROR_CATEGORY_RESOURCE && failure.GetCode() == "overloaded" &&
		failure.GetEffect() == foundation.EffectCertainty_EFFECT_CERTAINTY_DID_NOT_HAPPEN &&
		proto.Equal(frame.GetMeta().GetCorrelationId(), correlation) && proto.Equal(failure.GetCorrelationId(), correlation)
}

func center04Usage(t *testing.T, run *center02NativeRun, b *browser, scope center03Target, sandbox *foundation.Id,
	previous *v2.ResourceSnapshot) *v2.ResourceSnapshot {
	t.Helper()
	request := &v2.ResourceServiceWatchUsageRequest{Meta: center03Meta(false, nil), ScopeKind: proto.String("sandbox"),
		ScopeId: sandbox, IntervalMs: proto.Uint32(1000)}
	stream, close := center04Stream(t, run, b, scope, sandboxv2connect.ResourceServiceWatchUsageProcedure, request)
	defer close()
	for {
		var frame v2.ResourceServiceWatchUsageFrame
		if err := stream.Receive(&frame); err != nil {
			t.Fatalf("the resource view did not return a fresh snapshot: %s", connect.CodeOf(err))
		}
		sample := frame.GetSnapshot()
		if sample == nil || frame.GetError() != nil || !proto.Equal(sample.GetScopeId(), sandbox) ||
			sample.GetScopeKind() != "sandbox" || sample.GetSampleEpoch() == "" || sample.GetSampledAt() == nil ||
			sample.GetPolicyRevision().GetValue() < 1 || sample.GetSampleSequence() == 0 {
			t.Fatal("the resource frame is not a complete snapshot for the authorized Sandbox")
		}
		if sample.GetStale() {
			continue
		}
		previousAt, currentAt := previous.GetSampledAt(), sample.GetSampledAt()
		newer := currentAt.GetUnixSeconds() > previousAt.GetUnixSeconds() ||
			currentAt.GetUnixSeconds() == previousAt.GetUnixSeconds() && currentAt.GetNanos() > previousAt.GetNanos()
		if newer && (sample.GetSampleEpoch() != previous.GetSampleEpoch() || sample.GetSampleSequence() > previous.GetSampleSequence()) {
			return sample
		}
	}
}
