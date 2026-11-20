// SPDX-License-Identifier: AGPL-3.0-only

package fleetapi

import (
	"testing"

	v2 "github.com/ArcForges/Contracts/go/arcforges/sandbox/v2"
	"google.golang.org/protobuf/proto"

	"github.com/ArcForges/Cloud/center/internal/management"
	"github.com/ArcForges/Cloud/center/internal/observe"
	"github.com/ArcForges/Cloud/center/internal/platform"
)

func TestV2WatchSlotsReleaseOwnAccountAndNode(t *testing.T) {
	slots := watchSlots{limit: 2 * watchPerIdentity, accounts: map[platform.ID]int{}, nodes: map[platform.ID]int{}}
	for n := byte(1); n <= watchPerIdentity; n++ {
		if !slots.take(management.Authority{Account: platform.ID{1}, Node: platform.ID{n}}) {
			t.Fatal("an available stream slot was refused")
		}
	}
	if slots.take(management.Authority{Account: platform.ID{1}, Node: platform.ID{99}}) {
		t.Fatal("one account exceeded its stream limit across nodes")
	}
	released := management.Authority{Account: platform.ID{1}, Node: platform.ID{1}}
	slots.release(released)
	if !slots.take(released) {
		t.Fatal("a canceled viewer's slot remained occupied")
	}
	for n := byte(1); n <= watchPerIdentity; n++ {
		slots.release(management.Authority{Account: platform.ID{1}, Node: platform.ID{n}})
	}
	if slots.total != 0 || len(slots.accounts) != 0 || len(slots.nodes) != 0 {
		t.Fatal("unused stream identities remained in memory")
	}
}

func TestV2WatchSlotsObserveEnforcedScopesAndRelease(t *testing.T) {
	metrics := observe.NewMetrics()
	slots := watchSlots{
		limit: 2 * watchPerIdentity, accounts: map[platform.ID]int{}, nodes: map[platform.ID]int{},
		observe: metrics.ObserveManagementWatch,
	}
	for n := byte(1); n <= watchPerIdentity; n++ {
		if !slots.take(management.Authority{Account: platform.ID{100}, Node: platform.ID{n}}) ||
			!slots.take(management.Authority{Account: platform.ID{n}, Node: platform.ID{100}}) {
			t.Fatal("an available watch slot was refused")
		}
	}
	if slots.take(management.Authority{Account: platform.ID{101}, Node: platform.ID{101}}) {
		t.Fatal("global limit admitted another watch")
	}
	slots.release(management.Authority{Account: platform.ID{1}, Node: platform.ID{100}})
	if slots.take(management.Authority{Account: platform.ID{100}, Node: platform.ID{101}}) {
		t.Fatal("account limit admitted another watch")
	}
	// Fill the Node's eight slots again with headroom for an independent
	// Node refusal, by giving up one watch from the other account.
	slots.release(management.Authority{Account: platform.ID{100}, Node: platform.ID{1}})
	if !slots.take(management.Authority{Account: platform.ID{1}, Node: platform.ID{100}}) ||
		slots.take(management.Authority{Account: platform.ID{101}, Node: platform.ID{100}}) {
		t.Fatal("Node limit did not act independently below the global cap")
	}
	var pulse observe.OperationalPulse
	metrics.ReadManagementWatch(&pulse)
	if pulse.ManagementWatch != (observe.Capacity{Active: 2*watchPerIdentity - 1, Limit: 2 * watchPerIdentity}) ||
		pulse.WatchGlobal != 1 || pulse.WatchAccount != 1 || pulse.WatchNode != 1 {
		t.Fatalf("watch reservation pulse: %+v", pulse)
	}
}

func TestV2WatchOutputAdvancesOnlyFromExactOffsetAndGap(t *testing.T) {
	request := &v2.RunServiceWatchOutputRequest{
		Epoch: proto.String("original-epoch"), Offset: proto.Uint64(4), Stream: v2.StreamKind_STREAM_KIND_STDOUT.Enum(),
	}
	chunk := &v2.OutputChunk{
		Epoch: request.Epoch, Offset: proto.Uint64(5), Stream: request.Stream, Data: []byte("log"), NextOffset: proto.Uint64(8),
	}
	frame := &v2.RunServiceWatchOutputFrame{Frame: &v2.RunServiceWatchOutputFrame_Chunk{Chunk: chunk}}
	if advanceOutputWatch(request, frame) != watchInvalid || request.GetOffset() != 4 {
		t.Fatal("an out-of-order chunk advanced the caller's cursor")
	}
	gap := &v2.OutputGap{Epoch: request.Epoch, RequestedOffset: proto.Uint64(4), EarliestOffset: proto.Uint64(5), Reason: proto.String("retention")}
	if advanceOutputWatch(request, &v2.RunServiceWatchOutputFrame{Frame: &v2.RunServiceWatchOutputFrame_Gap{Gap: gap}}) != watchSend ||
		request.GetOffset() != 5 || advanceOutputWatch(request, frame) != watchSend || request.GetOffset() != 8 {
		t.Fatal("the real gap and chunk did not advance their exact offsets")
	}
	gap.Epoch, gap.RequestedOffset, gap.Reason = proto.String("new-epoch"), proto.Uint64(8), proto.String("epoch_changed")
	if advanceOutputWatch(request, &v2.RunServiceWatchOutputFrame{Frame: &v2.RunServiceWatchOutputFrame_Gap{Gap: gap}}) != watchFinish ||
		request.GetEpoch() != "original-epoch" || request.GetOffset() != 8 {
		t.Fatal("an epoch change silently replaced the viewer's identity")
	}
}

func TestV2WatchOutputAdoptsDefaultsFromAuthenticatedFrames(t *testing.T) {
	request := &v2.RunServiceWatchOutputRequest{RunId: id(platform.ID{1})}
	gap := &v2.OutputGap{Epoch: proto.String("native-epoch"), RequestedOffset: proto.Uint64(0),
		EarliestOffset: proto.Uint64(5), Reason: proto.String("retention")}
	if advanceOutputWatch(request, &v2.RunServiceWatchOutputFrame{Frame: &v2.RunServiceWatchOutputFrame_Gap{Gap: gap}}) != watchSend ||
		request.GetEpoch() != "native-epoch" || request.Stream != nil || request.GetOffset() != 5 {
		t.Fatal("a first retention gap did not establish the native epoch and next offset")
	}
	chunk := &v2.OutputChunk{Epoch: gap.Epoch, Stream: v2.StreamKind_STREAM_KIND_STDOUT.Enum(),
		Offset: proto.Uint64(5), NextOffset: proto.Uint64(8), Data: []byte("log")}
	frame := &v2.RunServiceWatchOutputFrame{Frame: &v2.RunServiceWatchOutputFrame_Chunk{Chunk: chunk}}
	if advanceOutputWatch(request, frame) != watchSend || request.GetStream() != chunk.GetStream() {
		t.Fatal("the first chunk did not establish the native stream")
	}
	chunk.Stream, chunk.Offset, chunk.NextOffset = v2.StreamKind_STREAM_KIND_STDERR.Enum(), proto.Uint64(8), proto.Uint64(11)
	if advanceOutputWatch(request, frame) != watchInvalid || request.GetOffset() != 8 {
		t.Fatal("a later frame changed the previously established stream")
	}
	terminal := &v2.Run{RunId: request.GetRunId(), Epoch: gap.Epoch}
	fresh := &v2.RunServiceWatchOutputRequest{RunId: request.GetRunId()}
	if advanceOutputWatch(fresh, &v2.RunServiceWatchOutputFrame{Frame: &v2.RunServiceWatchOutputFrame_Run{Run: terminal}}) != watchFinish {
		t.Fatal("an output-free Run could not finish a watch with the default epoch")
	}
}

func TestV2WatchUsageResamplesAndRejectsOldSequence(t *testing.T) {
	request := &v2.ResourceServiceWatchUsageRequest{ScopeKind: proto.String("run"), ScopeId: id(platform.ID{1})}
	advance := usageWatch()
	sample := &v2.ResourceSnapshot{
		ScopeKind: request.ScopeKind, ScopeId: request.ScopeId, SampleEpoch: proto.String("sampler-one"),
		SampleSequence: proto.Uint64(4), Stale: proto.Bool(false),
	}
	frame := &v2.ResourceServiceWatchUsageFrame{Frame: &v2.ResourceServiceWatchUsageFrame_Snapshot{Snapshot: sample}}
	if advance(request, frame) != watchSend || advance(request, frame) != watchSkip {
		t.Fatal("a repeated sample was presented as new observation")
	}
	sample.SampleSequence = proto.Uint64(3)
	if advance(request, frame) != watchInvalid {
		t.Fatal("an earlier sequence in the same sample epoch was delivered")
	}
	sample.SampleSequence, sample.SampleEpoch = proto.Uint64(1), proto.String("sampler-two")
	if advance(request, frame) != watchSend {
		t.Fatal("a real new sample epoch could not resnapshot")
	}
	fresh := usageWatch()
	if fresh(request, frame) != watchSend {
		t.Fatal("a new viewer inherited another viewer's read checkpoint")
	}
}
