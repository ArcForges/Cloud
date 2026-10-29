// SPDX-License-Identifier: AGPL-3.0-only

package workertables

import (
	"bytes"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	foundationv1 "github.com/ArcForges/Contracts/go/arcforges/foundation/v1"
	"google.golang.org/protobuf/encoding/protowire"
	"google.golang.org/protobuf/proto"

	"github.com/ArcForges/Cloud/center/internal/arc"
	"github.com/ArcForges/Cloud/center/internal/arc/arctest"
	"github.com/ArcForges/Cloud/center/internal/correlation"
	"github.com/ArcForges/Cloud/center/internal/ingress"
	"github.com/ArcForges/Cloud/center/internal/routes"
)

// TestCommittedWorkerTablesAreCurrent is the drift check of the generated production table, the Go counterpart of
// `npm run check:generated`: a changed registration fails it until `python eng/center.py generate` is run and committed.
func TestCommittedWorkerTablesAreCurrent(t *testing.T) {
	root, err := RepositoryRoot(".")
	if err != nil {
		t.Fatal(err)
	}
	committed, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(Path)))
	if err != nil {
		t.Fatal(err)
	}
	generated, err := Generate()
	if err != nil {
		t.Fatal(err)
	}
	if string(committed) != generated {
		t.Fatalf("%s is out of date: run python eng/center.py generate and commit the result", Path)
	}
}

// TestTheProductionRowsAreTheRowsTheWorkerServedBefore pins the rows the C# generator wrote for Hello before the split; the C#
// GeneratedTablesTests check the same fragment against the C# registrations of the rollback host. The surfaces (AF-CTR-03) come
// before it, so the generated module still ends with exactly these bytes.
func TestTheProductionRowsAreTheRowsTheWorkerServedBefore(t *testing.T) {
	generated, err := Generate()
	if err != nil {
		t.Fatal(err)
	}
	const before = `export const helloPath = "/api/arcforges.hello.v1.HelloService/SayHello";
export const healthPath = "/api/healthz";
/** The bound of a whole request body of a method that declares no larger one, frame header included. */
export const maxBodyBytes = 4096;
/** The Container may take at most this long to start before a stream's response headers arrive. */
export const coldStartBudgetMs = 15000;
/** A server stream's lifetime when the client states no shorter deadline: the annex 10 server close after five minutes plus slack. */
export const streamLifetimeMs = 310000;

/** The health route: a small plain reply that the pipeline answers itself. */
export const healthRoute: ApiRoute = {
  path: "/healthz",
  kind: "unary",
  auth: "anonymous",
  maxRequestBytes: 0,
  maxFrameBytes: 0,
  maxUnaryResponseBytes: 8192,
  maxDurationMs: 15000,
  instance: "hello",
  requestMeta: false,
};

/** The methods the production Worker serves. */
export const productionRoutes: readonly ApiRoute[] = [
  {
    path: "/arcforges.hello.v1.HelloService/SayHello",
    kind: "unary",
    auth: "anonymous",
    maxRequestBytes: 4096,
    maxFrameBytes: 8192,
    maxUnaryResponseBytes: 8192,
    maxDurationMs: 10000,
    instance: "hello",
    requestMeta: false,
  },
];
`
	if !strings.HasSuffix(generated, before) {
		t.Fatal("the production rows changed")
	}
}

// generatedConstant reads the quoted base64 value of a generated constant or property named by marker.
func generatedConstant(t *testing.T, generated, marker string) []byte {
	t.Helper()
	start := strings.Index(generated, marker)
	if start < 0 {
		t.Fatalf("%s is not generated", marker)
	}
	rest := generated[start:]
	open := strings.Index(rest, `"`)
	closing := strings.Index(rest[open+1:], `"`)
	body, err := base64.StdEncoding.DecodeString(rest[open+1 : open+1+closing])
	if err != nil {
		t.Fatal(err)
	}
	return body
}

// generatedNumber reads the number after the marker of a generated constant.
func generatedNumber(t *testing.T, generated, marker string) int {
	t.Helper()
	start := strings.Index(generated, marker)
	if start < 0 {
		t.Fatalf("%s is not generated", marker)
	}
	rest := strings.TrimLeft(generated[start+len(marker):], " ")
	end := strings.IndexAny(rest, ",;\n")
	value, err := strconv.Atoi(rest[:end])
	if err != nil {
		t.Fatal(err)
	}
	return value
}

// decodeReply reads the ArcError of a generated gRPC-Web body: one reply frame (the error is field 3 of the outcome) and the OK
// status trailer.
func decodeReply(t *testing.T, body []byte) *foundationv1.ArcError {
	t.Helper()
	if len(body) < 5 || body[0] != 0 {
		t.Fatal("not a data frame")
	}
	length := int(binary.BigEndian.Uint32(body[1:5]))
	message, trailer := body[5:5+length], body[5+length:]
	if !bytes.Equal(trailer, ingress.TrailerFrame(ingress.StatusOK, "", false)) {
		t.Fatal("the reply does not end with the OK status trailer")
	}
	number, kind, tag := protowire.ConsumeTag(message)
	if number != arc.ReplyErrorField || kind != protowire.BytesType || tag < 0 {
		t.Fatal("the reply is not the error outcome")
	}
	payload, size := protowire.ConsumeBytes(message[tag:])
	if size < 0 || tag+size != len(message) {
		t.Fatal("the reply holds more than its error")
	}
	var value foundationv1.ArcError
	if err := proto.Unmarshal(payload, &value); err != nil {
		t.Fatal(err)
	}
	return &value
}

// writeCorrelation does what the Worker does: it writes a correlation id into the template's slot.
func writeCorrelation(body []byte, offset int, id string) []byte {
	patched := bytes.Clone(body)
	copy(patched[offset:offset+CorrelationSlotBytes], correlation.IDBytes(id))
	return patched
}

// TestTheSurfaceRepliesAreTheCentersRefusals decodes the generated replies: each is one gRPC-Web reply frame whose message is the
// center's own refusal and an OK status trailer, and with the call's correlation id written into its slot it is exactly the
// center's reply for that call (E4-1): the correlation id is required by Contracts, so the template carries a slot for it and every
// reply, as the Worker sends it, passes the same ArcError check the center's own refusals pass, including the correlation rule.
func TestTheSurfaceRepliesAreTheCentersRefusals(t *testing.T) {
	generated, err := Generate()
	if err != nil {
		t.Fatal(err)
	}
	limited, instants, limitedSlot, err := rateLimitedReply()
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(generated, "export const replyCorrelationBytes = 16;") {
		t.Fatal("the correlation slot width is not generated")
	}
	template := bytes.Clone(correlation.IDBytes(TemplateCorrelation))
	for name, item := range map[string]struct {
		want   *arc.Refusal
		body   []byte
		offset int
	}{
		"identity": {arc.NotActivated("identity"), generatedConstant(t, generated, "notActivatedReplies: Readonly<Record<Surface, string>> = {\n  identity:"),
			generatedNumber(t, generated, "notActivatedReplyCorrelationOffsets: Readonly<Record<Surface, number>> = {\n  identity:")},
		"rateLimitedReply": {arc.RateLimited("edge", 0, time.Unix(1<<33, 0)), generatedConstant(t, generated, "export const rateLimitedReply"),
			generatedNumber(t, generated, "export const rateLimitedReplyCorrelationOffset =")},
	} {
		if name == "rateLimitedReply" && (limitedSlot != item.offset || base64.StdEncoding.EncodeToString(item.body) != limited || len(instants) != 2) {
			t.Fatal("the rate_limited constants are not the generator's")
		}
		if !bytes.Equal(item.body[item.offset:item.offset+CorrelationSlotBytes], template) || bytes.Count(item.body, template) != 1 {
			t.Fatalf("%s: the correlation slot is not at its offset exactly once", name)
		}
		// The template as generated is the center's refusal with the marker correlation, and passes the Contracts rules.
		value := decodeReply(t, item.body)
		for _, violation := range arctest.Violations(value) {
			t.Errorf("%s: %s", name, violation)
		}
		if !proto.Equal(value, item.want.ArcError(templateCorrelationContext())) {
			t.Fatalf("%s is not the center's refusal", name)
		}
		// With a call's correlation id written into the slot it is the center's reply for that call.
		for _, id := range []string{"6c1d7f0e-3a52-4b9c-8e47-90a1b2c3d4e5", "ffffffff-ffff-4fff-bfff-ffffffffffff"} {
			patched := writeCorrelation(item.body, item.offset, id)
			value := decodeReply(t, patched)
			if violations := arctest.Violations(value); len(violations) != 0 {
				t.Errorf("%s with %s: %v", name, id, violations)
			}
			if !proto.Equal(value, item.want.ArcError(correlation.Context{CorrelationID: id})) {
				t.Fatalf("%s with %s is not the center's refusal for that call", name, id)
			}
			if !bytes.Equal(patched[:item.offset], item.body[:item.offset]) || !bytes.Equal(patched[item.offset+CorrelationSlotBytes:], item.body[item.offset+CorrelationSlotBytes:]) {
				t.Fatalf("%s: writing the slot changed other bytes", name)
			}
		}
		// A reply the Worker left unwritten would still pass the rule with the marker, so the marker itself is never a real id.
		if correlation.IsValidID(TemplateCorrelation) && correlation.FormatID(template) != TemplateCorrelation {
			t.Fatal("the template marker does not round trip")
		}
	}
	if !strings.Contains(generated, `export const surfaceNames: readonly Surface[] = ["identity", "pages"];`) ||
		!strings.Contains(generated, `export const clientIpHeader = "x-arcforges-client-ip";`) ||
		!strings.Contains(generated, `export type Surface = "identity" | "pages";`) {
		t.Fatal("the surface constants changed")
	}
}

// TestTheRateLimitedTemplateTakesTheWorkersInstant (F17) writes an instant into the generated template as the Worker does (its
// zigzag seconds as five varint bytes at each offset) and finds exactly the center's rate_limited refusal at that instant, with
// retry_at and recovery_at set; the period is the edge limiter's.
func TestTheRateLimitedTemplateTakesTheWorkersInstant(t *testing.T) {
	generated, err := Generate()
	if err != nil {
		t.Fatal(err)
	}
	body, offsets, slot, err := rateLimitedReply()
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(generated, "export const rateLimitedReplyInstantOffsets: readonly number[] = ["+joinInts(offsets)+"];") ||
		!strings.Contains(generated, "export const rateLimitedReplyInstantBytes = 5;") ||
		!strings.Contains(generated, "export const rateLimitedReplyCorrelationOffset = "+strconv.Itoa(slot)+";") ||
		!strings.Contains(generated, "export const edgeRateLimitPeriodSeconds = 60;") ||
		!strings.Contains(generated, "export const edgeIpv6PrefixBits = 64;") {
		t.Fatal("the edge constants are not generated")
	}
	// AF-CTR-03: the Container class's bounds for a center left running under another version's settings follow the center's
	// own shutdown bound.
	if !strings.Contains(generated, "export const staleCenterStopMs = 6000;") || !strings.Contains(generated, "export const staleCenterKillMs = 4000;") ||
		!strings.Contains(generated, "export const centerStopPollMs = 100;") {
		t.Fatal("the stale center's stop bounds are not generated")
	}
	template, err := base64.StdEncoding.DecodeString(body)
	if err != nil {
		t.Fatal(err)
	}
	id := "6c1d7f0e-3a52-4b9c-8e47-90a1b2c3d4e5"
	for _, at := range []time.Time{time.Date(2026, 10, 29, 12, 0, 1, 0, time.UTC), time.Unix(1<<27, 0), time.Unix(1<<34-1, 0)} {
		patched := writeCorrelation(template, slot, id)
		for _, offset := range offsets {
			value := uint64(at.Unix()) * 2 // the zigzag of a positive sint64
			for index := range 5 {
				patched[offset+index] = byte(value % 128)
				if index < 4 {
					patched[offset+index] |= 128
				}
				value /= 128
			}
		}
		message, err := arc.ReplyMessage(arc.RateLimited("edge", 0, at).ArcError(correlation.Context{CorrelationID: id}))
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(patched, append(ingress.Frame(message), ingress.TrailerFrame(ingress.StatusOK, "", false)...)) {
			t.Fatalf("the template at %s is not the center's refusal", at)
		}
	}
}

// TestAReplyTemplateWithoutItsSlotIsNotGenerated: a template whose marker is missing or repeated is an error, never a table that
// the Worker could not complete.
func TestAReplyTemplateWithoutItsSlotIsNotGenerated(t *testing.T) {
	marker := correlation.IDBytes(TemplateCorrelation)
	if _, err := correlationOffset([]byte("no marker here")); err == nil {
		t.Fatal("a body without the marker has an offset")
	}
	if _, err := correlationOffset(append(append(bytes.Clone(marker), 1), marker...)); err == nil {
		t.Fatal("a body with the marker twice has an offset")
	}
	if offset, err := correlationOffset(append([]byte{1, 2, 3}, marker...)); err != nil || offset != 3 {
		t.Fatalf("offset %d %v", offset, err)
	}
}

func TestAChangedRegistrationChangesTheTable(t *testing.T) {
	modules, err := routes.Center()
	if err != nil {
		t.Fatal(err)
	}
	table, err := routes.Table(modules)
	if err != nil {
		t.Fatal(err)
	}
	original, err := Render(table)
	if err != nil {
		t.Fatal(err)
	}
	table.Production[0].MaxDurationMilliseconds++
	changed, err := Render(table)
	if err != nil || changed == original {
		t.Fatal("a changed budget did not change the table")
	}
	table.Production[0].Instance = `he"llo`
	if _, err := Render(table); !errors.Is(err, ErrUnsafeText) {
		t.Fatal("an unsafe string was written")
	}
	if _, err := RepositoryRoot(string(filepath.Separator)); err == nil {
		t.Fatal("found a repository root outside the repository")
	}
}
