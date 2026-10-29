// SPDX-License-Identifier: AGPL-3.0-only

package workertables

import (
	"bytes"
	"encoding/base64"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	foundationv1 "github.com/ArcForges/Contracts/go/arcforges/foundation/v1"

	"github.com/ArcForges/Cloud/center/internal/arc"
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

// TestTheSurfaceRepliesAreTheCentersRefusals decodes the generated replies: each is one gRPC-Web reply frame whose message is the
// center's own refusal (without a correlation id) and an OK status trailer; the rate_limited template carries its template instant.
func TestTheSurfaceRepliesAreTheCentersRefusals(t *testing.T) {
	generated, err := Generate()
	if err != nil {
		t.Fatal(err)
	}
	for name, want := range map[string]*arc.Refusal{
		"identity":         arc.NotActivated("identity"),
		"rateLimitedReply": arc.RateLimited("edge", 0, time.Unix(1<<33, 0)),
	} {
		start := strings.Index(generated, name+":")
		if name == "rateLimitedReply" {
			start = strings.Index(generated, "export const rateLimitedReply")
		}
		if start < 0 {
			t.Fatalf("%s is not generated", name)
		}
		rest := generated[start:]
		open := strings.Index(rest, `"`)
		closing := strings.Index(rest[open+1:], `"`)
		body, err := base64.StdEncoding.DecodeString(rest[open+1 : open+1+closing])
		if err != nil {
			t.Fatal(err)
		}
		value := want.ArcError(correlation.Context{})
		message, err := arc.ReplyMessage(value)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(body, append(ingress.Frame(message), ingress.TrailerFrame(ingress.StatusOK, "", false)...)) {
			t.Fatalf("%s is not the center's refusal", name)
		}
		// E4: the Contracts rule retryAdvice: retry_at if and only if AFTER_TIME (the rate_limited template carries one, which the
		// Worker sets at refusal time; not_activated is NEVER), a reconciliation operation if and only if RECONCILE.
		retry := value.GetRetry()
		if (retry.GetMode() == foundationv1.RetryMode_RETRY_MODE_AFTER_TIME) != (retry.GetRetryAt() != nil) ||
			(retry.GetMode() == foundationv1.RetryMode_RETRY_MODE_RECONCILE) != (retry.ReconciliationOperation != nil) {
			t.Fatalf("%s breaks the retryAdvice rule: %v", name, retry)
		}
	}
	if !strings.Contains(generated, `export const surfaceNames: readonly Surface[] = ["identity"];`) ||
		!strings.Contains(generated, `export const clientIpHeader = "x-arcforges-client-ip";`) ||
		!strings.Contains(generated, `export type Surface = "identity";`) {
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
	body, offsets, err := rateLimitedReply()
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(generated, "export const rateLimitedReplyInstantOffsets: readonly number[] = ["+joinInts(offsets)+"];") ||
		!strings.Contains(generated, "export const rateLimitedReplyInstantBytes = 5;") ||
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
	for _, at := range []time.Time{time.Date(2026, 10, 29, 12, 0, 1, 0, time.UTC), time.Unix(1<<27, 0), time.Unix(1<<34-1, 0)} {
		patched := bytes.Clone(template)
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
		message, err := arc.ReplyMessage(arc.RateLimited("edge", 0, at).ArcError(correlation.Context{}))
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(patched, append(ingress.Frame(message), ingress.TrailerFrame(ingress.StatusOK, "", false)...)) {
			t.Fatalf("the template at %s is not the center's refusal", at)
		}
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
