// SPDX-License-Identifier: AGPL-3.0-only

package workertables

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

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
// GeneratedTablesTests check the same fragment against the C# registrations of the rollback host.
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
