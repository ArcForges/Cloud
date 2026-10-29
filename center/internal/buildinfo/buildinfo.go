// SPDX-License-Identifier: AGPL-3.0-only

// Package buildinfo is the compiled identity of the arcforges-center executable and the health document that reports it.
// The candidate image build sets the variables with -ldflags -X from the same inputs as the C# executable's identity
// (tooling/build-identity.ts imageBuildVariables), so health reports the release, the source commit and the build run.
package buildinfo

import (
	"errors"
	"strconv"
	"strings"
)

// Set by -ldflags "-X github.com/ArcForges/Cloud/center/internal/buildinfo.<name>=<value>"; the defaults identify a local
// development build.
var (
	appVersion   = "0.1.0-local.0"
	sourceCommit = "local"
	sourceDirty  = "true"
	buildKind    = "local"
	buildID      = "local"
	pipelineRun  = ""
	sourceEpoch  = "0"
)

// Binary is the name of the center executable.
const Binary = "arcforges-center"

// Build is the build identity: the source, whether it was dirty, and the run that built it.
type Build struct {
	SourceCommit    string  `json:"sourceCommit"`
	Dirty           bool    `json:"dirty"`
	Kind            string  `json:"kind"`
	BuildID         string  `json:"buildId"`
	RunID           *string `json:"runId"`
	RunAttempt      *int    `json:"runAttempt"`
	PipelineRun     *string `json:"pipelineRun"`
	SourceDateEpoch int64   `json:"sourceDateEpoch"`
}

// Artifact is the release identity.
type Artifact struct {
	ID      string `json:"id"`
	Version string `json:"version"`
}

// Center is the center's own identity in the health document: the executable, the configured mode, the configured public
// base URL, from which every URL the center issues is derived, and the surfaces it serves (comma-separated, "none" when none, as
// ARCFORGES_CENTER_SURFACES states them), so a deployment can be checked against the surfaces its Worker forwards.
type Center struct {
	Binary        string `json:"binary"`
	Mode          string `json:"mode,omitempty"`
	PublicBaseURL string `json:"publicBaseUrl,omitempty"`
	Surfaces      string `json:"surfaces,omitempty"`
}

// Health is the health document. It keeps the fields the Worker and the release tooling read (service, revision, nativeAot,
// runtime, helloBackend, artifact and build) and adds the center identity. Go is compiled native code but not .NET Native AOT,
// so nativeAot is false.
type Health struct {
	Service      string   `json:"service"`
	Revision     string   `json:"revision"`
	NativeAOT    bool     `json:"nativeAot"`
	Runtime      string   `json:"runtime"`
	HelloBackend string   `json:"helloBackend"`
	Artifact     Artifact `json:"artifact"`
	Build        Build    `json:"build"`
	Center       Center   `json:"center"`
}

// ErrInvalid reports compiled build metadata that does not describe a valid build.
var ErrInvalid = errors.New("invalid build metadata")

// Document is the health document of this executable with the given Hello backend and center identity.
func Document(helloBackend string, center Center) (Health, error) {
	return document(helloBackend, center, appVersion, sourceCommit, sourceDirty, buildKind, buildID, pipelineRun, sourceEpoch)
}

func document(helloBackend string, center Center, version, commit, dirtyText, kind, id, pipeline, epochText string) (Health, error) {
	dirty, err := strconv.ParseBool(dirtyText)
	if err != nil {
		return Health{}, ErrInvalid
	}
	epoch, err := strconv.ParseInt(epochText, 10, 64)
	if err != nil {
		return Health{}, ErrInvalid
	}
	build := Build{SourceCommit: commit, Dirty: dirty, Kind: kind, BuildID: id, SourceDateEpoch: epoch}
	if kind == "ci" {
		run, attemptText, found := strings.Cut(id, ".")
		attempt, err := strconv.Atoi(attemptText)
		if !found || strings.Contains(attemptText, ".") || err != nil || attempt < 1 || len(commit) != 40 || dirty || pipeline == "" || epoch <= 0 {
			return Health{}, ErrInvalid
		}
		build.RunID, build.RunAttempt, build.PipelineRun = &run, &attempt, &pipeline
	}
	revision := commit
	if dirty {
		revision += "-dirty"
	}
	center.Binary = Binary
	return Health{
		Service: "arcforges-cloud", Revision: revision, NativeAOT: false, Runtime: "go", HelloBackend: helloBackend,
		Artifact: Artifact{ID: "Cloud", Version: version}, Build: build, Center: center,
	}, nil
}
