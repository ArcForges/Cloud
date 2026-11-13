# SPDX-License-Identifier: AGPL-3.0-only
"""Local verification steps of Cloud, loaded by eng/verify.py (which injects `Step`).

The full profile is every validation job of .github/workflows/ci.yml plus `candidate` (the Native AOT image and Worker
build that `deploy` ships; main pushes no longer re-validate it), each on the host the hosted job used, in two legs on
two native machines (eng/verify.py; AGENTS.md):
- lane `win` (Windows, in <main checkout>/.worktree/_verify): `source (windows-latest)`: npm ci, the locked restore and
  Release build of Cloud.slnx, the Go center's controls (`win-center`: python eng/center.py check, without the race detector
  and fuzzing because the Windows host has no cgo; docs/engineering-controls.md), the native 8e5 self-hosted bridge
  build and asset seal against the active release profile, and the evaluated licence report.
- lane `linux` (Linux, in ~/.cache/arcforges-verify/Cloud): `clone-identity`, `fresh-intermediates` (see
  FRESH_INTERMEDIATES), then `source (ubuntu-latest)`: npm ci,
  `npm run check`, `npm run check:dotnet`, the Go center's controls (`linux-center`: python eng/center.py check with the race
  detector, the fuzz targets, govulncheck and the image target) and the evaluated licence report; the dependency audit of
  `quality`; then
  the 615.1 self-hosted bridge carrier extraction and asset seal against the active release profile; then
  `candidate` (`npm run candidate`: the Linux Native AOT image in the Linux host's Docker, both Worker bundles, the sealed tool and the
  manifest, verified). Everything that runs dotnet or npm in the clone is in this lane: concurrent restores or builds of
  shared projects in one checkout would race. `linux-center` runs in its own lane `center` beside it (Go and Docker only).
- lane `scan`: the whitespace check of the commits since the merge base (`git diff --check`) and the secret
  scan of `quality` (the pinned gitleaks image digest, .gitleaks.toml) over the same range ({range}), in Docker
  without network and with a read-only mount of the clone; lane `actionlint` only when .github/workflows/** changed.
`quality`'s build and forbidden-term scan are the same commands as `check:dotnet`'s build and `check`'s `npm run policy`
on the same commit, so they run once.

Differences from the hosted jobs:
- The hosted architecture gate (`ARCFORGES_ARCHITECTURE_GATE=hosted`) trusts the secret scan (RP-09) only inside the
  GitHub `quality` job (GITHUB_ACTIONS, GITHUB_JOB, GITHUB_SHA), so it cannot run locally by design. The same
  EvaluatedRepositoryGate runs in `check:dotnet` without hosted mode, where every rule must hold and RP-09 is the only
  accepted finding (as in the hosted Linux source job); the secret scan itself runs in lane `scan`.
- The clone has the identity of a pull-request checkout of ArcForges/Cloud (`clone-identity`): its `origin` URL is the
  GitHub repository, which the forbidden-term scan requires, `origin/main` is the merge base with main, which `check:physical` (`--base origin/main`) and the provenance audit compare against (hosted: the PR base from the
  event), and HEAD is a local branch at the pushed commit, because the provenance audit reads `origin/main` only off
  `main` and needs a branch (hosted: the event). Nothing is fetched from a remote.
- `CI` and `GITHUB_*` are not set. Without GITHUB_RUN_NUMBER the candidate takes the local version
  `0.1.0-local.<milliseconds>` (hosted: `0.1.0-ci.<run number>.<attempt>`); the hosted `CI=true` refusal of a dirty
  checkout is the explicit clean-tree test before `npm run candidate`, and the image build fetches over the host network
  (see CANDIDATE). Artifacts are not uploaded. The candidate's image
  tag is removed after a pass (the tar in artifacts/candidate stays until the next run). Cloudflare credentials are
  unset for the candidate: its Wrangler bundles are `--dry-run` builds, and nothing contacts Cloudflare.
- npm on Windows is the npm bundled with the selected Node (hosted: setup-node's Node with its bundled npm), because a
  globally installed newer npm earlier on PATH fails the repository's engine-strict pin.
- The secret scan covers the commits since the merge base, not the full history: history before it is main, scanned
  when its own PRs were verified.
- The bridge asset checks use each native host and a new temporary directory. Linux reuses a previously verified carrier from the
  documented workspace or `ARCFORGES_CTR06_BRIDGE_CARRIER` (an absolute non-secret path); otherwise it retrieves the fixed
  durable release once and checks its digest. Windows compiles the archived 8e5 source with the host's existing Go 1.27.3.
  `ARCFORGES_CTR06_BRIDGE_GO` may name that absolute executable path for the bridge step only. For the center, optional
  `ARCFORGES_CENTER_GO` names the absolute native pinned Go executable; the fingerprint and center step use the same
  captured choice after any login profile, with the actual version and native target checked. Without either variable
  the corresponding step retains its existing PATH selection. Each native host also exercises the actual security-bridge producer
  with a synthetic local event and no upload or authority claim; `ARCFORGES_CTR06_SECURITY_GO_ARCHIVE` selects an existing absolute
  Go 1.27.4 distribution archive, whose full digest and installed compiler contents the producer verifies independently.
- Added to the hosted jobs: `worker-provenance` (`npm run test:artifact`: the verifier's own tests on the real locked Wrangler output against the release profile's approved Worker closure; the hosted candidate job runs the verifier itself on the real bundle, so only these tests and the early feedback are leg-only).
- Not reproduced: GitHub dependency review (a GitHub service; external PRs keep it; the locked restores with NuGet audit
  and `npm audit` cover vulnerable packages locally) and CodeQL (external PRs, dispatch and the weekly schedule).
Every change runs the full profile: the forbidden-term scan, Prettier and the provenance inventory read Markdown too.
"""

import os
from pathlib import Path
import shlex

REPOSITORY = "Cloud"


def selected_center_go() -> str | None:
    """An optional native center compiler, fixed before any Linux login profile runs."""
    value = os.environ.get("ARCFORGES_CENTER_GO")
    if value is None:
        return None
    path = Path(value)
    expected_name = "go.exe" if os.name == "nt" else "go"
    actual_name = path.name.lower() if os.name == "nt" else path.name
    if not path.is_absolute() or actual_name != expected_name:
        raise ValueError("ARCFORGES_CENTER_GO must name an existing absolute native Go executable")
    try:
        path = path.resolve(strict=True)
    except OSError as error:
        raise ValueError("ARCFORGES_CENTER_GO must name an existing absolute native Go executable") from error
    actual_name = path.name.lower() if os.name == "nt" else path.name
    if not path.is_file() or actual_name != expected_name or os.pathsep in str(path.parent):
        raise ValueError("ARCFORGES_CENTER_GO must name an existing absolute native Go executable")
    return str(path)


def selected_security_archive() -> str | None:
    """Capture the optional archive before a login profile can replace it."""
    value = os.environ.get("ARCFORGES_CTR06_SECURITY_GO_ARCHIVE")
    if value is None:
        return None
    path = Path(value)
    if not path.is_absolute():
        raise ValueError("ARCFORGES_CTR06_SECURITY_GO_ARCHIVE must name an existing absolute file")
    try:
        path = path.resolve(strict=True)
    except OSError as error:
        raise ValueError("ARCFORGES_CTR06_SECURITY_GO_ARCHIVE must name an existing absolute file") from error
    if not path.is_file():
        raise ValueError("ARCFORGES_CTR06_SECURITY_GO_ARCHIVE must name an existing absolute file")
    return str(path)


_CENTER_GO = selected_center_go()
_SECURITY_GO_ARCHIVE = selected_security_archive()
# The fingerprint and the center step receive the same captured executable, even if a login profile rewrites PATH.
# A child-local environment also prevents a different GOROOT or automatic toolchain download from changing the probe.
_GO_PROBE = ("import os, subprocess, sys; e=dict(os.environ, GOTOOLCHAIN='local'); e.pop('GOROOT', None); "
             "sys.exit(subprocess.call([sys.argv[1], 'version'], env=e))")

# The npm bundled with the Node that `node` selects (Windows; see above).
_BUNDLED_NPM = ("require('path').join(require('path').dirname(process.execPath), 'node_modules', 'npm', "
                "'bin', 'npm-cli.js')")

# Tool versions recorded in each leg's summary (the python running eng/verify.py is added by the core).
FINGERPRINT = {
    "win": {
        "dotnet-sdks": ["dotnet", "--list-sdks"],
        "dotnet-runtimes": ["dotnet", "--list-runtimes"],
        "node": ["node", "--version"],
        "go": (["python", "-c", _GO_PROBE, _CENTER_GO] if _CENTER_GO is not None else ["go", "version"]),
        "npm": ["node", "-p", "require(" + _BUNDLED_NPM.replace("'bin', 'npm-cli.js'", "'package.json'") + ").version"],
    },
    "linux": {
        "dotnet-sdks": "dotnet --list-sdks | tr '\\n' ' '",
        "dotnet-runtimes": "dotnet --list-runtimes | tr '\\n' ' '",
        "node": "node --version",
        "go": (f"python -c {shlex.quote(_GO_PROBE)} {shlex.quote(_CENTER_GO)}"
               if _CENTER_GO is not None else "go version"),
        "npm": "npm --version",
        "python": "python --version",
        "docker": "docker version --format '{{.Server.Version}}'",
        "git": "git --version",
    },
}

# Timeouts are five to ten times the warm durations measured on this workstation (18 logical processors, both hosts'
# lanes concurrently; eng/verify.py's summary.json), with a floor of one to five minutes; the restore and image steps
# allow a cold NuGet cache and base-image pull.

# The environment of ci.yml, without CI=true (see above). MSBuild node reuse is off, so that no build node outlives its step
# (a step's process tree is what a timeout or a failure stops). RestoreLockedMode (an MSBuild property read from the
# environment) locks the implicit restores of `dotnet run`/`dotnet publish` in check:plans, check:generated and the candidate's
# tool publish, as the hosted jobs' explicit `--locked-mode` restores do.
ENV = {"DOTNET_NOLOGO": "true", "DOTNET_CLI_TELEMETRY_OPTOUT": "true", "WRANGLER_SEND_METRICS": "false",
       "MSBUILDDISABLENODEREUSE": "1", "RestoreLockedMode": "true"}

# ci.yml's secret scan (same pinned image digest, redaction and config), over the commits since the merge base, without network and with
# a read-only mount of the verification clone.
SECRET_SCAN = (
    "docker run --rm --network none -v \"$PWD:/repo:ro\" "
    "-e GIT_CONFIG_COUNT=1 -e GIT_CONFIG_KEY_0=safe.directory -e GIT_CONFIG_VALUE_0=/repo "
    "ghcr.io/gitleaks/gitleaks:v8.30.1@sha256:c00b6bd0aeb3071cbcb79009cb16a60dd9e0a7c60e2be9ab65d25e6bc8abbb7f "
    "git /repo --redact=100 --no-banner --verbose --config /repo/.gitleaks.toml "
    "--log-opts=\"--full-history {range}\""
)

# actionlint as pinned in ci.yml, cached once on the Linux host; the archive is checked on every run.
ACTIONLINT = (
    "set -euo pipefail; v=1.7.12; "
    "sum=8aca8db96f1b94770f1b0d72b6dddcb1ebb8123cb3712530b08cc387b349a3d8; "
    "d=\"$HOME/.cache/arcforges-verify/tools\"; t=\"$d/actionlint_${v}_linux_amd64.tar.gz\"; mkdir -p \"$d\"; "
    "if [ ! -f \"$t\" ]; then "
    "curl --fail --silent --show-error --location --output \"$t.part\" "
    "\"https://github.com/rhysd/actionlint/releases/download/v${v}/actionlint_${v}_linux_amd64.tar.gz\"; "
    "echo \"$sum  $t.part\" | sha256sum --check --quiet; mv \"$t.part\" \"$t\"; fi; "
    "echo \"$sum  $t\" | sha256sum --check --quiet; "
    "mkdir -p \"$d/actionlint-$v\"; tar -xzf \"$t\" -C \"$d/actionlint-$v\" actionlint; "
    "\"$d/actionlint-$v/actionlint\" -color"
)

# ci.yml `candidate`, from the clean checkout CI builds it from; the image tag is removed after the verified build. The
# image build's RUN steps fetch over the host network (ARCFORGES_LOCAL_DOCKER_BUILD_NETWORK=host, which
# tooling/project.ts honours only outside CI): containers on Docker's default bridge network could not reach NuGet on the
# workstation's former Linux environment, and the host network is the route that works wherever the host reaches NuGet.
# Only the route changes: the restore is locked to the packages.lock.json content hashes, both base images
# are pinned by digest, and the network mode enters neither the image nor the manifest.
CANDIDATE = (
    "set -euo pipefail; unset CLOUDFLARE_API_TOKEN CLOUDFLARE_ACCOUNT_ID CLOUDFLARE_API_KEY CLOUDFLARE_EMAIL; "
    "if [ -n \"$(git status --porcelain)\" ]; then git status --porcelain; "
    "echo 'the checkout changed during verification; the candidate is built from a clean checkout' >&2; exit 1; fi; "
    "ARCFORGES_LOCAL_DOCKER_BUILD_NETWORK=host npm run candidate; "
    "image=\"$(node -p 'JSON.parse(require(\"fs\").readFileSync(\"artifacts/candidate/manifest.json\", \"utf8\")).image')\"; "
    "docker image rm \"$image\" >/dev/null"
)


# The hosted jobs compile in a fresh checkout. The clone keeps its build output, but the architecture gate in
# `check:dotnet` (ArcForges.Build.Policy's project evaluation: `dotnet msbuild -target:Compile` with a forced compile
# input) rewrites each project's intermediate assembly obj/Release/<tfm>/<name>.dll without its embedded resources. At an
# unchanged commit the next incremental build skips the compiler and copies that assembly to bin, so the Storage.D1
# runner and policy-engine tests then fail (measured: a second run at the same commit failed 120 tests; restoring
# the intermediate assembly and rebuilding fixed it). The intermediate assemblies (and their ref/refint and pdb files) are
# therefore removed first, so each verification compiles every project once, as CI does; restore output and the RID
# outputs of the candidate's tool publish stay.
FRESH_INTERMEDIATES = (
    "set -o pipefail; find src tests tools -type f -regextype posix-extended "
    "-regex '.*/obj/(Debug|Release)/net[0-9.]+/((ref|refint)/)?[^/]+[.](dll|pdb)' -print -delete | wc -l "
    "| sed 's/$/ intermediate assemblies removed/'"
)


def select_profile(changed: list[str]) -> str:
    return "full"


def workflows_changed(changed: list[str]) -> bool:
    return any(path.startswith(".github/workflows/") for path in changed)


def pwsh(script: str) -> list[str]:
    return ["pwsh", "-NoProfile", "-NonInteractive", "-Command",
            "$ErrorActionPreference = 'Stop'; " + script + "; exit $LASTEXITCODE"]


def win(step_id: str, cmd: list[str], timeout: int, *, center_go: bool = False,
        security_archive: bool = False, **options) -> Step:
    env = dict(ENV)
    if security_archive:
        env["ARCFORGES_CTR06_SECURITY_GO_ARCHIVE"] = _SECURITY_GO_ARCHIVE or ""
    if center_go and _CENTER_GO is not None:
        env["ARCFORGES_CENTER_GO"] = _CENTER_GO
        env["PATH"] = str(Path(_CENTER_GO).parent) + os.pathsep + os.environ.get("PATH", "")
        env["GOROOT"] = ""
        env["GOTOOLCHAIN"] = "local"
    return Step(step_id, "win", cmd, timeout=timeout, env=env, **options)


def linux(step_id: str, cmd: str, timeout: int, *, center_go: bool = False,
          security_archive: bool = False, **options) -> Step:
    if security_archive:
        setting = (f"export ARCFORGES_CTR06_SECURITY_GO_ARCHIVE={shlex.quote(_SECURITY_GO_ARCHIVE)}; "
                   if _SECURITY_GO_ARCHIVE is not None else "unset ARCFORGES_CTR06_SECURITY_GO_ARCHIVE; ")
        cmd = setting + cmd
    if center_go and _CENTER_GO is not None:
        # This runs after eng/verify.py's login shell and before center.py's child processes.
        cmd = (f"export ARCFORGES_CENTER_GO={shlex.quote(_CENTER_GO)}; "
               f"export PATH={shlex.quote(str(Path(_CENTER_GO).parent))}:\"$PATH\"; "
               "unset GOROOT; export GOTOOLCHAIN=local; " + cmd)
    return Step(step_id, "linux", cmd, timeout=timeout, env=ENV, **options)


STEPS = [
    # ci.yml source (windows-latest)
    win("win-npm-ci", pwsh(f"node (node -p \"{_BUNDLED_NPM}\") ci --ignore-scripts"), 300),
    win("win-restore", ["dotnet", "restore", "Cloud.slnx", "--locked-mode"], 600),
    win("win-build", ["dotnet", "build", "Cloud.slnx", "-c", "Release", "--no-restore"], 900),
    # The Go center (AF-CTR-02): build, gofmt, vet, staticcheck, unit and protocol tests, drift, govulncheck and the native build.
    win("win-center", ["python", "eng/center.py", "check"], 900, center_go=True),
    # The exact 8e5 bridge is compiled on Windows and its complete asset is
    # sealed and checked against this commit's active release profile.
    win("win-ctr06-bridge-asset", ["python", "eng/verification/ctr06_native_bridge_check.py"], 600),
    win("win-ctr06-security-bridge", ["python", "eng/verification/ctr06_security_bridge_native_check.py"], 1200, center_go=True, security_archive=True),
    win("win-licence-evaluated", ["node", "tooling/project.ts", "licence-evaluated"], 600),
    # ci.yml source (ubuntu-latest), the dependency audit of quality, then candidate
    linux("clone-identity", "set -e; git config remote.origin.url https://github.com/ArcForges/Cloud.git; "
        "git checkout -q -B arcforges-verify {sha}; git update-ref refs/remotes/origin/main {base}", 60),
    linux("fresh-intermediates", FRESH_INTERMEDIATES, 60),
    linux("npm-ci", "npm ci --ignore-scripts", 300),
    # Reuse this host's pinned 615.1 carrier when available; otherwise fetch
    # that one durable carrier, verify it and seal the Linux asset.
    linux("linux-ctr06-bridge-asset", "python eng/verification/ctr06_native_bridge_check.py", 600),
    linux("linux-ctr06-security-bridge", "python eng/verification/ctr06_security_bridge_native_check.py", 1800, center_go=True, security_archive=True),
    linux("npm-audit", "npm audit --audit-level=high && npm audit --audit-level=high --prefix eng/verification/browser", 300),
    linux("check", "npm run check", 1200),
    linux("check-dotnet", "npm run check:dotnet", 1200),
    # The verifier's own tests on the real locked Wrangler output against the approved Worker closure of the release profile (`npm run
    # test:artifact`), which no hosted job runs (the hosted candidate job runs the verifier itself): a profile that no longer names
    # the bundle the source builds fails here, before the candidate is built.
    linux("worker-provenance", "npm run test:artifact", 600),
    # The Go center (AF-CTR-02): the Windows controls plus the race detector, the fuzz targets and the image target.
    # Its own lane: center.py runs only Go and Docker (its own
    # PostgreSQL container, govulncheck, the image target), never npm or dotnet, and reads nothing the other Linux steps write, so it
    # cannot race the restores and builds of the `linux` lane; fresh-intermediates touches only C# obj directories.
    linux("linux-center", "python eng/center.py check", 900, lane="center", center_go=True),
    linux("licence-evaluated", "node tooling/project.ts licence-evaluated", 300),
    linux("candidate", CANDIDATE, 900),
    # the whitespace check and quality's secret scan over the commits since the merge base; actionlint when a workflow changed
    linux("whitespace", "git diff --check {base} {sha}", 120, lane="scan"),
    linux("secret-scan", SECRET_SCAN, 600, lane="scan"),
    linux("actionlint", ACTIONLINT, 300, lane="actionlint", when=workflows_changed),
]
