# SPDX-License-Identifier: AGPL-3.0-only
"""Local verification steps of Cloud, loaded by eng/verify.py (which injects `Step`).

The full profile is every validation job of .github/workflows/ci.yml plus `candidate` (the Native AOT image and Worker
build that `deploy` ships; main pushes no longer re-validate it), each on the host the hosted job used, in two legs on
two native machines (eng/verify.py; AGENTS.md):
- lane `win` (Windows, in <main checkout>/.worktree/_verify): `source (windows-latest)`: npm ci, the locked restore and
  Release build of Cloud.slnx, the Go center's controls (`win-center`: python eng/center.py check, without the race detector
  and fuzzing because the Windows host has no cgo; docs/engineering-controls.md), and the evaluated licence report.
- lane `linux` (Linux, in ~/.cache/arcforges-verify/Cloud): `clone-identity`, `fresh-intermediates` (see
  FRESH_INTERMEDIATES), then `source (ubuntu-latest)`: npm ci,
  `npm run check`, `npm run check:dotnet`, the Go center's controls (`linux-center`: python eng/center.py check with the race
  detector, the fuzz targets, govulncheck and the image target) and the evaluated licence report; the dependency audit of
  `quality`; then
  `candidate` (`npm run candidate`: the Linux Native AOT image in the Linux host's Docker, both Worker bundles, the sealed tool and the
  manifest, verified). Everything that runs dotnet or npm in the clone is in this lane: concurrent restores or builds of
  shared projects in one checkout would race.
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
- Added to the hosted jobs: `worker-provenance` (`npm run test:artifact`: the real locked Wrangler output against the release profile's approved Worker closure, which no hosted job runs).
- Not reproduced: GitHub dependency review (a GitHub service; external PRs keep it; the locked restores with NuGet audit
  and `npm audit` cover vulnerable packages locally) and CodeQL (external PRs, dispatch and the weekly schedule).
Every change runs the full profile: the forbidden-term scan, Prettier and the provenance inventory read Markdown too.
"""

REPOSITORY = "Cloud"

# The npm bundled with the Node that `node` selects (Windows; see above).
_BUNDLED_NPM = ("require('path').join(require('path').dirname(process.execPath), 'node_modules', 'npm', "
                "'bin', 'npm-cli.js')")

# Tool versions recorded in each leg's summary (the python running eng/verify.py is added by the core).
FINGERPRINT = {
    "win": {
        "dotnet-sdks": ["dotnet", "--list-sdks"],
        "dotnet-runtimes": ["dotnet", "--list-runtimes"],
        "node": ["node", "--version"],
        "go": ["go", "version"],
        "npm": ["node", "-p", "require(" + _BUNDLED_NPM.replace("'bin', 'npm-cli.js'", "'package.json'") + ").version"],
    },
    "linux": {
        "dotnet-sdks": "dotnet --list-sdks | tr '\\n' ' '",
        "dotnet-runtimes": "dotnet --list-runtimes | tr '\\n' ' '",
        "node": "node --version",
        "go": "go version",
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


def win(step_id: str, cmd: list[str], timeout: int, **options) -> Step:
    return Step(step_id, "win", cmd, timeout=timeout, env=ENV, **options)


def linux(step_id: str, cmd: str, timeout: int, **options) -> Step:
    return Step(step_id, "linux", cmd, timeout=timeout, env=ENV, **options)


STEPS = [
    # ci.yml source (windows-latest)
    win("win-npm-ci", pwsh(f"node (node -p \"{_BUNDLED_NPM}\") ci --ignore-scripts"), 300),
    win("win-restore", ["dotnet", "restore", "Cloud.slnx", "--locked-mode"], 600),
    win("win-build", ["dotnet", "build", "Cloud.slnx", "-c", "Release", "--no-restore"], 900),
    # The Go center (AF-CTR-02): build, gofmt, vet, staticcheck, unit and protocol tests, drift, govulncheck and the native build.
    win("win-center", ["python", "eng/center.py", "check"], 900),
    win("win-licence-evaluated", ["node", "tooling/project.ts", "licence-evaluated"], 600),
    # ci.yml source (ubuntu-latest), the dependency audit of quality, then candidate
    linux("clone-identity", "set -e; git config remote.origin.url https://github.com/ArcForges/Cloud.git; "
        "git checkout -q -B arcforges-verify {sha}; git update-ref refs/remotes/origin/main {base}", 60),
    linux("fresh-intermediates", FRESH_INTERMEDIATES, 60),
    linux("npm-ci", "npm ci --ignore-scripts", 300),
    linux("npm-audit", "npm audit --audit-level=high && npm audit --audit-level=high --prefix eng/verification/browser", 300),
    linux("check", "npm run check", 1200),
    linux("check-dotnet", "npm run check:dotnet", 1200),
    # The real locked Wrangler output against the approved Worker closure of the release profile (`npm run test:artifact`), which no
    # hosted job runs: a profile that no longer names the bundle the source builds fails here, before the candidate is built.
    linux("worker-provenance", "npm run test:artifact", 600),
    # The Go center (AF-CTR-02): the Windows controls plus the race detector, the fuzz targets and the image target.
    linux("linux-center", "python eng/center.py check", 900),
    linux("licence-evaluated", "node tooling/project.ts licence-evaluated", 300),
    linux("candidate", CANDIDATE, 900),
    # the whitespace check and quality's secret scan over the commits since the merge base; actionlint when a workflow changed
    linux("whitespace", "git diff --check {base} {sha}", 120, lane="scan"),
    linux("secret-scan", SECRET_SCAN, 600, lane="scan"),
    linux("actionlint", ACTIONLINT, 300, lane="actionlint", when=workflows_changed),
]
