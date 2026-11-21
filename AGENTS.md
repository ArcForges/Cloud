# Cloud repository instructions

Plan bounded changes before implementation. This repository owns the Go Center (`center/`), its Docker image and the Cloudflare Container ingress Worker. ArcForges-Design governs the active design. [ArcForges-Design](https://github.com/ArcForges/ArcForges-Design) · [AD-0021](https://github.com/ArcForges/ArcForges-Design/blob/main/docs/decisions/AD-0021-central-access-go-center.md)

- Work in an isolated worktree. Do not edit adjacent repositories as part of a Cloud change.
- The Go Center owns product decisions and authoritative state. Keep the Worker to ingress, routing and platform adapters. The Worker table derived from Go registrations remains under its generator check. Preserve the frozen compatibility table and the named WorkerAdapter exceptions for the existing proof adapters. [Worker table authority](docs/center.md#worker-table-authority)
- Keep repository documentation in English. Preserve AGPL-3.0-only and third-party notices.
- Consume exact published Contracts packages: NuGet, npm for `@arcforges/ai-internal` only, and the Go module `github.com/ArcForges/Contracts/go` at an exact version verified by `go.sum`. Never edit generated contracts here, copy sibling source, use submodules, `replace` directives or adjacent ProjectReferences.
- Build the Linux candidate with the native Go executable. `Cloud.slnx` contains the independent published-contract Consumer and the ArchitectureTests project. Build both with locked dependencies and retain the existing source, binary and provenance checks. Runtime diagnostics remain local opt-in.
- Commit the NuGet, npm and Go (`go.sum`) locks; pin tools/base images/Actions and the Go release (`center/toolchain.json`). Dependency updates must pass locked restores and the relevant compilation and packaging checks; a Go dependency change is re-admitted in `center/dependencies.json` by review.
- PR code must not receive deployment secrets. Main deployment promotes the sealed candidate image and Worker; never rebuild during publication.
- The ingress pipeline is deny-by-default. Register each new Center method with its route, policy and budget. Preserve the bounded anonymous Hello diagnostic and the authorization requirements of authenticated methods. [Cloud ingress](docs/cloud-ingress.md)
- The Center uses PostgreSQL through its declared runtime role. Keep D1 migration history, frozen output and the existing historical-plan checks available for verification. [PostgreSQL store](docs/postgres-store.md) · [D1 physical schema and history](docs/d1-physical-schema.md)
- One correlation identity per call is accepted or created at the edge, joined to one W3C `traceparent` from the Worker to the host and carried with a causation id in the job wake and the private job-slice call ([cloud-ingress](docs/cloud-ingress.md)). It uses only the wire fields `RequestMeta`, `ResponseMeta` and `ArcError` already define, adds no header or contract meaning, never takes part in authorization, and a malformed client value is refused with `validation.invalid_request`. Later hops (events, providers) reuse the seam; do not re-implement propagation per module.
- Keep Center health and the operator-signed Worker proof readiness surface within their existing authorization and response scopes. Preserve the closed readiness vocabulary and fail closed when required evidence is unavailable. [Cloud readiness](docs/cloud-readiness.md)
- Keep the API route separate from Web's apex Custom Domain. Preserve binary gRPC-Web responses and status trailers.
- Run the checks in CONTRIBUTING.md. Distinguish unit, Docker, local Worker runtime, live Cloudflare and real browser evidence.
- Never read or print local credential stores, log tokens, commit secrets or request secret values in chat. Describe missing environment configuration explicitly.

## Flagship role

Cloud provides the Go Center for account access, node enrollment and typed remote management. The Worker forwards the channel upgrade to the Center, and Node retains local authorization and execution. Flagship activation is governed by Plan task AFV2-PROD-01. [Center](docs/center.md) · [Delivery graph](https://github.com/ArcForges/Plan/blob/main/delivery-graph.json)

The former C# host, its generator, the original D1 tools and their tests are preserved at Cloud commit `9b8796eac760982d9814f371b820b736ddd945c4`. Verify the archived inputs with `npm run check:legacy-cloud-history`. Use the conditions in the deployment guide for any previously admitted rollback artifact. [D1 history](docs/d1-physical-schema.md#migrations) · [Deployment](docs/deployment.md)

## Delivery (serial, ArcForges/Plan)

Tasks for this repository come from the [Plan delivery graph](https://github.com/ArcForges/Plan/blob/main/delivery-graph.json) and are delivered under the Plan [execution policy](https://github.com/ArcForges/Plan/blob/main/execution-policy.md) and [delivery procedure](https://github.com/ArcForges/Plan/blob/main/delivery-procedure.md) ([AD-0014](https://github.com/ArcForges/ArcForges-Design/blob/main/docs/decisions/AD-0014-delivery-method.md)). They are binding. The historical P2-018 model (delivery lanes, adoption slices, `delivery.py` claims and handoffs, parallel workers, integration-owner roles, leases, the build slot and the launcher) is retired and never resumed.

- One task is active at a time. Work only inside its write scope, in a worktree `.worktree/<task-id-lower>` on branch `task/<task-id-lower>`, never in the primary checkout.
- Delegated workers and reviewers work locally. Only the coordinator pushes, verifies the pushed head on both hosts, opens pull requests, merges (at the reviewed head, after the merge gate: the required statuses `arcforges/windows` and `arcforges/linux` for every PR, and hosted CI too for external PRs) and deploys through the guarded main-push path.
- Title pull requests `[<TASK-ID>] <summary>`.
- Shared files follow the active task scope and component ownership. Keep PostgreSQL schema changes in numbered migrations with an explicit runtime-grant decision. Keep generated Worker routes tied to their source registrations. Each publication watermark, Durable Object alarm namespace and R2 prefix has one owner in the binding plan.
- Dated bootstrap and validation records under `docs/` describe the host, source revision and proof scope recorded at the time. Use the current development commands and reproduce historical-only work from its recorded revision when needed. [Development](docs/development.md)

## Verification after the push (AD-0020)

Every PR into `main` is verified after the push, on the two verification hosts, and gated by GitHub ([AD-0016](https://github.com/ArcForges/ArcForges-Design/blob/main/docs/decisions/AD-0016-local-first-verification.md) as amended by [AD-0020](https://github.com/ArcForges/ArcForges-Design/blob/main/docs/decisions/AD-0020-post-push-verification-and-required-checks.md)). The flow: Push → Fetch → Local verification → Report status → Required checks → Review → Merge. The cross-repository rules are the Plan [AGENTS.md](https://github.com/ArcForges/Plan/blob/main/AGENTS.md) rules 6 and 7.

- **Push** the branch to GitHub before the formal verification. The `pre-commit` hook checks staged whitespace and `gofmt -s` on staged Go files. `python eng/verify.py install`, once per clone from the main checkout on `main`, installs it in the clone's common hooks directory and makes it executable. It also removes the retired pre-push hook and any `core.hooksPath`. Re-run it when `.githooks/` changes.
- **Two native hosts.** Run the Windows leg in PowerShell on the designated Windows workstation. Run the Linux leg in a native shell on the designated Linux host over its existing SSH access, from that host's native filesystem. The verifier runs the leg of its own host. WSL and Windows-mounted Linux checkouts are outside this profile.
- **Fetch and verify on each host.** Use the host's own Git clone. Replace `BRANCH` and `SHA` with the pushed branch and exact commit.

  ```
  git fetch origin BRANCH
  git worktree add --detach .worktree/verify-SHA SHA
  cd .worktree/verify-SHA
  python eng/verify.py run-and-report
  ```

  For an external PR (Dependabot included), read the diff first; for one from a fork, fetch `refs/pull/<n>/head`.

- **Report status.** Each host reports the commit status `arcforges/windows` or `arcforges/linux` on that exact commit:
  - `pending` when it starts;
  - `success` only when every step of its leg ran and passed;
  - `failure` when a step failed, `error` when the leg could not complete.

  The command exits 0 after success, 1 when a step failed and 2 when the leg could not complete or be reported. The host reports with `ARCFORGES_STATUS_TOKEN` when set (a token limited to commit statuses), otherwise with its own `gh` login; steps never receive either through their environment, and neither is printed. The `gh` login stays readable from the host's `gh` configuration by the code being verified, so set `ARCFORGES_STATUS_TOKEN` on the host.

- **Required checks.** The `main` ruleset requires both statuses for every PR, with no bypass actors and the strict up-to-date policy; classic branch protection keeps requiring the hosted `Verify` check (skipped for the owner's PRs). The branch must be up to date with `main`, and every new push needs verifying again on both hosts.
- **Unavailable host.** Report the exact failed operation or missing prerequisite. Merge requires both success statuses from the designated hosts. Preserve the original result and run the affected leg when its host is available.
- `python eng/verify.py list` shows the profile and each host's steps. `python eng/verify.py run` runs this host's leg of `HEAD` without reporting.
- **What runs.** The full profile in `eng/verify_steps.py` checks the exact fetched commit. It includes applicable checks for documentation changes.
  - The Windows lane in `<main checkout>/.worktree/_verify` runs the native Go controls, locked npm install, locked restore and Release build of the two-project managed solution, the archived CTR06 bridge checks and the evaluated licence check.
  - The Linux lane in `~/.cache/arcforges-verify/Cloud` checks clone identity and fresh managed intermediates. It runs the locked installs and dependency audits, source and managed architecture checks, archived CTR06 bridge checks, Worker provenance tests on the locked Wrangler output, and the evaluated licence check. Its candidate step builds the sole Go Center image and both Worker bundles with Wrangler `--dry-run`, and verifies the sealed manifest and artifact contents. The Linux Go lane adds the race detector, PostgreSQL integration tests, restore drill, fuzz targets and vulnerability checks.
  - Lane `scan`: `git diff --check` and the pinned gitleaks image over the commits since the merge base with `.gitleaks.toml`, without network. `actionlint` when `.github/workflows/**` changed.
  - Not reproduced: the hosted architecture gate's RP-09 receipt (it trusts the secret scan only inside the GitHub `quality` job; locally RP-09 is the one accepted finding of the gate in `check:dotnet`, as in the hosted Linux source job), dependency review and CodeQL (GitHub services; external PRs, dispatch and the weekly schedule keep them). `CI` and `GITHUB_*` are not set and Cloudflare credentials are unset: nothing contacts Cloudflare.
- **Prerequisites.** Both hosts use their existing Git and GitHub identities, the pinned .NET SDK, Node/npm, Go and Python, and access to the approved registries and checksum and vulnerability databases. The Windows leg uses PowerShell 7 and the npm bundled with the selected Node. The Linux leg uses the verified LLVM/GNU tools for Go race/cgo and a native Docker Engine for the Go image, PostgreSQL fixtures and secret scan. Keep the separately pinned CTR06 historical inputs available on the host. [Development](docs/development.md)
- **Failures.** A failed, timed-out or unrunnable step reports `failure` and prints the step, the last log lines and the log path (`<git common dir>/arcforges-verify/logs/`, with `summary.json`). Read the log, fix the cause, push, verify again.
- **Statuses and rulesets.** A status is reported only by `python eng/verify.py run-and-report` on the host it names, at the commit it verified. Never post, edit or copy an `arcforges/*` status by hand, and never change the ruleset, branch protection or required checks to get a PR merged.
- AI agents must never use `git push --no-verify` to bypass required validation.
- They must also never disable, remove, modify, or otherwise circumvent the hooks or required checks merely to get a change through.
- If validation fails, investigate and fix the underlying issue.
- If a required local test cannot run, do not silently skip it or claim successful verification.
- Changing `eng/verify*.py`, `.githooks/` or the ruleset as reviewed engineering work is allowed; changing them to get a change through is not.

## Efficient execution

The Plan's rule 7 applies. In this repository:

- Install once (`npm ci --ignore-scripts`, `dotnet restore Cloud.slnx --locked-mode`), then build incrementally: `dotnet build Cloud.slnx -c Release --no-restore`.
- While iterating, run the affected checks. Use `dotnet test --project tests/ArchitectureTests -c Release --no-build` for the managed tests, `node --test tests/worker/<name>.test.ts` for an affected Worker suite, and the current Go and historical artifact checks for route, migration or schema changes. Use `npm run check:dependencies` after editing a bound input and the repository formatters for changed files.
- Run the full profile once per pushed head on each designated host with `python eng/verify.py run-and-report`. `python eng/verify.py run` runs this host's leg without reporting a status.

## Hosted CI

Under the AF-CTR-06 user exception dated 2026-11-13, external qualification, bootstrap publication and successor deployment remain deferred. The workflow disables their authority and deployment entries. Exact-head native verification and independent review remain required for development delivery. Unperformed external actions remain NOT PROVEN. [Deployment](docs/deployment.md)

- **Owner PRs:** no hosted validation or security analysis; `Source`, `Dependency audit and repository checks`, `Dependency review`, `CodeQL`, the candidate and `Verify` show as skipped. `Verify` is the required hosted check (classic protection); a skipped `Verify` satisfies it. The `main` ruleset also requires the host statuses `arcforges/windows` and `arcforges/linux` for every PR ([Verification after the push](#verification-after-the-push-ad-0020)), which are the owner PRs' gate together with the review.
- **External PRs** (Dependabot included) and manual dispatches: the full CI as before: both `Source` legs (each also runs `python eng/center.py check`), `quality` (audit, actionlint, the full-history secret scan, the build and the hosted architecture gate), dependency review (PRs), CodeQL for C#, Go, JavaScript/TypeScript and Actions, the candidate after `source` and `quality`, and `Verify`, which requires every one of them. A dispatch with `proof` = `access`, `provision` or `observe` keeps this chain and adds `proof-access`.
- **Proof deployment.** The deployment entry is disabled. Its retained gate requires the exact tree verified by both host statuses and binds the candidate to its successful source run, artifact ID, digest and sealed manifest. Any future enabled deployment uses that candidate unchanged. [Proof deployment gate](docs/deployment.md#the-proof-deployment-gate)
- **Main pushes.** The workflow keeps ordinary main-push candidate and deployment jobs disabled. The native Linux profile builds the candidate before merge. The existing production promotion path still requires the sealed candidate and its migration receipt if deployment is authorized.
- **Schedule** (weekly): the security analysis: CodeQL and `quality` (dependency audit, the full-history secret scan, the build and the hosted architecture gate that must follow the scan in that job). No source or candidate job.

## Required validation limits

Follow the Plan execution policy and the repository's validation limits. AD-0014 supersedes the parallel-delivery rule in the historical Design policy at `64173614`. Keep runtime checks explicit local opt-in. Exclude macOS, device, emulator, GUI/browser E2E, live service/inference, installed-consumer and public-download checks from CI. Preserve lock, signature, licence and provenance checks at their trust handoffs. Use the designated hosts and their existing toolchains. Report an unavailable prerequisite or the exact failed network operation. Run the formal full profile on the pushed head before merge and preserve its receipts. [Validation policy](docs/validation-policy.md) · [Native-host policy](https://github.com/ArcForges/ArcForges-Design/blob/main/docs/decisions/AD-0018-native-platforms-without-wsl-integration.md)

Dependency additions and upgrades follow [the enforced admission policy](docs/dependency-policy.md); update its input-bound review and retain the existing class and provenance gates.

## Go center (AF-CTR-02)

The Container runs `arcforges-center`, the sole application executable in the release image. The bounded Go Hello proof of 2026-10-27 retains its original scope in the historical record. [Center](docs/center.md) · [Go Hello history](docs/go-hello.md)

- The mode is explicit configuration: `ARCFORGES_CENTER_MODE` is `official-hosted` or `self-hosted`, and a missing or invalid
  value refuses to start. In official-hosted mode no gated feature is enabled without a valid plan configuration (AD-0021
  §13a); Hello and health are not gated features. No official endpoint is compiled into a code path: health and every URL the
  center issues derive from `ARCFORGES_CENTER_PUBLIC_BASE_URL`.
- Every public method registers its policy and Worker budget in `center/internal/routes`; the ingress registry and the
  Worker's production table (`worker/tables/center-tables.generated.ts`) are generated from it. After a registration change,
  run `python eng/center.py generate`; never edit the generated table by hand.
- The center keeps the C# ingress behaviour for the methods it serves (deny by default, framing, credentials, body bounds,
  correlation, refusal statuses; [center](docs/center.md#ingress-compatibility)). Signatures and request digests cover the
  transmitted bytes, never a re-encoding (AD-0021 §10).
- Logs carry correlation ids and never a secret, a header value, a command line, a body, output or file content.
- Use the pinned Go release (`center/toolchain.json`) with `GOTOOLCHAIN=local` and `GOFLAGS=-mod=readonly`. Run
  `python eng/center.py check` (both legs run it as `win-center` and `linux-center`); the Linux leg adds the race detector,
  the PostgreSQL integration tests, the restore drill, the fuzz targets and the image target. The controls and their C# counterparts are in
  [engineering controls](docs/engineering-controls.md).
- The store is PostgreSQL ([PostgreSQL store](docs/postgres-store.md)): pgx with hand-written SQL in exec query mode (no
  session state, so it works through the Neon pooler); every runtime transaction runs in `store.InTx` (deadline,
  serialization retries, errors without the server's message). Change the schema only
  with a new numbered file in `center/internal/schema/migrations`; never edit, rename or remove an applied migration (the
  runner refuses it). Changes are expand and contract: a migration must keep the running and the previous release working.
- The runtime role's privileges are declared in `center/internal/schema` (`RuntimeGrants`, `MigrationOnly`); a new table needs
  a grant decision there (a test fails otherwise). The runtime role never runs DDL; only `arcforges-center migrate` (the
  migration role, direct connection) changes the schema.
- Never print a database URL, password or server message: `migrate` and `admin` print only non-secret results (versions,
  checksums, role and database names, slots, timestamps, counts, and the target the operator named), and the deploy job's runtime
  password reaches only a private temporary file and the Worker secret. Store tests run against a
  real PostgreSQL on Linux (`ARCFORGES_TEST_POSTGRES_URL`; the check starts a pinned container) and skip on Windows.
- Mail ([center](docs/center.md#mail)): every message of the identity surface goes through `identity`'s `deliver`; a credential is a
  `config.Secret`, revealed only in `mail/postmark.go` and `mail/smtp.go`; `mail/mailtest` is imported by `_test.go` files only; a test
  never contacts a real provider unless its own explicit local switch is set; mail stays disabled in every deployed environment, and
  no workflow or script references a mail secret until the later enabling step. No real account can be mailed yet.
- The current candidate requires the Go Center. Under H-03, rollback may use a previously admitted Worker and image only
  after checking the live schema and credential compatibility. Go health reports `runtime=go` and `nativeAot=false`.
