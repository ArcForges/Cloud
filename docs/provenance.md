# Reuse, provenance and distribution

Cloud implements Design's WP-00.03 current-owner and packaging profiles at
`5322d698a1b650a52a5a139d986dd85b00b48581`. The current Cloud repository is the audit
subject. The retired initialization repository is not a producer or required checkout.

`eng/provenance/template.json` defines the reusable ten-field record shape.
Records live at `eng/provenance/records/<lowercase-id>-r<N>.json` and the active
source/artifact bindings live in `eng/provenance/files.json`. The closed five-row
decision table is `eng/policy/reuse-policy.json`. Original owner tooling is AGPL;
this checker was authored here and adds no sibling-source dependency.

Before introducing reused source, tests, assets, wrappers or packaging resources,
the Licensing and Provenance Owner reviews their particular file-level grant,
source repository/commit/paths, copyright, targets, disposition, oracle, notice and
lifetime. Maintainer-authorized implementation review may exercise that role and
must record the reviewer, date and rationale. A temporary record also needs an
accountable owner and an observable removal trigger. Generated material names
the exact generator and inputs and their separate licence positions.

Used records are immutable, including retired records. A changed source, intent,
target or legal obligation requires a new record with `supersedes`; update active
bindings and retain the old file. Remove a target's binding when the target is
removed. Review the complete contribution for newly reused material inserted into
an authored file; an inventory cannot determine authorship. Do not format immutable
records/profiles or full upstream legal documents with a general code formatter.

Register conflicts at `eng/provenance/conflicts/<id>.json` with `schemaVersion`,
`id`, `material`, `evidence`, `boundary`, `owner`, `requiredDecision`, `status` and
`resolution`. An unresolved status blocks the gate. The responsible owner records
the decision and admits a new valid record, or removes the contribution. This
process does not authorize a new licence exception or a change of product scope.

Run `node tooling/project.ts provenance` to audit all tracked and non-ignored new
files, exact reused bytes, record history, conflicts, policy and NOTICE. Local
branches compare against fetched `origin/main`; main compares its current committed
baseline. CI requires full history and the trusted event base. Missing history is
an error. After an approved binding change, run
`node tooling/project.ts provenance-notice` to regenerate
`eng/provenance/NOTICE.txt`. The summary supplements full legal texts.

The initial reconciliation covers the retained AGPL text and three standard
Gradle 9.7.1 wrapper files. Independent generation matched all three files. Gradle
is build/test-only. New full upstream legal files were admitted under reviewed
records before copying. A legal-document record permits notice reproduction only;
it does not admit or relicense the implementation mentioned by that document.

## Actual release closure

The two active artifact records select one immutable `cloud-release-r<N>` profile.
It binds all six parsed Worker inputs, five emitted inputs, external imports,
exports, exact bundle hash, installed package versions/integrities, both Docker
image pins, Native AOT source/configuration/lock inputs and applicable full legal
texts. Unknown or changed material requires a newly reviewed profile and record.

Cloud's own type checker is **TypeScript 7.0.2**, with **Wrangler 4.132.0**.
The historical **TypeScript 6.0.3** identity in the Containers provenance record
describes the compiler used by upstream `@cloudflare/containers@0.3.7`. It was used
only to reproduce that package's four published JavaScript files exactly. It is
not Cloud's compiler and does not identify a Workers runtime version.

`candidate` verifies the actual generated Worker and metafile, stages complete
legal documents, and inspects `/app` in the real final Native AOT image. The image
must contain only the application, retained root licence and the declared notice
tree. Each full notice, its source receipt and all six base copyright paths are
verified. The existing immutable base preserves its own original terms. The
native binary's concrete hash is recorded along with the image identity. The
existing C#/TypeScript/Kotlin, restart and local Worker/Container tests remain
required; provenance checks do not replace runtime evidence.

The candidate's `legal-notices.json` contains the full relevant licence texts,
active source records and source/profile identities. `worker-meta.json` describes
the actual bundle; `image-provenance.json` records the inspected image closure.
Every payload is covered by the candidate manifest. Verification independently
compares Worker bytes and legal contents with the approved source profile, so
forging a new outer payload hash does not admit changed content. After loading the
tested image, deployment inspects it again and compares the complete image receipt
before promotion. Publishing never rebuilds the Worker or application.

The image has readable full legal files and `provenance.json` under `/app/notices`;
the Worker release archive has its applicable full texts in `legal-notices.json`.
The source summary also describes source-only Gradle material and does not claim
it is shipped in either runtime. No browser UI is added to native applications.

Windows/Linux source CI runs positive and failure tests and retains the source
receipt. Candidate/deployment jobs retain actual image and protocol evidence.
These gates cover the current scaffold and provenance obligations; they do not
establish completed business features or commercial readiness.

## WP02.04 support identity

`cloud-release-r5` and successors `cloud-runtime-notices-r6` / `cloud-worker-bundle-r5` retain every predecessor. They bind the reviewed source commit, embedded version inputs and exact Worker build-header change. Its expected bundle was derived from the retained r4 bundle plus that single reviewed assignment before regeneration; full byte equality was then verified. `arcnotes-build-identity-r1` records the resolver/catalog/test/PE-inspection adaptation under the same AGPL boundary. Full corresponding source and original terms remain in the distributed legal bundle. Actual image support identity, three compiled assemblies and Worker/Container deployment identity are additional gates; none replaces existing protocol or legal checks.
