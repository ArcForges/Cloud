# Project licence boundaries (WP00.02)

The [accepted Design profile](https://github.com/ArcForges/ArcForges-Design/blob/6ba885ad38dd71de532c74d7b69f439d01d19a0a/docs/architecture/01-solution-and-project-layout.md#41-project-declaration-and-verification-profile)
assigns Cloud's original code, tests and tooling to AGPL-3.0-only / AGPL.
`eng/policy/licence-boundary.json` enumerates every current project/build manifest.
The inventory check discovers tracked and nonignored files independently; changing
the policy cannot change the permitted repository assignment.

The existing `npm run check` and candidate build check effective npm declarations,
source declarations for every build scope, imported MSBuild properties, project
reference containment and locked first-party package ownership. Tests exercise
new projects, missing/inconsistent properties, imports, escaped references, npm
aliases, unknown transitive first-party packages and invalid Gradle declarations.
No adjacent repository is imported or built. Third-party licences and existing
candidate notices remain separately owned and enforced.

`node tooling/project.ts licence-evaluated` evaluates owned MSBuild projects in
Debug and Release and retains their actual properties and reference edges. Build
targets reject wrong effective values before build/pack. Source and evaluated
reports include the exact commit, dirty state, inventory and findings under
`artifacts/evidence/licence-*.json`; CI uploads the reports.

The npm scope, three managed projects and independent Kotlin consumer are covered. Gradle checks its actual evaluated declaration and graph and writes `tests/kotlin-consumer/build/reports/licence-boundary.json`. The Docker build includes the same MSBuild guard; the AOT image cannot omit the declaration check. Existing image, three-client protocol, restart, local Worker/Container and post-merge live Cloudflare verification remain required.

These source/build-policy results do not establish product functionality or close
later commercial gates. Local candidate identity and fixture/runtime evidence are
recorded separately from the merged deployment and public release.
