# Cloudflare deployment

## One-time setup

The user already has the paid Workers plan. Use the same account that owns `arcforges.com` and `arcforges-web`. This repository creates `arcforges-cloud`, its Container binding, managed image registry entries and the route `arcforges.com/api/*`. It must not replace Web's apex Custom Domain or DNS record.

1. In Cloudflare, create a scoped API token with **Account → Workers Scripts → Edit**, **Account → Containers → Edit**, **Zone → Workers Routes → Edit**, and **Zone → Zone → Read**. Some interfaces label Edit as Write. Limit account resources to the ArcForges hosting account and zone resources to `arcforges.com`. No DNS edit, Workers AI or R2 permission is needed for Hello. Zone Read lets Wrangler resolve the configured zone name. Container image publication needs Containers permission; an older Web-only token may lack it.
2. In [Cloud repository environments](https://github.com/ArcForges/Cloud/settings/environments), use the repository's **cloudflare** environment. Environments and their secrets are not automatically shared from Web/AI.
3. Add environment variable `CLOUDFLARE_ACCOUNT_ID` with the real 32-character account ID. Add environment secret `CLOUDFLARE_API_TOKEN` with the token from step 1. Never place the token in Variables, source, a browser client or chat.
4. Restrict the environment to deployments from branch `main`. No manual reviewer is required for the requested automatic pipeline.
5. Add environment secret `NEON_DATABASE_URL_DIRECT`: the direct (unpooled, not `-pooler`) URL of the Neon owner role, which is the migration role of the PostgreSQL store, with `sslmode=require` and `channel_binding=require` ([PostgreSQL store](postgres-store.md#deployment)). The existing secret `NEON_DATABASE_URL` (the Hello's pooled URL) stays for the C# rollback path. The runtime role's credential is not a GitHub secret: the deployment generates and rotates it and uploads it as the Worker secret `ARCFORGES_CENTER_DATABASE_URL`.
6. Merge the verified PR. `CI / Deploy Cloudflare` will run after all required checks. There is no deploy-enable variable.

The agent can create the environment and set the already known Account ID. The account owner enters the secret in GitHub. Placeholder names in this guide are not working credentials and must not be installed as fake secrets.

## Pipeline and evidence

PR checks use no cloud credentials. Main builds a versioned Linux Native AOT image and Worker candidate, with static/offline checks and legal/provenance inspection. The application is not executed by CI.

Publication consumes the candidate by its workflow artifact ID. Before anything is pushed or promoted, the gated PostgreSQL step runs the sealed image's own `arcforges-center migrate` with the migration role (`tooling/postgres-deploy.ts`, [PostgreSQL store](postgres-store.md#deployment)) and records `artifacts/postgres-gate-production.json`. The deployment entry point then performs one promotion identity/integrity check, requires both gate records (D1 and PostgreSQL) for this candidate, loads the image and checks the Docker image ID. It pushes that image, reads the live Worker version's runtime slot from Cloudflare (its version message `runtime-slot=<slot>`), rotates the other slot with the image's `admin rotate-runtime-credential` (proved directly and through the pooled endpoint, never printed), deploys the same bundled Worker with it using the returned registry digest and the new slot's label and, only after that deployment succeeded, records the slot as promoted with `admin confirm-runtime-credential` ([runtime credential rotation](postgres-store.md#runtime-credential-rotation)). Publication does not rebuild. Deployments serialize and reject superseded main commits.

`artifacts/deployment.json` records the source, version and image/digest after the provider operation succeeds, and the configured surfaces: those the deployed Worker version starts the Go center with (`center.configuredSurfaces`, as `ARCFORGES_CENTER_SURFACES` states them; the acceptance deployment's `artifacts/proof-deployment.json` records the same field). The field is computed from the version's configuration, not observed from the running center ([start environment](#start-environment-after-a-deployment)). A prerelease preserves the candidate and deployment record. There is no automatic health/RPC/readiness polling, browser test or public archive download. A successful deployment is reported as deployment completion, not live runtime acceptance.

Existing `test:live` command remains an explicit local diagnostic for a concrete affected behavior. They are not merge/publication gates. The Web page may be exercised locally when needed; no mandatory cross-owner test is implied. Preserve the API route and Web's apex binding.

See [validation policy](validation-policy.md) for the retained checks and post-merge stopping boundary.

## Ingress pipeline

Every public call crosses the deny-by-default method table of the Worker and the admission pipeline of the host before any
business code runs; the Container port is never published and a server stream is passed through frame by frame, never
buffered. The route table, credential and CSRF rules, the frame guard, the proof-only probe and the checks that exist are in
[cloud ingress](cloud-ingress.md). Merging changes the production Worker bundle and Container image through this same
pipeline, but the production route table still serves only the anonymous Hello method; the probe and every session method
existed only in the `proof` environment. Since AF-CTR-02 the `proof` Worker (deployed only by the manual dispatch on `main`) is the
Go center's acceptance environment: official-hosted mode with the development fixtures of the plan configuration, its own
PostgreSQL database and runtime role, and the C# proof routes no longer deployed ([PostgreSQL store](postgres-store.md#acceptance-environment)).

## Runtime configuration and cost

The production Container runs the Go center (`/app/arcforges-center`, [center](center.md)); `wrangler.json` selects it with `ARCFORGES_HELLO_RUNTIME=go` and states its explicit mode and public base URL (`ARCFORGES_CENTER_MODE=official-hosted`, `ARCFORGES_CENTER_PUBLIC_BASE_URL=https://arcforges.com/api`), which the Container class passes through unchanged; the center refuses to start without them. In official-hosted mode no gated feature is enabled until the plan configuration exists (AF-CTR-03); Hello and health are not gated. The runtime secrets are the runtime role's pooled URL `ARCFORGES_CENTER_DATABASE_URL`, rotated by every deployment and passed to the Go center, which reads the Hello greeting through it, and the Hello's pooled `NEON_DATABASE_URL`, which only the C# rollback path receives (`tooling/neon-runtime.ts`). The migration role's `NEON_DATABASE_URL_DIRECT` stays in the deployment job and never reaches the Worker or the Container. The deployment token is a GitHub CI credential, not an application credential and not forwarded into the Container. The C# Native AOT executable stays in the image as its default entrypoint and as the Hello rollback (`ARCFORGES_HELLO_RUNTIME=csharp` through a reviewed main push).

The `identity` surface (AF-CTR-03, [accounts, sessions and devices](center-identity.md#surface-switch)) is switched by
`FLAGSHIP_SURFACES`: production carries `""` (no surface; Hello only, so no account page is served there), the acceptance
environment `identity,pages` with `ALLOWED_ORIGIN` set to its own origin. The `pages` surface ([account pages](center-identity.md#account-pages-and-browser-sessions))
is switched by the same flag, needs `identity`, and is forwarded by the Worker's [page handler](cloud-ingress.md#page-routes-plt-1);
a disabled one is a 404 at the edge. The Worker passes the parsed list to the Container as `ARCFORGES_CENTER_SURFACES` and always
`ARCFORGES_CENTER_CLIENT_IP_HEADER`; a disabled surface is answered at the edge without waking the Container. Both environments bind
an `IDENTITY_RATE_LIMITER` (60 per minute per location and client) for the surface methods; over it the Worker answers the generated
`RESOURCE/rate_limited` with a retry instant one limiter period (60 s) after the refusal. The acceptance environment also passes
`ARCFORGES_CENTER_IDENTITY_POLICY` with its anonymous-flow ceiling (600 flows per hour), because it shares the production Neon
project ([identity policy](center-identity.md#identity-policy)); production passes no policy. No bootstrap or mail value is ever in
`wrangler.json` (the proof bootstrap is an input of the protected dispatch, [below](#the-acceptance-environments-owner-bootstrap));
e-mail delivery stays disabled in every environment.

Both edge rate limits, the Hello's and the surface's, key a client by `edgeClientKey` (AF-CTR-03 F7): an IPv4 address, or the IPv4
address of an IPv4-mapped IPv6 address, by itself; an IPv6 address by its /64 network (the generated `edgeIpv6PrefixBits`), so one
host cannot pass the limit by changing its address within its own network. This changes the production Hello's keying for IPv6
clients only: every address of one /64 now shares the Hello's 60 requests per minute and location. The full address still reaches the
center in `x-arcforges-client-ip` for the surface methods.

Structural cost bounds stay in configuration: one `lite` Container instance (`max_instances: 1`), a 60-second idle `sleepAfter`, a 50 ms Worker CPU limit, the per-location Hello rate limit, at most 64 connections per center listener and a runtime database pool of four ([center](center.md#hosted-deployment), [PostgreSQL store](postgres-store.md#connection-budgets)).

Anyone can construct a valid Hello request. Rate limiting is per Cloudflare location and client (an IPv4 address or an IPv6 /64), not authorization or a hard spending cap. A single lite instance, idle sleep, request limits and disabled egress reduce exposure; sustained traffic can still keep it running and incur Worker/Container charges. Configure Cloudflare usage alerts and inspect logs/metrics.

### The acceptance environment's owner bootstrap

The acceptance center has no account until its owner enrolls with a one-time token ([proof bootstrap and
acceptance](center-identity.md#proof-bootstrap-and-acceptance)). The `CI` workflow's dispatch takes two more inputs, both used only
by `proof: deploy`: `bootstrap_sha256` (the SHA-256 of the token text, 64 lowercase hexadecimal characters; never the token) and
`bootstrap_expires_at` (an RFC 3339 UTC instant to the second, in the future and at most seven days ahead). They reach the deploy
step as the environment variables `PROOF_BOOTSTRAP_SHA256` and `PROOF_BOOTSTRAP_EXPIRES_AT` (never interpolated into a script),
`buildProofConfig` validates them before anything is pushed (both or neither; the messages never repeat a value) and sets them in
the generated proof configuration only, as `ARCFORGES_CENTER_BOOTSTRAP_SHA256` and `ARCFORGES_CENTER_BOOTSTRAP_EXPIRES_AT`, which the
Worker passes to the center; they are part of the start digest, so a center started under another bootstrap, or none, is restarted
before it serves a request. `artifacts/proof-deployment.json` records them (`center.bootstrap`, `null` for a dispatch without). The
checked-in `wrangler.json` carries neither in any environment (`tests/worker/center-config.test.ts`), production has no bootstrap, and a
dispatch without the inputs removes a spent or expired one. The token itself is generated on the owner's machine
(`eng/verification/proof-bootstrap.ts`) and never reaches CI, the Worker or the Container. The real-browser acceptance
(`eng/verification/browser`, its own package with an exact lockfile that the root `npm ci` and no workflow installs) runs on the
Windows host after the deployment; it is post-merge evidence, not a CI check.

### Start environment after a deployment

The Container's start environment follows the deployed Worker version (AF-CTR-03). A `--containers-rollout immediate` deployment
restarts the running instance with the new image but with the environment of its previous start; the new variables (surfaces, the
client-address header, the identity policy, the rotated runtime credential) apply only at the next start. Before AF-CTR-03 that next
start was the first idle sleep (`sleepAfter`), so after the A1a deployment the acceptance Worker forwarded identity calls to a
center still started without `ARCFORGES_CENTER_SURFACES`, which answered `STATE/not_activated` until it slept. Now the Container
class (`worker/foundation/cloud-container.ts`) records, in its Durable Object's storage and before every start, the SHA-256 of the
start settings: the Worker's `SOURCE_REVISION`, the entrypoint, the egress switch and every variable. Every request first compares
it with the digest of this version's settings. A center started under another digest (or before the digest existed) gets SIGTERM
(the center stops within 5 s; the class waits up to 6 s), then SIGKILL (bounded at 4 s), and is started again with this version's
settings before the request is forwarded. The bounds are generated from the center (`staleCenterStopMs`, `staleCenterKillMs` and
`centerStopPollMs` in `worker/tables/center-tables.generated.ts`, from `routes.ShutdownMilliseconds`, the center's own shutdown
bound). Requests that arrive meanwhile wait for the same restart, so with `max_instances: 1` the
previous environment never serves a request of the new version. Health and the Hello go through the same rule: the first request
after a deployment pays one restart and is never refused by it. A previous center that cannot be stopped within the bounds is never
forwarded to: after up to about 10 s (6 s for SIGTERM, then 4 s for SIGKILL) the request gets the library's start-failure reply,
which the Worker answers as the retryable `UNAVAILABLE`, but only if the request's own deadline has not run out first. Health and
the identity methods (15 s budgets) get that reply. The Hello (a 10 s budget), and any call whose client deadline is shorter than
about 10 s, reaches its deadline first and gets `DEADLINE_EXCEEDED`, which carries no retry advice
([development](development.md)), again without having been forwarded; so does a Hello whose restart and cold start together take
longer than 10 s.
The digest covers the runtime credential, so it stays in the Durable Object's storage and is never logged or returned.

The center states the surfaces it serves in its health document (`center.surfaces`, [center](center.md#health-readiness-logs-and-metrics)).
The deployment evidence (`center.configuredSurfaces` in `artifacts/deployment.json` and `artifacts/proof-deployment.json`) is
what the deployed version starts the center with, computed from its configuration; it is not an observation of the running center.
`npm run test:live` compares the production health with `artifacts/deployment.json`, and the local Worker check
(`npm run test:worker`) compares it with the surfaces the candidate's Worker forwards. CI makes no such request
([validation policy](validation-policy.md)), so for both environments the post-deploy acceptance reads `/api/healthz`
`center.surfaces` and compares it with the deployment evidence (`none` on production, `identity,pages` on proof).

A rollback to a Worker version from before AF-CTR-03 part A1b (`wrangler rollback` or the dashboard, which reach only the
immediately previous version) brings back a Container class without the start digest. The running center keeps the start
environment of the newer version (its surfaces, client-address header, identity policy and runtime credential) until it has been
idle for `sleepAfter` (60 s); only its next start takes the rolled-back version's variables. Meanwhile its health can state other
surfaces than the rolled-back Worker forwards, and on proof an identity call can be answered by a center whose surfaces differ from
the Worker's. The operator step after such a rollback: read `/api/healthz` `center.surfaces`; while it differs from the rolled-back
version's configured surfaces, keep the environment's API route without traffic for at least 60 s (for production, remove only the
`arcforges.com/api/*` route, as for containment under [recovery](#recovery)), then restore the route and read it again. The digest
the newer version recorded stays in the Durable Object's storage, so the next deployment of a new version restarts the center as
above; a second rollback, back to exactly that newer version, finds its own digest and does not restart a center the older version
started, so the same check follows it. A rollback between two versions that have the digest restarts the center once, as a
deployment does.

## Recovery

- A failed upload/provisioning does not necessarily mean nothing changed. Inspect the recorded workflow logs and Cloudflare Worker/Container state before retrying.
- Diagnose an actual provider failure before a scoped retry. On a network failure, report the exact operation and stop; do not change proxy settings or blindly rerun.
- For a source regression, revert the offending main commit with a PR. The normal pipeline builds, checks and deploys the reverted behavior under a new identity/version.
- For urgent containment, remove only `arcforges.com/api/*` from `arcforges-cloud` routes or disable this Worker. Preserve `arcforges-web` and the apex Custom Domain. The Web connection page will show unavailable instead of fabricated success.
- Retain candidate release archives and referenced registry images. Do not delete an image still used by a current/previous deployment.
- The PostgreSQL store never migrates down: a rollback is an application revert on `main` over an expanded schema (expand and contract), and its data is recovered from Neon's history or a logical backup ([PostgreSQL store](postgres-store.md#recovery)). A Cloudflare version rollback (`wrangler rollback` or the dashboard) works only to the immediately previous version: an older version carries a runtime slot password that has since been rotated, and a version rollback also reverts the version's secrets. A failed migration rolls back completely and stops the deployment before promotion; the running revision is untouched.
- To roll the Hello back to C#, set `ARCFORGES_HELLO_RUNTIME` to `csharp` in `wrangler.json` through a reviewed PR; the same image carries both executables and the Worker table is identical for both runtimes (`GeneratedTablesTests`).
- Durable Object migrations are append-only and must start from the tag the live script records. A build that was later discarded from `main` (CLOUD.07, PR #72) was deployed to production and applied migration `capacity-pacer-v1`, adding the class `CapacityJobPacer`; the baseline list lacked that tag, so Wrangler replayed `v1` and Cloudflare refused it (error 10074). The production list therefore keeps `v1`, records `capacity-pacer-v1` exactly as applied, and retires the class with `retire-capacity-pacer-v1` (`deleted_classes`). The class held only scheduling hints, was never enabled in production, has no binding, export or code here, and its storage is discarded by the deletion. Never edit or reuse these tags; any later class change is a new appended tag. The proof environment never applied it.
- The same discarded builds registered a production cron schedule `* * * * *` for that work. Wrangler replaces a Worker's schedules only when `triggers.crons` is declared, so the production configuration declares `"triggers": {"crons": []}` to remove it; the baseline Worker has no `scheduled` handler and production needs no schedule. Environments inherit top-level `triggers`, so the proof environment declares `"triggers": {}` and keeps its schedules untouched (it never had one). A later task that needs a production schedule declares it here.
- Cloudflare refuses to upload a Worker that a queue still names as its consumer when the Worker has no `queue` handler (code 11001). The retired C# proof bundle consumed `arcforges-proof-wake` and `arcforges-proof-wake-dlq`, so `npm run deploy:proof` detaches exactly those consumers of the proof script before the upload and refuses any proof-script consumer, cron schedule or Durable Object migration tag that the generated proof configuration does not declare; the queues stay, unconsumed, until AF-CTR-09 ([PostgreSQL store](postgres-store.md#acceptance-environment)).
- If a deployment token is exposed, revoke it at Cloudflare, replace the GitHub secret, inspect deployments and then redeploy verified main.

## Official references

- [Containers setup and provisioning](https://developers.cloudflare.com/containers/get-started/)
- [Image management and registry publication](https://developers.cloudflare.com/containers/guides/image-management/)
- [API token permission groups](https://developers.cloudflare.com/fundamentals/api/reference/permissions/)
- [Worker route permissions](https://developers.cloudflare.com/workers/authorization/)
- [Routes ahead of Custom Domains](https://developers.cloudflare.com/workers/configuration/routing/custom-domains/#interaction-with-routes)
