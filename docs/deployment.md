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

`artifacts/deployment.json` records the source, version and image/digest after the provider operation succeeds. A prerelease preserves the candidate and deployment record. There is no automatic health/RPC/readiness polling, browser test or public archive download. A successful deployment is reported as deployment completion, not live runtime acceptance.

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

Structural cost bounds stay in configuration: one `lite` Container instance (`max_instances: 1`), a 60-second idle `sleepAfter`, a 50 ms Worker CPU limit, the per-location Hello rate limit, at most 64 connections per center listener and a runtime database pool of four ([center](center.md#hosted-deployment), [PostgreSQL store](postgres-store.md#connection-budgets)).

Anyone can construct a valid Hello request. Rate limiting is per Cloudflare location and IP, not authorization or a hard spending cap. A single lite instance, idle sleep, request limits and disabled egress reduce exposure; sustained traffic can still keep it running and incur Worker/Container charges. Configure Cloudflare usage alerts and inspect logs/metrics.

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
