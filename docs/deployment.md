# Cloudflare deployment

## One-time setup

The user already has the paid Workers plan. Use the same account that owns `arcforges.com` and `arcforges-web`. This repository creates `arcforges-cloud`, its Container binding, managed image registry entries and the route `arcforges.com/api/*`. It must not replace Web's apex Custom Domain or DNS record.

1. In Cloudflare, create a scoped API token with **Account → Workers Scripts → Edit**, **Account → Containers → Edit**, **Zone → Workers Routes → Edit**, and **Zone → Zone → Read**. Some interfaces label Edit as Write. Limit account resources to the ArcForges hosting account and zone resources to `arcforges.com`. No DNS edit, Workers AI or R2 permission is needed for Hello. Zone Read lets Wrangler resolve the configured zone name. Container image publication needs Containers permission; an older Web-only token may lack it.
2. In [Cloud repository environments](https://github.com/ArcForges/Cloud/settings/environments), use the repository's **cloudflare** environment. Environments and their secrets are not automatically shared from Web/AI.
3. Add environment variable `CLOUDFLARE_ACCOUNT_ID` with the real 32-character account ID. Add environment secret `CLOUDFLARE_API_TOKEN` with the token from step 1. Never place the token in Variables, source, a browser client or chat.
4. Restrict the environment to deployments from branch `main`. No manual reviewer is required for the requested automatic pipeline.
5. Merge the verified PR. `CI / Deploy and verify Cloudflare` will run after all required checks. There is no deploy-enable variable, runtime API key or database secret in this Hello increment.

The agent can create the environment and set the already known Account ID. The account owner enters the secret in GitHub. Placeholder names in this guide are not working credentials and must not be installed as fake secrets.

## Pipeline and evidence

PR checks use no cloud credentials. A push to main builds `0.1.0-ci.<run-number>.<attempt>`, tests a real Linux AOT image, then uploads the immutable candidate artifact. Publication downloads that artifact by ID, checks hashes and source identity, loads the image archive, verifies its Docker image ID and pushes to `registry.cloudflare.com`. Deployment uses a registry **digest**, not a floating tag, and the previously bundled Worker.

Deployments are serialized and check current main before upload. A stale run fails rather than replacing a newer commit. Rerunning all jobs creates a new attempt version; rerunning only failed deployment jobs reuses the already verified candidate. Tests and smoke never silently rebuild or redeploy.

Initial Container provisioning may take several minutes. Smoke polls readiness for up to ten minutes and requires both the Worker header and the compiled C# health revision to match the candidate. A healthy old container is not accepted. After readiness, the published TypeScript SDK verifies successful/Unicode greetings and gRPC `INVALID_ARGUMENT`/`RESOURCE_EXHAUSTED`; additional requests check route/size/type rejection. It also checks that the Web homepage still serves HTML.

`artifacts/deployment.json` records source revision, exact image identity/digest and live evidence. A GitHub prerelease is created only after these checks pass. A successful Docker build or Wrangler upload alone is not successful production verification.

## Public verification and Web

```sh
curl --fail https://arcforges.com/api/healthz
```

The response must identify `arcforges-cloud`, the expected source revision and `nativeAot: true`. A health response is necessary but does not replace the SDK tests.

Web PR #5 adds `https://arcforges.com/cloud-hello/`. Once that page is merged/deployed and Cloud is healthy, click **Check connection** and verify **Hello, ArcForges!** with a real successful network request to the protobuf method. No change to Web's domain, CSP or CORS is required. Until Web PR #5 is deployed, API smoke can pass while that page is unavailable; report those as separate milestones.

Keep `workers_dev` and preview URLs disabled. No Cloud custom domain is needed: the route takes precedence for `/api/*`, and the existing Web Worker continues serving everything else.

## Runtime configuration and cost

Hello has no runtime secrets, database or AI calls. The deployment token is a GitHub CI credential, not an application credential and not forwarded into the C# process. Later database/session/AI secrets require a separate runtime configuration design.

Anyone can construct a valid Hello request. Rate limiting is per Cloudflare location and IP, not authorization or a hard spending cap. A single lite instance, idle sleep, request limits and disabled egress reduce exposure; sustained traffic can still keep it running and incur Worker/Container charges. Configure Cloudflare usage alerts and inspect logs/metrics.

## Recovery

- A failed upload/provisioning/smoke does not necessarily mean nothing changed. Inspect the recorded workflow logs and Cloudflare Worker/Container state before retrying.
- For a transient first provisioning delay, wait for the platform status, then rerun failed jobs. Smoke does not automatically issue another deployment.
- For a source regression, revert the offending main commit with a PR. The normal pipeline builds, tests and deploys the reverted behavior under a new identity/version.
- For urgent containment, remove only `arcforges.com/api/*` from `arcforges-cloud` routes or disable this Worker. Preserve `arcforges-web` and the apex Custom Domain. The Web connection page will show unavailable instead of fabricated success.
- Retain candidate release archives and referenced registry images. Do not delete an image still used by a current/previous deployment. This stateless Hello has no database migration or persistent application data to roll back.
- If a deployment token is exposed, revoke it at Cloudflare, replace the GitHub secret, inspect deployments and then redeploy verified main.

## Official references

- [Containers setup and provisioning](https://developers.cloudflare.com/containers/get-started/)
- [Image management and registry publication](https://developers.cloudflare.com/containers/guides/image-management/)
- [API token permission groups](https://developers.cloudflare.com/fundamentals/api/reference/permissions/)
- [Worker route permissions](https://developers.cloudflare.com/workers/authorization/)
- [Routes ahead of Custom Domains](https://developers.cloudflare.com/workers/configuration/routing/custom-domains/#interaction-with-routes)
