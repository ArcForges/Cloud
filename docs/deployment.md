# Cloudflare deployment

## One-time setup

The user already has the paid Workers plan. Use the same account that owns `arcforges.com` and `arcforges-web`. This repository creates `arcforges-cloud`, its Container binding, managed image registry entries and the route `arcforges.com/api/*`. It must not replace Web's apex Custom Domain or DNS record.

1. In Cloudflare, create a scoped API token with **Account → Workers Scripts → Edit**, **Account → Containers → Edit**, **Zone → Workers Routes → Edit**, and **Zone → Zone → Read**. Some interfaces label Edit as Write. Limit account resources to the ArcForges hosting account and zone resources to `arcforges.com`. No DNS edit, Workers AI or R2 permission is needed for Hello. Zone Read lets Wrangler resolve the configured zone name. Container image publication needs Containers permission; an older Web-only token may lack it.
2. In [Cloud repository environments](https://github.com/ArcForges/Cloud/settings/environments), use the repository's **cloudflare** environment. Environments and their secrets are not automatically shared from Web/AI.
3. Add environment variable `CLOUDFLARE_ACCOUNT_ID` with the real 32-character account ID. Add environment secret `CLOUDFLARE_API_TOKEN` with the token from step 1. Never place the token in Variables, source, a browser client or chat.
4. Restrict the environment to deployments from branch `main`. No manual reviewer is required for the requested automatic pipeline.
5. Merge the verified PR. `CI / Deploy Cloudflare` will run after all required checks. There is no deploy-enable variable, runtime API key or database secret in this Hello increment.

The agent can create the environment and set the already known Account ID. The account owner enters the secret in GitHub. Placeholder names in this guide are not working credentials and must not be installed as fake secrets.

## Pipeline and evidence

PR checks use no cloud credentials. Main builds a versioned Linux Native AOT image and Worker candidate, with static/offline checks and legal/provenance inspection. The application is not executed by CI.

Publication consumes the candidate by its workflow artifact ID. Its deployment entry point performs one promotion identity/integrity check, loads the image and checks the Docker image ID. It pushes that image and deploys the same bundled Worker using the returned registry digest. Publication does not rebuild or repeat image extraction/application execution. Deployments serialize and reject superseded main commits.

`artifacts/deployment.json` records the source, version and image/digest after the provider operation succeeds. A prerelease preserves the candidate and deployment record. There is no automatic health/RPC/readiness polling, browser test or public archive download. A successful deployment is reported as deployment completion, not live runtime acceptance.

Existing `test:live` and `test:kotlin:live` commands remain explicit local diagnostics for a concrete affected behavior. They are not merge/publication gates. The Web page may be exercised locally when needed; no mandatory cross-owner test is implied. Preserve the API route and Web's apex binding.

See [validation policy](validation-policy.md) for the retained checks and post-merge stopping boundary.

## Runtime configuration and cost

Hello has no runtime secrets, database or AI calls. The deployment token is a GitHub CI credential, not an application credential and not forwarded into the C# process. Later database/session/AI secrets require a separate runtime configuration design.

Anyone can construct a valid Hello request. Rate limiting is per Cloudflare location and IP, not authorization or a hard spending cap. A single lite instance, idle sleep, request limits and disabled egress reduce exposure; sustained traffic can still keep it running and incur Worker/Container charges. Configure Cloudflare usage alerts and inspect logs/metrics.

## Recovery

- A failed upload/provisioning does not necessarily mean nothing changed. Inspect the recorded workflow logs and Cloudflare Worker/Container state before retrying.
- Diagnose an actual provider failure before a scoped retry. On a network failure, report the exact operation and stop; do not change proxy settings or blindly rerun.
- For a source regression, revert the offending main commit with a PR. The normal pipeline builds, checks and deploys the reverted behavior under a new identity/version.
- For urgent containment, remove only `arcforges.com/api/*` from `arcforges-cloud` routes or disable this Worker. Preserve `arcforges-web` and the apex Custom Domain. The Web connection page will show unavailable instead of fabricated success.
- Retain candidate release archives and referenced registry images. Do not delete an image still used by a current/previous deployment. This stateless Hello has no database migration or persistent application data to roll back.
- If a deployment token is exposed, revoke it at Cloudflare, replace the GitHub secret, inspect deployments and then redeploy verified main.

## Official references

- [Containers setup and provisioning](https://developers.cloudflare.com/containers/get-started/)
- [Image management and registry publication](https://developers.cloudflare.com/containers/guides/image-management/)
- [API token permission groups](https://developers.cloudflare.com/fundamentals/api/reference/permissions/)
- [Worker route permissions](https://developers.cloudflare.com/workers/authorization/)
- [Routes ahead of Custom Domains](https://developers.cloudflare.com/workers/configuration/routing/custom-domains/#interaction-with-routes)
