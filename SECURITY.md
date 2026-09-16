# Security policy

The latest main branch is supported. This is a Hello transport bootstrap, not an authenticated business server.

Report security vulnerabilities through [GitHub private vulnerability reporting](https://github.com/ArcForges/Cloud/security/advisories/new). Do not post credentials, private request data or an exploit against production in a public issue. Include the affected commit, impact and a safe local reproduction.

PR jobs run without Cloudflare credentials. Only the main deployment job receives the protected repository environment. Use a scoped deployment token; never ship it to the browser or C# runtime. Rotate a compromised token in Cloudflare and replace the GitHub environment secret.

The Hello endpoint is intentionally public and can be reproduced by any HTTP client. Input limits, a per-location IP rate limit, one container instance, CPU/memory settings, disabled container egress and idle shutdown constrain exposure; they do not prevent all abuse or impose an account-wide spending cap. Configure billing alerts and monitor Cloudflare usage. For an incident, remove only Cloud's `arcforges.com/api/*` route or disable this Worker, following [recovery](docs/deployment.md#recovery).

No account, AI, payment, file storage or database operation is available in this bootstrap. Adding such operations requires authentication, authorization and quota design before exposure.
