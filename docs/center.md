# ArcForges center (Go)

The center is the Go service of [AD-0021](https://github.com/ArcForges/ArcForges-Design/blob/main/docs/decisions/AD-0021-central-access-go-center.md):
one executable, `arcforges-center`, built from the `center/` Go module (`github.com/ArcForges/Cloud/center`). It replaces the
bounded Go Hello proof ([go-hello](go-hello.md), now history) and is the runtime the production Worker selects. AF-CTR-02 delivered
it in two parts:

- **Part A (this document):** the executable, the ingress compatibility with the Worker and the C# host, the explicit center
  mode, configuration, health, readiness, logs and metrics, the Worker's production table generated from the center's
  registrations, and the Go engineering controls ([engineering controls](engineering-controls.md)).
- **Part B ([PostgreSQL store](postgres-store.md)):** the store, its migrations and platform tables, the roles, the
  `migrate` and `admin` commands, the deployment's PostgreSQL step and runtime credential rotation, the acceptance environment
  and the recovery procedure.

AF-CTR-03 adds accounts, sessions and devices behind the `identity` surface switch ([accounts, sessions and
devices](center-identity.md)).

The C# Native AOT host stays in the same image as its default entrypoint: setting `ARCFORGES_HELLO_RUNTIME=csharp` through a
reviewed main push is the Hello rollback (AD-0021 §15, until AF-CTR-09). The `proof` environment (proof.arcforges.com) runs the
Go center as the acceptance environment since part B.

## Layout

| Path                                                                                                         | Contents                                                                                                                                                                                                                                                                                                                                                                                           |
| ------------------------------------------------------------------------------------------------------------ | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `center/cmd/arcforges-center`                                                                                | The executable: `serve` (default), `migrate [apply\|status\|plan]`, `admin ensure-database`, `admin rotate-runtime-credential [--live-slot a\|b]`, `admin confirm-runtime-credential --slot a\|b`, `admin revoke-sessions --account <uuid>\|--all`, `admin grant-operator --account <uuid> --reason <text> [--days N]`, `admin revoke-operator --account <uuid>`, `version`/`--build-info`, `help` |
| `center/cmd/center-gen`                                                                                      | Development generator (never in the image): `worker-tables` writes `worker/tables/center-tables.generated.ts`                                                                                                                                                                                                                                                                                      |
| `center/cmd/node-probe`                                                                                      | Development stand-in for a node (never in the image; **MOCKED**, not the ArcForges node): signs in through the browser or device-code sign-in for the node-approve run ([center fleet](center-fleet.md#node-probe-and-the-node-approve-run))                                                                                                                                                       |
| `center/cmd/mobile-probe`                                                                                    | MobileProbe, the development stand-in of the Android app (never in the image; **MOCKED**, not the ArcForges app): begins a mobile native authorization and redeems its code for the mobile-approve run ([center mobile](center-mobile.md#mobileprobe-and-h3))                                                                                                                                      |
| `center/internal/config`                                                                                     | Environment configuration, refused when missing or invalid; the public base URL and database URL parsers                                                                                                                                                                                                                                                                                           |
| `center/internal/ingress`                                                                                    | The admission pipeline: policy registry, framing, envelope reader, credential shapes, owner gate, refusals and their status                                                                                                                                                                                                                                                                        |
| `center/internal/correlation`                                                                                | Correlation identity and the strict W3C `traceparent` parser                                                                                                                                                                                                                                                                                                                                       |
| `center/internal/routes`                                                                                     | The center's registrations: methods with policies, plain routes and the Worker's transport budgets                                                                                                                                                                                                                                                                                                 |
| `center/internal/workertables`                                                                               | Rendering of the Worker's production table from the registrations                                                                                                                                                                                                                                                                                                                                  |
| `center/internal/hello`                                                                                      | The anonymous Hello (`arcforges.hello.v1`), stateless or read from PostgreSQL                                                                                                                                                                                                                                                                                                                      |
| `center/internal/schema`                                                                                     | The embedded migrations and the runtime role's grants ([PostgreSQL store](postgres-store.md))                                                                                                                                                                                                                                                                                                      |
| `center/internal/store`                                                                                      | The runtime store: transactions, retries, sanitized errors; `store/migrate` is the migration runner                                                                                                                                                                                                                                                                                                |
| `center/internal/platform`                                                                                   | Command receipts, inbox, outbox and publisher, job leases, the audit chain and signing-key metadata                                                                                                                                                                                                                                                                                                |
| `center/internal/provision`                                                                                  | Database creation and the runtime credential rotation                                                                                                                                                                                                                                                                                                                                              |
| `center/internal/pgtest`                                                                                     | Integration test support: an isolated database on a real PostgreSQL                                                                                                                                                                                                                                                                                                                                |
| `center/internal/feature`, `entitlement`, `dbtest`                                                           | Feature availability and entitlements (AF-CTR-03 B): the gate, the plan catalogue, the resolver port, the store, the operator grant, and the test database support ([center entitlement](center-entitlement.md))                                                                                                                                                                                   |
| `center/internal/quota`                                                                                      | The per-account resource controls of the gated rows (AF-CTR-05 E0): the routed calls' rate and in-flight bounds and the node channel's upgrade rate ([routed task control](#routed-task-control))                                                                                                                                                                                                  |
| `center/internal/identity`, `session`, `device`, `access`, `identityapi`, `ratelimit`, `page`, `mail`, `arc` | The identity surface (AF-CTR-03): [accounts, sessions and devices](center-identity.md)                                                                                                                                                                                                                                                                                                             |
| `center/internal/pages`                                                                                      | The pages surface (AF-CTR-03 A2): the account pages, their script and style sheet and the `/session/v1/web` routes ([account pages](center-identity.md#account-pages-and-browser-sessions))                                                                                                                                                                                                        |
| `center/internal/mobileauth`, `mobiletest`                                                                   | The mobile surface (AF-CTR-04 part M): the mobile app's native authorization, and MobileProbe's library (**MOCKED** app, test and probe use only) ([center mobile](center-mobile.md))                                                                                                                                                                                                              |
| `center/internal/buildinfo`                                                                                  | The compiled build identity and the health document                                                                                                                                                                                                                                                                                                                                                |
| `center/internal/observe`                                                                                    | JSON logging and request metrics                                                                                                                                                                                                                                                                                                                                                                   |
| `center/internal/server`                                                                                     | Composition, listeners, readiness, metrics exposition and graceful shutdown                                                                                                                                                                                                                                                                                                                        |
| `center/tools`                                                                                               | A separate, never shipped module that pins staticcheck and govulncheck as Go `tool` dependencies                                                                                                                                                                                                                                                                                                   |

The bindings come from the published Contracts Go module `github.com/ArcForges/Contracts/go` at exactly `v1.0.0-ci.416.1`
(tag `go/v1.0.0-ci.416.1`, Contracts commit `62ccef1`, the cohort of the NuGet and npm packages `1.0.0-ci.416.1`, which adds the
installation products `arcforges-node`, `arcforges-mobile` and `arcforges-web`), fetched through the public module proxy and
verified by `go.sum` and the checksum database. No wire code is generated or written here. The center's WebAuthn relying party
uses `github.com/go-webauthn/webauthn` (admitted with its runtime closure in `center/dependencies.json`). The mobile surface's
HTTP JSON document (Contracts MobileNativeAuth v1, which no proto carries) is pinned to the Contracts cohort `1.0.0-ci.430.1`
(commit `5873dc2`): the document and its shared vectors are vendored byte for byte in `center/internal/mobileauth/testdata` and
replayed in Go ([center mobile](center-mobile.md#expected-divergences-from-the-contract)); the Go module stays at its version, because
that cohort changed no proto.

## Request path

```text
client (published C# gRPC-Web client, Web)
  → arcforges-cloud Worker (/api/*; deny-by-default table from center-tables.generated.ts, edge limits, traceparent)
  → Cloudflare Container :8080 (/app/arcforges-center, official-hosted)
  → ingress pipeline (canonical path, policy, media type, credentials, body bound, envelope, correlation)
  → Connect handler (binary gRPC-Web or gRPC) → Hello → (Neon read-only transaction when enabled)

self-hosted client → arcforges-center serve (HTTP/1.1 + h2c on the configured address; the same pipeline and routes)
```

The Worker strips the `/api` prefix it owns; the center serves the method paths and `/healthz` at its root. A self-hosted center
that is published under a path prefix sits behind a proxy that removes it, exactly as the Worker does.

## Configuration

Every value is an environment variable. A missing or invalid value refuses to start with one JSON log line that names the
variable and never repeats its value.

| Variable                                 | Default  | Rule                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                 |
| ---------------------------------------- | -------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| `ARCFORGES_CENTER_MODE`                  | none     | Required: `official-hosted` or `self-hosted` exactly                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                 |
| `ARCFORGES_CENTER_PUBLIC_BASE_URL`       | none     | Required: canonical absolute `https` URL (lowercase host, optional non-default port and path, no trailing slash, query, fragment or user); `http` only for a loopback host in self-hosted mode                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                       |
| `ARCFORGES_CENTER_HTTP_ADDRESS`          | `:8080`  | HTTP/1.1 and h2c listener; `host:port` with an IP literal, `localhost` or no host                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                    |
| `ARCFORGES_CENTER_GRPC_ADDRESS`          | `:8081`  | h2c-only listener; `off` disables it                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                 |
| `ARCFORGES_CENTER_ADMIN_ADDRESS`         | disabled | Readiness (`/readyz`) and metrics (`/metrics`); must be a loopback address in official-hosted mode                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                   |
| `ARCFORGES_CENTER_MAX_CONNECTIONS`       | `64`     | Concurrent connections per listener, 1 to 4096                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                       |
| `ARCFORGES_CENTER_MAX_NODE_CONNECTIONS`  | `256`    | Node channel connections (upgraded WebSockets of the relay surface, AF-CTR-05 E1a), 1 to 4096: an admitted upgrade gives its listener slot back and holds one of these instead ([center fleet](center-fleet.md#node-channel))                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                        |
| `ARCFORGES_CENTER_KEY_<NAME>`            | none     | The command-signing keys (AF-CTR-05 E1a, [center fleet](center-fleet.md#node-channel)): each the standard base64 of a PKCS#8 ECDSA P-256 key, the binding its `fleet.signing_key` row names; at most eight; read once at start, unset from the process environment (not from `/proc/<pid>/environ`, which keeps the start environment) and never logged; the relay surface needs one that matches a valid row, or the center does not start                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                          |
| `ARCFORGES_CENTER_LOG_LEVEL`             | `info`   | `debug`, `info`, `warn` or `error`                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                   |
| `ARCFORGES_CENTER_METRICS_LOG_INTERVAL`  | `1m`     | The periodic metrics log line; `0` disables it, otherwise 10 s to 1 h                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                |
| `ARCFORGES_CENTER_PLAN_CONFIGURATION`    | none     | Official-hosted only: empty (production until H-07: no catalogue, every gated key unavailable) or `development-fixtures` (the acceptance environment: an embedded catalogue of illustrative prices, never approved ones); any other value refuses to start, and no other source of a catalogue exists (DC-12); never `development-fixtures` in production (`tests/worker/proof-deploy.test.ts`) ([center entitlement](center-entitlement.md#the-catalogue))                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                          |
| `ARCFORGES_CENTER_DISABLED_FEATURES`     | none     | Self-hosted only: gated keys the operator disables, exact keys comma-separated (`operator_limit`); an unknown, repeated or empty key refuses to start; refused in official-hosted mode, and the Worker never passes it (PLT-18, `tests/worker/container-classes.test.ts`)                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                            |
| `ARCFORGES_NEON_HELLO`                   | disabled | `enabled` reads the Hello greeting from PostgreSQL: through the runtime role when `ARCFORGES_CENTER_DATABASE_URL` is set, otherwise through `NEON_DATABASE_URL`                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                      |
| `NEON_DATABASE_URL`                      | none     | With the Neon Hello and no store: a complete pooled Neon URL with `sslmode` and `channel_binding=require`; pool of two, exec query mode; `application_name` `arcforges-center` (the Go Hello sent `arcforges-go-hello`)                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                              |
| `ARCFORGES_CENTER_DATABASE_URL`          | none     | The runtime role's pooled URL of the store (a login role of the runtime group; [PostgreSQL store](postgres-store.md)); verified TLS with channel binding, except a loopback host of a self-hosted center                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                             |
| `ARCFORGES_CENTER_DATABASE_MAX_CONNS`    | `4`      | Pool size of the runtime database, 1 to 32                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                           |
| `ARCFORGES_CENTER_SURFACES`              | per mode | The enabled surfaces: exact names (`identity`, `pages`, `operations`, `fleet`, `mobile`, `relay`, `nodes`), comma-separated, or `none`; `pages` needs `identity`; `operations` needs both and exists only in official-hosted mode; `fleet` (node enrollment, [center fleet](center-fleet.md)) needs both; `mobile` (the mobile app's native authorization, [center mobile](center-mobile.md)) needs both and a public base URL that is a MobileNativeAuth issuer; `relay` (the node channel, [center fleet](center-fleet.md#node-channel)) needs `identity`, `fleet` and a command key (`ARCFORGES_CENTER_KEY_<NAME>`); `nodes` (FleetService's node registry, [center fleet](center-fleet.md#node-registry)) needs `identity`, `fleet` and `relay`; official-hosted enables none by default, self-hosted `identity`, `pages`, `fleet`, `mobile`, `relay` and `nodes` (without `mobile` for a base URL that is no issuer, without `relay` and `nodes` when no command key is configured) ([surface switch](center-identity.md#surface-switch)); a surface needs the runtime database |
| `ARCFORGES_CENTER_CLIENT_IP_HEADER`      | none     | Empty or `X-Arcforges-Client-Ip`; required in official-hosted mode while a surface is enabled (the Worker always passes it); self-hosted only with trusted proxies                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                   |
| `ARCFORGES_CENTER_TRUSTED_PROXIES`       | none     | Self-hosted only: CIDR prefixes, comma-separated, whose client-address header is trusted                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                             |
| `ARCFORGES_CENTER_BOOTSTRAP_SHA256`      | none     | With `..._EXPIRES_AT`: the SHA-256 (64 lowercase hex characters) of the exact owner bootstrap token text, prefix included (`printf %s "$TOKEN" \| sha256sum`); never the token itself                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                |
| `ARCFORGES_CENTER_BOOTSTRAP_EXPIRES_AT`  | none     | RFC 3339 UTC instant at most seven days ahead; a past one still starts the center (the bootstrap is then refused as expired, and the start-up log warns that both variables can be removed)                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                          |
| `ARCFORGES_CENTER_IDENTITY_POLICY`       | defaults | A bounded JSON override of the identity lifetimes and limits ([identity policy](center-identity.md#identity-policy)); the hosted Worker passes it only where `wrangler.json` sets it (the acceptance environment's anonymous-flow ceiling)                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                           |
| `ARCFORGES_CENTER_ANDROID_APP`           | `[]`     | The Android app identity of `/.well-known/assetlinks.json` ([center mobile](center-mobile.md#asset-links)): a JSON array of at most 4 objects of exactly `packageName`, `sha256CertFingerprints` (1 to 4 upper-case colon-separated SHA-256 fingerprints) and optionally `testOnly: true`; a malformed value refuses start; production leaves it unset, proof sets a labelled non-shipping test statement                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                            |
| `ARCFORGES_CENTER_MOBILE_DEBUG_REDIRECT` | none     | Self-hosted only (its presence refuses an official-hosted start): the debug app's private-use scheme, a lower-case reverse-DNS name with at least one dot; the debug client `arcforges.android.local` is admitted with exactly `<scheme>:/callback` while it is set ([center mobile](center-mobile.md#the-debug-client))                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                             |

The `migrate` and `admin` commands read their own variables (`ARCFORGES_CENTER_MIGRATION_DATABASE_URL`, the migration role's
direct URL; `ARCFORGES_CENTER_DATABASE_NAME`; `ARCFORGES_CENTER_RUNTIME_ROLE`; `ARCFORGES_CENTER_RUNTIME_SECRET_FILE`;
`ARCFORGES_CENTER_RUNTIME_POOLED_HOST`; `ARCFORGES_CENTER_MIGRATION_LOCK_TIMEOUT`); `serve` never reads them
([PostgreSQL store](postgres-store.md)); `admin register-signing-key`, `retire-signing-key` and `revoke-device` are the fleet's
([center fleet](center-fleet.md#the-centers-signing-keys)). No URL of the official deployment is compiled
into a code path: `TestNoOfficialEndpointIsCompiledIn` fails if one appears, and health and every URL the center issues derive
from `ARCFORGES_CENTER_PUBLIC_BASE_URL`. The production deployment states its values in `wrangler.json`
(`ARCFORGES_CENTER_MODE=official-hosted`, `ARCFORGES_CENTER_PUBLIC_BASE_URL=https://arcforges.com/api`), which
`worker/foundation/cloud-container.ts` passes to the Container unchanged.

### Mail

Mail is disabled unless `ARCFORGES_CENTER_MAIL_PROVIDER` names a provider. A disabled center sends nothing and does not offer the
e-mail sign-in method. The live adapters (Postmark over HTTPS and an SMTP submission service over TLS, Amazon SES being the first
target; AF-CTR-03) are tested **MOCKED** in every ordinary run: against servers on the loopback interface. Four tests reach a real
endpoint only when an explicit local switch is set (the public Postmark test token, an unauthenticated SES handshake and the owner-run live
send in its Postmark form and in its SMTP form); see the [evidence](#mail-verification-and-the-opt-in-live-tests). No deployed environment configures a provider, and none can before the
owner has the provider accounts, a verified sender domain and the secrets ([deployment](deployment.md#mail)).

**No real account can be mailed.** Nothing in the center creates an e-mail identity: the only statements that insert an identity
row enroll passkeys, and no task yet owns the enrollment of an e-mail identity. The sign-in-code and step-up calls therefore never
reach the sender for a real account (an address with no account is answered alike and never sent to), and the browser channel
refuses e-mail unconditionally. A configured provider makes the center validate its configuration at start and, with the identity surface on, build the adapter;
nothing calls `Send` until an e-mail identity can exist, so the credential is not used and enabling a provider tests nothing about the
provider. The owner-run live send is the only test of the credential, and nothing in this repository proves that a code would reach a user.

| Variable                                | Default                           | Rule                                                                                                                                                                                |
| --------------------------------------- | --------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `ARCFORGES_CENTER_MAIL_PROVIDER`        | disabled                          | `disabled` (or unset), `postmark` or `smtp`, exactly                                                                                                                                |
| `ARCFORGES_CENTER_MAIL_FROM`            | none                              | Required with a provider: one plain address (no display name, list or IP literal), at most 254 bytes                                                                                |
| `ARCFORGES_CENTER_MAIL_FROM_NAME`       | none                              | Optional display name: at most 64 bytes of printable ASCII without `" \ < > ( ) [ ] , : ; @ .` or an encoded-word opener (`=?`); the composed `Name <address>` is at most 255 bytes |
| `ARCFORGES_CENTER_MAIL_TIMEOUT`         | `10s`                             | A Go duration from `2s` to `25s`: the bound of one send, connect to reply                                                                                                           |
| `ARCFORGES_CENTER_MAIL_POSTMARK_TOKEN`  | none                              | `postmark`: required, 1 to 128 bytes of visible ASCII (a secret); Postmark's public test token is refused, because it delivers nothing                                              |
| `ARCFORGES_CENTER_MAIL_POSTMARK_STREAM` | `outbound`                        | `postmark`: the message stream, 1 to 40 bytes of `a-z`, `0-9` and hyphen                                                                                                            |
| `ARCFORGES_CENTER_MAIL_SMTP_HOST`       | none                              | `smtp`: required, a DNS name of at least two labels, at most 252 bytes; an IP address is refused, because the certificate is checked against the name                               |
| `ARCFORGES_CENTER_MAIL_SMTP_PORT`       | `587` (`starttls`), `465` (`tls`) | `smtp`: 1 to 65535                                                                                                                                                                  |
| `ARCFORGES_CENTER_MAIL_SMTP_MODE`       | `starttls`                        | `smtp`: `starttls` or `tls` (TLS from the first byte). There is no plain-text mode, not even for a relay on the loopback interface                                                  |
| `ARCFORGES_CENTER_MAIL_SMTP_USERNAME`   | none                              | `smtp`: required, 1 to 256 bytes without control characters (a secret)                                                                                                              |
| `ARCFORGES_CENTER_MAIL_SMTP_PASSWORD`   | none                              | `smtp`: required, 1 to 256 bytes without control characters (a secret)                                                                                                              |

The center refuses to start on: leading or trailing white space in any mail variable; a provider other than `disabled`, `postmark` or
`smtp`; any other mail variable set while the provider is unset or `disabled`; a variable of the other provider; a missing or invalid
value above. The refusal names the variable and never its value. The sender address and the SMTP host follow the one address rule of
the center (`config.ValidMailAddress`, which also validates a sign-in address: ASCII, a dot-atom local part of at most 64 bytes, a
domain of at least two labels whose last label contains a letter, at most 254 bytes in all). The three secrets are `config.Secret`
values; the start line names the provider only (`"mail": "disabled|postmark|smtp"`), and the value is never printed in any shape the
tests cover; where Go cannot call the methods (a Secret reached through an unexported field) it prints an address.

Two examples for a self-hosted center (placeholders; one Postmark Server or one IAM user per center):

```sh
# Postmark: the token belongs to one Server and does not restrict the From address (Postmark's sender signatures belong to the account).
ARCFORGES_CENTER_MAIL_PROVIDER=postmark \
ARCFORGES_CENTER_MAIL_FROM=<sender-address> \
ARCFORGES_CENTER_MAIL_POSTMARK_TOKEN=<postmark-server-token> \
./arcforges-center serve

# Amazon SES over SMTP: the SMTP credentials of an IAM user allowed ses:SendRawEmail; 587 and 465 are the defaults of the two modes.
ARCFORGES_CENTER_MAIL_PROVIDER=smtp \
ARCFORGES_CENTER_MAIL_FROM=<verified-sender-address> \
ARCFORGES_CENTER_MAIL_SMTP_HOST=<region-smtp-endpoint> \
ARCFORGES_CENTER_MAIL_SMTP_USERNAME=<smtp-username> \
ARCFORGES_CENTER_MAIL_SMTP_PASSWORD=<smtp-password> \
./arcforges-center serve
```

The SMTP adapter is written for a submission service that offers TLS and `AUTH PLAIN` after TLS. Only Amazon SES was probed, and only up
to AUTH; no message has been accepted by any SMTP service (NOT PROVEN). Certificate verification uses the system roots, so a relay with a
private CA needs that CA in the system trust store. Amazon SES also accepts connections on 2587 and 2465, which a network
that filters 587 and 465 often leaves open. Any other HTTP provider is out of scope.

### Mail delivery and what an operator sees

The sign-in code and the step-up code are the only messages. A message is sent after the reply has been built, never inside a
transaction and never in the reply's path: the reply of a request does not depend on the provider, on the account having the address,
or on a failure (the contract is the "Mail delivery" paragraph of [center identity](center-identity.md#sign-in)). Four sends talk to the provider at once and
sixty-four more wait inside the process; a send past that is refused as `unavailable` without reaching the provider. A send ends at the
provider timeout above (10 s by default, 25 s at most) and in any case at 30 s. There is no retry and no durable queue (the waiting sends are held in memory): a failed or lost
message is not repeated by the center, and a stop of the process loses the sends in flight (the drain gives them the part of the 5 s
stop bound that the listeners leave; what is still running then is abandoned and logged as
`deliveries still in flight were abandoned at the shutdown bound`). Under a slow provider the guard loses more than its 68 places
suggest: when a send takes L, about 4 x floor(30 s / L) sends are delivered inside the 30 s (about 40 at 3 s, about 12 at 9.5 s), so the
68 hold only while the provider answers in under about 1.76 s.

`arcforges_center_identity_events_total{event="email_send",outcome=…}` counts every delivery by one closed outcome, and every outcome
but `sent` is also logged as one WARN line (`an e-mail code could not be delivered` or `a step-up code could not be delivered`) with the
field `outcome` and nothing else: no address, no code, no provider text and no provider code. The counters reset at every restart and
reach the operator in the periodic `metrics` log line.

| Outcome        | Meaning                                                                                                                                                                                                               |
| -------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `sent`         | The provider accepted the message. That is not delivery to an inbox                                                                                                                                                   |
| `rejected`     | The provider refused this message or the message was invalid; sending it again unchanged will not help                                                                                                                |
| `unavailable`  | A network, timeout, capacity or provider fault, a refusal before any credential was offered, or the center's own guard being full or stopping; a later send may succeed                                               |
| `unauthorized` | The provider refused the account, sender, stream, credential or its permission to send; an operator must act. It is a counter and a WARN line, not a page: AF-OPS-01 owns paging, and this change adds no alert       |
| `failed`       | Anything else: a sender other than the two adapters that failed without a typed reason or panicked (a panic inside the Postmark or SMTP adapter is recovered by the adapter and counted `unavailable`, stage `panic`) |

Amazon SES words an unverified From identity (and, in its sandbox, an unverified recipient) as `554 Message rejected`, which the center
counts as `rejected`: on a first send, `rejected` most likely means that identity is not verified, and `unauthorized` means the credential
or the IAM policy. That is the documented behaviour of SES; no credential was used to observe it. A failed delivery costs the flow one of
its three sends (the center never refunds one), so a provider outage can exhaust a flow in a minute; the user starts a new flow.

The Design meter `EMAILS_SENT` is counted by the identity e-mail adapter and belongs to AF-PLAT-01. The in-process counter above resets at
every restart and is not that meter; `deliver` (`center/internal/identity/deliver.go`) is the one place such a meter hooks in.

### Mail verification and the opt-in live tests

What is proved, and how:

| Claim                                                                                                                                                                                                                                                                                                                                                                                                                                                               | Evidence                                                                                                             | Label                            |
| ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------- | -------------------------------- |
| Both adapters speak the documented protocol to a double: classification of every answer, certificate and name verification, no STARTTLS downgrade, no credential before TLS, byte and time bounds, no redirect and no environment proxy                                                                                                                                                                                                                             | `center/internal/mail` tests, the doubles of `center/internal/mail/mailtest` (importable from `_test.go` files only) | MOCKED (loopback servers)        |
| The configuration rules, the composition, the delivery counting, panic recovery and drain                                                                                                                                                                                                                                                                                                                                                                           | `center/internal/config`, `server` and `identity` tests                                                              | MOCKED                           |
| The sign-in, resend and step-up loops through each adapter; an unknown address makes no request; each failure class leaves the reply unchanged and is counted; no refund; the reply never waits for the provider                                                                                                                                                                                                                                                    | `center/internal/identityapi` tests on a real PostgreSQL (the Linux leg)                                             | MOCKED provider, real PostgreSQL |
| The Worker hands the center the mail variables of the named provider only                                                                                                                                                                                                                                                                                                                                                                                           | `tests/worker/container-classes.test.ts`, `center-config.test.ts`                                                    | MOCKED                           |
| The Postmark API contract with Postmark's public test token: the draft request is accepted and a wrong token is `unauthorized`; nothing is delivered, and the sender, the stream and the account state are not exercised                                                                                                                                                                                                                                            | the first probe below                                                                                                | REAL when run (skips otherwise)  |
| An Amazon SES SMTP endpoint offers TLS 1.2 or later with a verified chain and `AUTH PLAIN`, up to but excluding AUTH                                                                                                                                                                                                                                                                                                                                                | the second probe below                                                                                               | REAL when run (skips otherwise)  |
| A real message is accepted by a real provider through the real adapter                                                                                                                                                                                                                                                                                                                                                                                              | the owner-run live send below                                                                                        | REAL when the owner runs it      |
| A message reaches a real inbox; the sender domain passes DKIM, SPF and DMARC; the Postmark approval state and the SES sandbox state; bounces and suppression; the isolation of a production sender from a leaked acceptance Postmark token (Postmark documents none inside one account); real latency and failure behaviour; whether the Cloudflare Container can reach SMTP ports (the documentation is silent; 443 for Postmark is the lower-risk first provider) | not provable by this change                                                                                          | NOT PROVEN (owner step)          |
| What SES does inside DATA (for example about line endings): the double rejects a bare CR or LF, which is a model of strictness, not known SES behaviour                                                                                                                                                                                                                                                                                                             | none                                                                                                                 | NOT PROVEN                       |
| Delivery of a sign-in code to a user                                                                                                                                                                                                                                                                                                                                                                                                                                | none: no e-mail identity can exist                                                                                   | NOT PROVEN                       |

Every test of the package `mail` skips its real-service form unless an explicit local switch is set, so no verification leg and no ordinary
`go test` contacts a provider. From the `center` directory:

```sh
# Postmark's public test token against the real API (nothing is delivered).
ARCFORGES_TEST_POSTMARK_LIVE=1 go test -count=1 -run '^TestLivePostmarkContractWithThePublicTestToken$' ./internal/mail/

# An SES endpoint's handshake up to AUTH (no credential exists in the process); 465 and 2465 select TLS from the first byte.
ARCFORGES_TEST_SES_PROBE_HOST=<region-smtp-endpoint> ARCFORGES_TEST_SES_PROBE_PORT=2587 \
  go test -count=1 -run '^TestLiveSESHandshakeStopsBeforeAUTH$' ./internal/mail/
```

The owner-run live send **sends one real message** through the real adapter. It needs three things at once, so that a shell that merely
exported the first variable sends nothing: `ARCFORGES_TEST_MAIL_LIVE_SEND=1`, `ARCFORGES_TEST_MAIL_LIVE_SEND_CONFIRM=send-one-real-message`
and an explicit `-run`. The credentials, the sender and the recipient come from the environment only and are never printed; the test
skips, naming the missing variables, when one is not set. Use an address of your own as the recipient: the message has the fixed subject
`ArcForges live send test`.

```sh
# Postmark (ARCFORGES_TEST_POSTMARK_STREAM is optional and defaults to outbound)
ARCFORGES_TEST_MAIL_LIVE_SEND=1 ARCFORGES_TEST_MAIL_LIVE_SEND_CONFIRM=send-one-real-message \
ARCFORGES_TEST_POSTMARK_TOKEN=<postmark-server-token> ARCFORGES_TEST_MAIL_FROM=<sender-address> \
ARCFORGES_TEST_MAIL_RECIPIENT=<your-own-address> \
  go test -count=1 -run '^TestLiveSendThroughPostmark$' ./internal/mail/

# SMTP (the port selects the mode: 465 and 2465 are TLS from the first byte, every other port is STARTTLS)
ARCFORGES_TEST_MAIL_LIVE_SEND=1 ARCFORGES_TEST_MAIL_LIVE_SEND_CONFIRM=send-one-real-message \
ARCFORGES_TEST_SMTP_HOST=<region-smtp-endpoint> ARCFORGES_TEST_SMTP_PORT=587 \
ARCFORGES_TEST_SMTP_USERNAME=<smtp-username> ARCFORGES_TEST_SMTP_PASSWORD=<smtp-password> \
ARCFORGES_TEST_MAIL_FROM=<verified-sender-address> ARCFORGES_TEST_MAIL_RECIPIENT=<your-own-address> \
  go test -count=1 -run '^TestLiveSendThroughSMTP$' ./internal/mail/
```

The names are exactly: `ARCFORGES_TEST_POSTMARK_LIVE`, `ARCFORGES_TEST_SES_PROBE_HOST`, `ARCFORGES_TEST_SES_PROBE_PORT`,
`ARCFORGES_TEST_MAIL_LIVE_SEND`, `ARCFORGES_TEST_MAIL_LIVE_SEND_CONFIRM`, `ARCFORGES_TEST_POSTMARK_TOKEN`,
`ARCFORGES_TEST_POSTMARK_STREAM`, `ARCFORGES_TEST_SMTP_HOST`, `ARCFORGES_TEST_SMTP_PORT`, `ARCFORGES_TEST_SMTP_USERNAME`,
`ARCFORGES_TEST_SMTP_PASSWORD`, `ARCFORGES_TEST_MAIL_FROM` and `ARCFORGES_TEST_MAIL_RECIPIENT`. Two more, `ARCFORGES_TEST_MAIL_PROXY_CHILD` and
`ARCFORGES_TEST_MAIL_PROXY_STANDIN`, are set by a test for its own child process and are not for operators. A successful live send proves that
a provider accepted one message from the adapter; it does not prove delivery to an inbox, and it does not prove the sign-in path, which
cannot reach a real account.

## Center mode and feature availability

The mode is explicit configuration (AD-0021 §13a); there is no default. `internal/feature` answers feature availability behind the
`feature.Gate` interface, for the six gated keys (`center.nodes`, `center.execute`, `remote.view`, `remote.control`, `center.mcp`,
`push`). The reason of every answer is a closed vocabulary, never request text:

| Mode and state                                         | Gated features                                                                                            | Reason                                                                                          |
| ------------------------------------------------------ | --------------------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------- |
| `official-hosted`, no plan configuration (production)  | unavailable                                                                                               | `plan_configuration_missing`                                                                    |
| `official-hosted`, a catalogue that does not validate  | unavailable                                                                                               | `plan_configuration_invalid` (the start logs which rule failed)                                 |
| `official-hosted`, a valid catalogue                   | decided by the account's entitlement snapshot (the resolver, [center entitlement](center-entitlement.md)) | `entitled`, `no_entitlement`, `payment_grace`, `subscription_expired`, `account_suspended`, ... |
| `official-hosted`, the entitlement store cannot answer | unavailable, as an unavailable store and not as a missing entitlement                                     | `entitlement_unavailable`                                                                       |
| `self-hosted`                                          | available: the built-in default, minus the operator's limits                                              | `self_hosted_default`; `operator_limit` for a key in `ARCFORGES_CENTER_DISABLED_FEATURES`       |
| `self-hosted`, `push`                                  | unavailable until a push sender is configured (DC-22; none exists before AF-CLD-06)                       | `push_sender_not_configured`                                                                    |
| anything else                                          | the center does not start                                                                                 | —                                                                                               |

An unknown key is never available (`unknown_feature`). Hello, health, readiness and metrics are not gated features, and neither
is any essential operation (sign-in, account, billing, security and recovery): a row of the operation table without a `Feature` is
never gated. Availability is one more check after authentication, ownership, authorization, AGENT/HUMAN separation, resource
controls and audit, in that order and last ([the gate](center-entitlement.md#the-gate)); it never replaces them.

### Routed task control

The node channel and routed task operations delivered by AF-CTR-05, and later MCP and push operations when implemented, carry
these keys. AF-CTR-04's node enrollment is essential and carries none. The table is `feature.OperationKeys`, and the operation table of `internal/access` is linked to it in code (AF-CTR-05 part E0): a row
that carries a `Feature` names its `Group`, and `access.CheckRow` refuses the row, and with it the composition, unless its key is the
key this table names for that group; a row without a `Feature` names no group (`TestEveryFeatureRowCarriesTheKeyOfItsGroup`, with a
table-driven negative over every group and key; the first served row was the node channel's, `fleet.nodeChannel`, AF-CTR-05 E1a;
E2b added the routed task rows). `TestTheCenterDocumentPrintsTheRoutedTaskControlTable`
fails when this table and the code differ:

| Key              | Group               | Gates                                               |
| ---------------- | ------------------- | --------------------------------------------------- |
| `remote.control` | `control`           | control of existing tasks (cancel, retry, priority) |
| `center.execute` | `submission`        | submission, and file and workspace operations       |
| `remote.view`    | `status_and_output` | status and output                                   |
| `center.nodes`   | `node_connection`   | node connection                                     |
| `center.mcp`     | `mcp`               | MCP                                                 |
| `push`           | `push`              | push                                                |

Resource limits are enforced through the resource-control stage of `Authorize` by the per-account controls of `internal/quota`
(AF-CTR-05 part E0), which the composition registers with `access.WithControls`; a gated row that no control covers stops the
composition (`access.CheckControls`). The entitlement layer decides whether a feature is available, not how much of it. Every number
of the controls is a policy key whose default is an owner placeholder (H-07, illustrative), never a plan limit, and no refusal of
them says `plan_limit_reached`:

| Control                        | Covers                                       | Policy keys (default)                                                      | Refusal                                              |
| ------------------------------ | -------------------------------------------- | -------------------------------------------------------------------------- | ---------------------------------------------------- |
| `routed_calls_per_account`     | the gated rows of the three routed groups    | `routedCallsAccountLimit` / `routedCallsAccountWindow` (3600 per hour)     | `RESOURCE/rate_limited`, `retry_at` the window's end |
| `routed_in_flight_per_account` | the gated rows of the three routed groups    | `routedInFlightPerAccount` (16 at once, per center process)                | `RESOURCE/rate_limited`, `retry_at` one second later |
| `channel_upgrades_per_account` | the gated node channel row (node connection) | `channelUpgradeAccount` (600 per hour), `channelUpgradeNode` (60 per hour) | `RESOURCE/rate_limited`, `retry_at` the window's end |

There is no connected-node cap (AF-CTR-05 Q21): the enrollment cap (`maxNodesPerAccount`) governs how many nodes an account has.
The node channel row (`fleet.nodeChannel`, E1a) and the six routed task rows (E2b) are served gated rows.
`channel_upgrades_per_account` stands in front of the channel, and both routed controls stand in front of the routed groups. A
composition whose controls leave a gated group uncovered refuses to start (`TestAGatedRowWithoutAControlFailsComposition`, E0 review N-9).
The MCP and push rows (AF-CTR-07, AF-CLD-06) bring their own controls with them.

## Self-hosted mode

```sh
cd center
go build -trimpath -o arcforges-center ./cmd/arcforges-center
ARCFORGES_CENTER_MODE=self-hosted \
ARCFORGES_CENTER_PUBLIC_BASE_URL=https://center.example.org \
ARCFORGES_CENTER_HTTP_ADDRESS=0.0.0.0:8080 \
ARCFORGES_CENTER_ADMIN_ADDRESS=127.0.0.1:9090 \
./arcforges-center serve
```

The same routes, pipeline and health document are served without the Worker. TLS is terminated by the operator's proxy;
`http` base URLs are accepted only for a loopback host. `python eng/center.py check` starts the built executable this way on an
ephemeral loopback port on both verification hosts, checks health and an `UNIMPLEMENTED` refusal, refuses a start without a mode,
and (on Linux) checks the graceful shutdown on `SIGTERM`.

## Ingress compatibility

The pipeline ports the host-side admission of the C# `IngressPipeline` (`src/ArcForges.Cloud/Ingress`) for the methods the
center serves, in the same order:

1. **Canonical target.** The raw request target must equal the decoded path: no percent-encoding, dot or empty segment, trailing
   slash, backslash or absolute-form target; otherwise plain `404`.
2. **Plain routes** (`/healthz`) go to their handler. A path shaped like `/package.Service/Method` is admitted below; any other
   path is plain `404`.
3. **Method.** Only `POST` (else plain `405`). A method without a registered policy is the trailers-only `UNIMPLEMENTED` refusal.
4. **Media.** Binary gRPC-Web (`application/grpc-web`, `application/grpc-web+proto`), as the C# host admitted, and binary gRPC
   (`application/grpc`, `application/grpc+proto`) for direct clients of a self-hosted center and the gRPC listener; no
   `content-encoding`, and `grpc-encoding` absent or `identity`. Anything else (JSON or text codecs, the Connect protocol) is plain
   `415`. Admitting native gRPC is the one widening against the C# host, which the Worker never reaches (it forwards gRPC-Web only).
5. **Credentials** of a `session` method: a bearer and a session cookie together are `UNAUTHENTICATED`; a bearer must be exactly
   one `Bearer` value of 16 to 4096 token characters and validate as a native bearer; a cookie (`__Host-af_session`, exactly once)
   needs exactly one `Origin` equal to the allowed origin (else `PERMISSION_DENIED`), a valid session and that session's
   `X-AF-CSRF` token (else `PERMISSION_DENIED`). A store that cannot be reached is `UNAVAILABLE dependency.unavailable`. A known
   bearer whose session, device or installation was revoked is `UNAUTHENTICATED auth.credential_revoked`, one whose access token
   expired `UNAUTHENTICATED auth.token_expired` (AF-CTR-03 registers the verifiers with the identity surface; without it every
   session method is `UNAUTHENTICATED`).
   A method of a switchable surface is first checked against the surface switch: a disabled surface is answered with the domain
   refusal `STATE/not_activated` before any credential, body or store is read, and an enabled one needs the client's address in
   official-hosted mode ([surface switch](center-identity.md#surface-switch)).
6. **Body bound.** A declared length over the method's bound is `RESOURCE_EXHAUSTED validation.invalid_request` before any byte is
   read; the reader stops at the bound for the others.
7. **Envelope** of a method that reads `RequestMeta` (workspace-scoped, or declared to carry one): exactly one data frame of the
   declared length, then the strict reader of `RequestMeta` (no repeated meta, workspace, generation or correlation id, `Id`
   values of exactly 16 nonzero bytes, no groups or truncation); anything else is `INVALID_ARGUMENT validation.invalid_request`.
   A workspace-scoped method then needs a workspace the caller owns (`PERMISSION_DENIED`) in the caller's recovery generation
   (`FAILED_PRECONDITION state.stale_generation`).
8. **Correlation.** One identity per call: the validated envelope value, else the trace id of the Worker's `traceparent` (strict
   W3C version 00, lowercase, nonzero ids, exactly one header), else a new UUID. A `traceparent` of another trace is not a parent.
   The identity is bound after every decision above and read by none of them; handlers return it in `ResponseMeta` (tag 4) and
   `ArcError` (tag 6).
9. Admitted replies carry `cache-control: no-store` and `x-content-type-options: nosniff`.

`center/internal/ingress` has a test for every rule, and the envelope reader and the `traceparent` parser are fuzz targets.

## ArcError and gRPC status

The design has no table from an `ArcError` category to a gRPC code, and neither the C# Cloud host nor DesktopPlatform's
LocalRpc keeps one: LocalRpc and the C# proof methods return a domain refusal as gRPC `OK` with the `ArcError` in the reply
message. The C# `IngressPipeline` produces a closed set of transport refusals, each a fixed pair of status and registry code. The
center ports both exactly (`center/internal/ingress/errors.go`, `TestTheRefusalTableIsTheHostTable`):

| Refusal (grpc-message)                | gRPC status             | ArcError category   | When                                                                         |
| ------------------------------------- | ----------------------- | ------------------- | ---------------------------------------------------------------------------- |
| `unimplemented`                       | 12 `UNIMPLEMENTED`      | — (not an ArcError) | a method-shaped path without a registered policy                             |
| `auth.unauthenticated`                | 16 `UNAUTHENTICATED`    | `AUTHENTICATION`    | missing, malformed, unknown or conflicting credential                        |
| `perm.resource_denied`                | 7 `PERMISSION_DENIED`   | `AUTHORIZATION`     | wrong Origin or CSRF token, or a workspace the caller does not own           |
| `validation.invalid_request`          | 3 `INVALID_ARGUMENT`    | `VALIDATION`        | malformed frame or envelope, including a malformed correlation id            |
| `validation.invalid_request`          | 8 `RESOURCE_EXHAUSTED`  | `VALIDATION`        | request body over the method's bound                                         |
| `state.stale_generation`              | 9 `FAILED_PRECONDITION` | `STATE`             | envelope recovery generation differs from the caller's session               |
| `dependency.unavailable`              | 14 `UNAVAILABLE`        | `EXECUTION`         | a credential store could not be reached                                      |
| `auth.token_expired`                  | 16 `UNAUTHENTICATED`    | `AUTHENTICATION`    | a known bearer whose access token expired (the client refreshes; AF-CTR-03)  |
| `auth.credential_revoked`             | 16 `UNAUTHENTICATED`    | `AUTHENTICATION`    | a known bearer whose session, device or installation was revoked (AF-CTR-03) |
| any other `ArcError` (domain refusal) | 0 `OK`                  | its own category    | after admission: the `ArcError` in the reply, with the call's correlation id |

An unexpected failure of the domain code is `INTERNAL/internal` with retry `NEVER` and effect `UNKNOWN` (`arc.Internal()`): the Contracts
rule `arcError` rejects `UNKNOWN` with `AFTER_TIME`, the failure may have followed the call's effect, and the advice therefore is not to
repeat the call as it was; a client that knows the command's identity may send the same command again, which the command receipt makes
safe. `RetryAdvice.reconciliation_operation` is set exactly with a `RECONCILE` advice (`arc.Refusal.Reconcile`); no center refusal uses it
yet. Details: `docs/center-identity.md`, "Refusals".

A transport refusal is trailers-only: to binary gRPC-Web it is HTTP 200 with one trailer frame, byte for byte the C# host's
(`grpc-status: N\r\ngrpc-message: <code>\r\n`, the message percent-encoded as .NET's `Uri.EscapeDataString`); to native gRPC it
is the trailers-only `HEADERS` of gRPC over HTTP/2. It has no reply message and therefore no correlation id. The Hello keeps its
own statuses: `INVALID_ARGUMENT` ("Name must not be empty."), `RESOURCE_EXHAUSTED` ("Name exceeds 256 UTF-16 code units."),
`UNAVAILABLE` ("Hello database unavailable."), `DEADLINE_EXCEEDED` and `CANCELED`. The Worker produces its own edge statuses
(`CANCELED`, `INVALID_ARGUMENT`, `DEADLINE_EXCEEDED`, `PERMISSION_DENIED`, `UNAVAILABLE`, `UNAUTHENTICATED`;
[cloud-ingress](cloud-ingress.md)). The Design records this mapping in a companion change of `contracts/errors.md`.

Signatures and request digests always cover the bytes as transmitted, never a re-encoding (AD-0021 §10): the Go and C# protobuf
encoders order `oneof` fields differently, so a verifier must never re-encode a decoded message. A command receipt's digest leaves
out only `RequestMeta.correlation_id`, which is per attempt, and copies every other byte as transmitted
([center identity](center-identity.md#command-receipts)).

## Worker table authority

The Worker's production method table, its health route and their transport budgets (`helloPath`, `healthPath`, `maxBodyBytes`,
`coldStartBudgetMs`, `streamLifetimeMs`, `healthRoute`, `productionRoutes`), and the switchable surfaces with their method rows and
their generated replies (`surfaceNames`, `surfaceRoutes`, `notActivatedReplies`, `rateLimitedReply`, `clientIpHeader`;
AF-CTR-03), and the page routes with their security headers, statuses and bounds (`pageRoutes`, `pageSecurityHeaders`,
`pageStatuses`, `pageCookieName`; A2), are generated from the center's registrations
(`center/internal/routes`) into `worker/tables/center-tables.generated.ts`, together with the `ApiRoute` type. The center's
ingress registry is built from the same registrations, so a method cannot be served without its Worker row or the reverse; the
generator refuses a method without a budget, a budget without a method, a second plain route, a changed Hello bound, and a
surface method outside the `hello` instance or without a `RequestMeta`. The generated refusals carry the call's correlation id (E4-1): the Worker writes a fresh one into a 16-byte slot of each
generated reply (`replyCorrelationBytes` and the `...Offsets` beside the replies, from the marker the generator renders them with),
so a refusal the Worker makes is joined to its call. The surface block comes first and the production block
(`helloPath` to `productionRoutes`, always on) stays last, byte for byte what the C# generator writes for the rollback host;
`maxBodyBytes` therefore stays the Hello bound (4 KiB), the bound of the Worker's disposal of an unread upload (a larger one is
cancelled), while every row carries its own `maxRequestBytes` (the identity ceremonies' 16 KiB). `python eng/center.py generate`
writes the file; `TestCommittedWorkerTablesAreCurrent` (part of `go test`, both legs)
and `go run ./cmd/center-gen worker-tables -check` fail on any drift, the Go counterpart of `npm run check:generated`.

The proof environment stays C# until AF-CTR-09: its methods, the edge guard, the correlation and storage guards, the readiness
vocabulary and the wire limits are still generated from C# into `worker/tables/cloud-tables.generated.ts`, which imports the
`ApiRoute` type from the center's module. The C# `HelloModule` registration stays for the rollback host, and
`GeneratedTablesTests.TheGoCenterProductionTableEqualsTheCSharpRegistrations` checks that the Go module carries byte for byte
the production rows the C# generator wrote before the split, so switching the runtime changes no Worker behaviour. Both
generated modules are excluded from the WorkerAdapter literal check, which keeps refusing any business literal in the
hand-written Worker sources.

## Health, readiness, logs and metrics

`GET /healthz` returns the health document; it never touches a database:

```json
{
  "service": "arcforges-cloud",
  "revision": "<commit>[-dirty]",
  "nativeAot": false,
  "runtime": "go",
  "helloBackend": "stateless | postgresql-runtime | neon-postgresql",
  "artifact": { "id": "Cloud", "version": "0.1.0-ci.<run>.<attempt>" },
  "build": {
    "sourceCommit": "…",
    "dirty": false,
    "kind": "ci",
    "buildId": "…",
    "runId": "…",
    "runAttempt": 1,
    "pipelineRun": "…",
    "sourceDateEpoch": 0
  },
  "center": {
    "binary": "arcforges-center",
    "mode": "official-hosted",
    "publicBaseUrl": "https://…",
    "surfaces": "none | the enabled surfaces in registration order (identity, pages, operations, fleet, mobile, relay, nodes), comma-separated",
    "signingKid": "the kid of the command key routed calls are signed with now (only with the relay surface and a valid held key)"
  }
}
```

Go is compiled native code but not .NET Native AOT, so `nativeAot` is false. The build identity is set with `-ldflags -X` from
the same inputs as the C# executable's (`tooling/build-identity.ts`), and the release tooling compares `artifact` and `build`
with the candidate. `center.surfaces` states the surfaces the center serves, as `ARCFORGES_CENTER_SURFACES` names them (`none` when
it serves none), so a deployment can be compared with the surfaces its Worker forwards ([deployment](deployment.md#start-environment-after-a-deployment)).
`operations` (the operator grant's interim page) is listed only together with `identity` and `pages`, and only on the official hosted
center.
`center.signingKid` (AF-CTR-05 E1b, Plan CTR5-SIG-02) names the command key the center signs routed calls with at the moment of the
request, the newest valid key whose private half it holds; it is absent without the relay surface or when no held key is valid, and
the document never carries key material.
`arcforges-center version` prints the same document with `helloBackend` `not-probed` and no mode or surfaces.

Readiness is separate from health. `GET /readyz` on the admin listener answers `200` with `{"status":"ready","components":{…}}`
when every configured database answers a ping within two seconds (`helloDatabase`, `database`) and the store's schema carries
every migration of this build exactly (`databaseSchema`), and `503` with `unavailable` otherwise. `GET /metrics` on the same
listener exposes the Prometheus text format: `arcforges_center_requests_total{method,code}`,
`arcforges_center_request_duration_seconds{method}` (histogram), `arcforges_center_refusals_total{code,category}`,
`arcforges_center_fleet_events_total{event,outcome}` (closed pairs, [center fleet](center-fleet.md#metrics-audit-and-transactions)),
`arcforges_center_channel_events_total{event,outcome}` and the gauge `arcforges_center_channel_connected_nodes` (the node channel's closed
pairs and its accepted connections, [center fleet](center-fleet.md#node-channel)), the gauge `arcforges_center_definitions_superseded` (1
while the deploy's definitions fact names another version than this revision's, read at every scrape and at every tick of the periodic
`metrics` log line; AF-CTR-05 E0 review C-N2: such a revision neither recomputes nor writes an entitlement, which was visible only in its
start-up warning) and the
database pool and schema metrics of the [PostgreSQL store](postgres-store.md#observability-and-alert-conditions). Labels are closed values: a registered method path or `plain`,
`unregistered`, `not_found`; a gRPC code name or `http_<status>`; a registry code and an `ArcError` category. The admin
listener is not configured in the hosted Container, so production adds no route; there the metrics reach the operator as the
periodic `metrics` log line, which the Container's logs carry: its counters and both gauges (`definitions superseded`, evaluated on
the tick itself, and `channel connected_nodes`).

Logs are JSON lines (`log/slog`) with `service=arcforges-center`. A request line holds the method label, the outcome code, the
duration, the correlation id of an admitted call or of a domain reply the pipeline answered itself (a disabled surface's
`not_activated`, logged and counted as the OK reply it is) and the refusal code and category; it never holds a header value, a
credential, a request or response body, a command line, output or file content. A configuration error names the variable only.

## Hosted deployment

`worker/foundation/cloud-container.ts` selects `/app/arcforges-center` when `ARCFORGES_HELLO_RUNTIME=go` and passes the center
mode, base URL and plan configuration, and the runtime role's URL (the Worker secret `ARCFORGES_CENTER_DATABASE_URL` that the
deployment rotates; [PostgreSQL store](postgres-store.md#deployment)). The Hello's own Neon secret reaches only the C# host or a
Go center without a store (`tooling/neon-runtime.ts`). The mail variables reach a Go center only while
`ARCFORGES_CENTER_MAIL_PROVIDER` names a provider, and then only that provider's own (the closed lists of the Worker, compared with
`center/internal/config/mail.go` by a test); no deployed environment names one, so none is passed ([mail](#mail)). The Dockerfile builds the
center with the pinned Go archive (`center/toolchain.json`, SHA-256 checked), `go mod verify`, `CGO_ENABLED=0`, `-trimpath`,
`-buildvcs=false` and the identity `-ldflags`, beside the C# executable, which stays the image's default entrypoint. The
candidate inspects both ELF members and their legal files without running them (`tooling/release-provenance.ts`).

Structural cost bounds of the production deployment, enforced by configuration:

| Bound               | Value                                                                    | Where                                                                                                   |
| ------------------- | ------------------------------------------------------------------------ | ------------------------------------------------------------------------------------------------------- |
| Container instances | `max_instances: 1`, `instance_type: lite`                                | `wrangler.json` (checked by the candidate)                                                              |
| Idle stop           | `sleepAfter` 60 s                                                        | generated `containerSleepAfter`                                                                         |
| Worker CPU          | `cpu_ms: 50`                                                             | `wrangler.json`                                                                                         |
| Public rate limit   | 60 requests per 60 s per location and client (an IPv6 client by its /64) | `HELLO_RATE_LIMITER` in `wrangler.json`; the key is `edgeClientKey` (`worker/ingress/edge-limit.ts`)    |
| Center connections  | 64 per listener                                                          | `ARCFORGES_CENTER_MAX_CONNECTIONS` default                                                              |
| Node channels       | 256 upgraded connections, counted apart from the listener's 64           | `ARCFORGES_CENTER_MAX_NODE_CONNECTIONS` default (AF-CTR-05 E1a, PN-1)                                   |
| Hello database      | pool of 2, 5 s statement timeout, 15 s call                              | `internal/config`, `internal/hello`                                                                     |
| Runtime database    | pool of 4 (1 to 32); login roles limited to 16 connections each          | `ARCFORGES_CENTER_DATABASE_MAX_CONNS` default; [PostgreSQL store](postgres-store.md#connection-budgets) |

While a node is connected (AF-CTR-05 onward) the one instance stays running; that always-on worst case is one `lite` instance
per deployment, which AF-PLAT-01's budgets take as the bound.

**The always-on cost of the node channel** (AF-CTR-05 E1a; Plan CTR5-HUB-12, PN-2; owner item H-09, MOCKED and not waited for). Once the
relay surface is enabled, any one connected node keeps the Container awake (every heartbeat, 25 s apart, is activity), so `sleepAfter`
never stops it: the hosted cost becomes one `lite` Container running all the time, plus the Durable Object `hello`, which proxies every
node's WebSocket (`@cloudflare/containers` accepts both ends of the socket in the object) and does not hibernate, so Durable Object
duration is billed for as long as any socket is open, on top of the Container. Both are bounded by configuration: one instance
(`max_instances: 1`), one Durable Object instance for every center route (`hello`, pinned for the upgrade route by the generated
`upgradeRoutes`), and at most `ARCFORGES_CENTER_MAX_NODE_CONNECTIONS` sockets. The owner's ceiling for both is H-09; production stays
dark (no `relay` in `FLAGSHIP_SURFACES`) until AF-PROD-01. A Worker redeploy restarts the center (`followWorkerVersion`) and drops every
channel without a 4500; through the Durable Object that close reaches the node as 1000 (`@cloudflare/containers` rewrites an abnormal
close), so a node treats any close without a preceding `RelayClose` like 4500 and reconnects with its backoff (the node side is N1's).

## Verification

`python eng/center.py check` is the one entry point of both verification legs (`win-center`, `linux-center` in
`eng/verify_steps.py`) and of hosted CI for external PRs; [engineering controls](engineering-controls.md) lists every control,
its stage and its evidence. The published C# client's exchange is covered offline by the protocol tests of
`center/internal/server` (greeting, Unicode, NUL, empty and oversized names, statuses and trailers over gRPC and binary
gRPC-Web, and the probe's raw HTTP/1.1 exchange). Two local opt-in diagnostics (never CI, not gates) start the sealed candidate
image: `npm run test:container` runs `/app/arcforges-center` as the Container does (the mode and public base URL of
`wrangler.json`, a read-only filesystem, no capabilities, `no-new-privileges`, 256 MiB) and checks its build identity, the health
identity and `center` block, the published C# gRPC-Web probe, the published native gRPC Consumer and a clean stop on `SIGTERM`;
`npm run test:worker` runs the same executable behind the real Worker bundle.
