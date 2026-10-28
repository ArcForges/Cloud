# Deployed Neon Hello

> **Update (AF-CTR-02 part B).** This record describes the C# Hello's Neon check, which stays as the rollback host. The
> Go center now reads the Hello greeting through its least-privilege runtime role, whose pooled URL the deploy job rotates
> and uploads; `NEON_DATABASE_URL` reaches only the C# host or a center without a store, and `NEON_DATABASE_URL_DIRECT` is
> used by the deploy job's migration step. See [PostgreSQL store](postgres-store.md).

The user authorized two sequential deployment checks on 2026-10-27: first the existing C# Hello with
Neon, then a Go Hello with the same public contract. This increment implements only the C# check.
It is not the full Go migration, a D1 migration, or activation of flagship business surfaces.

When production sets `ARCFORGES_NEON_HELLO=enabled`, every valid SayHello call executes a
parameterized SELECT through Npgsql in a read-only PostgreSQL transaction, then rolls it back.
The existing reply and gRPC-Web route stay the same. A database failure returns UNAVAILABLE;
there is no successful local greeting fallback in enabled mode. Health reports the configured
`helloBackend` as `neon-postgresql`; this reports configuration, not database readiness.
A successful Hello on that deployed revision is the live database check.

## Runtime configuration

The existing GitHub `cloudflare` environment holds `NEON_DATABASE_URL`. Only the trusted main-push
deployment reads it. The deployment validates the presence of a pooled Neon URL, stages it outside
the artifact directories in a private temporary file, uploads it with the Worker deployment and
removes the file even on failure. PR builds and the image build receive no database credentials.
`NEON_DATABASE_URL_DIRECT` remains reserved for later migration work and is not sent to Hello.

The production Container forwards only the enable flag and pooled URL. Native PostgreSQL uses
TCP port 5432, which Cloudflare's HTTP outbound handlers do not proxy. Therefore this explicit
Hello mode enables Internet egress for that production Container. HTTP host allowlists do not
restrict other TCP ports, so this is not claimed as a network-level PostgreSQL-only allowlist.
The C# configuration accepts only Neon pooler endpoints on port 5432, verifies the TLS certificate
and hostname, requires channel binding, caps the connection pool at two and uses bounded calls.
Proof subclasses keep their closed egress policy and existing environment.

No tables, migrations, records or D1 data are changed. The currently provisioned owner credential
is used only for this bounded SELECT proof; a future business service needs its own runtime role
and privilege design before wider database access is enabled.

## Verification and recovery

Offline checks cover configuration refusal, encoded credentials, failure redaction, no fallback,
Worker runtime forwarding and temporary-secret cleanup. Required native-host checks retain the
full repository profile, including the final Native AOT image.

After the guarded main-push deploy, run the repository's published C# Hello protocol probe from
an authorized native host and check the deployed health revision and backend. This live check is
explicit local opt-in, never a hosted-CI database test. Record its result with the deployment ID.
Do not interpret a provider deployment success as runtime acceptance.

Revert through a normal reviewed main-push PR, or set the flag to `disabled` through that same path.
Disabled mode restores the original stateless Hello and closed Container egress. No data rollback
is needed because the probe performs no writes.

References:

- https://developers.cloudflare.com/containers/configuration/outbound-traffic/
- https://www.npgsql.org/doc/security.html
