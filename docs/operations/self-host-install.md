<!-- SPDX-License-Identifier: AGPL-3.0-only -->

# Install a self-hosted Center on Linux

This profile uses the pinned Go Center, a dedicated PostgreSQL 18 cluster,
systemd, and a stock Caddy v2 TLS proxy. It runs with operator-owned database,
TLS certificate, and signing credentials. Local ArcForges Node and CLI use
continue independently of this optional Center.

## Prepare the host

Use a supported Linux host with a stable clock. Reserve a DNS name and a TLS
certificate trusted by the browsers and Nodes that will connect. This profile
uses HTTPS on port 443. Set the same DNS name in both configuration files and
keep the public API base at `https://<your-host>/api`.

Use the verified Linux Center artifact for the repository revision you intend
to install. Check the artifact digest against its trusted build receipt before
copying it over. For a source build, install the Go toolchain recorded in
[`center/toolchain.json`](../../center/toolchain.json), fetch and verify its
locked inputs, and build the ordinary executable.

```sh
cd center
export GOTOOLCHAIN=local
go version
go mod download
go mod verify
CGO_ENABLED=0 go build -trimpath -mod=readonly -o /path/to/staging/arcforges-center ./cmd/arcforges-center
/path/to/staging/arcforges-center version
```

Run the remaining setup commands from a privileged Linux shell, with the Cloud
checkout or a copy of its `deploy/self-host` directory available. Set
`DEFINITION` and `CENTER_BUILD` to your actual paths. Install PostgreSQL and a
standard Caddy package with its systemd service before starting the Center.
Python 3 and OpenSSL are operator setup tools. Center itself runs as the Go
executable.

```sh
set -eu
umask 077
DEFINITION=/path/to/Cloud/deploy/self-host
CENTER_BUILD=/path/to/staging/arcforges-center
CENTER=/opt/arcforges-center/arcforges-center

useradd --system --user-group --no-create-home --shell /usr/sbin/nologin arcforges-center
install -d -m 0755 /opt/arcforges-center
install -d -m 0700 /etc/arcforges-center /var/lib/arcforges-center/operator
install -m 0755 "$CENTER_BUILD" "$CENTER"
install -m 0644 "$DEFINITION/arcforges-center.service" /etc/systemd/system/arcforges-center.service
install -m 0600 "$DEFINITION/center.env.example" /etc/arcforges-center/center.env
install -m 0600 "$DEFINITION/migration.env.example" /etc/arcforges-center/migration.env
```

Adjust `center.env` for your hostname. The sample retains explicit ceilings
on PostgreSQL connections, in-flight requests, and Node channels. The
optional `ARCFORGES_CENTER_DISABLED_FEATURES` turns off named Center
capabilities for this operator. A capability allowed by the Center still
requires account, enrollment, and Node-local authorization.

## Provision PostgreSQL and signing custody

Apply the supplied [PostgreSQL listener example](../../deploy/self-host/postgresql.conf.example)
and [host authentication example](../../deploy/self-host/pg_hba.conf.example)
to the dedicated cluster. Retain the package's local administrative connection
and verify the server is listening only on `127.0.0.1:5432`. In that cluster,
open the PostgreSQL administrator's local session and create the migration
login with a strong operator-managed password. The interactive password command
keeps the password out of the SQL history and command arguments.

```sh
sudo -u postgres psql -X --dbname=postgres
```

```sql
CREATE ROLE arcforges_owner LOGIN CREATEROLE CREATEDB;
\password arcforges_owner
\q
```

Edit `migration.env` to add the URI-encoded owner password to the connection
URL. Keep the URL's database set to `postgres` so database creation uses the
maintenance connection. `ARCFORGES_CENTER_DATABASE_NAME` identifies the actual
Center database. Give the migration file to the privileged operator only. The
daemon receives its generated PostgreSQL runtime login through `runtime.env`.
systemd reads the root-owned files at startup and runs Center as the separate
`arcforges-center` Unix account. [systemd execution settings](https://www.freedesktop.org/software/systemd/man/latest/systemd.exec.html)

Generate a command-signing key in a new private directory. Its private
PKCS#8 data is delivered only to the daemon as a base64 environment value.
Keep a separate protected copy under operator signing custody for recovery
and schedule a successor before the current key expires.

```sh
KEY_DIR=/var/lib/arcforges-center/operator/initial-command
mkdir -m 0700 "$KEY_DIR"
openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out "$KEY_DIR/command.pem"
openssl pkey -in "$KEY_DIR/command.pem" -pubout -out "$KEY_DIR/command-public.pem"
openssl pkcs8 -topk8 -nocrypt -in "$KEY_DIR/command.pem" -outform DER -out "$KEY_DIR/command.der"
binding=$(openssl base64 -A -in "$KEY_DIR/command.der")
printf 'ARCFORGES_CENTER_KEY_SELFHOST=%s\n' "$binding" > /etc/arcforges-center/signing.env
unset binding

(
  set -a
  . /etc/arcforges-center/migration.env
  set +a
  "$CENTER" admin ensure-database
  "$CENTER" migrate apply
  "$CENTER" admin register-signing-key --purpose command --kid selfhost-command-01 \
    --public-key-file "$KEY_DIR/command-public.pem" --secret-binding ARCFORGES_CENTER_KEY_SELFHOST \
    --not-before "$(date -u -d '-1 minute' +%Y-%m-%dT%H:%M:%SZ)" \
    --not-after "$(date -u -d '+180 days' +%Y-%m-%dT%H:%M:%SZ)"
  export ARCFORGES_CENTER_RUNTIME_SECRET_FILE="$KEY_DIR/runtime-01.json"
  "$CENTER" admin rotate-runtime-credential
)
python3 "$DEFINITION/operator-inputs.py" runtime-env "$KEY_DIR/runtime-01.json" /etc/arcforges-center/runtime.env
```

The rotation prints the slot and successful database privilege checks. Record
the slot privately and confirm it only after the daemon is ready. The
operator helper verifies the runtime login and local URI before it creates the
root-only environment file. It supports the exact IPv4 loopback profile
above. Any additional signing material, migration credentials, or backup
files belong in protected operator custody. Preserve the minimum required
copies under the operator's local retention policy.

## Start Center and its TLS proxy

Generate a one-use bootstrap token for the first owner. The daemon receives
the SHA-256 digest and expiration. The operator's separate token file is
needed in the initial registration form.

```sh
BOOTSTRAP_DIR=/var/lib/arcforges-center/operator/initial-bootstrap
python3 "$DEFINITION/operator-inputs.py" bootstrap "$BOOTSTRAP_DIR" --hours 2
install -m 0600 "$BOOTSTRAP_DIR/bootstrap.env" /etc/arcforges-center/bootstrap.env
systemctl daemon-reload
systemctl start arcforges-center.service
curl --fail --silent --show-error http://127.0.0.1:8082/readyz
```

After readiness succeeds confirm the exact reported slot, for example `a` on
a first system.

```sh
(
  set -a
  . /etc/arcforges-center/migration.env
  set +a
  "$CENTER" admin confirm-runtime-credential --slot a
)
systemctl enable arcforges-center.service
```

Install the supplied [Caddy site](../../deploy/self-host/Caddyfile) and
[systemd drop-in](../../deploy/self-host/caddy.service.d/arcforges-env.conf).
Use a dedicated Caddy instance for this configuration. The TLS chain must
match the site name, and the Caddy service account needs read access to its
private TLS key through the package's ownership or group settings.

```sh
install -d -m 0755 /etc/systemd/system/caddy.service.d /etc/arcforges/static-origin.d
install -m 0644 "$DEFINITION/Caddyfile" /etc/caddy/Caddyfile
install -m 0644 "$DEFINITION/caddy.service.d/arcforges-env.conf" /etc/systemd/system/caddy.service.d/arcforges-env.conf
install -m 0600 "$DEFINITION/caddy.env.example" /etc/arcforges-center/caddy.env
```

Edit `caddy.env` to supply the same hostname as `center.env` and the actual
TLS file paths. With the same environment, validate the site as the Caddy
user and start the managed service. Caddy's admin API is disabled. Validate
again and restart the service when selecting a new TLS key or site.

```sh
(
  set -a
  . /etc/arcforges-center/caddy.env
  set +a
  runuser -u caddy --preserve-environment -- caddy validate --config /etc/caddy/Caddyfile --adapter caddyfile
)
systemctl daemon-reload
systemctl restart caddy.service
systemctl enable caddy.service
```

The proxy strips `/api` once and forwards native gRPC to loopback port 8081.
Browser pages, gRPC-Web, and Node WebSocket upgrades use loopback port 8080.
The proxy supplies the client address from its actual peer. Center trusts
the header from connections on its configured IPv4 loopback. Use a
dedicated host or a trusted local network namespace so access to loopback
belongs to the operator's trust boundary. Port 8082 has private readiness
and metrics. Keep all three Center ports and PostgreSQL on loopback, and
avoid placing another proxy in front of this client address policy.
Static frontend releases use an optional exact route fragment on this same
origin. An empty fragment directory supports API and Go account pages only.
[Static origin operator procedure](static-origin.md), [Caddy reverse proxy documentation](https://caddyserver.com/docs/caddyfile/directives/reverse_proxy)

## Create the owner and enroll a Node

Visit `https://<your-host>/api/account/bootstrap` over the trusted TLS origin.
Use the token in the form and complete the browser's passkey registration.
Handle the token locally and keep it out of URLs, chat, and logs. After
success, verify sign-in at `/api/account/sign-in`, withdraw the bootstrap
input with `unlink /etc/arcforges-center/bootstrap.env`, and restart Center.
Keep the spent token and temporary copies only for as long as your operator
custody policy requires. Enroll additional passkeys and verify the operator's
recovery channel where configured.

From the user account that owns the installed ArcForges Node run these
commands with the actual hostname.

```sh
arcforges center set https://center.example.org/api
arcforges center connect https://center.example.org --mode self_hosted
arcforges center status
```

The setting retains the API prefix. The connection request selects the origin
and mode. Use the returned flow ID and compare the Node key fingerprint during
browser approval. Apply any required per-Node remote grant locally. For role
rotation, backup, restore, revocation, and outage procedures, see the
[self-hosted recovery runbook](self-host-recovery.md).
