<!-- SPDX-License-Identifier: AGPL-3.0-only -->

# Operate and recover a self-hosted Center

Use the installed configuration from the [Linux setup procedure](self-host-install.md).
Run these maintenance commands from the operator account in a private shell
with `umask 077`. The examples assume elevated access to the root-owned
configuration and a locally managed PostgreSQL 18 cluster. Preserve the
build revision, digest, and operator custody records with each procedure.

## Verify service readiness

Use the loopback admin listener from the Center host. A successful readiness
response confirms that this process has admitted its database. Check its
service log and bounded metrics when readiness fails. Preserve only the
necessary sanitized diagnostics. For interpretation, see the
[Center monitoring guide](monitoring.md).

```sh
systemctl status arcforges-center.service
curl --fail --silent --show-error http://127.0.0.1:8082/readyz
curl --fail --silent --show-error http://127.0.0.1:8082/metrics
```

If TLS fails while readiness is healthy, check the configured Caddy site
and certificate as the Caddy user. Verify the supported origin with a client
that trusts that chain. Confirm `/api/account/sign-in` is served and the
private admin paths are refused through the TLS origin. Check a real Node
enrollment and connected WebSocket state separately. A service restart
ends active sessions on the transport and clients may reconnect under
their existing authorization.

When the Center or network is unavailable, local Sandbox and Run commands
continue on the Node. Check an uncertain local mutation with
`arcforges operation inspect "$COMMAND_ID" --owner-epoch "$OWNER_EPOCH" --json`.
For a remote request with an uncertain result, preserve the original command
identity and inspect its receipt through the authorized operation read when
the service returns. Resubmitting as a new command can apply a second effect.

## Rotate the runtime database credential

Keep the current `runtime.env` and its recorded slot until the successor has
passed readiness. Use the recorded slot of the live daemon to select the
other PostgreSQL login. Here `a` is the known live slot. Retain the original
rotation receipt privately before continuing.

```sh
set -eu
umask 077
CENTER=/opt/arcforges-center/arcforges-center
DEFINITION=/path/to/Cloud/deploy/self-host
ROTATION=$(mktemp -d /var/lib/arcforges-center/operator/rotate-XXXXXXXX)
install -m 0600 /etc/arcforges-center/runtime.env "$ROTATION/previous.env"
(
  set -a
  . /etc/arcforges-center/migration.env
  set +a
  export ARCFORGES_CENTER_RUNTIME_SECRET_FILE="$ROTATION/next.json"
  "$CENTER" admin rotate-runtime-credential --live-slot a
) > "$ROTATION/rotation-receipt.json"
python3 "$DEFINITION/operator-inputs.py" runtime-env "$ROTATION/next.json" /etc/arcforges-center/runtime.env.next
mv -T /etc/arcforges-center/runtime.env.next /etc/arcforges-center/runtime.env
systemctl restart arcforges-center.service
curl --fail --silent --show-error http://127.0.0.1:8082/readyz
```

Check the receipt for the new slot and test a real authenticated request.
After both pass, load `migration.env` in a private operator command and
run `arcforges-center admin confirm-runtime-credential --slot b` with the
recorded new slot. If the new process fails before confirmation, reinstall
`previous.env` by staging it beside `runtime.env` and atomically renaming
it, restart, and check readiness again. A lost confirmation reply can be
reconciled by running the same confirmation for the same slot. Keep any
superseded secret in operator custody only as long as recovery requires.

Protect signing custody separately. Register an ES256 successor using a new
key ID and secret binding. The key registry requires the successor to
become valid at least seven days before, and outlive, the current key. Hold
both configured signing keys while the fleet discovers the successor.
Inspect registered public metadata with `admin inspect-signing-key --kid ID`.
Use the supported retirement procedure after verifying continuity with real
Node credentials. [Center Fleet signing key procedure](../center-fleet.md)

## Capture and retain a logical backup

Use the PostgreSQL 18 `pg_dump` and `pg_restore` executables in the
operator's trusted `PATH`. The Center validates the database's migration
history, restore admission, and ownership. It takes a consistent archive
and its metadata from one snapshot. Plan a maintenance window because the
capture waits for writers and can hold table locks.

Drain remote traffic and stop Center for a predictable maintenance window.
Capture into a new directory accessible only to the operator.

```sh
set -eu
umask 077
CENTER=/opt/arcforges-center/arcforges-center
BACKUP=$(mktemp -d "/var/lib/arcforges-center/operator/backup-$(date -u +%Y%m%dT%H%M%SZ)-XXXXXXXX")
systemctl stop arcforges-center.service
(
  set -a
  . /etc/arcforges-center/migration.env
  set +a
  "$CENTER" admin backup-logical --archive "$BACKUP/archive.dump" --metadata "$BACKUP/archive.metadata.json"
) > "$BACKUP/backup-receipt.json"
date -u +%Y-%m-%dT%H:%M:%SZ > "$BACKUP/captured-at.txt"
systemctl start arcforges-center.service
curl --fail --silent --show-error http://127.0.0.1:8082/readyz
```

On failure, preserve the diagnostics and any partial files as failed
evidence. Restore source service when it is safe to do so. Count a backup
only after the command succeeds. Keep the original receipt, completion
timestamp, archive, and metadata together in protected backup storage.
Trust their hashes from the separately retained original receipt when
restoring. A hash calculated from the only available copy can detect later
changes to that copy. Independent custody of the original receipt establishes
which bytes the capture admitted. The files contain private account and
operational data. Keep TLS and signing custody materials under their own
protected recovery procedures.

## Restore into a new database

Use the matching Center artifact and trusted archive and metadata. Prepare
a separate PostgreSQL 18 recovery cluster with loopback access and a fresh
migration owner. Configure a new private `restore.env` with the maintenance
database URL, a new explicitly named target database, and a fresh runtime
role stem. Create only the migration owner. The restore command creates
and isolates the target and refuses a database or runtime group/slot roles
that already exist. Leave the source cluster and archive intact.

Set `BACKUP` to the verified capture directory. Set `ARCHIVE_SHA256` and
`METADATA_SHA256` from the original independently retained receipt fields
`archiveSha256` and `metadataSha256`. Verify both before restoring an
archive copied out of their trusted custody.

```sh
set -eu
umask 077
CENTER=/opt/arcforges-center/arcforges-center
RESTORE=$(mktemp -d /var/lib/arcforges-center/operator/restore-XXXXXXXX)
(
  set -a
  . /etc/arcforges-center/restore.env
  set +a
  "$CENTER" admin restore-logical-backup \
    --archive "$BACKUP/archive.dump" --sha256 "$ARCHIVE_SHA256" \
    --metadata "$BACKUP/archive.metadata.json" --metadata-sha256 "$METADATA_SHA256"
) > "$RESTORE/restore-receipt.json"
(
  set -a
  . /etc/arcforges-center/restore.env
  set +a
  "$CENTER" migrate status
  "$CENTER" migrate apply
  export ARCFORGES_CENTER_RUNTIME_SECRET_FILE="$RESTORE/runtime.json"
  "$CENTER" admin rotate-runtime-credential
) > "$RESTORE/runtime-admission.json"
```

Preserve an isolated destination after a failure or an `UNKNOWN` admission.
The restore receipt and database lifecycle records identify the result.
Use a fresh destination for a new authorized restore once the previous
outcome is understood. Older schema promotion and bridge procedures require
their own verified inputs. [PostgreSQL store recovery procedures](../postgres-store.md#recovery)

Before switching traffic, validate the destination on an isolated operator
host or with network admission restricted to the recovery team.

1. Prepare a target `runtime.env` with the helper, passing `--role` if the
   target role differs from the sample. Provide the signing keys that match
   the target registry and retain the original expected HTTPS authority for
   WebAuthn and Node validation. Use the dedicated TLS origin configuration
   and omit bootstrap material on a restored database.
2. Start the target and verify loopback readiness. Confirm the exact new
   runtime slot using the target's migration configuration. Keep the target
   migration credentials separate from daemon startup files.
3. Verify a pre-restore browser session is refused and a fresh passkey
   sign-in works. Restore advances account authority epochs and revokes
   existing sessions, in-flight approval proofs, and prior Node protocol
   authorization. With the target's migration configuration, run
   `arcforges-center admin revoke-device --node <stable-node-uuid>` for each
   obsolete enrollment that will be renewed. Run `arcforges center signout`
   as its local Node owner to clear the old credential, then approve a fresh
   enrollment through the normal passkey flow. Confirm TLS and WebSocket
   connectivity and reissue the intended remote grant from the same Node.
4. Preserve the actual post-restore observation with the restore receipt.
   Fence the original Center before changing DNS or proxy selection so only
   one database can serve traffic. Retain the old database for incident
   analysis under private custody.

Rehearse this procedure with an isolated destination before depending on its
recovery time. A successful backup, database ping, or start-up readiness
alone cannot establish that recovered account and Node authority work.

## Revoke access and recover an account

Use the operator's private migration credentials for emergency revocation.
Choose the scope precisely. The command records the action in Center audit
history. Keep your own incident reference separately from credentials.

```sh
(
  set -a
  . /etc/arcforges-center/migration.env
  set +a
  /opt/arcforges-center/arcforges-center admin revoke-sessions --account "$ACCOUNT_ID"
  /opt/arcforges-center/arcforges-center admin revoke-device --node "$NODE_ID"
)
```

Run only the action required by the incident. The device command also
accepts a specific `--device` ID in place of `--node`. Use `--all` with
`revoke-sessions` only for a reviewed Center-wide incident. Confirm the
old session or enrollment can no longer reach its protected resource.
Device revocation can affect remote availability. The Node continues
processing local work under local authority.

For a lost passkey, use a remaining enrolled passkey or the supported
verified email recovery flow at `/api/account/recovery` when configured.
Keep recovery authority tied to a previously verified channel. For total
loss, preserve the database and escalate to your operator recovery procedure.
The initial bootstrap capability is one-time and stays spent.
