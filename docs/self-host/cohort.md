<!-- SPDX-License-Identifier: AGPL-3.0-only -->

# Self-host distribution

The Linux x64 cohort stages the Go Center from its verified producer image,
the published Blazor Dashboard profile, the PostgreSQL 18 configuration, and
the Caddy and systemd service definitions. Its provenance includes the Cloud
candidate receipt, build identity, legal records and reviewed Go dependency
inventory, together with the Web profile's producer receipt, licences and App
dependency locks. The service runs the Go executable, PostgreSQL and Caddy.
The staging tools use the repository's pinned Node.js version.

## Assemble a private candidate

Use clean Cloud and Web producer checkouts, with the exact Git commits and
trees identified by the verified producer inputs. For Cloud, obtain the
original sealed candidate directory and the Go executable extracted from that
candidate's image. The assembler uses the stock verifier from a private copy
of the exact producer commit and checks the executable against the verified
image receipt. Service definitions and notices come from the producer's Git
tree. Keep the input candidate and its sealed manifest available for
provenance review.

For Web, verify the GitHub Actions artifact against its approved workflow run,
producer commit and raw ZIP SHA-256. Extract the single published
`web-profiles-<sha256>.tar` member and record its own SHA-256. Use a reviewed
receipt from this verification as a separate input to assembly:

```json
{
  "source": {
    "repo": "ArcForges/Web",
    "commit": "<40 lowercase hexadecimal digits>",
    "tree": "<40 lowercase hexadecimal digits>"
  },
  "runId": "<GitHub Actions run ID>",
  "artifactId": "<GitHub Actions profile artifact ID>",
  "artifactZipSha256": "<verified workflow ZIP digest>",
  "profileSha256": "<verified inner TAR digest>"
}
```

```sh
node tooling/self-host-cohort.ts assemble \
  --cloud-repo "$CLOUD_PRODUCER" --web-repo "$WEB_PRODUCER" \
  --candidate "$CLOUD_CANDIDATE" --center "$CENTER_EXECUTABLE" \
  --profile "$WEB_PROFILE" --web-receipt "$WEB_RECEIPT" \
  --output "$FRESH_OUTPUT_DIR" --qualification candidate
```

The output contains `arcforges-self-host-linux-x64.tar` and its
`.manifest.json` sidecar. The authorized signer signs the exact manifest bytes
with Ed25519 and supplies a 64-byte raw `.manifest.sig` sidecar. Distribute
the pinned PEM SPKI public key through the independent operator trust channel.

Main qualification also requires an independently maintained admission
document and local copies of the actual Cloud and Web `origin/main` history.
Fetch and validate those references through the existing repository trust
process before offline verification. The admission document uses
`{"schema":1,"admitted":[...],"denied":[...],"archiveSha256":"..."}` with
the currently authorized Cloud and Web `{repo,commit,tree}` rows in that
order and the independently approved SHA-256 of the exact cohort archive.
Record withdrawn producer revisions in `denied`. The archive pin prevents a
withdrawn package with the same source identity from being selected. The
verifier also checks each producer's Git tree and ancestry. Use
`--qualification main --admission "$ADMISSION"` with the authorized
admission record.

## Verify and stage

Use an operator-controlled staging directory and the separately supplied
public key. The tool verifies the detached signature, then binds the archive's
filename, length and SHA-256 before reading its members. On Linux x64 it
stages those verified bytes under the archive digest without replacing an
existing release. The command prints the staging path, profile path and
profile SHA-256.

```sh
node tooling/self-host-cohort.ts verify \
  --archive "$ARCHIVE" --public-key "$PINNED_PUBLIC_KEY" --allow-candidate
node tooling/self-host-cohort.ts stage \
  --archive "$ARCHIVE" --public-key "$PINNED_PUBLIC_KEY" \
  --staging "$OPERATOR_STAGING" --allow-candidate
```

The commands above explicitly select an isolated candidate. For main
qualification provide `--cloud-repo`, `--web-repo` and `--admission` with
the verified history and current admission record.

On the target, confirm a Linux x86-64 host, PostgreSQL 18, systemd, Caddy and
the operator's TLS name and certificate. Follow the
[Linux installation procedure](../operations/self-host-install.md) with
`CENTER_BUILD` pointing at the staged `bin/arcforges-center` and
`DEFINITION` at its `setup/` directory. Use the Center's `version` and
`migrate status` outputs to compare the installed build and database with the
cohort. Use the staged profile and its verified SHA-256 from the cohort
receipt. Set `CENTER_ORIGIN` to the same public HTTPS scheme, host and port
as the API, without the `/api` path.

```sh
node tooling/self-host-static-origin.ts stage \
  "$STAGED_PROFILE" "$STAGED_PROFILE_SHA256" "$STATIC_RELEASES" \
  --dashboard "$CENTER_ORIGIN"
```

Use the returned release to select the fragment through the
[static origin procedure](../operations/static-origin.md). Keep the preceding
verified cohort and the applicable
[database recovery material](../operations/self-host-recovery.md) under
operator custody.
