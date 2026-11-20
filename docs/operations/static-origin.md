# Self-host static origin

A self-hosted Center can serve its API through the TLS proxy with an empty static import directory. With a selected Web release, the same HTTPS host serves the static browser files and proxies `/api/` to the Center. The Center owns sessions, request authorization, and API responses. Use its configured public base `https://<host>/api`. Reserve the proxy's API and private paths before importing any static routes.

This integration consumes the existing Web profile archive. The current artifact contains the Account and Chat profiles. `AFV2-DIST-01` packages and qualifies the completed Dashboard after the Web tasks and final cutover. [Web profile archive contract](https://github.com/ArcForges/Web/blob/69be85d95ea412cc027597ffd0d990bf0e28e50f/docs/profile-bundle.md)

## Verify and stage a release

Obtain `web-profiles-<sha256>.tar` and the independently approved, lowercase SHA-256 from the reviewed producer release record or a reviewed local build. Verify any producer signature or provenance required by that record before handing its pin to the staging tool. The tool checks the archive and staged bytes against the supplied approval.

Provide Node.js 26.13.1, the matching Cloud source, and an operator-owned release directory. Keep the archive and its parent under operator control. Create digest directories exclusively with the staging tool. Give Caddy read and traverse permissions. Only the operator should be able to write to the release store, its parents, and the proxy configuration. Keep backups, credentials, and other private files outside the release store. Set `PROFILE_ARCHIVE` to the producer archive and `PROFILE_SHA256` to the approved pin.

```sh
releases=/srv/arcforges-static/releases
sudo install -d -m 0755 "$releases" /etc/arcforges/static-origin.d &&
  release=$(sudo node tooling/self-host-static-origin.ts stage "$PROFILE_ARCHIVE" "$PROFILE_SHA256" "$releases") &&
  sudo node tooling/self-host-static-origin.ts verify "$PROFILE_ARCHIVE" "$PROFILE_SHA256" "$releases"
```

The tool reuses the Web profile verifier used by Cloud. It verifies the outer digest before parsing, checks the deterministic regular-file archive, and checks the schema, order, path allowlist, CSP, size, and SHA-256 of each member. Missing, extra, or duplicate members, links, traversal, and inconsistent compressed forms cause refusal. The tool builds a sibling staging directory with exclusively created files, checks the exact disk tree and contents, then renames it to the digest path. Repeating `stage` reuses an exact existing release. A changed release fails both `stage` and `verify` and needs operator investigation. Select the verified release in the proxy separately.

The release directory contains a copy of the parsed `manifest.json`, the verified `_headers`, and a generated `static-origin.caddy`. Only the `site/` subtree contains web asset bytes. The fragment refers to that release's absolute digest directory, so a proxy configuration and its headers always refer to files in the same release. Keep selected and previous release directories intact while Caddy might still need them.

## Select and roll back

The provided Caddy example imports `/etc/arcforges/static-origin.d/*.caddy` inside its TLS route. Keep this directory empty for API-only operation or use exactly one fragment named `active.caddy`. The proxy environment file supplies the public host and upstream settings. Keep any test import override out of that file when selecting a release for the service. [Caddy import rules](https://caddyserver.com/docs/caddyfile/directives/import)

First run `verify` with the approved archive again and validate the complete proposed proxy configuration. Check that the service account can read the release files. Save the previous fragment outside the import glob, or record that the directory was empty.

```sh
sudo env ARCFORGES_STATIC_ORIGIN_IMPORT="$release/static-origin.caddy" \
  caddy validate --config /etc/caddy/Caddyfile --adapter caddyfile \
    --envfile /etc/arcforges-center/caddy.env &&
  sudo -u caddy test -r "$release/site/account/index.html"
```

Once those checks succeed, install and rename the fragment on the same filesystem, then validate the selected configuration. Restart `caddy.service` during the planned maintenance window. Clients can reconnect after the proxy restarts. The example uses `admin off`.

```sh
active=/etc/arcforges/static-origin.d/active.caddy
sudo install -m 0644 -- "$release/static-origin.caddy" "$active.new" &&
  sudo mv -T -- "$active.new" "$active" &&
  sudo caddy validate --config /etc/caddy/Caddyfile --adapter caddyfile \
    --envfile /etc/arcforges-center/caddy.env &&
  sudo systemctl restart caddy.service
```

If validation fails, restore the previous selection before restarting. If restart or the post-start checks fail, select the previous verified fragment using the same atomic rename, validate it, and restart Caddy. To return to an empty selection, move `active.caddy` outside the import glob and validate before restarting. Asset rollback only updates the Caddy configuration.

## Check the request contract

- API requests preserve the Center's method, status, content type, and cache controls. A missing or refused API call stays an API response. Test with an existing typed Center method and an unknown API path. Validate the normal Node channel and forwarded origin when qualifying the TLS proxy.
- Static requests use `GET` or `HEAD` to exact manifest file paths or `/account`, `/account/`, `/chat`, and `/chat/`. These four paths serve their corresponding verified index files. Other paths, including the root, arbitrary deep links, direct `.br` or `.gz` names, and private metadata, receive the proxy's no-store 404.
- Profile HTML uses its verified CSP and revalidation headers. Unfingerprinted root assets and framework loaders revalidate. Fingerprinted framework assets are immutable. Verify the response headers, and request a verified compressed representation through `Accept-Encoding`; `file_server` does the negotiation from the same release directory. [Caddy static file behavior](https://caddyserver.com/docs/caddyfile/directives/file_server)

The local tests exercise admission, exact static paths, concurrent staging, and stale or modified release refusal. Browser and distribution qualification still use the completed application and installed Center, as specified by the later tasks.
