#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
"""Check public release metadata before rebuilding the one-time bridge assets.

Only GitHub's fixed API is contacted; no asset is downloaded. An existing
same-name asset with a missing or different provider digest is a hard refusal.
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import sys
import urllib.request

from ctr06_bridge_bundle import (ASSETS, ASSET_SHA256, CARRIER_SHA256, EXE, IMAGE_DIGEST, REVISION,
                                 SOURCE_SHA256, TREE)


def require_active_profile(root):
    inventory = json.loads((root / "eng/provenance/files.json").read_text(encoding="utf-8"))
    records = inventory.get("artifacts")
    if not isinstance(records, list) or len(records) != 2:
        raise ValueError("active release records unavailable")
    references = []
    for name in records:
        if not isinstance(name, str) or "/" in name or "\\" in name:
            raise ValueError("invalid active release record")
        record = json.loads((root / "eng/provenance/records" / (name + ".json")).read_text(encoding="utf-8"))
        targets = record.get("artifactTargets")
        if not isinstance(targets, list) or len(targets) != 1:
            raise ValueError("invalid active release profile reference")
        references.append((targets[0].get("profile"), targets[0].get("sha256")))
    if references[0] != references[1]:
        raise ValueError("active release records disagree")
    profile_path, expected_hash = references[0]
    if not isinstance(profile_path, str) or not profile_path.startswith("eng/provenance/artifact-profiles/") or ".." in profile_path:
        raise ValueError("invalid active release profile path")
    raw = (root / profile_path).read_bytes().replace(b"\r\n", b"\n")
    if hashlib.sha256(raw).hexdigest() != expected_hash:
        raise ValueError("active release profile changed")
    profile = json.loads(raw)
    bridge = profile.get("bridgeAssets", {})
    if (bridge.get("sourceCommit") != REVISION or bridge.get("sourceTree") != TREE or
            bridge.get("sourceArchiveSha256") != SOURCE_SHA256 or bridge.get("contractsGo") != "v1.0.0-ci.437.1" or
            bridge.get("carrierSha256") != CARRIER_SHA256 or bridge.get("ociManifestDigest") != IMAGE_DIGEST):
        raise ValueError("active profile bridge identity differs")
    for platform in ASSETS:
        item = bridge.get("assets", {}).get(platform, {})
        if (item.get("name") != ASSETS[platform] or item.get("sha256") != ASSET_SHA256[platform] or
                item.get("executableSha256") != EXE[platform][1]):
            raise ValueError("active profile bridge asset differs")


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def check_existing_assets(read_page):
    found = {platform: False for platform in ASSETS}
    for page in range(1, 101):
        releases = read_page(page)
        if not isinstance(releases, list):
            raise ValueError("release metadata is not a list")
        for release in releases:
            if not isinstance(release, dict) or not isinstance(release.get("draft"), bool):
                raise ValueError("release draft state is unavailable")
            if release["draft"]:
                continue
            assets = release.get("assets")
            if not isinstance(assets, list):
                raise ValueError("release assets are unavailable")
            for asset in assets:
                if not isinstance(asset, dict):
                    raise ValueError("invalid release asset")
                for platform, name in ASSETS.items():
                    if asset.get("name") == name:
                        if asset.get("state") != "uploaded" or asset.get("digest") != "sha256:" + ASSET_SHA256[platform]:
                            raise ValueError("an existing bridge asset has a different or missing digest")
                        found[platform] = True
        if all(found.values()) or len(releases) < 100:
            return found
    raise ValueError("release pagination exceeded the bound")


def read_github_page(page):
    token = os.environ.get("GH_TOKEN", "")
    if not token:
        raise ValueError("GitHub read token unavailable")
    url = "https://api.github.com/repos/ArcForges/Cloud/releases?per_page=100&page=" + str(page)
    request = urllib.request.Request(url, headers={"Authorization": "Bearer " + token,
        "Accept": "application/vnd.github+json", "User-Agent": "ArcForges-CTR06-bridge-assets",
        "X-GitHub-Api-Version": "2022-11-28"})
    opener = urllib.request.build_opener(NoRedirect())
    with opener.open(request, timeout=20) as response:
        raw = response.read(8 * 1024 * 1024 + 1)
    if len(raw) > 8 * 1024 * 1024:
        raise ValueError("release metadata is too large")
    return json.loads(raw)


if __name__ == "__main__":
    try:
        require_active_profile(Path(__file__).resolve().parents[2])
        state = check_existing_assets(read_github_page)
        for platform in sorted(state):
            print(platform + "_present=" + str(state[platform]).lower())
    except (OSError, ValueError, json.JSONDecodeError):
        raise SystemExit("bridge release metadata could not be verified") from None
