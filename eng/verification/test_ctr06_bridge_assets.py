#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
"""Offline checks for release metadata and sealed bridge assets."""
import hashlib
import json
import os
from pathlib import Path
import tempfile
import unittest

import ctr06_bridge_asset_state as state
import ctr06_bridge_bundle as bundle


def asset(platform, digest=None):
    return {"name": bundle.ASSETS[platform], "state": "uploaded",
            "digest": "sha256:" + (digest or bundle.ASSET_SHA256[platform])}


class BridgeAssetStateTest(unittest.TestCase):
    def test_existing_assets_and_pagination(self):
        page1 = [{"draft": False, "assets": [asset("linux")]}] + [
            {"draft": False, "assets": []} for _ in range(99)]
        page2 = [{"draft": False, "assets": [asset("windows")]}]
        pages = {1: page1, 2: page2}
        self.assertEqual(state.check_existing_assets(pages.__getitem__), {"linux": True, "windows": True})

    def test_absent_and_draft_assets_do_not_claim_delivery(self):
        pages = [{"draft": True, "assets": [asset("windows")]}, {"draft": False, "assets": []}]
        self.assertEqual(state.check_existing_assets(lambda _: pages), {"linux": False, "windows": False})

    def test_matching_name_with_wrong_or_missing_digest_refuses(self):
        for entry in (asset("linux", "a" * 64),
                      {"name": bundle.ASSETS["linux"], "state": "uploaded", "digest": None},
                      {"name": bundle.ASSETS["linux"], "state": "new", "digest": "sha256:" + bundle.ASSET_SHA256["linux"]}):
            with self.subTest(entry=entry), self.assertRaises(ValueError):
                state.check_existing_assets(lambda _: [{"draft": False, "assets": [entry]}])

    def test_unknown_release_shape_refuses(self):
        for value in ({"draft": False}, {"assets": []}, "not-a-release"):
            with self.subTest(value=value), self.assertRaises(ValueError):
                state.check_existing_assets(lambda _: [value])

    def test_missing_owner_read_token_refuses_without_network(self):
        saved = os.environ.pop("GH_TOKEN", None)
        try:
            with self.assertRaises(ValueError):
                state.read_github_page(1)
        finally:
            if saved is not None:
                os.environ["GH_TOKEN"] = saved

    def test_metadata_check_requires_the_active_profile_binding(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            records = root / "eng/provenance/records"
            profiles = root / "eng/provenance/artifact-profiles"
            records.mkdir(parents=True)
            profiles.mkdir(parents=True)
            profile = {"bridgeAssets": {
                "sourceCommit": bundle.REVISION, "sourceTree": bundle.TREE,
                "sourceArchiveSha256": bundle.SOURCE_SHA256, "contractsGo": "v1.0.0-ci.437.1",
                "carrierSha256": bundle.CARRIER_SHA256, "ociManifestDigest": bundle.IMAGE_DIGEST,
                "assets": {platform: {"name": bundle.ASSETS[platform], "sha256": bundle.ASSET_SHA256[platform],
                                      "executableSha256": bundle.EXE[platform][1]} for platform in bundle.ASSETS},
            }}
            profile_path = "eng/provenance/artifact-profiles/cloud-release-r111.json"
            inventory = root / "eng/provenance/files.json"
            inventory.write_text(json.dumps({"artifacts": ["runtime-r1", "worker-r1"]}), encoding="utf-8")

            def write_profile():
                raw = (json.dumps(profile) + "\n").encode()
                (root / profile_path).write_bytes(raw)
                target = {"profile": profile_path, "sha256": hashlib.sha256(raw).hexdigest()}
                for name in ("runtime-r1", "worker-r1"):
                    (records / (name + ".json")).write_text(json.dumps({"artifactTargets": [target]}), encoding="utf-8")

            write_profile()
            state.require_active_profile(root)
            profile["bridgeAssets"]["assets"]["windows"]["sha256"] = "a" * 64
            write_profile()
            with self.assertRaises(ValueError):
                state.require_active_profile(root)

    def test_random_bundle_fails_the_release_digest(self):
        with tempfile.TemporaryDirectory() as tmp:
            candidate = Path(tmp, "bridge.zip")
            candidate.write_bytes(b"not the sealed bridge")
            with self.assertRaises(ValueError):
                bundle.verify_bundle("linux", candidate)

    def test_existing_fixture_and_corrupted_copy(self):
        fixtures = [(platform, os.environ.get("ARCFORGES_TEST_CTR06_" + platform.upper() + "_BUNDLE"))
                    for platform in ("linux", "windows")]
        fixtures = [(platform, raw) for platform, raw in fixtures if raw]
        if not fixtures:
            self.skipTest("requires an offline native bridge bundle")
        for platform, raw in fixtures:
            with self.subTest(platform=platform), tempfile.TemporaryDirectory() as tmp:
                original = Path(raw)
                bundle.verify_bundle(platform, original)
                copy = Path(tmp, "corrupt.zip")
                data = bytearray(original.read_bytes())
                data[len(data)//2] ^= 1
                copy.write_bytes(data)
                with self.assertRaises(ValueError):
                    bundle.verify_bundle(platform, copy)


if __name__ == "__main__":
    unittest.main()
