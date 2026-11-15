# SPDX-License-Identifier: AGPL-3.0-only
"""Selection failures that could silently build with another installed SDK."""
from pathlib import Path
import tempfile
import unittest

from check_toolchain import bundled_npm, exact, sdk_root


class ToolchainSelection(unittest.TestCase):
    def test_bundled_npm_uses_each_official_layout_and_rejects_missing_bundle(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            for system, binary, entry in (
                ("nt", "node.exe", "node_modules/npm/bin/npm-cli.js"),
                ("posix", "bin/node", "lib/node_modules/npm/bin/npm-cli.js"),
            ):
                install = root / system
                executable = install / binary
                executable.parent.mkdir(parents=True, exist_ok=True)
                executable.touch()
                with self.assertRaises(ValueError):
                    bundled_npm(executable, system)
                npm = install / entry
                npm.parent.mkdir(parents=True)
                npm.touch()
                self.assertEqual(bundled_npm(executable, system), npm)

    def test_cli_selection_is_exact_among_patch_and_preview_sdks(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "11.0.100").mkdir()
            listing = f"10.0.403 [{root}]\n11.0.100 [{root}]\n11.0.200-preview.1 [{root}]"
            self.assertEqual(sdk_root(listing, "11.0.100"), root / "11.0.100")

    def test_missing_or_ambiguous_sdk_is_refused(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "11.0.100").mkdir()
            for listing in (f"11.0.101 [{root}]", f"11.0.100 [{root}]\n11.0.100 [{root}]"):
                with self.subTest(listing=listing), self.assertRaises(ValueError):
                    sdk_root(listing, "11.0.100")

    def test_version_rejects_a_different_patch_and_preview(self):
        for actual in ("11.0.101", "11.0.100-preview.1"):
            with self.subTest(actual=actual), self.assertRaises(ValueError):
                exact(actual, "11.0.100", "SDK")


if __name__ == "__main__":
    unittest.main()
