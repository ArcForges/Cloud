# SPDX-License-Identifier: AGPL-3.0-only
"""Selection failures that could silently build with another installed SDK."""
from pathlib import Path
import tempfile
import unittest

from check_toolchain import exact, sdk_root


class ToolchainSelection(unittest.TestCase):
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
