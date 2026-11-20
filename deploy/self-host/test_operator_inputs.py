# SPDX-License-Identifier: AGPL-3.0-only

from datetime import datetime, timedelta, timezone
from hashlib import sha256
import json
import os
from pathlib import Path
import stat
import subprocess
import sys
from tempfile import TemporaryDirectory
import unittest


SCRIPT = Path(__file__).with_name("operator-inputs.py")
DATABASE_URL = "ARCFORGES_CENTER_DATABASE_URL"
RUNTIME = "postgres://arcforges_center_runtime_a:fixture%2Fpw@127.0.0.1:5432/arcforges?sslmode=disable"


class OperatorInputsTest(unittest.TestCase):
    def setUp(self):
        private = TemporaryDirectory()
        self.addCleanup(private.cleanup)
        self.root = Path(private.name)

    def command(self, *arguments, code=0):
        result = subprocess.run([sys.executable, "-B", SCRIPT, *map(str, arguments)], capture_output=True)
        self.assertEqual(result.returncode, code, result.stderr)
        self.assertEqual(result.stdout, b"")
        self.assertNotIn(b"fixture", result.stderr)

    @unittest.skipUnless(sys.platform.startswith("linux"), "real Linux credential file protection")
    def test_runtime_conversion_and_refusals(self):
        secret = self.root / "rotated.json"
        output = self.root / "runtime.env"
        secret.write_text(json.dumps({DATABASE_URL: RUNTIME}), encoding="ascii")
        secret.chmod(0o600)
        self.command("runtime-env", secret, output)
        expected = f'{DATABASE_URL}="{RUNTIME}"\n'
        self.assertEqual(output.read_text(encoding="ascii"), expected)
        self.assertEqual(stat.S_IMODE(output.stat().st_mode), 0o600)
        self.command("runtime-env", secret, output, code=1)
        self.assertEqual(output.read_text(encoding="ascii"), expected)
        output.unlink()

        for rejected in (
            RUNTIME.replace("runtime_a", "owner"),
            RUNTIME.replace("127.0.0.1", "192.0.2.10"),
            RUNTIME.replace("arcforges?", "arcforges?host=example.org&"),
            RUNTIME + "\nANOTHER=value",
        ):
            secret.write_text(json.dumps({DATABASE_URL: rejected}), encoding="ascii")
            self.command("runtime-env", secret, output, code=1)
            self.assertFalse(output.exists())

        secret.write_text(f'{{"{DATABASE_URL}":"{RUNTIME}","{DATABASE_URL}":"{RUNTIME}"}}', encoding="ascii")
        self.command("runtime-env", secret, output, code=1)
        secret.write_text(json.dumps({DATABASE_URL: RUNTIME}), encoding="ascii")
        secret.chmod(0o644)
        self.command("runtime-env", secret, output, code=1)
        secret.chmod(0o600)
        linked = self.root / "symlink"
        linked.symlink_to(secret)
        self.command("runtime-env", linked, output, code=1)
        self.assertFalse(output.exists())

    def test_bootstrap_hash_expiry_and_no_overwrite(self):
        directory = self.root / "bootstrap"
        before = datetime.now(timezone.utc)
        self.command("bootstrap", directory, "--hours", 1)
        token_file = directory / "bootstrap-token"
        environment = directory / "bootstrap.env"
        token = token_file.read_text(encoding="ascii").rstrip("\n")
        self.assertRegex(token, r"^afb1\.[A-Za-z0-9_-]{43}$")
        values = dict(line.split("=", 1) for line in environment.read_text(encoding="ascii").splitlines())
        self.assertEqual(values["ARCFORGES_CENTER_BOOTSTRAP_SHA256"], sha256(token.encode("ascii")).hexdigest())
        expiry = datetime.strptime(values["ARCFORGES_CENTER_BOOTSTRAP_EXPIRES_AT"], "%Y-%m-%dT%H:%M:%SZ")
        expiry = expiry.replace(tzinfo=timezone.utc)
        self.assertLess(abs(expiry - before - timedelta(hours=1)), timedelta(seconds=5))
        if os.name == "posix":
            self.assertEqual(stat.S_IMODE(directory.stat().st_mode), 0o700)
            self.assertEqual(stat.S_IMODE(token_file.stat().st_mode), 0o600)
            self.assertEqual(stat.S_IMODE(environment.stat().st_mode), 0o600)
        self.command("bootstrap", directory, code=1)
        self.assertEqual(token_file.read_text(encoding="ascii").rstrip("\n"), token)
        unexpected = self.root / "rejected"
        self.command("bootstrap", unexpected, "--hours", 169, code=2)
        self.assertFalse(unexpected.exists())


if __name__ == "__main__":
    unittest.main()
