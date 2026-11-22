# SPDX-License-Identifier: AGPL-3.0-only

from datetime import datetime, timedelta, timezone
from hashlib import sha256
import json
import os
from pathlib import Path
import runpy
import socket
import stat
import subprocess
import sys
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import Mock, patch


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

    def test_stopped_failed_unit_requires_zero_pids_and_a_drained_group(self):
        operations = runpy.run_path(str(SCRIPT))
        upgrade_class = operations["Upgrade"]
        refusal = operations["UpgradeRefused"]
        unit = "arcforges-center-fixture.service"
        group = f"/user.slice/{unit}"
        for state, main_pid, control_pid, after_group, drained, problem in (
            ("inactive", "0", "0", group, "empty", None),
            ("failed", "0", "0", "", "removed", None),
            ("active", "0", "0", "", "removed", "unit did not stop"),
            ("deactivating", "0", "0", "", "removed", "unit did not stop"),
            ("failed", "17", "0", "", "removed", "unit did not stop"),
            ("failed", "0", "19", "", "removed", "unit did not stop"),
            ("failed", "0", "0", f"/other.slice/{unit}", "removed", "group changed"),
            ("failed", "0", "0", "", None, "group still holds processes"),
        ):
            with self.subTest(state=state, main_pid=main_pid, control_pid=control_pid,
                              after_group=after_group, drained=drained):
                upgrade = upgrade_class.__new__(upgrade_class)
                upgrade.unit = unit
                upgrade.journal = {"phase": "activation-fencing", "serviceControlGroup": group}
                upgrade.systemd = Mock(side_effect=["", "", state, main_pid, control_pid, after_group])
                upgrade.phase = Mock()
                check_drain = Mock(
                    return_value=drained,
                    side_effect=None if drained else refusal("Center control group still holds processes."),
                )
                with patch.dict(upgrade_class.stop_service.__globals__,
                                cgroup_path=lambda *_: True, drained_group=check_drain):
                    if problem is None:
                        upgrade.stop_service()
                        upgrade.phase.assert_called_with("activation-fencing", serviceControlGroupState=drained)
                    else:
                        with self.assertRaisesRegex(refusal, problem):
                            upgrade.stop_service()
                        upgrade.phase.assert_called_once_with("activation-fencing", serviceControlGroup=group)
                if problem is None or drained is None:
                    check_drain.assert_called_once_with(group, unit)
                else:
                    check_drain.assert_not_called()
                upgrade.systemd.assert_any_call("stop", unit)

    @unittest.skipUnless(sys.platform.startswith("linux"), "real Linux durable file and link operations")
    def test_private_journal_inspection_and_immutable_release_tree(self):
        operations = runpy.run_path(str(SCRIPT))
        state = self.root / "state"
        state.mkdir(mode=0o700)
        journal = operations["Upgrade"].__new__(operations["Upgrade"])
        journal.journal_path = state / "upgrade.json"
        journal.journal = {"schema": 1, "operation": "0" * 16}
        journal.phase("contracting", predecessor={"version": 16})
        operations["replace_file"](state / "maintenance", b"0" * 16 + b"\n")
        inspected = subprocess.run(
            [sys.executable, "-B", SCRIPT, "upgrade", "inspect", "--state-root", state],
            capture_output=True,
            check=True,
        )
        observed = json.loads(inspected.stdout)
        self.assertEqual(observed["phase"], "contracting")
        self.assertTrue(observed["maintenance"])
        self.assertEqual(observed["predecessor"], {"version": 16})
        self.assertEqual(stat.S_IMODE(journal.journal_path.stat().st_mode), 0o600)
        journal.fence = state / "maintenance"
        journal.current = self.root / "current"
        journal.journal["previous"] = "1" * 64
        journal.current.symlink_to(f"releases/{'1' * 64}")
        journal.fence.unlink()
        self.assertFalse(journal.previous_recovery_fence(rolling_back=False))
        journal.phase("fencing")
        self.assertTrue(journal.previous_recovery_fence(rolling_back=False))
        journal.current.unlink()
        journal.current.symlink_to(f"releases/{'2' * 64}")
        self.assertFalse(journal.previous_recovery_fence(rolling_back=False))

        tree = self.root / "verified-release"
        tree.mkdir(mode=0o755)
        artifact = tree / "member"
        artifact.write_bytes(b"original")
        verified = operations["release_tree"](tree, synchronize=True)
        artifact.write_bytes(b"changed")
        self.assertNotEqual(operations["release_tree"](tree), verified)
        (tree / "unexpected-link").symlink_to(artifact)
        with self.assertRaises(operations["UpgradeRefused"]):
            operations["release_tree"](tree)

        journal.releases = self.root / "releases"
        selected = journal.releases / ("1" * 64) / "bin"
        selected.mkdir(parents=True)
        executable = selected / "arcforges-center"
        executable.write_bytes(b"candidate")
        executable.chmod(0o755)
        self.assertEqual(journal.binary("1" * 64), executable)
        executable.chmod(0o775)
        with self.assertRaises(operations["UpgradeRefused"]):
            journal.binary("1" * 64)

    @unittest.skipUnless(sys.platform.startswith("linux"), "real Linux TCP listener ownership")
    def test_listener_receipt_changes_when_the_socket_is_replaced(self):
        operations = runpy.run_path(str(SCRIPT))
        listeners = operations["listening_sockets"]
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as admin:
            admin.bind(("127.0.0.1", 0))
            admin.listen()
            admin_port = admin.getsockname()[1]
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as public:
                public.bind(("127.0.0.1", 0))
                public.listen()
                public_port = public.getsockname()[1]
                addresses = (f"127.0.0.1:{public_port}", f"127.0.0.1:{admin_port}")
                previous = listeners(os.getpid(), addresses)
                self.assertIsNotNone(previous)
            self.assertIsNone(listeners(os.getpid(), addresses))
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as replacement:
                replacement.bind(("127.0.0.1", public_port))
                replacement.listen()
                current = listeners(os.getpid(), addresses)
                self.assertIsNotNone(current)
                self.assertNotEqual(previous, current)


if __name__ == "__main__":
    unittest.main()
