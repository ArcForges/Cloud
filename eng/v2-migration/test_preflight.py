# SPDX-License-Identifier: AGPL-3.0-only
"""Real PostgreSQL inventory fixtures, not guarded upgrade/authority qualification.

Run explicitly on the designated Linux host: python eng/v2-migration/test_preflight.py
Uses the existing pinned disposable Postgres context; no operator database is opened.
"""

import hashlib
import importlib.util
import json
from pathlib import Path
import re
import subprocess
import unittest
import uuid


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


ROOT = Path(__file__).resolve().parents[2]
preflight = load("center_preflight", Path(__file__).with_name("preflight.py"))
center = load("center_controls", ROOT / "eng/center.py")


class PostgresInventoryTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server = center.Postgres("v2-preflight")
        cls.server.__enter__()

    @classmethod
    def tearDownClass(cls):
        cls.server.__exit__()

    def setUp(self):
        self.database = "afv2_" + uuid.uuid4().hex
        self.run_sql("CREATE DATABASE " + self.database, database="postgres")
        self.command = ["docker", "exec", "-i", self.server.name, "psql", "-X", "-qAt", "-w",
                        "-U", "postgres", "-d", self.database, "-v", "ON_ERROR_STOP=1"]

    def tearDown(self):
        self.run_sql("DROP DATABASE " + self.database + " WITH (FORCE)", database="postgres")

    def run_sql(self, sql, database=None):
        command = ["docker", "exec", "-i", self.server.name, "psql", "-X", "-qAt", "-w", "-U", "postgres",
                   "-d", database or self.database, "-v", "ON_ERROR_STOP=1"]
        result = subprocess.run(command, input=sql, text=True, capture_output=True, timeout=35)
        if result.returncode:
            self.fail("fixture_sql_failed (database output intentionally withheld)")
        return result.stdout

    def fixture(self, version):
        # Replay real immutable DDL in a private synthetic database. This deliberately does
        # not call/admit the guarded migration runner or mint a credential/restore floor.
        runner = (ROOT / "center/internal/store/migrate/migrate.go").read_text(encoding="utf-8")
        bootstrap = re.search(r"const bootstrapSQL = `(.*?)`", runner, re.S).group(1)
        parts = ["BEGIN;", bootstrap]
        for step in preflight.migration_sources()[:version]:
            parts.append((preflight.MIGRATIONS / step["name"]).read_text(encoding="utf-8"))
            parts.append("INSERT INTO platform.schema_migration (version,name,sha256,duration_ms,runner) "
                         f"VALUES ({step['version']},'{step['name']}','{step['sha256']}',0,'afv2-inventory-fixture');")
        parts.append("COMMIT;")
        self.run_sql("\n".join(parts))

    def inventory(self):
        result = preflight.inventory(self.command)
        self.assertFalse(result["destructive_contraction_allowed"])
        self.assertEqual("unknown", result["deployment"])
        return result

    def snapshot(self):
        # Discard per-invocation random \restrict tokens from logical SQL.
        result = subprocess.run(["docker", "exec", self.server.name, "pg_dump", "-U", "postgres",
                                 "-d", self.database], capture_output=True, text=True, timeout=35)
        self.assertEqual(0, result.returncode)
        content = "\n".join(line for line in result.stdout.splitlines()
                            if not line.startswith(("\\restrict ", "\\unrestrict ")))
        return hashlib.sha256(content.encode()).hexdigest()

    def test_fresh(self):
        self.assertEqual("fresh", self.inventory()["classification"])

    def test_schema10_read_only_and_no_data_output(self):
        self.fixture(10)
        sentinel = "private_fixture_marker"
        self.run_sql("INSERT INTO platform.inbox VALUES ('fixture','" + sentinel + "',now(),NULL,NULL,now()+interval '1 day')")
        before = self.snapshot()
        result = self.inventory()
        self.assertEqual("center10", result["classification"])
        self.assertTrue(result["read_only_transaction"])
        self.assertEqual(1, result["counts"]["pending_inbox"])
        self.assertIn("pending_inbox", result["blockers"])
        self.assertNotIn(sentinel, json.dumps(result))
        self.assertEqual(before, self.snapshot())

    def test_schema11_is_not_deployment_or_floor_proof(self):
        self.fixture(11)
        result = self.inventory()
        self.assertEqual("center11", result["classification"])
        self.assertIn("schema11_runtime_floor_or_restore_admission_unproven", result["blockers"])

    def test_newer(self):
        self.fixture(11)
        self.run_sql("INSERT INTO platform.schema_migration (version,name,sha256,duration_ms,runner) "
                     "VALUES (12,'0012_fixture.sql',repeat('a',64),0,'fixture')")
        self.assertEqual("newer", self.inventory()["classification"])

    def test_checksum_drift(self):
        self.fixture(10)
        self.run_sql("UPDATE platform.schema_migration SET sha256=repeat('a',64) WHERE version=10")
        self.assertEqual("unknown", self.inventory()["classification"])

    def test_unknown_owned_schema(self):
        self.run_sql("CREATE SCHEMA platform; CREATE TABLE platform.unknown_fixture(id integer)")
        self.assertEqual("unknown", self.inventory()["classification"])

    def test_active_session_and_migration_lock(self):
        self.fixture(10)
        holder = subprocess.Popen(self.command, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                  text=True, bufsize=1)
        try:
            holder.stdin.write("SELECT pg_advisory_lock(7021784060631607141);\n\\echo locked\n")
            holder.stdin.flush()
            while True:
                line = holder.stdout.readline()
                if line.strip() == "locked":
                    break
                if not line:
                    self.fail("fixture_lock_not_established")
            result = self.inventory()
            self.assertEqual("center10", result["classification"])
            self.assertIn("other_sessions", result["blockers"])
            self.assertIn("migration_locks", result["blockers"])
        finally:
            holder.communicate("\\q\n", timeout=10)

    def test_locked_metadata_fails_closed(self):
        self.fixture(10)
        holder = subprocess.Popen(self.command, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                  text=True, bufsize=1)
        try:
            holder.stdin.write("BEGIN; LOCK TABLE platform.schema_migration IN ACCESS EXCLUSIVE MODE;\n\\echo locked\n")
            holder.stdin.flush()
            self.assertEqual("locked", holder.stdout.readline().strip())
            self.assertEqual("unknown", self.inventory()["classification"])
        finally:
            holder.communicate("ROLLBACK;\n\\q\n", timeout=10)


if __name__ == "__main__":
    unittest.main(verbosity=2)
