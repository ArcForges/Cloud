# SPDX-License-Identifier: AGPL-3.0-only
"""Exercise the read-only inventory contract and its existing PostgreSQL fixtures.

Model only, no database: python eng/v2-migration/test_preflight.py InventoryModelTests
Existing PostgreSQL fixtures: python eng/v2-migration/test_preflight.py PostgresInventoryTests
The PostgreSQL suite uses the pinned disposable context and opens no operator database.
"""

import hashlib
import importlib.util
import json
from pathlib import Path
import re
import subprocess
import unittest
from unittest.mock import patch
import uuid


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


ROOT = Path(__file__).resolve().parents[2]
preflight = load("center_preflight", Path(__file__).with_name("preflight.py"))
center = load("center_controls", ROOT / "eng/center.py")


class InventoryModelTests(unittest.TestCase):
    command = ["psql", "-X", "-qAt", "-w", "-v", "ON_ERROR_STOP=1", "--dbname", "fixture"]

    def setUp(self):
        self.source = preflight.migration_sources()

    def rows(self, version, *, counts=None, owned=1):
        applied = None if version is None else [dict(entry) for entry in self.source[:version]]
        results = [{"kind": "transaction", "read_only": True, "other_sessions": 0, "migration_locks": 0, "owned_tables": owned},
                   {"kind": "ledger", "rows": applied}]
        if version in {10, 11, 16}:
            counts = counts or {}
            defaults = {name: 0 for name in preflight.COUNTS}
            if version == 10:
                defaults.update(dict.fromkeys(preflight.SCHEMA11_COUNTS))
            if version == 16:
                defaults.update(dict.fromkeys(preflight.CURRENT_COUNTS, 0))
            defaults.update(counts)
            results.extend({"kind": "count", "name": name, "value": value} for name, value in defaults.items())
        return results

    def inventory(self, rows):
        output = "\n".join(json.dumps(row) for row in rows)
        response = subprocess.CompletedProcess(self.command, 0, output, "")
        with patch.object(preflight.subprocess, "run", return_value=response) as run:
            result = preflight.inventory(self.command)
        run.assert_called_once_with(self.command, input=preflight.inspection_sql(), capture_output=True, text=True, timeout=35)
        self.assertFalse(result["destructive_contraction_allowed"])
        self.assertEqual("unknown", result["deployment"])
        return result

    def test_historical_baselines_keep_names_keys_and_prerequisite_text(self):
        for version in (10, 11):
            with self.subTest(version=version):
                report = self.inventory(self.rows(version, counts={"pending_inbox": 1}))
                self.assertEqual(f"center{version}", report["classification"])
                self.assertEqual(self.source[:11], report["source_migrations"])
                self.assertEqual(self.source[:version], report["applied_migrations"])
                self.assertEqual(set(preflight.COUNTS) | {"other_sessions", "migration_locks"}, set(report["counts"]))
                self.assertEqual(preflight.PREREQUISITES, report["prerequisites"])
                self.assertIn("pending_inbox", report["blockers"])
        self.assertIn("schema10_requires_0011_security_successor_admission_not_simple_append",
                      self.inventory(self.rows(10))["blockers"])
        self.assertIn("schema11_runtime_floor_or_restore_admission_unproven", self.inventory(self.rows(11))["blockers"])

    def test_current_expansion_counts_legacy_unknown_and_preserved_outcomes(self):
        counts = {"live_hub_lease": 1, "unsettled_routed_calls": 3, "unknown_routed_calls": 2,
                  "unknown_routed_file_calls": 1, "unsettled_legacy_outcomes": 4, "unknown_legacy_outcomes": 3}
        report = self.inventory(self.rows(16, counts=counts))
        self.assertEqual("center16", report["classification"])
        self.assertTrue(report["migration_ledger_matches_source"])
        self.assertEqual(self.source, report["source_migrations"])
        self.assertEqual(self.source, report["applied_migrations"])
        self.assertIn("0001..0016", report["prerequisites"][-1])
        self.assertIn("deployment_cohort_backup_and_authority_qualification_required", report["blockers"])
        for name, value in counts.items():
            self.assertEqual(value, report["counts"][name])
            self.assertIn(name, report["blockers"])

    def test_fresh_or_unledgered_objects(self):
        self.assertEqual("fresh", self.inventory(self.rows(None, owned=0))["classification"])
        unknown = self.inventory(self.rows(None))
        self.assertEqual("unknown", unknown["classification"])
        self.assertIn("owned_tables_without_migration_ledger", unknown["blockers"])

    def test_partial_expansion_and_future_are_refused(self):
        for version in (12, 13, 14, 15):
            with self.subTest(version=version):
                report = self.inventory(self.rows(version))
                self.assertEqual("unknown", report["classification"])
                self.assertIn("unsupported_or_incomplete_migration_baseline", report["blockers"])
        future = self.rows(16)
        future[1]["rows"].append({"version": 17, "name": "0017_fixture.sql", "sha256": "a" * 64})
        self.assertEqual("newer", self.inventory(future)["classification"])

    def test_mismatched_migration_and_missing_current_table_are_unknown(self):
        rows = self.rows(16)
        rows[1]["rows"][-1]["sha256"] = "b" * 64
        report = self.inventory(rows)
        self.assertEqual("unknown", report["classification"])
        self.assertIn("applied_migration_name_checksum_or_sequence_mismatch", report["blockers"])
        rows = self.rows(16, counts={"unsettled_legacy_outcomes": None})
        report = self.inventory(rows)
        self.assertEqual("unknown", report["classification"])
        self.assertIn("required_metadata_table_missing", report["blockers"])

    def test_malformed_observation_is_unknown_and_opaque(self):
        marker = "private_fixture_marker"
        for value in (True, -1, marker):
            with self.subTest(value=value):
                report = self.inventory(self.rows(16, counts={"unknown_routed_calls": value}))
                self.assertEqual("unknown", report["classification"])
                self.assertNotIn(marker, json.dumps(report))
        rows = self.rows(16)
        rows.append(rows[-1])
        self.assertEqual("unknown", self.inventory(rows)["classification"])
        rows = self.rows(16)
        rows[0]["read_only"] = False
        report = self.inventory(rows)
        self.assertEqual("unknown", report["classification"])
        self.assertNotIn("read_only_transaction", report)

    def test_failed_psql_never_exports_diagnostics(self):
        marker = "private_psql_diagnostic"
        response = subprocess.CompletedProcess(self.command, 1, "", marker)
        with patch.object(preflight.subprocess, "run", return_value=response):
            report = preflight.inventory(self.command)
        self.assertEqual("unknown", report["classification"])
        self.assertNotIn(marker, json.dumps(report))

    def test_fixed_sql_is_read_only_bounded_and_matches_legacy_schema(self):
        sql = preflight.inspection_sql()
        self.assertTrue(sql.startswith("BEGIN TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY;\n"))
        self.assertTrue(sql.endswith("ROLLBACK;\n"))
        self.assertIn("SET LOCAL search_path=pg_catalog", sql)
        self.assertIn("ORDER BY version LIMIT 17", sql)
        self.assertIn("AND relkind='r'", sql)
        for table in ("fleet.routed_call", "fleet.routed_file_call"):
            self.assertIn(f"FROM {table} WHERE state = 7;", sql)
        self.assertIn("FROM management.legacy_outcome WHERE final_at IS NULL OR legacy_state = 7;", sql)
        self.assertNotRegex(sql, r"\b(INSERT|UPDATE|DELETE|CREATE|DROP|ALTER|COMMIT)\b")
        self.assertTrue(all(line.startswith(("BEGIN ", "SET LOCAL ", "SELECT ", "\\if ", "\\else", "\\endif", "ROLLBACK;"))
                            for line in sql.splitlines()))
        migration = (preflight.MIGRATIONS / "0012_management_storage.sql").read_text(encoding="utf-8")
        self.assertIn("CREATE TABLE management.legacy_outcome", migration)
        self.assertIn("CREATE TRIGGER legacy_task_frozen", migration)
        self.assertIn("CREATE TRIGGER legacy_file_frozen", migration)


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
                     "VALUES (17,'0017_fixture.sql',repeat('a',64),0,'fixture')")
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
