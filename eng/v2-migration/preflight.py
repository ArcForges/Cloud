# SPDX-License-Identifier: AGPL-3.0-only
"""Inventory Center migration metadata in one PostgreSQL READ ONLY transaction."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import re
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[2]
MIGRATIONS = ROOT / "center/internal/schema/migrations"
IDENTIFIER = re.compile(r"[A-Za-z_][A-Za-z0-9_.-]{0,127}\Z")
COUNTS = {
    "pending_commands": ("platform.command_receipt", "status = 1"),
    "pending_inbox": ("platform.inbox", "processed_at IS NULL"),
    "undispatched_outbox": ("platform.outbox", "state <> 2"),
    "unsettled_jobs": ("platform.job_lease", "state <> 3"),
    "live_hub_lease": ("fleet.hub_lease", "expires_at > transaction_timestamp()"),
    "unsettled_routed_calls": ("fleet.routed_call", "final_at IS NULL"),
    "unsettled_routed_file_calls": ("fleet.routed_file_call", "final_at IS NULL"),
    "runtime_floor_rows": ("platform.ctr06_runtime_floor", "true"),
    "restore_admission_rows": ("platform.ctr06_restore_admission", "true"),
    "unready_restore_admission": ("platform.ctr06_restore_admission", "state <> 'READY'"),
    "floor_wrong_database": ("platform.ctr06_runtime_floor", "database_oid <> (SELECT oid FROM pg_database WHERE datname=current_database())"),
}
PREREQUISITES = [
    "operator-confirmed installed cohort, authority inventory and security-successor qualification (H-03)",
    "exclusive maintenance ownership, stopped hub/runtime sessions and settled routed effects",
    "consistent approved backup plus tested restore preserving receipts and credential/recovery floors",
    "AFV2-CENTER-01 guarded fresh/schema10/schema11 migration and restore qualification",
    "retain applied 0001..0011 SQL/checksums and published artifacts",
]


def migration_sources() -> list[dict]:
    result = []
    for version, path in enumerate(sorted(MIGRATIONS.glob("*.sql")), 1):
        if not path.name.startswith(f"{version:04d}_"):
            raise ValueError("source_migration_sequence_invalid")
        result.append({"version": version, "name": path.name,
                       "sha256": hashlib.sha256(path.read_text(encoding="utf-8").encode("utf-8")).hexdigest()})
    if len(result) != 11:
        raise ValueError("source_migration_baseline_changed_requires_review")
    return result


def inspection_sql() -> str:
    # psql conditionals keep absent objects out of PostgreSQL's query parse tree.
    # All SQL text and identifiers are fixed here; no credential/table/query input is accepted.
    parts = ["BEGIN TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY;",
             "SET LOCAL statement_timeout='5s'; SET LOCAL lock_timeout='1s';",
             "SELECT json_build_object('kind','transaction','read_only',current_setting('transaction_read_only')='on',"
             "'other_sessions',(SELECT count(*) FROM pg_stat_activity WHERE datname=current_database() AND pid<>pg_backend_pid() AND backend_type='client backend'),"
             "'migration_locks',(SELECT count(*) FROM pg_locks WHERE locktype='advisory' AND granted AND classid=1634886502 AND objid=1869768549 AND database=(SELECT oid FROM pg_database WHERE datname=current_database())),"
             "'owned_tables',(SELECT count(*) FROM pg_tables WHERE schemaname IN ('platform','audit','fleet','identity','device','entitlement')));",
             "SELECT to_regclass('platform.schema_migration') IS NOT NULL AS has_ledger \\gset",
             "\\if :has_ledger",
             "SELECT json_build_object('kind','ledger','rows',coalesce(json_agg(json_build_object('version',version,'name',name,'sha256',sha256) ORDER BY version),'[]'::json)) FROM platform.schema_migration;",
             "\\else", "SELECT json_build_object('kind','ledger','rows',NULL);", "\\endif"]
    for name, (table, predicate) in COUNTS.items():
        parts.extend([f"SELECT to_regclass('{table}') IS NOT NULL AS has_table \\gset", "\\if :has_table",
                      f"SELECT json_build_object('kind','count','name','{name}','value',count(*)) FROM {table} WHERE {predicate};",
                      "\\else", f"SELECT json_build_object('kind','count','name','{name}','value',NULL);", "\\endif"])
    parts.append("ROLLBACK;")
    return "\n".join(parts) + "\n"


def psql(command: list[str], sql: str) -> list[dict]:
    result = subprocess.run(command, input=sql, capture_output=True, text=True, timeout=35)
    if result.returncode != 0:
        # PostgreSQL errors may contain a connection URL, role details or data. Keep them local.
        raise ValueError("postgres_inspection_failed_or_locked")
    return [json.loads(line) for line in result.stdout.splitlines() if line.strip()]


def inventory(command: list[str]) -> dict:
    report = {"schema": 1, "kind": "arcforges-v2-center-preflight", "classification": "unknown",
              "deployment": "unknown", "destructive_contraction_allowed": False,
              "prerequisites": PREREQUISITES, "counts": {}, "blockers": [], "applied_migrations": []}
    blockers = report["blockers"]
    try:
        source = migration_sources()
        report["source_migrations"] = source
        rows = psql(command, inspection_sql())
        transaction = next(row for row in rows if row["kind"] == "transaction")
        if transaction["read_only"] is not True:
            raise ValueError("transaction_read_only_not_established")
        report["read_only_transaction"] = True
        for key in ("other_sessions", "migration_locks"):
            report["counts"][key] = transaction[key]
            if transaction[key]:
                blockers.append(key)
        applied = next(row["rows"] for row in rows if row["kind"] == "ledger")
        if applied is None:
            if transaction["owned_tables"] == 0:
                report["classification"] = "fresh"
                blockers.append("fresh_database_requires_guarded_initialization")
            else:
                blockers.append("owned_tables_without_migration_ledger")
            return report
        if any(type(row.get("version")) is not int or not re.fullmatch(r"[0-9]{4}_[a-z0-9_]+[.]sql", str(row.get("name", "")))
               or not re.fullmatch(r"[a-f0-9]{64}", str(row.get("sha256", ""))) for row in applied):
            raise ValueError("invalid_migration_ledger")
        report["applied_migrations"] = applied
        versions = [row["version"] for row in applied]
        if versions and max(versions) > 11:
            report["classification"] = "newer"
            blockers.append("newer_database_refused")
            return report
        if versions != list(range(1, len(applied) + 1)) or applied != source[:len(applied)]:
            blockers.append("applied_migration_name_checksum_or_sequence_mismatch")
            return report
        if len(applied) not in {10, 11}:
            blockers.append("unsupported_or_incomplete_migration_baseline")
            return report
        report["classification"] = f"center{len(applied)}"
        report["migration_ledger_matches_source"] = True
        for row in rows:
            if row["kind"] == "count":
                report["counts"][row["name"]] = row["value"]
        required = {name for name in COUNTS if len(applied) == 11 or name not in {
            "unsettled_routed_file_calls", "runtime_floor_rows", "restore_admission_rows", "unready_restore_admission", "floor_wrong_database"}}
        if any(report["counts"].get(name) is None for name in required):
            report["classification"] = "unknown"
            blockers.append("required_metadata_table_missing")
            return report
        for name, value in report["counts"].items():
            if name not in {"runtime_floor_rows", "restore_admission_rows"} and value:
                blockers.append(name)
        if len(applied) == 10:
            blockers.append("schema10_requires_0011_security_successor_admission_not_simple_append")
        elif report["counts"]["runtime_floor_rows"] != 1 or report["counts"]["restore_admission_rows"] != 1:
            blockers.append("schema11_runtime_floor_or_restore_admission_unproven")
        report["authority_and_full_schema_identity"] = "unproven_requires_guarded_runner_qualification"
        blockers.append("deployment_cohort_backup_and_authority_qualification_required")
    except (OSError, subprocess.SubprocessError, ValueError, KeyError, TypeError, StopIteration):
        report["classification"] = "unknown"
        blockers.append("postgres_inspection_failed_or_locked")
    return report


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--container", help="Optional existing local PostgreSQL fixture container; never creates a container")
    parser.add_argument("--database", required=True, help="Database name; connection settings/credentials remain in psql's environment")
    parser.add_argument("--user", help="Optional role name; no password/URL argument is accepted")
    args = parser.parse_args()
    for value in (args.database, args.container, args.user):
        if value is not None and not IDENTIFIER.fullmatch(value):
            parser.error("names must be bounded plain identifiers; URLs/passwords are not accepted")
    command = ["docker", "exec", "-i", args.container] if args.container else []
    command += ["psql", "-X", "-qAt", "-w", "-v", "ON_ERROR_STOP=1", "--dbname", args.database]
    if args.user:
        command += ["--username", args.user]
    report = inventory(command)
    print(json.dumps(report, indent=2, sort_keys=True))
    return 2 if report["classification"] in {"unknown", "newer"} else 0


if __name__ == "__main__":
    sys.exit(main())
