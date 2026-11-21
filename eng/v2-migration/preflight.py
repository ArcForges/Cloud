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
HISTORICAL_SCHEMA = 11
EXPANDED_SCHEMA = 16
CURRENT_SCHEMA = 17
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
SCHEMA11_COUNTS = frozenset({"unsettled_routed_file_calls", "runtime_floor_rows", "restore_admission_rows",
                            "unready_restore_admission", "floor_wrong_database"})
CURRENT_COUNTS = {
    "unknown_routed_calls": ("fleet.routed_call", "state = 7"),
    "unknown_routed_file_calls": ("fleet.routed_file_call", "state = 7"),
    "unsettled_legacy_outcomes": ("management.legacy_outcome", "final_at IS NULL OR legacy_state = 7"),
    "unknown_legacy_outcomes": ("management.legacy_outcome", "legacy_state = 7"),
}
LEGACY_SOURCE_COUNTS = frozenset({"unsettled_routed_calls", "unsettled_routed_file_calls",
                                  "unknown_routed_calls", "unknown_routed_file_calls"})
CONTRACTED_COUNTS = {name: count for name, count in CURRENT_COUNTS.items() if name not in LEGACY_SOURCE_COUNTS}
CONTRACTED_COUNTS["ready_contraction_receipts"] = ("management.cutover_receipt", "target_schema = 17 AND phase = 4")
RETIRED_RELATIONS = ("fleet.routed_call", "fleet.routed_file_call", "fleet.routed_file_target",
                     "fleet.routed_command_id", "fleet.refusal_code", "identity.mobile_authorization")
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
    if len(result) != CURRENT_SCHEMA:
        raise ValueError("source_migration_baseline_changed_requires_review")
    return result


def inspection_sql() -> str:
    # psql conditionals keep absent objects out of PostgreSQL's query parse tree.
    # All SQL text and identifiers are fixed here; no credential/table/query input is accepted.
    parts = ["BEGIN TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY;",
             "SET LOCAL statement_timeout='5s'; SET LOCAL lock_timeout='1s'; SET LOCAL search_path=pg_catalog;",
             "SELECT json_build_object('kind','transaction','read_only',current_setting('transaction_read_only')='on',"
             "'other_sessions',(SELECT count(*) FROM pg_stat_activity WHERE datname=current_database() AND pid<>pg_backend_pid() AND backend_type='client backend'),"
             "'migration_locks',(SELECT count(*) FROM pg_locks WHERE locktype='advisory' AND granted AND classid=1634886502 AND objid=1869768549 AND database=(SELECT oid FROM pg_database WHERE datname=current_database())),"
             "'owned_tables',(SELECT count(*) FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace "
             "WHERE n.nspname IN ('platform','audit','fleet','identity','device','entitlement','management','commerce') "
             "AND c.relkind IN ('r','p','v','m','f','S')));",
             table_exists_sql("platform.schema_migration", "has_ledger"),
             "\\if :has_ledger",
             "SELECT json_build_object('kind','ledger','rows',coalesce(json_agg(json_build_object('version',version,'name',name,'sha256',sha256) ORDER BY version),'[]'::json)) "
             "FROM (SELECT version, CASE WHEN length(name)<=128 THEN name END AS name, "
             "CASE WHEN length(sha256)=64 THEN sha256 END AS sha256 FROM platform.schema_migration "
             f"ORDER BY version LIMIT {CURRENT_SCHEMA + 1}) AS observed;",
             f"SELECT count(*)={EXPANDED_SCHEMA} AND min(version)=1 AND max(version)={EXPANDED_SCHEMA} AS inspect_expanded, "
             f"count(*)={CURRENT_SCHEMA} AND min(version)=1 AND max(version)={CURRENT_SCHEMA} AS inspect_contracted "
             f"FROM (SELECT version FROM platform.schema_migration ORDER BY version LIMIT {CURRENT_SCHEMA + 1}) AS observed \\gset",
             "\\else", "SELECT json_build_object('kind','ledger','rows',NULL);",
             "SELECT false AS inspect_expanded, false AS inspect_contracted \\gset", "\\endif"]
    parts.extend(count_sql(COUNTS))
    retired = ",".join(f"'{name}'" for name in RETIRED_RELATIONS)
    parts.extend(["\\if :inspect_expanded", *count_sql(CURRENT_COUNTS), "\\endif",
                  "\\if :inspect_contracted", *count_sql(CONTRACTED_COUNTS),
                  "SELECT json_build_object('kind','count','name','retired_relations_present','value',count(*)) "
                  f"FROM unnest(ARRAY[{retired}]) AS retired(name) WHERE to_regclass(name) IS NOT NULL;",
                  "\\endif", "ROLLBACK;"])
    return "\n".join(parts) + "\n"


def table_exists_sql(table: str, variable: str) -> str:
    # Only ordinary tables from the shipped schema are expected. Avoid reading a replacement view or foreign table.
    return f"SELECT EXISTS (SELECT 1 FROM pg_class WHERE oid=to_regclass('{table}') AND relkind='r') AS {variable} \\gset"


def count_sql(counts: dict[str, tuple[str, str]]) -> list[str]:
    parts = []
    for name, (table, predicate) in counts.items():
        parts.extend([table_exists_sql(table, "has_table"), "\\if :has_table",
                      f"SELECT json_build_object('kind','count','name','{name}','value',count(*)) FROM {table} WHERE {predicate};",
                      "\\else", f"SELECT json_build_object('kind','count','name','{name}','value',NULL);", "\\endif"])
    return parts


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
        report["source_migrations"] = source[:HISTORICAL_SCHEMA]
        rows = psql(command, inspection_sql())
        transaction, ledger, *observations = rows
        if (set(transaction) != {"kind", "read_only", "other_sessions", "migration_locks", "owned_tables"}
                or transaction["kind"] != "transaction" or set(ledger) != {"kind", "rows"} or ledger["kind"] != "ledger"
                or any(type(transaction[key]) is not int or transaction[key] < 0
                       for key in ("other_sessions", "migration_locks", "owned_tables"))):
            raise ValueError("invalid_inventory_metadata")
        if transaction["read_only"] is not True:
            raise ValueError("transaction_read_only_not_established")
        report["read_only_transaction"] = True
        for key in ("other_sessions", "migration_locks"):
            report["counts"][key] = transaction[key]
            if transaction[key]:
                blockers.append(key)
        applied = ledger["rows"]
        if applied is None:
            if transaction["owned_tables"] == 0:
                report["classification"] = "fresh"
                blockers.append("fresh_database_requires_guarded_initialization")
            else:
                blockers.append("owned_tables_without_migration_ledger")
            return report
        if (not isinstance(applied, list) or len(applied) > CURRENT_SCHEMA + 1
                or any(not isinstance(row, dict) or set(row) != {"version", "name", "sha256"}
                       or type(row["version"]) is not int or not 0 < row["version"]
                       or not isinstance(row["name"], str) or not re.fullmatch(r"[0-9]{4}_[a-z0-9_]{1,119}[.]sql", row["name"])
                       or not isinstance(row["sha256"], str) or not re.fullmatch(r"[a-f0-9]{64}", row["sha256"]) for row in applied)):
            raise ValueError("invalid_migration_ledger")
        versions = [row["version"] for row in applied]
        report["applied_migrations"] = applied
        if versions and max(versions) > HISTORICAL_SCHEMA:
            report["source_migrations"] = source[:max(versions)]
        if versions and max(versions) > CURRENT_SCHEMA:
            report["classification"] = "newer"
            blockers.append("newer_database_refused")
            return report
        if versions != list(range(1, len(applied) + 1)) or applied != source[:len(applied)]:
            blockers.append("applied_migration_name_checksum_or_sequence_mismatch")
            return report
        version = len(applied)
        if version not in {10, HISTORICAL_SCHEMA, EXPANDED_SCHEMA, CURRENT_SCHEMA}:
            blockers.append("unsupported_or_incomplete_migration_baseline")
            return report
        report["classification"] = f"center{version}"
        report["migration_ledger_matches_source"] = True
        expected = set(COUNTS)
        if version == EXPANDED_SCHEMA:
            expected.update(CURRENT_COUNTS)
        if version == CURRENT_SCHEMA:
            expected.update(CONTRACTED_COUNTS)
            expected.add("retired_relations_present")
        count_values = observed_counts(observations, expected)
        report["counts"].update(count_values)
        required = expected - SCHEMA11_COUNTS if version == 10 else expected
        if version == CURRENT_SCHEMA:
            required -= LEGACY_SOURCE_COUNTS
        if any(report["counts"].get(name) is None for name in required):
            report["classification"] = "unknown"
            blockers.append("required_metadata_table_missing")
            return report
        if version == CURRENT_SCHEMA and (count_values["retired_relations_present"] != 0
                                          or count_values["ready_contraction_receipts"] != 1):
            report["classification"] = "unknown"
            blockers.append("contracted_schema_identity_unproven")
            return report
        for name, value in report["counts"].items():
            if name not in {"runtime_floor_rows", "restore_admission_rows", "ready_contraction_receipts"} and value:
                blockers.append(name)
        if version == 10:
            blockers.append("schema10_requires_0011_security_successor_admission_not_simple_append")
        elif report["counts"]["runtime_floor_rows"] != 1 or report["counts"]["restore_admission_rows"] != 1:
            blockers.append(f"schema{version}_runtime_floor_or_restore_admission_unproven")
        if version >= EXPANDED_SCHEMA:
            report["prerequisites"] = [*PREREQUISITES[:-1],
                                       f"retain applied 0001..{version:04d} SQL/checksums and published artifacts"]
        report["authority_and_full_schema_identity"] = "unproven_requires_guarded_runner_qualification"
        blockers.append("deployment_cohort_backup_and_authority_qualification_required")
    except (OSError, subprocess.SubprocessError, ValueError, KeyError, TypeError, StopIteration):
        report["classification"] = "unknown"
        blockers.append("postgres_inspection_failed_or_locked")
    return report


def observed_counts(rows: list[dict], expected: set[str]) -> dict[str, int | None]:
    counts = {}
    for row in rows:
        if (not isinstance(row, dict) or set(row) != {"kind", "name", "value"} or row["kind"] != "count"
                or not isinstance(row["name"], str) or row["name"] not in expected or row["name"] in counts
                or (row["value"] is not None and (type(row["value"]) is not int or row["value"] < 0))):
            raise ValueError("invalid_inventory_counts")
        counts[row["name"]] = row["value"]
    return counts


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
