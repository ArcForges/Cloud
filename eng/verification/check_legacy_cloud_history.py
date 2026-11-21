#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
"""Attest the reviewed Cloud history without building or running its legacy host."""
from __future__ import annotations

import io
import json
import os
from argparse import ArgumentParser
from pathlib import Path
import subprocess
import sys
import tarfile

from ctr06_bridge_bundle import archive_file, digest
from ctr06_security_bridge_native_check import environment

ROOT = Path(__file__).resolve().parents[2]
COMMIT = "9b8796eac760982d9814f371b820b736ddd945c4"
TREE = "2b35c50007089d6e6c51797f62437334bd2826f3"
SOURCE_SHA256 = "536d12a42b9141cd3a61f3c3c5796095948b16c21a1b557d28f9e056896761da"
D1_MIGRATIONS = "src/ArcForges.Cloud.Storage.D1/Migrations"
PROOF_MIGRATIONS = "worker/proof-migrations"
D1_PLAN_TREES = ("storage/plans", "src/ArcForges.Cloud.Storage.D1/Physical/manifest")
D1_PLAN_OUTPUTS = ("worker/storage/plans.generated.ts", "src/ArcForges.Cloud.Storage.D1/PlanManifest.g.cs")
RESOLVER_VECTORS = "center/internal/entitlement/testdata/csharp-resolver-vectors.json"
ARCHIVES = {
    "d1Migrations": (
        (D1_MIGRATIONS,),
        "9d2ff204bce284b2e276d51f9b412420a18d357e96ba8be02f114a6e4fa67a23",
    ),
    "proofMigrations": (
        (PROOF_MIGRATIONS,),
        "305d240ff067b6031b5d57dc4c30a92d9a23429437419ccaef46214d9edf08ae",
    ),
    "generation": (
        ("tools/ArcForges.Cloud.Generation", "storage/plans",
         "worker/storage/plans.generated.ts", "worker/tables/cloud-tables.generated.ts",
         "eng/generated/contracts-identity.json"),
        "5255d848c6e8143d1e6afcdc9a8a6cec12399008aabe3067d3636d3163b5dc86",
    ),
    "entitlement": (
        ("src/ArcForges.Cloud.Modules.Entitlement", "tests/ArcForges.Cloud.Tests/Entitlement",
         "storage/plans/entitlement", RESOLVER_VECTORS),
        "7b898e44e35bdafc51f3d9bfede8929cc5d6f0d85519e99ab29fd613b99560b1",
    ),
}


def local_git(root: Path, *args: str) -> bytes:
    env = environment()
    env.update(GIT_CONFIG_NOSYSTEM="1", GIT_CONFIG_GLOBAL=os.devnull,
               GIT_NO_LAZY_FETCH="1", GIT_TERMINAL_PROMPT="0")
    return subprocess.check_output(
        ["git", "--no-replace-objects", "-c", "tar.umask=0002", *args],
        cwd=root, env=env, timeout=60,
    )


def check_archive(root: Path, expected: str, paths: tuple[str, ...] = ()) -> bytes:
    data = local_git(root, "archive", "--format=tar", COMMIT, "--", *paths)
    if digest(data) != expected:
        raise ValueError("reviewed Cloud archive differs: " + (", ".join(paths) or "full source"))
    return data


def check_retained_tree(root: Path, archive: tarfile.TarFile, directory: str) -> int:
    directories: dict[str, dict[str, tarfile.TarInfo]] = {}
    for member in archive.getmembers():
        if member.name.startswith(directory + "/"):
            parent, _, name = member.name.rpartition("/")
            directories.setdefault(parent, {})[name] = member
    if directory not in directories:
        raise ValueError("retained historical inventory differs: " + directory)
    files = 0
    # Inspect only directories enumerated by the admitted archive, including each parent first.
    for parent, expected in sorted(directories.items()):
        path = root / parent
        if path.is_symlink() or path.is_junction() or not path.is_dir() or path.resolve(strict=True) != path:
            raise ValueError("retained historical directory differs: " + parent)
        actual = {entry.name: entry for entry in path.iterdir()}
        if actual.keys() != expected.keys():
            raise ValueError("retained historical inventory differs: " + parent)
        for name, member in expected.items():
            entry = actual[name]
            if entry.is_symlink() or entry.is_junction():
                raise ValueError("retained historical entry differs: " + member.name)
            if member.isfile():
                check_retained_file(root, archive, member.name)
                files += 1
            elif not member.isdir() or not entry.is_dir():
                raise ValueError("retained historical entry differs: " + member.name)
    return files


def check_retained(root: Path, archive: tarfile.TarFile) -> dict[str, int]:
    """Verify immutable histories, retired generator inputs and outputs, and Go parity data."""
    retained = {directory: check_retained_tree(root, archive, directory)
                for directory in (D1_MIGRATIONS, PROOF_MIGRATIONS, *D1_PLAN_TREES)}
    for name in (*D1_PLAN_OUTPUTS, RESOLVER_VECTORS):
        check_retained_file(root, archive, name)
        retained[name] = 1
    return retained


def check_retained_file(root: Path, archive: tarfile.TarFile, name: str) -> None:
    path = root / name
    if path.is_symlink() or not path.is_file() or path.resolve(strict=True) != path:
        raise ValueError("retained historical file differs: " + name)
    expected = archive_file(archive, name)
    if path.stat().st_size != len(expected) or path.read_bytes() != expected:
        raise ValueError("retained historical file differs: " + name)


def attest(root: Path, *, migrations_only: bool = False) -> dict[str, object]:
    if Path(os.fsdecode(local_git(root, "rev-parse", "--show-toplevel").strip())).resolve() != root:
        raise ValueError("Cloud Git root differs")
    if local_git(root, "rev-parse", "--verify", f"{COMMIT}^{{tree}}").decode("ascii").strip() != TREE:
        raise ValueError("reviewed Cloud tree differs")
    retained = {}
    if not migrations_only:
        source = check_archive(root, SOURCE_SHA256)
        with tarfile.open(fileobj=io.BytesIO(source), mode="r:") as archive:
            retained = check_retained(root, archive)
    archives = {}
    for name, (paths, expected) in ARCHIVES.items():
        if migrations_only and name not in ("d1Migrations", "proofMigrations"):
            continue
        data = check_archive(root, expected, paths)
        archives[name] = {"paths": list(paths), "bytes": len(data), "sha256": expected}
        if migrations_only:
            with tarfile.open(fileobj=io.BytesIO(data), mode="r:") as archive:
                retained[paths[0]] = check_retained_tree(root, archive, paths[0])
    report = {"schemaVersion": 1, "sourceCommit": COMMIT, "sourceTree": TREE,
              "archives": archives, "retained": retained}
    if migrations_only:
        report["scope"] = "d1-migrations"
    else:
        report["sourceSha256"] = SOURCE_SHA256
    return report


if __name__ == "__main__":
    parser = ArgumentParser(description=__doc__)
    parser.add_argument("--migrations-only", action="store_true",
                        help="Verify only the reviewed D1 and proof migration inventories.")
    args = parser.parse_args()
    try:
        print(json.dumps(attest(ROOT, migrations_only=args.migrations_only), indent=2))
    except (OSError, ValueError, KeyError, subprocess.SubprocessError, tarfile.TarError) as error:
        sys.exit(f"Legacy Cloud history check failed: {error}")
