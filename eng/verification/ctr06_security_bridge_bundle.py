#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
"""Seal a newly compiled security bridge using the historical source and legal closure.

This is a construction primitive, not publication authority. Its producer identity must be
independently obtained from the protected workflow's actual GitHub context before calling it.
"""
from __future__ import annotations

import hashlib
import io
import json
import os
from pathlib import Path
import re
import subprocess
import stat
import tempfile
import zipfile

import ctr06_bridge_bundle as historical
import ctr06_security_bridge_compiler as compiler


def git(source, *arguments):
    env = {key: value for key, value in os.environ.items() if not key.startswith("GIT_")}
    return subprocess.check_output(["git", *arguments], cwd=source, env=env, timeout=60)


def source_archive(source):
    if (git(source, "rev-parse", "HEAD").decode().strip() != historical.REVISION or
            git(source, "rev-parse", "HEAD^{tree}").decode().strip() != historical.TREE or
            git(source, "status", "--porcelain=v1", "--untracked-files=all").strip()):
        raise ValueError("security bridge source checkout differs")
    archive = git(source, "archive", "--format=tar", historical.REVISION)
    dependencies, notices = historical.source_evidence(archive)
    return archive, dependencies, notices


def security_go_legal(producer_source):
    """Bind the new compiler licence record independently of the historical 1.27.3 source."""
    producer_source = Path(producer_source)
    if not producer_source.is_absolute():
        raise ValueError("producer source must be absolute")
    record_path = producer_source / "eng/provenance/records/go-go-legal-r2.json"
    license_path = producer_source / "third-party/Go.LICENSE.txt"
    for path in (record_path, license_path):
        if path.is_symlink() or not path.is_file():
            raise ValueError("missing or linked security compiler legal source")
    record_bytes, license_bytes = record_path.read_bytes(), license_path.read_bytes()
    def object_pairs(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError("duplicate security legal record key")
            result[key] = value
        return result
    record = json.loads(record_bytes, object_pairs_hook=object_pairs)
    expected_license = "911f8f5782931320f5b8d1160a76365b83aea6447ee6c04fa6d5591467db9dad"
    if (record.get("id") != "go-go-legal-r2" or record.get("kind") != "legal-document" or
            record.get("sourceRepository") != "https://github.com/golang/go" or
            record.get("sourceCommit") != "7b2881024c95a11ddb86663a616340aa3a88b67f" or
            record.get("sourcePaths") != ["LICENSE"] or record.get("supersedes") != "go-go-legal-r1" or
            record.get("licence", {}).get("spdx") != "BSD-3-Clause" or
            record.get("targets") != [{"path": "third-party/Go.LICENSE.txt", "sha256": expected_license, "normalization": "lf"}] or
            hashlib.sha256(license_bytes).hexdigest() != expected_license):
        raise ValueError("security compiler legal source differs")
    return {"notices/security-bridge/go-1.27.4/LICENSE": license_bytes,
            "notices/security-bridge/go-1.27.4/go-go-legal-r2.json": record_bytes}


def inspect_binary(platform, executable, go, dependencies):
    env = compiler.native_environment(platform)
    output = subprocess.check_output([str(go), "version", "-m", str(executable)],
                                     env=env, text=True, timeout=30)
    lines = output.splitlines()
    if not lines or not lines[0].endswith(": go1.27.4"):
        raise ValueError("security bridge binary compiler differs")
    actual_deps, settings, main_path = {}, set(), ""
    for line in lines[1:]:
        parts = line.strip().split("\t")
        if parts[0] == "dep" and len(parts) == 4:
            if parts[1] in actual_deps:
                raise ValueError("duplicate linked bridge dependency")
            actual_deps[parts[1]] = (parts[2], parts[3])
        elif parts[0] == "build" and len(parts) == 2:
            settings.add(parts[1])
        elif parts[0] == "path" and len(parts) == 2:
            main_path = parts[1]
    expected = {m["path"]: (m["version"], m["sum"]) for m in dependencies["runtimeModules"]}
    if platform == "windows":
        expected.pop("golang.org/x/sys")
    if (main_path != "github.com/ArcForges/Cloud/center/cmd/arcforges-center" or actual_deps != expected or
            not {"-trimpath=true", "CGO_ENABLED=0", "GOARCH=amd64", "GOOS=" + platform}.issubset(settings)):
        raise ValueError("security bridge linked closure or build settings differ")
    return {"package": main_path, "dependencies": actual_deps, "settings": sorted(settings), "binaryVersion": "go1.27.4"}


def verify_binary(platform, executable, go, dependencies, identity):
    evidence = inspect_binary(platform, executable, go, dependencies)
    actual = json.loads(subprocess.check_output([str(executable), "version"], env=compiler.native_environment(platform), timeout=30))
    if actual.get("artifact") != identity["artifact"] or actual.get("build") != identity["build"]:
        raise ValueError("security bridge executable build identity differs")
    return {**evidence, "identity": {"artifact": actual["artifact"], "build": actual["build"]}}


def checked_identity(identity):
    if set(identity) != {"schema", "owner", "artifact", "build", "axes"} or identity["schema"] != "arcforges.build-identity.v1" or identity["owner"] != "Cloud":
        raise ValueError("invalid bridge identity shape")
    artifact, build = identity["artifact"], identity["build"]
    if set(artifact) != {"id", "version"} or set(build) != {"sourceCommit", "dirty", "kind", "buildId", "runId", "runAttempt", "pipelineRun", "sourceDateEpoch"}:
        raise ValueError("invalid bridge artifact or build shape")
    run_id, attempt = build["runId"], build["runAttempt"]
    if (not isinstance(run_id, str) or not re.fullmatch(r"[1-9][0-9]{0,14}", run_id) or
            not isinstance(attempt, int) or isinstance(attempt, bool) or attempt < 1 or
            build["buildId"] != f"{run_id}.{attempt}" or
            build["pipelineRun"] != f"https://github.com/ArcForges/Cloud/actions/runs/{run_id}" or
            not isinstance(artifact["version"], str) or
            not re.fullmatch(rf"0\.1\.0-ci\.[1-9][0-9]*\.{attempt}", artifact["version"])):
        raise ValueError("security bridge run identity differs")
    return artifact, build


def build_native(platform, source, archive, go_root, output, identity):
    """Run the real native compiler after verifying its complete official distribution."""
    source, go_root, executable = map(Path, (source, go_root, output))
    if (not all(p.is_absolute() for p in (source, go_root, executable)) or executable.exists() or
            executable.resolve().is_relative_to(source.resolve())):
        raise ValueError("native build requires absolute source, compiler and new outside output")
    compiler_evidence = compiler.verify_compiler(archive, go_root, platform)
    go = go_root / "bin" / ("go.exe" if platform == "windows" else "go")
    source_archive(source)
    checked_identity(identity)
    prefix = "github.com/ArcForges/Cloud/center/internal/buildinfo."
    build = identity["build"]
    fields = {"appVersion": identity["artifact"]["version"], "sourceCommit": build["sourceCommit"],
              "sourceDirty": "false", "buildKind": build["kind"], "buildID": build["buildId"],
              "pipelineRun": build["pipelineRun"], "sourceEpoch": str(build["sourceDateEpoch"])}
    if (identity["artifact"]["id"] != "Cloud" or build["sourceCommit"] != historical.REVISION or
            build["dirty"] is not False or build["kind"] != "ci" or
            not re.fullmatch(r"0\.1\.0-ci\.[1-9][0-9]*\.[1-9][0-9]*", fields["appVersion"]) or
            not re.fullmatch(r"[1-9][0-9]*\.[1-9][0-9]*", fields["buildID"]) or
            not re.fullmatch(r"https://github\.com/ArcForges/Cloud/actions/runs/[1-9][0-9]*", fields["pipelineRun"]) or
            fields["sourceEpoch"] != "1794319148"):
        raise ValueError("invalid security bridge build identity")
    flags = "-s -w " + " ".join("-X=" + prefix + key + "=" + value for key, value in fields.items())
    env = compiler.native_environment(platform)
    def verify_modules():
        output = subprocess.check_output([str(go), "mod", "verify"], cwd=Path(source) / "center",
                                         env=env, text=True, timeout=120)
        if output.strip() != "all modules verified":
            raise ValueError("unexpected Go module verification result")

    # The driver returns a single JSON document on stdout. Go's actual module
    # verification is checked both before and after, without mixing its text into it.
    verify_modules()
    subprocess.run([str(go), "build", "-trimpath", "-buildvcs=false", "-ldflags", flags,
                    "-o", str(executable), "./cmd/arcforges-center"],
                   cwd=Path(source) / "center", env=env, check=True, stdout=subprocess.PIPE, timeout=300)
    verify_modules()
    archive_bytes, dependencies, _ = source_archive(source)
    binary_evidence = verify_binary(platform, executable, go, dependencies, identity)
    return {"flags": flags, "compiler": compiler_evidence, "binary": binary_evidence,
            "binarySha256": compiler.digest_file(executable),
            "sourceArchiveSha256": hashlib.sha256(archive_bytes).hexdigest()}


def seal_native(platform, source, producer_source, executable, archive_path, go_root, producer, identity, expected_binary_sha256, output):
    """Seal a native build; the caller retains the protected producer's evidence separately."""
    source, executable, go_root, output = map(Path, (source, executable, go_root, output))
    go = go_root / "bin" / ("go.exe" if platform == "windows" else "go")
    if (platform not in ("linux", "windows") or not all(p.is_absolute() for p in (source, executable, go, output)) or
            output.exists() or not output.parent.is_dir() or executable.is_symlink() or not executable.is_file()):
        raise ValueError("invalid security bridge bundle paths")
    compiler_evidence = compiler.verify_compiler(archive_path, go_root, platform)
    checked_identity(identity)
    if (producer.get("runId") != identity["build"]["runId"] or
            producer.get("runAttempt") != identity["build"]["runAttempt"] or
            identity["artifact"]["version"] != f"0.1.0-ci.{producer.get('runNumber')}.{producer.get('runAttempt')}"):
        raise ValueError("producer and bridge run identities differ")
    archive, dependencies, notices = source_archive(source)
    binary = executable.read_bytes()
    if (len(binary) > 100 * 1024 * 1024 or not re.fullmatch(r"[0-9a-f]{64}", expected_binary_sha256) or
            hashlib.sha256(binary).hexdigest() != expected_binary_sha256):
        raise ValueError("security bridge binary differs from the verified build")
    build = verify_binary(platform, executable, go, dependencies, identity)
    exe_name = "arcforges-center.exe" if platform == "windows" else "arcforges-center"
    files = {"source.tar": archive, exe_name: binary, **notices, **security_go_legal(producer_source)}
    manifest = {
        "schema": "arcforges.ctr06-security-bridge-native.v1",
        "source": {"repository": "https://github.com/ArcForges/Cloud", "commit": historical.REVISION,
                   "tree": historical.TREE, "archiveSha256": historical.SOURCE_SHA256},
        "producer": producer,
        "identity": {"artifact": identity["artifact"], "build": identity["build"]},
        "historicalSourceGoVersion": dependencies["goVersion"],
        "actualCompiler": {k: v for k, v in compiler_evidence.items() if k != "root"},
        "contracts": {"module": "github.com/ArcForges/Contracts/go", "version": "v1.0.0-ci.437.1"},
        "binary": {"platform": platform + "/amd64", "name": exe_name, "sha256": hashlib.sha256(binary).hexdigest(),
                   "build": build},
        "files": {name: {"sha256": hashlib.sha256(data).hexdigest(), "size": len(data)}
                  for name, data in sorted(files.items())},
    }
    files["manifest.json"] = json.dumps(manifest, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode() + b"\n"
    with zipfile.ZipFile(output, "x", compression=zipfile.ZIP_STORED) as writer:
        for name, data in sorted(files.items()):
            item = zipfile.ZipInfo(name, (1980, 1, 1, 0, 0, 0))
            item.create_system = 3
            item.external_attr = ((0o100755 if name == exe_name else 0o100644) << 16)
            writer.writestr(item, data)
    return {"sha256": compiler.digest_file(output), "size": output.stat().st_size,
            "manifestSha256": hashlib.sha256(files["manifest.json"]).hexdigest()}


def _verify_bundle(platform, bundle, producer_source, go, expected_compiler, producer, identity, expected_binary_sha256, native):
    """Read the sealed ZIP independently and verify every member and the real native binary."""
    bundle, go = Path(bundle), Path(go)
    if platform not in ("linux", "windows") or not bundle.is_absolute() or not go.is_absolute():
        raise ValueError("invalid bridge verification paths")
    checked_identity(identity)
    exe_name = "arcforges-center.exe" if platform == "windows" else "arcforges-center"
    if bundle.is_symlink() or getattr(bundle, "is_junction", lambda: False)():
        raise ValueError("linked bridge bundle")
    fd = os.open(bundle, os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0))
    with os.fdopen(fd, "rb") as stream:
        before = os.fstat(stream.fileno())
        if not stat.S_ISREG(before.st_mode) or before.st_size > 256 * 1024 * 1024:
            raise ValueError("invalid bridge bundle object")
        bundle_bytes = stream.read(256 * 1024 * 1024 + 1)
        after = os.fstat(stream.fileno())
        current = os.stat(bundle, follow_symlinks=False)
        if (len(bundle_bytes) != before.st_size or
                (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns) !=
                (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns) or
                (after.st_dev, after.st_ino) != (current.st_dev, current.st_ino)):
            raise ValueError("bridge bundle changed while reading")
    with zipfile.ZipFile(io.BytesIO(bundle_bytes)) as reader:
        entries = reader.infolist()
        names = [item.filename for item in entries]
        if len(names) != len(set(names)) or names != sorted(names):
            raise ValueError("duplicate or unordered bridge bundle member")
        for item in entries:
            expected_mode = 0o100755 if item.filename == exe_name else 0o100644
            if (item.is_dir() or item.compress_type != zipfile.ZIP_STORED or item.date_time != (1980, 1, 1, 0, 0, 0) or
                    item.create_system != 3 or item.external_attr >> 16 != expected_mode or item.file_size > 100 * 1024 * 1024):
                raise ValueError("invalid bridge bundle member metadata")
        if "source.tar" not in names or exe_name not in names or "manifest.json" not in names:
            raise ValueError("bridge bundle is incomplete")
        archive = reader.read("source.tar")
        dependencies, notices = historical.source_evidence(archive)
        notices.update(security_go_legal(producer_source))
        if set(names) != {"source.tar", exe_name, "manifest.json", *notices}:
            raise ValueError("bridge bundle has unclassified members")
        for name, data in notices.items():
            if reader.read(name) != data:
                raise ValueError("bridge bundle legal material differs")
        manifest = json.loads(reader.read("manifest.json"))
        if (set(manifest) != {"schema", "source", "producer", "identity", "historicalSourceGoVersion", "actualCompiler", "contracts", "binary", "files"} or
                manifest.get("schema") != "arcforges.ctr06-security-bridge-native.v1" or
                manifest.get("producer") != producer or
                manifest.get("identity") != {"artifact": identity["artifact"], "build": identity["build"]} or
                manifest.get("actualCompiler") != {k: v for k, v in expected_compiler.items() if k != "root"} or
                manifest.get("source") != {"repository": "https://github.com/ArcForges/Cloud",
                                           "commit": historical.REVISION, "tree": historical.TREE,
                                           "archiveSha256": historical.SOURCE_SHA256} or
                manifest.get("historicalSourceGoVersion") != "go1.27.3" or
                manifest.get("contracts") != {"module": "github.com/ArcForges/Contracts/go", "version": "v1.0.0-ci.437.1"}):
            raise ValueError("bridge bundle identity differs")
        files = {name: reader.read(name) for name in names if name != "manifest.json"}
        expected_files = {name: {"sha256": hashlib.sha256(data).hexdigest(), "size": len(data)}
                          for name, data in sorted(files.items())}
        if manifest.get("files") != expected_files:
            raise ValueError("bridge bundle member digest differs")
        if (not re.fullmatch(r"[0-9a-f]{64}", expected_binary_sha256) or
                hashlib.sha256(files[exe_name]).hexdigest() != expected_binary_sha256):
            raise ValueError("bridge bundle binary is not the independently verified build")
        with tempfile.TemporaryDirectory(prefix="ctr06-security-bridge-verify-") as temporary:
            executable = Path(temporary) / exe_name
            executable.write_bytes(files[exe_name])
            if os.name != "nt":
                executable.chmod(0o700)
            if native:
                build = verify_binary(platform, executable, go, dependencies, identity)
            else:
                # Cross-host readback can inspect PE metadata, but cannot prove Windows execution.
                # The protected native job must already have executed and bound this exact digest.
                if platform != "windows":
                    raise ValueError("non-native readback is restricted to a Windows native-job artifact")
                build = {**inspect_binary(platform, executable, go, dependencies),
                         "identity": {"artifact": identity["artifact"], "build": identity["build"]}}
        expected_binary = {"platform": platform + "/amd64", "name": exe_name,
                           "sha256": hashlib.sha256(files[exe_name]).hexdigest(), "build": build}
        if json.loads(json.dumps(expected_binary)) != manifest.get("binary"):
            raise ValueError("bridge bundle executable evidence differs")
    return {"sha256": hashlib.sha256(bundle_bytes).hexdigest(), "size": len(bundle_bytes),
            "members": len(names), "binarySha256": expected_binary["sha256"]}


def verify_native_bundle(platform, bundle, producer_source, go, expected_compiler, producer, identity, expected_binary_sha256):
    return _verify_bundle(platform, bundle, producer_source, go, expected_compiler, producer, identity, expected_binary_sha256, True)


def verify_windows_from_native_job(bundle, producer_source, go, expected_compiler, producer, identity, expected_binary_sha256):
    """Only for readback of an authenticated same-run Windows job; this does not execute PE."""
    return _verify_bundle("windows", bundle, producer_source, go, expected_compiler, producer, identity, expected_binary_sha256, False)
