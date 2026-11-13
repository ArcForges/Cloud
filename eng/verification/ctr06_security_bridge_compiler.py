#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
"""Verify the complete native Go 1.27.4 toolchain against the fixed official archive.

This checks construction inputs; it does not authorize a release or a deployment.
The existing Go 1.27.3 bridge remains a separately identified historical artifact.
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import stat
import subprocess
import sys
import tarfile
import zipfile

ARCHIVES = {
    "linux": ("go1.27.4.linux-amd64.tar.gz", "7226736c2339719cda28fbf3a54d71aa63bcefe376e98cef00034268dab24840"),
    "windows": ("go1.27.4.windows-amd64.zip", "178ab98950ac69ab25069307dc6ade79f3816e414cce95b4da166a115cde1e7e"),
}


def digest_stream(stream):
    digest = hashlib.sha256()
    for block in iter(lambda: stream.read(1024 * 1024), b""):
        digest.update(block)
    return digest.hexdigest()


def digest_file(path):
    with path.open("rb") as stream:
        return digest_stream(stream)


def safe_name(name):
    p = PurePosixPath(name)
    if (not name or "\\" in name or ":" in name or p.is_absolute() or
            any(part in ("", ".", "..") for part in p.parts) or not p.parts or p.parts[0] != "go"):
        raise ValueError("invalid Go archive member")
    return p


def regular_file(path):
    if path.is_symlink() or getattr(path, "is_junction", lambda: False)():
        raise ValueError("linked Go distribution input")
    if not path.is_file():
        raise ValueError("Go distribution file missing")


def compare_member(root, name, source, size, expected, seen):
    parts = safe_name(name).parts
    key = "/".join(parts[1:])
    if not key or key.casefold() in seen:
        raise ValueError("duplicate Go archive member")
    seen.add(key.casefold())
    path = root.joinpath(*parts[1:])
    for depth in range(1, len(parts) - 1):
        directory = root.joinpath(*parts[1:depth + 1])
        if directory.is_symlink() or getattr(directory, "is_junction", lambda: False)() or not directory.is_dir():
            raise ValueError("linked Go distribution ancestor")
    regular_file(path)
    if path.stat().st_size != size or digest_stream(source) != digest_file(path):
        raise ValueError("installed Go distribution member differs")
    expected.add(key)


def compare_distribution(root, archive, platform):
    """Compare every regular archive member and refuse unclassified local files or links."""
    expected, expected_dirs, seen = set(), set(), set()
    if platform == "linux":
        with tarfile.open(archive, "r:gz") as reader:
            for member in reader:
                safe_name(member.name)
                if member.isdir():
                    name = "/".join(safe_name(member.name).parts[1:])
                    if name: expected_dirs.add(name)
                    continue
                if not member.isfile():
                    raise ValueError("unsupported Go archive member")
                source = reader.extractfile(member)
                if source is None:
                    raise ValueError("unreadable Go archive member")
                with source:
                    compare_member(root, member.name, source, member.size, expected, seen)
                if os.name != "nt" and stat.S_IMODE(root.joinpath(*safe_name(member.name).parts[1:]).stat().st_mode) != (member.mode & 0o777):
                    raise ValueError("installed Go distribution mode differs")
    elif platform == "windows":
        with zipfile.ZipFile(archive) as reader:
            for member in reader.infolist():
                safe_name(member.filename)
                if member.is_dir():
                    name = "/".join(safe_name(member.filename).parts[1:])
                    if name: expected_dirs.add(name)
                    continue
                if stat.S_IFMT(member.external_attr >> 16) == stat.S_IFLNK:
                    raise ValueError("linked Go archive member")
                with reader.open(member) as source:
                    compare_member(root, member.filename, source, member.file_size, expected, seen)
    else:
        raise ValueError("unsupported Go host")
    for name in expected:
        parent = PurePosixPath(name).parent
        while str(parent) != ".":
            expected_dirs.add(str(parent))
            parent = parent.parent
    actual, actual_dirs = set(), set()
    for directory, folders, files in os.walk(root, followlinks=False):
        for name in folders:
            member = Path(directory) / name
            if member.is_symlink() or getattr(member, "is_junction", lambda: False)():
                raise ValueError("linked Go distribution directory")
            actual_dirs.add(member.relative_to(root).as_posix())
        for name in files:
            member = Path(directory) / name
            regular_file(member)
            actual.add(member.relative_to(root).as_posix())
    if not expected or actual != expected or actual_dirs != expected_dirs:
        raise ValueError("Go distribution has unclassified or missing files")
    return len(expected)


def native_environment(platform):
    env = os.environ.copy()
    for key in tuple(env):
        if key.upper().startswith("GO"):
            env.pop(key)
    env.update({"GOENV": "off", "GOTOOLCHAIN": "local", "GOWORK": "off", "GOFLAGS": "-mod=readonly",
                "GOTELEMETRY": "off", "CGO_ENABLED": "0", "GOOS": platform, "GOARCH": "amd64", "GOAMD64": "v1"})
    return env


def verify_compiler(archive, root, platform):
    archive, root = Path(archive), Path(root)
    if platform not in ARCHIVES or not archive.is_absolute() or not root.is_absolute():
        raise ValueError("absolute native Go archive and root required")
    if (os.name == "nt") != (platform == "windows") or root.is_symlink() or not root.is_dir():
        raise ValueError("incorrect native Go host or root")
    regular_file(archive)
    filename, expected = ARCHIVES[platform]
    if archive.name != filename or digest_file(archive) != expected:
        raise ValueError("Go 1.27.4 official archive differs")
    count = compare_distribution(root, archive, platform)
    exe = root / "bin" / ("go.exe" if platform == "windows" else "go")
    regular_file(exe)
    env = native_environment(platform)
    version = subprocess.check_output([str(exe), "version"], text=True, env=env, timeout=30).strip()
    compiler = subprocess.check_output([str(exe), "tool", "compile", "-V"], text=True, env=env, timeout=30).strip()
    goroot = subprocess.check_output([str(exe), "env", "GOROOT"], text=True, env=env, timeout=30).strip()
    if version != f"go version go1.27.4 {platform}/amd64" or compiler != "compile version go1.27.4" or Path(goroot).resolve() != root.resolve():
        raise ValueError("Go executable, compiler or root identity differs")
    return {"platform": platform + "/amd64", "archive": filename, "archiveSha256": expected,
            "root": str(root), "executableSha256": digest_file(exe), "version": version,
            "compilerVersion": compiler, "regularFiles": count}


if __name__ == "__main__":
    if len(sys.argv) != 4:
        raise SystemExit("usage: ctr06_security_bridge_compiler.py linux|windows /absolute/archive /absolute/go-root")
    try:
        print(json.dumps(verify_compiler(sys.argv[2], sys.argv[3], sys.argv[1]), sort_keys=True))
    except (OSError, ValueError, subprocess.SubprocessError, tarfile.TarError, zipfile.BadZipFile) as error:
        raise SystemExit(f"security bridge compiler verification failed: {error}") from None
