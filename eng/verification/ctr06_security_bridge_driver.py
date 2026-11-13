#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
"""Private bridge build primitives; no operation here grants publication authority."""
from __future__ import annotations

import hashlib
import io
import json
import os
import tarfile
from pathlib import Path
import sys

import ctr06_security_bridge_bundle as bundle
import ctr06_security_bridge_compiler as compiler
import ctr06_security_bridge_oci as oci


def pairs(values):
    result = {}
    for key, value in values:
        if key in result:
            raise ValueError("duplicate driver input")
        result[key] = value
    return result


def tool_context(source, destination):
    """Copy only the pinned tool-source members from the verified 8e5 archive."""
    source, destination = Path(source), Path(destination)
    if not source.is_absolute() or not destination.is_absolute() or destination.exists() or not destination.parent.is_dir():
        raise ValueError("invalid tool source context")
    archive, _, _ = bundle.source_archive(source)
    destination.mkdir(mode=0o700)
    prefix = "tools/ArcForges.Cloud.Generation/"
    files = {}
    with tarfile.open(fileobj=io.BytesIO(archive), mode="r:") as reader:
        for member in reader:
            if not member.name.startswith(prefix):
                continue
            relative = member.name[len("tools/"):]
            parts = relative.rstrip("/").split("/")
            if not parts or any(p in ("", ".", "..") for p in parts) or "\\" in relative or ":" in relative:
                raise ValueError("unsafe tool source member")
            target = destination.joinpath(*parts)
            if member.isdir():
                target.mkdir(parents=True, exist_ok=True)
            elif member.isfile() and member.size <= 16 * 1024 * 1024:
                target.parent.mkdir(parents=True, exist_ok=True)
                contents = reader.extractfile(member)
                if contents is None or relative in files:
                    raise ValueError("duplicate or unreadable tool source")
                data = contents.read()
                if len(data) != member.size:
                    raise ValueError("truncated tool source")
                fd = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o644)
                with os.fdopen(fd, "wb") as f:
                    f.write(data)
                files[relative] = hashlib.sha256(data).hexdigest()
            else:
                raise ValueError("unsupported tool source member")
    if not files or "ArcForges.Cloud.Generation/packages.lock.json" not in files:
        raise ValueError("incomplete tool source context")
    return {"sourceArchiveSha256": bundle.historical.SOURCE_SHA256, "files": files}


def extract_verified_tool(archive, destination, expected):
    archive, destination = Path(archive), Path(destination)
    if not archive.is_absolute() or not destination.is_absolute() or destination.exists() or not destination.parent.is_dir():
        raise ValueError("invalid verified tool paths")
    if not isinstance(expected, dict) or not expected:
        raise ValueError("empty expected tool members")
    destination.mkdir(mode=0o700)
    seen = set()
    with tarfile.open(archive, mode="r:") as reader:
        for member in reader:
            if member.name == "." and member.isdir():
                continue
            name = member.name.removeprefix("./")
            if (not name or "/" in name or "\\" in name or name in (".", "..") or name in seen or
                    name not in expected or not member.isfile() or member.uid != 0 or member.gid != 0 or
                    member.mtime != 0 or member.size > 100 * 1024 * 1024):
                raise ValueError("invalid sealed tool member")
            item = expected[name]
            contents = reader.extractfile(member)
            if contents is None:
                raise ValueError("unreadable sealed tool member")
            data = contents.read()
            if (len(data) != member.size or item != {"sha256": hashlib.sha256(data).hexdigest(), "size": member.size, "mode": member.mode & 0o777}):
                raise ValueError("sealed tool member differs")
            seen.add(name)
            if name.startswith("ArcForges.Cloud") and name.endswith(".dll"):
                fd = os.open(destination / name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
                with os.fdopen(fd, "wb") as f:
                    f.write(data)
    if seen != set(expected):
        raise ValueError("sealed tool member set differs")
    return {"members": len(seen), "assemblies": len(list(destination.iterdir()))}


def verify_carrier(archive, expected):
    """Reopen the compressed carrier and verify its closed, normalized member set."""
    archive = Path(archive)
    if not archive.is_absolute() or archive.is_symlink() or not archive.is_file() or not isinstance(expected, dict):
        raise ValueError("invalid carrier inputs")
    expected_dirs = {".", "linux", "windows"}
    seen, directories, total = set(), set(), 0
    with tarfile.open(archive, mode="r:gz") as reader:
        for member in reader:
            name = member.name.removeprefix("./").rstrip("/") or "."
            if member.isdir():
                if name not in expected_dirs or name in directories or member.uid != 0 or member.gid != 0 or member.mtime != 0:
                    raise ValueError("invalid carrier directory")
                directories.add(name)
                continue
            if (name in seen or name not in expected or not member.isfile() or member.uid != 0 or member.gid != 0 or
                    member.mtime != 0 or (member.mode & 0o777) != 0o644 or member.size > 256 * 1024 * 1024):
                raise ValueError("invalid carrier member")
            source = reader.extractfile(member)
            if source is None:
                raise ValueError("unreadable carrier member")
            digest = hashlib.sha256()
            size = 0
            for block in iter(lambda: source.read(1024 * 1024), b""):
                size += len(block)
                total += len(block)
                if total > 512 * 1024 * 1024:
                    raise ValueError("carrier exceeds limit")
                digest.update(block)
            if size != member.size or expected[name] != {"sha256": digest.hexdigest(), "size": size}:
                raise ValueError("carrier member differs")
            seen.add(name)
    if seen != set(expected) or directories != expected_dirs:
        raise ValueError("carrier member set differs")
    return {"sha256": compiler.digest_file(archive), "size": archive.stat().st_size, "members": len(seen)}


def main():
    if len(sys.argv) != 2:
        raise ValueError("one build operation is required")
    data = sys.stdin.buffer.read(2 * 1024 * 1024 + 1)
    if len(data) > 2 * 1024 * 1024:
        raise ValueError("oversized build input")
    args = json.loads(data, object_pairs_hook=pairs)
    operation = sys.argv[1]
    if operation == "verify-compiler":
        if set(args) != {"platform", "goArchive", "goRoot"}:
            raise ValueError("unexpected compiler verification inputs")
        return compiler.verify_compiler(args["goArchive"], args["goRoot"], args["platform"])
    if operation == "verify-carrier":
        if set(args) != {"archive", "members"}:
            raise ValueError("unexpected carrier verification inputs")
        return verify_carrier(args["archive"], args["members"])
    if operation == "extract-verified-tool":
        if set(args) != {"archive", "destination", "members"}:
            raise ValueError("unexpected sealed tool inputs")
        return extract_verified_tool(args["archive"], args["destination"], args["members"])
    if operation == "tool-context":
        if set(args) != {"source", "destination"}:
            raise ValueError("unexpected tool context inputs")
        return tool_context(args["source"], args["destination"])
    if operation == "build-native":
        required = {"platform", "source", "goArchive", "goRoot", "output", "identity"}
        if set(args) != required:
            raise ValueError("unexpected native build inputs")
        return bundle.build_native(args["platform"], args["source"], args["goArchive"], args["goRoot"], args["output"], args["identity"])
    if operation == "image-binary":
        required = {"source", "goArchive", "goRoot", "binary", "identity"}
        if set(args) != required:
            raise ValueError("unexpected image binary inputs")
        evidence = compiler.verify_compiler(args["goArchive"], args["goRoot"], "linux")
        _, dependencies, _ = bundle.source_archive(args["source"])
        binary = Path(args["binary"])
        compiler.regular_file(binary)
        binary_hash = compiler.digest_file(binary)
        build = bundle.verify_binary("linux", binary, Path(args["goRoot"]) / "bin/go", dependencies, args["identity"])
        if compiler.digest_file(binary) != binary_hash:
            raise ValueError("image binary changed while validating")
        return {"compiler": evidence, "binary": build, "binarySha256": binary_hash}
    if operation == "seal-native":
        required = {"platform", "source", "producerSource", "binary", "goArchive", "goRoot", "producer", "identity", "binarySha256", "output"}
        if set(args) != required:
            raise ValueError("unexpected native seal inputs")
        return bundle.seal_native(args["platform"], args["source"], args["producerSource"], args["binary"], args["goArchive"], args["goRoot"], args["producer"], args["identity"], args["binarySha256"], args["output"])
    if operation == "verify-native":
        required = {"platform", "bundle", "producerSource", "go", "compiler", "producer", "identity", "binarySha256"}
        if set(args) != required:
            raise ValueError("unexpected native bundle verification inputs")
        return bundle.verify_native_bundle(args["platform"], args["bundle"], args["producerSource"], args["go"], args["compiler"], args["producer"], args["identity"], args["binarySha256"])
    if operation == "verify-windows-from-native-job":
        required = {"bundle", "producerSource", "go", "compiler", "producer", "identity", "binarySha256"}
        if set(args) != required:
            raise ValueError("unexpected Windows native-job readback inputs")
        return bundle.verify_windows_from_native_job(args["bundle"], args["producerSource"], args["go"], args["compiler"], args["producer"], args["identity"], args["binarySha256"])
    if operation == "verify-oci":
        if set(args) != {"archive", "imageId", "tag", "appMembers"}:
            raise ValueError("unexpected OCI verification inputs")
        return oci.verify_oci(args["archive"], args["imageId"], args["tag"], args["appMembers"])
    raise ValueError("unsupported security bridge build operation")


if __name__ == "__main__":
    try:
        print(json.dumps(main(), sort_keys=True, separators=(",", ":")))
    except (OSError, ValueError, KeyError, TypeError) as error:
        raise SystemExit(f"security bridge build failed: {error}") from None
