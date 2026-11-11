#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
"""Extract only the exact, pinned bridge release files into an empty private directory."""
import hashlib
import io
import json
import re
import os
from pathlib import Path
import shutil
import sys
import tarfile

PIN = "d9c52a13c54b073758866c9e02168cc1e527cca92257df259e97298a5aa2a466"
FILES = {
    "manifest.json", "build-identity.json", "docker-image.tar", "worker.js", "wrangler.json",
    "legal-notices.json", "worker-meta.json", "proof-worker.js", "proof-worker-meta.json",
    "image-provenance.json", "arcforges-tool.tar",
}

def main(archive, destination, executable_output=None):
    archive, destination = Path(archive), Path(destination)
    if not archive.is_absolute() or not destination.is_absolute() or destination.is_symlink():
        raise ValueError("bridge paths must be absolute and the destination must not be a symlink")
    if not destination.is_dir() or any(destination.iterdir()):
        raise ValueError("bridge destination must be an empty private directory")
    if destination.stat().st_mode & 0o077:
        raise ValueError("bridge destination must be private")
    digest = hashlib.sha256()
    with archive.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    if digest.hexdigest() != PIN:
        raise ValueError("bridge release carrier digest differs")
    with tarfile.open(archive, "r:gz") as carrier:
        members = carrier.getmembers()
        regular = {}
        for member in members:
            if member.name == "." and member.isdir():
                continue
            name = member.name.removeprefix("./")
            if name not in FILES or not member.isfile() or name in regular or member.size > 200 * 1024 * 1024:
                raise ValueError("bridge release contains an unexpected member")
            regular[name] = member
        if set(regular) != FILES or sum(m.size for m in regular.values()) > 256 * 1024 * 1024:
            raise ValueError("bridge release members are incomplete or too large")
        for name, member in regular.items():
            source = carrier.extractfile(member)
            if source is None:
                raise ValueError("bridge release member is unreadable")
            flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
            fd = os.open(destination / name, flags, 0o600)
            with source, os.fdopen(fd, "wb") as output:
                shutil.copyfileobj(source, output, 1024 * 1024)
    executable = verify_oci(destination / "docker-image.tar")
    if executable_output is not None:
        output = Path(executable_output)
        if not output.is_absolute():
            raise ValueError("bridge executable output must be absolute")
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
        fd = os.open(output, flags, 0o500)
        with os.fdopen(fd, "wb") as target:
            target.write(executable)

def verify_oci(image):
    manifest_pin = "sha256:9b90c26264806fda339cdcff44dcf987bccf702117b3cd3e81ed7248de9730f0"
    config_pin = "sha256:4556fa0bd1029afc0aeea3f0368023c852b36e39c39ed800eacef8741b1702ee"
    with tarfile.open(image, "r:") as carrier:
        members = carrier.getmembers()
        by_name = {}
        for member in members:
            if member.name in by_name:
                raise ValueError("duplicate OCI member")
            by_name[member.name] = member
        def read_descriptor(descriptor):
            digest = descriptor.get("digest")
            size = descriptor.get("size")
            if not isinstance(digest, str) or not re.fullmatch(r"sha256:[0-9a-f]{64}", digest) or not isinstance(size, int):
                raise ValueError("invalid OCI descriptor")
            member = by_name.get("blobs/sha256/" + digest[7:])
            if member is None or not member.isfile() or member.size != size or size > 200 * 1024 * 1024:
                raise ValueError("missing OCI blob")
            source = carrier.extractfile(member)
            if source is None:
                raise ValueError("unreadable OCI blob")
            data = source.read()
            if len(data) != size or "sha256:" + hashlib.sha256(data).hexdigest() != digest:
                raise ValueError("OCI blob digest mismatch")
            return data
        index_member = by_name.get("index.json")
        if index_member is None or not index_member.isfile() or index_member.size > 65536:
            raise ValueError("OCI index absent")
        index = json.load(carrier.extractfile(index_member))
        manifests = index.get("manifests", [])
        if len(manifests) != 1 or manifests[0].get("digest") != manifest_pin:
            raise ValueError("OCI main manifest differs")
        manifest = json.loads(read_descriptor(manifests[0]))
        if manifest.get("config", {}).get("digest") != config_pin:
            raise ValueError("OCI config differs")
        config = json.loads(read_descriptor(manifest["config"]))
        if config.get("architecture") != "amd64" or config.get("os") != "linux" or config.get("config", {}).get("Labels", {}).get("org.opencontainers.image.revision") != "8e5f6e26aa97b123d9f60b91f780364a094e74cd":
            raise ValueError("OCI configuration identity differs")
        layers = manifest.get("layers")
        if not isinstance(layers, list) or not layers:
            raise ValueError("OCI layers absent")
        executable = None
        for layer in layers:
            data = read_descriptor(layer)
            with tarfile.open(fileobj=io.BytesIO(data), mode="r:*") as contents:
                for member in contents:
                    name = member.name.removeprefix("./").lstrip("/")
                    if name in ("app/.wh.arcforges-center", "app/.wh..wh..opq"):
                        executable = None
                    elif name == "app/arcforges-center":
                        if not member.isfile() or member.size > 100 * 1024 * 1024:
                            raise ValueError("OCI center executable is not regular")
                        source = contents.extractfile(member)
                        if source is None:
                            raise ValueError("OCI center executable is absent")
                        executable = source.read()
        if executable is None or hashlib.sha256(executable).hexdigest() != "028223a3dcbcbd6d7724558de02409e1e8874d876049f03fed38f47998773ba4":
            raise ValueError("OCI center executable differs")
        return executable

if __name__ == "__main__":
    if len(sys.argv) not in (3, 4):
        raise SystemExit("usage: ctr06_bridge_carrier.py /absolute/release.tar.gz /absolute/empty-directory [/absolute/new-executable]")
    try:
        main(sys.argv[1], sys.argv[2], sys.argv[3] if len(sys.argv) == 4 else None)
    except (OSError, ValueError, tarfile.TarError):
        raise SystemExit("bridge release carrier verification failed") from None
