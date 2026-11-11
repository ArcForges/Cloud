#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
"""Verify the security bridge OCI graph and complete layer/path/mode inventory.

Expected application member digests come from the independently checked stopped image, not from
this archive's own manifest. This is a sealing primitive and confers no publication authority.
"""
from __future__ import annotations

import gzip
import hashlib
import io
import json
from pathlib import Path, PurePosixPath
import re
import stat
import tarfile

SOURCE = "8e5f6e26aa97b123d9f60b91f780364a094e74cd"
BASE_DIFFS = [
    "sha256:97d8d88367e6fc37b71fce566d77054c81ff3f7184d6d1cc9161beefbae901ac",
    "sha256:0d12f8f57c5ec11597499635ebe332f1b8560719b275320a2d2105c18ec3bcec",
]
MAX_ARCHIVE = 256 * 1024 * 1024


def digest(data):
    return "sha256:" + hashlib.sha256(data).hexdigest()


def object_pairs(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate OCI JSON key")
        result[key] = value
    return result


def document(data):
    return json.loads(data, object_pairs_hook=object_pairs)


def bounded(stream):
    data = stream.read(MAX_ARCHIVE + 1)
    if len(data) > MAX_ARCHIVE:
        raise ValueError("OCI member too large")
    return data


def safe_path(name):
    if not name or name.startswith("/") or "\\" in name:
        raise ValueError("unsafe OCI path")
    parts = name.removeprefix("./").rstrip("/").split("/")
    if any(part in ("", ".", "..") for part in parts):
        raise ValueError("unsafe OCI path component")
    return "/".join(parts)


def verify_oci(archive, expected_image_id, expected_tag, expected_app_members):
    """Validate every descriptor, diff-id, layer entry and app mode without extracting archive paths."""
    archive = Path(archive)
    if not archive.is_absolute() or archive.is_symlink() or not archive.is_file() or archive.stat().st_size > MAX_ARCHIVE:
        raise ValueError("invalid OCI archive")
    if not re.fullmatch(r"sha256:[0-9a-f]{64}", expected_image_id):
        raise ValueError("invalid expected image identity")
    if not re.fullmatch(r"arcforges-ctr06-security-bridge:[a-z0-9.-]+", expected_tag):
        raise ValueError("invalid expected image tag")
    with archive.open("rb") as stream:
        contents = bounded(stream)
    with tarfile.open(fileobj=io.BytesIO(contents), mode="r:") as carrier:
        entries = {}
        for entry in carrier:
            name = safe_path(entry.name)
            if name in entries or (not entry.isfile() and not entry.isdir()):
                raise ValueError("duplicate or non-regular OCI archive member")
            entries[name] = entry
        directories = {name for name, entry in entries.items() if entry.isdir()}
        if directories != {"blobs", "blobs/sha256"}:
            raise ValueError("unexpected OCI archive directories")
        def read(name):
            entry = entries.get(name)
            if entry is None or not entry.isfile() or entry.size > MAX_ARCHIVE:
                raise ValueError("missing OCI file")
            source = carrier.extractfile(entry)
            if source is None:
                raise ValueError("unreadable OCI file")
            data = bounded(source)
            if len(data) != entry.size:
                raise ValueError("truncated OCI file")
            return data
        if document(read("oci-layout")) != {"imageLayoutVersion": "1.0.0"}:
            raise ValueError("unsupported OCI layout")
        index = document(read("index.json"))
        if index.get("schemaVersion") != 2 or len(index.get("manifests", [])) != 1:
            raise ValueError("invalid OCI index")
        descriptors = set()
        def blob(descriptor):
            identity, size = descriptor.get("digest"), descriptor.get("size")
            if not isinstance(identity, str) or not re.fullmatch(r"sha256:[0-9a-f]{64}", identity) or type(size) is not int or size <= 0:
                raise ValueError("invalid OCI descriptor")
            name = "blobs/sha256/" + identity[7:]
            data = read(name)
            if len(data) != size or digest(data) != identity:
                raise ValueError("OCI descriptor digest differs")
            descriptors.add(name)
            return data
        image_descriptor = index["manifests"][0]
        if image_descriptor.get("digest") != expected_image_id:
            raise ValueError("OCI image identity differs")
        manifest = document(blob(image_descriptor))
        if manifest.get("schemaVersion") != 2 or not isinstance(manifest.get("layers"), list):
            raise ValueError("invalid OCI manifest")
        config = document(blob(manifest.get("config", {})))
        image_config = config.get("config", {})
        labels = {"org.opencontainers.image.source": "https://github.com/ArcForges/Cloud",
                  "org.opencontainers.image.licenses": "AGPL-3.0-only", "org.opencontainers.image.revision": SOURCE}
        expected_env = {"PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin", "APP_UID=1654",
                        "ASPNETCORE_HTTP_PORTS=8080", "DOTNET_RUNNING_IN_CONTAINER=true",
                        "DOTNET_SYSTEM_GLOBALIZATION_INVARIANT=1", "ASPNETCORE_ENVIRONMENT=Production"}
        env = image_config.get("Env", [])
        if (config.get("architecture") != "amd64" or config.get("os") != "linux" or
                set(image_config) != {"User", "ExposedPorts", "Env", "Entrypoint", "WorkingDir", "Labels"} or
                image_config.get("User") != "1654" or image_config.get("Entrypoint") != ["/app/ArcForges.Cloud"] or
                image_config.get("WorkingDir") != "/app" or image_config.get("Labels") != labels or
                image_config.get("ExposedPorts") != {"8080/tcp": {}, "8081/tcp": {}} or
                not isinstance(env, list) or len(env) != len(expected_env) or set(env) != expected_env):
            raise ValueError("OCI image config differs")
        rootfs = config.get("rootfs", {})
        diffs = rootfs.get("diff_ids", [])
        layers = manifest["layers"]
        if rootfs.get("type") != "layers" or len(diffs) != len(layers) or diffs[:len(BASE_DIFFS)] != BASE_DIFFS:
            raise ValueError("OCI base or layer count differs")
        docker_manifest = document(read("manifest.json"))
        if docker_manifest != [{"Config": "blobs/sha256/" + manifest["config"]["digest"][7:],
                                "RepoTags": [expected_tag],
                                "Layers": ["blobs/sha256/" + layer["digest"][7:] for layer in layers]}]:
            raise ValueError("Docker manifest differs from OCI descriptors")
        image_files, layer_inventory = {}, []
        for index, (descriptor, diff_id) in enumerate(zip(layers, diffs, strict=True)):
            raw = blob(descriptor)
            media = descriptor.get("mediaType")
            if media in ("application/vnd.docker.image.rootfs.diff.tar.gzip", "application/vnd.oci.image.layer.v1.tar+gzip"):
                with gzip.GzipFile(fileobj=io.BytesIO(raw)) as compressed:
                    layer_data = bounded(compressed)
            elif media == "application/vnd.oci.image.layer.v1.tar":
                layer_data = raw
            else:
                raise ValueError("unsupported OCI layer format")
            if digest(layer_data) != diff_id:
                raise ValueError("OCI uncompressed layer digest differs")
            members, names = [], set()
            with tarfile.open(fileobj=io.BytesIO(layer_data), mode="r:") as layer:
                for item in layer:
                    name = safe_path(item.name)
                    if name in names:
                        raise ValueError("duplicate OCI layer path")
                    names.add(name)
                    row = {"path": name, "mode": stat.S_IMODE(item.mode), "uid": item.uid, "gid": item.gid,
                           "type": item.type.decode("latin1"), "link": item.linkname, "size": item.size,
                           "pax": dict(item.pax_headers)}
                    if item.isfile():
                        data = bounded(layer.extractfile(item))
                        if len(data) != item.size:
                            raise ValueError("truncated OCI layer file")
                        row["sha256"] = hashlib.sha256(data).hexdigest()
                    if index >= len(BASE_DIFFS):
                        if name != "app" and not name.startswith("app/"):
                            raise ValueError("security bridge adds material outside /app")
                        relative = name.removeprefix("app/")
                        if item.isdir():
                            if stat.S_IMODE(item.mode) != 0o755:
                                raise ValueError("untraversable security bridge directory")
                        elif item.isfile():
                            if name == "app" or relative not in expected_app_members or relative in image_files:
                                raise ValueError("unclassified or repeated security bridge file")
                            expected_mode = 0o755 if relative in ("ArcForges.Cloud", "arcforges-center") else 0o644
                            if stat.S_IMODE(item.mode) != expected_mode or item.uid != 0 or item.gid != 0:
                                raise ValueError("unreadable or unexpected security bridge file mode")
                            image_files[relative] = row["sha256"]
                        else:
                            raise ValueError("linked or special security bridge layer entry")
                    elif name == "app" or name.startswith("app/"):
                        raise ValueError("base image unexpectedly contains /app")
                    members.append(row)
            layer_inventory.append({"digest": descriptor["digest"], "diffId": diff_id, "members": members})
        if image_files != expected_app_members:
            raise ValueError("OCI app members differ from independently verified image")
        regular = {name for name, entry in entries.items() if entry.isfile()}
        if regular != {"oci-layout", "index.json", "manifest.json", *descriptors}:
            raise ValueError("unclassified OCI blob")
    return {"archiveSha256": hashlib.sha256(contents).hexdigest(), "size": len(contents),
            "manifestDigest": image_descriptor["digest"], "configDigest": manifest["config"]["digest"],
            "baseDiffIds": BASE_DIFFS, "layers": layer_inventory, "appMembers": image_files}
