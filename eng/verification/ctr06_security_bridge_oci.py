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
MAX_LAYERS = 64
MAX_LAYER_ENTRIES = 20_000
MAX_TOTAL_LAYER_ENTRIES = 50_000
MAX_TOTAL_LAYER_BYTES = 512 * 1024 * 1024
MAX_APP_FILES = 4096
MAX_APP_PATHS = 16_384
MAX_PATH_LENGTH = 4096


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
    if not isinstance(name, str) or not name or len(name) > MAX_PATH_LENGTH or name.startswith("/") or "\\" in name:
        raise ValueError("unsafe OCI path")
    parts = name.removeprefix("./").rstrip("/").split("/")
    if any(part in ("", ".", "..") for part in parts):
        raise ValueError("unsafe OCI path component")
    return "/".join(parts)


def verify_index_annotations(descriptor, tag, config_digest):
    expected = {"config.digest": config_digest,
                "io.containerd.image.name": "docker.io/library/" + tag,
                "org.opencontainers.image.ref.name": tag.partition(":")[2]}
    if descriptor.get("annotations") != expected:
        raise ValueError("OCI image index annotations differ")


class AppTree:
    """Apply the closed /app portion of the verified layer stream without extracting it."""

    def __init__(self, expected_files):
        if not isinstance(expected_files, dict) or not 0 < len(expected_files) <= MAX_APP_FILES:
            raise ValueError("invalid expected app member set")
        self.files = {}
        self.directories = {"app"}
        for relative, value in expected_files.items():
            if (not isinstance(relative, str) or safe_path(relative) != relative or
                    not isinstance(value, str) or not re.fullmatch(r"[0-9a-f]{64}", value) or
                    any(part.startswith(".wh.") for part in relative.split("/"))):
                raise ValueError("invalid expected app member")
            name = "app/" + relative
            if len(name) > MAX_PATH_LENGTH:
                raise ValueError("expected app path too long")
            self.files[name] = value
            parent = PurePosixPath(name).parent
            while str(parent) != ".":
                self.directories.add(str(parent))
                if len(self.directories) + len(self.files) > MAX_APP_PATHS:
                    raise ValueError("too many expected app paths")
                parent = parent.parent
        if self.directories.intersection(self.files):
            raise ValueError("expected app file is also a directory")
        self.entries = {}

    def apply(self, name, item, content_hash):
        if name != "app" and not name.startswith("app/"):
            raise ValueError("security bridge adds material outside /app")
        if any(part.startswith(".wh.") for part in name.split("/")):
            raise ValueError("OCI whiteouts are unsupported in /app")
        if (item.pax_headers or item.linkname or item.uname or item.gname or
                item.devmajor != 0 or item.devminor != 0 or type(item.mtime) is not int or
                item.mtime < 0 or item.mtime > (1 << 63) - 1):
            raise ValueError("unexpected security bridge metadata")
        if name != "app":
            parent = name.rpartition("/")[0]
            if parent not in self.entries or self.entries[parent]["type"] != "directory":
                raise ValueError("missing or non-directory app parent")
        previous = self.entries.get(name)
        if item.isdir():
            owner = 1654 if name == "app" else 0
            if (name not in self.directories or item.size != 0 or item.mode != 0o755 or
                    item.uid != owner or item.gid != owner or content_hash is not None):
                raise ValueError("unexpected security bridge directory")
            if previous is not None and previous["type"] != "directory":
                raise ValueError("security bridge path changes type")
            self.entries[name] = {"type": "directory", "mode": item.mode, "uid": item.uid,
                                  "gid": item.gid, "mtime": item.mtime}
        elif item.isfile():
            expected = self.files.get(name)
            executable = name in ("app/ArcForges.Cloud", "app/arcforges-center")
            mode = 0o755 if executable else 0o644
            if (expected is None or previous is not None or item.mode != mode or
                    item.uid != 0 or item.gid != 0 or content_hash != expected):
                raise ValueError("unclassified, repeated or changed security bridge file")
            self.entries[name] = {"type": "file", "mode": item.mode, "uid": item.uid,
                                  "gid": item.gid, "mtime": item.mtime, "size": item.size,
                                  "sha256": content_hash}
        else:
            raise ValueError("linked or special security bridge layer entry")

    def finish(self):
        if set(self.entries) != self.directories.union(self.files):
            raise ValueError("effective security bridge path set differs")
        actual = {name.removeprefix("app/"): self.entries[name]["sha256"] for name in self.files}
        expected = {name.removeprefix("app/"): value for name, value in self.files.items()}
        if actual != expected:
            raise ValueError("OCI app members differ from independently verified image")
        return actual, {name: self.entries[name] for name in sorted(self.entries)}


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
            if len(entries) >= MAX_TOTAL_LAYER_ENTRIES or name in entries or (not entry.isfile() and not entry.isdir()):
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
        config_descriptor = manifest.get("config", {})
        config = document(blob(config_descriptor))
        verify_index_annotations(image_descriptor, expected_tag, config_descriptor["digest"])
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
        if (rootfs.get("type") != "layers" or not isinstance(diffs, list) or len(diffs) != len(layers) or
                len(layers) > MAX_LAYERS or diffs[:len(BASE_DIFFS)] != BASE_DIFFS):
            raise ValueError("OCI base or layer count differs")
        docker_manifest = document(read("manifest.json"))
        if docker_manifest != [{"Config": "blobs/sha256/" + manifest["config"]["digest"][7:],
                                "RepoTags": [expected_tag],
                                "Layers": ["blobs/sha256/" + layer["digest"][7:] for layer in layers]}]:
            raise ValueError("Docker manifest differs from OCI descriptors")
        app_tree, layer_inventory, total_entries, total_layer_bytes = AppTree(expected_app_members), [], 0, 0
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
            total_layer_bytes += len(layer_data)
            if total_layer_bytes > MAX_TOTAL_LAYER_BYTES:
                raise ValueError("OCI layers exceed total size limit")
            if digest(layer_data) != diff_id:
                raise ValueError("OCI uncompressed layer digest differs")
            members, names = [], set()
            with tarfile.open(fileobj=io.BytesIO(layer_data), mode="r:") as layer:
                for item in layer:
                    name = safe_path(item.name)
                    total_entries += 1
                    if (name in names or len(names) >= MAX_LAYER_ENTRIES or
                            total_entries > MAX_TOTAL_LAYER_ENTRIES):
                        raise ValueError("duplicate or excessive OCI layer paths")
                    names.add(name)
                    row = {"path": name, "mode": stat.S_IMODE(item.mode), "uid": item.uid, "gid": item.gid,
                           "type": item.type.decode("latin1"), "link": item.linkname, "size": item.size,
                           "pax": dict(item.pax_headers)}
                    if item.isfile():
                        source = layer.extractfile(item)
                        if source is None:
                            raise ValueError("unreadable OCI layer file")
                        data = bounded(source)
                        if len(data) != item.size:
                            raise ValueError("truncated OCI layer file")
                        row["sha256"] = hashlib.sha256(data).hexdigest()
                    if index >= len(BASE_DIFFS):
                        app_tree.apply(name, item, row.get("sha256"))
                    elif name == "app" or name.startswith("app/"):
                        raise ValueError("base image unexpectedly contains /app")
                    members.append(row)
            layer_inventory.append({"digest": descriptor["digest"], "diffId": diff_id, "members": members})
        image_files, effective_tree = app_tree.finish()
        regular = {name for name, entry in entries.items() if entry.isfile()}
        if regular != {"oci-layout", "index.json", "manifest.json", *descriptors}:
            raise ValueError("unclassified OCI blob")
    return {"archiveSha256": hashlib.sha256(contents).hexdigest(), "size": len(contents),
            "manifestDigest": image_descriptor["digest"], "configDigest": manifest["config"]["digest"],
            "baseDiffIds": BASE_DIFFS, "layers": layer_inventory, "appMembers": image_files,
            "effectiveAppTree": effective_tree}
