#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
"""Seal the one-time self-hosted CTR06 bridge bundle and verify its inputs.

The Linux executable is from the already-published 615.1 carrier; the Windows
executable is a native reproducible build from the reviewed 8e5 source and is
not claimed to be a released OCI member. Neither contains Contracts 450.1.
"""
from __future__ import annotations

import hashlib
import io
import json
from pathlib import Path
import subprocess
import sys
import tarfile
import zipfile

REVISION = "8e5f6e26aa97b123d9f60b91f780364a094e74cd"
TREE = "4a315ea6b47d96c3262e8111fcc26ad1957097f2"
SOURCE_SHA256 = "ea07d57bdc0acf43c2e58bdc3666d8334185600f46e903e2d5a109547e59293c"
CARRIER_SHA256 = "d9c52a13c54b073758866c9e02168cc1e527cca92257df259e97298a5aa2a466"
IMAGE_DIGEST = "sha256:9b90c26264806fda339cdcff44dcf987bccf702117b3cd3e81ed7248de9730f0"
LINUX_SHA256 = "028223a3dcbcbd6d7724558de02409e1e8874d876049f03fed38f47998773ba4"
WINDOWS_SHA256 = "646338cd9bcfe0fcd0411abbf4fb036fc739b4a586d739c8a9fe58d9ff654f46"
ASSETS = {
    "linux": "arcforges-ctr06-bridge-8e5-linux-amd64.zip",
    "windows": "arcforges-ctr06-bridge-8e5-windows-amd64.zip",
}
# Populated only after each bundle is generated on its own native host.
ASSET_SHA256 = {
    "linux": "85a506aea961296436f4aa7c06996d4f35ae21b373f56e0e61de8c1b94d7039e",
    "windows": "858102439faa18c056dbd5b2c87f84f16afcc188eaafa642d6e34ee6cb41ff27",
}
EXE = {
    "linux": ("arcforges-center", LINUX_SHA256),
    "windows": ("arcforges-center.exe", WINDOWS_SHA256),
}
METADATA = [
    "LICENSE",
    "center/dependencies.json",
    "center/go.mod",
    "center/go.sum",
    "center/toolchain.json",
    "eng/provenance/NOTICE.txt",
    "eng/provenance/records/center-runtime-r56.json",
    "eng/provenance/artifact-profiles/cloud-release-r110.json",
    "third-party/Go.LICENSE.txt",
]


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def archive_file(archive: tarfile.TarFile, name: str) -> bytes:
    entry = archive.getmember(name)
    if not entry.isfile() or entry.size > 16 * 1024 * 1024:
        raise ValueError("source archive member is not a bounded regular file")
    stream = archive.extractfile(entry)
    if stream is None:
        raise ValueError("source archive member is unavailable")
    data = stream.read()
    if len(data) != entry.size:
        raise ValueError("source archive member is truncated")
    return data


def source_evidence(source_tar: bytes) -> tuple[dict, dict[str, bytes]]:
    if digest(source_tar) != SOURCE_SHA256:
        raise ValueError("source archive does not match the reviewed 8e5 tree")
    with tarfile.open(fileobj=io.BytesIO(source_tar), mode="r:") as archive:
        dependencies = json.loads(archive_file(archive, "center/dependencies.json"))
        if dependencies.get("goVersion") != "go1.27.3":
            raise ValueError("bridge toolchain differs")
        modules = dependencies.get("runtimeModules")
        if not isinstance(modules, list):
            raise ValueError("bridge runtime dependency inventory is absent")
        by_name = {m["path"]: m for m in modules}
        if len(by_name) != len(modules):
            raise ValueError("duplicate bridge runtime dependency")
        contracts = by_name.get("github.com/ArcForges/Contracts/go", {})
        if contracts.get("version") != "v1.0.0-ci.437.1":
            raise ValueError("bridge Contracts cohort differs")
        paths = set(METADATA)
        for module in modules:
            paths.add(module["licenceFile"])
            if module.get("noticeFile"):
                paths.add(module["noticeFile"])
        files = {"notices/" + name: archive_file(archive, name) for name in sorted(paths)}
        for module in modules:
            for path_key, hash_key in (("licenceFile", "licenceSha256"), ("noticeFile", "noticeSha256")):
                if path_key in module and digest(files["notices/" + module[path_key]]) != module[hash_key]:
                    raise ValueError("bridge dependency licence or notice differs")
        return dependencies, files


def verify_buildinfo(executable: Path, platform: str, dependencies: dict) -> None:
    output = subprocess.check_output(["go", "version", "-m", str(executable)], text=True)
    lines = output.splitlines()
    if not lines or not lines[0].endswith(": go1.27.3"):
        raise ValueError("bridge executable has an unexpected Go version")
    deps: dict[str, tuple[str, str]] = {}
    settings: set[str] = set()
    main_path = ""
    for line in lines[1:]:
        parts = line.strip().split("\t")
        if parts[0] == "dep" and len(parts) == 4:
            if parts[1] in deps:
                raise ValueError("duplicate linked dependency")
            deps[parts[1]] = (parts[2], parts[3])
        elif parts[0] == "build" and len(parts) == 2:
            settings.add(parts[1])
        elif parts[0] == "path" and len(parts) == 2:
            main_path = parts[1]
    if main_path != "github.com/ArcForges/Cloud/center/cmd/arcforges-center":
        raise ValueError("bridge executable package differs")
    expected = {m["path"]: (m["version"], m["sum"]) for m in dependencies["runtimeModules"]}
    # The reviewed Windows build does not link x/sys; the Linux 615.1 build
    # does. All other modules and the old Contracts 437.1 identity match.
    if platform == "windows":
        expected.pop("golang.org/x/sys")
    if deps != expected:
        raise ValueError("bridge linked dependency closure differs")
    if not {"-trimpath=true", "CGO_ENABLED=0", "GOARCH=amd64", "GOOS=" + platform}.issubset(settings):
        raise ValueError("bridge executable build settings differ")


def expected_manifest(platform: str, files: dict[str, bytes], dependencies: dict) -> dict:
    executable, exe_hash = EXE[platform]
    origin = ({"kind": "published cloud-0.1.0-ci.615.1 OCI executable", "carrierSha256": CARRIER_SHA256,
               "ociManifestDigest": IMAGE_DIGEST} if platform == "linux" else
              {"kind": "native reproducible build from reviewed 8e5 source, not the 615.1 OCI executable",
               "flags": ["-trimpath", "-buildvcs=false",
                         "-ldflags=-buildid= -X=github.com/ArcForges/Cloud/center/internal/buildinfo.sourceCommit=" + REVISION +
                         " -X=github.com/ArcForges/Cloud/center/internal/buildinfo.sourceDirty=false"]})
    return {
        "schema": 1,
        "source": {"repository": "https://github.com/ArcForges/Cloud", "commit": REVISION, "tree": TREE,
                   "archive": "source.tar", "sha256": SOURCE_SHA256},
        "goVersion": "go1.27.3",
        "contracts": {"module": "github.com/ArcForges/Contracts/go", "version": "v1.0.0-ci.437.1"},
        "binary": {"platform": platform + "/amd64", "executable": executable, "sha256": exe_hash, "origin": origin},
        "runtimeModules": dependencies["runtimeModules"],
        "notLinked": ["golang.org/x/sys"] if platform == "windows" else [],
        "files": {name: {"sha256": digest(data), "size": len(data)} for name, data in sorted(files.items())},
    }


def make_bundle(platform: str, source: Path, binary: Path, output: Path) -> None:
    if platform not in EXE or not all(p.is_absolute() for p in (source, binary, output)) or output.exists():
        raise ValueError("bundle inputs must be absolute and the output must be new")
    head = subprocess.check_output(["git", "-C", str(source), "rev-parse", "HEAD"], text=True).strip()
    tree = subprocess.check_output(["git", "-C", str(source), "rev-parse", "HEAD^{tree}"], text=True).strip()
    status = subprocess.check_output(["git", "-C", str(source), "status", "--porcelain=v1"], text=True)
    if head != REVISION or tree != TREE or status:
        raise ValueError("bridge source checkout is not the reviewed clean tree")
    source_tar = subprocess.check_output(["git", "-C", str(source), "archive", "--format=tar", REVISION])
    write_bundle(platform, source_tar, binary, output)


def make_bundle_from_archive(platform: str, archive: Path, binary: Path, output: Path) -> None:
    if platform not in EXE or not all(p.is_absolute() for p in (archive, binary, output)) or output.exists():
        raise ValueError("bundle inputs must be absolute and the output must be new")
    write_bundle(platform, archive.read_bytes(), binary, output)


def write_bundle(platform: str, source_tar: bytes, binary: Path, output: Path) -> None:
    dependencies, notices = source_evidence(source_tar)
    exe_name, exe_hash = EXE[platform]
    exe_bytes = binary.read_bytes()
    if digest(exe_bytes) != exe_hash:
        raise ValueError("bridge executable digest differs")
    verify_buildinfo(binary, platform, dependencies)
    files = {"source.tar": source_tar, exe_name: exe_bytes, **notices}
    manifest = json.dumps(expected_manifest(platform, files, dependencies), sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode() + b"\n"
    files["manifest.json"] = manifest
    # Stored entries, fixed metadata and fixed order make the exact release
    # asset digest reproducible independently of zlib versions or clocks.
    with zipfile.ZipFile(output, "x", compression=zipfile.ZIP_STORED, allowZip64=False) as out:
        for name, data in sorted(files.items()):
            info = zipfile.ZipInfo(name, date_time=(1980, 1, 1, 0, 0, 0))
            info.create_system = 3
            info.external_attr = (0o100755 if name == "arcforges-center" else 0o100644) << 16
            out.writestr(info, data)
    verify_bundle(platform, output)


def verify_bundle(platform: str, bundle: Path) -> None:
    if platform not in EXE or not bundle.is_absolute() or not bundle.is_file():
        raise ValueError("bundle platform and absolute path are required")
    actual = hashlib.sha256()
    with bundle.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            actual.update(block)
    if actual.hexdigest() != ASSET_SHA256[platform]:
        raise ValueError("bridge release asset digest differs")
    with zipfile.ZipFile(bundle, "r") as archive:
        infos = archive.infolist()
        names = [info.filename for info in infos]
        if len(names) != len(set(names)) or len(names) > 100 or any(info.compress_type != zipfile.ZIP_STORED for info in infos):
            raise ValueError("unexpected or duplicate bundle member")
        if any(info.file_size > 128 * 1024 * 1024 or info.filename.startswith("/") or
               any(p in ("", ".", "..") for p in info.filename.split("/")) for info in infos):
            raise ValueError("unsafe bundle member")
        files = {info.filename: archive.read(info) for info in infos}
    manifest_raw = files.pop("manifest.json")
    source = files.get("source.tar", b"")
    dependencies, notices = source_evidence(source)
    exe_name, exe_hash = EXE[platform]
    if set(files) != {"source.tar", exe_name, *notices.keys()}:
        raise ValueError("bridge bundle membership differs")
    if digest(files[exe_name]) != exe_hash:
        raise ValueError("bridge binary differs")
    if any(files[name] != data for name, data in notices.items()):
        raise ValueError("bridge source notices differ")
    manifest = json.dumps(expected_manifest(platform, files, dependencies), sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode() + b"\n"
    if manifest_raw != manifest:
        raise ValueError("bridge manifest differs from its contents")

def main() -> None:
    if len(sys.argv) == 6 and sys.argv[1] == "build":
        make_bundle(sys.argv[2], *(Path(value) for value in sys.argv[3:]))
    elif len(sys.argv) == 6 and sys.argv[1] == "build-archive":
        make_bundle_from_archive(sys.argv[2], *(Path(value) for value in sys.argv[3:]))
    elif len(sys.argv) == 4 and sys.argv[1] == "verify":
        verify_bundle(sys.argv[2], Path(sys.argv[3]))
    else:
        raise ValueError("usage: ctr06_bridge_bundle.py build|build-archive PLATFORM /source /binary /output | verify PLATFORM /bundle")


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError, KeyError, json.JSONDecodeError, subprocess.CalledProcessError, tarfile.TarError, zipfile.BadZipFile):
        raise SystemExit("self-hosted bridge bundle verification failed") from None
