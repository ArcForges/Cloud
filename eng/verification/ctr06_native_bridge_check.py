#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
"""Native host verification of the sealed self-hosted CTR06 bridge asset.

This runs in the ordinary full verification profile, without deployment
credentials. Windows compiles the reviewed source natively; Linux verifies and
extracts the durable 615.1 carrier. Temporary files belong to this invocation.
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import platform
import shutil
import subprocess
import sys
import tarfile
import tempfile
import urllib.request

import ctr06_bridge_bundle as bundle

ROOT = Path(__file__).resolve().parents[2]
CARRIER_NAME = "cloud-0.1.0-ci.615.1.tar.gz"
CARRIER_URL = ("https://github.com/ArcForges/Cloud/releases/download/"
               "cloud-0.1.0-ci.615.1/" + CARRIER_NAME)
CARRIER_LIMIT = 128 * 1024 * 1024
BRIDGE_GO_ENV = "ARCFORGES_CTR06_BRIDGE_GO"


def bridge_environment(**extra: str) -> dict[str, str]:
    # The historical compiler is chosen only for this subprocess. Do not pass
    # the selector or a newer GOROOT into it, or change the parent's PATH.
    env = dict(os.environ)
    env.pop(BRIDGE_GO_ENV, None)
    env.pop("ARCFORGES_CENTER_GO", None)
    env.pop("GOROOT", None)
    env.update({"GOTOOLCHAIN": "local", "GOWORK": "off", **extra})
    return env


def checked_bridge_go(host: str, cwd: Path, env: dict[str, str]) -> str:
    if host not in ("windows", "linux"):
        raise ValueError("unsupported bridge compiler host")
    selected = os.environ.get(BRIDGE_GO_ENV)
    if selected is None:
        executable = "go"
    else:
        path = Path(selected)
        if not path.is_absolute() or not path.is_file():
            raise ValueError("the selected bridge Go executable must be an existing absolute file")
        executable = str(path)
    version = subprocess.check_output([executable, "version"], cwd=cwd, env=env, text=True).strip()
    target = subprocess.check_output([executable, "env", "GOOS", "GOARCH"], cwd=cwd, env=env, text=True).splitlines()
    if version != f"go version go1.27.3 {host}/amd64" or target != [host, "amd64"]:
        raise ValueError(f"the {host} bridge needs native Go 1.27.3 amd64")
    return executable


def run(argv, cwd=ROOT, env=None):
    subprocess.run(argv, cwd=cwd, env=env, check=True, timeout=300)


def archive_source(destination: Path) -> None:
    with destination.open("xb") as output:
        subprocess.run(["git", "archive", "--format=tar", bundle.REVISION],
                       cwd=ROOT, stdout=output, check=True, timeout=60)
    data = destination.read_bytes()
    if hashlib.sha256(data).hexdigest() != bundle.SOURCE_SHA256:
        raise ValueError("the reviewed bridge source archive differs")


def unpack_center(archive: Path, destination: Path) -> Path:
    destination.mkdir(mode=0o700)
    with tarfile.open(archive, "r:") as source:
        for item in source:
            if not item.name.startswith("center/"):
                continue
            parts = item.name.split("/")
            if any(part in ("", ".", "..") or "\\" in part or ":" in part for part in parts):
                raise ValueError("unsafe archived source path")
            if item.isdir():
                (destination / item.name).mkdir(parents=True, exist_ok=True)
            elif item.isfile():
                target = destination / item.name
                target.parent.mkdir(parents=True, exist_ok=True)
                contents = source.extractfile(item)
                if contents is None or item.size > 16 * 1024 * 1024:
                    raise ValueError("invalid archived source member")
                with contents, target.open("xb") as output:
                    shutil.copyfileobj(contents, output, 1024 * 1024)
            else:
                raise ValueError("linked or special archived source member")
    return destination / "center"


def native_windows(source_archive: Path, directory: Path) -> Path:
    center = unpack_center(source_archive, directory / "source")
    binary = directory / "arcforges-center.exe"
    env = bridge_environment(CGO_ENABLED="0", GOFLAGS="-mod=readonly", GOTELEMETRY="off")
    go = checked_bridge_go("windows", center, env)
    link = ("-buildid= -X=github.com/ArcForges/Cloud/center/internal/buildinfo.sourceCommit=" +
            bundle.REVISION + " -X=github.com/ArcForges/Cloud/center/internal/buildinfo.sourceDirty=false")
    run([go, "build", "-trimpath", "-buildvcs=false", "-ldflags", link, "-o", str(binary),
         "./cmd/arcforges-center"], cwd=center, env=env)
    identity = json.loads(subprocess.check_output([str(binary), "version"], cwd=center, env=env, text=True))
    if identity.get("build", {}).get("sourceCommit") != bundle.REVISION or identity.get("build", {}).get("dirty") is not False:
        raise ValueError("the native Windows bridge identity differs")
    return binary


def find_or_download_carrier(directory: Path) -> Path:
    explicit = os.environ.get("ARCFORGES_CTR06_BRIDGE_CARRIER", "")
    if explicit:
        carrier = Path(explicit)
        if not carrier.is_absolute() or not carrier.is_file():
            raise ValueError("the selected bridge carrier is unavailable")
        return carrier
    # Reuse the already retrieved carrier in the documented Linux workspace.
    existing = (Path.home() / "arcforges/tmp/af-ctr-06-scratch/cloud/"
                "ctr06-bridge-durable-carrier-20261110" / CARRIER_NAME)
    if existing.is_file():
        return existing
    # A new verifier host can obtain the public durable carrier once for this
    # invocation; its fixed digest is checked before parsing or use.
    target = directory / CARRIER_NAME
    request = urllib.request.Request(CARRIER_URL, headers={"User-Agent": "ArcForges-CTR06-native-verifier"})
    with urllib.request.urlopen(request, timeout=120) as response, target.open("xb") as output:
        size = 0
        while block := response.read(1024 * 1024):
            size += len(block)
            if size > CARRIER_LIMIT:
                raise ValueError("bridge carrier exceeds its bound")
            output.write(block)
    return target


def native_linux(directory: Path) -> Path:
    if platform.machine() not in ("x86_64", "amd64"):
        raise ValueError("no reviewed native Linux bridge exists for this architecture")
    env = bridge_environment()
    checked_bridge_go("linux", ROOT, env)
    carrier = find_or_download_carrier(directory)
    extracted = directory / "carrier"
    extracted.mkdir(mode=0o700)
    binary = directory / "arcforges-center"
    run(["python3", str(ROOT / "tooling/ctr06_bridge_carrier.py"), str(carrier), str(extracted), str(binary)])
    return binary


def main() -> None:
    current = "windows" if os.name == "nt" else "linux" if sys.platform.startswith("linux") else ""
    if current not in bundle.ASSETS:
        raise ValueError("this host has no reviewed native bridge")
    with tempfile.TemporaryDirectory(prefix="arcforges-ctr06-native-") as temp:
        directory = Path(temp).resolve()
        archive = directory / "source.tar"
        archive_source(archive)
        binary = native_windows(archive, directory) if current == "windows" else native_linux(directory)
        output = directory / bundle.ASSETS[current]
        bundle.make_bundle_from_archive(current, archive, binary, output)
        # Use the same active release profile and verifier as the guarded main
        # release, not a manually written status or a copied evidence file.
        node = ("import fs from 'node:fs'; "
                "import {verifyBridgeAsset} from './tooling/release-provenance.ts'; "
                "verifyBridgeAsset(process.cwd(),process.argv[1],fs.readFileSync(process.argv[2]));")
        run(["node", "--input-type=module", "-e", node, current, str(output)])
        print("verified native", current, "bridge asset", bundle.ASSET_SHA256[current])


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError, subprocess.SubprocessError, tarfile.TarError, json.JSONDecodeError):
        raise SystemExit("native self-hosted bridge verification failed") from None
