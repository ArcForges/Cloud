#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
"""Pinned, offline-behavior Go checks. No deployment credentials or live database calls."""
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
MODULE = ROOT / "hello-go"
ENV = {**os.environ, "GOTOOLCHAIN": "local", "GOFLAGS": "-mod=readonly", "GOTELEMETRY": "off"}

def run(*args, capture=False):
    result = subprocess.run(args, cwd=MODULE, env=ENV, check=True, text=True,
                            encoding="utf-8", stdout=subprocess.PIPE if capture else None)
    return result.stdout if capture else ""

def validate_dependencies():
    manifest = json.loads((MODULE / "dependencies.json").read_text())
    if set(manifest["inputs"]) != {"go.mod", "go.sum", "contracts.lock.json", "toolchain.json"}:
        raise SystemExit("Unexpected Go dependency input inventory.")
    for name, expected in manifest["inputs"].items():
        actual = hashlib.sha256((MODULE / name).read_bytes().replace(b"\r\n", b"\n")).hexdigest()
        if actual != expected:
            raise SystemExit("Go dependency input requires a reviewed successor: " + name)
    raw = run("go", "list", "-deps", "-json", "./cmd/server", capture=True)
    decoder = json.JSONDecoder()
    actual = {}
    while raw.strip():
        raw = raw.lstrip()
        package, end = decoder.raw_decode(raw)
        raw = raw[end:]
        dependency = package.get("Module")
        if dependency and not dependency.get("Main"):
            actual[dependency["Path"]] = (dependency["Version"], dependency["Sum"])
    expected = {item["path"]: (item["version"], item["sum"]) for item in manifest["runtimeModules"]}
    if actual != expected:
        raise SystemExit("Unreviewed Go runtime dependency closure.")
    legal_root = (ROOT / "third-party").resolve()
    for item in manifest["runtimeModules"]:
        target = (ROOT / item["licenceFile"]).resolve()
        if not target.is_relative_to(legal_root):
            raise SystemExit("Invalid Go licence path.")
        actual_hash = hashlib.sha256(target.read_bytes().replace(b"\r\n", b"\n")).hexdigest()
        if actual_hash != item["licenceSha256"]:
            raise SystemExit("Changed Go dependency licence.")
    toolchain = json.loads((MODULE / "toolchain.json").read_text())
    dockerfile = (ROOT / "Dockerfile").read_text()
    if toolchain["linuxAmd64"]["url"] not in dockerfile or toolchain["linuxAmd64"]["sha256"] not in dockerfile:
        raise SystemExit("Docker Go toolchain differs from the reviewed archive.")

def main():
    if sys.argv[1:] != ["check"]:
        raise SystemExit("usage: python eng/hello-go.py check")
    pinned = json.loads((MODULE / "toolchain.json").read_text())["goVersion"]
    actual = run("go", "version", capture=True).split()
    if len(actual) < 3 or actual[2] != pinned:
        raise SystemExit(f"Install the pinned {pinned} on this native verification host.")
    before = {name: (MODULE / name).read_bytes() for name in ("go.mod", "go.sum")}
    run("go", "mod", "download")
    run("go", "mod", "verify")
    run("go", "run", "./tools/contractgen")
    validate_dependencies()
    unformatted = run("gofmt", "-l", "cmd", "tools", capture=True).strip()
    if unformatted:
        raise SystemExit("Unformatted Go sources: " + unformatted)
    run("go", "vet", "./...")
    run("go", "test", "./...")
    run("go", "tool", "govulncheck", "./cmd/server")
    artifact = ROOT / "artifacts" / "hello-go"
    artifact.mkdir(parents=True, exist_ok=True)
    executable = artifact / ("arcforges-hello-go.exe" if os.name == "nt" else "arcforges-hello-go")
    run("go", "build", "-trimpath", "-buildvcs=false", "-o", str(executable), "./cmd/server")
    for name, content in before.items():
        if (MODULE / name).read_bytes() != content:
            raise SystemExit(f"The locked Go check modified {name}.")
    evidence = {"go": pinned, "checks": ["module-integrity", "published-contract-generation",
        "format", "vet", "unit", "govulncheck", "native-build"], "passed": True,
        "liveDatabaseTested": False,
        "executableSha256": hashlib.sha256(executable.read_bytes()).hexdigest()}
    (artifact / "checks.json").write_text(json.dumps(evidence, indent=2) + "\n")
    print(json.dumps(evidence))

if __name__ == "__main__":
    main()
