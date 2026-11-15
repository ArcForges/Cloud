# SPDX-License-Identifier: AGPL-3.0-only
"""Check actual Cloud SDK/Python/Node/npm selections before current builds."""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]


def invoke(arguments: list[str]) -> str:
    return subprocess.check_output(arguments, cwd=ROOT, text=True, encoding="utf-8").strip()


def exact(actual: str, expected: str, label: str) -> None:
    if actual != expected:
        raise ValueError(f"Wrong {label}: expected {expected}, observed {actual}")


def sdk_root(lines: str, version: str) -> Path:
    roots = [Path(match[1]) / version for line in lines.splitlines()
             if (match := re.fullmatch(re.escape(version) + r" \[(.+)\]", line))]
    if len(roots) != 1:
        raise ValueError("Selected SDK is missing or ambiguous in dotnet --list-sdks")
    return roots[0].resolve(strict=True)


def check(tools: list[str]) -> dict:
    report = {"schemaVersion": 1, "repository": "Cloud", "tools": {}, "inputs": {}}
    if "python" in tools:
        version = (ROOT / ".python-version").read_text().strip()
        exact(".".join(map(str, sys.version_info[:3])), version, "invoking Python")
        selected = shutil.which("python")
        if not selected or Path(selected).resolve() != Path(sys.executable).resolve():
            raise ValueError("PATH Python differs from invoking Python")
        report["tools"]["python"] = {"version": version, "path": str(Path(sys.executable).resolve())}
    if "dotnet" in tools:
        version = json.loads((ROOT / "global.json").read_text())["sdk"]["version"]
        exact(invoke(["dotnet", "--version"]), version, "dotnet SDK")
        root = sdk_root(invoke(["dotnet", "--list-sdks"]), version)
        output = invoke(["dotnet", "msbuild", "src/ArcForges.Cloud/ArcForges.Cloud.csproj", "-nologo",
                         "-getProperty:NETCoreSdkVersion,MSBuildToolsPath,MSBuildSDKsPath"])
        actual = json.loads(output)["Properties"]
        exact(actual["NETCoreSdkVersion"], version, "evaluated SDK")
        if Path(actual["MSBuildToolsPath"]).resolve() != root or Path(actual["MSBuildSDKsPath"]).resolve() != root / "Sdks":
            raise ValueError("Evaluated MSBuild SDK roots differ from the selected CLI SDK")
        override = os.environ.get("MSBuildSDKsPath")
        if override and Path(override).resolve() != root / "Sdks":
            raise ValueError("MSBuildSDKsPath override selects another SDK")
        report["tools"]["dotnet"] = {"version": version, "path": shutil.which("dotnet"), "sdkRoot": str(root), **actual}
    if "node" in tools:
        version = (ROOT / ".node-version").read_text().strip()
        exact(invoke(["node", "--version"]), "v" + version, "Node")
        executable = Path(invoke(["node", "-p", "process.execPath"])).resolve()
        npm = executable.parent / "node_modules/npm/bin/npm-cli.js"
        if not npm.is_file():
            raise ValueError("Selected Node does not contain its pinned npm")
        npm_version = invoke([str(executable), str(npm), "--version"])
        exact("npm@" + npm_version, json.loads((ROOT / "package.json").read_text())["packageManager"], "bundled npm")
        report["tools"]["node"] = {"version": version, "path": str(executable), "npm": npm_version, "npmPath": str(npm)}
    for name in (".python-version", ".node-version", "global.json", "Directory.Build.props", "Directory.Packages.props", "package-lock.json"):
        report["inputs"][name] = hashlib.sha256((ROOT / name).read_bytes().replace(b"\r\n", b"\n")).hexdigest()
    return report


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--tools", nargs="+", choices=("python", "dotnet", "node"), default=["python", "dotnet", "node"])
    args = parser.parse_args()
    try:
        result = check(args.tools)
    except (OSError, ValueError, KeyError, subprocess.SubprocessError) as error:
        parser.exit(1, f"Toolchain selection failed: {error}\n")
    output = ROOT / "artifacts/evidence/toolchain.json"
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(result, indent=2))
