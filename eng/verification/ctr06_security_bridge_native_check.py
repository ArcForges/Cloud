#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
"""Exercise the actual security-bridge producer on this native verification host.

The local event and run identifiers are synthetic and authorize nothing. No artifact
is uploaded. The producer and its source are separate, clean checkouts of the
reviewed commits; the original producer checks them again. The archive is an
existing, non-secret Go distribution selected only for this process.
"""
from __future__ import annotations

import json
import os
from pathlib import Path
import secrets
import shutil
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[2]
PRODUCER = "9b8796eac760982d9814f371b820b736ddd945c4"
PRODUCER_TREE = "2b35c50007089d6e6c51797f62437334bd2826f3"
SOURCE = "8e5f6e26aa97b123d9f60b91f780364a094e74cd"
SOURCE_TREE = "4a315ea6b47d96c3262e8111fcc26ad1957097f2"
ARCHIVE_ENV = "ARCFORGES_CTR06_SECURITY_GO_ARCHIVE"


def selected_file(value: str | None, label: str) -> Path:
    if not value:
        raise ValueError(f"{label} must select an existing absolute file")
    candidate = Path(value)
    if not candidate.is_absolute():
        raise ValueError(f"{label} must select an existing absolute file")
    candidate = candidate.resolve(strict=True)
    if not candidate.is_file():
        raise ValueError(f"{label} must select an existing absolute file")
    return candidate


def environment() -> dict[str, str]:
    allowed = ("PATH", "HOME", "USERPROFILE", "LOCALAPPDATA", "SYSTEMROOT", "WINDIR", "COMSPEC", "PATHEXT",
               "TMP", "TEMP", "TMPDIR", "LANG", "LC_ALL", "DOTNET_ROOT")
    return {key: os.environ[key] for key in allowed if key in os.environ}


def run(argv: list[str], cwd: Path, env: dict[str, str], capture: bool = False) -> str:
    result = subprocess.run(argv, cwd=cwd, env=env, check=True, text=True,
                            stdout=subprocess.PIPE if capture else None, timeout=1200)
    return result.stdout.strip() if capture and result.stdout else ""


def verify_checkout(directory: Path, commit: str, tree: str, env: dict[str, str],
                    *, fresh: bool) -> None:
    git = ["git", "--no-replace-objects"]
    if Path(run(git + ["rev-parse", "--show-toplevel"], directory, env, True)).resolve() != directory:
        raise ValueError("historical Git checkout root differs")
    identity = run(git + ["rev-parse", "HEAD", "HEAD^{tree}"], directory, env, True)
    if identity.splitlines() != [commit, tree]:
        raise ValueError("historical Git checkout commit or tree differs")
    args = git + ["status", "--porcelain=v1", "--untracked-files=all"]
    if fresh:
        args.append("--ignored=matching")
    if run(args, directory, env, True):
        raise ValueError("historical Git checkout has unexpected files or changes")


def materialize_checkouts(tmp: Path, env: dict[str, str]) -> tuple[Path, Path]:
    producer = tmp / "producer"
    source = tmp / "source"
    # Never run a hook from the current Git configuration when materializing a checkout.
    git = ["git", "--no-replace-objects", "-c", f"core.hooksPath={tmp / 'unused-hooks'}"]
    run(git + ["clone", "--quiet", "--no-local", "--no-checkout", "--",
               str(ROOT), str(producer)], ROOT, env)
    run(git + ["checkout", "--quiet", "--detach", PRODUCER], producer, env)
    verify_checkout(producer, PRODUCER, PRODUCER_TREE, env, fresh=True)
    run(git + ["worktree", "add", "--detach", str(source), SOURCE], producer, env)
    verify_checkout(source, SOURCE, SOURCE_TREE, env, fresh=True)
    return producer, source


def main() -> None:
    platform = "windows" if os.name == "nt" else "linux" if sys.platform.startswith("linux") else ""
    if not platform:
        raise ValueError("unsupported native security bridge platform")
    archive = selected_file(os.environ.get(ARCHIVE_ENV), ARCHIVE_ENV)
    choice = os.environ.get("ARCFORGES_CENTER_GO") or shutil.which("go")
    go = selected_file(choice, "native Go executable")
    if go.name.lower() != ("go.exe" if platform == "windows" else "go"):
        raise ValueError("native Go executable name differs")
    env = environment()
    env.update({"GOTOOLCHAIN": "local", "GOWORK": "off", "GOTELEMETRY": "off",
                "PYTHONDONTWRITEBYTECODE": "1"})
    if platform == "linux":
        # The reviewed producer uses Node 26; the 8e5 source uses its separately
        # preserved historical Node/npm pair.
        historical = selected_file(os.environ.get("ARCFORGES_CTR06_HISTORICAL_NODE") or
                                   str(Path.home() / ".local/node/bin/node"), "historical 8e5 Node")
        if run([str(historical), "--version"], ROOT, env, True) != "v24.21.0":
            raise ValueError("the frozen 8e5 source requires preserved Node 24.21.0")
        env["ARCFORGES_CTR06_HISTORICAL_NODE"] = str(historical)
    # Windows resolves a bare executable using the parent's PATH before its child
    # environment is installed. Resolve the actual Node selection explicitly.
    node = selected_file(shutil.which("node", path=env.get("PATH")), "native Node executable")
    if run([str(node), "--version"], ROOT, env, True) != "v26.13.1":
        raise ValueError("the security bridge requires native Node 26.13.1")
    head = run(["git", "rev-parse", "HEAD"], ROOT, env, True)
    if len(head) != 40 or any(c not in "0123456789abcdef" for c in head):
        raise ValueError("invalid verified HEAD")
    with tempfile.TemporaryDirectory(prefix="arcforges-ctr06-security-native-") as name:
        tmp = Path(name).resolve()
        runner = tmp / "runner"
        runner.mkdir(mode=0o700)
        producer, source = materialize_checkouts(tmp, env)
        if platform == "windows":
            npm = run([str(node), "-p", "require('path').join(require('path').dirname(process.execPath), 'node_modules', 'npm', 'bin', 'npm-cli.js')"], producer, env, True)
            run([str(node), npm, "ci", "--ignore-scripts"], producer, env)
        else:
            run(["npm", "ci", "--ignore-scripts"], producer, env)
        verify_checkout(producer, PRODUCER, PRODUCER_TREE, env, fresh=False)
        verify_checkout(source, SOURCE, SOURCE_TREE, env, fresh=True)
        event = tmp / "synthetic-push.json"
        event.write_text(json.dumps({"ref": "refs/heads/main", "after": PRODUCER, "deleted": False,
                                     "repository": {"full_name": "ArcForges/Cloud", "default_branch": "main"}}),
                         encoding="utf-8")
        number = str(10000000000000 + secrets.randbelow(89999999999999))
        env.update({"GITHUB_ACTIONS": "true", "GITHUB_EVENT_NAME": "push", "GITHUB_REPOSITORY": "ArcForges/Cloud",
                    "GITHUB_SERVER_URL": "https://github.com", "GITHUB_REF": "refs/heads/main",
                    "GITHUB_REF_PROTECTED": "true", "GITHUB_WORKFLOW_REF": "ArcForges/Cloud/.github/workflows/ci.yml@refs/heads/main",
                    "GITHUB_WORKFLOW_SHA": PRODUCER, "GITHUB_SHA": PRODUCER, "GITHUB_RUN_ID": number,
                    "GITHUB_RUN_NUMBER": number, "GITHUB_RUN_ATTEMPT": "1", "GITHUB_EVENT_PATH": str(event),
                    "RUNNER_TEMP": str(runner)})
        tag = f"arcforges-ctr06-security-bridge:ci.{number}.1"
        if platform == "linux":
            exists = subprocess.run(["docker", "image", "inspect", tag], cwd=producer, env=env,
                                    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=False)
            if exists.returncode == 0:
                raise ValueError("synthetic image tag is already occupied")
        print("Synthetic local producer context; this is not a GitHub run, publication or authority proof.", flush=True)
        run([str(node), "tooling/ctr06-security-bridge-producer.ts", platform, str(source), str(archive),
             str(go), str(runner / "output")], producer, env)
        if platform == "linux":
            manifest = json.loads((runner / "output/sealed/manifest.json").read_text(encoding="utf-8"))
            expected = manifest["imageId"]
            actual = run(["docker", "image", "inspect", "--format", "{{.Id}}", tag], producer, env, True)
            if actual != expected:
                raise ValueError("synthetic image identity changed before cleanup")
            run(["docker", "image", "rm", tag], producer, env)
        print(f"Verified synthetic native {platform} historical security bridge producer {PRODUCER} "
              f"for bridge source {SOURCE} while checking current HEAD {head}.", flush=True)


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError, subprocess.SubprocessError, json.JSONDecodeError) as error:
        raise SystemExit(f"native security bridge verification failed: {error}") from None
