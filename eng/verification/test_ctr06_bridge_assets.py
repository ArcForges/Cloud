#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
"""Offline checks for release metadata and sealed bridge assets."""
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import shlex
import tarfile
import zipfile
import subprocess
import tempfile
import types
import unittest
import warnings
from unittest import mock

import ctr06_bridge_asset_state as state
import ctr06_bridge_bundle as bundle
import ctr06_native_bridge_check as native
import ctr06_security_bridge_compiler as security_compiler
import ctr06_security_bridge_driver as security_driver
import ctr06_security_bridge_native_check as security_native


def asset(platform, digest=None):
    return {"name": bundle.ASSETS[platform], "state": "uploaded",
            "digest": "sha256:" + (digest or bundle.ASSET_SHA256[platform])}


class SecurityBridgeCompilerTest(unittest.TestCase):
    @staticmethod
    def sample(root, kind):
        folder = root / "go"
        (folder / "bin").mkdir(parents=True)
        (folder / "bin" / "go").write_bytes(b"verified compiler")
        (folder / "VERSION").write_bytes(b"go1.27.4")
        archive = root / ("sample.tar.gz" if kind == "linux" else "sample.zip")
        if kind == "linux":
            with tarfile.open(archive, "w:gz") as writer:
                writer.add(folder, arcname="go")
        else:
            with zipfile.ZipFile(archive, "w") as writer:
                writer.write(folder / "bin" / "go", "go/bin/go")
                writer.write(folder / "VERSION", "go/VERSION")
        return folder, archive

    def test_complete_distribution_and_tampering_are_checked(self):
        for kind in ("linux", "windows"):
            with self.subTest(kind=kind), tempfile.TemporaryDirectory() as tmp:
                folder, archive = self.sample(Path(tmp), kind)
                self.assertEqual(security_compiler.compare_distribution(folder, archive, kind), 2)
                compiler = folder / "bin" / "go"
                compiler.write_bytes(b"changed compiler!")
                with self.assertRaises(ValueError):
                    security_compiler.compare_distribution(folder, archive, kind)
                compiler.write_bytes(b"verified compiler")
                (folder / "extra").write_text("unclassified")
                with self.assertRaises(ValueError):
                    security_compiler.compare_distribution(folder, archive, kind)
                (folder / "extra").unlink()
                (folder / "unexpected-dir").mkdir()
                with self.assertRaises(ValueError):
                    security_compiler.compare_distribution(folder, archive, kind)

    def test_bad_member_names_duplicates_and_wrong_archive_fail(self):
        for name in ("../go/a", "go/../outside", "/go/a", "go/a\\b", "go/C:evil"):
            with self.subTest(name=name), self.assertRaises(ValueError):
                security_compiler.safe_name(name)
        with tempfile.TemporaryDirectory() as tmp:
            folder, archive = self.sample(Path(tmp), "windows")
            with warnings.catch_warnings():
                warnings.filterwarnings("ignore", message="Duplicate name:")
                with zipfile.ZipFile(archive, "a") as writer:
                    writer.writestr("go/VERSION", b"duplicate")
            with self.assertRaises(ValueError):
                security_compiler.compare_distribution(folder, archive, "windows")
            with self.assertRaises(ValueError):
                security_compiler.verify_compiler(archive, folder, "windows" if os.name == "nt" else "linux")


class SecurityBridgeCarrierTest(unittest.TestCase):
    def test_closed_carrier_checks_real_archive_bytes_and_metadata(self):
        members = {"manifest.json": b"manifest", "linux/a": b"linux", "windows/b": b"windows"}
        expected = {name: {"sha256": hashlib.sha256(data).hexdigest(), "size": len(data)}
                    for name, data in members.items()}
        with tempfile.TemporaryDirectory() as tmp:
            archive = Path(tmp) / "carrier.tar.gz"
            def make(change=None):
                with tarfile.open(archive, "w:gz") as writer:
                    for name in (".", "linux", "windows"):
                        info = tarfile.TarInfo(name)
                        info.type = tarfile.DIRTYPE
                        info.mode = 0o755
                        info.mtime = info.uid = info.gid = 0
                        writer.addfile(info)
                    for name, original in members.items():
                        data = b"changed" if change == "content" and name == "linux/a" else original
                        info = tarfile.TarInfo(name)
                        info.size = len(data)
                        info.mode = 0o600 if change == "mode" and name == "linux/a" else 0o644
                        info.mtime = 1 if change == "time" and name == "linux/a" else 0
                        info.uid = 1 if change == "owner" and name == "linux/a" else 0
                        info.gid = 0
                        if change == "missing" and name == "linux/a":
                            continue
                        writer.addfile(info, io.BytesIO(data))
                        if change == "duplicate" and name == "linux/a":
                            writer.addfile(info, io.BytesIO(data))
                    if change == "extra":
                        info = tarfile.TarInfo("linux/extra")
                        info.size = 1
                        info.mode = 0o644
                        info.mtime = info.uid = info.gid = 0
                        writer.addfile(info, io.BytesIO(b"x"))
            make()
            self.assertEqual(security_driver.verify_carrier(archive, expected)["members"], len(members))
            for change in ("content", "mode", "time", "owner", "missing", "duplicate", "extra"):
                with self.subTest(change=change):
                    make(change)
                    with self.assertRaises(ValueError):
                        security_driver.verify_carrier(archive, expected)


class SecurityBridgeNativeSelectionTest(unittest.TestCase):
    def test_archive_selection_and_child_environment_fail_closed(self):
        with tempfile.TemporaryDirectory(prefix="security archive ") as tmp:
            archive = Path(tmp) / "go archive.zip"
            archive.write_bytes(b"synthetic input")
            self.assertEqual(security_native.selected_file(str(archive), "archive"), archive.resolve())
            for value in (None, "", "relative", str(Path(tmp)), str(Path(tmp) / "missing")):
                with self.subTest(value=value), self.assertRaises((ValueError, OSError)):
                    security_native.selected_file(value, "archive")
            with mock.patch.dict(os.environ, {"LOCALAPPDATA": "local-cache", "ARCFORGES_CTR06_BRIDGE_GO": "old", "GH_TOKEN": "private",
                                               "NEON_DATABASE_URL": "private", "CLOUDFLARE_API_TOKEN": "private"}):
                child = security_native.environment()
                self.assertEqual(child["LOCALAPPDATA"], "local-cache")
                for key in ("ARCFORGES_CTR06_BRIDGE_GO", "GH_TOKEN", "NEON_DATABASE_URL", "CLOUDFLARE_API_TOKEN"):
                    self.assertNotIn(key, child)

    def test_host_steps_capture_the_absolute_archive(self):
        with tempfile.TemporaryDirectory(prefix="security archive ") as tmp:
            archive = Path(tmp) / "official archive"
            archive.write_bytes(b"synthetic input")
            with mock.patch.dict(os.environ, {"ARCFORGES_CTR06_SECURITY_GO_ARCHIVE": str(archive)}, clear=False):
                table = load_verify_steps()
                self.assertEqual(table["_SECURITY_GO_ARCHIVE"], str(archive.resolve()))
                win = next(step for step in table["STEPS"] if step.id == "win-ctr06-security-bridge")
                self.assertEqual(win.env["ARCFORGES_CTR06_SECURITY_GO_ARCHIVE"], str(archive.resolve()))
                linux = next(step for step in table["STEPS"] if step.id == "linux-ctr06-security-bridge")
                self.assertIn(shlex.quote(str(archive.resolve())), linux.cmd)
                if os.name != "nt":
                    code = "import os; print(os.environ.get('ARCFORGES_CTR06_SECURITY_GO_ARCHIVE'))"
                    command = linux.cmd.replace("python eng/verification/ctr06_security_bridge_native_check.py",
                                                f"python -c {shlex.quote(code)}")
                    profile = f"export ARCFORGES_CTR06_SECURITY_GO_ARCHIVE=decoy; {command}"
                    result = subprocess.run(["bash", "-lc", profile], check=True, text=True, capture_output=True)
                    self.assertEqual(result.stdout.strip(), str(archive.resolve()))
            for value in ("", "relative", str(Path(tmp)), str(Path(tmp) / "missing")):
                with self.subTest(value=value), mock.patch.dict(os.environ, {"ARCFORGES_CTR06_SECURITY_GO_ARCHIVE": value}):
                    with self.assertRaises(ValueError):
                        load_verify_steps()


class BridgeGoSelectionTest(unittest.TestCase):
    def test_default_keeps_path_and_explicit_absolute_file_is_isolated(self):
        with tempfile.TemporaryDirectory() as tmp, mock.patch.dict(os.environ, {}, clear=False):
            directory = Path(tmp)
            old_go = directory / "go"
            old_go.write_bytes(b"synthetic executable")
            original_path = os.environ.get("PATH", "")
            os.environ[native.BRIDGE_GO_ENV] = str(old_go)
            os.environ["ARCFORGES_CENTER_GO"] = str(directory / "current-go")
            os.environ["GOROOT"] = str(directory / "newer-goroot")
            env = native.bridge_environment(CGO_ENABLED="0")
            self.assertNotIn(native.BRIDGE_GO_ENV, env)
            self.assertNotIn("ARCFORGES_CENTER_GO", env)
            self.assertNotIn("GOROOT", env)
            self.assertEqual(env.get("PATH", ""), original_path)
            self.assertEqual(os.environ.get("PATH", ""), original_path)
            self.assertEqual(env["GOTOOLCHAIN"], "local")
            self.assertEqual(env["GOWORK"], "off")
            with mock.patch.object(native.subprocess, "check_output", side_effect=[
                    "go version go1.27.3 linux/amd64\n", "linux\namd64\n"]) as check:
                self.assertEqual(native.checked_bridge_go("linux", directory, env), str(old_go))
            self.assertEqual(check.call_args_list[0].args[0], [str(old_go), "version"])
            self.assertEqual(check.call_args_list[1].args[0], [str(old_go), "env", "GOOS", "GOARCH"])
            os.environ.pop(native.BRIDGE_GO_ENV)
            with mock.patch.object(native.subprocess, "check_output", side_effect=[
                    "go version go1.27.3 linux/amd64\n", "linux\namd64\n"]) as check:
                self.assertEqual(native.checked_bridge_go("linux", directory, env), "go")
            self.assertEqual(check.call_args_list[0].args[0], ["go", "version"])
            self.assertEqual(os.environ.get("PATH", ""), original_path)

    def test_relative_empty_missing_and_directory_paths_fail_without_echo(self):
        with tempfile.TemporaryDirectory() as tmp:
            directory = Path(tmp)
            for value in ("", "relative-secret", str(directory / "missing"), str(directory)):
                with self.subTest(value=value), mock.patch.dict(os.environ, {native.BRIDGE_GO_ENV: value}):
                    with mock.patch.object(native.subprocess, "check_output") as check:
                        with self.assertRaises(ValueError) as refusal:
                            native.checked_bridge_go("linux", directory, native.bridge_environment())
                    check.assert_not_called()
                    if value:
                        self.assertNotIn(value, str(refusal.exception))

    def test_wrong_version_arch_and_host_refuse_without_fallback(self):
        with tempfile.TemporaryDirectory() as tmp:
            directory = Path(tmp)
            old_go = directory / "go"
            old_go.write_bytes(b"synthetic executable")
            cases = [
                ("linux", "go version go1.27.4 linux/amd64\n", "linux\namd64\n"),
                ("linux", "go version go1.27.3 windows/amd64\n", "linux\namd64\n"),
                ("linux", "go version go1.27.3 linux/amd64\n", "linux\narm64\n"),
                ("windows", "go version go1.27.3 windows/amd64\n", "linux\namd64\n"),
            ]
            with mock.patch.dict(os.environ, {native.BRIDGE_GO_ENV: str(old_go)}):
                for host, version, target in cases:
                    with self.subTest(host=host, version=version, target=target):
                        with mock.patch.object(native.subprocess, "check_output", side_effect=[version, target]) as check:
                            with self.assertRaises(ValueError):
                                native.checked_bridge_go(host, directory, native.bridge_environment())
                        self.assertEqual(check.call_count, 2)
                        self.assertTrue(all(call.args[0][0] == str(old_go) for call in check.call_args_list))
                with self.assertRaises(ValueError):
                    native.checked_bridge_go("other", directory, native.bridge_environment())


ROOT = Path(__file__).resolve().parents[2]


def load_center():
    spec = importlib.util.spec_from_file_location("center_selection_test", ROOT / "eng/center.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def load_verify_steps():
    class TestStep:
        def __init__(self, step_id, host, cmd, **kwargs):
            self.id, self.host, self.cmd = step_id, host, cmd
            self.env = kwargs.get("env", {})

    source = ROOT / "eng/verify_steps.py"
    namespace = {"Step": TestStep, "__name__": "verify_steps_selection_test"}
    exec(compile(source.read_text(encoding="utf-8"), str(source), "exec"), namespace)
    return namespace


class CenterGoSelectionTest(unittest.TestCase):
    def test_absolute_selection_is_shared_and_child_local(self):
        with tempfile.TemporaryDirectory(prefix="center go selection ") as tmp:
            directory = Path(tmp)
            go = directory / ("go.exe" if os.name == "nt" else "go")
            fmt = directory / ("gofmt.exe" if os.name == "nt" else "gofmt")
            go.write_bytes(b"synthetic Go")
            fmt.write_bytes(b"synthetic gofmt")
            values = {"ARCFORGES_CENTER_GO": str(go), "ARCFORGES_CTR06_BRIDGE_GO": str(directory / "old-go"),
                      "GOROOT": str(directory / "old-goroot")}
            with mock.patch.dict(os.environ, values, clear=False):
                before_path = os.environ.get("PATH", "")
                table = load_verify_steps()
                center = load_center()
                self.assertEqual(table["_CENTER_GO"], str(go.resolve()))
                self.assertEqual(center.selected_center_tool("go"), str(go.resolve()))
                self.assertEqual(center.selected_center_tool("gofmt"), str(fmt.resolve()))
                self.assertNotIn("GOROOT", center.ENV)
                self.assertNotIn("ARCFORGES_CENTER_GO", center.ENV)
                self.assertNotIn("ARCFORGES_CTR06_BRIDGE_GO", center.ENV)
                self.assertEqual(os.environ.get("PATH", ""), before_path)
                with mock.patch.object(center.subprocess, "run",
                                       return_value=types.SimpleNamespace(returncode=0, stdout="ok\n")) as run:
                    center.go("go", "version", capture=True)
                    center.go("gofmt", "-l", ".", capture=True)
                self.assertEqual(run.call_args_list[0].args[0], (str(go.resolve()), "version"))
                self.assertEqual(run.call_args_list[1].args[0], (str(fmt.resolve()), "-l", "."))
                self.assertTrue(all(call.kwargs["env"] is center.ENV for call in run.call_args_list))
                win = next(step for step in table["STEPS"] if step.id == "win-center")
                linux = next(step for step in table["STEPS"] if step.id == "linux-center")
                self.assertEqual(win.env["ARCFORGES_CENTER_GO"], str(go.resolve()))
                self.assertIn(shlex.quote(str(go.resolve())), linux.cmd)
                self.assertEqual(table["FINGERPRINT"]["win"]["go"][-1], str(go.resolve()))
                self.assertIn(shlex.quote(str(go.resolve())), table["FINGERPRINT"]["linux"]["go"])

    def test_default_and_invalid_selectors_do_not_fallback(self):
        with tempfile.TemporaryDirectory() as tmp, mock.patch.dict(os.environ, {}, clear=False):
            os.environ.pop("ARCFORGES_CENTER_GO", None)
            table = load_verify_steps()
            center = load_center()
            self.assertEqual(table["FINGERPRINT"]["win"]["go"], ["go", "version"])
            self.assertEqual(table["FINGERPRINT"]["linux"]["go"], "go version")
            self.assertEqual(center.selected_center_tool("go"), "go")
            name = "go.exe" if os.name == "nt" else "go"
            wrong_name = Path(tmp) / ("wrong.exe" if os.name == "nt" else "wrong")
            wrong_name.write_bytes(b"not Go")
            missing = Path(tmp) / "missing" / name
            invalid = ["", "relative-secret", str(Path(tmp)), str(wrong_name), str(missing)]
            if os.name != "nt":
                wrong_case = Path(tmp) / "GO"
                wrong_case.write_bytes(b"not go")
                invalid.append(str(wrong_case))
            for value in invalid:
                with self.subTest(value=value), mock.patch.dict(os.environ, {"ARCFORGES_CENTER_GO": value}):
                    with self.assertRaises(ValueError) as error:
                        load_verify_steps()
                    if value:
                        self.assertNotIn(value, str(error.exception))
                    center = load_center()
                    with self.assertRaises(SystemExit):
                        center.selected_center_tool("go")

    def test_version_and_native_target_are_checked(self):
        center = load_center()
        pinned = json.loads((ROOT / "center/toolchain.json").read_text(encoding="utf-8"))["goVersion"]
        host = "windows" if os.name == "nt" else "linux"
        good_version = f"go version {pinned} {host}/amd64\n"
        good_target = f"{host}\namd64\n"
        with mock.patch.object(center, "go", side_effect=[good_version, good_target]):
            self.assertEqual(center.check_toolchain(), pinned)
        cases = [(f"go version go1.27.3 {host}/amd64\n", good_target),
                 (f"go version {pinned} {host}/arm64\n", good_target),
                 (good_version, f"{host}\narm64\n"),
                 (good_version, "other\namd64\n")]
        for version, target in cases:
            with self.subTest(version=version, target=target), mock.patch.object(center, "go",
                                                                               side_effect=[version, target]):
                with self.assertRaises(SystemExit):
                    center.check_toolchain()

    @unittest.skipIf(os.name == "nt", "Linux login-shell behavior is tested on Linux")
    def test_login_profile_path_and_selector_changes_do_not_change_the_choice(self):
        with tempfile.TemporaryDirectory(prefix="login profile ") as tmp, mock.patch.dict(os.environ, {}, clear=False):
            directory = Path(tmp)
            selected_dir = directory / "selected compiler"
            decoy_dir = directory / "profile compiler"
            selected_dir.mkdir()
            decoy_dir.mkdir()
            selected = selected_dir / "go"
            decoy = decoy_dir / "go"
            selected.write_text("#!/bin/sh\nprintf 'selected-native-go\\n'\n", encoding="utf-8")
            decoy.write_text("#!/bin/sh\nprintf 'wrong-profile-go\\n'\n", encoding="utf-8")
            selected.chmod(0o700)
            decoy.chmod(0o700)
            os.environ["ARCFORGES_CENTER_GO"] = str(selected)
            table = load_verify_steps()
            profile = directory / "profile"
            profile.write_text(f"export PATH={shlex.quote(str(decoy_dir))}:\"$PATH\"\n"
                               f"export ARCFORGES_CENTER_GO={shlex.quote(str(decoy))}\n", encoding="utf-8")
            probe = table["FINGERPRINT"]["linux"]["go"]
            step = next(step for step in table["STEPS"] if step.id == "linux-center")
            code = ("import importlib.util; s=importlib.util.spec_from_file_location('center', "
                    + repr(str(ROOT / "eng/center.py")) + "); m=importlib.util.module_from_spec(s); "
                    "s.loader.exec_module(m); print(m.selected_center_tool('go')); "
                    "print(m.go('go', 'version', capture=True).strip())")
            command = step.cmd.replace("python eng/center.py check", f"python -c {shlex.quote(code)}")
            prefix = f". {shlex.quote(str(profile))}; "
            probe_result = subprocess.run(["bash", "-lc", prefix + probe], check=True, text=True, capture_output=True)
            center_result = subprocess.run(["bash", "-lc", prefix + command], check=True, text=True, capture_output=True)
            self.assertEqual(probe_result.stdout.strip(), "selected-native-go")
            self.assertEqual(center_result.stdout.splitlines(), [str(selected.resolve()), "selected-native-go"])


class BridgeAssetStateTest(unittest.TestCase):
    def test_existing_assets_and_pagination(self):
        page1 = [{"draft": False, "assets": [asset("linux")]}] + [
            {"draft": False, "assets": []} for _ in range(99)]
        page2 = [{"draft": False, "assets": [asset("windows")]}]
        pages = {1: page1, 2: page2}
        self.assertEqual(state.check_existing_assets(pages.__getitem__), {"linux": True, "windows": True})

    def test_absent_and_draft_assets_do_not_claim_delivery(self):
        pages = [{"draft": True, "assets": [asset("windows")]}, {"draft": False, "assets": []}]
        self.assertEqual(state.check_existing_assets(lambda _: pages), {"linux": False, "windows": False})

    def test_matching_name_with_wrong_or_missing_digest_refuses(self):
        for entry in (asset("linux", "a" * 64),
                      {"name": bundle.ASSETS["linux"], "state": "uploaded", "digest": None},
                      {"name": bundle.ASSETS["linux"], "state": "new", "digest": "sha256:" + bundle.ASSET_SHA256["linux"]}):
            with self.subTest(entry=entry), self.assertRaises(ValueError):
                state.check_existing_assets(lambda _: [{"draft": False, "assets": [entry]}])

    def test_unknown_release_shape_refuses(self):
        for value in ({"draft": False}, {"assets": []}, "not-a-release"):
            with self.subTest(value=value), self.assertRaises(ValueError):
                state.check_existing_assets(lambda _: [value])

    def test_missing_owner_read_token_refuses_without_network(self):
        saved = os.environ.pop("GH_TOKEN", None)
        try:
            with self.assertRaises(ValueError):
                state.read_github_page(1)
        finally:
            if saved is not None:
                os.environ["GH_TOKEN"] = saved

    def test_metadata_check_requires_the_active_profile_binding(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            records = root / "eng/provenance/records"
            profiles = root / "eng/provenance/artifact-profiles"
            records.mkdir(parents=True)
            profiles.mkdir(parents=True)
            profile = {"bridgeAssets": {
                "sourceCommit": bundle.REVISION, "sourceTree": bundle.TREE,
                "sourceArchiveSha256": bundle.SOURCE_SHA256, "contractsGo": "v1.0.0-ci.437.1",
                "carrierSha256": bundle.CARRIER_SHA256, "ociManifestDigest": bundle.IMAGE_DIGEST,
                "assets": {platform: {"name": bundle.ASSETS[platform], "sha256": bundle.ASSET_SHA256[platform],
                                      "executableSha256": bundle.EXE[platform][1]} for platform in bundle.ASSETS},
            }}
            profile_path = "eng/provenance/artifact-profiles/cloud-release-r111.json"
            inventory = root / "eng/provenance/files.json"
            inventory.write_text(json.dumps({"artifacts": ["runtime-r1", "worker-r1"]}), encoding="utf-8")

            def write_profile():
                raw = (json.dumps(profile) + "\n").encode()
                (root / profile_path).write_bytes(raw)
                target = {"profile": profile_path, "sha256": hashlib.sha256(raw).hexdigest()}
                for name in ("runtime-r1", "worker-r1"):
                    (records / (name + ".json")).write_text(json.dumps({"artifactTargets": [target]}), encoding="utf-8")

            write_profile()
            state.require_active_profile(root)
            profile["bridgeAssets"]["assets"]["windows"]["sha256"] = "a" * 64
            write_profile()
            with self.assertRaises(ValueError):
                state.require_active_profile(root)

    def test_random_bundle_fails_the_release_digest(self):
        with tempfile.TemporaryDirectory() as tmp:
            candidate = Path(tmp, "bridge.zip")
            candidate.write_bytes(b"not the sealed bridge")
            with self.assertRaises(ValueError):
                bundle.verify_bundle("linux", candidate)

    def test_existing_fixture_and_corrupted_copy(self):
        fixtures = [(platform, os.environ.get("ARCFORGES_TEST_CTR06_" + platform.upper() + "_BUNDLE"))
                    for platform in ("linux", "windows")]
        fixtures = [(platform, raw) for platform, raw in fixtures if raw]
        if not fixtures:
            self.skipTest("requires an offline native bridge bundle")
        for platform, raw in fixtures:
            with self.subTest(platform=platform), tempfile.TemporaryDirectory() as tmp:
                original = Path(raw)
                bundle.verify_bundle(platform, original)
                copy = Path(tmp, "corrupt.zip")
                data = bytearray(original.read_bytes())
                data[len(data)//2] ^= 1
                copy.write_bytes(data)
                with self.assertRaises(ValueError):
                    bundle.verify_bundle(platform, copy)


if __name__ == "__main__":
    unittest.main()
