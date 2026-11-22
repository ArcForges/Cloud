#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only

"""Prepare private inputs and operate the Linux self-host release selector."""

import argparse
from contextlib import ExitStack
from datetime import datetime, timedelta, timezone
from hashlib import file_digest, sha256
import http.client
import json
import os
from pathlib import Path
import re
import secrets
import shlex
import socket
import stat
import subprocess
import sys
import tempfile
import time
from urllib.parse import urlsplit


DATABASE_URL = "ARCFORGES_CENTER_DATABASE_URL"
MAX_SECRET_BYTES = 16 * 1024


def read_runtime_url(path, role):
    with os.fdopen(os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK), "rb") as source:
        mode = os.fstat(source.fileno()).st_mode
        if not stat.S_ISREG(mode) or mode & 0o077:
            raise ValueError("expected one private regular credential file")
        contents = source.read(MAX_SECRET_BYTES + 1)
    if len(contents) > MAX_SECRET_BYTES:
        raise ValueError("credential file exceeds the allowed size")

    # Read object members as pairs so a repeated credential key is refused.
    fields = json.loads(contents, object_pairs_hook=list)
    if not isinstance(fields, list) or len(fields) != 1 or not isinstance(fields[0], tuple):
        raise ValueError("credential file must hold one database URL")
    key, value = fields[0]
    if key != DATABASE_URL or not isinstance(value, str):
        raise ValueError("credential file must hold one database URL")
    if not value.isascii() or any(char <= " " or char == "\x7f" or char in '\"\\' for char in value):
        raise ValueError("runtime URL cannot be stored safely")

    url = urlsplit(value)
    if (
        url.scheme not in ("postgres", "postgresql")
        or url.hostname != "127.0.0.1"
        or url.port == 0
        or url.username not in (role + "_a", role + "_b")
        or not url.password
        or not re.fullmatch(r"/[a-z][a-z0-9_]{0,62}", url.path)
        or url.fragment
        or url.query != "sslmode=disable"
    ):
        raise ValueError("expected a rotated login for the local PostgreSQL database")
    return value


def write_private(path, value):
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "w", encoding="ascii", newline="\n") as output:
        output.write(value)


def bootstrap(directory, hours):
    directory.mkdir(mode=0o700)
    token = "afb1." + secrets.token_urlsafe(32)
    digest = sha256(token.encode("ascii")).hexdigest()
    expiry = datetime.now(timezone.utc) + timedelta(hours=hours)
    write_private(directory / "bootstrap-token", token + "\n")
    write_private(
        directory / "bootstrap.env",
        f"ARCFORGES_CENTER_BOOTSTRAP_SHA256={digest}\n"
        f"ARCFORGES_CENTER_BOOTSTRAP_EXPIRES_AT={expiry:%Y-%m-%dT%H:%M:%SZ}\n",
    )


class UpgradeRefused(ValueError):
    """A bounded operator diagnostic that contains no private inputs."""


def require(condition, message):
    if not condition:
        raise UpgradeRefused(message)


def owner_directory(path, private=False):
    path = path.absolute()
    info = path.lstat()
    require(
        path.resolve(strict=True) == path and stat.S_ISDIR(info.st_mode)
        and info.st_uid == os.geteuid() and not info.st_mode & (0o077 if private else 0o022),
        "Expected an operator-owned directory with protected permissions.",
    )
    return path


def private_input(path, limit=64 * 1024):
    with os.fdopen(os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK), "rb") as source:
        info = os.fstat(source.fileno())
        require(
            stat.S_ISREG(info.st_mode) and info.st_uid == os.geteuid() and not info.st_mode & 0o077,
            "Expected a private operator-owned file.",
        )
        contents = source.read(limit + 1)
    require(len(contents) <= limit, "Private input exceeds its size limit.")
    return contents


def read_environment(path, optional=False):
    try:
        lines = private_input(path).decode("ascii").splitlines()
    except FileNotFoundError:
        if optional:
            return {}
        raise
    environment = {}
    for line in lines:
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        name, separator, value = line.partition("=")
        require(
            separator and re.fullmatch(r"ARCFORGES_CENTER_[A-Z0-9_]+", name)
            and name not in environment,
            "Invalid Center environment file.",
        )
        parts = shlex.split(value, comments=False)
        require(
            len(parts) == 1 and all(32 <= ord(char) <= 126 for char in parts[0]),
            "Invalid Center environment value.",
        )
        environment[name] = parts[0]
    return environment


def durable_directory(path):
    descriptor = os.open(path, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def replace_file(path, content, mode=0o600):
    descriptor, temporary = tempfile.mkstemp(prefix=f".{path.name}-", dir=path.parent)
    try:
        with os.fdopen(descriptor, "wb") as output:
            os.fchmod(output.fileno(), mode)
            output.write(content)
            output.flush()
            os.fsync(output.fileno())
        os.replace(temporary, path)
        durable_directory(path.parent)
    finally:
        Path(temporary).unlink(missing_ok=True)


def digest_file(path):
    with os.fdopen(os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK), "rb") as source:
        require(stat.S_ISREG(os.fstat(source.fileno()).st_mode), "Expected a regular artifact file.")
        return file_digest(source, "sha256").hexdigest()


def is_digest(value):
    return isinstance(value, str) and re.fullmatch(r"[a-f0-9]{64}", value) is not None


def release_tree(path, synchronize=False):
    """Read the exact regular-file tree before admitting or reusing an immutable release."""
    contents = {}
    for child in sorted(owner_directory(path).iterdir()):
        info = child.lstat()
        require(info.st_uid == os.geteuid() and not info.st_mode & 0o022,
                "Release must remain under operator ownership.")
        if stat.S_ISDIR(info.st_mode):
            contents[f"{child.name}/"] = stat.S_IMODE(info.st_mode)
            for name, value in release_tree(child, synchronize).items():
                contents[f"{child.name}/{name}"] = value
        else:
            require(stat.S_ISREG(info.st_mode), "Release contains a linked or special file.")
            contents[child.name] = (stat.S_IMODE(info.st_mode), digest_file(child))
            if synchronize:
                descriptor = os.open(child, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
                try:
                    os.fsync(descriptor)
                finally:
                    os.close(descriptor)
    if synchronize:
        durable_directory(path)
    return contents


def checked(command, label, environment=None, *, timeout=1800, umask=-1):
    try:
        result = subprocess.run(
            list(map(str, command)),
            env=environment,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=timeout,
            umask=umask,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        raise UpgradeRefused(f"{label} did not return a confirmed result.") from None
    require(result.returncode == 0, f"{label} failed or its effect could not be confirmed.")
    require(len(result.stdout) <= 1024 * 1024, f"{label} exceeded its receipt limit.")
    return result.stdout


def json_receipt(output, label):
    try:
        document = json.loads(output)
    except (UnicodeError, ValueError):
        raise UpgradeRefused(f"{label} returned an invalid receipt.") from None
    require(isinstance(document, dict), f"{label} returned an invalid receipt.")
    return document


def command_environment(extra):
    # Keep the host toolchain selector, but only the explicitly read Center settings.
    return {**{key: value for key, value in os.environ.items() if not key.startswith("ARCFORGES_CENTER_")}, **extra}


def native_command(binary, environment, label, *arguments):
    return json_receipt(checked([binary, *arguments], label, command_environment(environment)), label)


def build_identity(document):
    build = document.get("build", {})
    artifact = document.get("artifact", {})
    require(
        build.get("dirty") is False and re.fullmatch(r"[a-f0-9]{40}", build.get("sourceCommit", ""))
        and isinstance(build.get("buildId"), str) and build["buildId"]
        and artifact.get("id") == "Cloud" and isinstance(artifact.get("version"), str),
        "Expected an identified clean Cloud build.",
    )
    return {"source": build["sourceCommit"], "build": build["buildId"], "version": artifact["version"]}


class Upgrade:
    def __init__(self, options, state):
        self.options = options
        self.state = state
        self.install = owner_directory(options.install_root)
        self.configuration = owner_directory(options.config_dir, private=True)
        self.releases = owner_directory(self.install / "releases")
        self.current = self.install / "current"
        self.fence = state / "maintenance"
        self.journal_path = state / "upgrade.json"
        self.systemctl = ["systemctl", *(["--user"] if options.user_manager else [])]
        self.unit = options.unit
        require(re.fullmatch(r"arcforges-center(?:-[a-z0-9-]+)?\.service", self.unit), "Invalid Center service unit.")
        self.migration = read_environment(self.configuration / "migration.env")
        self.center = read_environment(self.configuration / "center.env")
        self.signing = read_environment(self.configuration / "signing.env", optional=True)
        self.live_runtime = read_environment(self.configuration / "runtime.env")
        self.database = self.migration.get("ARCFORGES_CENTER_DATABASE_NAME")
        self.role = self.migration.get("ARCFORGES_CENTER_RUNTIME_ROLE")
        require(
            self.migration.get("ARCFORGES_CENTER_MODE") == self.center.get("ARCFORGES_CENTER_MODE") == "self-hosted"
            and isinstance(self.database, str) and isinstance(self.role, str),
            "Expected the configured self-host PostgreSQL source and runtime role.",
        )
        self.journal = None

    def systemd(self, *arguments):
        return checked([*self.systemctl, *arguments], "Center systemd operation", timeout=120).decode("utf-8").strip()

    def verify_unit(self):
        require(
            self.systemd("show", "--property=NeedDaemonReload", "--value", self.unit) == "no",
            "Reload the reviewed Center unit before updating.",
        )
        require(
            self.systemd("show", "--property=KillMode", "--value", self.unit) == "control-group",
            "The Center unit must stop its owned process group.",
        )
        effective = {}
        section = ""
        for line in self.systemd("cat", self.unit).splitlines():
            line = line.strip()
            if line.startswith("[") and line.endswith("]"):
                section = line
            key, separator, value = line.partition("=")
            if separator and (section, key) in {
                ("[Unit]", "ConditionPathExists"), ("[Service]", "ExecStart"),
                ("[Service]", "EnvironmentFile"),
            }:
                entries = effective.setdefault(key, [])
                if value:
                    entries.append(value)
                else:
                    entries.clear()
        require(
            f"!{self.fence}" in effective.get("ConditionPathExists", [])
            and effective.get("ExecStart") == [f"{self.current}/bin/arcforges-center serve"]
            and all(
                str(self.configuration / name) in effective.get("EnvironmentFile", [])
                for name in ("center.env", "runtime.env")
            ),
            "The loaded Center unit does not use this selector, maintenance fence and configuration.",
        )
        self.service_user = self.systemd("show", "--property=User", "--value", self.unit)
        require(
            self.options.user_manager or self.service_user not in ("", "root", "0"),
            "Expected the dedicated unprivileged Go Center service user.",
        )

    def runtime_identity(self, environment):
        url = urlsplit(environment.get(DATABASE_URL, ""))
        source = urlsplit(self.migration.get("ARCFORGES_CENTER_MIGRATION_DATABASE_URL", ""))
        require(
            url.scheme in ("postgresql", "postgres") and url.hostname == source.hostname == "127.0.0.1"
            and (url.port or 5432) == (source.port or 5432)
            and url.path == f"/{self.database}" and url.username in (f"{self.role}_a", f"{self.role}_b")
            and url.password and not url.fragment and url.query == "sslmode=disable",
            "Runtime credentials do not select the admitted local PostgreSQL database and role.",
        )
        return url.username[-1]

    def selected(self):
        target = os.readlink(self.current)
        require(re.fullmatch(r"releases/[a-f0-9]{64}", target), "Center selector is not a verified release directory.")
        return target.split("/")[-1]

    def binary(self, digest):
        require(is_digest(digest), "Invalid release identity.")
        release = owner_directory(self.releases / digest)
        binary = owner_directory(release / "bin") / "arcforges-center"
        info = binary.lstat()
        require(
            stat.S_ISREG(info.st_mode) and info.st_uid == os.geteuid()
            and info.st_mode & stat.S_IXUSR and not info.st_mode & 0o022,
            "The exact Center executable must remain operator-owned and protected from other writers.",
        )
        return binary

    def select(self, digest):
        self.binary(digest)
        temporary = self.install / f".current-{self.journal['operation']}-{secrets.token_hex(4)}"
        temporary.symlink_to(f"releases/{digest}")
        try:
            os.replace(temporary, self.current)
            durable_directory(self.install)
        finally:
            temporary.unlink(missing_ok=True)

    def phase(self, phase, **facts):
        self.journal.update(facts, phase=phase)
        replace_file(self.journal_path, (json.dumps(self.journal, indent=2) + "\n").encode("utf-8"))

    def guard(self):
        self.fence_service()
        self.stop_service()

    def fence_service(self):
        replace_file(self.fence, (self.journal["operation"] + "\n").encode("ascii"))

    def stop_service(self):
        group = self.systemd("show", "--property=ControlGroup", "--value", self.unit)
        group = group or self.journal.get("serviceControlGroup")
        require(group and cgroup_path(group, self.unit), "The exact Center control group is unknown.")
        self.phase(self.journal["phase"], serviceControlGroup=group)
        self.systemd("stop", self.unit)
        require(
            self.systemd("show", "--property=ActiveState", "--value", self.unit) == "inactive"
            and self.systemd("show", "--property=MainPID", "--value", self.unit) == "0",
            "The previous Center did not stop.",
        )
        require(self.systemd("show", "--property=ControlGroup", "--value", self.unit) in ("", group),
                "The Center control group changed during shutdown.")
        self.phase(self.journal["phase"], serviceControlGroupState=drained_group(group, self.unit))

    def inspect_database(self, binary):
        result = native_command(binary, self.migration, "PostgreSQL schema inspection", "migrate", "status")
        version = result.get("version")
        applied = result.get("applied")
        require(
            type(version) is int and isinstance(applied, list) and len(applied) == version
            and all(isinstance(row, dict) and row.get("version") == index and is_digest(row.get("sha256"))
                    for index, row in enumerate(applied, 1))
            and result.get("serverMajorMatchesTested") is True
            and result.get("database") == self.database and result.get("runtimeRole") == self.role
            and result.get("state") in ("pending", "current") and not result.get("problems"),
            "The source database, schema or runtime role is unavailable or incompatible.",
        )
        return {
            "version": version, "buildVersion": result.get("buildVersion"), "state": result["state"],
            "history": [row["sha256"] for row in applied],
        }

    def verify_stage(self):
        options = self.options
        command = ["node", options.cohort_tool]
        trust = ["--archive", options.archive, "--public-key", options.public_key]
        if options.allow_candidate:
            trust.append("--allow-candidate")
        if options.admission:
            require(options.cloud_repo and options.web_repo, "Main admission requires both producer Git histories.")
            trust += ["--admission", options.admission, "--cloud-repo", options.cloud_repo,
                      "--web-repo", options.web_repo]
        envelope = json_receipt(checked([*command, "verify", *trust], "Signed candidate verification"), "Signed candidate verification")
        digest = envelope.get("archive", {}).get("sha256")
        require(is_digest(digest), "Signed candidate receipt lacks its archive identity.")
        destination = self.releases / digest
        with tempfile.TemporaryDirectory(prefix=".update-candidate-", dir=self.releases) as directory:
            stage = json_receipt(
                checked([*command, "stage", *trust, "--staging", directory], "Signed candidate staging", umask=0o022),
                "Signed candidate staging",
            )
            candidate = Path(directory) / digest
            require(stage.get("release") == str(candidate), "Signed candidate staging identity differs.")
            authenticated = release_tree(candidate, synchronize=True)
            if destination.exists() or destination.is_symlink():
                require(release_tree(destination, synchronize=True) == authenticated,
                        "An existing release differs from the signed staged bytes.")
            else:
                candidate.rename(destination)
                durable_directory(self.releases)
        binary = self.binary(digest)
        cohort = json_receipt((self.releases / digest / "cohort.json").read_bytes(), "Candidate metadata")
        health = native_command(binary, {}, "Candidate build identity", "version")
        identity = build_identity(health)
        require(
            cohort.get("postgres") == {"major": 18, "schema": 17}
            and envelope.get("producers", [{}])[0].get("commit") == identity["source"]
            and cohort.get("cloud", {}).get("version") == identity["version"]
            and health.get("runtime") == "go",
            "The native binary does not match the signed Center producer or supported PostgreSQL schema.",
        )
        return digest, digest_file(binary), identity

    def backup(self, binary, job, previous):
        archive, metadata = job / "archive.dump", job / "archive.metadata.json"
        receipt = native_command(
            binary, self.migration, "Source PostgreSQL backup", "admin", "backup-logical",
            "--archive", archive, "--metadata", metadata,
        )
        archive_hash, metadata_hash = digest_file(archive), digest_file(metadata)
        require(
            receipt.get("schemaVersion") == previous["version"]
            and receipt.get("archiveSha256") == archive_hash and receipt.get("metadataSha256") == metadata_hash,
            "Source backup receipt does not match the exact pre-update schema and bytes.",
        )
        self.phase("verifying-backup", backup={
            "archiveSha256": archive_hash, "metadataSha256": metadata_hash,
            "capturedAt": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        })
        database = f"af_update_{self.journal['operation']}"
        role = f"af_runtime_{self.journal['operation']}"
        witness = {
            **self.migration, "ARCFORGES_CENTER_DATABASE_NAME": database,
            "ARCFORGES_CENTER_RUNTIME_ROLE": role,
        }
        restored = native_command(
            binary, witness, "PostgreSQL backup restore witness", "admin", "restore-logical-backup",
            "--archive", archive, "--sha256", archive_hash, "--metadata", metadata,
            "--metadata-sha256", metadata_hash,
        )
        require(
            restored.get("database") == database and restored.get("runtimeRole") == role
            and restored.get("schemaVersion") == previous["version"]
            and restored.get("sourceBackupSha256") == archive_hash
            and is_digest(restored.get("restoreReceipt")) and is_digest(restored.get("targetFloorSha256")),
            "The restored backup witness does not match the exact source backup.",
        )
        self.phase("backup-verified", restoreWitness=restored)

    def contract(self, binary, job, previous):
        self.phase("preparing-contraction")
        prepared = native_command(binary, self.migration, "Prepare the exact schema 16 predecessor", "migrate", "prepare-contraction")
        require(
            prepared.get("version") == prepared.get("buildVersion") == 16
            and prepared.get("state") == "current" and prepared.get("runtimeRole") == self.role
            and prepared.get("grants") == "reconciled",
            "The exact schema 16 predecessor could not be confirmed.",
        )
        confirmed = self.inspect_database(binary)
        require(
            confirmed["version"] == 16 and confirmed["state"] == "pending"
            and confirmed["history"][:previous["version"]] == previous["history"],
            "The prepared schema does not preserve the admitted predecessor history.",
        )
        self.phase("contracting", prepared=confirmed)
        contracted = native_command(
            binary, self.migration, "Witnessed irreversible PostgreSQL contraction", "migrate", "contract",
            "--archive", job / "contract.dump", "--metadata", job / "contract.metadata.json",
            "--witness-database", f"af_contract_{self.journal['operation']}",
            "--witness-role", f"af_contract_rt_{self.journal['operation']}",
        )
        successor = contracted.get("runtimeRole")
        require(
            isinstance(successor, str) and re.fullmatch(r"[a-z][a-z0-9_]{2,40}", successor)
            and successor != self.role,
            "Contraction did not identify its distinct runtime role.",
        )
        self.role = successor
        self.migration["ARCFORGES_CENTER_RUNTIME_ROLE"] = successor
        final = self.inspect_database(binary)
        require(
            contracted.get("version") == final["version"] == final["buildVersion"] == 17
            and final["state"] == "current" and final["history"][:16] == confirmed["history"],
            "Contraction or its post-commit runtime admission could not be confirmed.",
        )
        self.phase("rotating-runtime", contracted=final, candidateRuntimeRole=successor)
        credential = job / "candidate-runtime.json"
        rotation = native_command(
            binary, {**self.migration, "ARCFORGES_CENTER_RUNTIME_SECRET_FILE": str(credential)},
            "Rotate the new runtime generation", "admin", "rotate-runtime-credential",
        )
        url = read_runtime_url(credential, self.role)
        runtime = {DATABASE_URL: url}
        slot = self.runtime_identity(runtime)
        require(
            rotation.get("database") == self.database and rotation.get("runtimeRole") == self.role
            and rotation.get("slot") == slot and rotation.get("loginRole") == f"{self.role}_{slot}",
            "The new runtime credential is not bound to the contracted database.",
        )
        new_environment = f'{DATABASE_URL}="{url}"\n'.encode("ascii")
        migration_environment = "".join(
            f"{key}={shlex.quote(value)}\n" for key, value in self.migration.items()
        ).encode("ascii")
        replace_file(job / "candidate-runtime.env", new_environment)
        replace_file(job / "candidate-migration.env", migration_environment)
        self.phase("runtime-ready", runtimeSlot=slot,
                   runtimeRotatedAt=rotation.get("rotatedAt"),
                   runtimeEnvironmentSha256=sha256(new_environment).hexdigest(),
                   migrationEnvironmentSha256=sha256(migration_environment).hexdigest())
        return runtime, slot

    def probe(self, binary, runtime, identity, job, phase="probing"):
        environment = {**self.center, **self.signing, **runtime}
        require(self.runtime_identity(runtime), "Invalid runtime probe identity.")
        with ExitStack() as sockets:
            listeners = [sockets.enter_context(socket.socket(socket.AF_INET, socket.SOCK_STREAM)) for _ in range(3)]
            for listener in listeners:
                listener.bind(("127.0.0.1", 0))
            http, grpc, admin = (s.getsockname()[1] for s in listeners)
        environment.update({
            "ARCFORGES_CENTER_HTTP_ADDRESS": f"127.0.0.1:{http}",
            "ARCFORGES_CENTER_GRPC_ADDRESS": f"127.0.0.1:{grpc}",
            "ARCFORGES_CENTER_ADMIN_ADDRESS": f"127.0.0.1:{admin}",
        })
        probe_env = job / "probe.env"
        replace_file(probe_env, "".join(f"{k}={json.dumps(v)}\n" for k, v in environment.items()).encode("ascii"))
        unit = f"arcforges-center-probe-{self.journal['operation']}-{secrets.token_hex(4)}.service"
        self.phase(phase, probeUnit=unit, probeControlGroup=None, probeControlGroupState=None)
        try:
            run = ["systemd-run", *(["--user"] if self.options.user_manager else []),
                   "--quiet", "--service-type=exec", "--unit", unit,
                   "--property=RuntimeMaxSec=60", f"--property=EnvironmentFile={probe_env}"]
            if self.service_user:
                run.append(f"--property=User={self.service_user}")
            checked([*run, binary, "serve"], "Start isolated native candidate", timeout=30)
            group = self.systemd("show", "--property=ControlGroup", "--value", unit)
            require(group and cgroup_path(group, unit), "The exact readiness probe control group is unknown.")
            self.phase(phase, probeControlGroup=group)
            self.await_ready(unit, binary, identity, f"127.0.0.1:{http}", f"127.0.0.1:{admin}")
        finally:
            self.stop_probe(unit)
            probe_env.unlink(missing_ok=True)

    def stop_probe(self, unit):
        if self.systemd("show", "--property=LoadState", "--value", unit) == "loaded":
            group = self.systemd("show", "--property=ControlGroup", "--value", unit)
            group = group or self.journal.get("probeControlGroup")
            self.systemd("stop", unit)
        else:
            group = self.journal.get("probeControlGroup")
        if group:
            self.phase(self.journal["phase"], probeControlGroupState=drained_group(group, unit))

    def await_ready(self, unit, binary, identity, http, admin):
        # Connect directly to the loopback listener and never follow an HTTP redirect.
        require(all(re.fullmatch(r"127\.0\.0\.1:[1-9][0-9]{0,4}", address) for address in (http, admin)),
                "Readiness must identify the private IPv4 listeners.")
        deadline = time.monotonic() + 25
        while time.monotonic() < deadline:
            try:
                before = self.listener_identity(unit, binary, (http, admin))
                if before:
                    health = http_receipt(http, "/healthz")
                    ready = http_receipt(admin, "/readyz")
                    require(build_identity(health) == identity and health.get("runtime") == "go"
                            and health.get("center", {}).get("mode") == "self-hosted",
                            "The native health identity does not match the selected release.")
                    if (ready.get("status") == "ready" and ready.get("components", {}).get("database") == "ready"
                            and ready.get("components", {}).get("databaseSchema") == "ready"):
                        require(self.listener_identity(unit, binary, (http, admin)) == before,
                                "The Center process or listening socket changed during readiness verification.")
                        return
            except (OSError, http.client.HTTPException):
                pass
            time.sleep(0.25)
        raise UpgradeRefused("The native private Center database did not become ready.")

    def listener_identity(self, unit, binary, addresses):
        pid = self.systemd("show", "--property=MainPID", "--value", unit)
        if not pid.isdecimal() or int(pid) == 0:
            return None
        process = Path("/proc") / pid
        require(os.path.samefile(process / "exe", binary), "Readiness belongs to another executable.")
        require(os.path.samefile(process / "ns" / "net", "/proc/self/ns/net"),
                "The Center does not share the readiness listener namespace.")
        sockets = listening_sockets(pid, addresses)
        return (pid, sockets) if sockets is not None else None

    def apply(self):
        self.verify_unit()
        self.runtime_identity(self.live_runtime)
        require(not (self.fence.exists() or self.fence.is_symlink()),
                "An unfinished Center maintenance operation is fenced.")
        if self.journal_path.exists():
            previous = json_receipt(private_input(self.journal_path), "Previous upgrade journal")
            require(previous.get("phase") in ("completed", "rolled-back"), "Inspect the unfinished Center upgrade.")
            require(re.fullmatch(r"[a-f0-9]{16}", previous.get("operation", "")), "Invalid prior operation identity.")
            replace_file(self.state / previous["operation"] / "final.json", private_input(self.journal_path))
        previous = self.selected()
        previous_binary = self.binary(previous)
        previous_hash = digest_file(previous_binary)
        require(previous_hash == self.options.previous_sha256, "The previous binary differs from its admitted digest.")
        previous_identity = build_identity(native_command(previous_binary, {}, "Previous build identity", "version"))
        target, target_hash, target_identity = self.verify_stage()
        binary = self.binary(target)
        require(previous != target, "The candidate is already selected.")
        operation = secrets.token_hex(8)
        job = self.state / operation
        job.mkdir(mode=0o700)
        durable_directory(self.state)
        self.journal = {
            "schema": 1, "operation": operation, "previous": previous, "candidate": target,
            "previousBinarySha256": previous_hash, "candidateBinarySha256": target_hash,
            "previousIdentity": previous_identity, "candidateIdentity": target_identity,
            "database": self.database, "runtimeRole": self.role,
            "previousRuntimeSha256": digest_file(self.configuration / "runtime.env"),
            "previousMigrationSha256": digest_file(self.configuration / "migration.env"),
            "installRoot": str(self.install), "configDir": str(self.configuration),
            "unit": self.unit, "userManager": self.options.user_manager,
        }
        before = self.inspect_database(binary)
        require(
            13 <= before["version"] <= 17 and before["buildVersion"] == 17,
            "Only admitted Center schemas 13 through 17 can enter this update.",
        )
        previous_status = self.inspect_database(previous_binary)
        require(
            previous_status["state"] == "current" and previous_status["version"] == before["version"]
            and previous_status["history"] == before["history"],
            "The selected previous binary is not compatible with the exact source schema.",
        )
        group = self.systemd("show", "--property=ControlGroup", "--value", self.unit)
        require(group and cgroup_path(group, self.unit), "The serving Center has no confirmed control group.")
        self.phase("fencing", predecessor=before, contractionRequired=before["version"] < 17,
                   serviceControlGroup=group)
        self.guard()
        require(self.inspect_database(binary) == before, "The database changed while fencing the old Center.")
        self.phase("capturing-backup")
        self.backup(binary, job, before)
        runtime, slot = (self.live_runtime, None)
        if before["version"] < 17:
            runtime, slot = self.contract(binary, job, before)
        self.probe(binary, runtime, target_identity, job)
        if slot is not None:
            self.phase("confirming-runtime")
            native_command(binary, self.migration, "Confirm the verified runtime generation",
                           "admin", "confirm-runtime-credential", "--slot", slot)
        self.phase("selecting", readinessVerified=True, selectionIntent="candidate")
        if slot is not None:
            replace_file(self.configuration / "runtime.env", private_input(job / "candidate-runtime.env"))
            replace_file(self.configuration / "migration.env", private_input(job / "candidate-migration.env"))
        self.activate_candidate(binary, target, target_identity)

    def activate_candidate(self, binary, digest, identity):
        try:
            self.activate(binary, digest, identity)
        except (OSError, ValueError):
            self.fence_service()
            self.phase("activation-fencing", observedSelection=self.selected())
            self.stop_service()
            if not self.journal["contractionRequired"]:
                self.select(self.journal["previous"])
            self.phase("activation-failed", observedSelection=self.selected())
            raise

    def activate(self, binary, digest, identity):
        self.select(digest)
        self.phase("selected", observedSelection=self.selected())
        self.start_selected(binary, identity)
        self.phase("completed")

    def start_selected(self, binary, identity):
        self.fence.unlink()
        durable_directory(self.state)
        self.systemd("start", self.unit)
        self.await_ready(
            self.unit, binary, identity,
            self.center.get("ARCFORGES_CENTER_HTTP_ADDRESS", "127.0.0.1:8080"),
            self.center.get("ARCFORGES_CENTER_ADMIN_ADDRESS", "127.0.0.1:8082"),
        )

    def recover(self):
        self.verify_unit()
        self.journal = json_receipt(private_input(self.journal_path), "Upgrade journal")
        require(
            self.journal.get("schema") == 1 and re.fullmatch(r"[a-f0-9]{16}", self.journal.get("operation", ""))
            and self.journal.get("installRoot") == str(self.install)
            and self.journal.get("configDir") == str(self.configuration)
            and self.journal.get("unit") == self.unit
            and self.journal.get("userManager") == self.options.user_manager
            and self.journal.get("database") == self.database
            and self.role in (self.journal.get("runtimeRole"), self.journal.get("candidateRuntimeRole"))
            and self.journal.get("phase") not in ("completed", "rolled-back"),
            "No matching unfinished Center upgrade was found.",
        )
        if self.fence.exists() or self.fence.is_symlink():
            require(private_input(self.fence) == (self.journal["operation"] + "\n").encode("ascii"),
                    "Maintenance fence belongs to another operation.")
        probe_unit = self.journal.get("probeUnit")
        if probe_unit:
            require(re.fullmatch(rf"arcforges-center-probe-{self.journal['operation']}-[a-f0-9]{{8}}\.service",
                                 probe_unit), "Invalid recorded readiness probe identity.")
            self.stop_probe(probe_unit)
        if self.options.operation == "resume":
            self.resume_selection()
        else:
            self.recover_compatible()

    def resume_selection(self):
        require(
            self.journal.get("readinessVerified") is True
            and self.journal.get("selectionIntent") == "candidate"
            and self.journal["phase"] in (
                "selecting", "selected", "rechecking-selection", "activation-fencing", "activation-failed",
            ),
            "The previous operation may have changed PostgreSQL. Inspect and recover before resuming.",
        )
        target = self.journal["candidate"]
        binary = self.binary(target)
        identity = self.journal["candidateIdentity"]
        require(digest_file(binary) == self.journal["candidateBinarySha256"], "Candidate binary changed.")
        require(self.selected() in (self.journal["previous"], target), "Unexpected active Center selector.")
        job = self.state / self.journal["operation"]
        current_env = self.configuration / "runtime.env"
        current_migration = self.configuration / "migration.env"
        if self.journal["contractionRequired"]:
            saved = private_input(job / "candidate-runtime.env")
            saved_migration = private_input(job / "candidate-migration.env")
            require(sha256(saved).hexdigest() == self.journal["runtimeEnvironmentSha256"],
                    "The candidate runtime input differs from its confirmed digest.")
            require(sha256(saved_migration).hexdigest() == self.journal["migrationEnvironmentSha256"],
                    "The candidate migration input differs from its confirmed digest.")
            require(
                digest_file(current_env) in (self.journal["previousRuntimeSha256"], self.journal["runtimeEnvironmentSha256"])
                and digest_file(current_migration) in (self.journal["previousMigrationSha256"], self.journal["migrationEnvironmentSha256"]),
                "An installed database input differs from both recorded generations.",
            )
            self.migration = read_environment(job / "candidate-migration.env")
            self.role = self.journal["candidateRuntimeRole"]
            runtime = read_environment(job / "candidate-runtime.env")
        else:
            require(digest_file(current_env) == self.journal["previousRuntimeSha256"]
                    and digest_file(current_migration) == self.journal["previousMigrationSha256"],
                    "The current database inputs have changed.")
            saved, saved_migration, runtime = None, None, self.live_runtime
        expected = self.journal.get("contracted", self.journal["predecessor"])
        require(self.inspect_database(binary) == expected, "The candidate no longer accepts the admitted database history.")
        self.guard()
        self.probe(binary, runtime, identity, job, phase="rechecking-selection")
        self.phase("selecting", readinessVerified=True, selectionIntent="candidate")
        if saved is not None and saved_migration is not None:
            replace_file(current_env, saved)
            replace_file(current_migration, saved_migration)
        self.activate_candidate(binary, target, identity)

    def recover_compatible(self):
        phase = self.journal["phase"]
        rolling_back = (
            self.journal.get("selectionIntent") == "previous"
            and self.journal.get("rollbackChecked") is True
        )
        require(
            self.previous_recovery_fence(rolling_back)
            and (not self.journal.get("contractionRequired")
                 or phase in ("fencing", "capturing-backup", "verifying-backup", "backup-verified")
                 or rolling_back)
            and digest_file(self.configuration / "runtime.env") == self.journal.get("previousRuntimeSha256"),
            "Previous compatibility is unconfirmed. Use the separately admitted restore or forward recovery.",
        )
        require(
            self.role == self.journal.get("runtimeRole")
            and digest_file(self.configuration / "migration.env") == self.journal.get("previousMigrationSha256"),
            "The original migration identity is unavailable.",
        )
        previous = self.journal.get("previous")
        binary = self.binary(previous)
        require(digest_file(binary) == self.journal.get("previousBinarySha256"), "Previous binary changed.")
        status = self.inspect_database(binary)
        anchor = self.journal["predecessor"]
        require(status["state"] == "current" and status["history"] == anchor["history"],
                "The previous binary cannot use the current database.")
        self.guard()
        identity = self.journal["previousIdentity"]
        self.phase("checking-previous", rollbackChecked=True, selectionIntent="previous")
        self.probe(binary, self.live_runtime, identity, self.state / self.journal["operation"],
                   phase="checking-previous")
        self.phase("rollback-selecting")
        try:
            self.select(previous)
            self.phase("rollback-selected", observedSelection=self.selected())
            self.start_selected(binary, identity)
        except (OSError, ValueError):
            self.fence_service()
            self.phase("rollback-fencing", observedSelection=self.selected())
            self.stop_service()
            self.phase("rollback-failed")
            raise
        self.phase("rolled-back")

    def previous_recovery_fence(self, rolling_back):
        if self.fence.is_file():
            return True
        if self.fence.exists() or self.fence.is_symlink():
            return False
        # A crash can leave the initial durable intent before the first fence is created.
        # Only the exact untouched previous selector can enter the compatibility checks.
        return ((self.journal["phase"] == "fencing" or rolling_back)
                and self.selected() == self.journal["previous"])


def cgroup_path(group, unit):
    require(isinstance(group, str) and group.startswith("/") and group.split("/")[-1] == unit
            and all(part not in ("", ".", "..") for part in group[1:].split("/")),
            "Invalid Center control group identity.")
    root = Path("/sys/fs/cgroup")
    require((root / "cgroup.controllers").is_file(), "Center updates require native cgroup v2.")
    path = root / group[1:]
    require(path.resolve() == path, "Center control group resolves outside its exact path.")
    return path


def drained_group(group, unit):
    path = cgroup_path(group, unit)
    try:
        events = (path / "cgroup.events").read_text(encoding="ascii").splitlines()
    except FileNotFoundError:
        require(not path.exists(), "Center control group state is unavailable.")
        return "removed"
    require("populated 0" in events, "Center control group still holds processes.")
    return "empty"


def listening_sockets(pid, addresses):
    # Link exact TCP LISTEN inodes in the unit's namespace to its MainPID descriptors.
    process = Path("/proc") / str(pid)
    endpoints = [f"0100007F:{int(address.split(':')[1]):04X}" for address in addresses]
    listeners = {endpoint: [] for endpoint in endpoints}
    for line in (process / "net" / "tcp").read_text(encoding="ascii").splitlines()[1:]:
        fields = line.split()
        if len(fields) >= 10 and fields[3] == "0A" and fields[1] in listeners:
            listeners[fields[1]].append(fields[9])
    if any(len(inodes) != 1 or inodes[0] == "0" for inodes in listeners.values()):
        return None
    owned = set()
    for descriptor in (process / "fd").iterdir():
        try:
            target = os.readlink(descriptor)
        except FileNotFoundError:
            continue
        match = re.fullmatch(r"socket:\[(\d+)\]", target)
        if match:
            owned.add(match[1])
    identities = tuple(listeners[endpoint][0] for endpoint in endpoints)
    return identities if set(identities) <= owned else None


def http_receipt(address, path):
    host, port = address.split(":")
    connection = http.client.HTTPConnection(host, int(port), timeout=2)
    try:
        connection.request("GET", path)
        response = connection.getresponse()
        if response.status != 200:
            raise OSError("The private endpoint is not ready.")
        return json_receipt(response.read(64 * 1024 + 1), "Center readiness")
    finally:
        connection.close()


def run_upgrade(options):
    require(sys.platform.startswith("linux"), "Center upgrades require Linux.")
    import fcntl

    state = owner_directory(options.state_root, private=True)
    descriptor = os.open(state / "upgrade.lock", os.O_WRONLY | os.O_CREAT | os.O_NOFOLLOW, 0o600)
    with os.fdopen(descriptor, "wb") as lock:
        fcntl.flock(lock.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        if options.operation == "inspect":
            journal = json_receipt(private_input(state / "upgrade.json"), "Upgrade journal")
            print(json.dumps({**journal, "maintenance": (state / "maintenance").exists()}, indent=2))
            return
        update = Upgrade(options, state)
        if options.operation == "apply":
            update.apply()
        else:
            update.recover()
        print(json.dumps(update.journal, indent=2))


def upgrade_arguments(operations):
    upgrade = operations.add_parser("upgrade")
    commands = upgrade.add_subparsers(dest="operation", required=True)
    for operation in ("apply", "inspect", "resume", "rollback-compatible"):
        command = commands.add_parser(operation)
        command.add_argument("--state-root", type=Path, default=Path("/var/lib/arcforges-center/operator"))
        if operation == "inspect":
            continue
        command.add_argument("--install-root", type=Path, default=Path("/opt/arcforges-center"))
        command.add_argument("--config-dir", type=Path, default=Path("/etc/arcforges-center"))
        command.add_argument("--unit", default="arcforges-center.service")
        command.add_argument("--user-manager", action="store_true")
        if operation == "apply":
            for name in ("cohort-tool", "archive", "public-key"):
                command.add_argument(f"--{name}", type=Path, required=True)
            command.add_argument("--previous-sha256", required=True)
            command.add_argument("--admission", type=Path)
            command.add_argument("--cloud-repo", type=Path)
            command.add_argument("--web-repo", type=Path)
            command.add_argument("--allow-candidate", action="store_true")



def main():
    parser = argparse.ArgumentParser(description=__doc__)
    operations = parser.add_subparsers(dest="action", required=True)
    runtime = operations.add_parser("runtime-env")
    runtime.add_argument("credential", type=Path)
    runtime.add_argument("output", type=Path)
    runtime.add_argument("--role", default="arcforges_center_runtime")
    owner = operations.add_parser("bootstrap")
    owner.add_argument("directory", type=Path)
    owner.add_argument("--hours", type=int, default=2)
    upgrade_arguments(operations)
    args = parser.parse_args()

    try:
        if args.action == "upgrade":
            run_upgrade(args)
        elif args.action == "runtime-env":
            if not re.fullmatch(r"[a-z][a-z0-9_]{2,40}", args.role):
                parser.error("runtime group role must be a lowercase database role")
            url = read_runtime_url(args.credential, args.role)
            write_private(args.output, f'{DATABASE_URL}="{url}"\n')
        else:
            if not 1 <= args.hours <= 168:
                parser.error("bootstrap duration must be between 1 and 168 hours")
            bootstrap(args.directory, args.hours)
    except UpgradeRefused as error:
        print(error, file=sys.stderr)
        return 1
    except (OSError, ValueError, RecursionError):
        print("Unable to prepare private input. Check the source format, permissions, and unused output path.", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
