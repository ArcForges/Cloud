#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
"""The Go center's engineering controls: one entry point for both verification legs and hosted CI (docs/engineering-controls.md).

  python eng/center.py check      every control of this host's leg (Linux adds the race detector, fuzzing, the PostgreSQL
                                  integration tests, the restore drill and the image target)
  python eng/center.py generate   rewrite worker/tables/center-tables.generated.ts from the center's registrations

The check uses the pinned Go release only (GOTOOLCHAIN=local) with read-only modules (GOFLAGS=-mod=readonly) and no telemetry.
It needs no credential; it reads the Go module proxy and checksum database (module downloads) and the Go vulnerability database
(govulncheck). On Linux it starts disposable PostgreSQL servers in Docker (the image pinned by digest below) on ephemeral
loopback ports with random superuser passwords that never leave this process, and removes them. It fails on the first failed
control and never modifies a tracked file.
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import secrets
import shutil
import subprocess
import sys
import tempfile
import time
import urllib.parse
import urllib.request

ROOT = Path(__file__).resolve().parents[1]
CENTER = ROOT / "center"
TOOLS = CENTER / "tools"
ARTIFACTS = ROOT / "artifacts" / "center"
WINDOWS = os.name == "nt"
EXE = ".exe" if WINDOWS else ""
ENV = {**os.environ, "GOTOOLCHAIN": "local", "GOFLAGS": "-mod=readonly", "GOTELEMETRY": "off"}
# The admitted inputs of center/dependencies.json, relative to center/.
INPUTS = ("go.mod", "go.sum", "toolchain.json", "tools/go.mod", "tools/go.sum")
# The native fuzz targets and their packages; each runs for FUZZ_TIME on Linux (their seed corpora run in every go test).
FUZZ_TARGETS = (
    ("./internal/correlation", "FuzzParseTraceparent"),
    ("./internal/ingress", "FuzzReadEnvelope"),
    ("./internal/config", "FuzzPublicBaseURL"),
    ("./internal/identity", "FuzzNormalizeEmail"),
    ("./internal/page", "FuzzParseCursor"),
    ("./internal/server", "FuzzClientAddressHeader"),
    ("./internal/identity/passkey", "FuzzCeremonyPayloads"),
)
FUZZ_TIME = "10s"
TEST_TIMEOUT = "10m"
# PostgreSQL 18.4 (the official Alpine image), pinned by digest: the integration server of the Linux leg and the two servers of
# the restore drill.
POSTGRES_IMAGE = "postgres:18-alpine@sha256:1b1689b20d16a014a3d195653381cf2caa75a41a92d93b255a9d6ea29fd353aa"


def say(message: str) -> None:
    print(f"[center] {message}", flush=True)


def go(*args: str, cwd: Path = CENTER, capture: bool = False, env: dict[str, str] | None = None) -> str:
    result = subprocess.run(args, cwd=cwd, env=env or ENV, text=True, encoding="utf-8",
                            stdout=subprocess.PIPE if capture else None)
    if result.returncode != 0:
        raise SystemExit(f"[center] failed ({result.returncode}): {' '.join(args)}")
    return result.stdout if capture else ""


def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes().replace(b"\r\n", b"\n")).hexdigest()


def check_toolchain() -> str:
    toolchain = json.loads((CENTER / "toolchain.json").read_text(encoding="utf-8"))
    pinned = toolchain["goVersion"]
    actual = go("go", "version", capture=True).split()
    if len(actual) < 3 or actual[2] != pinned:
        raise SystemExit(f"[center] install the pinned {pinned} (center/toolchain.json) on this native verification host")
    dockerfile = (ROOT / "Dockerfile").read_text(encoding="utf-8")
    archive = toolchain["linuxAmd64"]
    if archive["url"] not in dockerfile or archive["sha256"] not in dockerfile:
        raise SystemExit("[center] the Dockerfile's Go archive differs from center/toolchain.json")
    return pinned


def check_modules() -> None:
    for module in (CENTER, TOOLS):
        go("go", "mod", "download", cwd=module)
        go("go", "mod", "verify", cwd=module)
        # Lock drift: go.mod and go.sum must be exactly what the imports and tool lines require.
        go("go", "mod", "tidy", "-diff", cwd=module)


def runtime_closure() -> dict[str, tuple[str, str, str]]:
    """The modules linked into the shipped executable (linux/amd64, no cgo), with their versions and go.sum hashes."""
    env = {**ENV, "GOOS": "linux", "GOARCH": "amd64", "CGO_ENABLED": "0"}
    raw = go("go", "list", "-deps", "-json", "./cmd/arcforges-center", capture=True, env=env)
    decoder = json.JSONDecoder()
    closure: dict[str, tuple[str, str, str]] = {}
    while raw.strip():
        raw = raw.lstrip()
        package, end = decoder.raw_decode(raw)
        raw = raw[end:]
        module = package.get("Module")
        if module and not module.get("Main"):
            if module.get("Replace"):
                raise SystemExit("[center] a runtime module is replaced; replacements are not admitted")
            closure[module["Path"]] = (module["Version"], module["Sum"], module["GoModSum"])
    return closure


def check_admission() -> int:
    manifest = json.loads((CENTER / "dependencies.json").read_text(encoding="utf-8"))
    if manifest.get("schemaVersion") != 1 or set(manifest["inputs"]) != set(INPUTS):
        raise SystemExit("[center] unexpected admission input inventory in center/dependencies.json")
    for name, expected in manifest["inputs"].items():
        if digest(CENTER / name) != expected:
            raise SystemExit(f"[center] center/{name} changed without a reviewed admission (center/dependencies.json)")
    admitted = {item["path"]: (item["version"], item["sum"], item["goModSum"]) for item in manifest["runtimeModules"]}
    if runtime_closure() != admitted:
        raise SystemExit("[center] unreviewed Go runtime dependency closure (center/dependencies.json)")
    legal = (ROOT / "third-party").resolve()
    for item in manifest["runtimeModules"]:
        for file_key, hash_key in (("licenceFile", "licenceSha256"), ("noticeFile", "noticeSha256")):
            if file_key not in item:
                continue
            target = (ROOT / item[file_key]).resolve()
            if not target.is_relative_to(legal) or digest(target) != item[hash_key]:
                raise SystemExit(f"[center] changed or misplaced legal file of {item['path']}")
        if not item["repository"].startswith("https://") or len(item["commit"]) != 40 or not item["spdx"]:
            raise SystemExit(f"[center] incomplete admission of {item['path']}")
    return len(admitted)


def check_format() -> None:
    unformatted = go("gofmt", "-s", "-l", ".", capture=True).strip()
    if unformatted:
        raise SystemExit("[center] gofmt -s would reformat:\n" + unformatted)


def build_tool(package: str, name: str) -> Path:
    target = ARTIFACTS / "tools" / (name + EXE)
    target.parent.mkdir(parents=True, exist_ok=True)
    go("go", "build", "-trimpath", "-o", str(target), package, cwd=TOOLS)
    return target


def check_static() -> None:
    go("go", "vet", "./...")
    staticcheck = build_tool("honnef.co/go/tools/cmd/staticcheck", "staticcheck")
    # Every check, generated code exempted only by its "Code generated ... DO NOT EDIT." header (staticcheck's own rule).
    go(str(staticcheck), "-checks", "all", "-tests", "./...")


class Postgres:
    """A disposable PostgreSQL server in Docker: its own container, an ephemeral loopback port, data on tmpfs and a random
    superuser password that lives only in this process. Leaving the context removes the container."""

    def __init__(self, purpose: str, settings: tuple[str, ...] = ()) -> None:
        self.name = f"arcforges-center-{purpose}-{secrets.token_hex(4)}"
        self.password = secrets.token_hex(24)
        self.address = ""
        self.settings = settings

    def __enter__(self) -> "Postgres":
        if shutil.which("docker") is None:
            raise SystemExit("[center] Docker is required on the Linux leg (PostgreSQL integration tests and the restore drill)")
        started = subprocess.run(
            ["docker", "run", "--detach", "--rm", "--name", self.name, "--env", "POSTGRES_PASSWORD", "--publish", "127.0.0.1::5432",
             "--tmpfs", "/var/lib/postgresql:rw,size=1g", POSTGRES_IMAGE, "-c", "max_connections=300", "-c", "fsync=off",
             "-c", "synchronous_commit=off", "-c", "full_page_writes=off",
             *[item for setting in self.settings for item in ("-c", setting)]],
            env={**os.environ, "POSTGRES_PASSWORD": self.password}, capture_output=True, text=True)
        if started.returncode != 0:
            raise SystemExit(f"[center] could not start PostgreSQL ({POSTGRES_IMAGE}): {started.stderr.strip()[-300:]}")
        deadline = time.monotonic() + 90
        while True:
            # The image's initialization server listens on the socket only; TCP answers once the final server runs.
            ready = subprocess.run(["docker", "exec", self.name, "pg_isready", "-U", "postgres", "-h", "127.0.0.1"], capture_output=True)
            if ready.returncode == 0:
                break
            if time.monotonic() > deadline:
                raise SystemExit("[center] PostgreSQL did not become ready")
            time.sleep(0.5)
        port = subprocess.run(["docker", "port", self.name, "5432/tcp"], capture_output=True, text=True, check=True).stdout
        self.address = port.splitlines()[0].strip()
        return self

    def __exit__(self, *_: object) -> None:
        subprocess.run(["docker", "rm", "--force", self.name], capture_output=True)

    def url(self, user: str = "postgres", password: str = "", database: str = "postgres") -> str:
        secret = urllib.parse.quote(password or self.password, safe="")
        return f"postgres://{user}:{secret}@{self.address}/{database}?sslmode=disable"

    def sql(self, statement: str, database: str = "postgres") -> None:
        result = subprocess.run(["docker", "exec", self.name, "psql", "-v", "ON_ERROR_STOP=1", "-q", "-U", "postgres", "-d", database,
                                 "-c", statement], capture_output=True, text=True)
        if result.returncode != 0:
            raise SystemExit(f"[center] PostgreSQL statement failed: {result.stderr.strip()[-300:]}")


def check_tests(linux: bool) -> None:
    arguments = ["go", "test", "-count=1", "-timeout", TEST_TIMEOUT]
    if not linux:
        # The PostgreSQL integration tests skip here: the Windows host has no Linux containers (docs/engineering-controls.md).
        go(*arguments, "./...")
    else:
        # The race detector needs cgo, which the Linux host has and the Windows host does not (docs/engineering-controls.md).
        # The integration tests must run here: ARCFORGES_TEST_POSTGRES_REQUIRED turns their skip into a failure. The server preloads
        # pg_stat_statements and logs every statement with its duration, so the rotation tests can check that no secret reaches a
        # statement record or a log line (they read the container's log by its name).
        arguments.insert(2, "-race")
        with Postgres("tests", ("shared_preload_libraries=pg_stat_statements", "log_statement=all",
                                "log_min_duration_statement=0")) as server:
            go(*arguments, "./...", env={**ENV, "ARCFORGES_TEST_POSTGRES_URL": server.url(), "ARCFORGES_TEST_POSTGRES_REQUIRED": "1",
                                          "ARCFORGES_TEST_POSTGRES_CONTAINER": server.name})
    go("go", "run", "./cmd/center-gen", "worker-tables", "-check")


def center_command(executable: Path, server: Postgres, owner_password: str, runtime_role: str, *arguments: str,
                   secret_file: Path | None = None) -> dict[str, object]:
    """Runs the native executable's migrate or admin command against a drill server as the migration role."""
    env = {key: value for key, value in os.environ.items() if not key.startswith(("ARCFORGES_", "NEON_"))}
    env.update({"ARCFORGES_CENTER_MODE": "self-hosted", "ARCFORGES_CENTER_RUNTIME_ROLE": runtime_role,
                "ARCFORGES_CENTER_MIGRATION_DATABASE_URL": server.url("drill_owner", owner_password, "drill"),
                "ARCFORGES_CENTER_RUNTIME_POOLED_HOST": server.address})
    if secret_file is not None:
        env["ARCFORGES_CENTER_RUNTIME_SECRET_FILE"] = str(secret_file)
    result = subprocess.run([str(executable), *arguments], env=env, capture_output=True, text=True, timeout=300)
    if result.returncode != 0:
        raise SystemExit(f"[center] arcforges-center {' '.join(arguments)} failed in the restore drill ({result.returncode})")
    return json.loads(result.stdout)


def rotate(executable: Path, server: Postgres, owner_password: str, runtime_role: str) -> tuple[str, str]:
    """Rotates the drill's runtime credential and confirms its slot as the deployment does after a promotion; returns the runtime
    URL (the secret file is removed at once) and the slot."""
    with tempfile.TemporaryDirectory() as directory:
        secret_file = Path(directory) / "runtime.json"
        rotation = center_command(executable, server, owner_password, runtime_role, "admin", "rotate-runtime-credential",
                                  secret_file=secret_file)
        runtime_url = json.loads(secret_file.read_text(encoding="utf-8"))["ARCFORGES_CENTER_DATABASE_URL"]
    slot = str(rotation["slot"])
    confirmation = center_command(executable, server, owner_password, runtime_role, "admin", "confirm-runtime-credential",
                                  "--slot", slot)
    if confirmation.get("slot") != slot or not confirmation.get("promotedAt"):
        raise SystemExit("[center] the restore drill could not confirm its runtime credential")
    return runtime_url, slot


def drill_phase(phase: str, runtime_url: str) -> None:
    """Runs one phase of the drill test with the runtime credential; a skipped phase fails the drill."""
    output = go("go", "test", "-count=1", "-v", "-run", "^TestRestoreDrill$", "./internal/platform", capture=True,
                env={**ENV, "ARCFORGES_DRILL_PHASE": phase, "ARCFORGES_DRILL_RUNTIME_URL": runtime_url})
    if "--- PASS: TestRestoreDrill" not in output:
        raise SystemExit(f"[center] the restore drill's {phase} phase did not run")


def drill(executable: Path) -> dict[str, object]:
    """The logical-backup restore drill (docs/postgres-store.md): migrate and seed a database with the native executable and
    the runtime credential, dump it with pg_dump, restore it into a second, isolated server, migrate, rotate and confirm there
    (the restored promotion record steers the rotation to the other slot) and run the verify phase (receipt replay, outbox
    publication, job lease, audit chain) against the restored database."""
    dump = ARTIFACTS / "drill" / "center.dump"
    dump.parent.mkdir(parents=True, exist_ok=True)
    owner_password = secrets.token_hex(24)
    setup = [f"CREATE ROLE drill_owner LOGIN CREATEROLE CREATEDB PASSWORD '{owner_password}'", "CREATE DATABASE drill OWNER drill_owner"]
    with Postgres("drill-source") as source, Postgres("drill-restore") as target:
        for statement in setup:
            source.sql(statement)
        migrated = center_command(executable, source, owner_password, "drill_runtime", "migrate")
        if migrated["state"] != "current":
            raise SystemExit("[center] the drill database did not migrate")
        seed_url, seed_slot = rotate(executable, source, owner_password, "drill_runtime")
        drill_phase("seed", seed_url)
        with dump.open("wb") as output:
            dumped = subprocess.run(["docker", "exec", source.name, "pg_dump", "-U", "postgres", "--format=custom", "-d", "drill"],
                                    stdout=output, stderr=subprocess.PIPE)
        if dumped.returncode != 0:
            raise SystemExit("[center] pg_dump failed in the restore drill")
        for statement in setup:
            target.sql(statement)
        with dump.open("rb") as source_file:
            restored = subprocess.run(["docker", "exec", "-i", target.name, "pg_restore", "-U", "postgres", "--no-owner", "--no-acl",
                                       "--role=drill_owner", "--exit-on-error", "-d", "drill"], stdin=source_file, stderr=subprocess.PIPE)
        if restored.returncode != 0:
            raise SystemExit("[center] pg_restore failed in the restore drill")
        status = center_command(executable, target, owner_password, "drill_runtime", "migrate", "status")
        if status["state"] != "current" or status["pending"]:
            raise SystemExit("[center] the restored database does not match the build's migrations")
        reconciled = center_command(executable, target, owner_password, "drill_runtime", "migrate")
        if reconciled["state"] != "current" or reconciled.get("ran") or reconciled.get("grants") != "reconciled":
            raise SystemExit("[center] the restored database did not reconcile its runtime grants")
        # The restored record says slot a is promoted (the live revision's), so the restored database rotates slot b.
        verify_url, verify_slot = rotate(executable, target, owner_password, "drill_runtime")
        if (seed_slot, verify_slot) != ("a", "b"):
            raise SystemExit(f"[center] the restore drill rotated slots {seed_slot} and {verify_slot}, expected a and b")
        drill_phase("verify", verify_url)
    return {"dumpBytes": dump.stat().st_size, "schemaVersion": status["version"], "serverVersionNum": status["serverVersionNum"],
            "slots": [seed_slot, verify_slot],
            "phases": ["seed", "dump", "restore", "migrate", "verify"]}


def check_fuzz() -> None:
    for package, target in FUZZ_TARGETS:
        go("go", "test", "-run", "^$", "-fuzz", f"^{target}$", "-fuzztime", FUZZ_TIME, package)


def check_vulnerabilities() -> None:
    govulncheck = build_tool("golang.org/x/vuln/cmd/govulncheck", "govulncheck")
    go(str(govulncheck), "-test", "./...")


def build_native() -> Path:
    executable = ARTIFACTS / ("arcforges-center" + EXE)
    executable.parent.mkdir(parents=True, exist_ok=True)
    go("go", "build", "-trimpath", "-buildvcs=false", "-o", str(executable), "./cmd/arcforges-center",
       env={**ENV, "CGO_ENABLED": "0"})
    return executable


def smoke(executable: Path, linux: bool) -> dict[str, object]:
    """Starts the native executable as a self-hosted center on an ephemeral loopback port and checks it serves and refuses."""
    identity = json.loads(subprocess.run([str(executable), "version"], capture_output=True, text=True, check=True).stdout)
    if identity["runtime"] != "go" or identity["nativeAot"] is not False or identity["center"]["binary"] != "arcforges-center":
        raise SystemExit("[center] the executable reports a wrong identity")
    bare = {key: value for key, value in os.environ.items() if not key.startswith(("ARCFORGES_", "NEON_"))}
    refused = subprocess.run([str(executable), "serve"], env=bare, capture_output=True, text=True, timeout=30)
    if refused.returncode != 1 or "the center refused to start" not in refused.stderr:
        raise SystemExit("[center] the center started without an explicit mode")
    log = ARTIFACTS / "smoke.log"
    env = {**bare, "ARCFORGES_CENTER_MODE": "self-hosted", "ARCFORGES_CENTER_PUBLIC_BASE_URL": "http://127.0.0.1:8080",
           "ARCFORGES_CENTER_HTTP_ADDRESS": "127.0.0.1:0", "ARCFORGES_CENTER_GRPC_ADDRESS": "off",
           "ARCFORGES_CENTER_METRICS_LOG_INTERVAL": "0"}
    with log.open("w", encoding="utf-8") as output:
        process = subprocess.Popen([str(executable)], env=env, stdout=output, stderr=output)
    # Loopback only, never through a proxy of the host's environment or registry.
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    try:
        address = ""
        deadline = time.monotonic() + 30
        while not address and time.monotonic() < deadline and process.poll() is None:
            for line in log.read_text(encoding="utf-8").splitlines():
                try:
                    entry = json.loads(line)
                except json.JSONDecodeError:
                    continue  # a line still being written
                if entry.get("msg") == "center started":
                    address = entry["listeners"]["http"]
            time.sleep(0.1)
        if not address:
            raise SystemExit("[center] the self-hosted center did not start; see " + str(log))
        with opener.open(f"http://{address}/healthz", timeout=10) as response:
            health = json.load(response)
        if health["runtime"] != "go" or health["center"] != {"binary": "arcforges-center", "mode": "self-hosted",
                                                              "publicBaseUrl": "http://127.0.0.1:8080"}:
            raise SystemExit("[center] the self-hosted health document is wrong")
        request = urllib.request.Request(f"http://{address}/arcforges.hello.v1.HelloService/Unknown", data=b"\0\0\0\0\0",
                                         headers={"Content-Type": "application/grpc-web+proto"}, method="POST")
        with opener.open(request, timeout=10) as response:
            body = response.read()
        if body != b"\x80\x00\x00\x00\x2egrpc-status: 12\r\ngrpc-message: unimplemented\r\n":
            raise SystemExit("[center] an unregistered method was not refused as UNIMPLEMENTED")
    finally:
        process.terminate()
        code = process.wait(timeout=30)
    # SIGTERM stops the center gracefully on Linux; Windows has no SIGTERM, so terminate() ends the process there.
    if linux and (code != 0 or '"msg":"center stopped"' not in log.read_text(encoding="utf-8")):
        raise SystemExit("[center] the center did not shut down gracefully on SIGTERM; see " + str(log))
    return {"address": address, "mode": health["center"]["mode"], "refusesWithoutMode": True,
            "gracefulShutdown": linux}


def check() -> None:
    linux = sys.platform.startswith("linux")
    if not linux and not WINDOWS:
        raise SystemExit("[center] the verification hosts are native Linux and native Windows")
    tracked = {name: (CENTER / name).read_bytes() for name in INPUTS}
    pinned = check_toolchain()
    say(f"{pinned}; {'Linux leg: race, fuzzing and the image target' if linux else 'Windows leg (no cgo: no race detector)'}")
    check_modules()
    modules = check_admission()
    say(f"{modules} runtime modules admitted")
    check_format()
    check_static()
    say("gofmt, go vet and staticcheck passed")
    check_tests(linux)
    say("unit, protocol and drift tests passed" + (" with the race detector and the PostgreSQL integration tests" if linux else ""))
    checks = ["toolchain", "module-integrity", "lock-drift", "dependency-admission", "format", "vet", "staticcheck",
              "unit" + ("-race" if linux else ""), "generation-drift"]
    if linux:
        checks.append("postgres-integration")
    if linux:
        check_fuzz()
        checks.append("fuzz-" + FUZZ_TIME)
        say("fuzz targets passed")
    check_vulnerabilities()
    checks.append("govulncheck")
    # On Linux the native build is the image target (linux/amd64 without cgo, as the Dockerfile builds it).
    executable = build_native()
    smoked = smoke(executable, linux)
    checks += ["native-build", "self-hosted-smoke"]
    drilled: dict[str, object] = {}
    if linux:
        drilled = drill(executable)
        checks.append("restore-drill")
        say("restore drill passed")
    for name, content in tracked.items():
        if (CENTER / name).read_bytes() != content:
            raise SystemExit(f"[center] the check modified center/{name}")
    evidence = {"go": pinned, "host": "linux" if linux else "windows", "checks": checks, "passed": True,
                "fuzzTargets": [target for _, target in FUZZ_TARGETS] if linux else [],
                "liveDatabaseTested": False, "postgres": {"image": POSTGRES_IMAGE, "drill": drilled} if linux else None,
                "smoke": smoked,
                "executableSha256": hashlib.sha256(executable.read_bytes()).hexdigest()}
    (ARTIFACTS / "checks.json").write_text(json.dumps(evidence, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(evidence), flush=True)


def generate() -> None:
    check_toolchain()
    go("go", "run", "./cmd/center-gen", "worker-tables")


def main() -> None:
    commands = {"check": check, "generate": generate}
    if sys.argv[1:] not in [[name] for name in commands]:
        raise SystemExit("usage: python eng/center.py check | generate")
    commands[sys.argv[1]]()


if __name__ == "__main__":
    main()
