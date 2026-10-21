#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Local pre-push verification (the same file in every ArcForges repository; the steps live in eng/verify_steps.py).

  python eng/verify.py install                    install .githooks/* for every worktree of this clone (once)
  python eng/verify.py run [--rev REV] [--force]  verify this machine's leg of a commit now (default HEAD)
  python eng/verify.py list [--rev REV]           show the profile, the steps and the state of each leg
  python eng/verify.py import RECORD              accept the pass record of a leg verified on another machine
  python eng/verify.py pre-push REMOTE [URL]      the hook entry point (refs on stdin)

Every step runs on one host, 'win' (native Windows) or 'linux' (native Linux); the steps of one host are the commit's
leg for that host. A machine runs only the leg of its own operating system, never another one through WSL, a VM or a
remote shell: on Windows in a detached verification worktree (<main checkout>/.worktree/_verify), on Linux in a
Linux-native clone (~/.cache/arcforges-verify/<repo>), both checked out at the commit and cleaned of untracked files
(ignored build output stays, so builds are incremental). That clone is shared by every clone of the repository on the
host, so one Linux leg of a repository runs on a host at a time. The pushed commit is verified, never the working tree,
and the step table and this script are read from the commit itself. Steps run in lanes: lanes run concurrently, the
steps of a lane in order, and steps marked exclusive run alone afterwards. Any step that fails, times out or cannot run
fails the leg (fail closed).

A passed leg is recorded under the Git common directory, keyed by the commit's tree (its exact commits when a step reads
history), the merge base, the profile, the leg's host and step set, these scripts and the step table's CONTEXT (inputs
other than the commit, such as the Plan's Design main commit). A local record also holds the tool versions it ran with
and is reused only while they are unchanged. The record of a leg that passed on another machine at the same commit is
accepted with `import`, which recomputes the key here and refuses a record whose commit, tree, merge base, profile, step
set, scripts or context differ, or which holds a step that did not pass. A push needs a passed or imported record for
every leg of every pushed commit, and is rejected while one is missing.
"""
from __future__ import annotations

import argparse
import contextlib
import ctypes
import datetime as _dt
import hashlib
import json
import os
import platform
import re
import shlex
import subprocess
import sys
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable

ZERO = "0" * 40
TAIL_LINES = 60
LINUX_STATE = "$HOME/.cache/arcforges-verify"
HOSTS = {"win": "Windows", "linux": "Linux"}
RECORD_FORMAT = "arcforges-verify-leg/1"


@dataclass(frozen=True)
class Step:
    """One verification step. `cmd` is an argv list on the 'win' host and a bash command string on the 'linux' host.
    The placeholders {sha}, {base} and {range} are replaced; a step that reads history must use them (never a
    hard-coded range), because they are what keys its pass to the exact commits. `profiles` names the profiles that
    include the step;
    `when` (changed paths -> bool) can narrow it further. Exclusive steps run alone after every lane has finished."""

    id: str
    host: str
    cmd: list[str] | str
    timeout: int = 1800
    lane: str = ""
    profiles: frozenset[str] = frozenset({"full"})
    when: Callable[[list[str]], bool] | None = None
    exclusive: bool = False
    env: dict[str, str] = field(default_factory=dict)

    @property
    def lane_name(self) -> str:
        return self.lane or self.host


class VerifyError(Exception):
    pass


def git(*args: str, cwd: Path | None = None, check: bool = True) -> str:
    result = subprocess.run(["git", *args], cwd=cwd, capture_output=True, text=True, encoding="utf-8", errors="replace")
    if check and result.returncode != 0:
        raise VerifyError(f"git {' '.join(args)} failed: {result.stderr.strip()}")
    return result.stdout.strip()


def say(message: str) -> None:
    print(f"[verify {_dt.datetime.now():%H:%M:%S}] {message}", flush=True)


def normalized(data: bytes) -> bytes:
    return data.replace(b"\r\n", b"\n")


class Repository:
    def __init__(self) -> None:
        self.top = Path(git("rev-parse", "--show-toplevel"))
        self.common = Path(git("rev-parse", "--path-format=absolute", "--git-common-dir"))
        self.main = self.common.parent if self.common.name == ".git" else self.top
        self.state = self.common / "arcforges-verify"
        self.state.mkdir(parents=True, exist_ok=True)
        self.steps = None
        self.digest = ""

    @property
    def name(self) -> str:
        return getattr(self.steps, "REPOSITORY", self.main.name)

    def load_steps(self, sha: str):
        """Reads the step table and this script from the commit being verified, so a push is verified by its own
        definition. The running script must be that commit's eng/verify.py."""
        try:
            core = subprocess.run(["git", "show", f"{sha}:eng/verify.py"], cwd=self.top, capture_output=True,
                                  check=True).stdout
            table = subprocess.run(["git", "show", f"{sha}:eng/verify_steps.py"], cwd=self.top, capture_output=True,
                                   check=True).stdout
        except subprocess.CalledProcessError as error:
            raise VerifyError(f"{sha[:12]} has no committed eng/verify.py and eng/verify_steps.py") from error
        if normalized(core) != normalized(Path(__file__).read_bytes()):
            raise VerifyError(f"the running {Path(__file__)} differs from eng/verify.py in {sha[:12]}; push from a "
                              "worktree whose eng/verify.py matches the pushed commit")
        self.digest = hashlib.sha256(normalized(core) + b"\0" + normalized(table)).hexdigest()
        module = type(sys)("verify_steps")
        module.__dict__["Step"] = Step
        sys.modules["verify_steps"] = module
        exec(compile(table, f"{sha[:12]}:eng/verify_steps.py", "exec"), module.__dict__)
        self.steps = module
        return module


# ---------------------------------------------------------------------------------------------------------------- hosts

def this_host() -> str:
    """The host this machine verifies: its own operating system, natively."""
    if os.name == "nt":
        return "win"
    if sys.platform.startswith("linux"):
        return "linux"
    raise VerifyError(f"no verification host runs on {sys.platform}; the hosts are native Windows and native Linux")


def bash_argv(command: str) -> list[str]:
    return ["bash", "-lc", command]


def bash_run(command: str, timeout: int = 600) -> str:
    try:
        result = subprocess.run(bash_argv(command), capture_output=True, text=True, encoding="utf-8",
                                errors="replace", timeout=timeout, stdin=subprocess.DEVNULL)
    except FileNotFoundError as error:
        raise VerifyError("bash was not found; the Linux steps need bash") from error
    except subprocess.TimeoutExpired as error:
        raise VerifyError(f"a Linux command timed out after {timeout}s: {command}") from error
    if result.returncode != 0:
        raise VerifyError(f"a Linux command failed with exit code {result.returncode}: "
                          f"{command}\n{(result.stdout + result.stderr).strip()[-2000:]}")
    return result.stdout.strip()


def fingerprint(repo: Repository, host: str) -> dict[str, str]:
    """Tool versions of this machine's leg (FINGERPRINT in the step table: {host: {name: probe}})."""
    probes = getattr(repo.steps, "FINGERPRINT", {})
    values: dict[str, str] = {"python": sys.version.split()[0]}
    for name, probe in probes.get(host, {}).items():
        if host == "linux":
            values[f"linux:{name}"] = bash_run(probe, timeout=300)
            continue
        try:
            result = subprocess.run(probe, capture_output=True, text=True, encoding="utf-8", errors="replace",
                                    timeout=300, cwd=repo.top, shell=isinstance(probe, str),
                                    stdin=subprocess.DEVNULL)
        except (OSError, subprocess.TimeoutExpired) as error:
            raise VerifyError(f"the Windows tool probe '{name}' cannot run: {error}") from error
        if result.returncode != 0:
            raise VerifyError(f"the Windows tool probe '{name}' failed: {result.stderr.strip()}")
        values[f"win:{name}"] = result.stdout.strip()
    return values


# -------------------------------------------------------------------------------------------------------------- sources

def prepare_windows(repo: Repository, sha: str) -> Path:
    path = repo.main / ".worktree" / "_verify"
    if not (path / ".git").exists():
        git("worktree", "prune", cwd=repo.main)
        path.parent.mkdir(parents=True, exist_ok=True)
        git("worktree", "add", "--force", "--detach", str(path), sha, cwd=repo.main)
    else:
        git("checkout", "--force", "--detach", sha, cwd=path)
    git("clean", "-ffdq", cwd=path)
    if git("rev-parse", "HEAD", cwd=path) != sha:
        raise VerifyError(f"the verification worktree {path} is not at {sha}")
    return path


def prepare_linux(repo: Repository, sha: str, base: str) -> str:
    source = str(repo.common)
    pack = "git -c uploadpack.allowAnySHA1InWant=true upload-pack"
    script = (
        "set -euo pipefail; "
        # Sessions left by an aborted earlier run (Runner.argv) stop before the sources change under them.
        f"for f in {LINUX_STATE}/pids/{repo.name}.*.pid; do [ -e \"$f\" ] || continue; g=\"$(cat \"$f\")\"; "
        "if grep -qa arcforges-verify /proc/$g/cmdline 2>/dev/null; then pkill -KILL -s $g || true; fi; "
        "rm -f \"$f\"; done; "
        # A fetch that git cannot complete (an earlier fetch from a shallow source, an interrupted one) can leave the
        # clone without some history while still exiting 0; a clone whose history from the commit and the base does
        # not walk is made again from scratch, and a second failure stops the leg.
        f"d={LINUX_STATE}/{repo.name}; "
        f"fill() {{ mkdir -p \"$d\" && cd \"$d\" && {{ [ -d .git ] || git init -q; }} && "
        f"git fetch -q --no-tags --upload-pack={shlex.quote(pack)} {shlex.quote(source)} {sha} {base} && "
        # rev-list treats a shallow boundary as a root, so a clone that is itself shallow would still walk.
        "test \"$(git rev-parse --is-shallow-repository)\" = false && "
        f"git rev-list --quiet {sha} {base} >/dev/null 2>&1; }}; "
        "if ! fill; then echo \"the Linux clone $d is incomplete; making it again\"; cd /; rm -rf \"$d\"; fill || "
        "{ echo \"the Linux clone $d cannot be filled from the commit's history\" >&2; exit 1; }; fi; "
        f"git checkout -q --force --detach {sha}; git clean -ffdq; test \"$(git rev-parse HEAD)\" = {sha}; pwd"
    )
    *notes, path = bash_run(script, timeout=1800).splitlines()
    for note in notes:
        say(note)
    return path


# ------------------------------------------------------------------------------------------------------------ execution

def kill_tree(process: subprocess.Popen) -> None:
    if process.poll() is not None:
        return
    if os.name == "nt":
        subprocess.run(["taskkill", "/PID", str(process.pid), "/T", "/F"], capture_output=True)
    else:
        process.kill()


@dataclass
class Outcome:
    step: Step
    ok: bool
    seconds: float
    log: Path
    reason: str = ""


class Runner:
    def __init__(self, repo: Repository, logs: Path, sha: str, base: str, workdir: Path | str, keep_going: bool):
        self.repo, self.logs, self.sha, self.base = repo, logs, sha, base
        self.workdir, self.keep_going = workdir, keep_going
        self.stop = threading.Event()
        self.live: dict[subprocess.Popen, Step] = {}
        self.lock = threading.Lock()
        self.outcomes: list[Outcome] = []
        self.aborted: set[str] = set()

    def expand(self, text: str) -> str:
        return text.replace("{sha}", self.sha).replace("{base}", self.base).replace("{range}", f"{self.base}..{self.sha}")

    def pidfile(self, step: Step) -> str:
        return f"{LINUX_STATE}/pids/{self.repo.name}.{step.id}.pid"

    def argv(self, step: Step) -> list[str]:
        if step.host == "win":
            if not isinstance(step.cmd, list):
                raise VerifyError(f"step {step.id}: a win step needs an argv list")
            return [self.expand(part) for part in step.cmd]
        if step.host != "linux" or not isinstance(step.cmd, str):
            raise VerifyError(f"step {step.id}: a linux step needs a bash command string")
        exports = "".join(f"export {key}={shlex.quote(value)}; " for key, value in step.env.items())
        inner = f"export ARCFORGES_VERIFY=1; {exports}{self.expand(step.cmd)}"
        # The step runs in its own session, recorded until it ends so that an abort can stop all of it (ending the bash
        # that started it does not stop its other processes); timeout(1) signals its process group when the step runs too
        # long.
        guarded = (f"echo $$ > {self.pidfile(step)}; timeout --kill-after=30 {step.timeout} bash -c {shlex.quote(inner)}; "
                   f"rc=$?; rm -f {self.pidfile(step)}; exit $rc")
        command = f"mkdir -p {LINUX_STATE}/pids; exec setsid --wait bash -c {shlex.quote(guarded)}"
        return bash_argv(command)

    def stop_linux(self, step: Step) -> None:
        """Stops a Linux step's session (setsid): TERM, up to 15 s for it to end, then KILL."""
        script = (f"g=\"$(cat {self.pidfile(step)} 2>/dev/null)\"; [ -n \"$g\" ] || exit 0; "
                  "grep -qa arcforges-verify /proc/$g/cmdline 2>/dev/null || exit 0; "
                  "pkill -TERM -s $g || exit 0; "
                  "for i in $(seq 30); do pgrep -s $g >/dev/null || exit 0; sleep 0.5; done; "
                  "pkill -KILL -s $g; true")
        try:
            bash_run(script, timeout=120)
        except VerifyError as error:
            say(f"could not stop the Linux step {step.id}: {error}")

    def abort(self, process: subprocess.Popen, step: Step) -> None:
        with self.lock:
            self.aborted.add(step.id)
        if step.host == "linux":
            self.stop_linux(step)
        kill_tree(process)

    def run(self, step: Step) -> Outcome:
        log = self.logs / f"{step.id}.log"
        if self.stop.is_set():
            return Outcome(step, False, 0.0, log, "not started: an earlier step failed")
        say(f"start {step.id} ({step.host})")
        started = time.monotonic()
        env = dict(os.environ, ARCFORGES_VERIFY="1", **(step.env if step.host == "win" else {}))
        reason = ""
        try:
            argv = self.argv(step)
            with open(log, "w", encoding="utf-8", errors="replace") as sink:
                sink.write(f"# {step.id} on {step.host} at {self.sha}\n# {argv}\n")
                sink.flush()
                process = subprocess.Popen(argv, cwd=self.workdir, stdout=sink,
                                           stderr=subprocess.STDOUT, stdin=subprocess.DEVNULL, env=env)
                with self.lock:
                    self.live[process] = step
                    stopped = self.stop.is_set()
                if stopped:
                    self.abort(process, step)
                try:
                    code = process.wait(timeout=step.timeout + (90 if step.host == "linux" else 0))
                    if code == 124 and step.host == "linux":
                        reason = f"timed out after {step.timeout}s"
                    elif code != 0:
                        reason = f"exit code {code}"
                except subprocess.TimeoutExpired:
                    self.abort(process, step)
                    process.wait()
                    reason = f"timed out after {step.timeout}s"
                finally:
                    with self.lock:
                        self.live.pop(process, None)
        except (OSError, VerifyError) as error:
            reason = f"cannot run: {error}"
        if reason and step.id in self.aborted and not reason.startswith("timed out"):
            reason = "stopped after an earlier failure"
        seconds = time.monotonic() - started
        say(f"{'pass' if not reason else 'FAIL'} {step.id} in {seconds:.0f}s{': ' + reason if reason else ''}")
        return Outcome(step, not reason, seconds, log, reason)

    def lane(self, steps: list[Step]) -> None:
        for step in steps:
            outcome = self.run(step)
            with self.lock:
                self.outcomes.append(outcome)
            if not outcome.ok:
                self.fail_fast()
                if not self.keep_going:
                    return

    def fail_fast(self) -> None:
        if self.keep_going:
            return
        self.stop.set()
        with self.lock:
            running = list(self.live.items())
        for process, step in running:
            self.abort(process, step)

    def execute(self, steps: list[Step]) -> bool:
        lanes: dict[str, list[Step]] = {}
        for step in steps:
            if not step.exclusive:
                lanes.setdefault(step.lane_name, []).append(step)
        threads = [threading.Thread(target=self.lane, args=(lane,), daemon=True) for lane in lanes.values()]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()
        for step in (s for s in steps if s.exclusive):
            if self.stop.is_set():
                break
            self.lane([step])
        return len(self.outcomes) == len(steps) and all(o.ok for o in self.outcomes)


# ------------------------------------------------------------------------------------------------------------- the lock

def process_alive(pid: int) -> bool:
    if os.name != "nt":
        try:
            os.kill(pid, 0)
            return True
        except OSError:
            return False
    # Never os.kill on Windows: it terminates the process.
    kernel = ctypes.windll.kernel32  # type: ignore[attr-defined]
    handle = kernel.OpenProcess(0x1000, False, pid)  # PROCESS_QUERY_LIMITED_INFORMATION
    if not handle:
        return False
    code = ctypes.c_ulong()
    kernel.GetExitCodeProcess(handle, ctypes.byref(code))
    kernel.CloseHandle(handle)
    return code.value == 259  # STILL_ACTIVE


class Lock:
    def __init__(self, path: Path) -> None:
        self.path = path

    def __enter__(self) -> "Lock":
        for _ in range(2):
            try:
                fd = os.open(self.path, os.O_CREAT | os.O_EXCL | os.O_WRONLY)
                os.write(fd, str(os.getpid()).encode())
                os.close(fd)
                return self
            except FileExistsError:
                try:
                    holder = int(self.path.read_text().strip() or "0")
                except (OSError, ValueError):
                    holder = 0
                if holder and process_alive(holder):
                    raise VerifyError(f"another verification (process {holder}) is running for this repository")
                self.path.unlink(missing_ok=True)
        raise VerifyError(f"cannot take the verification lock {self.path}")

    def __exit__(self, *_: object) -> None:
        self.path.unlink(missing_ok=True)


class HostLock:
    """The Linux leg's lock across every clone of the repository on this host. Its Linux-native clone, its pid files and
    the step table's caches under ~/.cache/arcforges-verify are named by the repository, not by the clone, so a second
    clone's leg would check out, clean or stop them under the first one's running steps. flock(2) is released when its
    holder ends, so a crashed run leaves nothing to clear."""

    def __init__(self, repo: Repository) -> None:
        self.path = Path.home() / ".cache" / "arcforges-verify" / "locks" / f"{repo.name}.lock"
        self.fd = -1

    def __enter__(self) -> "HostLock":
        import fcntl  # noqa: PLC0415 - POSIX only; the Linux leg runs only on Linux

        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.fd = os.open(self.path, os.O_CREAT | os.O_RDWR, 0o644)
        try:
            fcntl.flock(self.fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError as error:
            holder = os.pread(self.fd, 64, 0).decode(errors="replace").strip() or "?"
            os.close(self.fd)
            raise VerifyError(f"another clone's Linux leg of this repository (process {holder}) is running on this "
                              f"host ({self.path}); verify again when it has finished") from error
        os.ftruncate(self.fd, 0)
        os.pwrite(self.fd, str(os.getpid()).encode(), 0)
        return self

    def __exit__(self, *_: object) -> None:
        os.close(self.fd)  # releases the flock; the file stays, so no other run can lock a different inode


# ------------------------------------------------------------------------------------------------------------- commands

def upstream_ref(remote: str) -> str:
    """The remote's default branch (refs/remotes/<remote>/HEAD when known, else main)."""
    head = git("symbolic-ref", "--quiet", f"refs/remotes/{remote}/HEAD", check=False)
    return head or f"refs/remotes/{remote}/main"


def plan(repo: Repository, sha: str, remote: str) -> tuple[str, str, list[str], list[Step]]:
    upstream = upstream_ref(remote)
    # A stale remote-tracking branch would give an older base, so it is refreshed first (pushing is online anyway).
    branch = upstream.removeprefix(f"refs/remotes/{remote}/")
    fetched = subprocess.run(["git", "fetch", "--quiet", "--no-tags", remote, f"+refs/heads/{branch}:{upstream}"],
                             capture_output=True, text=True, encoding="utf-8", errors="replace")
    if fetched.returncode != 0:
        raise VerifyError(f"cannot refresh {upstream} from {remote}: {fetched.stderr.strip()}; check the network "
                          "access to the remote and push again")
    if not git("rev-parse", "--verify", "--quiet", upstream, check=False):
        raise VerifyError(f"{upstream} is missing after fetching {remote}")
    base = git("merge-base", sha, upstream)
    # Without renames a moved file lists both paths, so a rename out of a code directory cannot select a lighter profile.
    changed = [line for line in git("diff", "--name-only", "--no-renames", base, sha).splitlines() if line]
    profile = repo.steps.select_profile(changed)
    steps = [s for s in repo.steps.STEPS if profile in s.profiles and (s.when is None or s.when(changed))]
    ids = [s.id for s in steps]
    if len(ids) != len(set(ids)):
        raise VerifyError("eng/verify_steps.py defines a step id twice")
    if not steps:
        raise VerifyError(f"profile '{profile}' selects no steps")
    return base, profile, changed, steps


@dataclass
class Leg:
    """The steps of one host for one commit, and where its pass record lives."""

    host: str
    steps: list[Step]
    key: str
    record: Path


@dataclass
class Target:
    sha: str
    tree: str
    base: str
    profile: str
    changed: list[str]
    context: dict[str, str]
    legs: dict[str, Leg]


def target(repo: Repository, rev: str, remote: str) -> Target:
    sha = git("rev-parse", "--verify", f"{rev}^{{commit}}")
    repo.load_steps(sha)
    base, profile, changed, steps = plan(repo, sha, remote)
    unknown = sorted({s.host for s in steps} - set(HOSTS))
    if unknown:
        raise VerifyError(f"eng/verify_steps.py names unknown hosts {', '.join(unknown)} (the hosts are {', '.join(HOSTS)})")
    tree = git("rev-parse", f"{sha}^{{tree}}")
    # The key is the source state the steps actually see: the tree, plus the exact commits when a step reads history
    # ({sha}, {base}, {range}, e.g. a secret scan of the pushed commits), the merge base, which selects the profile and
    # the steps, the leg's host and step set, and CONTEXT: inputs other than the commit that every leg checks against
    # (for example the Plan's Design main commit), declared by the step table as {name: value}.
    context = {str(k): str(v) for k, v in getattr(repo.steps, "CONTEXT", {}).items()}
    legs: dict[str, Leg] = {}
    for host in HOSTS:
        host_steps = [s for s in steps if s.host == host]
        if not host_steps:
            continue
        history = any(marker in (s.cmd if isinstance(s.cmd, str) else " ".join(s.cmd))
                      for s in host_steps for marker in ("{sha}", "{base}", "{range}"))
        source = [tree, base, sha] if history else [tree, base]
        key = hashlib.sha256(json.dumps([source, profile, host, sorted(s.id for s in host_steps), repo.digest, context],
                                        sort_keys=True).encode()).hexdigest()
        legs[host] = Leg(host, host_steps, key, repo.state / f"leg-{host}-{key[:32]}.json")
    return Target(sha, tree, base, profile, changed, context, legs)


def read_record(leg: Leg) -> dict | None:
    """The leg's pass record, or None. A record that is unreadable or not a pass of exactly this leg is ignored."""
    try:
        data = json.loads(leg.record.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    ok = (isinstance(data, dict) and data.get("format") == RECORD_FORMAT and data.get("key") == leg.key
          and data.get("host") == leg.host and results_cover(data.get("results"), leg))
    return data if ok else None


def results_cover(results: object, leg: Leg) -> bool:
    """True when the results hold exactly the leg's steps, each passed."""
    if not isinstance(results, list) or not all(isinstance(r, dict) for r in results):
        return False
    return (sorted(str(r.get("step")) for r in results) == sorted(s.id for s in leg.steps)
            and all(r.get("ok") is True for r in results))


def describe(data: dict) -> str:
    origin = "imported" if data.get("origin") == "imported" else "local"
    return f"{data.get('host')}@{data.get('machine', '?')} ({origin}, {data.get('finished', '?')})"


def log_digest(path: Path) -> str:
    try:
        return hashlib.sha256(path.read_bytes()).hexdigest()
    except OSError:
        return ""


def run_leg(repo: Repository, t: Target, leg: Leg, tools: dict[str, str], keep_going: bool) -> dict:
    stamp = _dt.datetime.now().strftime("%Y%m%d-%H%M%S")
    logs = repo.state / "logs" / f"{stamp}-{t.sha[:12]}-{leg.host}"
    logs.mkdir(parents=True, exist_ok=True)
    say(f"verifying the {leg.host} leg of {t.sha[:12]} (base {t.base[:12]}, {len(t.changed)} changed paths), profile "
        f"'{t.profile}', {len(leg.steps)} steps; logs in {logs}")
    # A shallow clone lacks the history that steps reading {base}..{sha} need, and a clone fetched from it is left
    # incomplete without an error, so it is refused instead of verified partially.
    if git("rev-parse", "--is-shallow-repository", check=False) == "true":
        raise VerifyError("this clone is shallow: run `git fetch --unshallow` (or clone it in full) and verify again")
    started = time.monotonic()
    with Lock(repo.state / "lock"), HostLock(repo) if leg.host == "linux" else contextlib.nullcontext():
        workdir = prepare_windows(repo, t.sha) if leg.host == "win" else prepare_linux(repo, t.sha, t.base)
        runner = Runner(repo, logs, t.sha, t.base, workdir, keep_going)
        ok = runner.execute(leg.steps)
    seconds = time.monotonic() - started
    results = [{"step": o.step.id, "ok": o.ok, "seconds": round(o.seconds, 1), "reason": o.reason,
                "log_sha256": log_digest(o.log)} for o in runner.outcomes]
    (logs / "summary.json").write_text(json.dumps({"sha": t.sha, "tree": t.tree, "base": t.base, "profile": t.profile,
                                                    "host": leg.host, "tools": tools, "ok": ok,
                                                    "seconds": round(seconds), "steps": results}, indent=2),
                                       encoding="utf-8")
    if not ok:
        failed = [o for o in runner.outcomes if not o.ok]
        first = failed[0] if failed else None
        if first is not None and first.log.exists():
            lines = first.log.read_text(encoding="utf-8", errors="replace").splitlines()[-TAIL_LINES:]
            print("\n".join(["", f"---- last {len(lines)} lines of {first.log} ----", *lines, "----"]), flush=True)
        ran = {o.step.id for o in runner.outcomes}
        raise VerifyError(f"the {leg.host} leg failed: " + "; ".join(
            [f"{o.step.id} ({o.reason})" for o in failed] + [f"{s.id} (not run)" for s in leg.steps if s.id not in ran]))
    data = {"format": RECORD_FORMAT, "origin": "local", "repository": repo.name, "sha": t.sha, "tree": t.tree,
            "base": t.base, "profile": t.profile, "host": leg.host, "key": leg.key, "digest": repo.digest,
            "steps": sorted(s.id for s in leg.steps), "context": t.context, "tools": tools, "machine": platform.node(),
            "platform": platform.platform(), "finished": _dt.datetime.now(_dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "seconds": round(seconds), "logs": str(logs), "results": results}
    leg.record.write_text(json.dumps(data, indent=2), encoding="utf-8")
    print(f"arcforges-verify: LEG PASS {t.sha} host {leg.host} on {data['machine']} tree {t.tree} profile {t.profile} "
          f"{len(leg.steps)} steps {seconds:.0f}s record {leg.record}", flush=True)
    return data


def missing_leg(t: Target, host: str) -> str:
    return (f"the {host} leg of {t.sha[:12]} has no pass record here: run `python eng/verify.py run --rev {t.sha}` on "
            f"native {HOSTS[host]}, in a checkout of this exact commit, then `python eng/verify.py import <its record>` "
            "in this clone")


def verify(repo: Repository, rev: str, remote: str, force: bool = False, keep_going: bool = False,
           require_all: bool = False) -> bool:
    """Runs this machine's leg of the commit unless it already passed, then checks every other leg's record. Returns
    True when every leg passed; with require_all, a missing leg raises instead."""
    t = target(repo, rev, remote)
    here = this_host()
    passed: dict[str, dict] = {}
    pending: list[str] = []
    # Before a push, the other machines' records are checked first, so a missing one rejects it without running this
    # machine's leg.
    if require_all:
        missing = [host for host, leg in t.legs.items() if host != here and read_record(leg) is None]
        if missing:
            raise VerifyError("; ".join(missing_leg(t, host) for host in missing))
    for host, leg in t.legs.items():
        data = read_record(leg)
        tools: dict[str, str] = {}
        if host == here and (data is None or data.get("origin") == "local" or force):
            tools = fingerprint(repo, host)
            if data is not None and data.get("origin") == "local" and data.get("tools") != tools and not force:
                say(f"the tool versions of the {host} leg changed since {leg.record.name}; verifying it again")
                data = None
        if data is not None and not (force and host == here):
            say(f"the {host} leg of {t.sha[:12]} already passed profile '{t.profile}' with these steps and scripts: "
                f"{describe(data)}, {leg.record.name}")
            passed[host] = data
        elif host == here:
            passed[host] = run_leg(repo, t, leg, tools, keep_going)
        else:
            pending.append(host)
    if pending:
        if require_all:
            raise VerifyError("; ".join(missing_leg(t, host) for host in pending))
        for host in pending:
            say(missing_leg(t, host))
        print(f"arcforges-verify: INCOMPLETE {t.sha} tree {t.tree} profile {t.profile}: passed "
              f"{', '.join(sorted(passed)) or 'no leg'}; missing {', '.join(pending)} (not a pass)", flush=True)
        return False
    print(f"arcforges-verify: PASS {t.sha} tree {t.tree} profile {t.profile} legs "
          + "; ".join(f"{describe(passed[h])} {t.legs[h].record.name}" for h in sorted(passed)), flush=True)
    return True


def command_import(repo: Repository, path: str, remote: str) -> None:
    """Accepts the pass record of a leg verified on another machine, after checking it against the commit here."""
    try:
        data = json.loads(Path(path).read_text(encoding="utf-8-sig"))
    except (OSError, ValueError) as error:
        raise VerifyError(f"cannot read the pass record {path}: {error}") from error
    if not isinstance(data, dict) or data.get("format") != RECORD_FORMAT:
        raise VerifyError(f"{path} is not a pass record of eng/verify.py ({RECORD_FORMAT})")
    sha = str(data.get("sha", ""))
    if not re.fullmatch(r"[0-9a-f]{40}", sha):
        raise VerifyError(f"{path} names no full commit id")
    if subprocess.run(["git", "cat-file", "-e", f"{sha}^{{commit}}"], capture_output=True).returncode != 0:
        raise VerifyError(f"the commit {sha} of {path} is not in this clone; fetch it first")
    t = target(repo, sha, remote)
    host = str(data.get("host", ""))
    leg = t.legs.get(host)
    if leg is None:
        raise VerifyError(f"{sha[:12]} has no {host or '(unnamed)'} leg here (its legs: {', '.join(t.legs) or 'none'})")
    expected = {"repository": repo.name, "tree": t.tree, "base": t.base, "profile": t.profile, "digest": repo.digest,
                "context": t.context, "key": leg.key, "steps": sorted(s.id for s in leg.steps)}
    differ = [name for name, value in expected.items() if data.get(name) != value]
    if not results_cover(data.get("results"), leg):
        differ.append("results (every step of the leg, each passed)")
    if not str(data.get("platform", "")).startswith(f"{HOSTS[host]}-"):
        differ.append(f"platform (a {host} record is written on {HOSTS[host]})")
    if differ:
        raise VerifyError(f"the record {path} does not match the {host} leg of {sha[:12]} here: {', '.join(differ)} "
                          "differ. Verify that leg again at this exact commit (a moved main can change the merge base)")
    data.update(origin="imported", imported_from=str(Path(path).resolve()),
                imported_at=_dt.datetime.now(_dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"))
    leg.record.write_text(json.dumps(data, indent=2), encoding="utf-8")
    print(f"arcforges-verify: IMPORTED {sha} host {host} from {data.get('machine', '?')} ({data.get('platform', '?')}, "
          f"finished {data.get('finished', '?')}, logs {data.get('logs', '?')} there) record {leg.record}", flush=True)


def command_pre_push(repo: Repository, remote: str) -> None:
    refs = [line.split() for line in sys.stdin.read().splitlines() if line.strip()]
    for local_ref, local_sha, _remote_ref, _remote_sha in refs:
        if local_sha == ZERO:
            continue
        upstream = upstream_ref(remote)
        if git("rev-parse", "--verify", "--quiet", upstream, check=False) and subprocess.run(
                ["git", "merge-base", "--is-ancestor", local_sha, upstream]).returncode == 0:
            say(f"{local_ref}: already contained in {upstream}; nothing to verify")
            continue
        verify(repo, local_sha, remote, require_all=True)


def command_install(repo: Repository) -> None:
    """Copies .githooks/* of this checkout (run it from the main checkout on main) into the clone's common hooks
    directory, which every worktree uses. A relative
    core.hooksPath would resolve per worktree and silently run no hook in a worktree whose commit lacks .githooks, so it
    is removed; the installed pre-push rejects a push from a worktree without eng/verify.py."""
    source = repo.top / ".githooks"
    if not (source / "pre-push").exists():
        raise VerifyError(f"{source / 'pre-push'} is missing")
    # core.hooksPath can be set in the shared config and, with extensions.worktreeConfig, in any worktree's own config
    # (older repository scripts did that); every one of them, even an empty value, would bypass the common hooks directory.
    # Presence is decided by git's exit code (0 = set, 1 = not set), never by the printed value.
    configs = [repo.common / "config"]
    configs += sorted((repo.common / "worktrees").glob("*/config.worktree"))
    configs += [repo.common / "config.worktree"]
    for config in (c for c in configs if c.exists()):
        found = subprocess.run(["git", "config", "--file", str(config), "--get-all", "core.hooksPath"],
                               capture_output=True, text=True, encoding="utf-8", errors="replace")
        if found.returncode == 0:
            git("config", "--file", str(config), "--unset-all", "core.hooksPath")
            say(f"removed core.hooksPath from {config} (the hooks now live in the common hooks directory)")
    # What each worktree actually reads (its includes, includeIf gitdir and global or system values) must leave it unset.
    worktrees = [Path(line[len("worktree "):]) for line in git("worktree", "list", "--porcelain", cwd=repo.top).splitlines()
                 if line.startswith("worktree ")]
    for worktree in (w for w in worktrees if w.exists()):
        effective = subprocess.run(["git", "-C", str(worktree), "config", "--get-all", "core.hooksPath"],
                                   capture_output=True, text=True, encoding="utf-8", errors="replace")
        if effective.returncode != 1:
            reason = "is still set" if effective.returncode == 0 else f"cannot be read ({effective.stderr.strip()})"
            raise VerifyError(f"core.hooksPath {reason} for the worktree {worktree} (`git -C \"{worktree}\" config "
                              "--show-origin --get-all core.hooksPath` shows where); remove it and install again")
    target = repo.common / "hooks"
    target.mkdir(exist_ok=True)
    for hook in sorted(p for p in source.iterdir() if p.is_file()):
        content, destination = normalized(hook.read_bytes()), target / hook.name
        if destination.exists() and destination.read_bytes() != content:
            say(f"replacing the existing {destination} (it differed from {hook})")
        destination.write_bytes(content)
        say(f"installed {hook.name} -> {destination}")
    say("every worktree of this clone now runs the pre-push verification (a branch-conditional includeIf that sets "
        "core.hooksPath would still bypass it; none is checked for)")


def main() -> int:
    parser = argparse.ArgumentParser(prog="eng/verify.py", description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("install")
    for name in ("run", "list"):
        command = sub.add_parser(name)
        command.add_argument("--rev", default="HEAD")
        command.add_argument("--remote", default="origin")
        if name == "run":
            command.add_argument("--force", action="store_true", help="verify this machine's leg even when it passed")
            command.add_argument("--keep-going", action="store_true", help="run every step even after a failure")
    imported = sub.add_parser("import")
    imported.add_argument("record", help="a leg's pass record from another machine (leg-<host>-<key>.json)")
    imported.add_argument("--remote", default="origin")
    hook = sub.add_parser("pre-push")
    hook.add_argument("remote")
    hook.add_argument("url", nargs="?")
    args = parser.parse_args()
    # Step logs carry arbitrary text (e.g. test-runner symbols); a console or pipe without UTF-8 must not turn printing a
    # failure into a second failure that hides it.
    for stream in (sys.stdout, sys.stderr):
        stream.reconfigure(errors="replace")
    # Git runs hooks with GIT_DIR and related variables set for the pushing worktree; left in place they would make
    # every git command (and every step) below act on that worktree instead of the verification checkouts.
    local = subprocess.run(["git", "rev-parse", "--local-env-vars"], capture_output=True, text=True)
    for name in local.stdout.split():
        os.environ.pop(name, None)
    try:
        repo = Repository()
        if args.command == "install":
            command_install(repo)
        elif args.command == "list":
            t = target(repo, args.rev, args.remote)
            print(f"{t.sha} base {t.base} profile {t.profile} ({len(t.changed)} changed paths)")
            for host, leg in t.legs.items():
                data = read_record(leg)
                state = f"passed: {describe(data)}" if data else "no pass record"
                print(f"leg {host} ({HOSTS[host]}, {len(leg.steps)} steps): {state}; {leg.record.name}")
                for step in leg.steps:
                    print(f"  {step.id:30} lane={step.lane_name:12} timeout={step.timeout}s"
                          f"{' exclusive' if step.exclusive else ''}")
        elif args.command == "run":
            verify(repo, args.rev, args.remote, args.force, args.keep_going)
        elif args.command == "import":
            command_import(repo, args.record, args.remote)
        else:
            command_pre_push(repo, args.remote)
    except VerifyError as error:
        print(f"arcforges-verify: FAIL {error}", file=sys.stderr, flush=True)
        if args.command == "pre-push":
            print("arcforges-verify: push rejected. Fix the cause and push again; never bypass or weaken the hook "
                  "(AGENTS.md, Local verification).", file=sys.stderr, flush=True)
        return 1
    except KeyboardInterrupt:
        print("arcforges-verify: FAIL interrupted", file=sys.stderr, flush=True)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
