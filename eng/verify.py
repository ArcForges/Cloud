#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Host-local verification (the same file in every ArcForges repository; the steps live in eng/verify_steps.py).

  python eng/verify.py run-and-report [--rev REV]  verify this host's leg of a pushed commit and report it to GitHub
  python eng/verify.py run [--rev REV]             verify this host's leg without reporting (a local check)
  python eng/verify.py list [--rev REV]            show the profile and the steps of each host's leg
  python eng/verify.py install                     install .githooks/* for every worktree of this clone (once)

Verification runs after a push (ArcForges-Design AD-0020): Push -> Fetch -> Local verification -> Report status ->
Required checks -> Review -> Merge. A commit is pushed to GitHub without verifying it first; each verification host
fetches that exact commit from GitHub, checks it out (a worktree of its clone, so this script is the commit's own), and
runs `python eng/verify.py run-and-report` there. The script reports the commit status `arcforges/windows` or
`arcforges/linux` on GitHub: `pending` when the leg starts, `success` only when every step of the leg passed, `failure`
when a step failed and `error` when the leg could not complete. GitHub's required status checks on `main` then refuse to
merge a pull request until every applicable host reported success for its head commit; a new push has no status, so it
needs verifying again.

Every step runs on one host, 'win' (native Windows) or 'linux' (native Linux); the steps of one host are the commit's
leg for that host. A machine runs only the leg of its own operating system, never another one through WSL, a VM or a
remote shell: on Windows in a detached verification worktree (<main checkout>/.worktree/_verify), on Linux in a
Linux-native clone (~/.cache/arcforges-verify/<repo>), both checked out at the commit and cleaned of untracked files
(ignored build output stays, so builds are incremental). That clone is shared by every clone of the repository on the
host, so one Linux leg of a repository runs on a host at a time. The commit is verified, never the working tree, and
the step table and this script are read from the commit itself. Steps run in lanes: lanes run concurrently, the steps
of a lane in order, and steps marked exclusive run alone afterwards. Any step that fails, times out or cannot run fails
the leg (fail closed). A host whose leg has no steps for the commit (the step table selects none for its profile)
reports success saying so. The step logs and a summary.json of each leg stay on the host under
<git common dir>/arcforges-verify/logs.

The status is posted to github.com with the GitHub CLI (`gh api`), authenticated by ARCFORGES_STATUS_TOKEN when it is
set (a token limited to commit statuses is enough) and otherwise by the host's own `gh` login. That token and the other
GitHub tokens of the environment (GH_TOKEN, GITHUB_TOKEN and their enterprise forms) are removed from the environment of
every step, again inside each Linux step after its login profile has run, and are never printed. The remote must be a
github.com URL (https, ssh://git@github.com/ or git@github.com:). The exit code is 0 after success, 1 when a step
failed and 2 when the leg could not complete or could not be reported. An interruption (Ctrl+C, SIGTERM, SIGHUP)
reports `error`; a process killed outright leaves `pending`, which keeps the merge blocked.

Agents reach each host through its standard MCP server (ArcForges-Design AD-0019): the Windows leg through the Windows
MCP server on the workstation, the Linux leg through the Linux MCP server on an independent Linux host. This script
knows nothing of MCP; it runs on the host and reports from there. Local WSL is never a venue, not even as a fallback.
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
import signal
import subprocess
import sys
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable

TAIL_LINES = 60
LINUX_STATE = "$HOME/.cache/arcforges-verify"
HOSTS = {"win": "Windows", "linux": "Linux"}
# The commit status context each host reports; the required status checks of `main` name exactly these.
CONTEXTS = {"win": "arcforges/windows", "linux": "arcforges/linux"}
STATUS_TOKEN = "ARCFORGES_STATUS_TOKEN"
# Credentials no step may see: the reporting token and any GitHub token of the environment.
CREDENTIALS = (STATUS_TOKEN, "GH_TOKEN", "GITHUB_TOKEN", "GH_ENTERPRISE_TOKEN", "GITHUB_ENTERPRISE_TOKEN")
# What an earlier eng/verify.py installed as the pre-push hook; `install` removes it (verification is after the push).
RETIRED_HOOK = "eng/verify.py\" pre-push"


@dataclass(frozen=True)
class Step:
    """One verification step. `cmd` is an argv list on the 'win' host and a bash command string on the 'linux' host.
    The placeholders {sha}, {base} and {range} are replaced; a step that reads history must use them (never a
    hard-coded range), so that it reads exactly the commits being verified. `profiles` names the profiles that
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


class StepsFailed(VerifyError):
    """A step of the leg failed (as opposed to the leg being unable to run)."""


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

    @property
    def name(self) -> str:
        return getattr(self.steps, "REPOSITORY", self.main.name)

    def load_steps(self, sha: str):
        """Reads the step table and this script from the commit being verified, so a commit is verified by its own
        definition. The running script must be that commit's eng/verify.py."""
        try:
            core = subprocess.run(["git", "show", f"{sha}:eng/verify.py"], cwd=self.top, capture_output=True,
                                  check=True).stdout
            table = subprocess.run(["git", "show", f"{sha}:eng/verify_steps.py"], cwd=self.top, capture_output=True,
                                   check=True).stdout
        except subprocess.CalledProcessError as error:
            raise VerifyError(f"{sha[:12]} has no committed eng/verify.py and eng/verify_steps.py") from error
        if normalized(core) != normalized(Path(__file__).read_bytes()):
            raise VerifyError(f"the running {Path(__file__)} differs from eng/verify.py in {sha[:12]}; run it from a "
                              "checkout of that commit (git worktree add --detach <dir> <commit>)")
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
    # A login shell reads the host's profile, which may export a credential again; it is unset after the profile, so no
    # Linux command of the step table (steps and tool probes) sees one.
    return ["bash", "-lc", f"unset {' '.join(CREDENTIALS)}; {command}"]


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
        if not self.keep_going:
            self.stop_all()

    def stop_all(self) -> None:
        """Starts no further step and stops every running one (a failure without --keep-going, or an interruption)."""
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
    # A stale remote-tracking branch would give an older base, so it is refreshed first.
    branch = upstream.removeprefix(f"refs/remotes/{remote}/")
    fetched = subprocess.run(["git", "fetch", "--quiet", "--no-tags", remote, f"+refs/heads/{branch}:{upstream}"],
                             capture_output=True, text=True, encoding="utf-8", errors="replace")
    if fetched.returncode != 0:
        raise VerifyError(f"cannot refresh {upstream} from {remote}: {fetched.stderr.strip()}; check the network "
                          "access to the remote and verify again")
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
class Target:
    sha: str
    tree: str
    base: str
    profile: str
    changed: list[str]
    context: dict[str, str]
    legs: dict[str, list[Step]]


def target(repo: Repository, sha: str, remote: str) -> Target:
    repo.load_steps(sha)
    base, profile, changed, steps = plan(repo, sha, remote)
    unknown = sorted({s.host for s in steps} - set(HOSTS))
    if unknown:
        raise VerifyError(f"eng/verify_steps.py names unknown hosts {', '.join(unknown)} (the hosts are {', '.join(HOSTS)})")
    tree = git("rev-parse", f"{sha}^{{tree}}")
    # CONTEXT: inputs other than the commit that every leg checks against (for example the Plan's Design main commit),
    # declared by the step table as {name: value} and kept in the leg's summary.
    context = {str(k): str(v) for k, v in getattr(repo.steps, "CONTEXT", {}).items()}
    legs = {host: [s for s in steps if s.host == host] for host in HOSTS if any(s.host == host for s in steps)}
    return Target(sha, tree, base, profile, changed, context, legs)


def log_digest(path: Path) -> str:
    try:
        return hashlib.sha256(path.read_bytes()).hexdigest()
    except OSError:
        return ""


def run_leg(repo: Repository, t: Target, host: str, keep_going: bool) -> dict:
    """Runs this host's leg of the commit and returns its summary; raises when any step did not pass."""
    steps = t.legs[host]
    tools = fingerprint(repo, host)
    stamp = _dt.datetime.now().strftime("%Y%m%d-%H%M%S")
    logs = repo.state / "logs" / f"{stamp}-{t.sha[:12]}-{host}"
    logs.mkdir(parents=True, exist_ok=True)
    say(f"verifying the {host} leg of {t.sha[:12]} (base {t.base[:12]}, {len(t.changed)} changed paths), profile "
        f"'{t.profile}', {len(steps)} steps; logs in {logs}")
    # A shallow clone lacks the history that steps reading {base}..{sha} need, and a clone fetched from it is left
    # incomplete without an error, so it is refused instead of verified partially.
    if git("rev-parse", "--is-shallow-repository", check=False) == "true":
        raise VerifyError("this clone is shallow: run `git fetch --unshallow` (or clone it in full) and verify again")
    started = time.monotonic()
    with Lock(repo.state / "lock"), HostLock(repo) if host == "linux" else contextlib.nullcontext():
        workdir = prepare_windows(repo, t.sha) if host == "win" else prepare_linux(repo, t.sha, t.base)
        runner = Runner(repo, logs, t.sha, t.base, workdir, keep_going)
        try:
            ok = runner.execute(steps)
        except BaseException:
            runner.stop_all()  # an interruption leaves no step running
            raise
    seconds = time.monotonic() - started
    results = [{"step": o.step.id, "ok": o.ok, "seconds": round(o.seconds, 1), "reason": o.reason,
                "log_sha256": log_digest(o.log)} for o in runner.outcomes]
    # Every step of the leg must have run and passed; a step that never ran is a failure, not a skip.
    ok = ok and sorted(r["step"] for r in results) == sorted(s.id for s in steps) and all(r["ok"] for r in results)
    summary = {"repository": repo.name, "sha": t.sha, "tree": t.tree, "base": t.base, "profile": t.profile,
               "host": host, "steps": sorted(s.id for s in steps), "context": t.context, "tools": tools,
               "machine": platform.node(), "platform": platform.platform(), "ok": ok,
               "finished": _dt.datetime.now(_dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
               "seconds": round(seconds), "logs": str(logs), "results": results}
    (logs / "summary.json").write_text(json.dumps(summary, indent=2), encoding="utf-8")
    if not ok:
        failed = [o for o in runner.outcomes if not o.ok]
        first = failed[0] if failed else None
        if first is not None and first.log.exists():
            lines = first.log.read_text(encoding="utf-8", errors="replace").splitlines()[-TAIL_LINES:]
            print("\n".join(["", f"---- last {len(lines)} lines of {first.log} ----", *lines, "----"]), flush=True)
        ran = {o.step.id for o in runner.outcomes}
        raise StepsFailed(f"the {host} leg failed: " + "; ".join(
            [f"{o.step.id} ({o.reason})" for o in failed] + [f"{s.id} (not run)" for s in steps if s.id not in ran]))
    print(f"arcforges-verify: LEG PASS {t.sha} host {host} on {summary['machine']} tree {t.tree} profile {t.profile} "
          f"{len(steps)} steps {seconds:.0f}s logs {logs}", flush=True)
    return summary


# ------------------------------------------------------------------------------------------------------------ reporting

def github_repository(remote: str) -> str:
    """owner/name of the GitHub repository behind the remote, from its URL (https, ssh or scp-like)."""
    # The configured URL, not `git remote get-url`, which applies url.<base>.insteadOf rewrites.
    url = git("config", "--get", f"remote.{remote}.url")
    match = re.fullmatch(r"(?:https://(?:[^@/]+@)?github\.com/|ssh://git@github\.com/|git@github\.com:)"
                         r"([A-Za-z0-9_.-]+)/([A-Za-z0-9_.-]+?)(?:\.git)?/?", url)
    if not match or {match.group(1), match.group(2)} & {".", ".."}:
        shown = re.sub(r"//[^@/]+@", "//<credentials>@", url)  # never print a credential embedded in the URL
        raise VerifyError(f"the remote {remote} ({shown}) is not a github.com repository, so there is nowhere to report "
                          "to (an SSH host alias is not recognised; use https://github.com/<owner>/<repo>.git)")
    return f"{match.group(1)}/{match.group(2)}"


class Reporter:
    """Posts this host's commit status for one commit through `gh api` (repos/{owner}/{repo}/statuses/{sha})."""

    def __init__(self, slug: str, sha: str, host: str, credentials: dict[str, str]) -> None:
        self.slug, self.sha, self.context = slug, sha, CONTEXTS[host]
        # gh gets back the GitHub tokens taken from the environment; the reporting token, when set, wins.
        self.env = dict(os.environ, **{k: v for k, v in credentials.items() if k != STATUS_TOKEN})
        if credentials.get(STATUS_TOKEN):
            self.env["GH_TOKEN"] = credentials[STATUS_TOKEN]

    def post(self, state: str, description: str) -> None:
        description = description if len(description) <= 140 else description[:137] + "..."
        argv = ["gh", "api", "--hostname", "github.com", "--method", "POST", f"repos/{self.slug}/statuses/{self.sha}",
                "--silent",
                "-f", f"state={state}", "-f", f"context={self.context}", "-f", f"description={description}"]
        error = ""
        for attempt in range(3):
            if attempt:
                time.sleep(5 * attempt)
            try:
                result = subprocess.run(argv, env=self.env, capture_output=True, text=True, encoding="utf-8",
                                        errors="replace", timeout=60, stdin=subprocess.DEVNULL)
            except FileNotFoundError as missing:
                raise VerifyError("the GitHub CLI (gh) was not found; the host reports its status with `gh api`") from missing
            except subprocess.TimeoutExpired:
                error = "gh api timed out after 60s"
                continue
            if result.returncode == 0:
                say(f"reported {self.context} {state} for {self.sha[:12]} on {self.slug}: {description}")
                return
            error = (result.stderr or result.stdout).strip()[-500:]
            if "HTTP 4" in error:  # not found, unprocessable, forbidden: a retry gives the same answer
                break
        raise VerifyError(f"cannot report {self.context} {state} for {self.sha[:12]} on {self.slug}: {error}. Is the "
                          "commit pushed to GitHub, and may this host's credentials write commit statuses?")


def verify_here(repo: Repository, rev: str, remote: str, keep_going: bool, report: bool,
                credentials: dict[str, str] | None = None) -> None:
    """Runs this host's leg of the commit; with report, posts its status around the run. Raises unless it passed."""
    sha = git("rev-parse", "--verify", f"{rev}^{{commit}}")
    host = this_host()
    reporter = Reporter(github_repository(remote), sha, host, credentials or {}) if report else None
    if reporter:
        reporter.post("pending", f"verifying on {platform.node()}")
    try:
        t = target(repo, sha, remote)
        if host not in t.legs:
            note = f"no {HOSTS[host]} steps apply to {sha[:12]} (profile '{t.profile}')"
            say(note)
            if reporter:
                reporter.post("success", note)
            print(f"arcforges-verify: PASS {sha} host {host}: {note}", flush=True)
            return
        summary = run_leg(repo, t, host, keep_going)
    except StepsFailed as error:
        if reporter:
            try:
                reporter.post("failure", f"{platform.node()}: {error}")
            except VerifyError as unreported:  # the status stays pending, which still blocks the merge
                raise VerifyError(f"{error}; {unreported}") from error
        raise
    except BaseException as error:
        if reporter:
            reason = str(error) if isinstance(error, VerifyError) else type(error).__name__
            with contextlib.suppress(VerifyError):
                reporter.post("error", f"{platform.node()}: not completed: {reason}")
        raise
    if reporter:
        reporter.post("success", f"{len(summary['steps'])} steps passed in {summary['seconds']}s on {summary['machine']} "
                                 f"(profile {summary['profile']})")
    print(f"arcforges-verify: PASS {sha} host {host} profile {t.profile}", flush=True)


def command_install(repo: Repository) -> None:
    """Copies .githooks/* of this checkout (run it from the main checkout on main) into the clone's common hooks
    directory, which every worktree uses, makes them executable (git ignores a hook that is not), and removes the
    pre-push hook an earlier eng/verify.py installed. A relative core.hooksPath would resolve per worktree and silently
    run no hook in a worktree whose commit lacks .githooks, so it is removed."""
    source = repo.top / ".githooks"
    hooks = sorted(p for p in source.iterdir() if p.is_file()) if source.is_dir() else []
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
    retired = target / "pre-push"
    if not (source / "pre-push").exists() and retired.is_file() and \
            RETIRED_HOOK in retired.read_text(encoding="utf-8", errors="replace"):
        retired.unlink()
        say(f"removed the retired pre-push verification hook {retired} (verification now runs after the push)")
    for hook in hooks:
        content, destination = normalized(hook.read_bytes()), target / hook.name
        if destination.exists() and destination.read_bytes() != content:
            say(f"replacing the existing {destination} (it differed from {hook})")
        destination.write_bytes(content)
        # Git skips a hook that is not executable with only a hint. write_bytes creates the file without the
        # executable bit (and keeps the mode of an existing one); Windows has no such bit.
        if os.name != "nt":
            destination.chmod(destination.stat().st_mode | 0o755)
            if not os.access(destination, os.X_OK):
                raise VerifyError(f"{destination} is still not executable after install, so git would skip it; make "
                                  "the hooks directory executable (e.g. not on a noexec mount) and install again")
        say(f"installed {hook.name} -> {destination}")
    if not hooks:
        say(f"{source} holds no hooks to install")


def main() -> int:
    parser = argparse.ArgumentParser(prog="eng/verify.py", description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("install")
    for name in ("run", "run-and-report", "list"):
        command = sub.add_parser(name)
        command.add_argument("--rev", default="HEAD")
        command.add_argument("--remote", default="origin")
        if name != "list":
            command.add_argument("--keep-going", action="store_true", help="run every step even after a failure")
    # A pre-push hook installed by an earlier eng/verify.py still calls this; pushing no longer waits for verification.
    retired = sub.add_parser("pre-push")
    retired.add_argument("remote")
    retired.add_argument("url", nargs="?")
    args = parser.parse_args()
    # No credential reaches a step (whose output is logged) or a child process other than gh.
    credentials = {name: os.environ.pop(name) for name in CREDENTIALS if name in os.environ}
    # A terminated or hung-up run reports `error` like Ctrl+C, instead of leaving `pending` behind.
    for name in ("SIGTERM", "SIGHUP"):
        if hasattr(signal, name):
            signal.signal(getattr(signal, name), interrupted)
    # Step logs carry arbitrary text (e.g. test-runner symbols); a console or pipe without UTF-8 must not turn printing a
    # failure into a second failure that hides it.
    for stream in (sys.stdout, sys.stderr):
        stream.reconfigure(errors="replace")
    # Git runs hooks with GIT_DIR and related variables set for the running worktree; left in place they would make
    # every git command (and every step) below act on that worktree instead of the verification checkouts.
    local = subprocess.run(["git", "rev-parse", "--local-env-vars"], capture_output=True, text=True)
    for name in local.stdout.split():
        os.environ.pop(name, None)
    if args.command == "pre-push":
        sys.stdin.read()
        print("arcforges-verify: verification runs after the push (`python eng/verify.py run-and-report` on each host); "
              "run `python eng/verify.py install` to remove this retired pre-push hook", file=sys.stderr, flush=True)
        return 0
    try:
        repo = Repository()
        if args.command == "install":
            command_install(repo)
        elif args.command == "list":
            sha = git("rev-parse", "--verify", f"{args.rev}^{{commit}}")
            t = target(repo, sha, args.remote)
            print(f"{t.sha} base {t.base} profile {t.profile} ({len(t.changed)} changed paths)")
            for host in HOSTS:
                steps = t.legs.get(host, [])
                print(f"leg {host} ({HOSTS[host]}, status {CONTEXTS[host]}): {len(steps)} steps")
                for step in steps:
                    print(f"  {step.id:30} lane={step.lane_name:12} timeout={step.timeout}s"
                          f"{' exclusive' if step.exclusive else ''}")
        else:
            verify_here(repo, args.rev, args.remote, args.keep_going, args.command == "run-and-report", credentials)
    except VerifyError as error:
        print(f"arcforges-verify: FAIL {error}", file=sys.stderr, flush=True)
        return 1 if isinstance(error, StepsFailed) else 2
    except KeyboardInterrupt:
        print("arcforges-verify: FAIL interrupted", file=sys.stderr, flush=True)
        return 2
    except Exception as error:  # noqa: BLE001 - a broken step table must still end as a reported, non-zero error
        print(f"arcforges-verify: FAIL {type(error).__name__}: {error}", file=sys.stderr, flush=True)
        return 2
    return 0


def interrupted(signum: int, _frame: object) -> None:
    raise KeyboardInterrupt(f"signal {signum}")


if __name__ == "__main__":
    sys.exit(main())
