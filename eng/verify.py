#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Local pre-push verification (the same file in every ArcForges repository; the steps live in eng/verify_steps.py).

  python eng/verify.py install                    install .githooks/* for every worktree of this clone (once)
  python eng/verify.py run [--rev REV] [--force]  verify a commit now (default HEAD); a pass is reused by the push
  python eng/verify.py list [--rev REV]           show the profile and steps a commit would run
  python eng/verify.py pre-push REMOTE [URL]      the hook entry point (refs on stdin)

The pushed commit is verified, never the working tree: a detached verification worktree on Windows
(<main checkout>/.worktree/_verify) and a Linux-native clone in WSL (~/.cache/arcforges-verify/<repo>), both checked
out at the commit and cleaned of untracked files (ignored build output stays, so builds are incremental). The step table
and this script are read from the commit itself. Steps run in lanes: lanes run concurrently, the steps of a lane in
order, and steps marked exclusive run alone afterwards. Any step that fails, times out or cannot run rejects the push
(fail closed). A pass is recorded under the Git common directory, keyed by the commit's tree, these scripts and the tool
versions; an identical key is not verified again.
"""
from __future__ import annotations

import argparse
import ctypes
import datetime as _dt
import hashlib
import json
import os
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
WSL_STATE = "$HOME/.cache/arcforges-verify"


@dataclass(frozen=True)
class Step:
    """One verification step. `cmd` is an argv list on the 'win' host and a bash command string on the 'wsl' host.
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

def wsl_distribution(repo: Repository) -> str:
    return getattr(repo.steps, "WSL_DISTRIBUTION", "Debian")


def to_wsl_path(path: Path) -> str:
    resolved = str(path.resolve())
    if len(resolved) < 2 or resolved[1] != ":":
        raise VerifyError(f"cannot map {resolved} into WSL")
    return "/mnt/" + resolved[0].lower() + resolved[2:].replace("\\", "/")


def wsl_argv(repo: Repository, command: str, cwd: str | None = None) -> list[str]:
    argv = ["wsl.exe", "-d", wsl_distribution(repo)]
    if cwd:
        argv += ["--cd", cwd]
    return argv + ["--exec", "bash", "-lc", command]


def wsl_run(repo: Repository, command: str, timeout: int = 600) -> str:
    try:
        result = subprocess.run(wsl_argv(repo, command), capture_output=True, text=True, encoding="utf-8",
                                errors="replace", timeout=timeout, stdin=subprocess.DEVNULL)
    except FileNotFoundError as error:
        raise VerifyError("wsl.exe was not found; WSL Debian is required for the Linux steps") from error
    except subprocess.TimeoutExpired as error:
        raise VerifyError(f"a WSL command timed out after {timeout}s: {command}") from error
    if result.returncode != 0:
        raise VerifyError(f"WSL ({wsl_distribution(repo)}) command failed with exit code {result.returncode}: "
                          f"{command}\n{(result.stdout + result.stderr).strip()[-2000:]}")
    return result.stdout.strip()


def fingerprint(repo: Repository, hosts: set[str]) -> dict[str, str]:
    """Tool versions that are part of the pass key (FINGERPRINT in the step table: {host: {name: probe}})."""
    probes = getattr(repo.steps, "FINGERPRINT", {})
    values: dict[str, str] = {"python": sys.version.split()[0]}
    for host in sorted(hosts):
        for name, probe in probes.get(host, {}).items():
            if host == "wsl":
                values[f"wsl:{name}"] = wsl_run(repo, probe, timeout=300)
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


def prepare_wsl(repo: Repository, sha: str, base: str) -> str:
    source = to_wsl_path(repo.common)
    pack = "git -c uploadpack.allowAnySHA1InWant=true upload-pack"
    script = (
        "set -euo pipefail; "
        # Sessions left by an aborted earlier run (Runner.argv) stop before the sources change under them.
        f"for f in {WSL_STATE}/pids/{repo.name}.*.pid; do [ -e \"$f\" ] || continue; g=\"$(cat \"$f\")\"; "
        "if grep -qa arcforges-verify /proc/$g/cmdline 2>/dev/null; then pkill -KILL -s $g || true; fi; "
        "rm -f \"$f\"; done; "
        f"d={WSL_STATE}/{repo.name}; mkdir -p \"$d\"; cd \"$d\"; [ -d .git ] || git init -q; "
        f"git fetch -q --no-tags --upload-pack={shlex.quote(pack)} {shlex.quote(source)} {sha} {base}; "
        f"git checkout -q --force --detach {sha}; git clean -ffdq; test \"$(git rev-parse HEAD)\" = {sha}; pwd"
    )
    return wsl_run(repo, script, timeout=1800).splitlines()[-1]


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
    def __init__(self, repo: Repository, logs: Path, sha: str, base: str, win_dir: Path | None, wsl_dir: str | None,
                 keep_going: bool):
        self.repo, self.logs, self.sha, self.base = repo, logs, sha, base
        self.win_dir, self.wsl_dir, self.keep_going = win_dir, wsl_dir, keep_going
        self.stop = threading.Event()
        self.live: dict[subprocess.Popen, Step] = {}
        self.lock = threading.Lock()
        self.outcomes: list[Outcome] = []
        self.aborted: set[str] = set()

    def expand(self, text: str) -> str:
        return text.replace("{sha}", self.sha).replace("{base}", self.base).replace("{range}", f"{self.base}..{self.sha}")

    def pidfile(self, step: Step) -> str:
        return f"{WSL_STATE}/pids/{self.repo.name}.{step.id}.pid"

    def argv(self, step: Step) -> list[str]:
        if step.host == "win":
            if not isinstance(step.cmd, list):
                raise VerifyError(f"step {step.id}: a win step needs an argv list")
            return [self.expand(part) for part in step.cmd]
        if step.host != "wsl" or not isinstance(step.cmd, str):
            raise VerifyError(f"step {step.id}: a wsl step needs a bash command string")
        exports = "".join(f"export {key}={shlex.quote(value)}; " for key, value in step.env.items())
        inner = f"export ARCFORGES_VERIFY=1; {exports}{self.expand(step.cmd)}"
        # The step runs in its own session, recorded until it ends so that an abort can stop all of it (ending wsl.exe
        # does not stop the Linux processes); timeout(1) signals its process group when the step runs too long.
        guarded = (f"echo $$ > {self.pidfile(step)}; timeout --kill-after=30 {step.timeout} bash -c {shlex.quote(inner)}; "
                   f"rc=$?; rm -f {self.pidfile(step)}; exit $rc")
        command = f"mkdir -p {WSL_STATE}/pids; exec setsid --wait bash -c {shlex.quote(guarded)}"
        return wsl_argv(self.repo, command, cwd=self.wsl_dir)

    def stop_wsl(self, step: Step) -> None:
        """Stops a WSL step's session (setsid): TERM, up to 15 s for it to end, then KILL."""
        script = (f"g=\"$(cat {self.pidfile(step)} 2>/dev/null)\"; [ -n \"$g\" ] || exit 0; "
                  "grep -qa arcforges-verify /proc/$g/cmdline 2>/dev/null || exit 0; "
                  "pkill -TERM -s $g || exit 0; "
                  "for i in $(seq 30); do pgrep -s $g >/dev/null || exit 0; sleep 0.5; done; "
                  "pkill -KILL -s $g; true")
        try:
            wsl_run(self.repo, script, timeout=120)
        except VerifyError as error:
            say(f"could not stop the WSL step {step.id}: {error}")

    def abort(self, process: subprocess.Popen, step: Step) -> None:
        with self.lock:
            self.aborted.add(step.id)
        if step.host == "wsl":
            self.stop_wsl(step)
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
                process = subprocess.Popen(argv, cwd=self.win_dir if step.host == "win" else None, stdout=sink,
                                           stderr=subprocess.STDOUT, stdin=subprocess.DEVNULL, env=env)
                with self.lock:
                    self.live[process] = step
                    stopped = self.stop.is_set()
                if stopped:
                    self.abort(process, step)
                try:
                    code = process.wait(timeout=step.timeout + (90 if step.host == "wsl" else 0))
                    if code == 124 and step.host == "wsl":
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


def verify(repo: Repository, rev: str, remote: str, force: bool = False, keep_going: bool = False) -> None:
    sha = git("rev-parse", "--verify", f"{rev}^{{commit}}")
    repo.load_steps(sha)
    base, profile, changed, steps = plan(repo, sha, remote)
    tree = git("rev-parse", f"{sha}^{{tree}}")
    hosts = {s.host for s in steps}
    if os.name != "nt" and "win" in hosts:
        raise VerifyError("verification needs the Windows host; push from Windows, not from WSL")
    tools = fingerprint(repo, hosts)
    # The key is the source state the steps actually see: the tree, plus the exact commits when a step reads history
    # ({sha}, {base}, {range}, e.g. a secret scan of the pushed commits), and the selected step set.
    history = any(marker in (s.cmd if isinstance(s.cmd, str) else " ".join(s.cmd))
                  for s in steps for marker in ("{sha}", "{base}", "{range}"))
    source = [tree, base, sha] if history else [tree]
    key = hashlib.sha256(json.dumps([source, profile, sorted(s.id for s in steps), repo.digest, tools],
                                    sort_keys=True).encode()).hexdigest()
    record = repo.state / f"pass-{key[:32]}.json"
    if record.exists() and not force:
        say(f"{'commit' if history else 'tree'} {(sha if history else tree)[:12]} already passed profile '{profile}' "
            f"with these steps, scripts and tools ({record.name})")
        print(f"arcforges-verify: PASS {sha} tree {tree} profile {profile} reused {record}", flush=True)
        return
    stamp = _dt.datetime.now().strftime("%Y%m%d-%H%M%S")
    logs = repo.state / "logs" / f"{stamp}-{sha[:12]}"
    logs.mkdir(parents=True, exist_ok=True)
    say(f"verifying {sha[:12]} (base {base[:12]}, {len(changed)} changed paths), profile '{profile}', "
        f"{len(steps)} steps; logs in {logs}")
    started = time.monotonic()
    with Lock(repo.state / "lock"):
        win_dir = prepare_windows(repo, sha) if "win" in hosts else None
        wsl_dir = prepare_wsl(repo, sha, base) if "wsl" in hosts else None
        runner = Runner(repo, logs, sha, base, win_dir, wsl_dir, keep_going)
        ok = runner.execute(steps)
    seconds = time.monotonic() - started
    summary = [{"step": o.step.id, "host": o.step.host, "ok": o.ok, "seconds": round(o.seconds, 1), "reason": o.reason}
               for o in runner.outcomes]
    (logs / "summary.json").write_text(json.dumps({"sha": sha, "tree": tree, "base": base, "profile": profile,
                                                    "tools": tools, "ok": ok, "seconds": round(seconds),
                                                    "steps": summary}, indent=2), encoding="utf-8")
    if not ok:
        failed = [o for o in runner.outcomes if not o.ok]
        first = failed[0] if failed else None
        if first is not None and first.log.exists():
            lines = first.log.read_text(encoding="utf-8", errors="replace").splitlines()[-TAIL_LINES:]
            print("\n".join(["", f"---- last {len(lines)} lines of {first.log} ----", *lines, "----"]), flush=True)
        ran = {o.step.id for o in runner.outcomes}
        raise VerifyError("verification failed: " + "; ".join(
            [f"{o.step.id} ({o.reason})" for o in failed] + [f"{s.id} (not run)" for s in steps if s.id not in ran]))
    record.write_text(json.dumps({"sha": sha, "tree": tree, "profile": profile, "tools": tools,
                                  "seconds": round(seconds), "logs": str(logs), "steps": summary}, indent=2),
                      encoding="utf-8")
    print(f"arcforges-verify: PASS {sha} tree {tree} profile {profile} {len(steps)} steps {seconds:.0f}s "
          f"record {record}", flush=True)


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
        verify(repo, local_sha, remote)


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
            command.add_argument("--force", action="store_true", help="verify even when a pass record exists")
            command.add_argument("--keep-going", action="store_true", help="run every step even after a failure")
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
            sha = git("rev-parse", "--verify", f"{args.rev}^{{commit}}")
            repo.load_steps(sha)
            base, profile, changed, steps = plan(repo, sha, args.remote)
            print(f"{sha} base {base} profile {profile} ({len(changed)} changed paths)")
            for step in steps:
                print(f"  {step.id:30} {step.host:4} lane={step.lane_name:8} timeout={step.timeout}s"
                      f"{' exclusive' if step.exclusive else ''}")
        elif args.command == "run":
            verify(repo, args.rev, args.remote, args.force, args.keep_going)
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
