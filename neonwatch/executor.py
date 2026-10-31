"""The read-only boundary: runs catalog entries and refuses everything else.

This module runs as root. It takes a `ProbeSpec`, admits it only if it is, by value, an element
of `probes.CATALOG` as imported (frozen here at import; no caller can supply another) or the
expansion of one of its templates for a device that exists, and then runs the *catalog's* copy,
never the caller's object. What it can do per kind:

- COMMAND: exec the argv as given. No shell, an empty environment, stdin `/dev/null`, cwd `/`,
  a new session, and only if the binary and every directory above it are root-owned and not
  group- or world-writable (a symlink must resolve into a system bin directory). A spec marked
  `unprivileged` runs as uid and gid `NOBODY` with no supplementary groups; if the drop fails the
  command is not run at all, never run as root instead. stdout is read up
  to `max_bytes`, stderr up to `STDERR_CAP`; past the stdout cap, or at the timeout, the child's
  whole process group is killed. CPU time is the child's own rusage from `os.wait4`.
- FILE: `os.open` read-only, refusing a symlink (`O_NOFOLLOW`) and anything but a regular file.
- GLOB: every match of the spec's pattern, read the same way, framed by `probes.frame_files`,
  each match capped at `max_bytes // 4` and all of them at `max_bytes`.
  The pattern's literal directory prefix is resolved first (so `/var/run/...` reads `/run/...`),
  and a match whose opened file lies outside the resolved pattern is skipped and named in
  `warnings`. The other matches are still returned, so one user's symlink cannot blind the probe.
- LISTDIR: `os.listdir`, and for each name that is a symbolic link its target by `os.readlink`,
  which reads the link itself and never follows it; framed by `probes.frame_listing`.
- DOCKER: HTTP `GET` of the spec's path over the Docker unix socket. The connection class refuses
  every other method, so no path through this module can send one.

Every kind but COMMAND runs on a daemon thread, and `execute` returns a timeout error at
`timeout_s` even if the read never returns (a sysfs read on a sick device can block in the
kernel). Such a thread is abandoned, not killed: it stays blocked. A command child that outlives
SIGKILL is likewise left to a background thread blocked in `os.wait4`. `outstanding()` counts both
per probe id until the thread returns or the child is reaped, so the collector can see stuck work
and must not start the same probe again on top of it.

The environment is `{}`, not `{"LANG": "C"}`: with no locale variable glibc runs in the C locale,
which is what `LANG=C` selects, and every catalog command produced the same bytes under both
when this was checked. The empty environment is the one with fewer inputs.

The one signal this module sends to more than its own child is `os.killpg` in
`_kill_own_group`, the single exception `tools/gates.py` allows (decided 2026-09-30). It is sent
only on a timeout or an overflow, only while the child is unreaped (so its pid, which is its
group id, cannot have been reused), and only after checking that the pid still leads its group.
"""

from __future__ import annotations

import dataclasses
import errno
import fnmatch
import glob
import http.client
import math
import os
import re
import resource
import selectors
import signal
import socket
import stat
import subprocess
import threading
import time
from collections.abc import Callable, Collection, Mapping

from neonwatch.probes import CATALOG, NOBODY, Kind, ProbeSpec, expand, frame_files, frame_listing

#: Bytes of a command's stderr kept; the rest is read and discarded so the child cannot block.
STDERR_CAP = 4096
#: Seconds to wait for a SIGKILLed child to exit before giving up on reaping it.
KILL_GRACE_S = 2.0
#: The longest pause between checks for a child's exit once its pipes have closed.
_POLL_MAX_S = 0.02
DOCKER_SOCKET = "/var/run/docker.sock"
#: Where a symlinked binary may resolve to.
_BIN_DIRS = frozenset({"/usr/bin", "/usr/sbin", "/bin", "/sbin"})
#: Everything `execute` will run, frozen at import. Tests replace this attribute; callers cannot.
_ADMITTED: frozenset[ProbeSpec] = frozenset(CATALOG)

_CHUNK = 65536
#: Matches one GLOB reads at most. A user can create any number of files where a glob looks
#: (`/home/*/.ssh/authorized_keys*`), each an open as root and a record in the observation:
#: 20000 empty files took 3 s and made an event over five times the publish limit.
MAX_MATCHES = 256
#: What makes a path component a glob wildcard (the catalog's own definition).
_WILDCARD = re.compile(r"[*?\[]")
#: Exit codes: a failed read; a command refused before exec; one that could not be exec'd.
_READ_FAILED, _REFUSED, _EXEC_FAILED, _NOT_REAPED = 1, 126, 127, -1


class NotInCatalog(Exception):
    """The spec is not a catalog entry or an admitted expansion of one."""


@dataclasses.dataclass(frozen=True, slots=True)
class RawResult:
    """What one probe run produced.

    `exit_code` is the command's status (negative: killed by that signal; 126: binary refused
    before exec; 127: could not exec; -1: not reaped), or for the other kinds 0 on success, 1 on
    a failed or timed-out read, or a Docker HTTP status outside 2xx. `error` says why whenever
    something went wrong; a truncation alone is not an error, `truncated` says it. `warnings`
    names GLOB matches skipped while the rest were read, which is not a failure.
    """

    stdout: bytes
    exit_code: int
    cpu_ms: int
    truncated: bool
    stderr: bytes = b""
    error: str = ""
    warnings: tuple[str, ...] = ()


def execute(spec: ProbeSpec, timeout_s: float, max_bytes: int, *,
            devices: Collection[str] | None = None) -> RawResult:
    """Run one admitted spec. Synchronous and blocking; safe to call from several threads.

    `devices` names the block devices that exist, for admitting a template's expansion.
    Raises `NotInCatalog` for anything not admitted, and `ValueError` for a non-positive
    `timeout_s` or `max_bytes`. Every failure after admission is reported in the result.
    """
    admitted = _admit(spec, devices)
    if not timeout_s > 0 or not math.isfinite(timeout_s) or max_bytes < 1:
        raise ValueError(f"timeout_s must be positive and max_bytes at least 1, "
                         f"not {timeout_s!r} and {max_bytes!r}")
    if admitted.kind is Kind.COMMAND:
        return _command(admitted, timeout_s, max_bytes)
    return _bounded(admitted, timeout_s, max_bytes)


def outstanding() -> Mapping[str, int]:
    """Probe id -> runs still blocked past their deadline: abandoned reads and unreaped children.

    A copy: changing it changes nothing here. An id is absent once all its stuck runs have
    returned or been reaped.
    """
    with _LOCK:
        return dict(_OUTSTANDING)


def _admit(spec: object, devices: Collection[str] | None) -> ProbeSpec:
    """The admission set's own copy of `spec`, compared by value; refuses anything else."""
    if type(spec) is not ProbeSpec:
        raise NotInCatalog(f"not a ProbeSpec: {type(spec).__name__}")
    admitted = _ADMITTED
    for entry in admitted:
        if not entry.devices and entry == spec:
            return entry
    existing = frozenset(devices) if devices is not None else frozenset()
    for template in admitted:
        name = spec.id.removeprefix(template.id + ".")
        if not template.devices or name == spec.id or name not in existing:
            continue
        try:
            (expanded,) = expand(template, [name])
        except ValueError:
            continue
        if expanded == spec:
            return expanded
    raise NotInCatalog(f"{spec.id!r} is not in the catalog, or not as given")


# --- COMMAND -------------------------------------------------------------------------------


def _command(spec: ProbeSpec, timeout_s: float, max_bytes: int) -> RawResult:
    """The module's one process-creation call site."""
    deadline = time.monotonic() + timeout_s
    try:
        problem = _binary_problem(spec.argv[0])
    except OSError as failed:
        return RawResult(b"", _EXEC_FAILED, 0, False,
                         error=f"cannot exec {spec.argv[0]}: {failed.strerror or failed}")
    if problem:
        return RawResult(b"", _REFUSED, 0, False, error=problem)
    # None leaves the child as root; a uid drops it before exec, and a failed drop raises here.
    drop = NOBODY if spec.unprivileged else None
    try:
        proc = subprocess.Popen(spec.argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE, env={}, cwd="/", close_fds=True,
                                start_new_session=True, user=drop, group=drop,
                                extra_groups=None if drop is None else [])
    except OSError as failed:
        return RawResult(b"", _EXEC_FAILED, 0, False,
                         error=f"cannot exec {spec.argv[0]}: {failed.strerror or failed}")
    try:
        out, err, truncated, timed_out = _collect(proc, deadline, max_bytes)
        reaped = None if truncated or timed_out else _reap_by(proc.pid, deadline)
        timed_out = timed_out or (reaped is None and not truncated)
        code, usage, problem = _finish(proc, reaped, spec.id)
    finally:
        proc.stdout.close()  # type: ignore[union-attr]
        proc.stderr.close()  # type: ignore[union-attr]
    errors = [f"timed out after {timeout_s}s; killed"] if timed_out else []
    errors += [problem] if problem else []
    cpu_ms = round((usage.ru_utime + usage.ru_stime) * 1000) if usage else 0
    return RawResult(bytes(out), code, cpu_ms, truncated, bytes(err), "; ".join(errors))


def _binary_problem(path: str) -> str:
    """Why `path` may not be exec'd as root, or `""`. Raises OSError if it cannot be examined.

    The final component is examined without following it: a symlink must resolve into one of
    `_BIN_DIRS`. The file it names, and every directory above both the given and the resolved
    path, must be owned by root and not group- or world-writable, so that only root could have
    put it there or could swap it between this check and the exec.
    """
    real = os.path.realpath(path)
    if stat.S_ISLNK(os.lstat(path).st_mode) and os.path.dirname(real) not in _BIN_DIRS:
        return f"refused {path}: a symlink that resolves outside {sorted(_BIN_DIRS)}, to {real}"
    target = os.stat(real)
    if not stat.S_ISREG(target.st_mode):
        return f"refused {path}: not a regular file"
    checks = [(real, target)]
    for start in (path, real):
        directory = os.path.dirname(start)
        while True:
            checks.append((directory, os.stat(directory)))
            if directory == "/":
                break
            directory = os.path.dirname(directory)
    for checked, status in checks:
        if problem := _owner_problem(checked, status):
            return f"refused {path}: {problem}"
    return ""


def _owner_problem(path: str, status: os.stat_result) -> str:
    if status.st_uid != 0:
        return f"{path} is owned by uid {status.st_uid}, not root"
    if status.st_mode & (stat.S_IWGRP | stat.S_IWOTH):
        return f"{path} is group- or world-writable ({stat.filemode(status.st_mode)})"
    return ""


def _collect(proc: subprocess.Popen, deadline: float,
             max_bytes: int) -> tuple[bytearray, bytearray, bool, bool]:
    """Read both pipes until they close, stdout passes the cap, or the deadline.

    Returns (stdout, stderr, truncated, timed_out).
    """
    out_fd, err_fd = proc.stdout.fileno(), proc.stderr.fileno()  # type: ignore[union-attr]
    out, err = bytearray(), bytearray()
    with selectors.DefaultSelector() as selector:
        for fd in (out_fd, err_fd):
            os.set_blocking(fd, False)
            selector.register(fd, selectors.EVENT_READ)
        while selector.get_map():
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                return out, err, False, True
            for key, _ in selector.select(remaining):
                want = max_bytes + 1 - len(out) if key.fd == out_fd else _CHUNK
                chunk = os.read(key.fd, min(_CHUNK, want))
                if not chunk:
                    selector.unregister(key.fd)
                elif key.fd == out_fd:
                    out += chunk
                    if len(out) > max_bytes:
                        del out[max_bytes:]
                        return out, err, True, False
                else:
                    err += chunk[: max(0, STDERR_CAP - len(err))]
    return out, err, False, False


_Reaped = tuple[int, resource.struct_rusage]


def _reap_by(pid: int, deadline: float) -> _Reaped | None:
    """Reap `pid` with `os.wait4` if it exits by `deadline`: (wait status, its own rusage).

    Polls with WNOHANG, because this Python has no `os.pidfd_open` to wait on with a timeout.
    `os.wait4` gives this child's own CPU time; RUSAGE_CHILDREN would mix in any other child
    reaped meanwhile by a concurrent call.
    """
    pause = 0.0005
    while True:
        reaped, status, usage = os.wait4(pid, os.WNOHANG)
        if reaped:
            return status, usage
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            return None
        time.sleep(min(pause, remaining))
        pause = min(pause * 2, _POLL_MAX_S)


def _reap_after_kill(pid: int) -> _Reaped | None:
    return _reap_by(pid, time.monotonic() + KILL_GRACE_S)


def _finish(proc: subprocess.Popen, reaped: _Reaped | None,
            probe_id: str) -> tuple[int, resource.struct_rusage | None, str]:
    """(exit code, rusage, problem), killing the child's group first if it was not reaped.

    Unreaped means the child is alive or a zombie, and either way its pid is still its own, so
    the group kill cannot reach a stranger. It comes before any reap for that reason.
    """
    if reaped is None:
        if not _kill_own_group(proc):
            # The child left its group (or vanished): signal it alone. `Popen.kill` polls
            # first, and a poll that finds the child exited reaps it, and its rusage with it.
            proc.kill()
            if proc.returncode is not None:
                return proc.returncode, None, "exited as it was killed; cpu time not measured"
        reaped = _reap_after_kill(proc.pid)
        if reaped is None:
            _reap_in_background(proc, probe_id)
            return _NOT_REAPED, None, (f"did not exit within {KILL_GRACE_S}s of SIGKILL; "
                                       f"left to a background reaper")
    status, usage = reaped
    proc.returncode = os.waitstatus_to_exitcode(status)
    return proc.returncode, usage, ""


def _reap_blocking(pid: int) -> _Reaped:
    _, status, usage = os.wait4(pid, 0)
    return status, usage


def _reap_in_background(proc: subprocess.Popen, probe_id: str) -> None:
    """Reap a child that outlived SIGKILL on a daemon thread, outstanding until it is reaped.

    The thread holds `proc`, so Popen's own finaliser never gets to reap it behind our back.
    """
    with _LOCK:
        _count(probe_id, +1)

    def work() -> None:
        try:
            status, _ = _reap_blocking(proc.pid)
            proc.returncode = os.waitstatus_to_exitcode(status)
        finally:
            with _LOCK:
                _count(probe_id, -1)

    threading.Thread(target=work, name=f"neonwatch-reap-{probe_id}", daemon=True).start()


def _kill_own_group(proc: subprocess.Popen) -> bool:
    """SIGKILL the process group of a child started here with `start_new_session`.

    Refuses (returns False, sends nothing) unless the child's pid still leads its own group.
    Call only while the child is unreaped. A vanished process is already gone: False.
    """
    try:
        if os.getpgid(proc.pid) != proc.pid:
            return False
        os.killpg(proc.pid, signal.SIGKILL)
    except ProcessLookupError:
        return False
    return True


# --- the other kinds, bounded by the deadline ---------------------------------------------

_LOCK = threading.Lock()
#: Probe id -> stuck runs (abandoned reads, unreaped children). Mutated only under `_LOCK`.
_OUTSTANDING: dict[str, int] = {}


def _count(probe_id: str, delta: int) -> None:
    """Adjust `probe_id`'s outstanding count, dropping it at zero. Call with `_LOCK` held."""
    count = _OUTSTANDING.get(probe_id, 0) + delta
    if count:
        _OUTSTANDING[probe_id] = count
    else:
        del _OUTSTANDING[probe_id]


def _bounded(spec: ProbeSpec, timeout_s: float, max_bytes: int) -> RawResult:
    """Run the reader on a daemon thread; at `timeout_s`, return a timeout and abandon it.

    A read blocked in the kernel cannot be interrupted from Python, so the thread is left to
    finish (or not) on its own, counted in `outstanding()` under its probe id until it does.
    """
    box: dict[str, object] = {}

    def work() -> None:
        started = time.thread_time_ns()
        try:
            outcome: object = _READERS[spec.kind](spec, timeout_s, max_bytes)
        except BaseException as raised:  # handed to the caller, not swallowed
            outcome = raised
        with _LOCK:
            if box.get("abandoned"):
                _count(spec.id, -1)
            box["outcome"] = outcome
            box["cpu_ms"] = round((time.thread_time_ns() - started) / 1e6)

    worker = threading.Thread(target=work, name=f"neonwatch-read-{spec.id}", daemon=True)
    worker.start()
    worker.join(timeout_s)
    with _LOCK:
        if "outcome" not in box:
            box["abandoned"] = True
            _count(spec.id, +1)
            return RawResult(b"", _READ_FAILED, 0, False,
                             error=f"timed out after {timeout_s}s; read abandoned")
    outcome = box["outcome"]
    if isinstance(outcome, BaseException):
        raise outcome
    assert isinstance(outcome, RawResult)
    return dataclasses.replace(outcome, cpu_ms=box["cpu_ms"])


# --- FILE, GLOB, LISTDIR -------------------------------------------------------------------


def _read_path(path: str, limit: int, within: str = "") -> tuple[bytes, bool]:
    """Up to `limit` bytes of one regular file, and whether there was more. Raises OSError.

    With `within`, the file actually opened must match that pattern. It is checked on the open
    descriptor rather than on `os.path.realpath(path)` beforehand, so swapping a directory
    symlink between the check and the open changes nothing.
    """
    # Read-only, spelled at the call so the gate can see it. O_NONBLOCK: opening a FIFO returns
    # at once instead of waiting for a writer.
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK)
    try:
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            raise OSError(errno.EINVAL, "not a regular file")
        opened = os.readlink(f"/proc/self/fd/{fd}")
        if within and not _matches(opened, within):
            raise OSError(errno.EINVAL, f"resolves to {opened}, outside {within}")
        data = bytearray()
        while len(data) <= limit:
            chunk = os.read(fd, min(_CHUNK, limit + 1 - len(data)))
            if not chunk:
                break
            data += chunk
    finally:
        os.close(fd)
    return bytes(data[:limit]), len(data) > limit


def _why(path: str, failed: OSError) -> str:
    reason = "a symbolic link (O_NOFOLLOW)" if failed.errno == errno.ELOOP else failed.strerror
    return f"refused {path}: {reason or failed}"


def _file(spec: ProbeSpec, _timeout_s: float, max_bytes: int) -> RawResult:
    try:
        data, truncated = _read_path(spec.path, max_bytes)
    except OSError as failed:
        return RawResult(b"", _READ_FAILED, 0, False, error=_why(spec.path, failed))
    return RawResult(data, 0, 0, truncated)


def _resolved(pattern: str) -> str:
    """`pattern` with its literal (wildcard-free) directory prefix resolved by realpath."""
    parts = pattern.split("/")
    first = next((i for i, part in enumerate(parts) if _WILDCARD.search(part)), len(parts) - 1)
    return os.path.join(os.path.realpath("/".join(parts[:first]) or "/"), *parts[first:])


def _matches(path: str, pattern: str) -> bool:
    """fnmatch one path component at a time, so a `*` never stretches across a `/`."""
    names, patterns = path.split("/"), pattern.split("/")
    return len(names) == len(patterns) and all(
        fnmatch.fnmatchcase(name, part) for name, part in zip(names, patterns, strict=True))


def _glob(spec: ProbeSpec, _timeout_s: float, max_bytes: int) -> RawResult:
    """Up to `MAX_MATCHES` matches, each capped at `max_bytes // 4`, all together at `max_bytes`.

    Matches are keyed under the resolved prefix, and each must open a file inside it. A match
    that is refused, cut at either cap, or left unread once the total is spent is named in
    `warnings`; the rest are still returned, exit 0. A vanished match is no match. Past
    `MAX_MATCHES` the glob is not walked further (which matches are kept is then the
    directory's order), and one warning says so.
    """
    pattern = _resolved(spec.path)
    per_file = max_bytes // 4
    files: dict[str, bytes] = {}
    warnings: list[str] = []
    truncated = False
    matches: list[str] = []
    for path in glob.iglob(pattern):
        if len(matches) == MAX_MATCHES:
            warnings.append(f"more than {MAX_MATCHES} matches: the rest were not read")
            truncated = True
            break
        matches.append(path)
    for path in sorted(matches):
        remaining = max_bytes - sum(map(len, files.values()))
        if remaining == 0:
            warnings.append(f"not read {path}: the total of {max_bytes} bytes is spent")
            truncated = True
            continue
        limit = min(per_file, remaining)
        try:
            data, cut = _read_path(path, limit, pattern)
        except FileNotFoundError:
            continue
        except OSError as failed:
            warnings.append(_why(path, failed))
            continue
        files[path] = data
        if cut:
            truncated = True
            warnings.append(f"cut {path} at the per-file cap of {per_file} bytes"
                            if limit == per_file else
                            f"cut {path} at {limit} bytes: the total of {max_bytes} is spent")
    return RawResult(frame_files(files), 0, 0, truncated, warnings=tuple(warnings))


def _listdir(spec: ProbeSpec, _timeout_s: float, max_bytes: int) -> RawResult:
    """The sorted names and each link's target, dropping names (and their targets) from the end
    until the framed listing fits `max_bytes`.

    A target is the link's own text from `os.readlink`, which does not follow it: cron runs what
    a periodic-directory link names while the GLOB beside this refuses to read through it, so
    the target is the one thing that says where such a job lives (/etc/cron.daily/google-chrome
    -> /opt/google/chrome/cron/google-chrome, read as a disguised job without it, 2026-10-27).
    A name that is not a link, or is gone since the listing, has none.
    """
    try:
        names = sorted(os.listdir(spec.path))
    except OSError as failed:
        return RawResult(b"", _READ_FAILED, 0, False, error=_why(spec.path, failed))
    links = {}
    for name in names:
        try:
            links[name] = os.readlink(os.path.join(spec.path, name))
        except OSError:
            continue   # EINVAL: not a link; ENOENT: removed since the listing
    kept = len(names)
    while len(frame_listing(names[:kept], links)) > max_bytes and kept:
        kept -= 1
    return RawResult(frame_listing(names[:kept], links), 0, 0, kept < len(names))


# --- DOCKER --------------------------------------------------------------------------------


class _DockerConnection(http.client.HTTPConnection):
    """HTTP over the Docker unix socket that can send GET and nothing else."""

    def __init__(self, socket_path: str, timeout_s: float):
        super().__init__("localhost", timeout=timeout_s)
        self._socket_path = socket_path

    def connect(self) -> None:
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        try:
            sock.settimeout(self.timeout)
            sock.connect(self._socket_path)
        except OSError:
            sock.close()
            raise
        self.sock = sock

    def putrequest(self, method: str, url: str, *args: object, **kwargs: object) -> None:
        if method != "GET":
            raise ValueError(f"the executor sends GET only, not {method!r}")
        super().putrequest("GET", url, *args, **kwargs)  # type: ignore[arg-type]


def _docker(spec: ProbeSpec, timeout_s: float, max_bytes: int) -> RawResult:
    """GET the spec's path on `DOCKER_SOCKET`; `_bounded` holds the exchange to the deadline."""
    connection = _DockerConnection(DOCKER_SOCKET, timeout_s)
    try:
        connection.request("GET", spec.path)
        response = connection.getresponse()
        body = response.read(max_bytes + 1)
    except (OSError, http.client.HTTPException) as failed:
        return RawResult(b"", _READ_FAILED, 0, False,
                         error=f"docker GET {spec.path}: {failed or type(failed).__name__}")
    finally:
        connection.close()
    ok = 200 <= response.status < 300
    return RawResult(body[:max_bytes], 0 if ok else response.status, 0, len(body) > max_bytes,
                     error="" if ok else f"docker GET {spec.path}: HTTP {response.status}")


_READERS: dict[Kind, Callable[[ProbeSpec, float, int], RawResult]] = {
    Kind.FILE: _file, Kind.GLOB: _glob, Kind.LISTDIR: _listdir, Kind.DOCKER: _docker,
}
