"""Tests for the read-only boundary.

Real catalog entries run where they work unprivileged. Process mechanics run against small scripts
written into tmp_path and admitted through a test `catalog`, which is the same code path.
"""

from __future__ import annotations

import base64
import contextlib
import dataclasses
import errno
import json
import os
import signal
import socket
import subprocess
import sys
import threading
import time
from pathlib import Path

import pytest

from neonwatch import executor
from neonwatch.executor import STDERR_CAP, NotInCatalog, RawResult, execute, outstanding
from neonwatch.probes import CATALOG, Cost, Kind, ProbeSpec, Tier, expand, parse

BY_ID = {spec.id: spec for spec in CATALOG}


def command(id: str, *argv: str, devices: str = "") -> ProbeSpec:
    return ProbeSpec(id, Tier.FAST, Kind.COMMAND, argv, "", Cost.CHEAP, "cpu", "test", devices)


def read(id: str, kind: Kind, path: Path | str) -> ProbeSpec:
    return ProbeSpec(id, Tier.FAST, kind, (), str(path), Cost.CHEAP, "cpu", "test")


def script(tmp_path: Path, name: str, body: str) -> str:
    path = tmp_path / name
    path.write_text(f"#!{sys.executable}\n{body}")
    path.chmod(0o755)
    return str(path)


#: The real binary check, kept so its own tests can run it unpatched.
BINARY_PROBLEM = executor._binary_problem


@contextlib.contextmanager
def admitting(*specs: ProbeSpec):
    """Replace the executor's admission set, the one thing tests may widen, for one block."""
    with pytest.MonkeyPatch.context() as patch:
        patch.setattr(executor, "_ADMITTED", frozenset(specs))
        yield


@pytest.fixture(autouse=True)
def trust_binaries_under_tmp_path(monkeypatch, tmp_path):
    """Scripts under tmp_path cannot be root-owned; every other path gets the real check."""
    monkeypatch.setattr(executor, "_binary_problem", lambda path: (
        "" if path.startswith(str(tmp_path)) else BINARY_PROBLEM(path)))


def run_one(spec: ProbeSpec, timeout_s: float = 10.0, max_bytes: int = 1 << 20,
            **kwargs) -> RawResult:
    with admitting(spec):
        return execute(spec, timeout_s, max_bytes, **kwargs)


def gone(pid: int) -> bool:
    """Whether a pid no longer names a live process (absent, or a zombie awaiting its reaper)."""
    try:
        text = Path(f"/proc/{pid}/stat").read_text()
    except OSError as failed:  # ProcessLookupError and FileNotFoundError are ESRCH and ENOENT
        if failed.errno in (errno.ESRCH, errno.ENOENT):
            return True  # it vanished between the lookup and the read
        raise
    if not text:
        return True  # it vanished during the read
    return text.rsplit(")", 1)[1].split()[0] in {"Z", "X"}


def wait_gone(pid: int, within_s: float = 3.0) -> bool:
    deadline = time.monotonic() + within_s
    while time.monotonic() < deadline:
        if gone(pid):
            return True
        time.sleep(0.02)
    return gone(pid)


# --- admission: only catalog values run ------------------------------------------------------


def test_an_off_catalog_spec_is_refused():
    with pytest.raises(NotInCatalog):
        execute(command("evil", "/usr/bin/id"), 5, 1024)


def test_a_catalog_id_with_a_different_argv_is_refused():
    forged = dataclasses.replace(BY_ID["listeners"], argv=("/usr/bin/ss", "-K"))
    with pytest.raises(NotInCatalog):
        execute(forged, 5, 1024)


def test_a_catalog_id_with_a_different_path_is_refused():
    forged = dataclasses.replace(BY_ID["load"], path="/etc/shadow")
    with pytest.raises(NotInCatalog):
        execute(forged, 5, 1024)


def test_an_object_that_claims_equality_is_refused():
    class Liar:
        id = "load"
        kind = Kind.FILE
        path = "/etc/shadow"

        def __eq__(self, other):
            return True

        __hash__ = object.__hash__

    with pytest.raises(NotInCatalog):
        execute(Liar(), 5, 1024)  # type: ignore[arg-type]


def test_the_admission_set_is_the_imported_catalog_frozen():
    assert type(executor._ADMITTED) is frozenset
    assert frozenset(CATALOG) == executor._ADMITTED


def test_a_caller_cannot_supply_its_own_catalog(tmp_path):
    """The trigger: execute(touch_spec, catalog=(touch_spec,)) ran touch."""
    proof = tmp_path / "proof"
    touch = command("evil", "/usr/bin/touch", str(proof))
    with pytest.raises(TypeError):
        execute(touch, 5, 1024, catalog=(touch,))  # type: ignore[call-arg]
    assert not proof.exists()


def test_an_arbitrary_spec_is_refused_whatever_else_the_caller_controls(tmp_path):
    proof = tmp_path / "proof"
    touch = command("evil", "/usr/bin/touch", str(proof))
    template = dataclasses.replace(BY_ID["smart"], id="evil", argv=(
        "/usr/bin/touch", str(tmp_path / "{device}")))
    for spec, devices in ((touch, None), (touch, {"evil", "proof"}),
                          (expand(template, ["sda"])[0], {"sda"})):
        for timeout_s, max_bytes in ((5, 1024), (1e9, 1 << 40)):
            with pytest.raises(NotInCatalog):
                execute(spec, timeout_s, max_bytes, devices=devices)
    for keyword in ("catalog", "docker_socket", "env", "argv", "cwd"):
        with pytest.raises(TypeError):
            execute(touch, 5, 1024, **{keyword: ()})
    assert not proof.exists() and not (tmp_path / "sda").exists()


def test_a_spec_admitted_through_a_lying_field_runs_the_catalogs_own_copy():
    class Liar(str):
        def __eq__(self, other):
            return True

        __hash__ = str.__hash__

    forged = dataclasses.replace(BY_ID["load"], path=Liar("/etc/shadow"))
    result = execute(forged, 5, 4096)
    assert parse("load", result.stdout)["threads"] > 0  # /proc/loadavg, not /etc/shadow


def test_a_device_template_itself_is_refused():
    with pytest.raises(NotInCatalog):
        execute(BY_ID["smart"], 5, 1024, devices={"nvme0n1"})


def run_template(spec: ProbeSpec, template: ProbeSpec, **kwargs) -> RawResult:
    with admitting(template):
        return execute(spec, 5, 1024, **kwargs)


def test_an_expansion_for_an_existing_device_runs_the_expanded_argv():
    template = command("echo", "/usr/bin/echo", "/dev/{device}", devices=r"sd[a-z]+")
    (spec,) = expand(template, ["sda"])
    result = run_template(spec, template, devices={"sda", "sdb"})
    assert result.stdout == b"/dev/sda\n"
    assert result.exit_code == 0


def test_an_expansion_for_a_device_that_does_not_exist_is_refused():
    template = command("echo", "/usr/bin/echo", "/dev/{device}", devices=r"sd[a-z]+")
    (spec,) = expand(template, ["sda"])
    with pytest.raises(NotInCatalog):
        run_template(spec, template, devices={"sdb"})
    with pytest.raises(NotInCatalog):
        run_template(spec, template)


def test_a_real_smart_expansion_for_a_non_matching_device_is_refused():
    (spec,) = expand(BY_ID["smart"], ["sda"])
    with pytest.raises(NotInCatalog):
        execute(spec, 5, 1024, devices={"nvme0n1"})


def test_a_hand_built_expansion_with_a_different_argv_is_refused():
    template = command("echo", "/usr/bin/echo", "/dev/{device}", devices=r"sd[a-z]+")
    forged = command("echo.sda", "/usr/bin/echo", "/etc/shadow")
    with pytest.raises(NotInCatalog):
        run_template(forged, template, devices={"sda"})


def test_a_device_name_the_template_regex_refuses_is_refused_even_if_it_exists():
    template = command("echo", "/usr/bin/echo", "/dev/{device}", devices=r"sd[a-z]+")
    forged = command("echo.nvme0", "/usr/bin/echo", "/dev/nvme0")
    with pytest.raises(NotInCatalog):
        run_template(forged, template, devices={"nvme0"})


@pytest.mark.parametrize(("timeout_s", "max_bytes"), [(0, 10), (-1, 10), (float("nan"), 10),
                                                      (1, 0), (1, -5)])
def test_nonsense_limits_are_refused(timeout_s, max_bytes):
    with pytest.raises(ValueError):
        execute(BY_ID["load"], timeout_s, max_bytes)


# --- real catalog entries, unprivileged ------------------------------------------------------


def test_the_load_file_probe_reads_proc_loadavg():
    result = execute(BY_ID["load"], 5, 4096)
    assert result.exit_code == 0 and not result.truncated and result.error == ""
    assert parse("load", result.stdout)["threads"] > 0


def test_the_listeners_command_probe_runs():
    result = execute(BY_ID["listeners"], 10, 1 << 20)
    assert result.exit_code == 0, result.stderr
    assert not result.truncated
    parse("listeners", result.stdout)


def test_the_block_devices_listdir_probe_lists_sys_block():
    result = execute(BY_ID["block.devices"], 5, 1 << 16)
    assert result.exit_code == 0
    assert parse("block.devices", result.stdout)["count"] > 0


DOCKER = "/var/run/docker.sock"


@pytest.mark.skipif(not os.access(DOCKER, os.R_OK | os.W_OK),
                    reason="the docker socket is not readable and writable by this user, so a "
                           "connect() to it would be refused")
def test_the_containers_docker_probe_gets_the_container_list():
    result = execute(BY_ID["containers"], 10, 1 << 22)
    assert result.exit_code == 0, result.error
    parse("containers", result.stdout)


# --- COMMAND mechanics -----------------------------------------------------------------------


def test_the_child_sees_an_empty_environment():
    result = run_one(command("env", "/usr/bin/cat", "/proc/self/environ"))
    assert result.exit_code == 0
    assert result.stdout == b""


def test_the_child_runs_in_root_with_stdin_from_dev_null_in_its_own_session(tmp_path):
    probe = script(tmp_path, "where.py",
                   "import os\n"
                   "print(os.getcwd())\n"
                   "print(os.readlink('/proc/self/fd/0'))\n"
                   "print(os.getsid(0) == os.getpid(), os.getpgid(0) == os.getpid())\n")
    result = run_one(command("where", probe))
    assert result.stdout.decode().splitlines() == ["/", "/dev/null", "True True"]


class _Spawned(Exception):
    """Raised by a recording Popen so a test can see the keywords without running anything."""


def _recorded_popen(monkeypatch) -> list[dict]:
    calls: list[dict] = []

    def record(argv, **kwargs):
        calls.append(kwargs)
        raise _Spawned

    monkeypatch.setattr(executor.subprocess, "Popen", record)
    return calls


def test_an_unprivileged_spec_is_spawned_as_nobody_with_no_groups(monkeypatch):
    calls = _recorded_popen(monkeypatch)
    with pytest.raises(_Spawned):
        run_one(dataclasses.replace(command("drop", "/usr/bin/true"), unprivileged=True))
    assert (calls[0]["user"], calls[0]["group"], calls[0]["extra_groups"]) == (65534, 65534, [])


def test_any_other_spec_is_spawned_without_a_change_of_user(monkeypatch):
    calls = _recorded_popen(monkeypatch)
    with pytest.raises(_Spawned):
        run_one(command("keep", "/usr/bin/true"))
    assert (calls[0]["user"], calls[0]["group"], calls[0]["extra_groups"]) == (None, None, None)


def test_the_real_gpu_probe_is_spawned_as_nobody(monkeypatch):
    calls = _recorded_popen(monkeypatch)
    with pytest.raises(_Spawned):
        execute(BY_ID["gpu"], 10.0, 1 << 20)
    assert calls[0]["user"] == 65534


@pytest.mark.skipif(os.geteuid() == 0, reason="root can drop to nobody, so the drop succeeds")
def test_a_drop_that_fails_runs_nothing_rather_than_running_as_the_caller(tmp_path):
    marker = tmp_path / "ran"
    binary = script(tmp_path, "s", f"open({str(marker)!r}, 'w')")
    spec = dataclasses.replace(command("drop", binary), unprivileged=True)
    result = run_one(spec)
    assert result.exit_code == 127 and "cannot exec" in result.error
    assert not marker.exists()


def test_a_nonzero_exit_status_is_reported():
    result = run_one(command("false", "/usr/bin/false"))
    assert result.exit_code == 1 and result.error == ""


def test_a_binary_that_cannot_be_executed_is_reported_not_raised(tmp_path):
    result = run_one(command("missing", str(tmp_path / "no-such-binary")))
    assert result.exit_code == 127
    assert "cannot exec" in result.error


def test_a_missing_binary_under_the_real_check_is_reported_as_cannot_exec(monkeypatch):
    monkeypatch.setattr(executor, "_binary_problem", BINARY_PROBLEM)
    result = run_one(command("missing", "/usr/bin/neonwatch-no-such-binary"))
    assert result.exit_code == 127 and "cannot exec" in result.error


def test_a_binary_not_owned_by_root_is_refused_before_exec(tmp_path, monkeypatch):
    monkeypatch.setattr(executor, "_binary_problem", BINARY_PROBLEM)
    marker = tmp_path / "ran"
    probe = script(tmp_path, "mine.py", f"open({str(marker)!r}, 'w').close()\n")
    result = run_one(command("mine", probe))
    assert result.exit_code == 126 and "owned by uid" in result.error
    assert not marker.exists()


def test_a_symlink_into_usr_bin_from_a_user_directory_is_refused(tmp_path):
    (tmp_path / "true").symlink_to("/usr/bin/true")
    assert "owned by uid" in BINARY_PROBLEM(str(tmp_path / "true"))


def test_a_binary_path_that_is_not_a_regular_file_is_refused():
    assert "not a regular file" in BINARY_PROBLEM("/usr/bin")


def test_catalog_binaries_on_this_host_pass_the_check():
    binaries = {spec.argv[0] for spec in CATALOG if spec.kind is Kind.COMMAND}
    present = [path for path in sorted(binaries) if os.path.exists(path)]
    assert present
    assert {path: BINARY_PROBLEM(path) for path in present} == dict.fromkeys(present, "")


def host_symlink(inside: bool) -> str | None:
    """A root-owned symlink in /usr/bin resolving inside (or outside) the trusted bin dirs."""
    for entry in sorted(os.scandir("/usr/bin"), key=lambda e: e.name):
        if not entry.is_symlink():
            continue
        target = os.path.realpath(entry.path)
        if os.path.isfile(target) and os.stat(target).st_uid == 0 and (
                (os.path.dirname(target) in executor._BIN_DIRS) == inside):
            return entry.path
    return None


def test_a_root_owned_symlink_resolving_inside_the_bin_dirs_is_allowed():
    link = host_symlink(inside=True)
    if link is None:
        pytest.skip("no symlink in /usr/bin resolves to a root-owned file in a bin dir")
    assert BINARY_PROBLEM(link) == ""


def test_a_root_owned_symlink_resolving_outside_the_bin_dirs_is_refused():
    link = host_symlink(inside=False)
    if link is None:
        pytest.skip("no symlink in /usr/bin resolves outside the bin dirs on this host")
    assert "resolves outside" in BINARY_PROBLEM(link)


def fake_stat(mode: int, uid: int) -> os.stat_result:
    return os.stat_result((mode, 1, 1, 1, uid, 0, 0, 0, 0, 0))


@pytest.mark.parametrize(("mode", "uid", "problem"), [
    (0o100755, 0, ""),
    (0o040755, 0, ""),
    (0o100775, 0, "group- or world-writable"),
    (0o100757, 0, "group- or world-writable"),
    (0o041777, 0, "group- or world-writable"),  # /tmp: sticky does not make it safe
    (0o100755, 1000, "owned by uid 1000"),
])
def test_ownership_and_mode_rules(mode, uid, problem):
    found = executor._owner_problem("/x", fake_stat(mode, uid))
    assert (problem in found) if problem else found == ""


def test_output_past_max_bytes_is_truncated_and_the_child_killed(tmp_path):
    probe = script(tmp_path, "flood.py",
                   "import os, sys\n"
                   "print(os.getpid(), flush=True)\n"
                   "while True:\n"
                   "    sys.stdout.buffer.write(b'x' * 65536)\n")
    started = time.monotonic()
    result = run_one(command("flood", probe), timeout_s=30, max_bytes=100_000)
    assert time.monotonic() - started < 10
    assert result.truncated
    assert len(result.stdout) == 100_000
    assert result.exit_code == -signal.SIGKILL
    assert wait_gone(int(result.stdout.split(b"\n", 1)[0]))


def test_output_of_exactly_max_bytes_is_not_truncated(tmp_path):
    probe = script(tmp_path, "exact.py", "import sys\nsys.stdout.buffer.write(b'y' * 5000)\n")
    result = run_one(command("exact", probe), max_bytes=5000)
    assert not result.truncated
    assert result.stdout == b"y" * 5000 and result.exit_code == 0


def test_stderr_is_capped_and_drained_so_a_chatty_child_finishes(tmp_path):
    probe = script(tmp_path, "chatty.py",
                   "import sys\n"
                   "sys.stderr.write('e' * 1_000_000)\n"
                   "print('done')\n")
    result = run_one(command("chatty", probe), timeout_s=10)
    assert result.exit_code == 0
    assert result.stdout == b"done\n"
    assert result.stderr == b"e" * STDERR_CAP


def sleeper_with_grandchild(tmp_path: Path) -> str:
    return script(tmp_path, "sleeper.py",
                  "import os, subprocess, time\n"
                  "grandchild = subprocess.Popen(['/usr/bin/sleep', '60'])\n"
                  "print(os.getpid(), grandchild.pid, flush=True)\n"
                  "time.sleep(60)\n")


def test_a_timeout_kills_the_child_and_says_so(tmp_path):
    started = time.monotonic()
    result = run_one(command("sleeper", sleeper_with_grandchild(tmp_path)), timeout_s=1.0)
    elapsed = time.monotonic() - started
    child, grandchild = (int(word) for word in result.stdout.split())
    try:
        assert 1.0 <= elapsed < 5
        assert "timed out" in result.error
        assert result.exit_code == -signal.SIGKILL
        assert wait_gone(child)
    finally:
        if not gone(grandchild):
            os.kill(grandchild, signal.SIGKILL)


def test_a_timeout_also_kills_the_childs_grandchildren(tmp_path):
    result = run_one(command("sleeper", sleeper_with_grandchild(tmp_path)), timeout_s=1.0)
    _, grandchild = (int(word) for word in result.stdout.split())
    try:
        assert wait_gone(grandchild, within_s=1.0)
    finally:
        if not gone(grandchild):
            os.kill(grandchild, signal.SIGKILL)


def test_a_timeout_after_the_child_exits_still_kills_a_grandchild_holding_its_pipe(tmp_path):
    probe = script(tmp_path, "orphan.py",
                   "import subprocess\n"
                   "grandchild = subprocess.Popen(['/usr/bin/sleep', '60'])\n"
                   "print(grandchild.pid, flush=True)\n")
    result = run_one(command("orphan", probe), timeout_s=1.0)
    grandchild = int(result.stdout)
    try:
        assert "timed out" in result.error
        assert result.exit_code == 0  # the child's own status: it had exited by itself
        assert wait_gone(grandchild, within_s=1.0)
    finally:
        if not gone(grandchild):
            os.kill(grandchild, signal.SIGKILL)


def test_output_past_max_bytes_also_kills_the_childs_grandchildren(tmp_path):
    probe = script(tmp_path, "flood_family.py",
                   "import subprocess, sys\n"
                   "grandchild = subprocess.Popen(['/usr/bin/sleep', '60'])\n"
                   "print(grandchild.pid, flush=True)\n"
                   "while True:\n"
                   "    sys.stdout.buffer.write(b'x' * 65536)\n")
    result = run_one(command("flood_family", probe), max_bytes=100_000)
    grandchild = int(result.stdout.split(b"\n", 1)[0])
    try:
        assert result.truncated and result.exit_code == -signal.SIGKILL
        assert wait_gone(grandchild, within_s=1.0)
    finally:
        if not gone(grandchild):
            os.kill(grandchild, signal.SIGKILL)


def test_kill_own_group_refuses_a_process_that_does_not_lead_its_own_group():
    stranger = subprocess.Popen(["/usr/bin/sleep", "30"])  # in this test's group, not its own
    try:
        assert os.getpgid(stranger.pid) != stranger.pid
        assert executor._kill_own_group(stranger) is False
        time.sleep(0.2)
        assert stranger.poll() is None, "it was signalled"
    finally:
        stranger.kill()
        stranger.wait()


def test_kill_own_group_treats_a_vanished_process_as_gone():
    finished = subprocess.Popen(["/usr/bin/true"], start_new_session=True)
    finished.wait()
    assert executor._kill_own_group(finished) is False


def test_a_child_that_left_its_group_is_still_killed_alone(tmp_path, monkeypatch):
    monkeypatch.setattr(executor, "_kill_own_group", lambda proc: False)
    probe = script(tmp_path, "sleep.py", "import time\ntime.sleep(30)\n")
    result = run_one(command("sleep", probe), timeout_s=0.3)
    assert result.exit_code == -signal.SIGKILL and "timed out" in result.error


def test_a_child_that_closes_its_output_and_keeps_running_still_times_out(tmp_path):
    probe = script(tmp_path, "quiet.py",
                   "import os, time\nos.close(1)\nos.close(2)\ntime.sleep(30)\n")
    result = run_one(command("quiet", probe), timeout_s=0.5)
    assert "timed out" in result.error
    assert result.exit_code == -signal.SIGKILL


def busy(tmp_path: Path, name: str, seconds: float) -> ProbeSpec:
    return command(name, script(tmp_path, f"{name}.py",
                                "import time\n"
                                "start = time.process_time()\n"
                                f"while time.process_time() - start < {seconds}:\n"
                                "    pass\n"))


def test_cpu_time_is_measured_for_a_busy_child(tmp_path):
    result = run_one(busy(tmp_path, "busy", 0.4))
    assert result.exit_code == 0
    assert 380 <= result.cpu_ms <= 900


def test_cpu_time_is_per_child_when_children_run_concurrently(tmp_path, monkeypatch):
    short, long = busy(tmp_path, "short", 0.2), busy(tmp_path, "long", 0.6)
    monkeypatch.setattr(executor, "_ADMITTED", frozenset({short, long}))
    results: dict[str, RawResult] = {}

    def go(spec: ProbeSpec) -> None:
        results[spec.id] = execute(spec, 10, 1024)

    threads = [threading.Thread(target=go, args=(spec,)) for spec in (short, long)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    # RUSAGE_CHILDREN deltas would charge the short child's time to the long one.
    assert 190 <= results["short"].cpu_ms <= 450
    assert 580 <= results["long"].cpu_ms <= 790


def test_cpu_time_is_measured_for_a_child_killed_at_the_timeout(tmp_path):
    result = run_one(busy(tmp_path, "spin", 30), timeout_s=0.6)
    assert "timed out" in result.error
    assert 300 <= result.cpu_ms <= 900


def test_a_child_reaped_by_popen_before_the_kill_reports_that_cpu_was_lost(tmp_path, monkeypatch):
    """Popen.kill() polls first, and a poll can reap a child that exited in that instant."""
    original = subprocess.Popen.kill

    def reap_then_kill(self):
        original(self)
        self.wait()

    monkeypatch.setattr(subprocess.Popen, "kill", reap_then_kill)
    monkeypatch.setattr(executor, "_kill_own_group", lambda proc: False)
    probe = script(tmp_path, "sleep.py", "import time\ntime.sleep(30)\n")
    result = run_one(command("sleep", probe), timeout_s=0.3)
    assert result.exit_code == -signal.SIGKILL
    assert result.cpu_ms == 0
    assert "cpu time not measured" in result.error


def test_a_child_that_outlives_its_kill_is_reported(tmp_path, monkeypatch):
    monkeypatch.setattr(executor, "_reap_after_kill", lambda pid: None)
    probe = script(tmp_path, "stuck.py", "import os, time\nprint(os.getpid(), flush=True)\n"
                                         "time.sleep(30)\n")
    result = run_one(command("stuck", probe), timeout_s=0.3)
    assert result.exit_code == -1
    assert "did not exit" in result.error
    assert wait_gone(int(result.stdout))


# --- FILE, GLOB, LISTDIR ---------------------------------------------------------------------


def test_a_file_is_read_whole_when_it_fits(tmp_path):
    (tmp_path / "f").write_bytes(b"hello")
    result = run_one(read("f", Kind.FILE, tmp_path / "f"), max_bytes=5)
    assert result == RawResult(b"hello", 0, result.cpu_ms, False)


def test_a_file_past_max_bytes_is_truncated(tmp_path):
    (tmp_path / "f").write_bytes(b"a" * 100_000)
    result = run_one(read("f", Kind.FILE, tmp_path / "f"), max_bytes=70_000)
    assert result.truncated and result.stdout == b"a" * 70_000 and result.exit_code == 0


def test_a_file_that_is_a_symlink_is_refused(tmp_path):
    (tmp_path / "real").write_text("secret")
    (tmp_path / "link").symlink_to(tmp_path / "real")
    result = run_one(read("f", Kind.FILE, tmp_path / "link"))
    assert result.stdout == b"" and result.exit_code == 1
    assert "symbolic link" in result.error


def test_a_fifo_is_refused_without_blocking(tmp_path):
    os.mkfifo(tmp_path / "pipe")
    started = time.monotonic()
    result = run_one(read("f", Kind.FILE, tmp_path / "pipe"))
    assert time.monotonic() - started < 2
    assert result.exit_code == 1 and "not a regular file" in result.error


def test_a_missing_file_is_an_error(tmp_path):
    result = run_one(read("f", Kind.FILE, tmp_path / "absent"))
    assert result.exit_code == 1 and "absent" in result.error


def test_a_glob_frames_every_match(tmp_path):
    (tmp_path / "k1").write_text("one")
    (tmp_path / "k2").write_text("two")
    result = run_one(read("g", Kind.GLOB, tmp_path / "k*"))
    assert result.exit_code == 0 and not result.truncated
    assert result.stdout.decode() == (
        f'{{"{tmp_path}/k1":"one","{tmp_path}/k2":"two"}}')


def test_a_glob_that_matches_nothing_is_an_empty_result(tmp_path):
    result = run_one(read("g", Kind.GLOB, tmp_path / "nothing*"))
    assert result == RawResult(b"{}", 0, result.cpu_ms, False)


def test_a_glob_refuses_a_match_that_is_itself_a_symlink(tmp_path):
    (tmp_path / "k1").write_text("one")
    (tmp_path / "k2").symlink_to(tmp_path / "k1")  # resolves inside the pattern: O_NOFOLLOW
    (tmp_path / "k3").symlink_to("/etc/passwd")    # resolves outside it
    result = run_one(read("g", Kind.GLOB, tmp_path / "k*"))
    assert result.stdout.decode() == f'{{"{tmp_path}/k1":"one"}}'
    assert result.exit_code == 0 and result.error == ""
    k2, k3 = result.warnings
    assert f"{tmp_path}/k2" in k2 and "symbolic link" in k2
    assert f"{tmp_path}/k3" in k3 and "symbolic link" in k3  # O_NOFOLLOW refuses it first


def fake_key(comment: str) -> str:
    blob = base64.b64encode(b"\x00\x00\x00\x0bssh-ed25519" + comment.encode() * 4).decode()
    return f"ssh-ed25519 {blob} {comment}\n"


def test_one_users_symlink_does_not_blind_the_keys_probe_for_everyone(tmp_path):
    """The trigger: a symlinked authorized_keys.bak in alice's ~/.ssh hid bob's key."""
    real = Path(os.path.realpath(tmp_path))
    for user in ("alice", "bob"):
        (real / "home" / user / ".ssh").mkdir(parents=True)
    (real / "home" / "alice" / ".ssh" / "authorized_keys").write_text(fake_key("alice@laptop"))
    (real / "home" / "alice" / ".ssh" / "authorized_keys.bak").symlink_to(
        real / "home" / "alice" / ".ssh" / "authorized_keys")
    (real / "home" / "bob" / ".ssh" / "authorized_keys").write_text(fake_key("bob@new"))
    result = run_one(read("ssh.keys.home", Kind.GLOB,
                          real / "home" / "*" / ".ssh" / "authorized_keys*"))
    assert result.exit_code == 0 and result.error == ""
    assert len(result.warnings) == 1 and "authorized_keys.bak" in result.warnings[0]
    keys = parse("ssh.keys.home", result.stdout)
    assert sorted(key["comment"] for key in keys["keys"]) == ["alice@laptop", "bob@new"]


def test_a_glob_follows_a_symlink_in_its_literal_prefix(tmp_path):
    real = Path(os.path.realpath(tmp_path))
    (real / "run").mkdir()
    (real / "run" / "reboot-required").write_text("*** System restart required ***\n")
    (real / "var").mkdir()
    (real / "var" / "run").symlink_to(real / "run")  # like /var/run -> /run
    result = run_one(read("g", Kind.GLOB, real / "var" / "run" / "reboot-required*"))
    assert result.exit_code == 0 and result.error == ""
    assert parse("reboot.required", result.stdout)["required"] is True
    assert result.stdout.decode() == (
        f'{{"{real}/run/reboot-required":"*** System restart required ***\\n"}}')


def test_a_glob_skips_a_match_reached_through_a_symlinked_directory(tmp_path):
    real = Path(os.path.realpath(tmp_path))
    for user in ("alice", "bob"):
        (real / "home" / user).mkdir(parents=True)
    (real / "home" / "alice" / ".ssh").mkdir()
    (real / "home" / "alice" / ".ssh" / "authorized_keys").write_text("alice")
    (real / "rootssh").mkdir()
    (real / "rootssh" / "authorized_keys").write_text("root's")
    (real / "home" / "bob" / ".ssh").symlink_to(real / "rootssh")  # bob points at root's keys
    result = run_one(read("g", Kind.GLOB, real / "home" / "*" / ".ssh" / "authorized_keys*"))
    assert result.stdout.decode() == f'{{"{real}/home/alice/.ssh/authorized_keys":"alice"}}'
    assert result.exit_code == 0 and result.error == ""
    assert [f"{real}/home/bob/.ssh/authorized_keys" in w for w in result.warnings] == [True]


def test_a_glob_wildcard_does_not_stretch_across_directories(tmp_path):
    real = Path(os.path.realpath(tmp_path))
    (real / "home" / "a" / "b" / ".ssh").mkdir(parents=True)
    (real / "home" / "a" / "b" / ".ssh" / "authorized_keys").write_text("deep")
    (real / "home" / "c").mkdir()
    (real / "home" / "c" / ".ssh").symlink_to(real / "home" / "a" / "b" / ".ssh")
    result = run_one(read("g", Kind.GLOB, real / "home" / "*" / ".ssh" / "authorized_keys*"))
    assert result.stdout == b"{}" and result.exit_code == 0
    assert [f"{real}/home/c/.ssh/authorized_keys" in w for w in result.warnings] == [True]


def test_a_glob_without_a_wildcard_reads_its_one_file(tmp_path):
    real = Path(os.path.realpath(tmp_path))
    (real / "exact").write_text("x")
    result = run_one(read("g", Kind.GLOB, real / "exact"))
    assert result.stdout.decode() == f'{{"{real}/exact":"x"}}' and result.exit_code == 0


def test_a_glob_match_that_vanishes_before_it_is_read_is_not_an_error(tmp_path, monkeypatch):
    (tmp_path / "k1").write_text("one")
    monkeypatch.setattr(executor.glob, "glob",
                        lambda pattern: [str(tmp_path / "k1"), str(tmp_path / "k-gone")])
    result = run_one(read("g", Kind.GLOB, tmp_path / "k*"))
    assert result.exit_code == 0
    assert result.stdout.decode() == f'{{"{tmp_path}/k1":"one"}}'


def test_one_huge_glob_match_cannot_starve_the_small_ones(tmp_path):
    """Each match gets at most max_bytes // 4, so an early huge file leaves room for the rest."""
    (tmp_path / "a_huge").write_bytes(b"h" * 100_000)
    for name in "bcde":
        (tmp_path / name).write_text(name * 10)
    result = run_one(read("g", Kind.GLOB, tmp_path / "*"), max_bytes=4000)
    files = json.loads(result.stdout)
    assert files[f"{tmp_path}/a_huge"] == "h" * 1000
    assert {name: files[f"{tmp_path}/{name}"] for name in "bcde"} == {
        name: name * 10 for name in "bcde"}
    assert result.truncated and result.exit_code == 0 and result.error == ""
    (warning,) = result.warnings
    assert f"{tmp_path}/a_huge" in warning and "per-file cap of 1000" in warning


def test_glob_matches_past_the_total_are_named_not_dropped(tmp_path):
    names = [f"k{i:02}" for i in range(10)]
    for name in names:
        (tmp_path / name).write_bytes(b"x" * 60)
    result = run_one(read("g", Kind.GLOB, tmp_path / "k*"), max_bytes=400)
    files = json.loads(result.stdout)
    # 100 bytes per file allowed; six whole files use 360, the seventh gets the last 40.
    assert [files[f"{tmp_path}/{name}"] for name in names[:6]] == ["x" * 60] * 6
    assert files[f"{tmp_path}/{names[6]}"] == "x" * 40
    assert set(files) == {f"{tmp_path}/{name}" for name in names[:7]}
    assert result.truncated and result.exit_code == 0
    cut, *unread = result.warnings
    assert f"{tmp_path}/{names[6]}" in cut and "total" in cut
    assert [f"{tmp_path}/{name}" in w and "not read" in w
            for name, w in zip(names[7:], unread, strict=True)] == [True] * 3


def test_a_listdir_frames_the_names(tmp_path):
    for name in ("b", "a"):
        (tmp_path / name).write_text("")
    result = run_one(read("d", Kind.LISTDIR, tmp_path))
    assert result == RawResult(b'{"names":["a","b"],"links":{}}', 0, result.cpu_ms, False)


def test_a_listdir_reads_where_each_link_points_without_following_it(tmp_path):
    """/etc/cron.daily/google-chrome is a link to /opt/google/chrome/cron/google-chrome; cron
    runs it, and without its target the job read as disguised (2026-10-27)."""
    secret = tmp_path / "secret"
    secret.write_text("root only")
    secret.chmod(0)
    listed = tmp_path / "d"
    listed.mkdir()
    (listed / "plain").write_text("")
    (listed / "chrome").symlink_to("/opt/google/chrome/cron/google-chrome")   # dangling here
    (listed / "up").symlink_to("../secret")
    (listed / "loop").symlink_to("loop")
    result = run_one(read("d", Kind.LISTDIR, listed))
    assert json.loads(result.stdout) == {
        "names": ["chrome", "loop", "plain", "up"],
        "links": {"chrome": "/opt/google/chrome/cron/google-chrome", "loop": "loop",
                  "up": "../secret"}}
    assert result.exit_code == 0 and not result.warnings
    assert parse("cron.daily.names", result.stdout)["links"]["up"] == "../secret"


def test_a_name_gone_or_not_a_link_has_no_target(tmp_path, monkeypatch):
    (tmp_path / "a").write_text("")
    real = os.readlink

    def vanished(path, *args, **kwargs):
        if path.endswith("/a"):
            raise FileNotFoundError(2, "gone")
        return real(path, *args, **kwargs)

    monkeypatch.setattr(os, "readlink", vanished)
    result = run_one(read("d", Kind.LISTDIR, tmp_path))
    assert json.loads(result.stdout) == {"names": ["a"], "links": {}}


def test_a_listdir_past_max_bytes_keeps_the_names_that_fit(tmp_path):
    for name in ("aaaa", "bbbb", "cccc"):
        (tmp_path / name).write_text("")
    (tmp_path / "dddd").symlink_to("/x")
    result = run_one(read("d", Kind.LISTDIR, tmp_path), max_bytes=40)
    assert result.truncated and result.stdout == b'{"names":["aaaa","bbbb"],"links":{}}'


def test_a_missing_directory_is_an_error(tmp_path):
    result = run_one(read("d", Kind.LISTDIR, tmp_path / "absent"))
    assert result.exit_code == 1 and "absent" in result.error


def settle(probe_id: str, within_s: float = 3.0) -> bool:
    """Whether `probe_id` leaves `outstanding()` within the time allowed."""
    deadline = time.monotonic() + within_s
    while probe_id in outstanding() and time.monotonic() < deadline:
        time.sleep(0.01)
    return probe_id not in outstanding()


def test_a_read_that_never_returns_is_outstanding_per_probe_until_it_does(tmp_path, monkeypatch):
    release = threading.Event()

    def stuck(spec, timeout_s, max_bytes):
        release.wait()
        return RawResult(b"late", 0, 0, False)

    monkeypatch.setitem(executor._READERS, Kind.FILE, stuck)
    spec = read("stuck.read", Kind.FILE, tmp_path / "f")
    try:
        started = time.monotonic()
        result = run_one(spec, timeout_s=0.3)
        assert time.monotonic() - started < 1.5
        assert result.exit_code == 1 and "timed out" in result.error
        assert "abandoned" in result.error and result.stdout == b""
        assert outstanding().get("stuck.read") == 1
        run_one(spec, timeout_s=0.1)
        assert outstanding().get("stuck.read") == 2
    finally:
        release.set()
    assert settle("stuck.read")


def test_a_reader_that_raises_raises_in_the_caller_and_leaves_nothing_outstanding(
        tmp_path, monkeypatch):
    def broken(spec, timeout_s, max_bytes):
        raise RuntimeError("reader bug")

    monkeypatch.setitem(executor._READERS, Kind.FILE, broken)
    with pytest.raises(RuntimeError, match="reader bug"):
        run_one(read("broken.read", Kind.FILE, tmp_path / "f"))
    assert "broken.read" not in outstanding()


def test_a_child_that_cannot_be_reaped_is_outstanding_per_probe_until_it_is(
        tmp_path, monkeypatch):
    release = threading.Event()
    real_reap = executor._reap_blocking

    def reap_when_released(pid):
        release.wait()
        return real_reap(pid)

    monkeypatch.setattr(executor, "_reap_after_kill", lambda pid: None)  # it survives SIGKILL
    monkeypatch.setattr(executor, "_reap_blocking", reap_when_released)
    probe = script(tmp_path, "stuck.py", "import os, time\nprint(os.getpid(), flush=True)\n"
                                         "time.sleep(30)\n")
    spec = command("stuck.child", probe)
    pids = []
    try:
        for expected in (1, 2):
            result = run_one(spec, timeout_s=0.3)
            assert result.exit_code == -1 and "did not exit" in result.error
            pids.append(int(result.stdout))
            assert outstanding().get("stuck.child") == expected
    finally:
        release.set()
    assert settle("stuck.child")
    # Reaped by the executor's own background reaper: not even a zombie is left.
    assert all(not Path(f"/proc/{pid}").exists() for pid in pids)


def test_outstanding_is_a_copy_that_cannot_change_the_executors_count(tmp_path, monkeypatch):
    release = threading.Event()
    monkeypatch.setitem(executor._READERS, Kind.FILE, lambda *args: release.wait())
    try:
        run_one(read("copied.read", Kind.FILE, tmp_path / "f"), timeout_s=0.1)
        snapshot = outstanding()
        snapshot["copied.read"] = 99  # type: ignore[index]
        snapshot["invented"] = 1  # type: ignore[index]
        assert outstanding().get("copied.read") == 1 and "invented" not in outstanding()
    finally:
        release.set()
    assert settle("copied.read")


# --- DOCKER ----------------------------------------------------------------------------------


class FakeDocker:
    """One-shot HTTP server on a unix socket in tmp_path, recording the request it received."""

    def __init__(self, path: Path, response: bytes | None):
        self.path = str(path)
        self.request = b""
        self._response = response
        self._server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self._server.bind(self.path)
        self._server.listen(1)
        self._thread = threading.Thread(target=self._serve, daemon=True)
        self._thread.start()

    def _serve(self) -> None:
        connection, _ = self._server.accept()
        with connection:
            while b"\r\n\r\n" not in self.request:
                chunk = connection.recv(4096)
                if not chunk:
                    break
                self.request += chunk
            if self._response is None:
                time.sleep(2)  # never answer inside the client's timeout
                return
            connection.sendall(self._response)

    def close(self) -> None:
        self._thread.join(timeout=5)
        self._server.close()


def http_response(status: str, body: bytes) -> bytes:
    return (f"HTTP/1.1 {status}\r\nContent-Type: application/json\r\n"
            f"Content-Length: {len(body)}\r\nConnection: close\r\n\r\n").encode() + body


def docker_get(monkeypatch, socket_path: str, spec: ProbeSpec, timeout_s: float,
               max_bytes: int) -> RawResult:
    monkeypatch.setattr(executor, "DOCKER_SOCKET", socket_path)
    return execute(spec, timeout_s, max_bytes)


@pytest.fixture
def docker_spec() -> ProbeSpec:
    return BY_ID["containers"]


def test_docker_sends_exactly_get_on_the_spec_path(tmp_path, docker_spec, monkeypatch):
    fake = FakeDocker(tmp_path / "d.sock", http_response("200 OK", b"[]"))
    result = docker_get(monkeypatch, fake.path, docker_spec, 5, 1024)
    fake.close()
    assert result == RawResult(b"[]", 0, result.cpu_ms, False)
    assert fake.request.startswith(b"GET /containers/json?all=1 HTTP/1.1\r\n")


def test_docker_reports_a_non_2xx_status_as_the_exit_code(tmp_path, docker_spec, monkeypatch):
    fake = FakeDocker(tmp_path / "d.sock", http_response("404 Not Found", b'{"message":"x"}'))
    result = docker_get(monkeypatch, fake.path, docker_spec, 5, 1024)
    fake.close()
    assert result.exit_code == 404 and "404" in result.error


def test_docker_caps_the_body(tmp_path, docker_spec, monkeypatch):
    fake = FakeDocker(tmp_path / "d.sock", http_response("200 OK", b"z" * 5000))
    result = docker_get(monkeypatch, fake.path, docker_spec, 5, 100)
    fake.close()
    assert result.truncated and result.stdout == b"z" * 100


def test_docker_times_out(tmp_path, docker_spec, monkeypatch):
    fake = FakeDocker(tmp_path / "d.sock", None)
    started = time.monotonic()
    result = docker_get(monkeypatch, fake.path, docker_spec, 0.3, 1024)
    assert time.monotonic() - started < 2
    fake.close()
    assert result.exit_code == 1 and "timed out" in result.error


def test_docker_without_a_socket_is_an_error(tmp_path, docker_spec, monkeypatch):
    result = docker_get(monkeypatch, str(tmp_path / "absent.sock"), docker_spec, 1, 1024)
    assert result.exit_code == 1 and result.stdout == b""


@pytest.mark.parametrize("method", ["POST", "PUT", "PATCH", "DELETE", "HEAD", "get"])
def test_the_docker_connection_refuses_every_method_but_get(tmp_path, method):
    connection = executor._DockerConnection(str(tmp_path / "unused.sock"), 1)
    with pytest.raises(ValueError):
        connection.request(method, "/containers/json")
