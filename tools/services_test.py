"""The service installer, run unprivileged: staged under a tmp root, files owned by whoever runs
the tests, and systemctl recorded rather than called.

The install test builds a real venv on the system python and imports the agent's modules from
it, so a bundle the system python cannot run (a 3.13-only construct, a missing module) fails here
rather than in the unit's first start.
"""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import subprocess
import sys
import zipfile
from pathlib import Path
from types import SimpleNamespace

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent))
import services
from services import Refused

REPO = Path(__file__).resolve().parent.parent
ME = SimpleNamespace(pw_uid=os.getuid())
system_python = pytest.mark.skipif(
    not Path(services.PYTHON).exists() or os.stat(services.PYTHON).st_uid != 0,
    reason=f"needs a root-owned {services.PYTHON}")


def users(**known):
    def getpwnam(name):
        if name not in known:
            raise KeyError(name)
        return SimpleNamespace(pw_uid=known[name])
    return getpwnam


def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def wheel(path: Path, files: dict[str, bytes]) -> Path:
    with zipfile.ZipFile(path, "w") as archive:
        for name, data in files.items():
            archive.writestr(name, data)
    return path


def write_bundle(where: Path, *wheels: Path) -> Path:
    where.mkdir(parents=True, exist_ok=True)
    for made in wheels:
        shutil.copy(made, where / made.name)
    (where / services.MANIFEST).write_text(
        json.dumps({"wheels": {w.name: digest(w) for w in wheels}}))
    return where


@pytest.fixture(scope="module")
def real_bundle(tmp_path_factory) -> Path:
    """The neonwatch package from this checkout and nats from its venv, as the two wheels."""
    import nats
    made = tmp_path_factory.mktemp("wheels")
    ours = {f"neonwatch/{p.relative_to(REPO / 'neonwatch')}": p.read_bytes()
            for p in (REPO / "neonwatch").rglob("*")
            if p.is_file() and "__pycache__" not in p.parts and not p.name.endswith("_test.py")}
    ours["neonwatch-0.1.0.dist-info/METADATA"] = b"Name: neonwatch\n"
    top = Path(nats.__file__).parent
    theirs = {f"nats/{p.relative_to(top)}": p.read_bytes() for p in top.rglob("*")
              if p.is_file() and "__pycache__" not in p.parts}
    return write_bundle(made / "bundle",
                        wheel(made / "neonwatch-0.1.0-py3-none-any.whl", ours),
                        wheel(made / "nats_py-2.16.0-py3-none-any.whl", theirs))


class Recorder:
    """Runs everything but systemctl for real, and records what it would have asked systemctl."""

    def __init__(self):
        self.systemctl: list[list[str]] = []

    def __call__(self, argv, **kwargs):
        if argv[0] == "systemctl":
            self.systemctl.append(list(argv))
            return subprocess.CompletedProcess(argv, 0)
        return subprocess.run(argv, **kwargs)


# --- the units -----------------------------------------------------------------------------------


def test_the_agent_unit_runs_the_root_owned_install_confined_for_the_named_operator():
    unit = services.AGENT_UNIT
    (start,) = [line for line in unit.splitlines() if line.startswith("ExecStart=")]
    assert start == ("ExecStart=/opt/neonwatch/venv/bin/python -I -B -m neonwatch.launch agent "
                     "--operator %i --require-confined")
    for line in ("ProtectSystem=strict", "ProtectHome=read-only", "NoNewPrivileges=yes",
                 "IPAddressDeny=any", "IPAddressAllow=localhost", "PrivateTmp=yes"):
        assert line in unit.splitlines()
    (caps,) = [line for line in unit.splitlines() if line.startswith("CapabilityBoundingSet=")]
    assert "CAP_DAC_OVERRIDE" not in caps and "CAP_SYS_MODULE" not in caps


@pytest.mark.skipif(shutil.which("systemd-analyze") is None, reason="needs systemd-analyze")
def test_systemd_accepts_every_directive_in_the_agent_unit(tmp_path):
    # verify checks that ExecStart exists, and /opt/neonwatch is not installed here; any root
    # executable stands in for it, since verify never runs the command.
    unit = tmp_path / "neonwatch-agent@alice.service"
    unit.write_text(services.AGENT_UNIT.replace("/opt/neonwatch/venv/bin/python", "/usr/bin/true"))
    checked = subprocess.run(["systemd-analyze", "verify", str(unit)], capture_output=True,
                             text=True)
    assert (checked.returncode, checked.stderr) == (0, "")


@pytest.mark.skipif(shutil.which("systemd-analyze") is None, reason="needs systemd-analyze")
def test_systemd_rates_the_agent_units_exposure_no_worse_than_ok(tmp_path):
    unit = tmp_path / "neonwatch-agent@alice.service"
    unit.write_text(services.AGENT_UNIT)
    rated = subprocess.run(["systemd-analyze", "security", "--offline=yes",
                            "--threshold=40", str(unit)], capture_output=True, text=True)
    assert rated.returncode == 0, rated.stdout[-400:]


def test_the_user_units_run_from_the_checkout_and_the_service_needs_the_broker():
    units = services.user_units(Path("/home/alice/neonwatch"))
    broker, service = units["neonwatch-broker.service"], units["neonwatch-service.service"]
    assert ("WorkingDirectory=/home/alice/neonwatch"
            in broker.splitlines())
    assert ("ExecStart=/home/alice/neonwatch/.venv/bin/neonwatch "
            "broker" in broker.splitlines())
    assert "Requires=neonwatch-broker.service" in service.splitlines()
    assert "After=neonwatch-broker.service" in service.splitlines()


@pytest.mark.parametrize("checkout", ["/home/a b/repo", "/home/a/%i", "relative/repo",
                                      "/home/a/$HOME"])
def test_a_checkout_path_a_unit_would_need_to_quote_is_refused(checkout):
    with pytest.raises(Refused, match="quote"):
        services.user_units(Path(checkout))


# --- bundle --------------------------------------------------------------------------------------


def test_the_nats_wheel_is_the_one_this_checkouts_lock_pins():
    url, sha = services.locked_wheel(REPO / "uv.lock", "nats-py")
    assert url.endswith("/nats_py-2.16.0-py3-none-any.whl") and url.startswith("https://")
    assert sha == "aeb1ff123966c05833d26c7df7e1d54c1c6d32b612428b21677a2e921f1fecae"


@pytest.mark.parametrize("wheels, why", [
    ([], "0 pure-python"),
    (["a-py3-none-any.whl", "b-py3-none-any.whl"], "2 pure-python"),
])
def test_a_lock_without_exactly_one_pure_wheel_is_refused(tmp_path, wheels, why):
    lock = tmp_path / "uv.lock"
    entries = ", ".join(f'{{ url = "https://x/{w}", hash = "sha256:00" }}' for w in wheels)
    lock.write_text(f'[[package]]\nname = "nats-py"\nwheels = [{entries}]\n')
    with pytest.raises(Refused, match=why):
        services.locked_wheel(lock, "nats-py")
    with pytest.raises(Refused, match="not in"):
        services.locked_wheel(lock, "aiohttp")


def fake_repo(tmp_path: Path, nats: bytes) -> Path:
    repo = tmp_path / "repo"
    repo.mkdir()
    sha = hashlib.sha256(nats).hexdigest()
    (repo / "uv.lock").write_text(
        f'[[package]]\nname = "nats-py"\nwheels = [{{ url = "https://files.example/'
        f'nats_py-2.16.0-py3-none-any.whl", hash = "sha256:{sha}" }}]\n')
    return repo


def fake_uv(argv, *, check):
    assert argv[:4] == ["uv", "build", "--wheel", "--out-dir"] and check
    (Path(argv[4]) / "neonwatch-0.1.0-py3-none-any.whl").write_bytes(b"ours")


def test_bundle_builds_our_wheel_fetches_the_pinned_one_and_writes_their_hashes(tmp_path):
    repo, out = fake_repo(tmp_path, b"theirs"), tmp_path / "dist" / "agent"
    (out / "stale").mkdir(parents=True)
    asked = []
    manifest = services.bundle(out, repo=repo, run=fake_uv,
                               get=lambda url: asked.append(url) or b"theirs")
    assert asked == ["https://files.example/nats_py-2.16.0-py3-none-any.whl"]
    assert manifest == {"wheels": {
        "neonwatch-0.1.0-py3-none-any.whl": hashlib.sha256(b"ours").hexdigest(),
        "nats_py-2.16.0-py3-none-any.whl": hashlib.sha256(b"theirs").hexdigest()}}
    assert json.loads((out / services.MANIFEST).read_text()) == manifest
    assert not (out / "stale").exists()


def test_bundle_refuses_and_discards_a_download_that_does_not_match_the_lock(tmp_path):
    repo, out = fake_repo(tmp_path, b"theirs"), tmp_path / "out"
    with pytest.raises(Refused, match=r"uv\.lock pins"):
        services.bundle(out, repo=repo, run=fake_uv, get=lambda url: b"tampered")
    assert not (out / "nats_py-2.16.0-py3-none-any.whl").exists()
    assert not (out / services.MANIFEST).exists()


def test_bundle_refuses_a_build_that_leaves_other_than_one_wheel(tmp_path):
    repo = fake_repo(tmp_path, b"theirs")
    with pytest.raises(Refused, match="0 wheels"):
        services.bundle(tmp_path / "out", repo=repo, run=lambda argv, check: None)


def test_bundle_refuses_to_run_as_root(tmp_path, monkeypatch):
    monkeypatch.setattr(os, "geteuid", lambda: 0)
    with pytest.raises(Refused, match="not as root"):
        services.bundle(tmp_path / "out", repo=tmp_path, run=fake_uv)


def test_fetch_reads_https_only(monkeypatch):
    class Response:
        def __enter__(self):
            return self

        def __exit__(self, *exc):
            return False

        def read(self):
            return b"wheel"
    seen = []
    monkeypatch.setattr(services.urllib.request, "urlopen",
                        lambda url, timeout: seen.append((url, timeout)) or Response())
    assert services.fetch("https://files.example/x.whl") == b"wheel"
    assert seen == [("https://files.example/x.whl", 60)]
    with pytest.raises(Refused, match="not https"):
        services.fetch("http://files.example/x.whl")


# --- install-agent -------------------------------------------------------------------------------


@system_python
def test_install_agent_builds_a_venv_the_system_python_can_run_the_agent_from(real_bundle,
                                                                              tmp_path, capsys):
    run = Recorder()
    opt = services.install_agent("alice", source=real_bundle, root=tmp_path, uid=os.getuid(),
                                 run=run, getpwnam=users(alice=1000))
    assert opt == tmp_path / "opt" / "neonwatch"
    assert (opt / "venv" / "bin" / "python").resolve() == Path(services.PYTHON).resolve()
    assert json.loads((opt / services.MANIFEST).read_text()) == json.loads(
        (real_bundle / services.MANIFEST).read_text())
    unit = tmp_path / "etc" / "systemd" / "system" / services.UNIT
    assert unit.read_text() == services.AGENT_UNIT and unit.stat().st_mode & 0o777 == 0o644
    assert run.systemctl == [["systemctl", "daemon-reload"],
                             ["systemctl", "enable", "neonwatch-agent@alice.service"],
                             ["systemctl", "try-restart", "neonwatch-agent@alice.service"]]
    assert sorted(p.name for p in (tmp_path / "opt").iterdir()) == ["neonwatch"]   # no staging
    assert not list(opt.rglob("__pycache__"))   # -B: the import check wrote no bytecode

    (tmp_path / "opt" / "neonwatch.new" / "debris").mkdir(parents=True)   # a failed install's
    for _ in range(2):   # the second replaces .old
        services.install_agent("alice", source=real_bundle, root=tmp_path, uid=os.getuid(),
                               run=run, systemctl=False, getpwnam=users(alice=1000))
    assert sorted(p.name for p in (tmp_path / "opt").iterdir()) == ["neonwatch", "neonwatch.old"]
    assert not (opt / "debris").exists()
    assert "enabled" not in capsys.readouterr().out.splitlines()[-4]   # --no-systemctl


@system_python
def test_install_agent_refuses_a_bundle_that_cannot_run_the_agent(tmp_path):
    empty = wheel(tmp_path / "neonwatch-0.1.0-py3-none-any.whl",
                  {"neonwatch/__init__.py": b""})
    bundle = write_bundle(tmp_path / "bundle", empty)
    with pytest.raises(subprocess.CalledProcessError):
        services.install_agent("alice", source=bundle, root=tmp_path / "root", uid=os.getuid(),
                               run=Recorder(), getpwnam=users(alice=1000))
    assert not (tmp_path / "root" / "opt" / "neonwatch").exists()


@system_python
def test_install_agent_refuses_a_wheel_changed_after_bundling_before_building_anything(
        real_bundle, tmp_path):
    bundle = tmp_path / "bundle"
    shutil.copytree(real_bundle, bundle)
    (name,) = [n for n in json.loads((bundle / services.MANIFEST).read_text())["wheels"]
               if n.startswith("nats")]
    with (bundle / name).open("ab") as changed:
        changed.write(b"\0")
    run = Recorder()
    with pytest.raises(Refused, match="the manifest says"):
        services.install_agent("alice", source=bundle, root=tmp_path / "root", uid=os.getuid(),
                               run=run, getpwnam=users(alice=1000))
    assert sorted(p.name for p in (tmp_path / "root" / "opt").iterdir()) == []
    assert run.systemctl == []


def test_install_agent_refuses_an_interpreter_that_is_not_roots(tmp_path):
    mine = tmp_path / "python3"
    mine.write_text("")
    with pytest.raises(Refused, match="not root's"):
        services.install_agent("alice", source=tmp_path, root=tmp_path, uid=os.getuid(),
                               python=str(mine), getpwnam=users(alice=1000))


@pytest.mark.parametrize("name, why", [
    ("alice; rm", "plain user name"), ("Alice", "plain user name"), ("", "plain user name"),
    ("mallory", "no such user"), ("root", "never root"),
])
def test_an_operator_who_is_not_a_plain_real_unprivileged_user_is_refused(name, why):
    with pytest.raises(Refused, match=why):
        services.operator_named(name, users(alice=1000, root=0))


@pytest.mark.parametrize("name", ["evil/../x.whl", "/etc/x.whl", "x.tar.gz"])
def test_a_manifest_naming_anything_but_a_wheel_beside_it_is_refused(tmp_path, name):
    (tmp_path / "in").mkdir()
    (tmp_path / "out").mkdir()
    (tmp_path / "in" / services.MANIFEST).write_text(json.dumps({"wheels": {name: "00"}}))
    with pytest.raises(Refused, match="not a wheel file name"):
        services.verified_copy(tmp_path / "in", tmp_path / "out")


@pytest.mark.parametrize("member", ["../escape.py", "/abs.py", "pkg-1.0.data/scripts/run",
                                    "pkg/../../escape.py"])
def test_a_wheel_member_that_would_land_outside_site_packages_is_refused(tmp_path, member):
    made = wheel(tmp_path / "pkg-1.0-py3-none-any.whl", {member: b"x"})
    (tmp_path / "site").mkdir()
    with pytest.raises(Refused, match="outside site-packages"):
        services.unpack(made, tmp_path / "site")


def test_two_wheels_that_would_write_the_same_file_are_refused(tmp_path):
    (tmp_path / "site").mkdir()
    services.unpack(wheel(tmp_path / "a.whl", {"pkg/": b"", "pkg/x.py": b"a"}), tmp_path / "site")
    with pytest.raises(FileExistsError):
        services.unpack(wheel(tmp_path / "b.whl", {"pkg/x.py": b"b"}), tmp_path / "site")
    assert (tmp_path / "site" / "pkg" / "x.py").read_bytes() == b"a"


def owned_tree(tmp_path: Path) -> Path:
    top = tmp_path / "opt" / "neonwatch.new"
    (top / "venv").mkdir(parents=True)
    (top / "venv" / "file").write_text("")
    (top / "venv" / "link").symlink_to("/usr/bin/python3")
    for path in (tmp_path, tmp_path / "opt", top, top / "venv", top / "venv" / "file"):
        path.chmod(0o755)
    return top


def test_a_tree_owned_by_the_installer_and_writable_by_nobody_else_passes(tmp_path):
    services.check_owned(owned_tree(tmp_path), os.getuid(), above=tmp_path)


@pytest.mark.parametrize("loosened", ["venv/file", "venv", ".", "..", "../.."])
def test_anything_group_or_other_writable_from_the_root_down_is_refused(tmp_path, loosened):
    top = owned_tree(tmp_path)
    (top / loosened).chmod(0o775)
    with pytest.raises(Refused, match="writable by group or others"):
        services.check_owned(top, os.getuid(), above=tmp_path)


def test_a_tree_owned_by_someone_else_is_refused(tmp_path):
    with pytest.raises(Refused, match="owned by uid"):
        services.check_owned(owned_tree(tmp_path), os.getuid() + 1, above=tmp_path)


def test_the_ownership_walk_stops_at_the_filesystem_root(tmp_path):
    # `above` that is not an ancestor: the walk ends at /, which is root's.
    with pytest.raises(Refused, match="owned by uid"):
        services.check_owned(owned_tree(tmp_path), os.getuid(), above=tmp_path / "elsewhere")


# --- uninstall-agent -----------------------------------------------------------------------------


def test_uninstall_agent_disables_every_enabled_instance_and_removes_the_install(tmp_path):
    units = tmp_path / "etc" / "systemd" / "system"
    (units / "multi-user.target.wants").mkdir(parents=True)
    (units / services.UNIT).write_text(services.AGENT_UNIT)
    (units / "multi-user.target.wants" / "neonwatch-agent@alice.service").symlink_to(
        units / services.UNIT)
    for tree in ("neonwatch", "neonwatch.old"):
        (tmp_path / "opt" / tree).mkdir(parents=True)
    run = Recorder()
    assert services.uninstall_agent(root=tmp_path, run=run) == ["neonwatch-agent@alice.service"]
    assert run.systemctl == [["systemctl", "disable", "--now", "neonwatch-agent@alice.service"],
                             ["systemctl", "daemon-reload"]]
    assert not (units / services.UNIT).exists() and list((tmp_path / "opt").iterdir()) == []


def test_uninstall_agent_with_nothing_installed_is_quiet(tmp_path, capsys):
    assert services.uninstall_agent(root=tmp_path, systemctl=False) == []
    assert "disabled" not in capsys.readouterr().out


# --- user units ----------------------------------------------------------------------------------


def checkout(tmp_path: Path) -> Path:
    repo = tmp_path / "repo"
    for needed in (".venv/bin/neonwatch", ".tools/nats-server"):
        (repo / needed).parent.mkdir(parents=True, exist_ok=True)
        (repo / needed).write_text("")
    return repo


def test_install_user_writes_both_units_and_enables_them(tmp_path, capsys):
    run = Recorder()
    written = services.install_user(checkout(tmp_path), home=tmp_path / "home", run=run)
    where = tmp_path / "home" / ".config" / "systemd" / "user"
    assert written == [where / name for name in services.USER_UNITS]
    assert (where / "neonwatch-broker.service").read_text() == services.user_units(
        tmp_path / "repo")["neonwatch-broker.service"]
    assert run.systemctl == [["systemctl", "--user", "daemon-reload"],
                             ["systemctl", "--user", "enable", *services.USER_UNITS],
                             ["systemctl", "--user", "try-restart", *services.USER_UNITS]]
    out = capsys.readouterr().out
    assert "enable-linger" in out and "installed and enabled" in out
    services.install_user(checkout(tmp_path), home=tmp_path / "home", systemctl=False)
    assert "enabled" not in capsys.readouterr().out.splitlines()[0]


def test_install_user_refuses_a_checkout_that_is_not_synced(tmp_path):
    repo = checkout(tmp_path)
    (repo / ".tools" / "nats-server").unlink()
    with pytest.raises(Refused, match="nats-server is missing"):
        services.install_user(repo, home=tmp_path, systemctl=False)


def test_install_user_refuses_to_run_as_root(tmp_path, monkeypatch):
    monkeypatch.setattr(os, "geteuid", lambda: 0)
    with pytest.raises(Refused, match="not as root"):
        services.install_user(checkout(tmp_path), home=tmp_path, systemctl=False)


def test_uninstall_user_disables_and_removes_both_units(tmp_path):
    services.install_user(checkout(tmp_path), home=tmp_path / "home", systemctl=False)
    run = Recorder()
    services.uninstall_user(home=tmp_path / "home", run=run)
    assert run.systemctl == [["systemctl", "--user", "disable", "--now", *services.USER_UNITS],
                             ["systemctl", "--user", "daemon-reload"]]
    assert list((tmp_path / "home" / ".config" / "systemd" / "user").iterdir()) == []


# --- the command line ----------------------------------------------------------------------------


def test_installing_the_agent_without_root_or_a_staging_root_names_sudo(capsys):
    assert services.main(["install-agent", "--operator", "alice"]) == 1
    assert "sudo /usr/bin/python3 -I tools/services.py install-agent" in capsys.readouterr().err


@system_python
def test_the_command_line_installs_and_uninstalls_under_a_staging_root(real_bundle, tmp_path,
                                                                        monkeypatch):
    monkeypatch.setattr(services, "BUNDLE", real_bundle)
    me = services.pwd.getpwuid(os.getuid()).pw_name
    assert services.main(["install-agent", "--operator", me, "--root", str(tmp_path),
                          "--no-systemctl"]) == 0
    assert (tmp_path / "opt" / "neonwatch" / "venv").is_dir()
    assert services.main(["uninstall-agent", "--root", str(tmp_path), "--no-systemctl"]) == 0
    assert not (tmp_path / "opt" / "neonwatch").exists()


def test_the_command_line_reports_a_refusal_and_exits_nonzero(tmp_path, monkeypatch, capsys):
    monkeypatch.setattr(services, "BUNDLE", tmp_path / "dist" / "agent")
    monkeypatch.setattr(services, "REPO", tmp_path)
    monkeypatch.setattr(services, "bundle", lambda out: {"wheels": {}})
    assert services.main(["bundle"]) == 0
    assert json.loads(capsys.readouterr().out) == {"wheels": {}}
    assert services.main(["install-user", "--no-systemctl"]) == 1
    assert "is missing" in capsys.readouterr().err


def test_the_command_line_uninstalls_the_user_units(tmp_path, monkeypatch, capsys):
    monkeypatch.setattr(services.Path, "home", lambda: tmp_path)
    assert services.main(["uninstall-user", "--no-systemctl"]) == 0
    assert "removed" in capsys.readouterr().out


# --- scripts/install-agent -----------------------------------------------------------------------

INSTALL = REPO / "scripts" / "install-agent"


def fake(path: Path, body: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("#!/bin/sh\n" + body)
    path.chmod(0o755)


@pytest.fixture
def install_run(tmp_path):
    """Runs a copy of the script in a tmp repo, with python, sudo and systemctl faked on PATH:
    each records its argv to `calls`; `systemctl is-active` succeeds when `active` exists."""
    repo, bin_, calls = tmp_path / "repo", tmp_path / "bin", tmp_path / "calls"
    (repo / "scripts").mkdir(parents=True)
    shutil.copy2(INSTALL, repo / "scripts" / "install-agent")
    record = f'printf "%s\\n" "$(basename "$0") $*" >> {calls}\n'
    fake(repo / ".venv" / "bin" / "python", record)
    fake(bin_ / "sudo", record)
    fake(bin_ / "systemctl", record + f'[ "$1" != is-active ] || [ -e {tmp_path / "active"} ]\n')

    def run(active: bool = False, uid: str | None = None):
        if active:
            (tmp_path / "active").touch()
        if uid is not None:
            fake(bin_ / "id", f'[ "$1" = -u ] && echo {uid} || /usr/bin/id "$@"\n')
        result = subprocess.run([str(repo / "scripts" / "install-agent")], capture_output=True,
                                text=True, env={"PATH": f"{bin_}:/usr/bin:/bin"})
        logged = calls.read_text().splitlines() if calls.exists() else []
        return result, logged, repo
    return run


def test_the_install_script_bundles_as_you_installs_with_sudo_and_starts_a_stopped_unit(
        install_run):
    me = services.pwd.getpwuid(os.getuid()).pw_name
    result, calls, repo = install_run()
    assert result.returncode == 0, result.stderr
    unit = f"neonwatch-agent@{me}.service"
    assert calls == [
        f"python {repo}/tools/services.py bundle",
        f"sudo /usr/bin/python3 -I {repo}/tools/services.py install-agent --operator {me}",
        f"systemctl is-active --quiet {unit}",
        f"sudo systemctl start {unit}",
        f"systemctl status --no-pager --lines=5 {unit}"]
    assert f"journalctl -u {unit} -f" in result.stdout


def test_the_install_script_leaves_a_running_unit_to_the_install_to_restart(install_run):
    result, calls, _ = install_run(active=True)
    assert result.returncode == 0
    assert not [c for c in calls if c.startswith("sudo systemctl")]


def test_the_install_script_refuses_root(install_run):
    result, calls, _ = install_run(uid="0")
    assert result.returncode == 1 and "not as root" in result.stderr and calls == []


def test_the_install_script_needs_the_venv(install_run, tmp_path):
    (tmp_path / "repo" / ".venv" / "bin" / "python").unlink()
    result, calls, _ = install_run()
    assert result.returncode == 1 and "uv sync" in result.stderr and calls == []


def test_the_install_script_stops_at_the_first_failure(install_run, tmp_path):
    fake(tmp_path / "repo" / ".venv" / "bin" / "python", "exit 3\n")
    result, calls, _ = install_run()
    assert result.returncode == 3 and calls == []   # bundle failed: nothing reached sudo


UNINSTALL = REPO / "scripts" / "uninstall-agent"


def run_uninstall(tmp_path: Path, uid: str | None = None):
    repo, bin_, calls = tmp_path / "repo", tmp_path / "bin", tmp_path / "calls"
    (repo / "scripts").mkdir(parents=True, exist_ok=True)
    shutil.copy2(UNINSTALL, repo / "scripts" / "uninstall-agent")
    fake(bin_ / "sudo", f'printf "%s\\n" "sudo $*" >> {calls}\n')
    if uid is not None:
        fake(bin_ / "id", f'[ "$1" = -u ] && echo {uid} || /usr/bin/id "$@"\n')
    result = subprocess.run([str(repo / "scripts" / "uninstall-agent")], capture_output=True,
                            text=True, env={"PATH": f"{bin_}:/usr/bin:/bin"})
    return result, calls.read_text().splitlines() if calls.exists() else [], repo


def test_the_uninstall_script_asks_sudo_to_run_the_isolated_uninstall(tmp_path):
    result, calls, repo = run_uninstall(tmp_path)
    assert result.returncode == 0, result.stderr
    assert calls == [f"sudo /usr/bin/python3 -I {repo}/tools/services.py uninstall-agent"]
    assert "scripts/neonwatch-agent" in result.stdout


def test_the_uninstall_script_refuses_root(tmp_path):
    result, calls, _ = run_uninstall(tmp_path, uid="0")
    assert result.returncode == 1 and "not as root" in result.stderr and calls == []


@pytest.mark.parametrize("script", [INSTALL, UNINSTALL])
def test_the_scripts_are_executable_posix_shell_that_stop_on_the_first_error(script):
    text = script.read_text()
    assert text.startswith("#!/bin/sh\n") and "\nset -eu\n" in text
    assert os.access(script, os.X_OK)
    assert "sudo /usr/bin/python3 -I " in text      # root runs the system python, isolated
