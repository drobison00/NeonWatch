"""The launcher: who may run what, where the root agent looks, and the wrapper that starts it.

Nothing here runs as root. The agent's checks are exercised with an injected uid, environment,
passwd lookup and interpreter flags; the wrapper runs from a tmp copy against a fake python.
"""

from __future__ import annotations

import asyncio
import os
import pwd
import re
import shutil
import signal
import subprocess
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

from neonwatch import broker, launch
from neonwatch.bus import BusError
from neonwatch.config import Config
from neonwatch.launch import Invoker, Role, WrongUser, invoking_user, require_uid, resolve_home

REPO = Path(__file__).resolve().parent.parent
WRAPPER = REPO / "scripts" / "neonwatch-agent"
ISOLATED = SimpleNamespace(isolated=1)


def passwd(name: str = "alice", uid: int = 1000, home: str = "/home/alice"):
    def getpwnam(wanted: str):
        if wanted != name:
            raise KeyError(wanted)
        return SimpleNamespace(pw_name=name, pw_uid=uid, pw_dir=home)
    return getpwnam


SUDO = {"SUDO_UID": "1000", "SUDO_USER": "alice"}


# --- require_uid ---------------------------------------------------------------------------------


@pytest.mark.parametrize("role", [Role.BROKER, Role.SERVICE])
def test_the_broker_and_service_refuse_root_and_accept_a_user(role):
    require_uid(role, 1000)
    with pytest.raises(WrongUser, match="root"):
        require_uid(role, 0)


def test_the_agent_requires_root_and_refuses_anyone_else():
    require_uid(Role.AGENT, 0)
    for uid in (1, 1000, 65534):
        with pytest.raises(WrongUser, match="sudo"):
            require_uid(Role.AGENT, uid)


def test_require_uid_refuses_what_is_not_a_role():
    with pytest.raises(ValueError):
        require_uid("agent", 0)  # type: ignore[arg-type]


# --- the invoking user ---------------------------------------------------------------------------


def test_the_invoking_user_comes_from_sudo_and_the_password_database():
    assert invoking_user(SUDO, passwd()) == Invoker(1000, "alice", Path("/home/alice"))


@pytest.mark.parametrize("environ, why", [
    ({}, "sudo"),
    ({"SUDO_UID": "1000"}, "sudo"),
    ({"SUDO_USER": "alice"}, "sudo"),
    ({"SUDO_UID": "", "SUDO_USER": "alice"}, "sudo"),
    ({"SUDO_UID": "10x0", "SUDO_USER": "alice"}, "not a uid"),
    ({"SUDO_UID": "0", "SUDO_USER": "root"}, "root"),
    ({"SUDO_UID": "1000", "SUDO_USER": "mallory"}, "no such user"),
    ({"SUDO_UID": "1001", "SUDO_USER": "alice"}, "inconsistent"),
])
def test_missing_or_inconsistent_sudo_variables_are_refused(environ, why):
    with pytest.raises(WrongUser, match=why):
        invoking_user(environ, passwd())


@pytest.mark.parametrize("home", ["", "relative/home", "/"])
def test_a_home_that_cannot_hold_the_state_dir_is_refused(home):
    with pytest.raises(WrongUser, match="home"):
        invoking_user(SUDO, passwd(home=home))


def test_resolve_home_expands_a_tilde_against_the_given_home_only():
    home = Path("/home/alice")
    assert resolve_home("~/.local/state/x", home) == Path("/home/alice/.local/state/x")
    assert resolve_home("~", home) == home
    assert resolve_home("/srv/neonwatch", home) == Path("/srv/neonwatch")
    assert resolve_home("relative/dir", home) == Path("relative/dir")
    with pytest.raises(WrongUser, match="~root"):
        resolve_home("~root/.ssh", home)


# --- the agent -----------------------------------------------------------------------------------


@pytest.fixture
def ran(monkeypatch):
    """Captures what the agent would run with, instead of connecting anywhere."""
    seen: dict = {}

    def run_agent(config, creds, invoker):
        seen.update(config=config, creds=creds, invoker=invoker)
        return 0
    monkeypatch.setattr(launch, "_run_agent", run_agent)
    monkeypatch.setattr(sys, "dont_write_bytecode", sys.dont_write_bytecode)
    return seen


def agent(argv=(), *, uid=0, environ=SUDO, flags=ISOLATED, home="/home/alice"):
    return launch.main(["agent", *argv], uid=uid, environ=environ, flags=flags,
                       getpwnam=passwd(home=home), home=Path("/nonexistent-caller-home"))


def test_the_agent_refuses_to_run_outside_isolated_mode_and_names_the_wrapper(ran, capsys):
    assert agent(flags=SimpleNamespace(isolated=0)) == 1
    err = capsys.readouterr().err
    assert "scripts/neonwatch-agent" in err and "isolated" in err
    assert ran == {}


def test_the_agent_stops_writing_bytecode_first_thing(ran, monkeypatch):
    monkeypatch.setattr(sys, "dont_write_bytecode", False)
    agent(flags=SimpleNamespace(isolated=0))
    assert sys.dont_write_bytecode is True


def test_the_agent_refuses_a_user_who_is_not_root(ran, capsys):
    assert agent(uid=1000) == 1
    assert "sudo" in capsys.readouterr().err and ran == {}


def test_the_agent_refuses_to_start_without_sudo_variables(ran, capsys):
    assert agent(environ={}) == 1
    assert "SUDO_UID" in capsys.readouterr().err and ran == {}


def test_the_agent_reads_the_invoking_users_credentials_not_roots(ran, tmp_path):
    assert agent(home=str(tmp_path)) == 0
    assert ran["creds"] == tmp_path / ".local/state/neonwatch/broker/agent.creds.json"
    assert ran["invoker"].name == "alice"
    assert ran["config"] == Config(broker=ran["config"].broker)   # built-in defaults otherwise


def test_the_agent_uses_the_invoking_users_config_file_when_it_exists(ran, tmp_path):
    (tmp_path / ".config" / "neonwatch").mkdir(parents=True)
    (tmp_path / ".config" / "neonwatch" / "config.toml").write_text(
        '[broker]\nstate_dir = "~/elsewhere"\nurl = "nats://127.0.0.1:4333"\n')
    assert agent(home=str(tmp_path)) == 0
    assert ran["creds"] == tmp_path / "elsewhere" / "agent.creds.json"
    assert ran["config"].broker.url == "nats://127.0.0.1:4333"


def test_the_agents_config_flag_resolves_a_tilde_against_the_invoking_user(ran, tmp_path):
    (tmp_path / "mine.toml").write_text('[cadence]\nfast = "2m"\n')
    assert agent(["--config", "~/mine.toml"], home=str(tmp_path)) == 0
    assert ran["config"].cadence.fast == 120


def test_the_agent_refuses_a_state_dir_in_someone_elses_home(ran, tmp_path, capsys):
    (tmp_path / "c.toml").write_text('[broker]\nstate_dir = "~root/state"\n')
    assert agent(["--config", str(tmp_path / "c.toml")], home=str(tmp_path)) == 1
    assert "~root" in capsys.readouterr().err


def test_a_config_the_agent_cannot_load_is_a_usage_error(ran, tmp_path, capsys):
    assert agent(["--config", str(tmp_path / "missing.toml")], home=str(tmp_path)) == 2
    assert "no such file" in capsys.readouterr().err


class FakeBus:
    def __init__(self) -> None:
        self.closed = False

    async def publish(self, event):
        return 1

    async def close(self):
        self.closed = True


def test_the_agent_runs_the_closed_catalog_through_the_executor_and_publishes(monkeypatch):
    from neonwatch import bus, collector, executor, probes
    made = {}

    async def connect(url, creds, *, owner):
        made["url"], made["creds"], made["owner"] = url, creds, owner
        made["bus"] = FakeBus()
        return made["bus"]

    class FakeCollector:
        def __init__(self, catalog, execute, publish, clock, budget, cadence, **_):
            made.update(catalog=catalog, execute=execute, publish=publish, budget=budget,
                        cadence=cadence)

        async def run_forever(self, stop):
            asyncio.get_running_loop().call_later(0.05, os.kill, os.getpid(), signal.SIGTERM)
            await asyncio.wait_for(stop.wait(), 5)
            made["stopped"] = True
    monkeypatch.setattr(bus, "connect", connect)
    monkeypatch.setattr(collector, "Collector", FakeCollector)
    config = Config()
    invoker = Invoker(1000, "alice", Path("/home/alice"))
    assert launch._run_agent(config, Path("/x/agent.creds.json"), invoker) == 0
    assert made["catalog"] is probes.CATALOG and made["execute"] is executor.execute
    assert made["publish"] == made["bus"].publish
    assert made["budget"] is config.budget and made["cadence"] is config.cadence
    assert made["url"] == config.broker.url and made["creds"] == Path("/x/agent.creds.json")
    assert made["owner"] == 1000   # the creds file must be the operator's (or root's)
    assert made["stopped"] and made["bus"].closed


def test_the_agent_reports_a_broker_it_cannot_reach(monkeypatch, capsys):
    from neonwatch import bus

    async def refuse(url, creds, *, owner):
        raise BusError("could not connect")
    monkeypatch.setattr(bus, "connect", refuse)
    invoker = Invoker(1000, "alice", Path("/home/alice"))
    assert launch._run_agent(Config(), Path("/x/agent.creds.json"), invoker) == 1
    assert "could not connect" in capsys.readouterr().err


@pytest.fixture
def loads(monkeypatch):
    """Records each config load's path and owner, then loads it for real."""
    seen = []
    real = launch.load

    def load(path, *, owner):
        seen.append((path, owner))
        return real(path, owner=owner)
    monkeypatch.setattr(launch, "load", load)
    return seen


def test_the_agent_reads_its_config_as_owned_by_the_invoking_user(ran, loads, tmp_path):
    (tmp_path / "mine.toml").write_text("")
    assert agent(["--config", "~/mine.toml"], home=str(tmp_path)) == 0
    assert loads == [(tmp_path / "mine.toml", 1000)]


def test_the_broker_reads_its_config_as_owned_by_itself(monkeypatch, loads, tmp_path):
    (tmp_path / "b.toml").write_text("")
    monkeypatch.setattr(broker, "run", lambda config: 0)
    assert launch.main(["broker", "--config", str(tmp_path / "b.toml")], uid=os.getuid(),
                       environ={}, home=tmp_path) == 0
    assert loads == [(tmp_path / "b.toml", os.getuid())]


# --- broker and service --------------------------------------------------------------------------


def test_the_broker_refuses_root(monkeypatch, capsys):
    monkeypatch.setattr(broker, "run", lambda config: pytest.fail("ran as root"))
    assert launch.main(["broker"], uid=0, environ={}, home=Path("/nonexistent")) == 1
    assert "root" in capsys.readouterr().err


def test_the_broker_runs_with_the_default_config_when_there_is_no_file(monkeypatch, tmp_path):
    seen = []
    monkeypatch.setattr(broker, "run", lambda config: seen.append(config) or 7)
    assert launch.main(["broker"], uid=1000, environ={}, home=tmp_path) == 7
    assert seen == [Config()]


def test_the_broker_reads_the_users_config_file_when_it_exists(monkeypatch, tmp_path):
    seen = []
    (tmp_path / ".config" / "neonwatch").mkdir(parents=True)
    (tmp_path / ".config" / "neonwatch" / "config.toml").write_text(
        '[broker]\nurl = "nats://127.0.0.1:4333"\n')
    monkeypatch.setattr(broker, "run", lambda config: seen.append(config) or 0)
    assert launch.main(["broker"], uid=1000, environ={}, home=tmp_path) == 0
    assert seen[0].broker.url == "nats://127.0.0.1:4333"


def test_the_broker_takes_an_explicit_config(monkeypatch, tmp_path):
    seen = []
    (tmp_path / "b.toml").write_text('[broker]\nurl = "nats://127.0.0.1:4444"\n')
    monkeypatch.setattr(broker, "run", lambda config: seen.append(config) or 0)
    assert launch.main(["broker", "--config", str(tmp_path / "b.toml")], uid=1000,
                       environ={}, home=tmp_path) == 0
    assert seen[0].broker.url == "nats://127.0.0.1:4444"


def test_the_service_refuses_root(monkeypatch, capsys):
    from neonwatch import service
    monkeypatch.setattr(service, "main", lambda argv, **_: pytest.fail("ran as root"))
    assert launch.main(["service"], uid=0, environ={}, home=Path("/nonexistent")) == 1
    assert "root" in capsys.readouterr().err


def test_the_service_is_handed_the_resolved_config_path(monkeypatch, tmp_path):
    from neonwatch import service
    seen = []
    monkeypatch.setattr(service, "main",
                        lambda argv, *, uid: seen.append(argv) or (uid == 1000) - 1)
    assert launch.main(["service"], uid=1000, environ={}, home=tmp_path) == 0
    (tmp_path / ".config" / "neonwatch").mkdir(parents=True)
    default = tmp_path / ".config" / "neonwatch" / "config.toml"
    default.write_text("")
    assert launch.main(["service"], uid=1000, environ={}, home=tmp_path) == 0
    assert launch.main(["service", "--config", "/etc/x.toml"], uid=1000, environ={},
                       home=tmp_path) == 0
    assert seen == [[], ["--config", str(default)], ["--config", "/etc/x.toml"]]


def test_a_config_that_does_not_load_is_a_usage_error(tmp_path, capsys):
    (tmp_path / "bad.toml").write_text("[nope]\n")
    assert launch.main(["broker", "--config", str(tmp_path / "bad.toml")], uid=1000,
                       environ={}, home=tmp_path) == 2
    assert "unknown section" in capsys.readouterr().err


# --- hash-password -------------------------------------------------------------------------------


def test_hash_password_refuses_root(monkeypatch, capsys):
    from neonwatch import service
    monkeypatch.setattr(service, "hash_password_command",
                        lambda **_: pytest.fail("ran as root"))
    assert launch.main(["hash-password"], uid=0, environ={}) == 1
    assert "neonwatch hash-password must not run as root" in capsys.readouterr().err


def test_hash_password_prompts_twice_and_prints_one_line(capsys):
    asked = []
    secret = "twelve chars or more"
    assert launch.main(["hash-password"], uid=1000, environ={},
                       ask=lambda prompt: asked.append(prompt) or secret) == 0
    out, err = capsys.readouterr()
    assert asked == ["Dashboard password: ", "The same password again: "]
    assert err == "" and out.count("\n") == 1 and out.startswith('password_hash = "scrypt$')
    # service_test verifies the hash itself; the launcher may not import web, even in a test.
    b64 = "[A-Za-z0-9+/=]+"
    assert re.fullmatch(rf'password_hash = "scrypt\$32768\$8\$1\${b64}\${b64}"\n', out)
    assert secret not in out


@pytest.mark.parametrize("replies, why", [(("twelve chars or more", "something else entirely"),
                                           "differ"),
                                          (("too short", "too short"), "at least 12")])
def test_hash_password_refusals_exit_1_with_nothing_on_stdout(replies, why, capsys):
    queue = list(replies)
    assert launch.main(["hash-password"], uid=1000, environ={},
                       ask=lambda _prompt: queue.pop(0)) == 1
    out, err = capsys.readouterr()
    assert out == "" and why in err


def test_hash_password_takes_no_arguments(capsys):
    assert launch.main(["hash-password", "--config", "x"], uid=1000, environ={}) == 2


def test_hash_password_help_points_at_the_certificate_command(capsys):
    assert launch.main(["hash-password", "--help"], uid=1000, environ={}) == 0
    out = capsys.readouterr().out
    assert "[web]" in out and "README" in out


def test_hash_password_loads_the_web_stack_only_when_run():
    probe = ("import sys, neonwatch.launch as l\n"
             "code = l.main(['hash-password'], uid=1000, environ={}, ask=lambda p: 'x' * 12)\n"
             "assert code == 0, code\n"
             "print('neonwatch.web' in sys.modules)")
    result = subprocess.run([sys.executable, "-I", "-B", "-c", probe], capture_output=True,
                            text=True, check=True, cwd="/")
    assert result.stdout.splitlines()[-1] == "True"


# --- agent-token and mcp -------------------------------------------------------------------------


def token_config(tmp_path: Path) -> Path:
    path = tmp_path / "config.toml"
    path.write_text(f'[store]\npath = "{tmp_path / "state" / "store.sqlite3"}"\n')
    return path


@pytest.mark.parametrize("command", ["agent-token", "mcp"])
def test_agent_token_and_mcp_refuse_root(command, capsys):
    assert launch.main([command], uid=0, environ={}) == 1
    assert f"neonwatch {command} must not run as root" in capsys.readouterr().err


def test_agent_token_makes_then_finds_the_token_without_printing_it(tmp_path, capsys):
    config, me = token_config(tmp_path), os.getuid()
    where = tmp_path / "state" / "agent.token"
    assert launch.main(["agent-token", "--config", str(config)], uid=me, environ={}) == 0
    token = where.read_text().strip()
    assert capsys.readouterr().out == f"made the agent token at {where}\n"
    assert launch.main(["agent-token", "--config", str(config)], uid=me, environ={}) == 0
    out = capsys.readouterr().out
    assert out == f"found the agent token at {where}\n" and token not in out
    assert launch.main(["agent-token", "--show", "--config", str(config)], uid=me,
                       environ={}) == 0
    assert capsys.readouterr().out.splitlines() == [f"found the agent token at {where}", token]


def test_agent_token_rotates(tmp_path, capsys):
    config, me = token_config(tmp_path), os.getuid()
    where = tmp_path / "state" / "agent.token"
    launch.main(["agent-token", "--config", str(config)], uid=me, environ={})
    old = where.read_text().strip()
    capsys.readouterr()
    assert launch.main(["agent-token", "--rotate", "--config", str(config)], uid=me,
                       environ={}) == 0
    new = where.read_text().strip()
    out = capsys.readouterr().out
    assert new != old and new not in out and old not in out
    assert out == f"rotated the agent token at {where}; the old one no longer works\n"
    assert launch.main(["agent-token", "--rotate", "--show", "--config", str(config)], uid=me,
                       environ={}) == 0
    assert capsys.readouterr().out.splitlines()[-1] == where.read_text().strip()


def test_agent_token_refuses_an_unsafe_file(tmp_path, capsys):
    config, me = token_config(tmp_path), os.getuid()
    (tmp_path / "state").mkdir()
    (tmp_path / "state" / "agent.token").symlink_to(tmp_path / "elsewhere")
    for argv in (["agent-token"], ["agent-token", "--rotate", "--show"]):
        assert launch.main([*argv, "--config", str(config)], uid=me, environ={}) == 1
        captured = capsys.readouterr()
        assert captured.out == "" and "neonwatch agent-token:" in captured.err
    assert not (tmp_path / "elsewhere").exists()


def test_mcp_is_handed_the_config_uid_agent_and_environment(monkeypatch, tmp_path):
    from neonwatch import mcp

    seen = []
    monkeypatch.setattr(mcp, "main", lambda config, **kw: seen.append((config, kw)) or 0)
    config = token_config(tmp_path)
    environ = {"NEONWATCH_AGENT": "x"}
    assert launch.main(["mcp", "--agent", "claude", "--config", str(config)], uid=os.getuid(),
                       environ=environ) == 0
    (loaded, kw), = seen
    assert loaded.store.path == str(tmp_path / "state" / "store.sqlite3")
    assert kw == {"uid": os.getuid(), "agent": "claude", "environ": environ}


def test_mcp_loads_no_web_stack_nats_client_or_store(tmp_path):
    config = token_config(tmp_path)
    probe = ("import sys, neonwatch.launch as l\n"
             "code = l.main(['mcp', '--config', sys.argv[1]], uid=sys.argv[2] and "
             "int(sys.argv[2]), environ={})\n"
             "assert code == 0, code\n" + UNWANTED)
    result = subprocess.run([sys.executable, "-I", "-B", "-c", probe, str(config),
                             str(os.getuid())], capture_output=True, text=True, check=True,
                            cwd="/", input="")
    assert result.stdout.strip() == "[]"


# --- argument parsing ----------------------------------------------------------------------------


@pytest.mark.parametrize("argv", [[], ["frobnicate"], ["agent", "--verbose"], ["broker", "x"]])
def test_a_bad_command_line_is_a_usage_error(argv, capsys):
    assert launch.main(argv, uid=1000, environ={}, home=Path("/nonexistent")) == 2


def test_help_exits_cleanly(capsys):
    assert launch.main(["--help"], uid=1000, environ={}) == 0
    assert "broker" in capsys.readouterr().out


def test_main_reads_the_real_process_when_nothing_is_injected(monkeypatch, capsys):
    monkeypatch.setattr(sys, "argv", ["neonwatch", "service"])
    monkeypatch.setattr(os, "getuid", lambda: 0)
    assert launch.main() == 1   # the real argv, uid and environment were read


def test_the_real_password_database_is_the_default_lookup(monkeypatch, capsys):
    me = pwd.getpwuid(os.getuid())
    environ = {"SUDO_UID": str(me.pw_uid), "SUDO_USER": me.pw_name}
    assert invoking_user(environ) == Invoker(me.pw_uid, me.pw_name, Path(me.pw_dir))


# --- what importing the launcher pulls in --------------------------------------------------------


UNWANTED = ("print(sorted(m for m in sys.modules if m.split('.')[0] in ('aiohttp', 'nats') "
            "or m in ('neonwatch.web', 'neonwatch.service', 'neonwatch.store', 'sqlite3', "
            "'neonwatch.broker', 'subprocess')))")


def test_importing_the_launcher_loads_no_web_stack_nats_client_broker_or_subprocess():
    probe = "import sys, neonwatch.launch; " + UNWANTED
    result = subprocess.run([sys.executable, "-I", "-B", "-c", probe], capture_output=True,
                            text=True, check=True, cwd="/")
    assert result.stdout.strip() == "[]"


def test_the_agents_checks_and_config_resolution_load_no_broker_or_subprocess(tmp_path):
    """Everything the agent does before it connects, run as far as a missing config file."""
    probe = (
        "import sys, types, neonwatch.launch as l\n"
        "pw = lambda n: types.SimpleNamespace(pw_uid=1000, pw_dir=sys.argv[1])\n"
        "code = l.main(['agent', '--config', '~/missing.toml'], uid=0, "
        "environ={'SUDO_UID': '1000', 'SUDO_USER': 'alice'}, getpwnam=pw)\n"
        "assert code == 2, code\n" + UNWANTED)
    result = subprocess.run([sys.executable, "-I", "-B", "-c", probe, str(tmp_path)],
                            capture_output=True, text=True, check=True, cwd="/")
    assert "no such file" in result.stderr
    assert result.stdout.strip() == "[]"


def test_the_launcher_runs_as_a_module_and_refuses_a_non_root_agent():
    result = subprocess.run([sys.executable, "-I", "-B", "-m", "neonwatch.launch", "agent"],
                            capture_output=True, text=True, cwd="/", env={})
    assert result.returncode == 1
    assert "sudo" in result.stderr


# --- the wrapper ---------------------------------------------------------------------------------


def test_the_wrapper_is_an_executable_shell_script_that_never_calls_uv():
    text = WRAPPER.read_text()
    assert text.startswith("#!/bin/sh\n")
    assert os.access(WRAPPER, os.X_OK)
    code = [line.strip() for line in text.splitlines() if not line.lstrip().startswith("#")]
    assert "uv run" not in text
    assert not any(line.split()[:1] == ["uv"] for line in code if line)   # no uv command
    assert [line for line in code if line.startswith("exec ")] == [
        'exec "$python" -I -B -m neonwatch.launch agent "$@"']


@pytest.fixture
def repo_copy(tmp_path):
    (tmp_path / "scripts").mkdir()
    shutil.copy2(WRAPPER, tmp_path / "scripts" / "neonwatch-agent")
    return tmp_path


def test_the_wrapper_execs_the_venv_python_isolated_without_bytecode(repo_copy, tmp_path):
    fake = repo_copy / ".venv" / "bin" / "python"
    fake.parent.mkdir(parents=True)
    fake.write_text('#!/bin/sh\nfor a in "$@"; do printf "%s\\n" "$a"; done\n')
    fake.chmod(0o755)
    elsewhere = tmp_path / "cwd"
    elsewhere.mkdir()
    result = subprocess.run([str(repo_copy / "scripts" / "neonwatch-agent"), "--config",
                             "a b.toml"], capture_output=True, text=True, cwd=elsewhere,
                            env={"PATH": "/usr/bin:/bin"}, check=True)
    assert result.stdout.splitlines() == ["-I", "-B", "-m", "neonwatch.launch", "agent",
                                          "--config", "a b.toml"]


def test_the_wrapper_resolves_the_repo_through_a_symlink(repo_copy, tmp_path):
    fake = repo_copy / ".venv" / "bin" / "python"
    fake.parent.mkdir(parents=True)
    fake.write_text('#!/bin/sh\necho "$0"\n')
    fake.chmod(0o755)
    link = tmp_path / "link-to-agent"
    link.symlink_to(repo_copy / "scripts" / "neonwatch-agent")
    result = subprocess.run([str(link)], capture_output=True, text=True,
                            env={"PATH": "/usr/bin:/bin"}, check=True)
    assert result.stdout.strip() == str(fake.resolve())


def test_the_wrapper_refuses_when_the_venv_python_is_missing(repo_copy):
    result = subprocess.run([str(repo_copy / "scripts" / "neonwatch-agent")],
                            capture_output=True, text=True, env={"PATH": "/usr/bin:/bin"})
    assert result.returncode == 1
    assert ".venv/bin/python" in result.stderr and "uv sync" in result.stderr
