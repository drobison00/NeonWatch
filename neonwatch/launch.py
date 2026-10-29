"""The CLI, `neonwatch`: six commands, each refusing the wrong user.

    neonwatch broker  [--config PATH]    as you: runs nats-server for manual mode
    neonwatch service [--config PATH]    as you, in the desktop session: the dashboard and the judge
    neonwatch hash-password              as you: prints a `password_hash = "..."` line for [web]
    neonwatch agent-token [--rotate] [--show] [--config PATH]
                                        as you: makes or rotates the agent API's token
    neonwatch mcp [--agent NAME] [--config PATH]
                                        as you: a stdio MCP server over the agent API
    sudo scripts/neonwatch-agent [--config PATH]    as root: the read-only observer

`agent-token` prints where the token file is and whether it was made, found or rotated, never the
token itself unless `--show` is given. A rotation takes effect at once: the dashboard reads the
file for every agent request. `mcp` speaks JSON-RPC on stdin and stdout for an AI agent's MCP
client and sends `X-Neonwatch-Agent: NAME` (default `$NEONWATCH_AGENT`, else "mcp"). Both import
their modules (`agent_token`, `mcp`) only when they run.

`hash-password` reads the password twice without echo and prints one line to paste into the
`[web]` table; the README has the one-line openssl command for the self-signed certificate that a
LAN dashboard also needs. Its work is in the service module, imported only when it runs.

`--config` defaults to `~/.config/neonwatch/config.toml` when that file exists, else the built-in
defaults.

**The agent** is only ever started by the operator through sudo, and only through
`scripts/neonwatch-agent`, which execs the repository venv's python with `-I -B`: isolated mode
(no user site, no PYTHON* variables, no current directory on the path) and no bytecode writes.
`uv run` is never used as root, because it would sync the venv and write caches as root. So
`neonwatch agent` stops writing bytecode first thing, refuses unless the interpreter is isolated,
refuses unless it is root, and refuses unless SUDO_UID and SUDO_USER name one real user. It then
reads that user's config (`~` meaning their home, never /root) and their broker state dir for
the AGENT credential, which it finds with `config.creds_file`: computed, never created, because
the agent writes nothing to the host. Both are read as owned by that user (or root): `config.load`
and `bus.connect` refuse a file anyone else owns, a symlink, or a non-regular file. It logs to
stderr only: no log file, pid file or state.

This module imports only config at load time. The broker (which starts processes), the service
(aiohttp, SQLite) and the agent's own modules (nats, the collector, asyncio) are imported by the
command that needs them, so the root agent never loads the broker or the web stack, and nothing
before it connects loads `subprocess`.
"""

from __future__ import annotations

import argparse
import dataclasses
import enum
import logging
import os
import pwd
import signal
import sys
import time
from collections.abc import Callable, Mapping
from pathlib import Path
from typing import Any

from neonwatch.config import Config, ConfigError, creds_file, load

CONFIG = Path(".config") / "neonwatch" / "config.toml"
WRAPPER = "sudo scripts/neonwatch-agent"

log = logging.getLogger("neonwatch.agent")


class WrongUser(Exception):
    """This command may not run as this user, or cannot tell which user started it."""


class Role(enum.Enum):
    BROKER = "broker"
    SERVICE = "service"
    HASH_PASSWORD = "hash-password"
    AGENT_TOKEN = "agent-token"
    MCP = "mcp"
    AGENT = "agent"


def require_uid(role: Role, uid: int) -> None:
    """The agent runs as root and nothing else does."""
    if not isinstance(role, Role):
        raise ValueError(f"unknown role {role!r}")
    if role is Role.AGENT:
        if uid != 0:
            raise WrongUser(f"the agent must run as root, and only through the wrapper: "
                            f"{WRAPPER}")
    elif uid == 0:
        raise WrongUser(f"neonwatch {role.value} must not run as root; run it as yourself")


@dataclasses.dataclass(frozen=True, slots=True)
class Invoker:
    """The operator who ran sudo."""

    uid: int
    name: str
    home: Path


def invoking_user(environ: Mapping[str, str],
                  getpwnam: Callable[[str], Any] = pwd.getpwnam) -> Invoker:
    """Who ran sudo, from SUDO_UID and SUDO_USER, checked against the password database."""
    raw, name = environ.get("SUDO_UID", ""), environ.get("SUDO_USER", "")
    if not raw or not name:
        raise WrongUser(f"SUDO_UID and SUDO_USER are not both set; the agent is started only by "
                        f"the operator, with {WRAPPER}")
    if not raw.isdigit():
        raise WrongUser(f"SUDO_UID={raw!r} is not a uid")
    uid = int(raw)
    if uid == 0:
        raise WrongUser(f"sudo was run by root; run {WRAPPER} from the operator's own account")
    try:
        entry = getpwnam(name)
    except KeyError:
        raise WrongUser(f"SUDO_USER={name!r}: no such user") from None
    if entry.pw_uid != uid:
        raise WrongUser(f"SUDO_USER={name!r} has uid {entry.pw_uid}, but SUDO_UID={uid}: "
                        f"inconsistent, refusing to guess")
    home = Path(entry.pw_dir)
    if not home.is_absolute() or home == Path("/"):
        raise WrongUser(f"user {name!r} has home {entry.pw_dir!r}, which cannot hold "
                        f"their neonwatch state")
    return Invoker(uid, name, home)


def resolve_home(path: str, home: Path) -> Path:
    """`path` with a leading `~` meaning `home`. `~user` is refused: only one home is meant."""
    if path == "~":
        return home
    if path.startswith("~/"):
        return home / path[2:]
    if path.startswith("~"):
        raise WrongUser(f"{path!r} names another user's home; only ~ (the invoking user's) is "
                        f"accepted")
    return Path(path)


def _default_config(home: Path) -> Path | None:
    candidate = home / CONFIG
    return candidate if candidate.is_file() else None


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="neonwatch", description="NeonWatch, a read-only workstation health monitor.")
    commands = parser.add_subparsers(dest="command", required=True, metavar="COMMAND")
    for name, what in (("broker", "run the NATS broker for manual mode (as yourself)"),
                       ("service", "run the dashboard and evaluator (as yourself)"),
                       ("agent", f"the root observer; start it with {WRAPPER}")):
        command = commands.add_parser(name, help=what)
        command.add_argument("--config", metavar="PATH",
                             help=f"the config file (default: ~/{CONFIG} if it exists)")
    commands.add_parser(
        "hash-password", help="print a password_hash line for the [web] table (as yourself)",
        description="Reads the dashboard password twice, without echo, and prints one line, "
                    "password_hash = \"scrypt$...\", to paste into the [web] table of the "
                    "config. A dashboard on the LAN also needs tls_cert, tls_key and "
                    "allowed_hosts; the README has the openssl command for a self-signed "
                    "certificate.")
    token = commands.add_parser(
        "agent-token", help="make or rotate the agent API's token (as yourself)",
        description="Makes the agent API's token file beside the store when it is missing, "
                    "and says where it is. The token is printed only with --show.")
    token.add_argument("--rotate", action="store_true",
                       help="replace the token; the old one stops working at once")
    token.add_argument("--show", action="store_true", help="print the token")
    token.add_argument("--config", metavar="PATH",
                       help=f"the config file (default: ~/{CONFIG} if it exists)")
    mcp = commands.add_parser(
        "mcp", help="a stdio MCP server over the dashboard's agent API (as yourself)",
        description="Speaks MCP (JSON-RPC on stdin and stdout) for an AI agent, and calls the "
                    "running dashboard's agent API on loopback with the agent token.")
    mcp.add_argument("--agent", metavar="NAME",
                     help="the name the agent's actions are recorded under (default: "
                          "$NEONWATCH_AGENT, else mcp)")
    mcp.add_argument("--config", metavar="PATH",
                     help=f"the config file (default: ~/{CONFIG} if it exists)")
    return parser


def main(argv: list[str] | None = None, *, uid: int | None = None,
         environ: Mapping[str, str] | None = None, flags: Any = None,
         getpwnam: Callable[[str], Any] | None = None, home: Path | None = None,
         ask: Callable[[str], str] | None = None) -> int:
    argv = sys.argv[1:] if argv is None else list(argv)
    if argv[:1] == ["agent"]:
        sys.dont_write_bytecode = True   # before anything else can be imported as root
    try:
        args = _parser().parse_args(argv)
    except SystemExit as done:
        return int(done.code or 0)
    uid = os.getuid() if uid is None else uid
    environ = os.environ if environ is None else environ
    try:
        if args.command == "agent":
            return _agent(args.config, uid, environ, sys.flags if flags is None else flags,
                          getpwnam or pwd.getpwnam)
        role = Role(args.command)
        require_uid(role, uid)
        if role is Role.HASH_PASSWORD:
            return _hash_password(ask)
        home = Path.home() if home is None else home
        path = (Path(args.config).expanduser() if args.config is not None
                else _default_config(home))
        if role is Role.SERVICE:
            return _service(path, uid)
        if role is Role.AGENT_TOKEN:
            return _agent_token(path, uid, args.rotate, args.show)
        if role is Role.MCP:
            return _mcp(path, uid, args.agent, environ)
        return _broker(path, uid)
    except WrongUser as refused:
        print(f"neonwatch {args.command}: {refused}", file=sys.stderr)
        return 1
    except ConfigError as bad:
        print(f"neonwatch {args.command}: {bad}", file=sys.stderr)
        return 2


def _service(path: Path | None, uid: int) -> int:
    from neonwatch import service  # aiohttp and SQLite load here, never in the agent

    return service.main(["--config", str(path)] if path is not None else [], uid=uid)


def _hash_password(ask: Callable[[str], str] | None) -> int:
    from neonwatch import service  # the web stack loads here, never in the agent

    return service.hash_password_command(ask=ask)


def _agent_token(path: Path | None, uid: int, rotate: bool, show: bool) -> int:
    from neonwatch import agent_token  # it writes the token file; never imported by the agent

    config = load(path, owner=uid)
    where = agent_token.path(config)
    try:
        if rotate:
            token = agent_token.rotate(where, uid)
            print(f"rotated the agent token at {where}; the old one no longer works")
        else:
            token, made = agent_token.ensure(where, uid)
            print(f"{'made' if made else 'found'} the agent token at {where}")
    except (agent_token.TokenError, OSError) as bad:
        print(f"neonwatch agent-token: {bad}", file=sys.stderr)
        return 1
    if show:
        print(token)
    return 0


def _mcp(path: Path | None, uid: int, agent: str | None, environ: Mapping[str, str]) -> int:
    from neonwatch import mcp  # an HTTP client; never imported by the agent

    return mcp.main(load(path, owner=uid), uid=uid, agent=agent, environ=environ)


def _broker(path: Path | None, uid: int) -> int:
    from neonwatch import broker  # it starts nats-server; never imported by the agent

    config = load(path, owner=uid)
    _log_to_stderr()
    return broker.run(config)


def _agent(config_arg: str | None, uid: int, environ: Mapping[str, str], flags: Any,
           getpwnam: Callable[[str], Any]) -> int:
    sys.dont_write_bytecode = True
    if not flags.isolated:
        raise WrongUser(f"refusing to run outside Python's isolated mode (-I); start the agent "
                        f"with {WRAPPER}, which runs the venv's python -I -B")
    require_uid(Role.AGENT, uid)
    invoker = invoking_user(environ, getpwnam)
    path = (resolve_home(config_arg, invoker.home) if config_arg is not None
            else _default_config(invoker.home))
    config = load(path, owner=invoker.uid)   # no symlink, regular, small, the operator's
    state = resolve_home(config.broker.state_dir, invoker.home)
    config = dataclasses.replace(
        config, broker=dataclasses.replace(config.broker, state_dir=str(state)))
    creds = creds_file(state, "agent")   # the broker's AGENT role; found, never created
    _log_to_stderr()
    return _run_agent(config, creds, invoker)


def _log_to_stderr() -> None:
    logging.basicConfig(stream=sys.stderr, level=logging.INFO,
                        format="%(asctime)s %(levelname)s %(name)s: %(message)s")


def _run_agent(config: Config, creds: Path, invoker: Invoker) -> int:
    """Connect as the AGENT role and run the collector until SIGINT or SIGTERM."""
    import asyncio  # loads subprocess (asyncio.subprocess); not needed before this point

    from neonwatch import bus, collector, executor, probes

    async def observe() -> int:
        stop = asyncio.Event()
        loop = asyncio.get_running_loop()
        for sig in (signal.SIGINT, signal.SIGTERM):
            loop.add_signal_handler(sig, stop.set)
        try:
            connection = await bus.connect(config.broker.url, creds, owner=invoker.uid)
        except bus.BusError as bad:
            print(f"neonwatch agent: {bad}", file=sys.stderr)
            return 1
        try:
            log.info("observing for %s (uid %d): %d probes, publishing to %s with %s",
                     invoker.name, invoker.uid, len(probes.CATALOG), config.broker.url, creds)
            observer = collector.Collector(probes.CATALOG, executor.execute, connection.publish,
                                           time.time, config.budget, config.cadence)
            await observer.run_forever(stop)
        finally:
            await connection.close()
        log.info("stopped")
        return 0

    return asyncio.run(observe())


if __name__ == "__main__":
    sys.exit(main())
