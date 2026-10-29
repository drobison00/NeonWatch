"""The NATS broker for manual mode: its config, its per-role credentials, and the policy as data.

The broker is what makes "the agent can only publish observations" true. Each role connects as
its own user, and the server refuses every subject outside that user's allow lists.

Files, all under `config.broker.state_dir` (0700):
    nats-server.conf        the rendered server config (0600), rewritten on every `init`
    <role>.creds.json       `{"user": "<role>", "password": "..."}` (0600), kept across starts
    data/                   the JetStream store

The agent runs as root (`sudo neonwatch agent`) but reads its credential from the *invoking
user's* state dir: with the default config that is
`~<user>/.local/state/neonwatch/broker/agent.creds.json`, i.e. `/home/<user>/...`, not `/root/...`.
Root reads it through DAC override; the file stays owned by the user who runs the broker. This
module never guesses which user that is: the caller passes a config whose `state_dir` names it.
The agent finds the file with `paths(config).creds[Role.AGENT]` and never calls `init`.

Contract with the clients (`bus`), measured against nats-server v2.15.0:
- A role's inbox prefix is `_INBOX.<user>` (`inbox_prefix`); connect with it, or even publish
  acks are refused. A shared `_INBOX.>` grant would let any role read messages JetStream
  delivers to another role's pull inbox — measured, and pinned in the tests.
- Consumers are pull consumers with fixed durable names (`evaluator` on `obs.>`, `evaluator-hb`
  on `hb.>`, `viewer`, `notifier` on `issue.>`), bound with `stream="NEONWATCH"` (no STREAM.NAMES
  lookup is granted). The filter a role may read is in
  the create subject, `$JS.API.CONSUMER.CREATE.NEONWATCH.<name>.<filter>`, and the server checks
  it against the request body (err 10131) and refuses multi-filter bodies there (err 10137).
"""

from __future__ import annotations

import json
import os
import re
import secrets
import signal
import subprocess
from collections.abc import Mapping
from dataclasses import dataclass
from enum import Enum
from pathlib import Path

from neonwatch.config import Config, ConfigError, creds_file
from neonwatch.schema import SUBJECT, Kind

STREAM = "NEONWATCH"
#: Every event kind's subjects, all held by the one stream.
SUBJECTS = tuple(f"{prefix}.>" for prefix in SUBJECT.values())
CONFIG_FILE = "nats-server.conf"
#: The JetStream store limit, relative to the stream's retention limit: room for the stream's
#: own overhead and its consumers' state, so retention and not the store decides what is dropped.
HEADROOM = 5 / 4

_API = "$JS.API"
_URL = re.compile(r"^nats://127\.0\.0\.1:(\d{1,5})$")
_PASSWORD = re.compile(r"^[A-Za-z0-9_-]{43,}$")  # secrets.token_urlsafe(32) and longer


class BrokerError(ValueError):
    """The broker's config, credentials or inputs are not something this version accepts."""


class Role(Enum):
    AGENT = "agent"          # the root observer: publishes observations and heartbeats
    EVALUATOR = "evaluator"  # reads observations; publishes findings, attestations, issues, links
    VIEWER = "viewer"        # the web dashboard: reads the stream
    NOTIFIER = "notifier"    # desktop notifications: reads issues


@dataclass(frozen=True, slots=True)
class Permissions:
    """What a role may publish and subscribe to. Everything else is denied by the server."""

    publish: tuple[str, ...]
    subscribe: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class Paths:
    state_dir: Path
    config_file: Path
    store_dir: Path
    creds: Mapping[Role, Path]


def _all(*kinds: Kind) -> tuple[str, ...]:
    return tuple(f"{SUBJECT[kind]}.>" for kind in kinds)


#: The event kinds each role publishes. A kind listed for no role is published by nobody.
_PUBLISHES: dict[Role, tuple[str, ...]] = {
    Role.AGENT: _all(Kind.OBSERVATION, Kind.HEARTBEAT),
    Role.EVALUATOR: _all(Kind.FINDING, Kind.ATTESTATION, Kind.ISSUE, Kind.LINK),
    Role.VIEWER: (),
    Role.NOTIFIER: (),
}
#: Each role's durable consumers, as (name, the one filter it may read); `>` is the whole stream.
#: The evaluator's second durable reads heartbeats: a missing or late one is the alarm for "the
#: machine stopped reporting".
_READS: dict[Role, tuple[tuple[str, str], ...]] = {
    Role.EVALUATOR: (("evaluator", *_all(Kind.OBSERVATION)),
                     ("evaluator-hb", *_all(Kind.HEARTBEAT))),
    Role.VIEWER: (("viewer", ">"),),
    Role.NOTIFIER: (("notifier", *_all(Kind.ISSUE)),),
}
#: Stream management, granted to the evaluator alone: the service creates the stream at start.
#: No role may delete or purge it, or read single messages around a consumer (MSG.GET, DIRECT).
_MANAGES: dict[Role, tuple[str, ...]] = {
    Role.EVALUATOR: tuple(f"{_API}.STREAM.{verb}.{STREAM}"
                          for verb in ("CREATE", "UPDATE", "INFO")),
}


def inbox_prefix(role: Role) -> str:
    """The inbox prefix a role's client must connect with."""
    return f"_INBOX.{role.value}"


def permissions(role: Role) -> Permissions:
    if not isinstance(role, Role):
        raise BrokerError(f"unknown role {role!r}")
    publish = list(_PUBLISHES[role]) + list(_MANAGES.get(role, ()))
    for name, where in _READS.get(role, ()):
        # nats-py sends no filter token for `>`, so the whole-stream reader gets both forms.
        creates = ((f"{_API}.CONSUMER.CREATE.{STREAM}.{name}",
                    f"{_API}.CONSUMER.CREATE.{STREAM}.{name}.>") if where == ">"
                   else (f"{_API}.CONSUMER.CREATE.{STREAM}.{name}.{where}",))
        publish += [f"{_API}.CONSUMER.INFO.{STREAM}.{name}", *creates,
                    f"{_API}.CONSUMER.MSG.NEXT.{STREAM}.{name}",
                    f"$JS.ACK.{STREAM}.{name}.>"]
    return Permissions(publish=tuple(publish), subscribe=(f"{inbox_prefix(role)}.>",))


def _port(url: str) -> int:
    match = _URL.match(url)
    if not match or not 1 <= int(match[1]) <= 65535:
        raise BrokerError(f"broker.url must be nats://127.0.0.1:<port>, got {url!r}")
    return int(match[1])


def render_config(config: Config, passwords: Mapping[Role, str]) -> str:
    """The nats-server config: one loopback client listener, JetStream, one user per role."""
    port = _port(config.broker.url)
    if set(passwords) != set(Role):
        raise BrokerError("render_config needs exactly one password per role")
    if not all(isinstance(p, str) and _PASSWORD.match(p) for p in passwords.values()):
        raise BrokerError("a password is not a strong url-safe token")
    users = []
    for role in Role:
        allowed = permissions(role)
        users.append(
            f"    {{user: {json.dumps(role.value)}, password: {json.dumps(passwords[role])}, "
            f"permissions: {{publish: {{allow: {json.dumps(list(allowed.publish))}}}, "
            f"subscribe: {{allow: {json.dumps(list(allowed.subscribe))}}}}}}}"
        )
    store = paths(config).store_dir
    return "\n".join([
        "# Written by neonwatch.broker on every start; edits are overwritten.",
        f'listen: "127.0.0.1:{port}"',
        "jetstream {",
        f"  store_dir: {json.dumps(str(store))}",
        f"  max_file_store: {int(config.retention.max_bytes * HEADROOM)}",
        "}",
        "authorization {",
        "  users = [",
        ",\n".join(users),
        "  ]",
        "}",
        "",
    ])


def _write_private(path: Path, text: str) -> None:
    """Replace `path` with `text`, mode 0600, never leaving a partial file in its place."""
    tmp = path.with_name(path.name + ".tmp")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "w") as out:
        os.fchmod(out.fileno(), 0o600)
        out.write(text)
    os.replace(tmp, path)


def _read_password(path: Path, role: Role) -> str:
    try:
        creds = json.loads(path.read_text())
    except json.JSONDecodeError:
        raise BrokerError(f"{path}: not JSON; rotate to replace it") from None
    if (not isinstance(creds, dict) or set(creds) != {"user", "password"}
            or creds["user"] != role.value or not isinstance(creds["password"], str)
            or not _PASSWORD.match(creds["password"])):
        raise BrokerError(f"{path}: not a {role.value} credential; rotate to replace it")
    return creds["password"]


def paths(config: Config) -> Paths:
    """Where `init` puts everything, computed only: nothing is created, read, written or chmod-ed.

    The root agent uses this to find its creds file, and never calls `init`: as root, `init` would
    leave root-owned files in the operator's state dir.
    """
    state = Path(config.broker.state_dir).expanduser()
    return Paths(state_dir=state, config_file=state / CONFIG_FILE, store_dir=state / "data",
                 creds={role: creds_file(state, role.value) for role in Role})


def init(config: Config, rotate: bool = False) -> Paths:
    """Create the state dir, keep (or with `rotate`, replace) each role's credential, and write
    the server config. Safe to run on every start."""
    where = paths(config)
    where.state_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
    os.chmod(where.state_dir, 0o700)
    passwords = {}
    for role, path in where.creds.items():
        if path.exists() and not rotate:
            passwords[role] = _read_password(path, role)
            os.chmod(path, 0o600)
        else:
            passwords[role] = secrets.token_urlsafe(32)
            _write_private(path, json.dumps({"user": role.value, "password": passwords[role]}))
    _write_private(where.config_file, render_config(config, passwords))
    return where


def run(config: Config) -> int:
    """Init, then run nats-server in the foreground, forwarding SIGINT and SIGTERM to it.

    Returns its exit code, or 128 + N when it was killed by signal N.
    """
    where = init(config)
    try:
        server = subprocess.Popen([config.broker.binary, "-c", str(where.config_file)])
    except OSError as bad:
        raise ConfigError(f"cannot run broker.binary {config.broker.binary!r} ({bad.strerror}): "
                          f"run scripts/fetch-nats-server, and start the broker from the "
                          f"repository root, which the default path is relative to") from None

    def forward(signum: int, _frame: object) -> None:
        server.send_signal(signum)

    previous = {sig: signal.signal(sig, forward) for sig in (signal.SIGINT, signal.SIGTERM)}
    try:
        code = server.wait()
    finally:
        for sig, handler in previous.items():
            signal.signal(sig, handler)
    return code if code >= 0 else 128 - code
