"""The one config file, loaded and validated. Defaults are complete: no file is a valid config.

Unknown sections or keys refuse, so a typo is an error rather than a default nobody chose. A few
values refuse on principle rather than type: the web server binds only to loopback, and the CPU
budget cannot be set above 5%.
"""

from __future__ import annotations

import dataclasses
import ipaddress
import os
import re
import stat
import tomllib
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit


class ConfigError(ValueError):
    """The config file does not say something this version accepts."""


@dataclass(frozen=True, slots=True)
class Cadence:
    """Seconds between runs of each probe tier, and between collations."""

    fast: int = 60
    medium: int = 300
    slow: int = 3600
    daily: int = 86400
    collate: int = 300


@dataclass(frozen=True, slots=True)
class Budget:
    #: Fraction of one CPU, averaged over a day, the agent may spend. 0.01 is 1%.
    cpu_fraction: float = 0.01


@dataclass(frozen=True, slots=True)
class Broker:
    url: str = "nats://127.0.0.1:4222"
    #: Where the broker's config, data and per-role credentials live. Created by `neonwatch broker`.
    state_dir: str = "~/.local/state/neonwatch/broker"
    binary: str = ".tools/nats-server"


@dataclass(frozen=True, slots=True)
class JudgeServer:
    """The judge: a typed-decision model server (docs/judge-protocol.md). Optional.

    `name` is how the dashboard and the APIs refer to it ("local-judge", "Qwen 7B judge"), so a
    badge or a vital says which model at which endpoint answered; each attestation records it.
    `model` is sent in every request, for a server that hosts several.
    """

    name: str = "Judge"
    url: str = "http://127.0.0.1:8200/v1/systemone"
    model: str = "judge"
    #: Requests in flight at once. Measured 2026-09-30 on one judge server: it answered requests
    #: one after another (~80 ms per question, ~12 questions/s however they were arranged), so
    #: more than a couple in flight only queues on a shared server. Pack questions instead.
    concurrency: int = 2
    #: Questions packed into one request, before the context budget splits it further.
    max_questions_per_request: int = 24
    #: Characters of state per request; sized for a model with a 16K-token context.
    max_state_chars: int = 24000
    timeout_s: float = 60.0


@dataclass(frozen=True, slots=True)
class Retention:
    """Whichever limit is reached first."""

    max_age_s: int = 7 * 86400
    max_bytes: int = 10 * 1024**3


@dataclass(frozen=True, slots=True)
class Notify:
    enabled: bool = True
    min_severity: str = "critical"
    #: Seconds before the same issue may notify again for a new state.
    rate_limit_s: int = 300


@dataclass(frozen=True, slots=True)
class Web:
    """The dashboard. Loopback by default; a LAN address only with TLS, a password and Host names.

    `password_hash` is an scrypt string made by `neonwatch hash-password`, never the password.
    `allowed_hosts` lists the exact `Host` values the dashboard answers (`name:port`), which is
    what keeps DNS rebinding out once it listens beyond loopback.
    """

    host: str = "127.0.0.1"
    port: int = 8765
    tls_cert: str = ""
    tls_key: str = ""
    password_hash: str = ""
    allowed_hosts: tuple[str, ...] = ()
    #: How long a login lasts.
    session_s: int = 12 * 3600
    #: The Board view's motherboard: a built-in layout's name, or a path to a TOML layout
    #: (docs/board-layouts.md).
    board: str = "atx"


@dataclass(frozen=True, slots=True)
class Analyst:
    """The backend LLM for manual analysis. Disabled until `provider` and `model` are set."""

    #: "" (disabled), "openai-compatible" or "anthropic".
    provider: str = ""
    #: The endpoint. For openai-compatible, the base that `/chat/completions` hangs off.
    base_url: str = ""
    model: str = ""
    #: The NAME of the environment variable holding the key, read by the service at startup.
    #: Never the key itself: nothing in the config, the store or a log may hold it.
    api_key_env: str = ""
    max_input_chars: int = 60000
    max_output_tokens: int = 2000
    #: How far a request may go: "local" (loopback only: nothing leaves the machine), "lan"
    #: (also private and link-local IP addresses), or "remote" (anywhere). Only loopback and a
    #: keyless LAN endpoint may be plain http; everything else needs https.
    reach: str = "local"
    #: openai-compatible only: sent as `reasoning_effort` when set ("low", "medium", "high").
    #: A reasoning model left at its own default can spend the whole token budget thinking.
    reasoning_effort: str = ""
    timeout_s: float = 120.0


@dataclass(frozen=True, slots=True)
class Store:
    path: str = "~/.local/state/neonwatch/store.sqlite3"


@dataclass(frozen=True, slots=True)
class Config:
    cadence: Cadence = field(default_factory=Cadence)
    budget: Budget = field(default_factory=Budget)
    broker: Broker = field(default_factory=Broker)
    judge: JudgeServer = field(default_factory=JudgeServer)
    retention: Retention = field(default_factory=Retention)
    notify: Notify = field(default_factory=Notify)
    web: Web = field(default_factory=Web)
    store: Store = field(default_factory=Store)
    analyst: Analyst = field(default_factory=Analyst)


#: For the positive-and-finite checks (a chained `0 < x < inf` also refuses NaN).
_INFINITY = float("inf")
_DURATION = re.compile(r"^(\d+)\s*(s|m|h|d|w)$")
_SECONDS = {"s": 1, "m": 60, "h": 3600, "d": 86400, "w": 604800}
_SIZE = re.compile(r"^(\d+(?:\.\d+)?)\s*(B|KB|MB|GB|TB|KiB|MiB|GiB|TiB)$")
_BYTES = {"B": 1, "KB": 10**3, "MB": 10**6, "GB": 10**9, "TB": 10**12,
          "KiB": 1024, "MiB": 1024**2, "GiB": 1024**3, "TiB": 1024**4}
_SEVERITIES = ("info", "watch", "warn", "critical")


def creds_file(state_dir: Path, role: str) -> Path:
    """Where the broker keeps `role`'s credentials: `<state_dir>/<role>.creds.json`.

    The one place this naming lives. The broker writes these files; the root agent only needs
    to find its own, and must not import the broker (which starts processes) to do it. `role` is
    a broker role name: lower-case letters and hyphens only, so it cannot name another path.
    """
    if not re.fullmatch(r"[a-z]+(?:-[a-z]+)*", role):
        raise ConfigError(f"not a broker role name: {role!r}")
    return Path(state_dir) / f"{role}.creds.json"


#: Largest config file accepted. A real one is a few hundred bytes.
MAX_CONFIG_BYTES = 64 * 1024


def load(path: Path | None = None, *, owner: int | None = None) -> Config:
    """The config at `path`, or the defaults when `path` is None.

    The root agent reads a config the operator chose, from the operator's home, so the read is
    safe against that path: the final component must not be a symlink, the file must be a regular
    file (a FIFO would hang root forever), at most MAX_CONFIG_BYTES, and — when `owner` is given —
    owned by that uid or by root. (Accepted risk, 2026-09-30: a process running as the operator
    can still edit the file's contents; this stops it from hanging or redirecting root.)
    """
    if path is None:
        return Config()
    try:
        raw = tomllib.loads(_read_safely(Path(path), owner))
    except FileNotFoundError:
        raise ConfigError(f"{path}: no such file") from None
    except tomllib.TOMLDecodeError as bad:
        raise ConfigError(f"{path}: not valid TOML: {bad}") from None
    except RecursionError:
        raise ConfigError(f"{path}: nested too deeply to be a config") from None
    sections = {f.name: f for f in dataclasses.fields(Config)}
    if unknown := sorted(set(raw) - set(sections)):
        raise ConfigError(f"unknown section(s) {unknown}")
    built = {name: _section(name, sections[name].default_factory, raw[name])  # type: ignore[misc]
             for name in raw}
    config = Config(**built)
    _principles(config)
    return config


def _read_safely(path: Path, owner: int | None) -> str:
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    except FileNotFoundError:
        raise
    except OSError as refused:
        raise ConfigError(f"{path}: cannot open safely ({refused.strerror}; a symlink is "
                          f"refused)") from None
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode):
            raise ConfigError(f"{path}: not a regular file")
        if info.st_size > MAX_CONFIG_BYTES:
            raise ConfigError(f"{path}: {info.st_size} bytes is over {MAX_CONFIG_BYTES}")
        if owner is not None and info.st_uid not in (owner, 0):
            raise ConfigError(f"{path}: owned by uid {info.st_uid}, not {owner} or root")
        data = os.read(fd, MAX_CONFIG_BYTES + 1)
    finally:
        os.close(fd)
    try:
        return data.decode("utf-8")
    except UnicodeDecodeError:
        raise ConfigError(f"{path}: not UTF-8") from None


def _section(name: str, factory: Any, raw: Any) -> Any:
    if not isinstance(raw, dict):
        raise ConfigError(f"[{name}] must be a table")
    default = factory()
    # Read field by field, not by the file's keys: tools/gates.py refuses a computed getattr.
    defaults = {f.name: getattr(default, f.name) for f in dataclasses.fields(default)}
    if unknown := sorted(set(raw) - set(defaults)):
        raise ConfigError(f"[{name}] has unknown key(s) {unknown}")
    values = {key: _value(f"{name}.{key}", defaults[key], value)
              for key, value in raw.items()}
    return dataclasses.replace(default, **values)


def _value(where: str, default: Any, value: Any) -> Any:
    if isinstance(default, tuple):
        if not isinstance(value, list) or not all(isinstance(v, str) and v.strip() for v in value):
            raise ConfigError(f"{where} must be a list of non-empty strings")
        return tuple(value)
    if isinstance(default, bool):
        if not isinstance(value, bool):
            raise ConfigError(f"{where} must be true or false")
        return value
    if (isinstance(default, int) and where.endswith("_s")) or where.startswith("cadence."):
        return _seconds(where, value)
    if where == "retention.max_bytes":
        return _bytes(where, value)
    if isinstance(default, int | float) and not isinstance(default, bool):
        if (isinstance(value, bool) or not isinstance(value, int | float)
                or not 0 < value < _INFINITY):
            raise ConfigError(f"{where} must be a positive number, and finite")
        if isinstance(default, int) and not isinstance(value, int):
            raise ConfigError(f"{where} must be a whole number")
        return type(default)(value)
    if not isinstance(value, str):
        raise ConfigError(f"{where} must be a string")
    if not value.strip() and not where.startswith("analyst."):
        raise ConfigError(f"{where} must be a non-empty string")
    return value


def _seconds(where: str, value: Any) -> int | float:
    if isinstance(value, bool):
        raise ConfigError(f"{where} must be seconds or a duration like '7d'")
    if isinstance(value, int | float):
        # A chained test, not `value <= 0`: NaN compares false both ways and would pass that.
        if not 0 < value < _INFINITY:
            raise ConfigError(f"{where} must be a positive, finite number of seconds")
        return value
    if isinstance(value, str) and (match := _DURATION.match(value.strip())):
        return int(match[1]) * _SECONDS[match[2]]
    raise ConfigError(f"{where} must be seconds or a duration like '7d', got {value!r}")


def _bytes(where: str, value: Any) -> int:
    if isinstance(value, int) and not isinstance(value, bool) and value > 0:
        return value
    if isinstance(value, str) and (match := _SIZE.match(value.strip())):
        return int(float(match[1]) * _BYTES[match[2]])
    raise ConfigError(f"{where} must be bytes or a size like '10GiB', got {value!r}")


#: `scrypt$N$r$p$salt$hash`, salt and hash in base64.
_SCRYPT = re.compile(r"scrypt\$(\d+)\$(\d+)\$(\d+)"
                     # salt >= 16 bytes (22 base64 chars), key >= 24 bytes: what verify accepts.
                     r"\$[A-Za-z0-9+/]{22,}={0,2}\$[A-Za-z0-9+/]{32,}={0,2}")
#: A display name: plain enough to sit in a badge, a header and a log line unescaped.
_JUDGE_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9 ._+/()-]{0,39}")
_ALLOWED_HOST = re.compile(r"(?:[A-Za-z0-9](?:[A-Za-z0-9.-]{0,251}[A-Za-z0-9])?"
                           r"|\[[0-9A-Fa-f:]+\]):(\d{1,5})")


def _web(web: Web) -> None:
    """Loopback is the default; anything wider must be encrypted, password-gated and named."""
    try:
        loopback = ipaddress.ip_address(web.host).is_loopback
    except ValueError:
        if web.host != "localhost":
            raise ConfigError(f"web.host must be an IP address or localhost, "
                              f"got {web.host!r}") from None
        loopback = True
    if bool(web.tls_cert) != bool(web.tls_key):
        raise ConfigError("web.tls_cert and web.tls_key must be set together")
    if web.password_hash:
        match = _SCRYPT.fullmatch(web.password_hash)
        if not match:
            raise ConfigError("web.password_hash is not an scrypt hash from "
                              "`neonwatch hash-password`")
        n, r, p = (int(match[i]) for i in (1, 2, 3))
        if n < 2**14 or n & (n - 1) or r < 8 or p < 1:
            raise ConfigError("web.password_hash is too weak: needs N >= 2^14 (a power of two), "
                              "r >= 8, p >= 1")
        # The same ceiling web.verify_password enforces: past it every login would fail, and
        # near it one attempt costs seconds of CPU.
        if 128 * n * r > 256 * 2**20 or p > 16:
            raise ConfigError("web.password_hash is too costly: needs 128*N*r <= 256 MiB "
                              "and p <= 16")
    if not loopback:
        missing = [name for name, value in (("tls_cert", web.tls_cert), ("tls_key", web.tls_key),
                                            ("password_hash", web.password_hash)) if not value]
        if missing:
            raise ConfigError(f"web.host {web.host!r} is not loopback, so "
                              f"web.{', web.'.join(missing)} must be set: the dashboard is "
                              f"refused on the network without TLS and a password")
        if not web.allowed_hosts:
            raise ConfigError("web.allowed_hosts must list the name:port values the dashboard "
                              "answers once it listens beyond loopback")
    for entry in web.allowed_hosts:
        if entry != entry.lower():
            raise ConfigError(f"web.allowed_hosts entry {entry!r} must be lower-case: browsers "
                              f"send Host in lower case, so it would never match")
        match = _ALLOWED_HOST.fullmatch(entry)
        if not match or int(match[1]) != web.port:
            raise ConfigError(f"web.allowed_hosts entry {entry!r} must be name:{web.port}")
    if not 300 <= web.session_s <= 7 * 86400:
        raise ConfigError("web.session_s must be between 5 minutes and 7 days")


def _principles(config: Config) -> None:
    _web(config.web)
    if not 0 < config.budget.cpu_fraction <= 0.05:
        raise ConfigError("budget.cpu_fraction must be in (0, 0.05]")
    if config.notify.min_severity not in _SEVERITIES:
        raise ConfigError(f"notify.min_severity must be one of {list(_SEVERITIES)}")
    broker = urlsplit(config.broker.url)
    if broker.scheme != "nats" or broker.hostname != "127.0.0.1" or not broker.port \
            or broker.username or broker.password or broker.path not in ("", "/"):
        raise ConfigError(f"broker.url must be nats://127.0.0.1:<port>; got {config.broker.url!r}"
                          f" — the agent's credential and every root observation travel over it")
    cadence = dataclasses.asdict(config.cadence)
    for tier, floor in _CADENCE_FLOORS.items():
        if cadence[tier] < floor:
            raise ConfigError(f"cadence.{tier} must be at least {floor} s: the root agent never "
                              f"defers fast probes, so a smaller value spends CPU as root")
    if not 1 <= config.judge.concurrency <= 16:
        raise ConfigError("judge.concurrency must be 1-16")
    if not _JUDGE_NAME.fullmatch(config.judge.name):
        raise ConfigError("judge.name must be 1-40 characters: letters, digits, spaces and . _ - "
                          "+ / ( ), starting with a letter or digit")
    if not 1 <= config.web.port <= 65535:
        raise ConfigError("web.port must be 1-65535")
    _analyst(config.analyst)


_PROVIDERS = ("", "openai-compatible", "anthropic")
REACHES = ("local", "lan", "remote")
_EFFORTS = ("", "low", "medium", "high")

#: Smallest interval each tier may be set to. Below these the budget stops meaning anything.
_CADENCE_FLOORS = {"fast": 10, "medium": 60, "slow": 600, "daily": 3600, "collate": 60}


def _analyst(analyst: Analyst) -> None:
    if analyst.provider not in _PROVIDERS:
        raise ConfigError(f"analyst.provider must be one of {list(_PROVIDERS[1:])} or empty")
    if not analyst.provider:
        return
    if not analyst.model.strip():
        raise ConfigError("analyst.model is required when analyst.provider is set")
    if analyst.provider == "openai-compatible" and not analyst.base_url.strip():
        raise ConfigError("analyst.base_url is required for an openai-compatible provider")
    if re.search(r"(?i)^(sk-|sk_|ant-|key-)|[A-Za-z0-9_-]{32,}", analyst.api_key_env):
        raise ConfigError("analyst.api_key_env names an environment variable; it looks like a key")
    if analyst.reach not in REACHES:
        raise ConfigError(f"analyst.reach must be one of {list(REACHES)}")
    if analyst.reasoning_effort not in _EFFORTS:
        raise ConfigError(f"analyst.reasoning_effort must be one of {list(_EFFORTS[1:])} or empty")
    if analyst.reasoning_effort and analyst.provider != "openai-compatible":
        raise ConfigError("analyst.reasoning_effort applies to an openai-compatible provider only")
    url = urlsplit(analyst.base_url or "https://api.anthropic.com")
    host = url.hostname or ""
    if url.scheme not in ("http", "https") or not host:
        raise ConfigError("analyst.base_url must be an http(s) URL with a host")
    if problem := endpoint_problem(analyst.reach, host, url.scheme,
                                   keyed=bool(analyst.api_key_env)):
        raise ConfigError(problem)


def endpoint_problem(reach: str, host: str, scheme: str, *, keyed: bool) -> str:
    """Why `reach` forbids sending analysis to `host` over `scheme`, or "".

    Used twice: when the config is loaded, and by the analyst before each send. "lan" takes IP
    addresses only, because a name could resolve anywhere. Plain http is allowed only to loopback
    and to a LAN address with no key, since a key or the host's data over http beyond that would
    travel in clear text.
    """
    network = endpoint_network(host)
    if network == "local":
        return ""
    if reach == "local":
        return (f"analyst endpoint {host!r} is not loopback and analyst.reach is \"local\"; set "
                f"reach = \"lan\" for a private address or \"remote\" for anywhere")
    if reach == "lan" and network != "lan":
        return (f"analyst endpoint {host!r} is not a private IP address and analyst.reach is "
                f"\"lan\"; set reach = \"remote\" to send beyond the local network")
    if scheme != "https" and (network != "lan" or keyed):
        return (f"analyst endpoint {host!r} must use https: over http the "
                f"{'API key and the ' if keyed else ''}host's data would travel in clear text")
    return ""


def endpoint_network(host: str) -> str:
    """Which network `host` is on: "local" (loopback), "lan" (a private or link-local IP
    address) or "remote"."""
    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        return "local" if host == "localhost" else "remote"
    if address.is_loopback:
        return "local"
    return "lan" if address.is_private or address.is_link_local else "remote"
