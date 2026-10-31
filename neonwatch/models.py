"""Which models NeonWatch calls, as the operator sets them from the dashboard.

Two files beside the config file (`~/.config/neonwatch/` by default), both the service's own,
mode 0600, written staged and renamed, so a reader never sees half of one and a symlink is
replaced rather than written through:

- `models.json`: an overlay on `[judge]` (`name`, `url`, `model`) and `[analyst]` (`provider`,
  `base_url`, `model`, `reach`, `reasoning_effort`). `config.toml` stays the operator's and is
  never written. A field here wins over it; reverting a section removes it from here, and only a
  field that differs from `config.toml` is kept.
- `secrets.json`: the keys, `{"judge": "...", "analyst": "..."}`. Never logged and never
  returned: the view says only whether a key is set and where it comes from. The analyst's key
  falls back to the environment variable `api_key_env` names, as before. A key goes only to the
  endpoint it was given for: a save that moves an endpoint gives its key again or removes it,
  and the environment's key serves config.toml's endpoint alone.

A change is checked whole by the config's own rules (`check_judge`, `check_analyst`)
before anything is written, then applied live through the callback the service gives; nothing
restarts. Reading is as careful as the config loader's: no symlink, a regular file of bounded
size, owned by the operator, no group or other bits. Anything else is a ModelsError that names
the file and what is wrong.
"""

from __future__ import annotations

import dataclasses
import json
import os
import re
import secrets as _secrets
import stat
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from neonwatch.config import (
    EFFORTS,
    PROVIDERS,
    REACHES,
    Analyst,
    Config,
    ConfigError,
    JudgeServer,
    check_analyst,
    check_judge,
)

SETTINGS = "models.json"
SECRETS = "secrets.json"
#: The fields the dashboard may set, by section. Everything else stays `config.toml`'s alone.
FIELDS: dict[str, tuple[str, ...]] = {
    "judge": ("name", "url", "model"),
    "analyst": ("provider", "base_url", "model", "reach", "reasoning_effort"),
}
MAX_BYTES = 64 * 1024
MAX_VALUE = 2048
MAX_KEY = 4096
#: A key is printable ASCII without spaces: anything else is a paste gone wrong.
_KEY = re.compile(r"[\x21-\x7e]+")
_STAGE = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC


class ModelsError(Exception):
    """A change or a file the models cannot take, with the reason in words."""


@dataclass(frozen=True, slots=True)
class Keys:
    judge: str = ""
    analyst: str = ""

    def __repr__(self) -> str:   # never the keys themselves, in a log or a traceback
        return f"Keys(judge={'set' if self.judge else 'unset'}, " \
               f"analyst={'set' if self.analyst else 'unset'})"


def directory(config_path: Path | None, home: Path) -> Path:
    """Where the files live: beside the config file, or `~/.config/neonwatch` without one."""
    return config_path.parent if config_path is not None else home / ".config" / "neonwatch"


def write_private(where: Path, text: str) -> None:
    """Write `text` to `where` as a 0600 file, atomically: a private staged file renamed over the
    old one, which replaces a symlink rather than writing through it."""
    staged = where.with_name(f".{where.name}.{_secrets.token_hex(8)}")
    fd = os.open(staged, _STAGE, 0o600)
    try:
        try:
            os.fchmod(fd, 0o600)   # whatever the umask
            os.write(fd, text.encode())
        finally:
            os.close(fd)
        os.replace(staged, where)
    except BaseException:
        staged.unlink(missing_ok=True)
        raise


def _read_private(path: Path, owner: int) -> dict[str, Any] | None:
    """A JSON object from `path`, read as carefully as the config; None when there is no file."""
    try:
        info = os.lstat(path)
    except FileNotFoundError:
        return None
    if not stat.S_ISREG(info.st_mode):
        raise ModelsError(f"{path}: not a regular file")
    if info.st_uid != owner:
        raise ModelsError(f"{path}: owned by uid {info.st_uid}, not {owner}")
    if info.st_mode & 0o077:
        raise ModelsError(f"{path}: readable or writable by group or others "
                          f"({info.st_mode & 0o777:o}); it must be 0600")
    if info.st_size > MAX_BYTES:
        raise ModelsError(f"{path}: {info.st_size} bytes, more than {MAX_BYTES}")
    try:
        data = json.loads(path.read_text())
    except (OSError, ValueError) as bad:
        raise ModelsError(f"{path}: not readable JSON ({bad})") from None
    if not isinstance(data, dict):
        raise ModelsError(f"{path}: not a JSON object")
    return data


def _section(name: str, raw: Any, origin: str) -> dict[str, str]:
    if not isinstance(raw, Mapping):
        raise ModelsError(f"{origin}: {name} must be an object")
    if unknown := sorted(set(raw) - set(FIELDS[name])):
        raise ModelsError(f"{origin}: {name} cannot set {unknown}; only {list(FIELDS[name])}")
    out = {}
    for field_, value in raw.items():
        if not isinstance(value, str) or len(value) > MAX_VALUE:
            raise ModelsError(f"{origin}: {name}.{field_} must be text of at most {MAX_VALUE} "
                              f"characters")
        out[field_] = value.strip()
    return out


def read_overlay(where: Path, owner: int) -> dict[str, dict[str, str]]:
    path = where / SETTINGS
    data = _read_private(path, owner) or {}
    if unknown := sorted(set(data) - set(FIELDS)):
        raise ModelsError(f"{path}: unknown section(s) {unknown}")
    return {name: _section(name, raw, str(path)) for name, raw in data.items()}


def _key(value: Any, name: str, origin: str) -> str:
    if not isinstance(value, str) or not value:
        raise ModelsError(f"{origin}: the {name} key must be non-empty text")
    if len(value) > MAX_KEY or not _KEY.fullmatch(value):
        raise ModelsError(f"{origin}: the {name} key must be printable characters without "
                          f"spaces, at most {MAX_KEY}")
    return value


def read_keys(where: Path, owner: int) -> Keys:
    path = where / SECRETS
    data = _read_private(path, owner) or {}
    if unknown := sorted(set(data) - set(FIELDS)):
        raise ModelsError(f"{path}: unknown key(s) {unknown}")
    return Keys(**{name: _key(value, name, str(path)) for name, value in data.items()})


def effective(base: Config, overlay: Mapping[str, Mapping[str, str]]) -> Config:
    """`base` with the overlay's fields in place of its own."""
    return dataclasses.replace(
        base,
        judge=dataclasses.replace(base.judge, **overlay.get("judge", {})),
        analyst=dataclasses.replace(base.analyst, **overlay.get("analyst", {})))


def analyst_key(config: Config, keys: Keys, environ: Mapping[str, str]) -> str:
    """The analyst's key: the dashboard's, else the environment variable `api_key_env` names."""
    if keys.analyst:
        return keys.analyst
    name = config.analyst.api_key_env
    return environ.get(name, "") if name else ""


def endpoint(config: Config, name: str) -> tuple[str, ...]:
    """Where a section's key is sent: the judge server's URL, or the analyst's provider and base
    URL."""
    if name == "judge":
        return (config.judge.url.strip().rstrip("/"),)
    return (config.analyst.provider, config.analyst.base_url.strip().rstrip("/"))


def check(config: Config, keys: Keys, environ: Mapping[str, str]) -> None:
    """Raise ModelsError unless the models in `config` are usable with these keys."""
    try:
        check_judge(config.judge)
        check_analyst(config.analyst, keyed=bool(analyst_key(config, keys, environ)))
    except ConfigError as bad:
        raise ModelsError(str(bad)) from None


class Models:
    """The models in force: the operator's config, the dashboard's overlay and keys on disk, and
    the service's callback that applies a change (it retargets the judge and rebuilds the
    analyst). One per service."""

    def __init__(self, base: Config, where: Path, owner: int, environ: Mapping[str, str],
                 apply: Callable[[Config, Keys], Any]) -> None:
        self.base, self.where, self.owner, self.environ = base, where, owner, environ
        self._apply = apply
        self.overlay: dict[str, dict[str, str]] = {}
        self.keys = Keys()

    def load(self) -> tuple[Config, list[str]]:
        """Read both files. One that is unusable, or that makes the models unusable, is left out
        and named in the problems returned: the service then runs on `config.toml` rather than
        refusing to start. Returns the config in force."""
        problems = []
        try:
            self.overlay = read_overlay(self.where, self.owner)
        except ModelsError as bad:
            problems.append(str(bad))
        try:
            self.keys = read_keys(self.where, self.owner)
        except ModelsError as bad:
            problems.append(str(bad))
        config = effective(self.base, self.overlay)
        try:
            check(config, self.keys, self.environ)
        except ModelsError as bad:
            problems.append(f"{self.where / SETTINGS} is not used: {bad}")
            self.overlay, config = {}, self.base
        return config, problems

    @property
    def config(self) -> Config:
        return effective(self.base, self.overlay)

    def view(self, *, editable: bool, why_not: str = "") -> dict[str, Any]:
        """What the dashboard shows: each field's value and where it comes from, and whether each
        key is set and where from. Never a key."""
        config = self.config
        defaults = {"judge": JudgeServer(), "analyst": Analyst()}

        def fields(name: str) -> dict[str, Any]:
            shown = {}
            for field_ in FIELDS[name]:
                value = getattr(getattr(config, name), field_)
                base = getattr(getattr(self.base, name), field_)
                source = ("dashboard" if field_ in self.overlay.get(name, {})
                          else "config.toml" if base != getattr(defaults[name], field_)
                          else "default")
                shown[field_] = {"value": value, "source": source}
            return shown

        env = config.analyst.api_key_env
        analyst_source = ("dashboard" if self.keys.analyst
                          else "environment" if env and self.environ.get(env) else None)
        return {
            "editable": editable,
            "why_not": "" if editable else why_not,
            "files": {"settings": str(self.where / SETTINGS),
                      "secrets": str(self.where / SECRETS)},
            "judge": {"fields": fields("judge"), "overridden": "judge" in self.overlay,
                      "key": {"set": bool(self.keys.judge),
                              "source": "dashboard" if self.keys.judge else None}},
            "analyst": {"fields": fields("analyst"), "overridden": "analyst" in self.overlay,
                        "key": {"set": bool(analyst_source), "source": analyst_source,
                                "env": env}},
            "choices": {"provider": list(PROVIDERS), "reach": list(REACHES),
                        "reasoning_effort": list(EFFORTS)},
        }

    def save(self, change: Mapping[str, Any]) -> tuple[Config, Any]:
        """Apply `change`, all of it or none:

        - `judge` and `analyst` are an object of fields to set (each replaces that section of the
          overlay, keeping only the fields that differ from `config.toml`), or null to revert the
          section to `config.toml`;
        - `keys` maps `judge` or `analyst` to a new key, or to "" to remove it.

        Checked whole before anything is written; then both files are written and the change is
        applied. Returns the config now in force and what the apply callback returned (the
        service's new analyst)."""
        if not isinstance(change, Mapping):
            raise ModelsError("a change is a JSON object")
        if unknown := sorted(set(change) - {*FIELDS, "keys"}):
            raise ModelsError(f"unknown part(s) of a change: {unknown}")
        overlay = {name: dict(section) for name, section in self.overlay.items()}
        for name in FIELDS:
            if name not in change:
                continue
            if change[name] is None:
                overlay.pop(name, None)
                continue
            asked = _section(name, change[name], "the change")
            base = getattr(self.base, name)
            kept = {f: v for f, v in asked.items() if v != getattr(base, f)}
            if kept:
                overlay[name] = kept
            else:
                overlay.pop(name, None)
        keys = self.keys
        asked_keys = change.get("keys", {})
        if not isinstance(asked_keys, Mapping):
            raise ModelsError("keys must be an object")
        if unknown := sorted(set(asked_keys) - set(FIELDS)):
            raise ModelsError(f"unknown key(s) {unknown}")
        for name, value in asked_keys.items():
            if value == "":
                keys = dataclasses.replace(keys, **{name: ""})
            else:
                keys = dataclasses.replace(keys, **{name: _key(value, name, "the change")})
        config = effective(self.base, overlay)
        check(config, keys, self.environ)
        self._keys_stay(config, keys, asked_keys)
        self.where.mkdir(parents=True, exist_ok=True, mode=0o700)
        if overlay != self.overlay:
            write_private(self.where / SETTINGS, json.dumps(overlay, indent=2) + "\n")
        if keys != self.keys:
            kept_keys = {k: v for k, v in dataclasses.asdict(keys).items() if v}
            write_private(self.where / SECRETS, json.dumps(kept_keys) + "\n")
        self.overlay, self.keys = overlay, keys
        return config, self._apply(config, keys)

    def _keys_stay(self, config: Config, keys: Keys, asked: Mapping[str, Any]) -> None:
        """A key is sent only where it was given for. A save that moves a section's endpoint
        brings that section's key with it, or removes it: the dashboard's key is never carried
        to a new endpoint, so whoever holds a dashboard session cannot point the analyst at a
        server of theirs and receive the key. The environment's key is config.toml's, for
        config.toml's endpoint alone."""
        for name in FIELDS:
            moved = endpoint(config, name) != endpoint(self.config, name)
            if moved and getattr(keys, name) and not asked.get(name):
                raise ModelsError(f"the {name} endpoint changes, and its key does not move with "
                                  f"it: give the key for the new endpoint in the same save, or "
                                  f"remove it")
        env = config.analyst.api_key_env
        if (not keys.analyst and endpoint(config, "analyst") != endpoint(self.base, "analyst")
                and analyst_key(config, keys, self.environ)):
            raise ModelsError(f"the key in ${env} is for config.toml's analyst endpoint, not this "
                              f"one: set a key for it here")
