"""The local agent API's credential: one long-lived token in a file beside the store.

`<the store's directory>/agent.token` (`~/.local/state/neonwatch/agent.token` by default), mode
0600, owned by the operator. The service creates it at startup when it is missing (`ensure`), and
the web layer reads it again for every agent request (`read`), so `rotate` takes effect at once,
without a restart, and the old token stops working. The token is never logged and never printed
unless asked for (`neonwatch agent-token --show`).

Reading is as careful as the config loader's: the final component must not be a symlink, the file
must be a regular file of at most `MAX_BYTES`, owned by `owner`, and not readable or writable by
group or other. Anything else is a `TokenError` naming the path and what is wrong, never a guess.
Creating uses `O_EXCL`, so an existing file (or a symlink planted where the file goes) is never
written through; rotating writes a new private file and renames it over the old one, which
replaces a symlink rather than following it.
"""

from __future__ import annotations

import os
import re
import secrets
import stat
from pathlib import Path

from neonwatch.config import Config

FILE = "agent.token"
#: A token file is one line; anything longer is not one of ours.
MAX_BYTES = 256
_TOKEN = re.compile(r"[A-Za-z0-9_-]{32,128}")
_CREATE = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC


class TokenError(Exception):
    """The agent token file is missing, unsafe, or does not hold a token."""


def path(config: Config) -> Path:
    """Where the token lives: beside the store, in the service's state directory."""
    return Path(config.store.path).expanduser().parent / FILE


def read(where: Path, owner: int) -> str:
    """The token in `where`, refusing a symlink, a non-regular or oversized file, another
    owner, any group or other permission, and content that is not one token."""
    try:
        fd = os.open(where, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    except FileNotFoundError:
        raise TokenError(f"{where}: no agent token; the service creates it at startup, or run "
                         f"`neonwatch agent-token`") from None
    except OSError as refused:
        raise TokenError(f"{where}: cannot open safely ({refused.strerror}; a symlink is "
                         f"refused)") from None
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode):
            raise TokenError(f"{where}: not a regular file")
        if info.st_uid != owner:
            raise TokenError(f"{where}: owned by uid {info.st_uid}, not {owner}")
        mode = stat.S_IMODE(info.st_mode)
        if mode & 0o077:
            raise TokenError(f"{where}: mode {mode:04o} lets other users at it; chmod 600 it or "
                             f"rotate it")
        if info.st_size > MAX_BYTES:
            raise TokenError(f"{where}: {info.st_size} bytes is not a token")
        data = os.read(fd, MAX_BYTES + 1)
    finally:
        os.close(fd)
    token = data.decode("ascii", "replace").strip()
    if not _TOKEN.fullmatch(token):
        raise TokenError(f"{where}: does not hold a token; rotate it")
    return token


def ensure(where: Path, owner: int) -> tuple[str, bool]:
    """The token, creating the file first when there is none. Returns (token, created)."""
    try:
        return read(where, owner), False
    except TokenError:
        if os.path.lexists(where):
            raise
    where.parent.mkdir(parents=True, exist_ok=True)
    token = _new()
    try:
        _write(where, token)
    except FileExistsError:  # made meanwhile, by another process
        return read(where, owner), False
    return token, True


def rotate(where: Path, owner: int) -> str:
    """Replace the token with a new one, atomically. The old one stops working at once.

    A file at `where` that is not a regular file owned by `owner` is refused rather than
    replaced, so rotating never removes something that is not ours."""
    try:
        info = os.lstat(where)
    except FileNotFoundError:
        info = None
    if info is not None and (not stat.S_ISREG(info.st_mode) or info.st_uid != owner):
        raise TokenError(f"{where}: not a regular file owned by uid {owner}; refusing to "
                         f"replace it")
    where.parent.mkdir(parents=True, exist_ok=True)
    token = _new()
    staged = where.with_name(f".{FILE}.{secrets.token_hex(8)}")
    _write(staged, token)
    try:
        os.replace(staged, where)
    except BaseException:
        staged.unlink(missing_ok=True)
        raise
    return token


def _new() -> str:
    return secrets.token_urlsafe(32)


def _write(where: Path, token: str) -> None:
    fd = os.open(where, _CREATE, 0o600)
    try:
        os.fchmod(fd, 0o600)  # whatever the umask
        os.write(fd, (token + "\n").encode("ascii"))
    finally:
        os.close(fd)
